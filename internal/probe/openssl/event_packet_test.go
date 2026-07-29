// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestPacketEventDecodeMetadata(t *testing.T) {
	var comm [TaskCommLen]byte
	copy(comm[:], "com.larus.nova")
	packet := []byte{0x45, 0, 0, 20}
	values := []any{
		uint64(1234),
		uint32(777),
		comm,
		uint32(len(packet)),
		uint32(9),
		uint32(10290),
		uint32(PacketFlagAttributed | PacketFlagRawIP),
		uint32(PacketDirectionEgress),
		uint64(0x11223344),
		uint64(0x55667788),
	}
	var encoded bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&encoded, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	encoded.Write(packet)

	var event PacketEvent
	if err := event.DecodeFromBytes(encoded.Bytes()); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if event.Pid != 777 || event.Uid != 10290 || event.InterfaceIndex != 9 {
		t.Fatalf("decoded identity = pid:%d uid:%d ifindex:%d", event.Pid, event.Uid, event.InterfaceIndex)
	}
	if event.SocketCookie != 0x11223344 || event.CGroupID != 0x55667788 {
		t.Fatalf("decoded socket metadata = cookie:%#x cgroup:%#x", event.SocketCookie, event.CGroupID)
	}
	if event.DirectionString() != "egress" || !bytes.Equal(event.PacketData, packet) {
		t.Fatalf("decoded packet direction=%s data=%x", event.DirectionString(), event.PacketData)
	}
}

func TestPacketEventRejectsLegacyShortHeader(t *testing.T) {
	var event PacketEvent
	if err := event.DecodeFromBytes(make([]byte, PacketMetadataLen-1)); err == nil {
		t.Fatal("DecodeFromBytes() should reject a truncated metadata header")
	}
}

func TestPacketEventParsesGQUICClientHello(t *testing.T) {
	packet := ethernetIPv4UDPPacket(
		t,
		net.IPv4(10, 0, 2, 15),
		net.IPv4(101, 72, 218, 199),
		42081,
		443,
		gquicClientHello(t, "api5-normal-lf.doubao.com"),
	)
	event := PacketEvent{
		PacketLen:  uint32(len(packet)),
		PacketData: packet,
		Direction:  PacketDirectionEgress,
	}

	if got, want := event.GetSrcIP(), "10.0.2.15"; got != want {
		t.Fatalf("GetSrcIP() = %q, want %q", got, want)
	}
	if got, want := event.GetDstIP(), "101.72.218.199"; got != want {
		t.Fatalf("GetDstIP() = %q, want %q", got, want)
	}
	if got, want := event.GetSrcPort(), uint16(42081); got != want {
		t.Fatalf("GetSrcPort() = %d, want %d", got, want)
	}
	if got, want := event.GetDstPort(), uint16(443); got != want {
		t.Fatalf("GetDstPort() = %d, want %d", got, want)
	}
	if got, want := event.GetTransportProtocol(), "udp"; got != want {
		t.Fatalf("GetTransportProtocol() = %q, want %q", got, want)
	}
	if got, want := event.GetApplicationProtocol(), "gquic"; got != want {
		t.Fatalf("GetApplicationProtocol() = %q, want %q", got, want)
	}
	if got, want := event.GetServerName(), "api5-normal-lf.doubao.com"; got != want {
		t.Fatalf("GetServerName() = %q, want %q", got, want)
	}
	for _, expected := range []string{
		"flow=10.0.2.15:42081->101.72.218.199:443",
		"transport=udp",
		"protocol=gquic",
		"server_name=api5-normal-lf.doubao.com",
	} {
		if got := event.String(); !strings.Contains(got, expected) {
			t.Fatalf("String() = %q, want substring %q", got, expected)
		}
	}
}

func TestPacketEventParsesRawIPv6TCP(t *testing.T) {
	packet := make([]byte, 40+20)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 20)
	packet[6] = ipProtocolTCP
	packet[7] = 64
	copy(packet[8:24], net.ParseIP("2001:db8::1").To16())
	copy(packet[24:40], net.ParseIP("2001:db8::2").To16())
	binary.BigEndian.PutUint16(packet[40:42], 54321)
	binary.BigEndian.PutUint16(packet[42:44], 443)
	event := PacketEvent{
		PacketLen:  uint32(len(packet)),
		PacketData: packet,
		Flags:      PacketFlagRawIP,
	}

	if got, want := event.GetSrcIP(), "2001:db8::1"; got != want {
		t.Fatalf("GetSrcIP() = %q, want %q", got, want)
	}
	if got, want := event.GetDstIP(), "2001:db8::2"; got != want {
		t.Fatalf("GetDstIP() = %q, want %q", got, want)
	}
	if got, want := event.GetSrcPort(), uint16(54321); got != want {
		t.Fatalf("GetSrcPort() = %d, want %d", got, want)
	}
	if got, want := event.GetDstPort(), uint16(443); got != want {
		t.Fatalf("GetDstPort() = %d, want %d", got, want)
	}
	if got, want := event.GetTransportProtocol(), "tcp"; got != want {
		t.Fatalf("GetTransportProtocol() = %q, want %q", got, want)
	}
}

func TestPacketEventMarksIETFQUICCandidate(t *testing.T) {
	packet := ethernetIPv4UDPPacket(
		t,
		net.IPv4(10, 0, 2, 15),
		net.IPv4(110, 249, 199, 78),
		51829,
		443,
		[]byte{0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4},
	)
	event := PacketEvent{PacketLen: uint32(len(packet)), PacketData: packet}
	if got, want := event.GetApplicationProtocol(), "quic"; got != want {
		t.Fatalf("GetApplicationProtocol() = %q, want %q", got, want)
	}
}

func TestPacketEventParsesTLSClientHello(t *testing.T) {
	packet := ethernetIPv4TCPPacket(
		t,
		net.IPv4(10, 0, 2, 15),
		net.IPv4(101, 72, 218, 199),
		59840,
		443,
		tlsClientHello(t, "api5-normal-lf.doubao.com"),
	)
	event := PacketEvent{PacketLen: uint32(len(packet)), PacketData: packet}
	if got, want := event.GetTransportProtocol(), "tcp"; got != want {
		t.Fatalf("GetTransportProtocol() = %q, want %q", got, want)
	}
	if got, want := event.GetApplicationProtocol(), "tls"; got != want {
		t.Fatalf("GetApplicationProtocol() = %q, want %q", got, want)
	}
	if got, want := event.GetServerName(), "api5-normal-lf.doubao.com"; got != want {
		t.Fatalf("GetServerName() = %q, want %q", got, want)
	}
	for _, expected := range []string{
		"flow=10.0.2.15:59840->101.72.218.199:443",
		"protocol=tls",
		"server_name=api5-normal-lf.doubao.com",
	} {
		if got := event.String(); !strings.Contains(got, expected) {
			t.Fatalf("String() = %q, want substring %q", got, expected)
		}
	}
}

func TestGQUICServerNameRejectsMalformedTagTable(t *testing.T) {
	payload := append([]byte{0x0d, 1, 2, 3}, []byte("CHLO")...)
	payload = append(payload, 0xff, 0xff, 0xff, 0x7f)
	if serverName, found := gquicServerName(payload); found || serverName != "" {
		t.Fatalf("gquicServerName() = %q, %t, want empty false", serverName, found)
	}
}

func ethernetIPv4UDPPacket(
	t *testing.T,
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	payload []byte,
) []byte {
	t.Helper()
	packet := make([]byte, 14+20+8+len(payload))
	copy(packet[0:6], []byte{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02})
	copy(packet[6:12], []byte{0x64, 0xa2, 0xf9, 0x2b, 0x01, 0x0a})
	binary.BigEndian.PutUint16(packet[12:14], etherTypeIPv4)
	ipOffset := 14
	packet[ipOffset] = 0x45
	binary.BigEndian.PutUint16(packet[ipOffset+2:ipOffset+4], uint16(20+8+len(payload)))
	packet[ipOffset+8] = 64
	packet[ipOffset+9] = ipProtocolUDP
	copy(packet[ipOffset+12:ipOffset+16], srcIP.To4())
	copy(packet[ipOffset+16:ipOffset+20], dstIP.To4())
	udpOffset := ipOffset + 20
	binary.BigEndian.PutUint16(packet[udpOffset:udpOffset+2], srcPort)
	binary.BigEndian.PutUint16(packet[udpOffset+2:udpOffset+4], dstPort)
	binary.BigEndian.PutUint16(packet[udpOffset+4:udpOffset+6], uint16(8+len(payload)))
	copy(packet[udpOffset+8:], payload)
	return packet
}

func ethernetIPv4TCPPacket(
	t *testing.T,
	srcIP net.IP,
	dstIP net.IP,
	srcPort uint16,
	dstPort uint16,
	payload []byte,
) []byte {
	t.Helper()
	packet := make([]byte, 14+20+20+len(payload))
	copy(packet[0:6], []byte{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02})
	copy(packet[6:12], []byte{0x64, 0xa2, 0xf9, 0x2b, 0x01, 0x0a})
	binary.BigEndian.PutUint16(packet[12:14], etherTypeIPv4)
	ipOffset := 14
	packet[ipOffset] = 0x45
	binary.BigEndian.PutUint16(packet[ipOffset+2:ipOffset+4], uint16(20+20+len(payload)))
	packet[ipOffset+8] = 64
	packet[ipOffset+9] = ipProtocolTCP
	copy(packet[ipOffset+12:ipOffset+16], srcIP.To4())
	copy(packet[ipOffset+16:ipOffset+20], dstIP.To4())
	tcpOffset := ipOffset + 20
	binary.BigEndian.PutUint16(packet[tcpOffset:tcpOffset+2], srcPort)
	binary.BigEndian.PutUint16(packet[tcpOffset+2:tcpOffset+4], dstPort)
	packet[tcpOffset+12] = 5 << 4
	copy(packet[tcpOffset+20:], payload)
	return packet
}

func tlsClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	serverNameBytes := []byte(serverName)
	serverNameExtension := make([]byte, 2+1+2+len(serverNameBytes))
	binary.BigEndian.PutUint16(serverNameExtension[:2], uint16(1+2+len(serverNameBytes)))
	serverNameExtension[2] = 0
	binary.BigEndian.PutUint16(serverNameExtension[3:5], uint16(len(serverNameBytes)))
	copy(serverNameExtension[5:], serverNameBytes)

	extensions := make([]byte, 4+len(serverNameExtension))
	binary.BigEndian.PutUint16(extensions[:2], 0)
	binary.BigEndian.PutUint16(extensions[2:4], uint16(len(serverNameExtension)))
	copy(extensions[4:], serverNameExtension)

	clientHello := make([]byte, 2+32+1+2+2+1+1+2+len(extensions))
	offset := 0
	copy(clientHello[offset:offset+2], []byte{0x03, 0x03})
	offset += 2 + 32
	clientHello[offset] = 0
	offset++
	binary.BigEndian.PutUint16(clientHello[offset:offset+2], 2)
	offset += 2
	copy(clientHello[offset:offset+2], []byte{0x13, 0x01})
	offset += 2
	clientHello[offset] = 1
	offset++
	clientHello[offset] = 0
	offset++
	binary.BigEndian.PutUint16(clientHello[offset:offset+2], uint16(len(extensions)))
	offset += 2
	copy(clientHello[offset:], extensions)

	handshake := make([]byte, 4+len(clientHello))
	handshake[0] = 1
	handshake[1] = byte(len(clientHello) >> 16)
	handshake[2] = byte(len(clientHello) >> 8)
	handshake[3] = byte(len(clientHello))
	copy(handshake[4:], clientHello)

	record := make([]byte, 5+len(handshake))
	copy(record[:3], []byte{22, 0x03, 0x01})
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)
	return record
}

func gquicClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	const tagCount = 2
	payload := []byte{
		0x0d,
		0xd6, 0x6d, 0x6a, 0x55, 0xd5, 0xa0, 0xa6, 0xfb,
		'Q', '0', '4', '3',
		0x01,
	}
	payload = append(payload, []byte("CHLO")...)
	count := make([]byte, 4)
	binary.LittleEndian.PutUint32(count, tagCount)
	payload = append(payload, count...)

	entry := make([]byte, 8)
	copy(entry[:4], []byte{'S', 'N', 'I', 0})
	binary.LittleEndian.PutUint32(entry[4:], uint32(len(serverName)))
	payload = append(payload, entry...)
	copy(entry[:4], []byte{'V', 'E', 'R', 0})
	binary.LittleEndian.PutUint32(entry[4:], uint32(len(serverName)+4))
	payload = append(payload, entry...)
	payload = append(payload, serverName...)
	payload = append(payload, []byte("Q043")...)
	return payload
}
