// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reconstruction

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestCorrelateWireMatchesBIOToSocketByExactCiphertext(t *testing.T) {
	ciphertext := make([]byte, 192)
	for i := range ciphertext {
		ciphertext[i] = byte((i*73 + 19) % 251)
	}
	socketPayload := append([]byte("unrelated-prefix"), ciphertext...)
	socketPayload = append(socketPayload, []byte("unrelated-suffix")...)

	var input bytes.Buffer
	encoder := json.NewEncoder(&input)
	writeWireEvent(t, encoder, 100, 0, 0xb10, boundaryTLSCiphertext,
		"WRITE", ciphertext[:80])
	writeWireEvent(t, encoder, 101, 0, 0xb10, boundaryTLSCiphertext,
		"WRITE", ciphertext[80:])
	writeWireEvent(t, encoder, 102, 1, 23, boundaryFDPayload,
		"WRITE", socketPayload[:97])
	writeWireEvent(t, encoder, 103, 1, 23, boundaryFDPayload,
		"WRITE", socketPayload[97:])
	writeWireEvent(t, encoder, 104, 2, 24, boundaryFDPayload,
		"WRITE", ciphertext[:40])

	var output bytes.Buffer
	summary, err := CorrelateWire(&input, &output)
	if err != nil {
		t.Fatalf("CorrelateWire() error = %v", err)
	}
	if summary.TLSBIOStreams != 1 || summary.FDStreams != 2 ||
		summary.Matched != 1 || summary.Unmatched != 0 ||
		summary.Ambiguous != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}

	var correlation WireCorrelation
	if err := json.NewDecoder(&output).Decode(&correlation); err != nil {
		t.Fatalf("decode correlation: %v", err)
	}
	if correlation.BIOAddr != 0xb10 || correlation.Fd != 23 ||
		correlation.Direction != "WRITE" ||
		correlation.MatchedBytes != len(ciphertext) ||
		correlation.Confidence != "exact-fd-content-unverified" ||
		correlation.NetworkVerified ||
		correlation.TargetKind != "fd_candidate" ||
		correlation.Ambiguous {
		t.Fatalf("unexpected correlation: %#v", correlation)
	}
}

func TestCorrelateWirePrefersNetworkVerifiedPacketFlow(t *testing.T) {
	ciphertext := make([]byte, 192)
	for i := range ciphertext {
		ciphertext[i] = byte((i*47 + 11) % 251)
	}

	var input bytes.Buffer
	encoder := json.NewEncoder(&input)
	writeWireEvent(t, encoder, 100, 0, 0xb10, boundaryTLSCiphertext,
		"WRITE", ciphertext[:80])
	writeWireEvent(t, encoder, 101, 0, 0xb10, boundaryTLSCiphertext,
		"WRITE", ciphertext[80:])
	writeTCPPacketEvent(t, encoder, 102, 1000, ciphertext[:90])
	writeTCPPacketEvent(t, encoder, 103, 1090, ciphertext[90:])
	writeWireEvent(t, encoder, 104, 1, 23, boundaryFDPayload,
		"WRITE", ciphertext)

	var output bytes.Buffer
	summary, err := CorrelateWire(&input, &output)
	if err != nil {
		t.Fatalf("CorrelateWire() error = %v", err)
	}
	if summary.Matched != 1 || summary.WireVerified != 1 ||
		summary.FDCandidates != 0 || summary.PacketFlows != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}

	var correlation WireCorrelation
	if err := json.NewDecoder(&output).Decode(&correlation); err != nil {
		t.Fatalf("decode correlation: %v", err)
	}
	if correlation.TargetKind != "packet_flow" ||
		!correlation.NetworkVerified ||
		correlation.Transport != "tcp" ||
		correlation.MatchedBytes != len(ciphertext) ||
		correlation.Fd != 0 ||
		correlation.Confidence != "exact-wire-content" {
		t.Fatalf("unexpected correlation: %#v", correlation)
	}
}

func TestLongestExactWireMatchRejectsShortCoincidence(t *testing.T) {
	source := bytes.Repeat([]byte{0x41}, wireCorrelationMinimum-1)
	target := append([]byte{0x00}, source...)
	match := longestExactWireMatch(source, target)
	if match.length != len(source) {
		t.Fatalf("match length = %d, want %d", match.length, len(source))
	}
	if match.length >= wireCorrelationMinimum {
		t.Fatalf("short match crossed confidence threshold: %#v", match)
	}
}

func writeWireEvent(
	t *testing.T,
	encoder *json.Encoder,
	timestamp uint64,
	hookID uint32,
	contextID uint64,
	boundaryRole string,
	direction string,
	data []byte,
) {
	t.Helper()
	event := map[string]any{
		"eventType":    "boundary_data",
		"captureLayer": "wire",
		"boundaryRole": boundaryRole,
		"timestamp":    timestamp,
		"pid":          uint32(42),
		"tid":          uint32(7),
		"hookId":       hookID,
		"contextId":    contextID,
		"direction":    direction,
		"originalLen":  len(data),
		"capturedLen":  len(data),
		"chunkOffset":  0,
		"dataLen":      len(data),
		"dataEncoding": "base64",
		"data":         data,
	}
	if boundaryRole == boundaryTLSCiphertext {
		event["transport"] = "tls"
	} else {
		event["transport"] = "fd"
	}
	if err := encoder.Encode(event); err != nil {
		t.Fatalf("encode wire event: %v", err)
	}
}

func writeTCPPacketEvent(
	t *testing.T,
	encoder *json.Encoder,
	timestamp uint64,
	sequence uint32,
	payload []byte,
) {
	t.Helper()
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 443,
		Seq:     sequence,
		ACK:     true,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set TCP checksum network layer: %v", err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernet,
		ip,
		tcp,
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("serialize TCP packet: %v", err)
	}
	event := map[string]any{
		"Timestamp":    timestamp,
		"Pid":          uint32(42),
		"Direction":    uint8(1),
		"SocketCookie": uint64(99),
		"PacketData":   buffer.Bytes(),
	}
	if err := encoder.Encode(event); err != nil {
		t.Fatalf("encode packet event: %v", err)
	}
}
