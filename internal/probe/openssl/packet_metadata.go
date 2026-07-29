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

package openssl

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88a8

	ipProtocolTCP      = 6
	ipProtocolUDP      = 17
	ipProtocolHopByHop = 0
	ipProtocolRouting  = 43
	ipProtocolFragment = 44
	ipProtocolESP      = 50
	ipProtocolAH       = 51
	ipProtocolDstOpts  = 60
)

type packetMetadata struct {
	srcIP       string
	dstIP       string
	srcPort     uint16
	dstPort     uint16
	transport   string
	application string
	serverName  string
}

func parsePacketMetadata(packet []byte, flags uint32) packetMetadata {
	var metadata packetMetadata
	l3Offset, etherType, ok := packetNetworkOffset(packet, flags)
	if !ok {
		return metadata
	}

	var protocol byte
	var transportOffset int
	switch etherType {
	case etherTypeIPv4:
		protocol, transportOffset, ok = parseIPv4Metadata(packet, l3Offset, &metadata)
	case etherTypeIPv6:
		protocol, transportOffset, ok = parseIPv6Metadata(packet, l3Offset, &metadata)
	default:
		return metadata
	}
	if !ok {
		return metadata
	}

	switch protocol {
	case ipProtocolTCP:
		metadata.transport = "tcp"
		if transportOffset+4 > len(packet) {
			return metadata
		}
		metadata.srcPort = binary.BigEndian.Uint16(packet[transportOffset : transportOffset+2])
		metadata.dstPort = binary.BigEndian.Uint16(packet[transportOffset+2 : transportOffset+4])
		if payloadOffset, found := tcpPayloadOffset(packet, transportOffset); found {
			if serverName, found := tlsClientHelloServerName(packet[payloadOffset:]); found {
				metadata.application = "tls"
				metadata.serverName = serverName
			}
		}
	case ipProtocolUDP:
		metadata.transport = "udp"
		if transportOffset+8 > len(packet) {
			return metadata
		}
		metadata.srcPort = binary.BigEndian.Uint16(packet[transportOffset : transportOffset+2])
		metadata.dstPort = binary.BigEndian.Uint16(packet[transportOffset+2 : transportOffset+4])
		payload := packet[transportOffset+8:]
		if serverName, found := gquicServerName(payload); found {
			metadata.application = "gquic"
			metadata.serverName = serverName
		} else if metadata.srcPort == 443 || metadata.dstPort == 443 {
			if isIETFQUICLongHeader(payload) {
				metadata.application = "quic"
			} else {
				metadata.application = "quic-candidate"
			}
		}
	}
	return metadata
}

func packetNetworkOffset(packet []byte, flags uint32) (int, uint16, bool) {
	if len(packet) == 0 {
		return 0, 0, false
	}
	if flags&PacketFlagRawIP != 0 {
		switch packet[0] >> 4 {
		case 4:
			return 0, etherTypeIPv4, true
		case 6:
			return 0, etherTypeIPv6, true
		default:
			return 0, 0, false
		}
	}

	if len(packet) >= 14 {
		offset := 14
		etherType := binary.BigEndian.Uint16(packet[12:14])
		for vlanDepth := 0; vlanDepth < 4 &&
			(etherType == etherTypeVLAN || etherType == etherTypeQinQ); vlanDepth++ {
			if offset+4 > len(packet) {
				return 0, 0, false
			}
			etherType = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
			offset += 4
		}
		if etherType == etherTypeIPv4 || etherType == etherTypeIPv6 {
			return offset, etherType, true
		}
	}

	// Some TUN drivers expose raw IP without setting the metadata flag. Keep
	// parsing best-effort so tuple logging never changes packet capture.
	switch packet[0] >> 4 {
	case 4:
		return 0, etherTypeIPv4, true
	case 6:
		return 0, etherTypeIPv6, true
	default:
		return 0, 0, false
	}
}

func parseIPv4Metadata(
	packet []byte, offset int, metadata *packetMetadata,
) (byte, int, bool) {
	if offset+20 > len(packet) || packet[offset]>>4 != 4 {
		return 0, 0, false
	}
	headerLength := int(packet[offset]&0x0f) * 4
	if headerLength < 20 || offset+headerLength > len(packet) {
		return 0, 0, false
	}
	metadata.srcIP = net.IP(packet[offset+12 : offset+16]).String()
	metadata.dstIP = net.IP(packet[offset+16 : offset+20]).String()

	fragment := binary.BigEndian.Uint16(packet[offset+6 : offset+8])
	if fragment&0x1fff != 0 {
		return packet[offset+9], 0, false
	}
	return packet[offset+9], offset + headerLength, true
}

func parseIPv6Metadata(
	packet []byte, offset int, metadata *packetMetadata,
) (byte, int, bool) {
	if offset+40 > len(packet) || packet[offset]>>4 != 6 {
		return 0, 0, false
	}
	metadata.srcIP = net.IP(packet[offset+8 : offset+24]).String()
	metadata.dstIP = net.IP(packet[offset+24 : offset+40]).String()
	nextHeader := packet[offset+6]
	transportOffset := offset + 40

	for extensionCount := 0; extensionCount < 8; extensionCount++ {
		switch nextHeader {
		case ipProtocolHopByHop, ipProtocolRouting, ipProtocolDstOpts:
			if transportOffset+2 > len(packet) {
				return nextHeader, 0, false
			}
			length := (int(packet[transportOffset+1]) + 1) * 8
			if length < 8 || transportOffset+length > len(packet) {
				return nextHeader, 0, false
			}
			nextHeader = packet[transportOffset]
			transportOffset += length
		case ipProtocolFragment:
			if transportOffset+8 > len(packet) {
				return nextHeader, 0, false
			}
			fragment := binary.BigEndian.Uint16(packet[transportOffset+2 : transportOffset+4])
			nextHeader = packet[transportOffset]
			if fragment&0xfff8 != 0 {
				return nextHeader, 0, false
			}
			transportOffset += 8
		case ipProtocolAH:
			if transportOffset+2 > len(packet) {
				return nextHeader, 0, false
			}
			length := (int(packet[transportOffset+1]) + 2) * 4
			if length < 8 || transportOffset+length > len(packet) {
				return nextHeader, 0, false
			}
			nextHeader = packet[transportOffset]
			transportOffset += length
		case ipProtocolESP:
			return nextHeader, 0, false
		default:
			return nextHeader, transportOffset, true
		}
	}
	return nextHeader, 0, false
}

func gquicServerName(payload []byte) (string, bool) {
	const (
		cryptoMessageHeaderLength = 8
		cryptoTagEntryLength      = 8
		maxCryptoTagEntries       = 64
		maxCHLOPrefixLength       = 64
	)

	chloOffset := bytes.Index(payload, []byte("CHLO"))
	if chloOffset < 0 || chloOffset > maxCHLOPrefixLength {
		return "", false
	}
	message := payload[chloOffset:]
	if len(message) < cryptoMessageHeaderLength {
		return "", false
	}
	entryCount := int(binary.LittleEndian.Uint32(message[4:8]))
	if entryCount <= 0 || entryCount > maxCryptoTagEntries {
		return "", false
	}
	valueOffset := cryptoMessageHeaderLength + entryCount*cryptoTagEntryLength
	if valueOffset > len(message) {
		return "", false
	}

	previousEnd := 0
	for entryIndex := 0; entryIndex < entryCount; entryIndex++ {
		entryOffset := cryptoMessageHeaderLength + entryIndex*cryptoTagEntryLength
		valueEnd := int(binary.LittleEndian.Uint32(message[entryOffset+4 : entryOffset+8]))
		if valueEnd < previousEnd || valueOffset+valueEnd > len(message) {
			return "", false
		}
		if bytes.Equal(message[entryOffset:entryOffset+4], []byte{'S', 'N', 'I', 0}) {
			serverName := strings.TrimSuffix(
				string(message[valueOffset+previousEnd:valueOffset+valueEnd]), ".",
			)
			if validServerName(serverName) {
				return serverName, true
			}
			return "", false
		}
		previousEnd = valueEnd
	}
	return "", false
}

func validServerName(serverName string) bool {
	if len(serverName) == 0 || len(serverName) > 253 {
		return false
	}
	for _, value := range []byte(serverName) {
		if (value >= 'a' && value <= 'z') ||
			(value >= 'A' && value <= 'Z') ||
			(value >= '0' && value <= '9') ||
			value == '.' || value == '-' || value == '_' {
			continue
		}
		return false
	}
	return true
}

func isIETFQUICLongHeader(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	// IETF QUIC long headers set both the Header Form and Fixed bits. A zero
	// version is version negotiation, which is still useful QUIC metadata.
	return payload[0]&0xc0 == 0xc0
}

func tcpPayloadOffset(packet []byte, transportOffset int) (int, bool) {
	if transportOffset+20 > len(packet) {
		return 0, false
	}
	headerLength := int(packet[transportOffset+12]>>4) * 4
	if headerLength < 20 || transportOffset+headerLength > len(packet) {
		return 0, false
	}
	return transportOffset + headerLength, true
}

func tlsClientHelloServerName(payload []byte) (string, bool) {
	const (
		tlsRecordHeaderLength    = 5
		tlsHandshakeHeaderLength = 4
		tlsHandshake             = 22
		tlsClientHello           = 1
		tlsExtensionServerName   = 0
	)

	if len(payload) < tlsRecordHeaderLength+tlsHandshakeHeaderLength ||
		payload[0] != tlsHandshake {
		return "", false
	}
	recordLength := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLength < tlsHandshakeHeaderLength || tlsRecordHeaderLength+recordLength > len(payload) {
		return "", false
	}
	handshake := payload[tlsRecordHeaderLength : tlsRecordHeaderLength+recordLength]
	if handshake[0] != tlsClientHello {
		return "", false
	}
	handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if handshakeLength+tlsHandshakeHeaderLength > len(handshake) {
		return "", false
	}
	clientHello := handshake[tlsHandshakeHeaderLength : tlsHandshakeHeaderLength+handshakeLength]

	// legacy_version + random
	offset := 2 + 32
	if offset+1 > len(clientHello) {
		return "", false
	}
	sessionIDLength := int(clientHello[offset])
	offset++
	if offset+sessionIDLength+2 > len(clientHello) {
		return "", false
	}
	offset += sessionIDLength

	cipherSuitesLength := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
	offset += 2
	if cipherSuitesLength%2 != 0 || offset+cipherSuitesLength+1 > len(clientHello) {
		return "", false
	}
	offset += cipherSuitesLength

	compressionMethodsLength := int(clientHello[offset])
	offset++
	if offset+compressionMethodsLength+2 > len(clientHello) {
		return "", false
	}
	offset += compressionMethodsLength

	extensionsLength := int(binary.BigEndian.Uint16(clientHello[offset : offset+2]))
	offset += 2
	if offset+extensionsLength > len(clientHello) {
		return "", false
	}
	extensionsEnd := offset + extensionsLength
	for offset+4 <= extensionsEnd {
		extensionType := binary.BigEndian.Uint16(clientHello[offset : offset+2])
		extensionLength := int(binary.BigEndian.Uint16(clientHello[offset+2 : offset+4]))
		offset += 4
		if offset+extensionLength > extensionsEnd {
			return "", false
		}
		if extensionType == tlsExtensionServerName {
			return tlsServerNameExtension(clientHello[offset : offset+extensionLength])
		}
		offset += extensionLength
	}
	return "", false
}

func tlsServerNameExtension(extension []byte) (string, bool) {
	if len(extension) < 2 {
		return "", false
	}
	listLength := int(binary.BigEndian.Uint16(extension[:2]))
	if listLength+2 > len(extension) {
		return "", false
	}
	offset := 2
	listEnd := offset + listLength
	for offset+3 <= listEnd {
		nameType := extension[offset]
		nameLength := int(binary.BigEndian.Uint16(extension[offset+1 : offset+3]))
		offset += 3
		if offset+nameLength > listEnd {
			return "", false
		}
		if nameType == 0 {
			serverName := strings.TrimSuffix(string(extension[offset:offset+nameLength]), ".")
			if validServerName(serverName) {
				return serverName, true
			}
			return "", false
		}
		offset += nameLength
	}
	return "", false
}
