// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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
	"encoding/json"
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	TaskCommLen       = 16
	CmdlineLen        = 256
	PacketMetadataLen = 64

	PacketFlagAttributed   = 0x01
	PacketFlagUIDFromSock  = 0x02
	PacketFlagUnknownFlow  = 0x04
	PacketFlagRawIP        = 0x08
	PacketFlagVLAN         = 0x10
	PacketDirectionIngress = 0
	PacketDirectionEgress  = 1
)

// PacketEvent represents a network packet captured by TC probes.
// This implements the PacketEvent interface from handlers package.
type PacketEvent struct {
	Timestamp      uint64
	Pid            uint32
	Comm           [TaskCommLen]byte
	Cmdline        [CmdlineLen]byte
	PacketLen      uint32
	CapturedLen    uint32
	InterfaceIndex uint32
	Uid            uint32
	Flags          uint32
	Direction      uint32
	SocketCookie   uint64
	CGroupID       uint64
	PacketData     []byte
}

func (e PacketEvent) MarshalJSON() ([]byte, error) {
	type packetEventAlias PacketEvent
	transport := e.GetTransportProtocol()
	if transport == "" {
		transport = "unknown"
	}
	return json.Marshal(struct {
		EventType    string `json:"eventType"`
		CaptureLayer string `json:"captureLayer"`
		Transport    string `json:"transport"`
		WallTime     string `json:"wallTime,omitempty"`
		packetEventAlias
	}{
		EventType:        "packet",
		CaptureLayer:     CaptureLayerWire,
		Transport:        transport,
		WallTime:         wallTimeFromMonotonic(e.Timestamp),
		packetEventAlias: packetEventAlias(e),
	})
}

// DecodeFromBytes decodes a packet event from raw bytes.
func (e *PacketEvent) DecodeFromBytes(data []byte) error {
	if len(data) < PacketMetadataLen {
		return errors.New(errors.ErrCodeEventDecode, "packet event data too short")
	}
	var err error
	buf := bytes.NewBuffer(data)
	if err = binary.Read(buf, binary.LittleEndian, &e.Timestamp); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return err
	}
	//if err = binary.Read(buf, binary.LittleEndian, &te.Cmdline); err != nil {
	//	return
	//}
	//TODO
	e.Cmdline[0] = 91 //ascii 91
	if err = binary.Read(buf, binary.LittleEndian, &e.PacketLen); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.InterfaceIndex); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Uid); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Flags); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Direction); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.SocketCookie); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.CGroupID); err != nil {
		return err
	}
	// PacketLen is the original skb length. The kernel deliberately caps the
	// bytes appended to one perf sample so large GSO/loopback skbs cannot
	// overflow perf_event_header.size and desynchronise the reader.
	// cilium/perf may expose up to seven bytes of record-alignment padding
	// after RawSample. Never treat those bytes as packet data.
	capturedLength := len(buf.Bytes())
	if uint64(capturedLength) > uint64(e.PacketLen) {
		capturedLength = int(e.PacketLen)
	}
	tmpData := append([]byte(nil), buf.Bytes()[:capturedLength]...)
	e.CapturedLen = uint32(len(tmpData))
	e.PacketData = tmpData
	return nil
}

// Validate checks if the event is valid.
func (e *PacketEvent) Validate() error {
	if e.PacketLen == 0 {
		return errors.New(errors.ErrCodeEventValidation, "packet length is zero")
	}
	if len(e.PacketData) == 0 {
		return errors.New(errors.ErrCodeEventValidation, "captured packet data is empty")
	}
	if uint64(len(e.PacketData)) > uint64(e.PacketLen) {
		return errors.New(errors.ErrCodeEventValidation, "captured packet data exceeds original packet length")
	}
	return nil
}

// String returns a human-readable representation of the event.
func (e *PacketEvent) String() string {
	result := fmt.Sprintf("Packet captured: len=%d bytes, timestamp=%d, interface=%d, pid=%d, uid=%d, direction=%s, cookie=%d, flags=%#x",
		e.PacketLen, e.Timestamp, e.InterfaceIndex, e.Pid, e.Uid, e.DirectionString(), e.SocketCookie, e.Flags)
	metadata := parsePacketMetadata(e.PacketData, e.Flags)
	if metadata.srcIP != "" && metadata.dstIP != "" {
		result += fmt.Sprintf(", flow=%s:%d->%s:%d",
			metadata.srcIP, metadata.srcPort, metadata.dstIP, metadata.dstPort)
	}
	if metadata.transport != "" {
		result += ", transport=" + metadata.transport
	}
	if metadata.application != "" {
		result += ", protocol=" + metadata.application
	}
	if metadata.serverName != "" {
		result += ", server_name=" + metadata.serverName
	}
	return result
}

// StringHex returns a hexadecimal representation of the event.
func (e *PacketEvent) StringHex() string {
	return e.String()
}

// Clone creates a copy of the event.
func (e *PacketEvent) Clone() domain.Event {
	clone := &PacketEvent{
		Timestamp:      e.Timestamp,
		Pid:            e.Pid,
		Comm:           e.Comm,
		Cmdline:        e.Cmdline,
		PacketLen:      e.PacketLen,
		CapturedLen:    e.CapturedLen,
		InterfaceIndex: e.InterfaceIndex,
		Uid:            e.Uid,
		Flags:          e.Flags,
		Direction:      e.Direction,
		SocketCookie:   e.SocketCookie,
		CGroupID:       e.CGroupID,
	}
	if e.PacketData != nil {
		clone.PacketData = make([]byte, len(e.PacketData))
		copy(clone.PacketData, e.PacketData)
	}
	return clone
}

// Type returns the event type.
func (e *PacketEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

// UUID returns a unique identifier for the event.
func (e *PacketEvent) UUID() string {
	return fmt.Sprintf("packet-%d", e.Timestamp)
}

// PacketEvent interface implementation for handlers.PacketEvent
func (e *PacketEvent) GetTimestamp() uint64 {
	return e.Timestamp
}

func (e *PacketEvent) PerfMonoNs() uint64 {
	return e.Timestamp
}

func (e *PacketEvent) GetPacketData() []byte {
	return e.PacketData
}

func (e *PacketEvent) GetPacketLen() uint32 {
	return e.PacketLen
}

func (e *PacketEvent) GetInterfaceIndex() uint32 {
	return e.InterfaceIndex
}

func (e *PacketEvent) GetPacketFlags() uint32 {
	return e.Flags
}

func (e *PacketEvent) GetUID() uint32 {
	return e.Uid
}

func (e *PacketEvent) GetPID() uint32 {
	return e.Pid
}

func (e *PacketEvent) GetDirection() uint32 {
	return e.Direction
}

func (e *PacketEvent) GetSocketCookie() uint64 {
	return e.SocketCookie
}

func (e *PacketEvent) GetCGroupID() uint64 {
	return e.CGroupID
}

func (e *PacketEvent) DirectionString() string {
	if e.Direction == PacketDirectionEgress {
		return "egress"
	}
	return "ingress"
}

func (e *PacketEvent) GetSrcIP() string {
	return parsePacketMetadata(e.PacketData, e.Flags).srcIP
}

func (e *PacketEvent) GetDstIP() string {
	return parsePacketMetadata(e.PacketData, e.Flags).dstIP
}

func (e *PacketEvent) GetSrcPort() uint16 {
	return parsePacketMetadata(e.PacketData, e.Flags).srcPort
}

func (e *PacketEvent) GetDstPort() uint16 {
	return parsePacketMetadata(e.PacketData, e.Flags).dstPort
}

func (e *PacketEvent) GetTransportProtocol() string {
	return parsePacketMetadata(e.PacketData, e.Flags).transport
}

func (e *PacketEvent) GetApplicationProtocol() string {
	return parsePacketMetadata(e.PacketData, e.Flags).application
}

func (e *PacketEvent) GetServerName() string {
	return parsePacketMetadata(e.PacketData, e.Flags).serverName
}

// Decode implements domain.EventDecoder interface for packet events.
func (e *PacketEvent) Decode(data []byte) (domain.Event, error) {
	event := &PacketEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}
