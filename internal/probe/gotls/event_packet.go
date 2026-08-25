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

package gotls

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
)

const (
	TaskCommLen       = 16
	CmdlineLen        = 256
	PacketMetadataLen = 80
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
	ChunkOffset    uint32
	ChunkLen       uint32
	ChunkCount     uint32
	PacketData     []byte
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
	if err = binary.Read(buf, binary.LittleEndian, &e.CapturedLen); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.ChunkOffset); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.ChunkLen); err != nil {
		return err
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.ChunkCount); err != nil {
		return err
	}
	if uint64(e.ChunkLen) > uint64(len(buf.Bytes())) {
		return errors.New(errors.ErrCodeEventDecode, "packet fragment payload is shorter than metadata")
	}
	e.PacketData = append([]byte(nil), buf.Bytes()[:e.ChunkLen]...)
	return nil
}

// Validate checks if the event is valid.
func (e *PacketEvent) Validate() error {
	if e.PacketLen == 0 {
		return errors.New(errors.ErrCodeEventValidation, "packet length is zero")
	}
	if e.CapturedLen == 0 && e.ChunkLen == 0 && e.ChunkCount == 0 {
		e.CapturedLen = uint32(len(e.PacketData))
		e.ChunkLen = e.CapturedLen
		e.ChunkCount = 1
	}
	if len(e.PacketData) == 0 {
		return errors.New(errors.ErrCodeEventValidation, "captured packet data is empty")
	}
	if e.CapturedLen > e.PacketLen || uint32(len(e.PacketData)) != e.ChunkLen {
		return errors.New(errors.ErrCodeEventValidation, "packet fragment lengths are inconsistent")
	}
	if e.ChunkCount == 0 || e.ChunkCount > 8 {
		return errors.New(errors.ErrCodeEventValidation, "packet fragment count is invalid")
	}
	if uint64(e.ChunkOffset)+uint64(e.ChunkLen) > uint64(e.CapturedLen) {
		return errors.New(errors.ErrCodeEventValidation, "packet fragment exceeds captured packet length")
	}
	return nil
}

// String returns a human-readable representation of the event.
func (e *PacketEvent) String() string {
	return fmt.Sprintf("Packet captured: len=%d bytes, timestamp=%d, interface=%d",
		e.PacketLen, e.Timestamp, e.InterfaceIndex)
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
		ChunkOffset:    e.ChunkOffset,
		ChunkLen:       e.ChunkLen,
		ChunkCount:     e.ChunkCount,
	}
	if e.PacketData != nil {
		clone.PacketData = make([]byte, len(e.PacketData))
		copy(clone.PacketData, e.PacketData)
	}
	return clone
}

func (e *PacketEvent) packetFragment() base.PacketFragment {
	return base.PacketFragment{
		Key: base.PacketFragmentKey{
			Timestamp:      e.Timestamp,
			PID:            e.Pid,
			UID:            e.Uid,
			InterfaceIndex: e.InterfaceIndex,
			Direction:      e.Direction,
			SocketCookie:   e.SocketCookie,
			CGroupID:       e.CGroupID,
			PacketLength:   e.PacketLen,
		},
		CapturedLength: e.CapturedLen,
		Offset:         e.ChunkOffset,
		Length:         e.ChunkLen,
		Count:          e.ChunkCount,
		Data:           e.PacketData,
	}
}

func (e *PacketEvent) setAssembledPacket(packet []byte) {
	e.PacketData = packet
	e.ChunkOffset = 0
	e.ChunkLen = uint32(len(packet))
	e.CapturedLen = uint32(len(packet))
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

// Connection tuple information - these would need to be parsed from packet data
// For now, return empty values as TC captures raw packets
func (e *PacketEvent) GetSrcIP() string {
	return ""
}

func (e *PacketEvent) GetDstIP() string {
	return ""
}

func (e *PacketEvent) GetSrcPort() uint16 {
	return 0
}

func (e *PacketEvent) GetDstPort() uint16 {
	return 0
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
