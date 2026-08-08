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
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	AppDataEventFlagTruncated       = 1
	AppDataStreamFlagOffsetValid    = 1
	AppDataStreamFlagFinValid       = 2
	AppDataStreamFlagFin            = 4
	AppDataMaxStackDepth            = 16
	appDataStreamFlagsSupportedMask = AppDataStreamFlagOffsetValid |
		AppDataStreamFlagFinValid |
		AppDataStreamFlagFin
)

// ApplicationDataEvent is the historical internal name for an event emitted
// by the generic profile-defined hook engine. Structured output distinguishes
// evidence-bearing boundary_data from optional semantic application_data.
// The serialized fields through Data exactly match struct app_data_event_t.
type ApplicationDataEvent struct {
	Timestamp       uint64                       `json:"timestamp"`
	BufferAddr      uint64                       `json:"bufferAddr"`
	ContextID       uint64                       `json:"contextId"`
	StreamID        uint64                       `json:"streamId"`
	StreamOffset    uint64                       `json:"streamOffset"`
	StreamFlags     uint32                       `json:"streamFlags"`
	Pid             uint32                       `json:"pid"`
	Tid             uint32                       `json:"tid"`
	HookID          uint32                       `json:"hookId"`
	Direction       uint32                       `json:"direction"`
	Flags           uint32                       `json:"flags"`
	OriginalLen     uint32                       `json:"originalLen"`
	CapturedLen     uint32                       `json:"capturedLen"`
	ChunkOffset     uint32                       `json:"chunkOffset"`
	DataLen         uint32                       `json:"dataLen"`
	Comm            [TaskCommLen]byte            `json:"comm"`
	UserStackStatus int32                        `json:"userStackStatus"`
	UserStackDepth  uint32                       `json:"userStackDepth"`
	UserStack       [AppDataMaxStackDepth]uint64 `json:"userStack"`
	UserStackMode   string                       `json:"userStackMode,omitempty"`
	Data            [MaxDataSize]byte            `json:"data"`
	HookName        string                       `json:"hookName,omitempty"`
	CaptureLayer    string                       `json:"captureLayer,omitempty"`
	Transport       string                       `json:"transport,omitempty"`
	BoundaryRole    string                       `json:"boundaryRole,omitempty"`
	StackFrames     []ApplicationDataStackFrame  `json:"stackFrames,omitempty"`
}

// ApplicationDataStackFrame is an ASLR-stable representation of one optional
// discovery call-chain entry. Address remains available when module resolution
// is incomplete; profiles should pin ModuleOffset together with BuildID.
type ApplicationDataStackFrame struct {
	Address         uint64 `json:"address"`
	ModulePath      string `json:"modulePath,omitempty"`
	ModuleOffset    uint64 `json:"moduleOffset,omitempty"`
	ModuleBuildID   string `json:"moduleBuildId,omitempty"`
	ResolutionError string `json:"resolutionError,omitempty"`
}

// MarshalJSON emits only the valid payload slice. Encoding a fixed 16 KiB
// array would turn every byte into a JSON number and make structured capture
// impractical; []byte is represented compactly as base64 by encoding/json.
func (e ApplicationDataEvent) MarshalJSON() ([]byte, error) {
	eventType := "boundary_data"
	if e.CaptureLayer == "" || e.CaptureLayer == CaptureLayerSemantic {
		eventType = "application_data"
	}
	var streamOffset *uint64
	if e.HasStreamOffset() {
		value := e.StreamOffset
		streamOffset = &value
	}
	var fin *bool
	if e.HasFin() {
		value := e.IsFin()
		fin = &value
	}
	return json.Marshal(struct {
		EventType       string                      `json:"eventType"`
		CaptureLayer    string                      `json:"captureLayer"`
		Transport       string                      `json:"transport,omitempty"`
		BoundaryRole    string                      `json:"boundaryRole,omitempty"`
		Timestamp       uint64                      `json:"timestamp"`
		WallTime        string                      `json:"wallTime,omitempty"`
		BufferAddr      uint64                      `json:"bufferAddr"`
		ContextID       uint64                      `json:"contextId,omitempty"`
		StreamID        uint64                      `json:"streamId,omitempty"`
		StreamOffset    *uint64                     `json:"streamOffset,omitempty"`
		Fin             *bool                       `json:"fin,omitempty"`
		Pid             uint32                      `json:"pid"`
		Tid             uint32                      `json:"tid"`
		HookID          uint32                      `json:"hookId"`
		HookName        string                      `json:"hookName,omitempty"`
		Direction       string                      `json:"direction"`
		Flags           uint32                      `json:"flags"`
		OriginalLen     uint32                      `json:"originalLen"`
		CapturedLen     uint32                      `json:"capturedLen"`
		ChunkOffset     uint32                      `json:"chunkOffset"`
		DataLen         uint32                      `json:"dataLen"`
		Comm            string                      `json:"comm"`
		UserStackStatus int32                       `json:"userStackStatus,omitempty"`
		UserStackDepth  uint32                      `json:"userStackDepth,omitempty"`
		UserStackMode   string                      `json:"userStackMode,omitempty"`
		StackFrames     []ApplicationDataStackFrame `json:"userStack,omitempty"`
		DataEncoding    string                      `json:"dataEncoding"`
		Data            []byte                      `json:"data"`
	}{
		EventType:       eventType,
		CaptureLayer:    e.CaptureLayer,
		Transport:       e.Transport,
		BoundaryRole:    e.BoundaryRole,
		Timestamp:       e.Timestamp,
		WallTime:        wallTimeFromMonotonic(e.Timestamp),
		BufferAddr:      e.BufferAddr,
		ContextID:       e.ContextID,
		StreamID:        e.StreamID,
		StreamOffset:    streamOffset,
		Fin:             fin,
		Pid:             e.Pid,
		Tid:             e.Tid,
		HookID:          e.HookID,
		HookName:        e.HookName,
		Direction:       e.directionName(),
		Flags:           e.Flags,
		OriginalLen:     e.OriginalLen,
		CapturedLen:     e.CapturedLen,
		ChunkOffset:     e.ChunkOffset,
		DataLen:         e.DataLen,
		Comm:            commToString(e.Comm[:]),
		UserStackStatus: e.UserStackStatus,
		UserStackDepth:  e.UserStackDepth,
		UserStackMode:   e.UserStackMode,
		StackFrames:     e.StackFrames,
		DataEncoding:    "base64",
		Data:            e.GetData(),
	})
}

func (e *ApplicationDataEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewReader(data)
	fields := []struct {
		name  string
		value any
	}{
		{"Timestamp", &e.Timestamp},
		{"BufferAddr", &e.BufferAddr},
		{"ContextID", &e.ContextID},
		{"StreamID", &e.StreamID},
		{"StreamOffset", &e.StreamOffset},
		{"StreamFlags", &e.StreamFlags},
		{"Pid", &e.Pid},
		{"Tid", &e.Tid},
		{"HookID", &e.HookID},
		{"Direction", &e.Direction},
		{"Flags", &e.Flags},
		{"OriginalLen", &e.OriginalLen},
		{"CapturedLen", &e.CapturedLen},
		{"ChunkOffset", &e.ChunkOffset},
		{"DataLen", &e.DataLen},
		{"Comm", &e.Comm},
		{"UserStackStatus", &e.UserStackStatus},
		{"UserStackDepth", &e.UserStackDepth},
		{"UserStack", &e.UserStack},
	}
	for _, field := range fields {
		if err := binary.Read(buf, binary.LittleEndian, field.value); err != nil {
			return errors.NewEventDecodeError("openssl.ApplicationDataEvent."+field.name, err)
		}
	}
	if e.DataLen > MaxDataSize {
		return errors.NewEventDecodeError(
			"openssl.ApplicationDataEvent.Data",
			fmt.Errorf("data length %d exceeds maximum %d", e.DataLen, MaxDataSize),
		)
	}
	if e.UserStackDepth > AppDataMaxStackDepth {
		return errors.NewEventDecodeError(
			"openssl.ApplicationDataEvent.UserStackDepth",
			fmt.Errorf("stack depth %d exceeds maximum %d",
				e.UserStackDepth, AppDataMaxStackDepth),
		)
	}
	if _, err := io.ReadFull(buf, e.Data[:e.DataLen]); err != nil {
		return errors.NewEventDecodeError("openssl.ApplicationDataEvent.Data", err)
	}
	return nil
}

func (e *ApplicationDataEvent) PerfMonoNs() uint64 {
	return e.Timestamp
}

func (e *ApplicationDataEvent) String() string {
	return fmt.Sprintf("[%s] PID:%d TID:%d Comm:%s CAPTURE-HOOK:%s[%d] Buffer:0x%x%s %s (%s):\n%s",
		e.eventTime().Format("2006-01-02 15:04:05.000"),
		e.Pid,
		e.Tid,
		commToString(e.Comm[:]),
		e.displayHookName(),
		e.HookID,
		e.BufferAddr,
		e.correlationSummary(),
		e.directionName(),
		e.captureSummary(),
		string(e.GetData()),
	)
}

func (e *ApplicationDataEvent) StringHex() string {
	return fmt.Sprintf("[%s] PID:%d TID:%d Comm:%s CAPTURE-HOOK:%s[%d] Buffer:0x%x%s %s (%s, hex):\n%s",
		e.eventTime().Format("2006-01-02 15:04:05.000"),
		e.Pid,
		e.Tid,
		commToString(e.Comm[:]),
		e.displayHookName(),
		e.HookID,
		e.BufferAddr,
		e.correlationSummary(),
		e.directionName(),
		e.captureSummary(),
		dumpByteSlice(e.GetData(), ""),
	)
}

func (e *ApplicationDataEvent) Clone() domain.Event {
	clone := *e
	return &clone
}

func (e *ApplicationDataEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

func (e *ApplicationDataEvent) UUID() string {
	return fmt.Sprintf("%d_app_%d_%x_%x_%d_%d",
		e.Pid, e.HookID, e.ContextID, e.StreamID, e.Timestamp, e.ChunkOffset)
}

func (e *ApplicationDataEvent) Validate() error {
	if e.HookID >= MaxApplicationHooks {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid application data hook id: %d", e.HookID))
	}
	if e.Direction != DataTypeRead && e.Direction != DataTypeWrite {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid application data direction: %d", e.Direction))
	}
	if e.StreamFlags&^uint32(appDataStreamFlagsSupportedMask) != 0 {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid application stream flags: %#x", e.StreamFlags))
	}
	if e.StreamFlags&AppDataStreamFlagFin != 0 && !e.HasFin() {
		return errors.New(errors.ErrCodeEventValidation,
			"application stream FIN value is missing the FIN-valid flag")
	}
	finOnly := e.DataLen == 0 &&
		e.CapturedLen == 0 &&
		e.OriginalLen == 0 &&
		e.HasFin() &&
		e.IsFin()
	if (!finOnly && e.DataLen == 0) || e.DataLen > MaxDataSize {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid application data length: %d", e.DataLen))
	}
	if (!finOnly && e.CapturedLen == 0) || e.CapturedLen > MaxApplicationData {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid application captured length: %d", e.CapturedLen))
	}
	if e.OriginalLen < e.CapturedLen {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("application original length %d is smaller than captured length %d",
				e.OriginalLen, e.CapturedLen))
	}
	if uint64(e.ChunkOffset)+uint64(e.DataLen) > uint64(e.CapturedLen) {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("application chunk range %d..%d exceeds captured length %d",
				e.ChunkOffset, uint64(e.ChunkOffset)+uint64(e.DataLen), e.CapturedLen))
	}
	if e.OriginalLen > e.CapturedLen && !e.IsTruncated() {
		return errors.New(errors.ErrCodeEventValidation,
			"truncated application data capture is missing the truncated flag")
	}
	return nil
}

func (e *ApplicationDataEvent) GetData() []byte {
	if e.DataLen > MaxDataSize {
		return e.Data[:]
	}
	return e.Data[:e.DataLen]
}

func (e *ApplicationDataEvent) IsTruncated() bool {
	return e.Flags&AppDataEventFlagTruncated != 0
}

func (e *ApplicationDataEvent) HasStreamOffset() bool {
	return e.StreamFlags&AppDataStreamFlagOffsetValid != 0
}

func (e *ApplicationDataEvent) HasFin() bool {
	return e.StreamFlags&AppDataStreamFlagFinValid != 0
}

func (e *ApplicationDataEvent) IsFin() bool {
	return e.StreamFlags&AppDataStreamFlagFin != 0
}

func (e *ApplicationDataEvent) displayHookName() string {
	if e.HookName != "" {
		return e.HookName
	}
	return "unknown"
}

func (e *ApplicationDataEvent) directionName() string {
	if e.Direction == DataTypeRead {
		return "READ"
	}
	return "WRITE"
}

func (e *ApplicationDataEvent) captureSummary() string {
	suffix := ""
	if e.IsTruncated() {
		suffix = ", truncated"
	}
	return fmt.Sprintf("chunk=%d+%d call=%d/%d bytes%s",
		e.ChunkOffset, e.DataLen, e.CapturedLen, e.OriginalLen, suffix)
}

func (e *ApplicationDataEvent) correlationSummary() string {
	streamMetadata := ""
	if e.HasStreamOffset() {
		streamMetadata += fmt.Sprintf(" Offset:%d", e.StreamOffset)
	}
	if e.HasFin() {
		streamMetadata += fmt.Sprintf(" FIN:%t", e.IsFin())
	}
	switch {
	case e.ContextID != 0 && e.StreamID != 0:
		return fmt.Sprintf(" Context:0x%x Stream:%d%s",
			e.ContextID, e.StreamID, streamMetadata)
	case e.ContextID != 0:
		return fmt.Sprintf(" Context:0x%x%s", e.ContextID, streamMetadata)
	case e.StreamID != 0:
		return fmt.Sprintf(" Stream:%d%s", e.StreamID, streamMetadata)
	default:
		return streamMetadata
	}
}

func (e *ApplicationDataEvent) eventTime() time.Time {
	offsetNs, err := getClockOffset()
	if err != nil {
		return time.Unix(0, int64(e.Timestamp))
	}
	return time.Unix(0, int64(e.Timestamp)+offsetNs)
}
