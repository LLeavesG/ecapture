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
	"fmt"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const AppDataEventFlagTruncated = 1

// ApplicationDataEvent is emitted by a profile-defined application data hook.
// The serialized fields through Data exactly match struct app_data_event_t.
type ApplicationDataEvent struct {
	Timestamp   uint64            `json:"timestamp"`
	BufferAddr  uint64            `json:"bufferAddr"`
	Pid         uint32            `json:"pid"`
	Tid         uint32            `json:"tid"`
	HookID      uint32            `json:"hookId"`
	Direction   uint32            `json:"direction"`
	Flags       uint32            `json:"flags"`
	OriginalLen uint32            `json:"originalLen"`
	CapturedLen uint32            `json:"capturedLen"`
	ChunkOffset uint32            `json:"chunkOffset"`
	DataLen     uint32            `json:"dataLen"`
	Comm        [TaskCommLen]byte `json:"comm"`
	Data        [MaxDataSize]byte `json:"data"`
	HookName    string            `json:"hookName,omitempty"`
}

func (e *ApplicationDataEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewReader(data)
	fields := []struct {
		name  string
		value any
	}{
		{"Timestamp", &e.Timestamp},
		{"BufferAddr", &e.BufferAddr},
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
		{"Data", &e.Data},
	}
	for _, field := range fields {
		if err := binary.Read(buf, binary.LittleEndian, field.value); err != nil {
			return errors.NewEventDecodeError("openssl.ApplicationDataEvent."+field.name, err)
		}
	}
	return nil
}

func (e *ApplicationDataEvent) PerfMonoNs() uint64 {
	return e.Timestamp
}

func (e *ApplicationDataEvent) String() string {
	return fmt.Sprintf("[%s] PID:%d TID:%d Comm:%s APP-HOOK:%s[%d] Buffer:0x%x %s (%s):\n%s",
		e.eventTime().Format("2006-01-02 15:04:05.000"),
		e.Pid,
		e.Tid,
		commToString(e.Comm[:]),
		e.displayHookName(),
		e.HookID,
		e.BufferAddr,
		e.directionName(),
		e.captureSummary(),
		string(e.GetData()),
	)
}

func (e *ApplicationDataEvent) StringHex() string {
	return fmt.Sprintf("[%s] PID:%d TID:%d Comm:%s APP-HOOK:%s[%d] Buffer:0x%x %s (%s, hex):\n%s",
		e.eventTime().Format("2006-01-02 15:04:05.000"),
		e.Pid,
		e.Tid,
		commToString(e.Comm[:]),
		e.displayHookName(),
		e.HookID,
		e.BufferAddr,
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
	return fmt.Sprintf("%d_app_%d_%x_%d_%d",
		e.Pid, e.HookID, e.BufferAddr, e.Timestamp, e.ChunkOffset)
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
	if e.DataLen == 0 || e.DataLen > MaxDataSize {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid application data length: %d", e.DataLen))
	}
	if e.CapturedLen == 0 || e.CapturedLen > MaxApplicationData {
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

func (e *ApplicationDataEvent) eventTime() time.Time {
	offsetNs, err := getClockOffset()
	if err != nil {
		return time.Unix(0, int64(e.Timestamp))
	}
	return time.Unix(0, int64(e.Timestamp)+offsetNs)
}
