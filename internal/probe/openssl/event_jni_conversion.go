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
	"strings"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	JNIConversionFlagHasBuffer               = 0x01
	JNIConversionFlagHasLength               = 0x02
	JNIConversionFlagHasData                 = 0x04
	JNIConversionFlagTruncated               = 0x08
	JNIConversionFlagJoined                  = 0x10
	JNIConversionFlagLengthLowerBound        = 0x20
	JNIConversionFlagLengthIsElements        = 0x40
	JNIConversionMaxSegments                 = 8
	JNIConversionMaxData                     = JNIConversionMaxSegments * MaxDataSize
	JNIConversionPhaseAcquire         uint32 = 1
	JNIConversionPhaseRelease         uint32 = 2
	JNIConversionPhaseRegion          uint32 = 3
	JNIConversionPhaseLength          uint32 = 4
)

var jniConversionRoleNames = map[uint32]string{
	1:  JNIConversionGetStringLength,
	2:  JNIConversionGetStringChars,
	3:  JNIConversionReleaseStringChars,
	4:  JNIConversionGetStringUTFLength,
	5:  JNIConversionGetStringUTFChars,
	6:  JNIConversionReleaseStringUTFChars,
	7:  JNIConversionGetArrayLength,
	8:  JNIConversionGetByteArrayElements,
	9:  JNIConversionReleaseByteArrayElements,
	10: JNIConversionGetByteArrayRegion,
	11: JNIConversionSetByteArrayRegion,
	12: JNIConversionGetPrimitiveArrayCritical,
	13: JNIConversionReleasePrimitiveArrayCritical,
	14: JNIConversionGetStringCritical,
	15: JNIConversionReleaseStringCritical,
	16: JNIConversionGetDirectBufferAddress,
	17: JNIConversionGetDirectBufferCapacity,
}

// JNIConversionEvent records a standard JNI managed-reference conversion.
// The fixed fields through Comm match struct jni_conversion_event_t. Metadata
// events intentionally omit the large trailing Data array on the perf ring.
type JNIConversionEvent struct {
	Timestamp    uint64            `json:"timestamp"`
	Env          uint64            `json:"env"`
	Object       uint64            `json:"object"`
	BufferAddr   uint64            `json:"bufferAddr"`
	CallerAddr   uint64            `json:"callerAddr"`
	ByteLength   uint64            `json:"byteLength"`
	ElementCount uint64            `json:"elementCount"`
	RegionStart  uint64            `json:"regionStart"`
	Pid          uint32            `json:"pid"`
	Tid          uint32            `json:"tid"`
	Role         uint32            `json:"role"`
	Phase        uint32            `json:"phase"`
	Flags        uint32            `json:"flags"`
	CapturedLen  uint32            `json:"capturedLen"`
	ChunkOffset  uint32            `json:"chunkOffset"`
	DataLen      uint32            `json:"dataLen"`
	Comm         [TaskCommLen]byte `json:"comm"`
	Data         [MaxDataSize]byte `json:"data"`

	CallerModulePath          string `json:"callerModulePath,omitempty"`
	CallerModuleOffset        uint64 `json:"callerModuleOffset,omitempty"`
	CallerModuleBuildID       string `json:"callerModuleBuildID,omitempty"`
	CallerModuleBuildIDError  string `json:"callerModuleBuildIDError,omitempty"`
	ModuleResolutionError     string `json:"moduleResolutionError,omitempty"`
	CallerFilterActive        bool   `json:"callerFilterActive,omitempty"`
	CallerFilterJustActivated bool   `json:"callerFilterJustActivated,omitempty"`
	CallerFilterPendingRules  uint32 `json:"callerFilterPendingRules,omitempty"`
	CallerFilterError         string `json:"callerFilterError,omitempty"`
}

func (e JNIConversionEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		EventType                 string `json:"eventType"`
		CaptureLayer              string `json:"captureLayer"`
		Timestamp                 uint64 `json:"timestamp"`
		Env                       uint64 `json:"env"`
		Object                    uint64 `json:"object"`
		BufferAddr                uint64 `json:"bufferAddr,omitempty"`
		CallerAddr                uint64 `json:"callerAddr,omitempty"`
		ByteLength                uint64 `json:"byteLength,omitempty"`
		ElementCount              uint64 `json:"elementCount,omitempty"`
		RegionStart               uint64 `json:"regionStart,omitempty"`
		Pid                       uint32 `json:"pid"`
		Tid                       uint32 `json:"tid"`
		Role                      string `json:"role"`
		Phase                     string `json:"phase"`
		Flags                     uint32 `json:"flags"`
		LengthExact               bool   `json:"lengthExact"`
		LengthUnit                string `json:"lengthUnit"`
		CapturedLen               uint32 `json:"capturedLen,omitempty"`
		ChunkOffset               uint32 `json:"chunkOffset,omitempty"`
		DataLen                   uint32 `json:"dataLen,omitempty"`
		Comm                      string `json:"comm"`
		DataEncoding              string `json:"dataEncoding,omitempty"`
		Data                      []byte `json:"data,omitempty"`
		CallerModulePath          string `json:"callerModulePath,omitempty"`
		CallerModuleOffset        uint64 `json:"callerModuleOffset,omitempty"`
		CallerModuleBuildID       string `json:"callerModuleBuildID,omitempty"`
		CallerModuleBuildIDError  string `json:"callerModuleBuildIDError,omitempty"`
		ModuleResolutionError     string `json:"moduleResolutionError,omitempty"`
		CallerFilterActive        bool   `json:"callerFilterActive,omitempty"`
		CallerFilterJustActivated bool   `json:"callerFilterJustActivated,omitempty"`
		CallerFilterPendingRules  uint32 `json:"callerFilterPendingRules,omitempty"`
		CallerFilterError         string `json:"callerFilterError,omitempty"`
	}{
		EventType:                 "jni_conversion",
		CaptureLayer:              CaptureLayerSemantic,
		Timestamp:                 e.Timestamp,
		Env:                       e.Env,
		Object:                    e.Object,
		BufferAddr:                e.BufferAddr,
		CallerAddr:                e.CallerAddr,
		ByteLength:                e.ByteLength,
		ElementCount:              e.ElementCount,
		RegionStart:               e.RegionStart,
		Pid:                       e.Pid,
		Tid:                       e.Tid,
		Role:                      e.RoleName(),
		Phase:                     e.PhaseName(),
		Flags:                     e.Flags,
		LengthExact:               e.Flags&JNIConversionFlagLengthLowerBound == 0,
		LengthUnit:                e.LengthUnit(),
		CapturedLen:               e.CapturedLen,
		ChunkOffset:               e.ChunkOffset,
		DataLen:                   e.DataLen,
		Comm:                      commToString(e.Comm[:]),
		DataEncoding:              dataEncoding(e.DataLen),
		Data:                      e.GetData(),
		CallerModulePath:          e.CallerModulePath,
		CallerModuleOffset:        e.CallerModuleOffset,
		CallerModuleBuildID:       e.CallerModuleBuildID,
		CallerModuleBuildIDError:  e.CallerModuleBuildIDError,
		ModuleResolutionError:     e.ModuleResolutionError,
		CallerFilterActive:        e.CallerFilterActive,
		CallerFilterJustActivated: e.CallerFilterJustActivated,
		CallerFilterPendingRules:  e.CallerFilterPendingRules,
		CallerFilterError:         e.CallerFilterError,
	})
}

func dataEncoding(length uint32) string {
	if length == 0 {
		return ""
	}
	return "base64"
}

func jniConversionRoleID(role string) (uint32, bool) {
	role = strings.ToLower(strings.TrimSpace(role))
	for id, name := range jniConversionRoleNames {
		if name == role {
			return id, true
		}
	}
	return 0, false
}

func (e *JNIConversionEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewReader(data)
	fields := []struct {
		name  string
		value any
	}{
		{"Timestamp", &e.Timestamp},
		{"Env", &e.Env},
		{"Object", &e.Object},
		{"BufferAddr", &e.BufferAddr},
		{"CallerAddr", &e.CallerAddr},
		{"ByteLength", &e.ByteLength},
		{"ElementCount", &e.ElementCount},
		{"RegionStart", &e.RegionStart},
		{"Pid", &e.Pid},
		{"Tid", &e.Tid},
		{"Role", &e.Role},
		{"Phase", &e.Phase},
		{"Flags", &e.Flags},
		{"CapturedLen", &e.CapturedLen},
		{"ChunkOffset", &e.ChunkOffset},
		{"DataLen", &e.DataLen},
		{"Comm", &e.Comm},
	}
	for _, field := range fields {
		if err := binary.Read(buf, binary.LittleEndian, field.value); err != nil {
			return errors.NewEventDecodeError(
				"openssl.JNIConversionEvent."+field.name,
				err,
			)
		}
	}
	remaining := buf.Len()
	if remaining == 0 || e.DataLen == 0 {
		return nil
	}
	if e.DataLen > MaxDataSize {
		return errors.NewEventDecodeError(
			"openssl.JNIConversionEvent.Data",
			fmt.Errorf("payload length %d exceeds maximum %d", e.DataLen, MaxDataSize),
		)
	}
	if remaining < int(e.DataLen) {
		return errors.NewEventDecodeError(
			"openssl.JNIConversionEvent.Data",
			fmt.Errorf(
				"short payload sample: trailing=%d want_at_least=%d total_sample=%d",
				remaining,
				e.DataLen,
				len(data),
			),
		)
	}
	copyLen := remaining
	if copyLen > MaxDataSize {
		copyLen = MaxDataSize
	}
	if _, err := buf.Read(e.Data[:copyLen]); err != nil {
		return errors.NewEventDecodeError(
			"openssl.JNIConversionEvent.Data",
			err,
		)
	}
	return nil
}

func (e *JNIConversionEvent) PerfMonoNs() uint64 {
	return e.Timestamp
}

func (e *JNIConversionEvent) String() string {
	caller := fmt.Sprintf("0x%x", e.CallerAddr)
	if e.CallerModulePath != "" {
		caller = fmt.Sprintf(
			"%s+0x%x",
			e.CallerModulePath,
			e.CallerModuleOffset,
		)
	}
	summary := fmt.Sprintf(
		"bytes=%d elements=%d",
		e.ByteLength,
		e.ElementCount,
	)
	if e.DataLen != 0 {
		summary += fmt.Sprintf(
			" chunk=%d+%d captured=%d",
			e.ChunkOffset,
			e.DataLen,
			e.CapturedLen,
		)
	}
	return fmt.Sprintf(
		"[%s] PID:%d TID:%d Comm:%s JNI:%s/%s object=0x%x buffer=0x%x caller=%s (%s)\n%s",
		e.eventTime().Format("2006-01-02 15:04:05.000"),
		e.Pid,
		e.Tid,
		commToString(e.Comm[:]),
		e.RoleName(),
		e.PhaseName(),
		e.Object,
		e.BufferAddr,
		caller,
		summary,
		string(e.GetData()),
	)
}

func (e *JNIConversionEvent) StringHex() string {
	return fmt.Sprintf("%s%s", e.String(), dumpByteSlice(e.GetData(), ""))
}

func (e *JNIConversionEvent) Clone() domain.Event {
	clone := *e
	return &clone
}

func (e *JNIConversionEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

func (e *JNIConversionEvent) UUID() string {
	return fmt.Sprintf(
		"jni_conversion_%d_%d_%d_%x_%d",
		e.Pid,
		e.Tid,
		e.Role,
		e.Object,
		e.Timestamp,
	)
}

func (e *JNIConversionEvent) Validate() error {
	if e.Pid == 0 || e.Tid == 0 {
		return errors.New(
			errors.ErrCodeEventValidation,
			"JNI conversion event has an empty process or thread ID",
		)
	}
	if e.Env == 0 || e.Object == 0 {
		return errors.New(
			errors.ErrCodeEventValidation,
			"JNI conversion event has an empty JNIEnv or object reference",
		)
	}
	if _, found := jniConversionRoleNames[e.Role]; !found {
		return errors.New(
			errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid JNI conversion role: %d", e.Role),
		)
	}
	switch e.Phase {
	case JNIConversionPhaseAcquire,
		JNIConversionPhaseRelease,
		JNIConversionPhaseRegion,
		JNIConversionPhaseLength:
	default:
		return errors.New(
			errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid JNI conversion phase: %d", e.Phase),
		)
	}
	if e.DataLen == 0 {
		if e.CapturedLen != 0 || e.Flags&JNIConversionFlagHasData != 0 {
			return errors.New(
				errors.ErrCodeEventValidation,
				"JNI conversion metadata event claims captured data",
			)
		}
		return nil
	}
	upperBound := uint64(e.ChunkOffset) + uint64(e.DataLen)
	if e.DataLen > MaxDataSize ||
		upperBound > uint64(JNIConversionMaxData) ||
		e.CapturedLen > JNIConversionMaxData {
		return errors.New(
			errors.ErrCodeEventValidation,
			fmt.Sprintf(
				"invalid JNI conversion capture range %d+%d/%d",
				e.ChunkOffset,
				e.DataLen,
				e.CapturedLen,
			),
		)
	}
	if e.CapturedLen < uint32(upperBound) {
		e.CapturedLen = uint32(upperBound)
	}
	if e.Flags&JNIConversionFlagHasData == 0 ||
		e.Flags&JNIConversionFlagHasBuffer == 0 ||
		e.BufferAddr == 0 {
		return errors.New(
			errors.ErrCodeEventValidation,
			"JNI conversion payload lacks data or buffer flags",
		)
	}
	return nil
}

func (e *JNIConversionEvent) GetData() []byte {
	if e.DataLen == 0 {
		return nil
	}
	if e.DataLen > MaxDataSize {
		return e.Data[:]
	}
	return e.Data[:e.DataLen]
}

func (e *JNIConversionEvent) RoleName() string {
	if name, found := jniConversionRoleNames[e.Role]; found {
		return name
	}
	return fmt.Sprintf("unknown_%d", e.Role)
}

func (e *JNIConversionEvent) PhaseName() string {
	switch e.Phase {
	case JNIConversionPhaseAcquire:
		return "acquire"
	case JNIConversionPhaseRelease:
		return "release"
	case JNIConversionPhaseRegion:
		return "region"
	case JNIConversionPhaseLength:
		return "length"
	default:
		return fmt.Sprintf("unknown_%d", e.Phase)
	}
}

func (e *JNIConversionEvent) LengthUnit() string {
	if e.Flags&JNIConversionFlagLengthIsElements != 0 &&
		e.ByteLength == 0 {
		return "elements"
	}
	return "bytes"
}

func (e *JNIConversionEvent) eventTime() time.Time {
	offsetNs, err := getClockOffset()
	if err != nil {
		return time.Unix(0, int64(e.Timestamp))
	}
	return time.Unix(0, int64(e.Timestamp)+offsetNs)
}
