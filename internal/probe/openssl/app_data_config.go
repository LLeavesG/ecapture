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

const (
	appDataFlagBufferIndirect uint32 = 1 << iota
	appDataFlagLengthMemory
	appDataFlagLengthReturn
	appDataFlagCaptureReturn
	appDataFlagLengthIndirect
	appDataFlagLengthFixed
	appDataFlagBufferLibCXX
	appDataFlagStateSave
	appDataFlagStateLoad
	appDataFlagBufferIOVec
	appDataFlagBufferMsgHdr
	appDataFlagUserStack
)

// applicationDataBPFConfig must stay byte-for-byte compatible with
// struct app_hook_config_t in kern/app_data.h.
type applicationDataBPFConfig struct {
	BufferArg              uint32
	LengthArg              uint32
	Direction              uint32
	Flags                  uint32
	BufferOffset           uint64
	LengthOffset           uint64
	LengthSize             uint32
	MaxBytes               uint32
	StateID                uint32
	StateKeyArg            uint32
	ContextArg             uint32
	StreamArg              uint32
	VectorCountArg         uint32
	Reserved               uint32
	ContextOffset          uint64
	StreamOffset           uint64
	ContextSize            uint32
	StreamSize             uint32
	VectorStride           uint32
	VectorBaseOffset       uint32
	VectorLengthOffset     uint32
	VectorLengthSize       uint32
	StreamByteOffsetArg    uint32
	StreamByteOffsetSize   uint32
	StreamByteOffsetOffset uint64
	FinArg                 uint32
	FinSize                uint32
	FinOffset              uint64
}

func (h ApplicationDataHook) bpfConfig() applicationDataBPFConfig {
	var flags uint32
	if h.BufferIndirect {
		flags |= appDataFlagBufferIndirect
	}
	if h.BufferFormat == AppDataBufferLibCXX {
		flags |= appDataFlagBufferLibCXX
	}
	if h.BufferFormat == AppDataBufferIOVec ||
		h.BufferFormat == AppDataBufferVector {
		flags |= appDataFlagBufferIOVec
	}
	if h.BufferFormat == AppDataBufferMsgHdr {
		flags |= appDataFlagBufferMsgHdr
	}
	switch h.StateAction {
	case AppDataStateSave:
		flags |= appDataFlagStateSave
	case AppDataStateLoad:
		flags |= appDataFlagStateLoad
	}
	switch h.LengthSource {
	case AppDataLengthMemory:
		flags |= appDataFlagLengthMemory
	case AppDataLengthReturn:
		flags |= appDataFlagLengthReturn
	case AppDataLengthFixed:
		flags |= appDataFlagLengthFixed
	}
	if h.CaptureOn == AppDataCaptureReturn {
		flags |= appDataFlagCaptureReturn
	}
	if h.LengthIndirect {
		flags |= appDataFlagLengthIndirect
	}
	if h.CollectUserStack {
		flags |= appDataFlagUserStack
	}

	direction := uint32(DataTypeRead)
	if h.Direction == AppDataDirectionWrite {
		direction = DataTypeWrite
	}
	vectorStride := h.VectorStride
	vectorLengthOffset := h.VectorLengthOffset
	vectorLengthSize := h.VectorLengthSize
	if (h.BufferFormat == AppDataBufferIOVec ||
		h.BufferFormat == AppDataBufferMsgHdr) && vectorStride == 0 {
		vectorStride = 16
		vectorLengthOffset = 8
		vectorLengthSize = 8
	}
	return applicationDataBPFConfig{
		BufferArg:              h.BufferArg,
		LengthArg:              h.bpfLengthArg(),
		Direction:              direction,
		Flags:                  flags,
		BufferOffset:           uint64(h.BufferOffset),
		LengthOffset:           uint64(h.LengthOffset),
		LengthSize:             h.LengthSize,
		MaxBytes:               h.MaxBytes,
		StateID:                h.stateID,
		StateKeyArg:            h.StateKeyArg,
		ContextArg:             h.ContextArg,
		StreamArg:              h.StreamArg,
		VectorCountArg:         h.VectorCountArg,
		ContextOffset:          uint64(h.ContextOffset),
		StreamOffset:           uint64(h.StreamOffset),
		ContextSize:            h.ContextSize,
		StreamSize:             h.StreamSize,
		VectorStride:           vectorStride,
		VectorBaseOffset:       h.VectorBaseOffset,
		VectorLengthOffset:     vectorLengthOffset,
		VectorLengthSize:       vectorLengthSize,
		StreamByteOffsetArg:    h.StreamByteOffsetArg,
		StreamByteOffsetSize:   h.StreamByteOffsetSize,
		StreamByteOffsetOffset: uint64(h.StreamByteOffsetOffset),
		FinArg:                 h.FinArg,
		FinSize:                h.FinSize,
		FinOffset:              uint64(h.FinOffset),
	}
}

func (h ApplicationDataHook) bpfLengthArg() uint32 {
	if h.LengthSource == AppDataLengthFixed {
		return h.FixedLength
	}
	return h.LengthArg
}
