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
)

// applicationDataBPFConfig must stay byte-for-byte compatible with
// struct app_hook_config_t in kern/app_data.h.
type applicationDataBPFConfig struct {
	BufferArg    uint32
	LengthArg    uint32
	Direction    uint32
	Flags        uint32
	BufferOffset uint64
	LengthOffset uint64
	LengthSize   uint32
	MaxBytes     uint32
	StateID      uint32
	StateKeyArg  uint32
}

func (h ApplicationDataHook) bpfConfig() applicationDataBPFConfig {
	var flags uint32
	if h.BufferIndirect {
		flags |= appDataFlagBufferIndirect
	}
	if h.BufferFormat == AppDataBufferLibCXX {
		flags |= appDataFlagBufferLibCXX
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

	direction := uint32(DataTypeRead)
	if h.Direction == AppDataDirectionWrite {
		direction = DataTypeWrite
	}
	return applicationDataBPFConfig{
		BufferArg:    h.BufferArg,
		LengthArg:    h.bpfLengthArg(),
		Direction:    direction,
		Flags:        flags,
		BufferOffset: uint64(h.BufferOffset),
		LengthOffset: uint64(h.LengthOffset),
		LengthSize:   h.LengthSize,
		MaxBytes:     h.MaxBytes,
		StateID:      h.stateID,
		StateKeyArg:  h.StateKeyArg,
	}
}

func (h ApplicationDataHook) bpfLengthArg() uint32 {
	if h.LengthSource == AppDataLengthFixed {
		return h.FixedLength
	}
	return h.LengthArg
}
