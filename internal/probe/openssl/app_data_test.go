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
	"testing"

	manager "github.com/gojue/ebpfmanager"
)

func TestApplicationDataHookValidationAndBPFConfig(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "cronet-app",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyAppData}},
		DataHooks: []ApplicationDataHook{{
			Name:           "request-body",
			Library:        "/data/app/libcronet.so",
			BuildID:        "0xAABBCCDD",
			Symbol:         "Cronet_Buffer_InitWithDataAndCallback",
			Direction:      "WRITE",
			CaptureOn:      "RETURN",
			BufferArg:      2,
			BufferOffset:   0x18,
			BufferIndirect: true,
			LengthSource:   "MEMORY",
			LengthArg:      1,
			LengthOffset:   0x20,
			LengthSize:     4,
			LengthIndirect: true,
			MaxBytes:       32768,
		}},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	hook := profile.DataHooks[0]
	if hook.Direction != AppDataDirectionWrite ||
		hook.CaptureOn != AppDataCaptureReturn ||
		hook.LengthSource != AppDataLengthMemory ||
		hook.BuildID != "aabbccdd" {
		t.Fatalf("hook was not normalized: %#v", hook)
	}

	got := hook.bpfConfig()
	if size := binary.Size(got); size != 48 {
		t.Fatalf("applicationDataBPFConfig size = %d, want 48", size)
	}
	wantFlags := uint32(appDataFlagBufferIndirect |
		appDataFlagLengthMemory |
		appDataFlagCaptureReturn |
		appDataFlagLengthIndirect)
	if got.Flags != wantFlags {
		t.Fatalf("BPF flags = %#x, want %#x", got.Flags, wantFlags)
	}
	if got.Direction != DataTypeWrite || got.BufferArg != 2 || got.LengthSize != 4 {
		t.Fatalf("unexpected BPF config: %#v", got)
	}
}

func TestApplicationDataHookFixedLengthBPFConfig(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "fixed-object-dump",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyAppData}},
		DataHooks: []ApplicationDataHook{{
			Name:         "ftx-send-object",
			Library:      "/data/app/libcronet.so",
			Symbol:       "FTX_Channel_SendMessage",
			Direction:    AppDataDirectionWrite,
			BufferArg:    2,
			LengthSource: AppDataLengthFixed,
			FixedLength:  256,
			MaxBytes:     256,
		}},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	got := profile.DataHooks[0].bpfConfig()
	wantFlags := uint32(appDataFlagLengthFixed)
	if got.Flags != wantFlags {
		t.Fatalf("BPF flags = %#x, want %#x", got.Flags, wantFlags)
	}
	if got.LengthArg != 256 {
		t.Fatalf("fixed length encoded as %d, want 256", got.LengthArg)
	}
}

func TestApplicationDataHookLibCXXStringBPFConfig(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "cronet-libcxx-string",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyAppData}},
		DataHooks: []ApplicationDataHook{{
			Name:         "request-url",
			Library:      "/data/app/libcronet.so",
			Offset:       0x1234,
			Direction:    AppDataDirectionWrite,
			BufferArg:    4,
			BufferFormat: "LIBCXX_STRING",
			MaxBytes:     4096,
		}},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	hook := profile.DataHooks[0]
	if hook.BufferFormat != AppDataBufferLibCXX || hook.LengthSource != "" {
		t.Fatalf("hook was not normalized: %#v", hook)
	}
	got := hook.bpfConfig()
	if got.Flags != appDataFlagBufferLibCXX || got.BufferArg != 4 || got.LengthArg != 0 {
		t.Fatalf("unexpected BPF config: %#v", got)
	}
}

func TestApplicationDataHookAsyncStateBPFConfig(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "cronet-async-upload",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyAppData}},
		DataHooks: []ApplicationDataHook{
			{
				Name:           "upload-buffer-save",
				Library:        "/data/app/libcronet.so",
				Offset:         0x1000,
				Direction:      AppDataDirectionWrite,
				BufferArg:      2,
				BufferOffset:   0x10,
				BufferIndirect: true,
				LengthSource:   AppDataLengthArgument,
				LengthArg:      3,
				StateGroup:     "UPLOAD",
				StateAction:    "SAVE",
				StateKeyArg:    1,
			},
			{
				Name:         "upload-buffer-load",
				Library:      "/data/app/libcronet.so",
				Offset:       0x2000,
				Direction:    AppDataDirectionWrite,
				BufferArg:    3,
				LengthSource: AppDataLengthArgument,
				LengthArg:    5,
				StateGroup:   "upload",
				StateAction:  "LOAD",
				StateKeyArg:  3,
				MaxBytes:     32768,
			},
		},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	save := profile.DataHooks[0]
	load := profile.DataHooks[1]
	if save.stateID == 0 || save.stateID != load.stateID ||
		save.StateGroup != "upload" || load.StateAction != AppDataStateLoad {
		t.Fatalf("state hooks were not paired: save=%#v load=%#v", save, load)
	}
	saveConfig := save.bpfConfig()
	loadConfig := load.bpfConfig()
	if saveConfig.Flags != appDataFlagBufferIndirect|appDataFlagStateSave ||
		saveConfig.StateKeyArg != 1 {
		t.Fatalf("unexpected save config: %#v", saveConfig)
	}
	if loadConfig.Flags != appDataFlagStateLoad || loadConfig.StateKeyArg != 3 ||
		loadConfig.StateID != saveConfig.StateID {
		t.Fatalf("unexpected load config: %#v", loadConfig)
	}
}

func TestNormalizeBuildID(t *testing.T) {
	got, err := normalizeBuildID(" 0xAABBcc ")
	if err != nil {
		t.Fatalf("normalizeBuildID() error = %v", err)
	}
	if got != "aabbcc" {
		t.Fatalf("normalizeBuildID() = %q", got)
	}
	for _, invalid := range []string{"abc", "not-hex"} {
		if _, err := normalizeBuildID(invalid); err == nil {
			t.Fatalf("normalizeBuildID(%q) should fail", invalid)
		}
	}
}

func TestApplicationDataHookValidationErrors(t *testing.T) {
	valid := ApplicationDataHook{
		Name:         "hook",
		Library:      "/tmp/libapp.so",
		Symbol:       "send",
		Direction:    AppDataDirectionWrite,
		BufferArg:    1,
		LengthSource: AppDataLengthArgument,
		LengthArg:    2,
	}
	tests := []struct {
		name string
		edit func(*ApplicationDataHook)
	}{
		{"missing library", func(h *ApplicationDataHook) { h.Library = "" }},
		{"two targets", func(h *ApplicationDataHook) { h.Offset = 0x10 }},
		{"bad buffer arg", func(h *ApplicationDataHook) { h.BufferArg = 6 }},
		{"return length at entry", func(h *ApplicationDataHook) {
			h.LengthSource = AppDataLengthReturn
		}},
		{"indirect argument length", func(h *ApplicationDataHook) {
			h.LengthIndirect = true
		}},
		{"capture too large", func(h *ApplicationDataHook) {
			h.MaxBytes = MaxApplicationData + 1
		}},
		{"fixed length without fixed mode", func(h *ApplicationDataHook) {
			h.FixedLength = 128
		}},
		{"fixed mode missing fixed length", func(h *ApplicationDataHook) {
			h.LengthSource = AppDataLengthFixed
			h.LengthArg = 0
		}},
		{"fixed mode with argument length", func(h *ApplicationDataHook) {
			h.LengthSource = AppDataLengthFixed
			h.LengthArg = 2
			h.FixedLength = 128
		}},
		{"bad buffer format", func(h *ApplicationDataHook) {
			h.BufferFormat = "java_string"
		}},
		{"libcxx string with explicit length", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferLibCXX
			h.LengthSource = AppDataLengthArgument
		}},
		{"state group without action", func(h *ApplicationDataHook) {
			h.StateGroup = "upload"
		}},
		{"state action without group", func(h *ApplicationDataHook) {
			h.StateAction = AppDataStateSave
			h.StateKeyArg = 1
		}},
		{"state key without action", func(h *ApplicationDataHook) {
			h.StateKeyArg = 1
		}},
		{"state action on return", func(h *ApplicationDataHook) {
			h.CaptureOn = AppDataCaptureReturn
			h.StateGroup = "upload"
			h.StateAction = AppDataStateSave
			h.StateKeyArg = 1
		}},
		{"indirect state load buffer", func(h *ApplicationDataHook) {
			h.BufferIndirect = true
			h.StateGroup = "upload"
			h.StateAction = AppDataStateLoad
			h.StateKeyArg = 1
		}},
		{"unpaired state save", func(h *ApplicationDataHook) {
			h.StateGroup = "upload"
			h.StateAction = AppDataStateSave
			h.StateKeyArg = 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hook := valid
			test.edit(&hook)
			profile := &ApplicationProfile{
				Version:   ApplicationProfileVersion,
				Name:      "bad-hook",
				Match:     ApplicationMatch{UID: 10001},
				DataHooks: []ApplicationDataHook{hook},
			}
			if err := profile.Validate(); err == nil {
				t.Fatal("Validate() should fail")
			}
		})
	}
}

func TestApplicationDataHookTarget(t *testing.T) {
	symbolProbe := &manager.Probe{}
	applyApplicationDataHookTarget(symbolProbe, ApplicationDataHook{Symbol: "send"})
	if symbolProbe.AttachToFuncName != "send" || symbolProbe.UAddress != 0 {
		t.Fatalf("symbol probe = %#v", symbolProbe)
	}

	offsetProbe := &manager.Probe{}
	applyApplicationDataHookTarget(offsetProbe, ApplicationDataHook{Offset: 0x1234})
	if offsetProbe.AttachToFuncName != offsetHookPlaceholder || offsetProbe.UAddress != 0x1234 {
		t.Fatalf("offset probe = %#v", offsetProbe)
	}

	tlsOffsetProbe := &manager.Probe{}
	applyHookToProbe(tlsOffsetProbe, HookProfile{Offset: 0x5678})
	if tlsOffsetProbe.AttachToFuncName != offsetHookPlaceholder ||
		tlsOffsetProbe.UAddress != 0x5678 {
		t.Fatalf("TLS offset probe = %#v", tlsOffsetProbe)
	}
}

func TestApplicationDataEventDecode(t *testing.T) {
	var comm [TaskCommLen]byte
	copy(comm[:], "doubao")
	var payload [MaxDataSize]byte
	copy(payload[:], `{"message":"hello"}`)
	values := []any{
		uint64(123456),
		uint64(0xabcdef),
		uint32(42),
		uint32(43),
		uint32(1),
		uint32(DataTypeWrite),
		uint32(0),
		uint32(19),
		uint32(19),
		uint32(0),
		uint32(19),
		comm,
		payload,
	}
	var raw bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&raw, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	// C rounds the structure size up to its eight-byte alignment.
	raw.Write(make([]byte, 4))

	decoder := &applicationDataEventDecoder{hookNames: []string{"unused", "request-body"}}
	decoded, err := decoder.Decode(nil, raw.Bytes())
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	event, ok := decoded.(*ApplicationDataEvent)
	if !ok {
		t.Fatalf("decoded type = %T", decoded)
	}
	if event.HookName != "request-body" || string(event.GetData()) != `{"message":"hello"}` {
		t.Fatalf("decoded event = %#v data=%q", event, event.GetData())
	}
	if event.PerfMonoNs() != 123456 || event.IsTruncated() {
		t.Fatalf("unexpected event metadata: %#v", event)
	}
}
