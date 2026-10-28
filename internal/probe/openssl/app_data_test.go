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
	"strings"
	"testing"
	"time"

	manager "github.com/gojue/ebpfmanager"
)

func TestApplicationDataHookOutputLength(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion, Name: "ssl-write-ex", Match: ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyBoundaryData}},
		DataHooks: []ApplicationDataHook{{Name: "write-ex", Library: "/data/app/libssl.so",
			Symbol: "SSL_write_ex", Direction: AppDataDirectionWrite, CaptureOn: AppDataCaptureReturn,
			BufferArg: 2, LengthSource: AppDataLengthOutput, LengthArg: 4, ReturnSuccessValue: 1}},
	}
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	hook := profile.DataHooks[0]
	config := hook.bpfConfig()
	if config.Flags != appDataFlagLengthOutput|appDataFlagCaptureReturn ||
		config.ReturnSuccessValue != 1 || config.LengthArg != 4 || config.LengthSize != 8 || binary.Size(config) != 152 {
		t.Fatalf("incorrect output-length config: %+v", config)
	}
	for _, change := range []func(*ApplicationDataHook){
		func(h *ApplicationDataHook) { h.CaptureOn = AppDataCaptureEntry },
		func(h *ApplicationDataHook) { h.ReturnSuccessValue = 0 },
		func(h *ApplicationDataHook) { h.LengthArg = 0 },
		func(h *ApplicationDataHook) { h.LengthSource = AppDataLengthMemory },
		func(h *ApplicationDataHook) { h.BufferFormat = AppDataBufferIOVec },
	} {
		profile.DataHooks[0] = hook
		change(&profile.DataHooks[0])
		if err := profile.Validate(); err == nil {
			t.Fatalf("invalid output-length hook accepted: %+v", profile.DataHooks[0])
		}
	}
}

func TestApplicationDataHookConnectionIdentityConfig(t *testing.T) {
	hook := ApplicationDataHook{ContextArg: 1, ContextSize: 8, ContextDerefOffset: 128,
		ContextGenerationOffset: 72, StreamByteOffsetArg: 2, StreamByteOffsetSize: 8,
		StreamByteOffsetDerefOffset: 16, FinArg: 3, FinMask: 4}
	config := hook.bpfConfig()
	if config.ContextDerefOffset != 128 || config.ContextGenerationOffset != 72 ||
		config.StreamByteOffsetDerefOffset != 16 || config.FinMask != 4 {
		t.Fatalf("connection identity fields were lost: %+v", config)
	}
}

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
			ContextArg:     1,
			StreamArg:      4,
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
	if size := binary.Size(got); size != 152 {
		t.Fatalf("applicationDataBPFConfig size = %d, want 152", size)
	}
	wantFlags := uint32(appDataFlagBufferIndirect |
		appDataFlagLengthMemory |
		appDataFlagCaptureReturn |
		appDataFlagLengthIndirect)
	if got.Flags != wantFlags {
		t.Fatalf("BPF flags = %#x, want %#x", got.Flags, wantFlags)
	}
	if got.Direction != DataTypeWrite || got.BufferArg != 2 || got.LengthSize != 4 ||
		got.ContextArg != 1 || got.StreamArg != 4 {
		t.Fatalf("unexpected BPF config: %#v", got)
	}
}

func TestApplicationDataHookReturnWidth(t *testing.T) {
	newProfile := func(lengthSize uint32) *ApplicationProfile {
		return &ApplicationProfile{
			Version: ApplicationProfileVersion,
			Name:    "return-width",
			Match:   ApplicationMatch{UID: 10001},
			Capture: ApplicationCapture{Strategies: []string{StrategyAppData}},
			DataHooks: []ApplicationDataHook{{
				Name:         "bio-read",
				Library:      "/data/app/libcronet.so",
				Offset:       0x1234,
				Direction:    AppDataDirectionRead,
				CaptureOn:    AppDataCaptureReturn,
				BufferArg:    2,
				LengthSource: AppDataLengthReturn,
				LengthSize:   lengthSize,
			}},
		}
	}

	profile := newProfile(4)
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate(32-bit return) error = %v", err)
	}
	if got := profile.DataHooks[0].bpfConfig().LengthSize; got != 4 {
		t.Fatalf("32-bit return length size = %d, want 4", got)
	}

	profile = newProfile(0)
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate(default return) error = %v", err)
	}
	if got := profile.DataHooks[0].bpfConfig().LengthSize; got != 8 {
		t.Fatalf("default return length size = %d, want 8", got)
	}

	if err := newProfile(2).Validate(); err == nil {
		t.Fatal("Validate() should reject a 2-byte function return")
	}
}

func TestApplicationDataHookIOVecBPFConfig(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "writev-capture",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyAppData}},
		DataHooks: []ApplicationDataHook{{
			Name:           "socket-writev",
			Library:        "/apex/com.android.runtime/lib64/bionic/libc.so",
			Symbol:         "writev",
			Direction:      AppDataDirectionWrite,
			CaptureOn:      AppDataCaptureEntry,
			BufferArg:      2,
			BufferFormat:   AppDataBufferIOVec,
			VectorCountArg: 3,
			ContextArg:     1,
			MaxBytes:       MaxApplicationData,
		}},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	hook := profile.DataHooks[0]
	if hook.LengthSource != "" || hook.VectorCountArg != 3 {
		t.Fatalf("iovec hook was normalized incorrectly: %#v", hook)
	}
	got := hook.bpfConfig()
	if size := binary.Size(got); size != 152 {
		t.Fatalf("applicationDataBPFConfig size = %d, want 152", size)
	}
	if got.Flags != appDataFlagBufferIOVec || got.BufferArg != 2 ||
		got.VectorCountArg != 3 || got.ContextArg != 1 ||
		got.VectorStride != 16 || got.VectorBaseOffset != 0 ||
		got.VectorLengthOffset != 8 || got.VectorLengthSize != 8 {
		t.Fatalf("unexpected iovec BPF config: %#v", got)
	}
}

func TestApplicationDataHookPrivateVectorAndObjectIdentityBPFConfig(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "quiche-mem-slice-capture",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyBoundaryData}},
		DataHooks: []ApplicationDataHook{{
			Name:                   "quiche-write-mem-slices",
			Library:                "/data/app/libcronet.so",
			Offset:                 0x61e13c,
			CaptureLayer:           CaptureLayerTransport,
			Transport:              CaptureTransportQUIC,
			Direction:              AppDataDirectionWrite,
			CaptureOn:              AppDataCaptureEntry,
			BufferArg:              2,
			BufferFormat:           AppDataBufferVector,
			VectorCountArg:         3,
			VectorStride:           24,
			VectorBaseOffset:       8,
			VectorLengthOffset:     16,
			VectorLengthSize:       8,
			ContextArg:             1,
			StreamArg:              1,
			StreamOffset:           0x1d8,
			StreamSize:             4,
			StreamByteOffsetArg:    2,
			StreamByteOffsetOffset: 0x10,
			StreamByteOffsetSize:   8,
			FinArg:                 2,
			FinOffset:              1,
			FinSize:                1,
			MaxBytes:               MaxApplicationData,
		}},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	hook := profile.DataHooks[0]
	got := hook.bpfConfig()
	if got.Flags != appDataFlagBufferIOVec ||
		got.VectorStride != 24 || got.VectorBaseOffset != 8 ||
		got.VectorLengthOffset != 16 || got.VectorLengthSize != 8 ||
		got.ContextArg != 1 || got.ContextSize != 0 ||
		got.StreamArg != 1 || got.StreamOffset != 0x1d8 ||
		got.StreamSize != 4 ||
		got.StreamByteOffsetArg != 2 ||
		got.StreamByteOffsetOffset != 0x10 ||
		got.StreamByteOffsetSize != 8 ||
		got.FinArg != 2 || got.FinOffset != 1 || got.FinSize != 1 {
		t.Fatalf("unexpected private-vector BPF config: %#v", got)
	}
}

func TestApplicationDataHookIdentityOffsetDefaultsToPointerWidth(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "identity-offset-default",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyBoundaryData}},
		DataHooks: []ApplicationDataHook{{
			Name:          "quic-recv",
			Library:       "/data/app/libcronet.so",
			Offset:        0x1234,
			CaptureLayer:  CaptureLayerTransport,
			Transport:     CaptureTransportQUIC,
			Direction:     AppDataDirectionRead,
			BufferArg:     2,
			LengthArg:     3,
			ContextArg:    1,
			ContextOffset: 0x20,
			StreamArg:     1,
			StreamOffset:  0x1d8,
		}},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	hook := profile.DataHooks[0]
	if hook.ContextSize != 8 || hook.StreamSize != 8 {
		t.Fatalf("identity field widths were not defaulted: %#v", hook)
	}
}

func TestApplicationDataHookHighArgumentIOVecResultMemory(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "ngtcp2-writev-stream",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyAppData}},
		DataHooks: []ApplicationDataHook{{
			Name:           "ngtcp2-stream-write",
			Library:        "/data/app/libngtcp2.so",
			Symbol:         "ngtcp2_conn_writev_stream_versioned",
			Direction:      AppDataDirectionWrite,
			CaptureOn:      AppDataCaptureReturn,
			BufferArg:      10,
			BufferFormat:   AppDataBufferIOVec,
			VectorCountArg: 11,
			LengthSource:   AppDataLengthMemory,
			LengthArg:      7,
			ContextArg:     1,
			StreamArg:      9,
			MaxBytes:       MaxApplicationData,
		}},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	hook := profile.DataHooks[0]
	if hook.LengthSize != 8 {
		t.Fatalf("deferred result length size = %d, want 8", hook.LengthSize)
	}
	got := hook.bpfConfig()
	wantFlags := uint32(appDataFlagBufferIOVec |
		appDataFlagLengthMemory |
		appDataFlagCaptureReturn)
	if got.Flags != wantFlags || got.BufferArg != 10 ||
		got.VectorCountArg != 11 || got.LengthArg != 7 ||
		got.ContextArg != 1 || got.StreamArg != 9 ||
		got.LengthSize != 8 {
		t.Fatalf("unexpected high-argument iovec BPF config: %#v", got)
	}
}

func TestApplicationDataHookMsgHdrBPFConfig(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "recvmsg-capture",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{Strategies: []string{StrategyAppData}},
		DataHooks: []ApplicationDataHook{{
			Name:         "socket-recvmsg",
			Library:      "/apex/com.android.runtime/lib64/bionic/libc.so",
			Symbol:       "recvmsg",
			Direction:    AppDataDirectionRead,
			CaptureOn:    AppDataCaptureReturn,
			BufferArg:    2,
			BufferFormat: AppDataBufferMsgHdr,
			ContextArg:   1,
			MaxBytes:     MaxApplicationData,
		}},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	hook := profile.DataHooks[0]
	if hook.BufferOffset != 16 || hook.LengthOffset != 24 ||
		hook.LengthSize != 8 || hook.LengthSource != "" {
		t.Fatalf("msghdr defaults were not applied: %#v", hook)
	}
	got := hook.bpfConfig()
	if got.Flags != appDataFlagBufferMsgHdr|appDataFlagCaptureReturn || got.BufferArg != 2 ||
		got.BufferOffset != 16 || got.LengthOffset != 24 ||
		got.LengthSize != 8 || got.ContextArg != 1 {
		t.Fatalf("unexpected msghdr BPF config: %#v", got)
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
		{"bad buffer arg", func(h *ApplicationDataHook) { h.BufferArg = 13 }},
		{"bad context arg", func(h *ApplicationDataHook) { h.ContextArg = 13 }},
		{"context memory without arg", func(h *ApplicationDataHook) {
			h.ContextSize = 8
		}},
		{"bad context size", func(h *ApplicationDataHook) {
			h.ContextArg = 1
			h.ContextSize = 3
		}},
		{"bad stream arg", func(h *ApplicationDataHook) { h.StreamArg = 13 }},
		{"stream memory without arg", func(h *ApplicationDataHook) {
			h.StreamSize = 4
		}},
		{"bad stream size", func(h *ApplicationDataHook) {
			h.StreamArg = 1
			h.StreamSize = 3
		}},
		{"bad stream byte offset arg", func(h *ApplicationDataHook) {
			h.StreamByteOffsetArg = 13
		}},
		{"stream byte offset memory without arg", func(h *ApplicationDataHook) {
			h.StreamByteOffsetSize = 8
		}},
		{"bad stream byte offset size", func(h *ApplicationDataHook) {
			h.StreamByteOffsetArg = 1
			h.StreamByteOffsetSize = 3
		}},
		{"stream byte offset on non-QUIC hook", func(h *ApplicationDataHook) {
			h.StreamByteOffsetArg = 1
		}},
		{"bad fin arg", func(h *ApplicationDataHook) {
			h.FinArg = 13
		}},
		{"fin memory without arg", func(h *ApplicationDataHook) {
			h.FinSize = 1
		}},
		{"bad fin size", func(h *ApplicationDataHook) {
			h.FinArg = 1
			h.FinSize = 3
		}},
		{"FIN on non-QUIC hook", func(h *ApplicationDataHook) {
			h.FinArg = 1
		}},
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
		{"iovec missing vector count", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferIOVec
			h.LengthSource = ""
			h.LengthArg = 0
		}},
		{"iovec with explicit length", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferIOVec
			h.VectorCountArg = 3
		}},
		{"iovec result memory at entry", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferIOVec
			h.VectorCountArg = 3
			h.LengthSource = AppDataLengthMemory
		}},
		{"iovec with indirect buffer", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferIOVec
			h.VectorCountArg = 3
			h.LengthSource = ""
			h.LengthArg = 0
			h.BufferIndirect = true
		}},
		{"iovec with private stride", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferIOVec
			h.VectorCountArg = 3
			h.LengthSource = ""
			h.LengthArg = 0
			h.VectorStride = 24
		}},
		{"vector missing stride", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferVector
			h.VectorCountArg = 3
			h.LengthSource = ""
			h.LengthArg = 0
		}},
		{"vector base outside stride", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferVector
			h.VectorCountArg = 3
			h.LengthSource = ""
			h.LengthArg = 0
			h.VectorStride = 24
			h.VectorBaseOffset = 20
			h.VectorLengthOffset = 16
		}},
		{"vector length outside stride", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferVector
			h.VectorCountArg = 3
			h.LengthSource = ""
			h.LengthArg = 0
			h.VectorStride = 24
			h.VectorLengthOffset = 20
			h.VectorLengthSize = 8
		}},
		{"raw buffer with vector count", func(h *ApplicationDataHook) {
			h.VectorCountArg = 3
		}},
		{"raw buffer with vector layout", func(h *ApplicationDataHook) {
			h.VectorStride = 16
		}},
		{"msghdr with vector count argument", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferMsgHdr
			h.VectorCountArg = 3
			h.LengthSource = ""
			h.LengthArg = 0
		}},
		{"msghdr with explicit length", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferMsgHdr
		}},
		{"msghdr with indirect header", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferMsgHdr
			h.LengthSource = ""
			h.LengthArg = 0
			h.BufferIndirect = true
		}},
		{"msghdr with invalid count size", func(h *ApplicationDataHook) {
			h.BufferFormat = AppDataBufferMsgHdr
			h.LengthSource = ""
			h.LengthArg = 0
			h.LengthSize = 2
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
		uint64(0x1234),
		uint64(7),
		uint64(4096),
		uint32(AppDataStreamFlagOffsetValid |
			AppDataStreamFlagFinValid |
			AppDataStreamFlagFin),
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
		int32(0),
		uint32(0),
		uint32(10293),
		uint32(0),
		uint64(0x12345678),
		[AppDataMaxStackDepth]uint64{},
		payload,
	}
	var raw bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&raw, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	decoder := &applicationDataEventDecoder{hooks: []ApplicationDataHook{
		{Name: "unused", CaptureLayer: CaptureLayerSemantic},
		{
			Name:         "request-body",
			CaptureLayer: CaptureLayerTransport,
			Transport:    CaptureTransportQUIC,
			BoundaryRole: "",
		},
	}}
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
	if event.CaptureLayer != CaptureLayerTransport ||
		event.Transport != CaptureTransportQUIC {
		t.Fatalf("capture provenance was not applied: %#v", event)
	}
	if event.PerfMonoNs() != 123456 || event.IsTruncated() {
		t.Fatalf("unexpected event metadata: %#v", event)
	}
	if event.Uid != 10293 || event.CGroupID != 0x12345678 {
		t.Fatalf("process ownership metadata was not preserved: %#v", event)
	}
	if event.ContextID != 0x1234 || event.StreamID != 7 ||
		!event.HasStreamOffset() || event.StreamOffset != 4096 ||
		!event.HasFin() || !event.IsFin() ||
		!strings.Contains(event.String(),
			"Context:0x1234 Stream:7 Offset:4096 FIN:true") {
		t.Fatalf("correlation metadata was not preserved: %#v", event)
	}
}

func TestApplicationDataEventDecodeCompactPayloadAndStack(t *testing.T) {
	var comm [TaskCommLen]byte
	copy(comm[:], "stack-test")
	var stack [AppDataMaxStackDepth]uint64
	stack[0] = 0x123456
	stack[1] = 0xabcdef
	values := []any{
		uint64(123456),
		uint64(0xabcdef),
		uint64(0x1234),
		uint64(7),
		uint64(0),
		uint32(0),
		uint32(42),
		uint32(43),
		uint32(0),
		uint32(DataTypeWrite),
		uint32(0),
		uint32(7),
		uint32(7),
		uint32(0),
		uint32(7),
		comm,
		int32(16),
		uint32(2),
		uint32(10293),
		uint32(0),
		uint64(0x12345678),
		stack,
		[]byte("payload"),
	}
	var raw bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&raw, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	event := &ApplicationDataEvent{}
	if err := event.DecodeFromBytes(raw.Bytes()); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if got := string(event.GetData()); got != "payload" {
		t.Fatalf("payload = %q", got)
	}
	if event.UserStackStatus != 16 || event.UserStackDepth != 2 ||
		event.UserStack[0] != 0x123456 || event.UserStack[1] != 0xabcdef {
		t.Fatalf("stack metadata = %#v", event)
	}
}

func TestApplicationDataBPFConfigEnablesUserStackExplicitly(t *testing.T) {
	withoutStack := ApplicationDataHook{}.bpfConfig()
	withStack := ApplicationDataHook{CollectUserStack: true}.bpfConfig()
	withDwarf := ApplicationDataHook{StackMode: AppDataStackDWARF}.bpfConfig()
	if withoutStack.Flags&appDataFlagUserStack != 0 {
		t.Fatalf("user stacks unexpectedly enabled by default: %#x", withoutStack.Flags)
	}
	if withStack.Flags&appDataFlagUserStack == 0 {
		t.Fatalf("user stack flag missing: %#x", withStack.Flags)
	}
	if withDwarf.Flags&appDataFlagUserStack == 0 ||
		withDwarf.Flags&appDataFlagDwarfStack == 0 {
		t.Fatalf("DWARF stack flags missing: %#x", withDwarf.Flags)
	}
}

func TestApplicationDataEventMarshalJSONIsCompact(t *testing.T) {
	event := &ApplicationDataEvent{
		Timestamp:    1,
		ContextID:    0x1234,
		StreamID:     7,
		StreamOffset: 0,
		StreamFlags: AppDataStreamFlagOffsetValid |
			AppDataStreamFlagFinValid,
		Pid:          42,
		Uid:          10293,
		CGroupID:     0x12345678,
		ProcessName:  "com.example.app:channel",
		HookID:       1,
		Direction:    DataTypeWrite,
		OriginalLen:  7,
		CapturedLen:  7,
		DataLen:      7,
		HookName:     "quic-send",
		CaptureLayer: CaptureLayerTransport,
		Transport:    CaptureTransportQUIC,
	}
	copy(event.Data[:], "payload")
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if len(data) > 1000 || !bytes.Contains(data, []byte(`"eventType":"boundary_data"`)) ||
		!bytes.Contains(data, []byte(`"captureLayer":"transport"`)) ||
		!bytes.Contains(data, []byte(`"transport":"quic"`)) ||
		!bytes.Contains(data, []byte(`"processName":"com.example.app:channel"`)) ||
		!bytes.Contains(data, []byte(`"uid":10293`)) ||
		!bytes.Contains(data, []byte(`"cgroupId":305419896`)) ||
		!bytes.Contains(data, []byte(`"data":"cGF5bG9hZA=="`)) ||
		!bytes.Contains(data, []byte(`"streamId":7`)) ||
		!bytes.Contains(data, []byte(`"streamOffset":0`)) ||
		!bytes.Contains(data, []byte(`"fin":false`)) {
		t.Fatalf("unexpected structured event: %s", data)
	}
	var envelope struct {
		WallTime string `json:"wallTime"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339Nano, envelope.WallTime); err != nil {
		t.Fatalf("wallTime is not an absolute RFC3339 timestamp: %q: %v",
			envelope.WallTime, err)
	}
}

func TestApplicationDataEventMarshalJSONPreservesZeroStreamIdentity(t *testing.T) {
	event := &ApplicationDataEvent{
		Timestamp:    1,
		StreamFlags:  AppDataStreamFlagOffsetValid | AppDataStreamFlagFinValid,
		Pid:          42,
		HookID:       1,
		Direction:    DataTypeWrite,
		HookName:     "quic-send",
		CaptureLayer: CaptureLayerTransport,
		Transport:    CaptureTransportQUIC,
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, field := range [][]byte{
		[]byte(`"contextId":0`),
		[]byte(`"streamId":0`),
		[]byte(`"streamOffset":0`),
	} {
		if !bytes.Contains(data, field) {
			t.Fatalf("zero-identity JSON %s is missing %s", data, field)
		}
	}
}

func TestApplicationDataEventAllowsQUICFinOnlyMetadata(t *testing.T) {
	event := &ApplicationDataEvent{
		Timestamp:    101,
		ContextID:    0x1234,
		StreamID:     9,
		StreamOffset: 57,
		StreamFlags: AppDataStreamFlagOffsetValid |
			AppDataStreamFlagFinValid |
			AppDataStreamFlagFin,
		Pid:          42,
		Tid:          43,
		HookID:       1,
		Direction:    DataTypeRead,
		CaptureLayer: CaptureLayerTransport,
		Transport:    CaptureTransportQUIC,
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() rejected FIN-only QUIC event: %v", err)
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{
		[]byte(`"streamOffset":57`),
		[]byte(`"fin":true`),
		[]byte(`"capturedLen":0`),
		[]byte(`"dataLen":0`),
		[]byte(`"data":""`),
	} {
		if !bytes.Contains(data, field) {
			t.Fatalf("FIN-only JSON %s is missing %s", data, field)
		}
	}
}

func TestApplicationDataEventKeepsSemanticEventTypeSeparate(t *testing.T) {
	event := &ApplicationDataEvent{
		Timestamp:    1,
		Pid:          42,
		HookID:       1,
		Direction:    DataTypeWrite,
		OriginalLen:  4,
		CapturedLen:  4,
		DataLen:      4,
		HookName:     "request-object",
		CaptureLayer: CaptureLayerSemantic,
	}
	copy(event.Data[:], "diag")
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !bytes.Contains(data, []byte(`"eventType":"application_data"`)) ||
		bytes.Contains(data, []byte(`"eventType":"boundary_data"`)) {
		t.Fatalf("semantic event was not isolated: %s", data)
	}
}

func TestApplicationDataEventMarshalJSONIncludesWireBoundaryRole(t *testing.T) {
	event := &ApplicationDataEvent{
		Timestamp:    1,
		ContextID:    0xb10,
		Pid:          42,
		HookID:       1,
		Direction:    DataTypeWrite,
		OriginalLen:  7,
		CapturedLen:  7,
		DataLen:      7,
		HookName:     "bio-ciphertext-write",
		CaptureLayer: CaptureLayerWire,
		Transport:    CaptureTransportTLS,
		BoundaryRole: CaptureBoundaryTLSCiphertext,
	}
	copy(event.Data[:], "payload")
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !bytes.Contains(data, []byte(`"boundaryRole":"tls_ciphertext"`)) {
		t.Fatalf("wire boundary role missing from event: %s", data)
	}
}
