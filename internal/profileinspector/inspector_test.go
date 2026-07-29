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

package profileinspector

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/gojue/ecapture/internal/probe/openssl"
)

func TestScanJNIFunctionTableData(t *testing.T) {
	data := make([]byte, jniFunctionTableEntries*8+32)
	for index := 4; index < jniFunctionTableEntries; index++ {
		binary.LittleEndian.PutUint64(
			data[index*8:index*8+8],
			0x1000+uint64(index)*16,
		)
	}
	wantRegister := uint64(0x1000 + jniRegisterNativesIndex*16)
	got := scanJNIFunctionTableData(
		data,
		0xa00000,
		binary.LittleEndian,
		func(address uint64) bool { return address >= 0x1000 && address < 0x100000 },
	)
	if len(got) != 1 {
		t.Fatalf("scanJNIFunctionTableData() = %#v", got)
	}
	if got[0].tableAddress != 0xa00000 || got[0].registerAddress != wantRegister {
		t.Fatalf("unexpected JNI table = %#v", got[0])
	}

	// An arbitrary sparse pointer array must not be classified as JNI.
	for index := 4; index < jniFunctionTableEntries; index += 2 {
		binary.LittleEndian.PutUint64(data[index*8:index*8+8], 0)
	}
	if sparse := scanJNIFunctionTableData(
		data,
		0xa00000,
		binary.LittleEndian,
		func(address uint64) bool { return address >= 0x1000 && address < 0x100000 },
	); len(sparse) != 0 {
		t.Fatalf("sparse table was accepted: %#v", sparse)
	}
}

func TestParseProcessMaps(t *testing.T) {
	input := strings.NewReader(`
70000000-70001000 r--p 00000000 00:00 0 /data/app/base.apk
71000000-71010000 r-xp 00001000 08:01 123 /data/app/lib/arm64/libcronet.so
72000000-72010000 r-xp 00001000 08:01 124 /apex/com.android.runtime/lib64/bionic/libc.so
73000000-73010000 r-xp 00001000 08:01 124 /apex/com.android.runtime/lib64/bionic/libc.so
74000000-74010000 r-xp 00001000 08:01 125 /data/app/lib/arm64/libgone.so (deleted)
75000000-75010000 r-xp 00001000 00:00 0 [vdso]
`)
	got, err := ParseProcessMaps(input)
	if err != nil {
		t.Fatalf("ParseProcessMaps() error = %v", err)
	}
	want := []string{
		"/apex/com.android.runtime/lib64/bionic/libc.so",
		"/data/app/lib/arm64/libcronet.so",
		"/data/app/lib/arm64/libgone.so",
	}
	if len(got) != len(want) {
		t.Fatalf("ParseProcessMaps() = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("ParseProcessMaps()[%d] = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestCandidateForKnownAndCronetSymbols(t *testing.T) {
	tests := []struct {
		symbol string
		family string
		role   string
		hook   bool
	}{
		{"SSL_write", "openssl", "tls-write", true},
		{"quiche_conn_stream_recv", "quiche", "quic-stream-recv", true},
		{"lsquic_stream_writev", "lsquic", "quic-stream-writev", true},
		{"ngtcp2_conn_writev_stream_versioned", "ngtcp2", "quic-stream-writev", true},
		{"writev", "libc", "fd-writev", true},
		{"sendmsg", "libc", "socket-sendmsg", true},
		{"Java_org_chromium_net_impl_CronetUrlRequest_onReadCompleted", "cronet", "jni-entry", false},
		{"CronetUpload_onReadSucceeded", "cronet", "upload-complete", false},
	}
	for _, test := range tests {
		t.Run(test.symbol, func(t *testing.T) {
			got, found := candidateForSymbol(test.symbol)
			if !found {
				t.Fatal("candidateForSymbol() did not find symbol")
			}
			if got.family != test.family || got.role != test.role || (got.hook != nil) != test.hook {
				t.Fatalf("candidateForSymbol() = %#v", got)
			}
		})
	}
	if _, found := candidateForSymbol("unrelated_function"); found {
		t.Fatal("candidateForSymbol() should ignore unrelated functions")
	}
	writev, _ := candidateForSymbol("writev")
	if writev.hook.BufferFormat != openssl.AppDataBufferIOVec ||
		writev.hook.BufferArg != 2 || writev.hook.VectorCountArg != 3 ||
		writev.hook.ContextArg != 1 {
		t.Fatalf("writev recipe = %#v", writev.hook)
	}
	sendmsg, _ := candidateForSymbol("sendmsg")
	if sendmsg.hook.BufferFormat != openssl.AppDataBufferMsgHdr ||
		sendmsg.hook.BufferArg != 2 || sendmsg.hook.ContextArg != 1 {
		t.Fatalf("sendmsg recipe = %#v", sendmsg.hook)
	}
	ngtcp2, _ := candidateForSymbol("ngtcp2_conn_writev_stream_versioned")
	if ngtcp2.hook.BufferFormat != openssl.AppDataBufferIOVec ||
		ngtcp2.hook.BufferArg != 10 || ngtcp2.hook.VectorCountArg != 11 ||
		ngtcp2.hook.LengthSource != openssl.AppDataLengthMemory ||
		ngtcp2.hook.LengthArg != 7 || ngtcp2.hook.ContextArg != 1 ||
		ngtcp2.hook.StreamArg != 9 {
		t.Fatalf("ngtcp2 recipe = %#v", ngtcp2.hook)
	}
}

func TestScaffoldProfileRanksKnownABIs(t *testing.T) {
	report := &Report{
		Version: ReportVersion,
		PID:     4242,
		Libraries: []LibraryReport{
			{
				Path:    "/data/app/libssl.so",
				BuildID: "aabbccdd",
				Candidates: []HookCandidate{
					{
						Family:       "openssl",
						Layer:        LayerPlaintext,
						Role:         "tls-write",
						Symbol:       "SSL_write",
						SymbolSource: "dynamic",
						Confidence:   ConfidenceExact,
						Priority:     100,
						Recipe: &HookRecipe{
							Direction:    "write",
							CaptureOn:    "entry",
							BufferArg:    2,
							LengthSource: "argument",
							LengthArg:    3,
							MaxBytes:     131072,
						},
					},
					{
						Family:       "openssl",
						Layer:        LayerCrypto,
						Role:         "application-encrypt",
						Symbol:       "EVP_EncryptUpdate",
						SymbolSource: "dynamic",
						Confidence:   ConfidenceExact,
						Priority:     55,
					},
				},
			},
			{
				Path:    "/data/app/libquiche.so",
				BuildID: "11223344",
				Candidates: []HookCandidate{{
					Family:       "quiche",
					Layer:        LayerPlaintext,
					Role:         "quic-stream-send",
					Symbol:       "quiche_conn_stream_send",
					SymbolSource: "symtab",
					FileOffset:   "0x1234",
					Confidence:   ConfidenceExact,
					Priority:     94,
					Recipe: &HookRecipe{
						Direction:    "write",
						CaptureOn:    "entry",
						BufferArg:    3,
						LengthSource: "argument",
						LengthArg:    4,
						MaxBytes:     131072,
						ContextArg:   1,
						StreamArg:    2,
					},
				}},
			},
		},
	}
	profile, err := ScaffoldProfile(report, ScaffoldOptions{MaxHooks: 2})
	if err != nil {
		t.Fatalf("ScaffoldProfile() error = %v", err)
	}
	if profile.Match.PID != 4242 || len(profile.DataHooks) != 2 {
		t.Fatalf("unexpected generated profile: %#v", profile)
	}
	if profile.DataHooks[0].Symbol != "SSL_write" {
		t.Fatalf("first hook = %#v", profile.DataHooks[0])
	}
	if uint64(profile.DataHooks[1].Offset) != 0x1234 ||
		profile.DataHooks[1].ContextArg != 1 ||
		profile.DataHooks[1].StreamArg != 2 {
		t.Fatalf("second hook = %#v", profile.DataHooks[1])
	}
	if len(profile.Capture.Strategies) != 2 ||
		profile.Capture.Strategies[0] != openssl.StrategyRawPackets ||
		profile.Capture.Strategies[1] != openssl.StrategyAppData {
		t.Fatalf("capture strategies = %#v", profile.Capture.Strategies)
	}
}

func TestScaffoldProfileWithoutDirectCandidatesKeepsRawPackets(t *testing.T) {
	report := &Report{
		Version: ReportVersion,
		PID:     7,
		Libraries: []LibraryReport{{
			Path: "/tmp/libcustom.so",
			Candidates: []HookCandidate{{
				Family: "custom",
				Layer:  LayerSemantic,
				Role:   "hint",
				Symbol: "custom_serializer",
			}},
		}},
	}
	profile, err := ScaffoldProfile(report, ScaffoldOptions{})
	if err != nil {
		t.Fatalf("ScaffoldProfile() error = %v", err)
	}
	if len(profile.DataHooks) != 0 || len(profile.Capture.Strategies) != 1 ||
		profile.Capture.Strategies[0] != openssl.StrategyRawPackets {
		t.Fatalf("unexpected raw-only profile: %#v", profile)
	}
}

func TestScaffoldProfilePreservesIOVecRecipe(t *testing.T) {
	recipe, found := candidateForSymbol("readv")
	if !found || recipe.hook == nil {
		t.Fatal("readv recipe is unavailable")
	}
	report := &Report{
		Version: ReportVersion,
		PID:     77,
		Libraries: []LibraryReport{{
			Path:    "/usr/lib/libc.so.6",
			BuildID: "aabbccdd",
			Candidates: []HookCandidate{{
				Family:       recipe.family,
				Layer:        recipe.layer,
				Role:         recipe.role,
				Symbol:       "readv",
				SymbolSource: "dynamic",
				Confidence:   recipe.confidence,
				Priority:     recipe.priority,
				Recipe:       cloneHookRecipe(recipe.hook),
			}},
		}},
	}
	profile, err := ScaffoldProfile(report, ScaffoldOptions{MaxHooks: 1})
	if err != nil {
		t.Fatalf("ScaffoldProfile() error = %v", err)
	}
	if len(profile.DataHooks) != 1 {
		t.Fatalf("data hooks = %#v", profile.DataHooks)
	}
	hook := profile.DataHooks[0]
	if hook.Symbol != "readv" || hook.BufferFormat != openssl.AppDataBufferIOVec ||
		hook.VectorCountArg != 3 || hook.CaptureOn != openssl.AppDataCaptureReturn ||
		hook.ContextArg != 1 {
		t.Fatalf("scaffolded readv hook = %#v", hook)
	}
}

func TestScaffoldProfilePreservesHighArgumentQUICRecipe(t *testing.T) {
	recipe, found := candidateForSymbol("ngtcp2_conn_writev_stream_versioned")
	if !found || recipe.hook == nil {
		t.Fatal("ngtcp2 versioned writev recipe is unavailable")
	}
	report := &Report{
		Version: ReportVersion,
		PID:     88,
		Libraries: []LibraryReport{{
			Path:    "/usr/lib/libngtcp2.so",
			BuildID: "11223344",
			Candidates: []HookCandidate{{
				Family:       recipe.family,
				Layer:        recipe.layer,
				Role:         recipe.role,
				Symbol:       "ngtcp2_conn_writev_stream_versioned",
				SymbolSource: "dynamic",
				Confidence:   recipe.confidence,
				Priority:     recipe.priority,
				Recipe:       cloneHookRecipe(recipe.hook),
			}},
		}},
	}
	profile, err := ScaffoldProfile(report, ScaffoldOptions{MaxHooks: 1})
	if err != nil {
		t.Fatalf("ScaffoldProfile() error = %v", err)
	}
	if len(profile.DataHooks) != 1 {
		t.Fatalf("data hooks = %#v", profile.DataHooks)
	}
	hook := profile.DataHooks[0]
	if hook.BufferArg != 10 || hook.VectorCountArg != 11 ||
		hook.LengthSource != openssl.AppDataLengthMemory ||
		hook.LengthArg != 7 || hook.LengthSize != 8 ||
		hook.ContextArg != 1 || hook.StreamArg != 9 {
		t.Fatalf("scaffolded ngtcp2 hook = %#v", hook)
	}
}

func TestScaffoldProfileAddsJNIDiscoveryAndDropsRestartPID(t *testing.T) {
	report := &Report{
		Version: ReportVersion,
		PID:     4242,
		Libraries: []LibraryReport{{
			Path:    "/apex/com.android.art/lib64/libart.so",
			BuildID: "aabbccdd",
			Candidates: []HookCandidate{
				{
					Family:       "art-jni",
					Layer:        LayerSemantic,
					Role:         "register-natives",
					Symbol:       "JNINativeInterface.RegisterNatives",
					SymbolSource: "function-table",
					FileOffset:   "0x4d1ef4",
					Confidence:   ConfidenceExact,
					Priority:     100,
				},
				{
					Family:       "art-jni",
					Layer:        LayerSemantic,
					Role:         "register-natives",
					Symbol:       "JNINativeInterface.RegisterNatives",
					SymbolSource: "function-table",
					FileOffset:   "0x8171b0",
					Confidence:   ConfidenceExact,
					Priority:     100,
				},
			},
		}},
	}
	profile, err := ScaffoldProfile(report, ScaffoldOptions{
		Package: "com.example.app",
		PID:     4242,
	})
	if err != nil {
		t.Fatalf("ScaffoldProfile() error = %v", err)
	}
	if profile.Match.Package != "com.example.app" || profile.Match.PID != 0 {
		t.Fatalf("restart-safe match = %#v", profile.Match)
	}
	if profile.JNI == nil ||
		len(profile.JNI.RegisterNativesOffsets) != 2 ||
		uint64(profile.JNI.RegisterNativesOffsets[0]) != 0x4d1ef4 {
		t.Fatalf("JNI discovery profile = %#v", profile.JNI)
	}
	if len(profile.Capture.Strategies) != 2 ||
		profile.Capture.Strategies[1] != openssl.StrategyJNIDiscovery {
		t.Fatalf("capture strategies = %#v", profile.Capture.Strategies)
	}
}
