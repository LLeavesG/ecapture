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
	"strings"
	"testing"

	"github.com/gojue/ecapture/internal/probe/openssl"
)

func TestLearnJNIJSONRanksPayloadBoundaries(t *testing.T) {
	input := `
{"eventType":"jni_register_natives","functionAddr":4096,"pid":42,"hookId":2,"methodName":"nativeCreateWorker","methodSignature":"(Ljava/nio/ByteBuffer;[B)J","modulePath":"/data/app/pkg/lib/arm64/libworker.so","moduleOffset":246504}
{"eventType":"jni_register_natives","functionAddr":4096,"pid":42,"hookId":2,"methodName":"nativeCreateWorker","methodSignature":"(Ljava/nio/ByteBuffer;[B)J","modulePath":"/data/app/pkg/lib/arm64/libworker.so","moduleOffset":246504}
{"eventType":"jni_register_natives","functionAddr":8192,"pid":42,"hookId":2,"methodName":"nativeInit","methodSignature":"()V","modulePath":"/apex/com.android.art/lib64/libart.so","moduleOffset":512}
{"eventType":"tls","pid":42}
`
	report, err := learnJNIBytes(input)
	if err != nil {
		t.Fatalf("LearnJNI() error = %v", err)
	}
	if report.InputFormat != "json" || report.EventsObserved != 3 ||
		report.UniqueMethods != 2 || report.ResolvedMethods != 3 {
		t.Fatalf("unexpected report summary: %#v", report)
	}
	first := report.Candidates[0]
	if first.MethodName != "nativeCreateWorker" || first.Observations != 2 ||
		first.Score < 90 || first.AutoHookSafe {
		t.Fatalf("unexpected first candidate: %#v", first)
	}
	if !containsString(first.PayloadKinds, "byte-array") ||
		!containsString(first.PayloadKinds, "direct-or-heap-byte-buffer") {
		t.Fatalf("payload kinds were not classified: %#v", first.PayloadKinds)
	}
	if first.ModuleOffset != "0x3c2e8" || first.FunctionAddress != "0x1000" {
		t.Fatalf("target was not preserved: %#v", first)
	}
}

func TestLearnJNIPlainText(t *testing.T) {
	input := strings.Join([]string{
		"[2026-07-29 14:02:02.000] PID:28831 TID:28831 Comm:com.larus.nova JNI RegisterNatives[2] fetchString(Ljava/lang/String;)Ljava/lang/String; -> /data/app/pkg/lib/arm64/libkeva.so+0x23e2c (1/8)",
		"[2026-07-29 14:02:02.001] PID:28831 TID:28831 Comm:com.larus.nova JNI RegisterNatives[2] nativeWrite([B)V -> /data/app/pkg/lib/arm64/libworker.so+0x3c2e8 (2/8)",
	}, "\n")
	report, err := learnJNIBytes(input)
	if err != nil {
		t.Fatalf("LearnJNI() error = %v", err)
	}
	if report.InputFormat != "plain" || report.EventsObserved != 2 ||
		report.UniqueMethods != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if report.Candidates[0].MethodName != "nativeWrite" {
		t.Fatalf("plain candidates were not ranked: %#v", report.Candidates)
	}
}

func TestLearnJNIJSONRanksTextAndBinaryConversionCallsites(t *testing.T) {
	input := `
{"eventType":"jni_conversion","pid":42,"tid":43,"role":"get_string_utf_chars","phase":"acquire","byteLength":36,"dataLen":36,"data":"aHR0cHM6Ly9hcGkuZXhhbXBsZS9jaGF0L2NvbXBsZXRpb25z","callerModulePath":"/data/app/pkg/lib/arm64/libnet.so","callerModuleOffset":4660,"callerModuleBuildID":"11223344"}
{"eventType":"jni_conversion","pid":42,"tid":43,"role":"get_string_utf_chars","phase":"acquire","byteLength":36,"dataLen":36,"data":"aHR0cHM6Ly9hcGkuZXhhbXBsZS9jaGF0L2NvbXBsZXRpb25z","callerModulePath":"/data/app/pkg/lib/arm64/libnet.so","callerModuleOffset":4660,"callerModuleBuildID":"11223344"}
{"eventType":"jni_conversion","pid":42,"tid":44,"role":"set_byte_array_region","phase":"region","byteLength":8,"dataLen":8,"data":"CJYBEgNhYmM=","callerModulePath":"/data/app/pkg/lib/arm64/libcodec.so","callerModuleOffset":9029,"callerModuleBuildID":"99887766"}
{"eventType":"jni_conversion","pid":42,"tid":45,"role":"get_string_chars","phase":"acquire","byteLength":8,"dataLen":8,"data":"dABlAHMAdAA=","callerModulePath":"/apex/com.android.i18n/lib64/libicu_jni.so","callerModuleOffset":1280}
{"eventType":"jni_conversion","pid":42,"tid":45,"role":"get_string_chars","phase":"acquire","callerModulePath":"","callerModuleOffset":0}
`
	report, err := learnJNIBytes(input)
	if err != nil {
		t.Fatalf("LearnJNI() error = %v", err)
	}
	if report.ConversionEventsObserved != 5 ||
		report.UniqueConversionCallsites != 3 ||
		report.UnresolvedConversionEvents != 1 {
		t.Fatalf("unexpected conversion summary: %#v", report)
	}
	first := report.ConversionCandidates[0]
	if first.Role != openssl.JNIConversionGetStringUTFChars ||
		first.ModuleOffset != "0x1234" ||
		first.BuildID != "11223344" ||
		!first.BuildIDPinned ||
		first.Observations != 2 ||
		first.StructuredHints != 2 ||
		first.Score < 95 ||
		first.ProfileRule.Module != "libnet.so" ||
		first.ProfileRule.BuildID != "11223344" {
		t.Fatalf("unexpected first conversion candidate: %#v", first)
	}
	var binary JNIConversionCandidate
	for _, candidate := range report.ConversionCandidates {
		if candidate.Role == openssl.JNIConversionSetByteArrayRegion {
			binary = candidate
			break
		}
	}
	if binary.BinaryPayloads != 1 || binary.Score < 90 {
		t.Fatalf("binary callsite was not retained: %#v", binary)
	}
	if report.ConversionCandidates[len(report.ConversionCandidates)-1].ModulePath !=
		"/apex/com.android.i18n/lib64/libicu_jni.so" {
		t.Fatalf("system callsite was not demoted: %#v", report.ConversionCandidates)
	}
}

func TestLearnJNIWithOptionsMarksInjectedPayload(t *testing.T) {
	input := `
{"eventType":"jni_conversion","pid":42,"tid":43,"role":"get_string_utf_chars","phase":"acquire","byteLength":25,"dataLen":25,"data":"eyJ0ZXh0IjoiRUI4UEYtTUFSS0VSIn0=","callerModulePath":"/data/app/pkg/lib/arm64/libnet.so","callerModuleOffset":4660,"callerModuleBuildID":"aabbccdd"}
{"eventType":"jni_conversion","pid":42,"tid":44,"role":"get_string_utf_chars","phase":"acquire","byteLength":7,"dataLen":7,"data":"bm9pc2UteA==","callerModulePath":"/data/app/pkg/lib/arm64/libnoise.so","callerModuleOffset":9029}
`
	report, err := LearnJNIWithOptions(
		strings.NewReader(input),
		JNILearningOptions{Markers: [][]byte{[]byte("EB8PF-MARKER")}},
	)
	if err != nil {
		t.Fatalf("LearnJNIWithOptions() error = %v", err)
	}
	if len(report.ConversionCandidates) != 2 {
		t.Fatalf("unexpected candidates: %#v", report.ConversionCandidates)
	}
	first := report.ConversionCandidates[0]
	if first.ProfileRule.Module != "libnet.so" ||
		first.ProfileRule.BuildID != "aabbccdd" ||
		first.BuildID != "aabbccdd" ||
		first.MarkerHits != 1 ||
		first.Score < 140 {
		t.Fatalf("marker did not promote the matching callsite: %#v", first)
	}
	if report.ConversionCandidates[1].MarkerHits != 0 {
		t.Fatalf("noise callsite matched marker: %#v", report.ConversionCandidates[1])
	}
}

func TestPromoteJNIConversionCallersBuildsValidatedProfile(t *testing.T) {
	profile := &openssl.ApplicationProfile{
		Version: openssl.ApplicationProfileVersion,
		Name:    "diagnostic",
		Match:   openssl.ApplicationMatch{Package: "com.example.app"},
		Capture: openssl.ApplicationCapture{
			Strategies: []string{openssl.StrategyJNIDiscovery},
		},
		JNI: &openssl.JNIDiscoveryProfile{
			Library: "/apex/com.android.art/lib64/libart.so",
			ConversionOffsets: map[string][]openssl.OffsetValue{
				openssl.JNIConversionGetStringUTFChars: {0x1000},
			},
		},
	}
	candidates := []JNIConversionCandidate{{
		KernelFilterReady: true,
		BuildIDPinned:     true,
		BuildID:           "11223344",
		ProfileRule: openssl.JNIConversionCaller{
			Module:  "libnet.so",
			BuildID: "11223344",
			Role:    openssl.JNIConversionGetStringUTFChars,
			Offset:  0x1234,
		},
	}}
	if err := PromoteJNIConversionCallers(profile, candidates); err != nil {
		t.Fatalf("PromoteJNIConversionCallers() error = %v", err)
	}
	if len(profile.JNI.CallerAllowlist) != 1 ||
		profile.JNI.CallerAllowlist[0].BuildID != "11223344" ||
		profile.Metadata["jni_caller_allowlist_entries"] != "1" {
		t.Fatalf("unexpected promoted profile: %#v", profile)
	}
}

func TestLearnJNIRejectsEmptyInput(t *testing.T) {
	if _, err := learnJNIBytes(" \n\t"); err == nil {
		t.Fatal("LearnJNI() should reject empty input")
	}
}
