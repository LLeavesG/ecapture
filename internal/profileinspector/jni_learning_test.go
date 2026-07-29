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

func TestLearnJNIRejectsEmptyInput(t *testing.T) {
	if _, err := learnJNIBytes(" \n\t"); err == nil {
		t.Fatal("LearnJNI() should reject empty input")
	}
}
