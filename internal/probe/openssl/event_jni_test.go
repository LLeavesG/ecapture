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
	"testing"
)

func TestAppendJNIDiscoveryProbesReusesSegmentPrograms(t *testing.T) {
	probe, err := NewProbe()
	if err != nil {
		t.Fatalf("NewProbe() error = %v", err)
	}
	jni := &JNIDiscoveryProfile{
		RegisterNativesOffsets: []OffsetValue{0x1000, 0x2000, 0x3000, 0x4000},
		resolvedLibrary:        "/apex/com.android.art/lib64/libart.so",
	}
	probe.config = &Config{JNIDiscovery: jni}
	probes, maps := probe.appendJNIDiscoveryProbes(nil, nil)
	wantProbes := MaxJNIRegisterHooks * JNIDiscoverySegments
	if len(probes) != wantProbes {
		t.Fatalf("probe count = %d, want %d", len(probes), wantProbes)
	}
	programs := make(map[string]struct{})
	uids := make(map[string]struct{})
	for _, current := range probes {
		programs[current.EbpfFuncName] = struct{}{}
		if _, found := uids[current.UID]; found {
			t.Fatalf("duplicate uprobe UID %q", current.UID)
		}
		uids[current.UID] = struct{}{}
	}
	if len(programs) != JNIDiscoverySegments {
		t.Fatalf("unique BPF programs = %d, want %d", len(programs), JNIDiscoverySegments)
	}
	for segment := 0; segment < JNIDiscoverySegments; segment++ {
		name := fmt.Sprintf("probe_jni_register_natives_%d", segment)
		if _, found := programs[name]; !found {
			t.Fatalf("missing segment program %q", name)
		}
	}
	if len(maps) != 2 {
		t.Fatalf("map count = %d, want 2", len(maps))
	}
}

func TestJNIDiscoveryEventMarshalJSON(t *testing.T) {
	event := &JNIDiscoveryEvent{
		Timestamp:    123,
		FunctionAddr: 0x1234,
		Pid:          42,
		Tid:          43,
		MethodCount:  2,
		MethodIndex:  1,
		HookID:       2,
		ModulePath:   "/data/app/libworker.so",
		ModuleOffset: 0x3c2e8,
	}
	copy(event.Comm[:], "doubao")
	copy(event.Name[:], "nativeCreateWorker")
	copy(event.Signature[:], "(Ljava/nio/ByteBuffer;[B)J")

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if value["eventType"] != "jni_register_natives" ||
		value["methodName"] != "nativeCreateWorker" ||
		value["methodSignature"] != "(Ljava/nio/ByteBuffer;[B)J" ||
		value["comm"] != "doubao" {
		t.Fatalf("unexpected structured event: %s", data)
	}
	if bytes.Contains(data, []byte(`"Name"`)) ||
		bytes.Contains(data, []byte(`"Signature"`)) {
		t.Fatalf("kernel byte arrays leaked into structured event: %s", data)
	}
}

func TestJNIDiscoveryEventDecode(t *testing.T) {
	var payload bytes.Buffer
	values := []any{
		uint64(123456),
		uint64(0x70001000),
		uint64(0x71002000),
		uint64(0x72003000),
		uint32(4242),
		uint32(4243),
		uint32(3),
		uint32(1),
		uint32(2),
		uint32(JNIEventFlagNameTruncated),
	}
	for _, value := range values {
		if err := binary.Write(&payload, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	var comm [TaskCommLen]byte
	copy(comm[:], "app_process64")
	var name [JNIMethodNameSize]byte
	copy(name[:], "nativeRead")
	var signature [JNIMethodSignatureSize]byte
	copy(signature[:], "(Ljava/nio/ByteBuffer;I)V")
	for _, value := range []any{comm, name, signature} {
		if err := binary.Write(&payload, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	if payload.Len() != 328 {
		t.Fatalf("serialized JNI event size = %d, want 328", payload.Len())
	}

	event := &JNIDiscoveryEvent{}
	if err := event.DecodeFromBytes(payload.Bytes()); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if event.MethodName() != "nativeRead" ||
		event.MethodSignature() != "(Ljava/nio/ByteBuffer;I)V" ||
		event.HookID != 2 || event.MethodIndex != 1 {
		t.Fatalf("decoded JNI event = %#v", event)
	}
	if event.PerfMonoNs() != 123456 {
		t.Fatalf("PerfMonoNs() = %d", event.PerfMonoNs())
	}
}

func TestResolveModuleAddress(t *testing.T) {
	input := strings.NewReader(`
70000000-70010000 r-xp 00001000 08:01 123 /data/app/with space/libnative.so
71000000-71010000 r--p 00000000 08:01 124 /data/app/base.apk
`)
	mappings, err := parseProcessModuleMappings(input)
	if err != nil {
		t.Fatalf("parseProcessModuleMappings() error = %v", err)
	}
	path, offset, found := resolveModuleAddress(mappings, 0x70000123)
	if !found || path != "/data/app/with space/libnative.so" || offset != 0x1123 {
		t.Fatalf("resolveModuleAddress() = %q %#x %v", path, offset, found)
	}
	tagged := uint64(0xab00000070000456)
	path, offset, found = resolveModuleAddress(mappings, tagged)
	if !found || path != "/data/app/with space/libnative.so" || offset != 0x1456 {
		t.Fatalf("resolveModuleAddress(tagged) = %q %#x %v", path, offset, found)
	}
	pointerAuthenticated := uint64(0xabcd000070000789)
	path, offset, found = resolveModuleAddress(mappings, pointerAuthenticated)
	if !found || path != "/data/app/with space/libnative.so" || offset != 0x1789 {
		t.Fatalf("resolveModuleAddress(pointer-authenticated) = %q %#x %v",
			path, offset, found)
	}
	if path, offset, found = resolveModuleAddress(mappings, 0x71000123); found {
		t.Fatalf("resolveModuleAddress(non-executable) = %q %#x %v, want no match",
			path, offset, found)
	}
}

func TestRegisterNativesHookID(t *testing.T) {
	offsets := []uint64{0x1000, 0x2000, 0x3000}
	for _, test := range []struct {
		observed uint64
		want     uint32
	}{
		{0x1000, 0},
		{0x2000, 1},
		{0x2004, 1},
		{0x2ffc, 2},
		{0x9999, 0},
	} {
		if got := registerNativesHookID(offsets, test.observed); got != test.want {
			t.Fatalf("registerNativesHookID(%#x) = %d, want %d",
				test.observed, got, test.want)
		}
	}
}
