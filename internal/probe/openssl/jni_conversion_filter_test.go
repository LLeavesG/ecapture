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
	"fmt"
	"testing"
)

func TestResolveJNIConversionCallerRulesTranslatesASLR(t *testing.T) {
	mappings := []processModuleMapping{
		{
			start:      0x70001000,
			end:        0x70005000,
			fileOffset: 0x1000,
			executable: true,
			path:       "/data/app/random/pkg/lib/arm64/libworker.so",
		},
		{
			start:      0x71002000,
			end:        0x71004000,
			fileOffset: 0x2000,
			executable: true,
			path:       "/data/app/random/pkg/lib/arm64/libother.so",
		},
	}
	rules := []JNIConversionCaller{
		{
			Module: "libworker.so",
			Role:   JNIConversionGetStringUTFChars,
			Offset: 0x2340,
		},
		{
			ModuleGlob: "/data/app/*/pkg/lib/arm64/libother.so",
			Role:       JNIConversionSetByteArrayRegion,
			Offset:     0x2100,
		},
	}
	keys, unresolved, err := resolveJNIConversionCallerRules(mappings, rules, nil)
	if err != nil {
		t.Fatalf("resolveJNIConversionCallerRules() error = %v", err)
	}
	if len(unresolved) != 0 || len(keys) != 2 {
		t.Fatalf("keys=%#v unresolved=%v", keys, unresolved)
	}
	if keys[0].CallerAddr != 0x70002340 ||
		keys[1].CallerAddr != 0x71002100 {
		t.Fatalf("unexpected translated callers: %#v", keys)
	}
	if keys[0].Role == keys[1].Role {
		t.Fatalf("role was not included in filter key: %#v", keys)
	}
}

func TestResolveJNIConversionCallerRulesWaitsForEveryModule(t *testing.T) {
	mappings := []processModuleMapping{{
		start:      0x70001000,
		end:        0x70005000,
		fileOffset: 0x1000,
		executable: true,
		path:       "/data/app/pkg/libworker.so",
	}}
	rules := []JNIConversionCaller{
		{
			Module: "libworker.so",
			Role:   JNIConversionGetStringUTFChars,
			Offset: 0x2340,
		},
		{
			Module: "liblate.so",
			Role:   JNIConversionGetByteArrayElements,
			Offset: 0x3000,
		},
	}
	keys, unresolved, err := resolveJNIConversionCallerRules(mappings, rules, nil)
	if err != nil {
		t.Fatalf("resolveJNIConversionCallerRules() error = %v", err)
	}
	if len(keys) != 1 || len(unresolved) != 1 || unresolved[0] != 1 {
		t.Fatalf("keys=%#v unresolved=%v", keys, unresolved)
	}
}

func TestResolveJNIConversionCallerRulesRejectsBuildIDMismatch(t *testing.T) {
	mappings := []processModuleMapping{{
		start:      0x70001000,
		end:        0x70005000,
		fileOffset: 0x1000,
		executable: true,
		path:       "/data/app/pkg/libworker.so",
	}}
	rules := []JNIConversionCaller{{
		Module:  "libworker.so",
		BuildID: "11223344",
		Role:    JNIConversionGetStringUTFChars,
		Offset:  0x2340,
	}}
	_, unresolved, err := resolveJNIConversionCallerRules(
		mappings,
		rules,
		func(path, buildID string) error {
			return fmt.Errorf("%s has another Build ID, want %s", path, buildID)
		},
	)
	if err == nil || len(unresolved) != 1 {
		t.Fatalf("error=%v unresolved=%v", err, unresolved)
	}
}
