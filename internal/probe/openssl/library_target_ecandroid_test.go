//go:build ecap_android

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
	"os"
	"strconv"
	"strings"
	"testing"
)

// This test is opt-in because it needs a live Android process which maps an
// uncompressed native library directly from an APK. It is used by the device
// validation workflow for WebView and Chrome providers.
func TestAndroidMappedArchiveDiscovery(t *testing.T) {
	pidText := os.Getenv("ECAPTURE_TEST_MAPPED_PID")
	if pidText == "" {
		t.Skip("ECAPTURE_TEST_MAPPED_PID is not set")
	}
	pid, err := strconv.ParseUint(pidText, 10, 64)
	if err != nil {
		t.Fatalf("invalid ECAPTURE_TEST_MAPPED_PID: %v", err)
	}
	want := os.Getenv("ECAPTURE_TEST_MAPPED_MEMBER")
	specs := mappedTLSLibrarySpecsForPID(pid)
	for _, spec := range specs {
		if want == "" || strings.Contains(spec, want) {
			target, err := resolveLibraryTarget(spec)
			if err != nil {
				t.Fatalf("resolve discovered target %q: %v", spec, err)
			}
			if !target.IsArchive() || target.ContainerOffset == 0 {
				t.Fatalf("discovered target is not archive-backed: %#v", target)
			}
			t.Logf("discovered %s at archive offset %#x",
				target.String(), target.ContainerOffset)
			return
		}
	}
	t.Fatalf("mapped archive member %q not found; candidates: %#v", want, specs)
}
