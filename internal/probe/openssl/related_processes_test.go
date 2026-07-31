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
	"sort"
	"testing"
	"time"
)

func TestParseAndroidRelatedProcessUIDs(t *testing.T) {
	const output = `
  *APP* UID 99050 ProcessRecord{8b97c24 17029:com.google.android.webview:sandboxed_process0/u0a137i50}
    user #0 uid=10137 ISOLATED uid=99050 gids={}
    packageList={com.google.android.googlequicksearchbox}
  *APP* UID 99051 ProcessRecord{other}
    packageList={com.example.unrelated}
  *APP* UID 10290 ProcessRecord{host}
    packageList={com.larus.nova, com.example.shared}
  *APP* UID 99052 ProcessRecord{renderer}
    packageList={com.example.shared com.larus.nova}
`
	got := parseAndroidRelatedProcessUIDs(output, "com.larus.nova")
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	want := []uint32{10290, 99052}
	if len(got) != len(want) {
		t.Fatalf("UIDs = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("UIDs = %#v, want %#v", got, want)
		}
	}
}

func TestParseAndroidRelatedProcessUIDsExactPackage(t *testing.T) {
	const output = `
  *APP* UID 99050 ProcessRecord{renderer}
    packageList={com.example.application.extra}
`
	if got := parseAndroidRelatedProcessUIDs(
		output,
		"com.example.application",
	); len(got) != 0 {
		t.Fatalf("prefix package unexpectedly matched: %#v", got)
	}
}

func TestRelatedUIDWatchBacksOffOnlyAfterFastWindow(t *testing.T) {
	now := time.Unix(100, 0)
	if got := relatedUIDWatchInterval(
		now,
		now.Add(time.Second),
	); got != relatedUIDFastWatchInterval {
		t.Fatalf("fast interval = %s", got)
	}
	if got := relatedUIDWatchInterval(
		now,
		now.Add(-time.Second),
	); got != relatedUIDSteadyWatchInterval {
		t.Fatalf("steady interval = %s", got)
	}
}

func TestSameUIDSetIgnoresOrderAndDetectsChanges(t *testing.T) {
	left := map[uint32]struct{}{90001: {}, 90002: {}}
	right := map[uint32]struct{}{90002: {}, 90001: {}}
	if !sameUIDSet(left, right) {
		t.Fatal("equal UID sets were reported as changed")
	}
	right[90003] = struct{}{}
	if sameUIDSet(left, right) {
		t.Fatal("changed UID sets were reported as equal")
	}
}
