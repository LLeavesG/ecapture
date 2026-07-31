//go:build linux

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
	"reflect"
	"testing"
)

func TestParseCPUList(t *testing.T) {
	got, err := parseCPUList("0-3,5,7-8,3")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{0, 1, 2, 3, 5, 7, 8}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseCPUList() = %v, want %v", got, want)
	}
}

func TestParseCPUListRejectsInvalidRanges(t *testing.T) {
	for _, value := range []string{"", "3-1", "x", "1,", "-2"} {
		if _, err := parseCPUList(value); err == nil {
			t.Fatalf("parseCPUList(%q) unexpectedly succeeded", value)
		}
	}
}
