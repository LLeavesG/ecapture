// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ktime

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMonotonicToWallTime(t *testing.T) {
	offset, err := RealtimeOffset()
	if err != nil {
		t.Fatalf("RealtimeOffset() error = %v", err)
	}
	var monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		t.Fatal(err)
	}
	got := ToWallTime(uint64(monotonic.Nano()), offset)
	if delta := time.Since(got).Abs(); delta > time.Second {
		t.Fatalf("converted wall time differs from now by %s", delta)
	}
}
