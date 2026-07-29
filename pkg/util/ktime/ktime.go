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
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// RealtimeOffset returns CLOCK_REALTIME - CLOCK_MONOTONIC in nanoseconds.
// Adding it to a bpf_ktime_get_ns timestamp produces a PCAP-compatible wall
// clock timestamp.
func RealtimeOffset() (int64, error) {
	var realtime unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realtime); err != nil {
		return 0, fmt.Errorf("read CLOCK_REALTIME: %w", err)
	}
	var monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		return 0, fmt.Errorf("read CLOCK_MONOTONIC: %w", err)
	}
	return realtime.Nano() - monotonic.Nano(), nil
}

func ToWallTime(monotonicNs uint64, realtimeOffset int64) time.Time {
	return time.Unix(0, int64(monotonicNs)+realtimeOffset)
}
