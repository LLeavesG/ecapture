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

package base

import (
	"encoding/json"
	"testing"
	"time"
)

func TestReaderStatsSnapshotTracksPerfAndRingbufPressure(t *testing.T) {
	probe := NewBaseProbe("test")
	probe.noteReaderRecord(false, 128)
	probe.noteReaderRecord(true, 256)
	probe.readerStats.lostSamples.Add(3)
	probe.readerStats.decodeErrors.Add(1)

	stats := probe.ReaderStats()
	if stats.PerfRecords != 1 || stats.PerfRawBytes != 128 {
		t.Fatalf("unexpected perf stats: %#v", stats)
	}
	if stats.RingbufRecords != 1 || stats.RingbufRawBytes != 256 {
		t.Fatalf("unexpected ringbuf stats: %#v", stats)
	}
	if stats.LostSamples != 3 || stats.DecodeErrors != 1 {
		t.Fatalf("unexpected loss/error stats: %#v", stats)
	}
}

func TestReaderStatsEventUsesStableJSONContract(t *testing.T) {
	event := &ReaderStatsEvent{
		EventType: "capture_stats",
		Probe:     "openssl",
		Final:     true,
		Timestamp: time.Unix(123, 0).UTC(),
		ReaderStatsSnapshot: ReaderStatsSnapshot{
			PerfRecords: 42,
			LostSamples: 2,
		},
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["eventType"] != "capture_stats" ||
		decoded["probe"] != "openssl" ||
		decoded["perfRecords"] != float64(42) ||
		decoded["lostSamples"] != float64(2) ||
		decoded["final"] != true {
		t.Fatalf("unexpected JSON: %s", data)
	}
}
