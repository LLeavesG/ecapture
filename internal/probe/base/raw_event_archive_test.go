// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.

package base

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestRawEventArchivePreservesFramedSamplesAndLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perf-events.raw")
	archive, err := newRawEventArchive(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := archive.write(rawEventSourcePerf, "app_data_events", 0,
		[]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := archive.write(rawEventSourcePerf, "skb_events", 7, nil); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte(rawEventArchiveMagic)) {
		t.Fatalf("archive header = %q", data[:8])
	}
	frames := data[len(rawEventArchiveMagic):]
	firstLength := int(binary.LittleEndian.Uint32(frames[0:4])) + 4
	first := frames[:firstLength]
	if binary.LittleEndian.Uint16(first[4:6]) != rawEventArchiveVersion ||
		first[6] != rawEventSourcePerf || first[7] != 0 ||
		binary.LittleEndian.Uint64(first[8:16]) != 1 ||
		binary.LittleEndian.Uint64(first[16:24]) != 0 ||
		binary.LittleEndian.Uint16(first[24:26]) != 15 ||
		binary.LittleEndian.Uint32(first[28:32]) != 3 ||
		string(first[32:47]) != "app_data_events" ||
		!bytes.Equal(first[47:], []byte{1, 2, 3}) {
		t.Fatalf("unexpected first raw frame: %x", first)
	}
	second := frames[firstLength:]
	if binary.LittleEndian.Uint64(second[8:16]) != 2 ||
		binary.LittleEndian.Uint64(second[16:24]) != 7 ||
		second[7]&rawEventFlagLost == 0 ||
		binary.LittleEndian.Uint32(second[28:32]) != 0 {
		t.Fatalf("unexpected lost-sample frame: %x", second)
	}
}
