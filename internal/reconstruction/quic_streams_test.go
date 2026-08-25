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

package reconstruction

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestReconstructQUICStreamsExplicitOffsetsAndFinOnly(t *testing.T) {
	input := strings.Join([]string{
		quicBoundaryEvent(12, "READ", 7, uint64Pointer(5), boolPointer(false), []byte("world")),
		quicBoundaryEvent(10, "READ", 7, uint64Pointer(0), boolPointer(false), []byte("hello")),
		quicBoundaryEvent(13, "READ", 7, uint64Pointer(0), boolPointer(false), []byte("hello")),
		quicBoundaryEvent(14, "READ", 7, uint64Pointer(10), boolPointer(true), nil),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructQUICStreams(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructQUICStreams() error = %v", err)
	}
	if summary.Streams != 1 || summary.CompleteStreams != 1 ||
		summary.DuplicateBytes != 5 || summary.MissingBytes != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	var stream QUICStream
	if err := json.Unmarshal(output.Bytes(), &stream); err != nil {
		t.Fatal(err)
	}
	if stream.OffsetMode != "explicit" || string(stream.Data) != "helloworld" ||
		!stream.Fin || !stream.Complete ||
		stream.FinalOffset == nil || *stream.FinalOffset != 10 {
		t.Fatalf("unexpected stream: %#v data=%q", stream, stream.Data)
	}
}

func TestReconstructQUICStreamsDeduplicatesRedundantHookCoverage(t *testing.T) {
	payload := []byte("redundant-boundary")
	input := strings.Join([]string{
		quicBoundaryEventForHook(
			10, "quic-router", 1, "READ", 7,
			uint64Pointer(0), boolPointer(true), payload,
		),
		quicBoundaryEventForHook(
			11, "quic-stream-fallback", 2, "READ", 7,
			uint64Pointer(0), boolPointer(true), payload,
		),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructQUICStreams(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructQUICStreams() error = %v", err)
	}
	if summary.Streams != 1 || summary.CompleteStreams != 1 ||
		summary.DuplicateBytes != uint64(len(payload)) ||
		summary.ConflictingBytes != 0 || summary.MissingBytes != 0 {
		t.Fatalf("unexpected redundant-hook summary: %#v", summary)
	}
}

func TestReconstructQUICStreamsInfersOrderedWriteOffsets(t *testing.T) {
	input := strings.Join([]string{
		quicBoundaryEvent(10, "WRITE", 9, nil, boolPointer(false), []byte("hello")),
		quicBoundaryEvent(11, "WRITE", 9, nil, boolPointer(true), []byte("world")),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructQUICStreams(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructQUICStreams() error = %v", err)
	}
	if summary.InferredOffsetStreams != 1 || summary.CompleteStreams != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	var stream QUICStream
	if err := json.Unmarshal(output.Bytes(), &stream); err != nil {
		t.Fatal(err)
	}
	if stream.OffsetMode != "inferred" || string(stream.Data) != "helloworld" ||
		!stream.Complete {
		t.Fatalf("unexpected stream: %#v data=%q", stream, stream.Data)
	}
}

func TestReconstructQUICStreamsReportsGapAndConflict(t *testing.T) {
	input := strings.Join([]string{
		quicBoundaryEvent(10, "READ", 11, uint64Pointer(2), boolPointer(false), []byte("abc")),
		quicBoundaryEvent(11, "READ", 11, uint64Pointer(4), boolPointer(false), []byte("Z")),
		quicBoundaryEvent(12, "READ", 11, uint64Pointer(5), boolPointer(true), nil),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructQUICStreams(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructQUICStreams() error = %v", err)
	}
	if summary.ConflictingBytes != 1 || summary.MissingBytes != 2 ||
		summary.CompleteStreams != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	var stream QUICStream
	if err := json.Unmarshal(output.Bytes(), &stream); err != nil {
		t.Fatal(err)
	}
	if stream.Complete || len(stream.Missing) != 1 ||
		stream.Missing[0] != (QUICByteRange{Start: 0, End: 2}) ||
		len(stream.Errors) == 0 {
		t.Fatalf("gap/conflict evidence missing: %#v", stream)
	}
}

func quicBoundaryEvent(
	timestamp uint64,
	direction string,
	streamID uint64,
	offset *uint64,
	fin *bool,
	data []byte,
) string {
	return quicBoundaryEventForHook(
		timestamp, "quiche-boundary", 1, direction, streamID, offset, fin, data,
	)
}

func quicBoundaryEventForHook(
	timestamp uint64,
	hookName string,
	hookID int,
	direction string,
	streamID uint64,
	offset *uint64,
	fin *bool,
	data []byte,
) string {
	event := map[string]any{
		"eventType":    "boundary_data",
		"captureLayer": "transport",
		"transport":    "quic",
		"timestamp":    timestamp,
		"pid":          42,
		"tid":          43,
		"direction":    direction,
		"hookId":       hookID,
		"hookName":     hookName,
		"bufferAddr":   4096 + timestamp,
		"contextId":    0x1234,
		"streamId":     streamID,
		"originalLen":  len(data),
		"capturedLen":  len(data),
		"chunkOffset":  0,
		"dataLen":      len(data),
		"dataEncoding": "base64",
		"data":         base64.StdEncoding.EncodeToString(data),
	}
	if offset != nil {
		event["streamOffset"] = *offset
	}
	if fin != nil {
		event["fin"] = *fin
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		panic(fmt.Sprintf("encode test event: %v", err))
	}
	return string(encoded)
}

func uint64Pointer(value uint64) *uint64 {
	return &value
}

func boolPointer(value bool) *bool {
	return &value
}
