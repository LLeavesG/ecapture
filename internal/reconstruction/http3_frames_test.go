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
	"encoding/json"
	"strings"
	"testing"
)

func TestReconstructHTTP3FramesAndQPACKStream(t *testing.T) {
	request := appendHTTP3Frame(nil, 1, []byte{0, 0, 0xd1})
	request = appendHTTP3Frame(request, 0, []byte("body"))
	control := encodeQUICVarintForTest(0)
	control = appendHTTP3Frame(control, 4, []byte{1, 0})
	qpack := encodeQUICVarintForTest(2)
	qpack = append(qpack, 0x3f, 0xe1, 0x1f)
	input := strings.Join([]string{
		quicBoundaryEvent(10, "WRITE", 0, nil, boolPointer(true), request),
		quicBoundaryEvent(11, "WRITE", 2, nil, boolPointer(false), control),
		quicBoundaryEvent(12, "WRITE", 6, nil, boolPointer(false), qpack),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP3Frames(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructHTTP3Frames() error = %v", err)
	}
	if summary.Frames != 3 || summary.HeaderFrames != 1 ||
		summary.DataFrames != 1 || summary.ControlFrames != 1 ||
		summary.QPACKStreams != 1 || summary.StreamsProcessed != 3 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	decoder := json.NewDecoder(&output)
	var records []HTTP3Record
	for decoder.More() {
		var record HTTP3Record
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if len(records) != 4 {
		t.Fatalf("got %d records: %s", len(records), output.String())
	}
	var sawHeaders, sawData, sawSettings, sawQPACK bool
	for _, record := range records {
		switch {
		case record.FrameName == "HEADERS":
			sawHeaders = bytes.Equal(record.Data, []byte{0, 0, 0xd1})
		case record.FrameName == "DATA":
			sawData = bytes.Equal(record.Data, []byte("body"))
		case record.FrameName == "SETTINGS":
			sawSettings = record.StreamName == "control"
		case record.EventType == "qpack_stream":
			sawQPACK = record.StreamName == "qpack_encoder" &&
				bytes.Equal(record.Data, []byte{0x3f, 0xe1, 0x1f})
		}
	}
	if !sawHeaders || !sawData || !sawSettings || !sawQPACK {
		t.Fatalf("records were not classified correctly: %#v", records)
	}
}

func TestReconstructHTTP3FramesIgnoresGQUICConnection(t *testing.T) {
	headers := makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders,
		5,
		[]byte{0x82},
	)
	input := strings.Join([]string{
		quicBoundaryEvent(10, "WRITE", 3, nil, boolPointer(false), headers),
		quicBoundaryEvent(11, "WRITE", 5, nil, boolPointer(true), []byte{0, 1, 'x'}),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP3Frames(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructHTTP3Frames() error = %v", err)
	}
	if summary.StreamsProcessed != 0 || output.Len() != 0 {
		t.Fatalf("gQUIC was misclassified as HTTP/3: %#v %s",
			summary, output.String())
	}
}

func appendHTTP3Frame(destination []byte, frameType uint64, payload []byte) []byte {
	destination = append(destination, encodeQUICVarintForTest(frameType)...)
	destination = append(destination,
		encodeQUICVarintForTest(uint64(len(payload)))...)
	return append(destination, payload...)
}

func encodeQUICVarintForTest(value uint64) []byte {
	switch {
	case value < 1<<6:
		return []byte{byte(value)}
	case value < 1<<14:
		return []byte{byte(value>>8) | 0x40, byte(value)}
	case value < 1<<30:
		return []byte{
			byte(value>>24) | 0x80,
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	default:
		return []byte{
			byte(value>>56) | 0xc0,
			byte(value >> 48),
			byte(value >> 40),
			byte(value >> 32),
			byte(value >> 24),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	}
}
