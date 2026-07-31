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

func TestReconstructOutOfOrderBoundaryChunks(t *testing.T) {
	input := strings.Join([]string{
		`{"eventType":"boundary_data","captureLayer":"transport","transport":"quic","timestamp":10,"pid":42,"tid":43,"direction":"WRITE","hookId":1,"hookName":"quiche-send","bufferAddr":4096,"contextId":4660,"streamId":7,"streamOffset":0,"fin":false,"originalLen":19,"capturedLen":19,"chunkOffset":10,"dataLen":9,"dataEncoding":"base64","data":"MS4xDQp4OiB5"}`,
		`{"eventType":"boundary_data","captureLayer":"transport","transport":"quic","timestamp":10,"pid":42,"tid":43,"direction":"WRITE","hookId":1,"hookName":"quiche-send","bufferAddr":4096,"contextId":4660,"streamId":7,"streamOffset":0,"fin":false,"originalLen":19,"capturedLen":19,"chunkOffset":0,"dataLen":10,"dataEncoding":"base64","data":"R0VUIC8gSFRUUA=="}`,
	}, "\n")
	var output bytes.Buffer
	summary, err := Reconstruct(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("Reconstruct() error = %v", err)
	}
	if summary.CallsComplete != 1 || summary.ChunksAccepted != 2 ||
		summary.CallsIncomplete != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	var call Call
	if err := json.Unmarshal(output.Bytes(), &call); err != nil {
		t.Fatalf("decode call: %v output=%s", err, output.String())
	}
	if string(call.Data) != "GET / HTTP1.1\r\nx: y" ||
		call.SourceType != "boundary_data" ||
		call.ContextID != 0x1234 || call.StreamID != 7 ||
		call.StreamOffset == nil || *call.StreamOffset != 0 ||
		call.Fin == nil || *call.Fin ||
		call.CaptureLayer != captureLayerTransport ||
		call.Transport != "quic" ||
		!call.Complete {
		t.Fatalf("unexpected reconstructed call: %#v data=%q", call, call.Data)
	}
}

func TestReconstructIgnoresSemanticEventsByDefault(t *testing.T) {
	input := `{"eventType":"application_data","captureLayer":"semantic","timestamp":10,"pid":42,"tid":43,"direction":"WRITE","hookId":1,"hookName":"request-log","bufferAddr":4096,"originalLen":4,"capturedLen":4,"chunkOffset":0,"dataLen":4,"dataEncoding":"base64","data":"bG9nIQ=="}`

	var output bytes.Buffer
	summary, err := Reconstruct(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("Reconstruct() error = %v", err)
	}
	if summary.EventsIgnored != 1 || summary.ChunksAccepted != 0 ||
		output.Len() != 0 {
		t.Fatalf("semantic event was treated as communication: summary=%#v output=%s",
			summary, output.String())
	}

	summary, err = ReconstructWithOptions(
		strings.NewReader(input),
		&output,
		Options{IncludeSemantic: true},
	)
	if err != nil {
		t.Fatalf("ReconstructWithOptions() error = %v", err)
	}
	if summary.CallsComplete != 1 || summary.ChunksAccepted != 1 {
		t.Fatalf("semantic diagnostic opt-in failed: %#v", summary)
	}
	var call Call
	if err := json.Unmarshal(output.Bytes(), &call); err != nil {
		t.Fatal(err)
	}
	if call.CaptureLayer != captureLayerSemantic || call.Transport != "" {
		t.Fatalf("semantic provenance was not preserved: %#v", call)
	}
}

func TestReconstructReportsMissingRanges(t *testing.T) {
	input := `{"eventType":"tls_plaintext","timestamp":10,"pid":42,"tid":43,"direction":"READ","dataType":0,"sslAddr":4096,"originalLen":8,"capturedLen":8,"chunkOffset":4,"dataLen":4,"dataEncoding":"base64","data":"ZWZnaA=="}`
	var output bytes.Buffer
	summary, err := Reconstruct(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("Reconstruct() error = %v", err)
	}
	if summary.CallsIncomplete != 1 || summary.CallsComplete != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	var call Call
	if err := json.Unmarshal(output.Bytes(), &call); err != nil {
		t.Fatal(err)
	}
	if call.Complete || len(call.MissingRanges) != 1 ||
		call.MissingRanges[0] != (ByteRange{Start: 0, End: 4}) {
		t.Fatalf("missing range was not preserved: %#v", call)
	}
}

func TestReconstructIgnoresPacketEventsBeforePayloadDecode(t *testing.T) {
	input := strings.Join([]string{
		`{"Timestamp":1,"Pid":42,"Comm":[97,112,112],"PacketLen":4,"PacketData":"AQIDBA=="}`,
		`{"eventType":"tls_plaintext","timestamp":10,"pid":42,"tid":43,"direction":"READ","dataType":0,"sslAddr":4096,"originalLen":4,"capturedLen":4,"chunkOffset":0,"dataLen":4,"dataEncoding":"base64","data":"YWJjZA=="}`,
	}, "\n")
	var output bytes.Buffer
	summary, err := Reconstruct(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("Reconstruct() error = %v", err)
	}
	if summary.EventsIgnored != 1 || summary.CallsComplete != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestReconstructRejectsConflictingOverlap(t *testing.T) {
	input := strings.Join([]string{
		`{"eventType":"tls_plaintext","timestamp":10,"pid":42,"tid":43,"direction":"READ","dataType":0,"sslAddr":4096,"originalLen":4,"capturedLen":4,"chunkOffset":0,"dataLen":2,"dataEncoding":"base64","data":"YWI="}`,
		`{"eventType":"tls_plaintext","timestamp":10,"pid":42,"tid":43,"direction":"READ","dataType":0,"sslAddr":4096,"originalLen":4,"capturedLen":4,"chunkOffset":1,"dataLen":2,"dataEncoding":"base64","data":"eHo="}`,
	}, "\n")
	if _, err := Reconstruct(strings.NewReader(input), &bytes.Buffer{}); err == nil {
		t.Fatal("Reconstruct() should reject conflicting overlap")
	}
}

func TestReconstructPreservesQUICFinOnlyCall(t *testing.T) {
	input := `{"eventType":"boundary_data","captureLayer":"transport","transport":"quic","timestamp":10,"pid":42,"tid":43,"direction":"READ","hookId":1,"hookName":"quiche-receive","contextId":4660,"streamId":7,"streamOffset":19,"fin":true,"originalLen":0,"capturedLen":0,"chunkOffset":0,"dataLen":0,"dataEncoding":"base64","data":""}`
	var output bytes.Buffer
	summary, err := Reconstruct(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("Reconstruct() error = %v", err)
	}
	if summary.CallsComplete != 1 || summary.ChunksAccepted != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	var call Call
	if err := json.Unmarshal(output.Bytes(), &call); err != nil {
		t.Fatal(err)
	}
	if call.StreamOffset == nil || *call.StreamOffset != 19 ||
		call.Fin == nil || !*call.Fin || len(call.Data) != 0 ||
		!call.Complete {
		t.Fatalf("FIN-only call was not preserved: %#v", call)
	}
}

func TestProtocolHints(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		stream uint64
		want   string
	}{
		{"http1", []byte("POST /chat HTTP/1.1\r\n"), 0, "http1-request"},
		{"json", []byte(`{"prompt":"marker"}`), 0, "json"},
		{"binary", []byte{0xff, 0x00, 0x81}, 0, "custom-binary"},
		{"quic", []byte{0x01, 0x04, 0, 0, 0, 0}, 7, "http3-or-quic-stream"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := protocolHint(test.data, test.stream); got != test.want {
				t.Fatalf("protocolHint() = %q, want %q", got, test.want)
			}
		})
	}
}
