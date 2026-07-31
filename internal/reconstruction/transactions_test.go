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

package reconstruction

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"golang.org/x/net/http2/hpack"
)

func TestReconstructTransactionsAutoDetectsAndOrdersProtocols(t *testing.T) {
	http2RequestHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/h2"},
	)
	http2ResponseHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
	)
	http2Write := append([]byte(nil), http2ClientPreface...)
	http2Write = append(http2Write, makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders|http2FlagEndStream,
		1,
		http2RequestHeaders,
	)...)
	http2Read := makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders|http2FlagEndStream,
		1,
		http2ResponseHeaders,
	)

	gquicRequestHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":path", Value: "/gquic"},
	)
	gquicResponseHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
	)
	gquicWriteHeaders := makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders,
		5,
		gquicRequestHeaders,
	)
	gquicReadHeaders := makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders,
		5,
		gquicResponseHeaders,
	)

	http3RequestHeaders := encodeQPACKHeaders(t,
		qpack.HeaderField{Name: ":method", Value: "POST"},
		qpack.HeaderField{Name: ":path", Value: "/h3"},
	)
	http3ResponseHeaders := encodeQPACKHeaders(t,
		qpack.HeaderField{Name: ":status", Value: "200"},
	)
	http3Write := appendHTTP3Frame(nil, 1, http3RequestHeaders)
	http3Read := appendHTTP3Frame(nil, 1, http3ResponseHeaders)

	inputLines := []string{
		withTLSAddress(t, marshalTLSCaptureEvent(
			t,
			50,
			"WRITE",
			[]byte("GET /h1 HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		), 0x9999),
		withTLSAddress(t, marshalTLSCaptureEvent(
			t,
			51,
			"READ",
			[]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
		), 0x9999),
		marshalTLSCaptureEvent(t, 100, "WRITE", http2Write),
		marshalTLSCaptureEvent(t, 101, "READ", http2Read),
		quicBoundaryEventForContext(
			t, 200, "WRITE", 3, 0x2200, nil,
			boolPointer(false), gquicWriteHeaders),
		quicBoundaryEventForContext(
			t, 201, "READ", 3, 0x2200, uint64Pointer(0),
			boolPointer(false), gquicReadHeaders),
		quicBoundaryEventForContext(
			t, 202, "WRITE", 5, 0x2200, nil,
			boolPointer(true), []byte("gquic request")),
		quicBoundaryEventForContext(
			t, 203, "READ", 5, 0x2200, uint64Pointer(0),
			boolPointer(true), []byte("gquic response")),
		quicBoundaryEventForContext(
			t, 300, "WRITE", 0, 0x3300, nil,
			boolPointer(true), http3Write),
		quicBoundaryEventForContext(
			t, 301, "READ", 0, 0x3300, uint64Pointer(0),
			boolPointer(true), http3Read),
	}
	wallAnchor := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)
	for index := range inputLines {
		inputLines[index] = addCaptureWallTime(t, inputLines[index], wallAnchor)
	}
	input := strings.Join(inputLines, "\n")
	var output bytes.Buffer
	summary, err := ReconstructTransactions(
		strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructTransactions() error = %v", err)
	}
	if summary.Transactions != 4 ||
		summary.CompleteTransactions != 4 ||
		summary.HTTP1Transactions != 1 ||
		summary.HTTP2Transactions != 1 ||
		summary.GQUICTransactions != 1 ||
		summary.HTTP3Transactions != 1 ||
		summary.InputBytes != int64(len(input)) {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}

	decoder := json.NewDecoder(&output)
	var metadata []transactionMetadata
	for decoder.More() {
		var item transactionMetadata
		if err := decoder.Decode(&item); err != nil {
			t.Fatal(err)
		}
		metadata = append(metadata, item)
	}
	if len(metadata) != 4 ||
		metadata[0].Protocol != "http1" ||
		metadata[1].Protocol != "http2" ||
		metadata[2].Protocol != "gquic-http" ||
		metadata[3].Protocol != "http3" ||
		metadata[0].WallTime != wallAnchor.Add(50).Format(time.RFC3339Nano) ||
		metadata[1].WallTime != wallAnchor.Add(100).Format(time.RFC3339Nano) ||
		metadata[2].WallTime != wallAnchor.Add(200).Format(time.RFC3339Nano) ||
		metadata[3].WallTime != wallAnchor.Add(300).Format(time.RFC3339Nano) ||
		metadata[0].Timestamp >= metadata[1].Timestamp ||
		metadata[1].Timestamp >= metadata[2].Timestamp ||
		metadata[2].Timestamp >= metadata[3].Timestamp {
		t.Fatalf("transactions were not time ordered: %#v", metadata)
	}
}

func withTLSAddress(
	t *testing.T,
	line string,
	address uint64,
) string {
	t.Helper()
	var event map[string]any
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatal(err)
	}
	event["sslAddr"] = address
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func addCaptureWallTime(
	t *testing.T,
	line string,
	anchor time.Time,
) string {
	t.Helper()
	var event map[string]any
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatal(err)
	}
	timestamp, ok := event["timestamp"].(float64)
	if !ok {
		t.Fatalf("capture event lacks numeric timestamp: %s", line)
	}
	event["wallTime"] = anchor.Add(
		time.Duration(uint64(timestamp)),
	).Format(time.RFC3339Nano)
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestReconstructTransactionsRejectsNilIO(t *testing.T) {
	if _, err := ReconstructTransactions(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("nil reader accepted")
	}
	if _, err := ReconstructTransactions(
		strings.NewReader(""), nil); err == nil {
		t.Fatal("nil writer accepted")
	}
}

func quicBoundaryEventForContext(
	t *testing.T,
	timestamp uint64,
	direction string,
	streamID uint64,
	contextID uint64,
	offset *uint64,
	fin *bool,
	data []byte,
) string {
	t.Helper()
	var event map[string]any
	if err := json.Unmarshal([]byte(quicBoundaryEvent(
		timestamp, direction, streamID, offset, fin, data,
	)), &event); err != nil {
		t.Fatal(err)
	}
	event["contextId"] = contextID
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
