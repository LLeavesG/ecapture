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

	"golang.org/x/net/http2/hpack"
)

func TestReconstructGQUICHeadersAndBodyStreams(t *testing.T) {
	requestHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "api.example.test"},
		hpack.HeaderField{Name: ":path", Value: "/chat/completions"},
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
	)
	requestHeaderPayload := append(make([]byte, 5), requestHeaders...)
	responseHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "content-type", Value: "text/event-stream"},
	)
	requestBody := []byte(`{"prompt":"hi"}`)
	responseBody := []byte("data: ok\n\n")
	writeHeaderFrame := makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagPriority|http2FlagEndHeaders,
		5,
		requestHeaderPayload,
	)
	readHeaderFrame := makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders,
		5,
		responseHeaders,
	)

	input := strings.Join([]string{
		quicBoundaryEvent(100, "WRITE", 3, nil, boolPointer(false), writeHeaderFrame),
		quicBoundaryEvent(101, "WRITE", 5, nil, boolPointer(true), requestBody),
		quicBoundaryEvent(102, "READ", 3, uint64Pointer(0), boolPointer(false), readHeaderFrame),
		quicBoundaryEvent(103, "READ", 5, uint64Pointer(0), boolPointer(true), responseBody),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructGQUIC(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructGQUIC() error = %v", err)
	}
	if summary.Connections != 1 || summary.Frames != 2 ||
		summary.Transactions != 1 || summary.CompleteTransactions != 1 ||
		summary.HeaderDecodeErrors != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	var transaction HTTP2Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatalf("decode transaction: %v output=%s", err, output.String())
	}
	if transaction.Protocol != "gquic-http" ||
		transaction.Transport != "quic" ||
		transaction.ContextID != 0x1234 ||
		transaction.Method != "POST" ||
		transaction.Authority != "api.example.test" ||
		transaction.Path != "/chat/completions" ||
		transaction.Status != "200" ||
		!transaction.Complete {
		t.Fatalf("unexpected transaction: %#v", transaction)
	}
	if !bytes.Equal(transaction.Request.Body, requestBody) ||
		!bytes.Equal(transaction.Response.Body, responseBody) {
		t.Fatalf("body changed: request=%q response=%q",
			transaction.Request.Body, transaction.Response.Body)
	}
}

func TestReconstructGQUICPreservesPerTransactionHeaderTimestamp(t *testing.T) {
	requestHeaders := func(path string) []byte {
		block := encodeHPACKHeaders(t,
			hpack.HeaderField{Name: ":method", Value: "POST"},
			hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: ":authority", Value: "api.example.test"},
			hpack.HeaderField{Name: ":path", Value: path},
		)
		return append(make([]byte, 5), block...)
	}
	responseHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
	)
	input := strings.Join([]string{
		quicBoundaryEvent(100, "WRITE", 3, nil, boolPointer(false),
			makeHTTP2Frame(http2FrameHeaders,
				http2FlagPriority|http2FlagEndHeaders|http2FlagEndStream,
				5, requestHeaders("/first"))),
		quicBoundaryEvent(110, "READ", 3, uint64Pointer(0), boolPointer(false),
			makeHTTP2Frame(http2FrameHeaders,
				http2FlagEndHeaders|http2FlagEndStream,
				5, responseHeaders)),
		quicBoundaryEvent(200, "WRITE", 3, nil, boolPointer(false),
			makeHTTP2Frame(http2FrameHeaders,
				http2FlagPriority|http2FlagEndHeaders|http2FlagEndStream,
				7, requestHeaders("/second"))),
		quicBoundaryEvent(210, "READ", 3, nil, boolPointer(false),
			makeHTTP2Frame(http2FrameHeaders,
				http2FlagEndHeaders|http2FlagEndStream,
				7, responseHeaders)),
	}, "\n")

	var output bytes.Buffer
	summary, err := ReconstructGQUIC(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructGQUIC() error = %v", err)
	}
	if summary.Transactions != 2 || summary.CompleteTransactions != 2 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	decoder := json.NewDecoder(&output)
	var first, second HTTP2Transaction
	if err := decoder.Decode(&first); err != nil {
		t.Fatalf("decode first transaction: %v", err)
	}
	if err := decoder.Decode(&second); err != nil {
		t.Fatalf("decode second transaction: %v", err)
	}
	if first.Path != "/first" || first.Timestamp != 100 {
		t.Fatalf("unexpected first transaction: %#v", first)
	}
	if second.Path != "/second" || second.Timestamp != 200 {
		t.Fatalf("later transaction lost its header timestamp: %#v", second)
	}
}
