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

	"github.com/quic-go/qpack"
)

func TestReconstructHTTP3StaticQPACKTransaction(t *testing.T) {
	requestHeaders := encodeQPACKHeaders(t,
		qpack.HeaderField{Name: ":method", Value: "POST"},
		qpack.HeaderField{Name: ":scheme", Value: "https"},
		qpack.HeaderField{Name: ":authority", Value: "api.example.test"},
		qpack.HeaderField{Name: ":path", Value: "/chat/completions"},
		qpack.HeaderField{Name: "content-type", Value: "application/json"},
	)
	responseHeaders := encodeQPACKHeaders(t,
		qpack.HeaderField{Name: ":status", Value: "200"},
		qpack.HeaderField{Name: "content-type", Value: "text/event-stream"},
	)
	requestBody := []byte(`{"prompt":"marker"}`)
	responseBody := []byte("data: answer\n\n")
	request := appendHTTP3Frame(nil, 1, requestHeaders)
	request = appendHTTP3Frame(request, 0, requestBody)
	response := appendHTTP3Frame(nil, 1, responseHeaders)
	response = appendHTTP3Frame(response, 0, responseBody)
	input := strings.Join([]string{
		quicBoundaryEvent(10, "WRITE", 0, nil, boolPointer(true), request),
		quicBoundaryEvent(11, "READ", 0, uint64Pointer(0), boolPointer(true), response),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP3(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructHTTP3() error = %v", err)
	}
	if summary.Transactions != 1 || summary.CompleteTransactions != 1 ||
		summary.HeaderBlocksDecoded != 2 || summary.HeaderDecodeErrors != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	var transaction HTTP3Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatalf("decode transaction: %v output=%s", err, output.String())
	}
	if transaction.Protocol != "http3" ||
		transaction.Method != "POST" ||
		transaction.Path != "/chat/completions" ||
		transaction.Authority != "api.example.test" ||
		transaction.Status != "200" ||
		!transaction.Complete ||
		!bytes.Equal(transaction.Request.Body, requestBody) ||
		!bytes.Equal(transaction.Response.Body, responseBody) {
		t.Fatalf("unexpected transaction: %#v", transaction)
	}
}

func TestReconstructHTTP3DynamicQPACKTransaction(t *testing.T) {
	settingsPayload := append(
		encodeQUICVarintForTest(1),
		encodeQUICVarintForTest(128)...,
	)
	peerControl := encodeQUICVarintForTest(0)
	peerControl = appendHTTP3Frame(peerControl, 4, settingsPayload)

	localEncoder := encodeQUICVarintForTest(2)
	localEncoder = appendQPACKInteger(localEncoder, 0x20, 5, 128)
	localEncoder = appendQPACKInteger(localEncoder, 0xc0, 6, 1)
	localEncoder = appendQPACKTestString(
		localEncoder, "/chat/dynamic")

	requestHeaders := []byte{2, 0}
	requestHeaders = appendQPACKInteger(
		requestHeaders, 0xc0, 6, 20) // :method = POST
	requestHeaders = appendQPACKInteger(
		requestHeaders, 0x80, 6, 0) // newest dynamic entry
	responseHeaders := encodeQPACKHeaders(t,
		qpack.HeaderField{Name: ":status", Value: "200"},
	)
	requestBody := []byte("opaque request")
	responseBody := []byte("opaque response")
	request := appendHTTP3Frame(nil, 1, requestHeaders)
	request = appendHTTP3Frame(request, 0, requestBody)
	response := appendHTTP3Frame(nil, 1, responseHeaders)
	response = appendHTTP3Frame(response, 0, responseBody)

	input := strings.Join([]string{
		quicBoundaryEvent(
			10, "READ", 3, uint64Pointer(0),
			boolPointer(false), peerControl),
		quicBoundaryEvent(
			11, "WRITE", 2, nil,
			boolPointer(false), localEncoder),
		quicBoundaryEvent(
			12, "WRITE", 0, nil,
			boolPointer(true), request),
		quicBoundaryEvent(
			13, "READ", 0, uint64Pointer(0),
			boolPointer(true), response),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP3(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructHTTP3() error = %v", err)
	}
	if summary.Transactions != 1 ||
		summary.CompleteTransactions != 1 ||
		summary.HeaderBlocksDecoded != 2 ||
		summary.DynamicBlocksDecoded != 1 ||
		summary.QPACKInstructions != 2 ||
		summary.QPACKStreamErrors != 0 ||
		summary.HeaderDecodeErrors != 0 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	var transaction HTTP3Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatalf("decode transaction: %v output=%s", err, output.String())
	}
	if transaction.Method != "POST" ||
		transaction.Path != "/chat/dynamic" ||
		transaction.Status != "200" ||
		transaction.Request.QPACKMode != "dynamic-table" ||
		!transaction.Complete ||
		!bytes.Equal(transaction.Request.Body, requestBody) ||
		!bytes.Equal(transaction.Response.Body, responseBody) {
		t.Fatalf("unexpected transaction: %#v", transaction)
	}
}

func TestReconstructHTTP3RetainsDynamicBlockWithoutSettings(t *testing.T) {
	localEncoder := encodeQUICVarintForTest(2)
	localEncoder = appendQPACKInteger(localEncoder, 0x20, 5, 128)
	requestHeaders := []byte{2, 0, 0x80}
	request := appendHTTP3Frame(nil, 1, requestHeaders)
	input := strings.Join([]string{
		quicBoundaryEvent(
			10, "WRITE", 2, nil,
			boolPointer(false), localEncoder),
		quicBoundaryEvent(
			11, "WRITE", 0, nil,
			boolPointer(true), request),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP3(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructHTTP3() error = %v", err)
	}
	if summary.HeaderDecodeErrors != 1 ||
		summary.QPACKStreamErrors != 1 ||
		summary.CompleteTransactions != 0 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	var transaction HTTP3Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatalf("decode transaction: %v output=%s", err, output.String())
	}
	if transaction.Request.QPACKMode != "exact-block-unresolved" ||
		len(transaction.Request.HeaderBlocks) != 1 ||
		!bytes.Equal(transaction.Request.HeaderBlocks[0], requestHeaders) ||
		len(transaction.Request.Errors) == 0 {
		t.Fatalf("missing unresolved evidence: %#v", transaction)
	}
}

func encodeQPACKHeaders(t *testing.T, fields ...qpack.HeaderField) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encoder := qpack.NewEncoder(&buffer)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func appendQPACKTestString(destination []byte, value string) []byte {
	destination = appendQPACKInteger(
		destination, 0, 7, uint64(len(value)))
	return append(destination, value...)
}
