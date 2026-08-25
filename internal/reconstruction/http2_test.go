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

func TestReconstructHTTP2TransactionFromSplitTLSCalls(t *testing.T) {
	requestHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "api-normal.doubao.com"},
		hpack.HeaderField{Name: ":path", Value: "/chat/completion"},
		hpack.HeaderField{Name: "content-type", Value: "application/octet-stream"},
	)
	responseHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "content-type", Value: "application/octet-stream"},
	)
	requestBody := []byte{0x91, 0x02, 0xfa, 0x77, 0x00, 0x10}
	responseBody := []byte{0x82, 0x01, 0xcc, 0x44, 0x55}

	writeBytes := append([]byte(nil), http2ClientPreface...)
	writeBytes = append(writeBytes, makeHTTP2Frame(
		http2FrameSettings,
		0,
		0,
		nil,
	)...)
	writeBytes = append(writeBytes, makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders,
		1,
		requestHeaders,
	)...)
	writeBytes = append(writeBytes, makeHTTP2Frame(
		http2FrameData,
		http2FlagEndStream,
		1,
		requestBody,
	)...)

	readBytes := makeHTTP2Frame(
		http2FrameSettings,
		0,
		0,
		nil,
	)
	readBytes = append(readBytes, makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders,
		1,
		responseHeaders,
	)...)
	readBytes = append(readBytes, makeHTTP2Frame(
		http2FrameData,
		http2FlagEndStream,
		1,
		responseBody,
	)...)

	input := strings.Join([]string{
		marshalTLSCaptureEvent(t, 100, "WRITE", writeBytes[:17]),
		marshalTLSCaptureEvent(t, 101, "WRITE", writeBytes[17:]),
		marshalTLSCaptureEvent(t, 102, "READ", readBytes[:7]),
		marshalTLSCaptureEvent(t, 103, "READ", readBytes[7:]),
	}, "\n")

	var output bytes.Buffer
	summary, err := ReconstructHTTP2(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructHTTP2() error = %v", err)
	}
	if summary.Transactions != 1 || summary.Frames != 6 ||
		summary.HeaderDecodeError != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}

	var transaction HTTP2Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatalf("decode transaction: %v output=%s", err, output.String())
	}
	if transaction.Method != "POST" ||
		transaction.Path != "/chat/completion" ||
		transaction.Authority != "api-normal.doubao.com" ||
		transaction.Status != "200" ||
		!transaction.Complete {
		t.Fatalf("unexpected transaction: %#v", transaction)
	}
	if !bytes.Equal(transaction.Request.Body, requestBody) ||
		!bytes.Equal(transaction.Response.Body, responseBody) {
		t.Fatalf(
			"body bytes changed: request=%x response=%x",
			transaction.Request.Body,
			transaction.Response.Body,
		)
	}
	if transaction.CaptureLayer != captureLayerTransport ||
		transaction.Transport != "tls" {
		t.Fatalf("unexpected provenance: %#v", transaction)
	}
}

func TestReconstructHTTP2FromGenericTLSBoundaryHooks(t *testing.T) {
	requestHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "config.example.test"},
		hpack.HeaderField{Name: ":path", Value: "/settings/v3"},
	)
	responseHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
	)
	writeBytes := append([]byte(nil), http2ClientPreface...)
	writeBytes = append(writeBytes, makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders|http2FlagEndStream,
		1,
		requestHeaders,
	)...)
	readBytes := makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders|http2FlagEndStream,
		1,
		responseHeaders,
	)
	input := strings.Join([]string{
		marshalTLSBoundaryEvent(t, 200, "WRITE", 0x5678, writeBytes),
		marshalTLSBoundaryEvent(t, 201, "READ", 0x5678, readBytes),
	}, "\n")

	var output bytes.Buffer
	summary, err := ReconstructHTTP2(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructHTTP2() error = %v", err)
	}
	if summary.Transactions != 1 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	var transaction HTTP2Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatalf("decode transaction: %v", err)
	}
	if transaction.Path != "/settings/v3" ||
		transaction.Status != "200" ||
		transaction.SSLAddr != 0x5678 ||
		transaction.CaptureLayer != captureLayerTransport ||
		transaction.Transport != "tls" {
		t.Fatalf("unexpected transaction: %#v", transaction)
	}
}

func TestReconstructHTTP2PushPromiseWithContinuation(t *testing.T) {
	requestHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "push.example.test"},
		hpack.HeaderField{Name: ":path", Value: "/index"},
	)
	pushedRequestHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "push.example.test"},
		hpack.HeaderField{Name: ":path", Value: "/asset.json"},
	)
	responseHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
	)

	writeBytes := append([]byte(nil), http2ClientPreface...)
	writeBytes = append(writeBytes, makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders|http2FlagEndStream,
		1,
		requestHeaders,
	)...)

	split := len(pushedRequestHeaders) / 2
	promisePayload := []byte{0, 0, 0, 2}
	promisePayload = append(promisePayload, pushedRequestHeaders[:split]...)
	readBytes := makeHTTP2Frame(
		http2FramePushPromise,
		0,
		1,
		promisePayload,
	)
	readBytes = append(readBytes, makeHTTP2Frame(
		http2FrameContinuation,
		http2FlagEndHeaders,
		1,
		pushedRequestHeaders[split:],
	)...)
	readBytes = append(readBytes, makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders|http2FlagEndStream,
		1,
		responseHeaders,
	)...)
	readBytes = append(readBytes, makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders,
		2,
		responseHeaders,
	)...)
	readBytes = append(readBytes, makeHTTP2Frame(
		http2FrameData,
		http2FlagEndStream,
		2,
		[]byte("pushed-body"),
	)...)

	input := strings.Join([]string{
		marshalTLSCaptureEvent(t, 100, "WRITE", writeBytes),
		marshalTLSCaptureEvent(t, 101, "READ", readBytes),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP2(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructHTTP2() error = %v", err)
	}
	if summary.Transactions != 2 || summary.CompleteTransactions != 2 ||
		summary.HeaderDecodeError != 0 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	decoder := json.NewDecoder(&output)
	var transactions []HTTP2Transaction
	for decoder.More() {
		var transaction HTTP2Transaction
		if err := decoder.Decode(&transaction); err != nil {
			t.Fatal(err)
		}
		transactions = append(transactions, transaction)
	}
	if len(transactions) != 2 || !transactions[0].Complete ||
		transactions[0].State != transactionStateComplete ||
		!transactions[1].Complete || transactions[1].StreamID != 2 ||
		transactions[1].State != transactionStateComplete ||
		transactions[1].Method != "GET" ||
		transactions[1].Path != "/asset.json" ||
		transactions[1].Status != "200" ||
		string(transactions[1].Response.Body) != "pushed-body" {
		t.Fatalf("unexpected PUSH_PROMISE transactions: %#v", transactions)
	}
}

func TestReconstructHTTP2ClassifiesOpenResetAndOrphan(t *testing.T) {
	requestHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "state.example.test"},
		hpack.HeaderField{Name: ":path", Value: "/open"},
	)
	responseHeaders := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
	)
	writeBytes := append([]byte(nil), http2ClientPreface...)
	for _, streamID := range []uint32{1, 3} {
		writeBytes = append(writeBytes, makeHTTP2Frame(
			http2FrameHeaders,
			http2FlagEndHeaders|http2FlagEndStream,
			streamID,
			requestHeaders,
		)...)
	}
	readBytes := makeHTTP2Frame(
		http2FrameHeaders,
		http2FlagEndHeaders|http2FlagEndStream,
		2,
		responseHeaders,
	)
	readBytes = append(readBytes, makeHTTP2Frame(
		http2FrameRSTStream,
		0,
		3,
		[]byte{0, 0, 0, 8},
	)...)

	input := strings.Join([]string{
		marshalTLSCaptureEvent(t, 100, "WRITE", writeBytes),
		marshalTLSCaptureEvent(t, 101, "READ", readBytes),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP2(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Transactions != 3 || summary.CompleteTransactions != 0 ||
		summary.OpenTransactions != 1 || summary.ResetTransactions != 1 ||
		summary.OrphanTransactions != 1 || summary.ErrorTransactions != 0 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	states := make(map[uint32]string)
	decoder := json.NewDecoder(&output)
	for decoder.More() {
		var transaction HTTP2Transaction
		if err := decoder.Decode(&transaction); err != nil {
			t.Fatal(err)
		}
		states[transaction.StreamID] = transaction.State
	}
	if states[1] != transactionStateOpen ||
		states[2] != transactionStateOrphan ||
		states[3] != transactionStateReset {
		t.Fatalf("unexpected transaction states: %#v", states)
	}
}

func TestReconstructHTTP2SplitsReusedSSLAddressAtClientPreface(t *testing.T) {
	firstRequest := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "first.example.test"},
		hpack.HeaderField{Name: ":path", Value: "/first"},
	)
	secondRequest := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":method", Value: "POST"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: "second.example.test"},
		hpack.HeaderField{Name: ":path", Value: "/second"},
	)
	firstResponse := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "content-encoding", Value: "gzip"},
	)
	secondResponse := encodeHPACKHeaders(t,
		hpack.HeaderField{Name: ":status", Value: "201"},
		hpack.HeaderField{Name: "content-type", Value: "application/json"},
	)
	requestBytes := func(headers []byte) []byte {
		result := append([]byte(nil), http2ClientPreface...)
		return append(result, makeHTTP2Frame(
			http2FrameHeaders,
			http2FlagEndHeaders|http2FlagEndStream,
			1,
			headers,
		)...)
	}
	responseBytes := func(headers []byte, body []byte) []byte {
		result := makeHTTP2Frame(
			http2FrameHeaders,
			http2FlagEndHeaders,
			1,
			headers,
		)
		return append(result, makeHTTP2Frame(
			http2FrameData,
			http2FlagEndStream,
			1,
			body,
		)...)
	}
	input := strings.Join([]string{
		marshalTLSCaptureEvent(t, 100, "WRITE", requestBytes(firstRequest)),
		marshalTLSCaptureEvent(t, 101, "READ", responseBytes(
			firstResponse, []byte("first-body"),
		)),
		marshalTLSCaptureEvent(t, 200, "WRITE", requestBytes(secondRequest)),
		marshalTLSCaptureEvent(t, 201, "READ", responseBytes(
			secondResponse, []byte("second-body"),
		)),
	}, "\n")

	var output bytes.Buffer
	summary, err := ReconstructHTTP2(strings.NewReader(input), &output)
	if err != nil {
		t.Fatalf("ReconstructHTTP2() error = %v", err)
	}
	if summary.Connections != 2 || summary.Transactions != 2 ||
		summary.HeaderDecodeError != 0 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	decoder := json.NewDecoder(&output)
	var transactions []HTTP2Transaction
	for decoder.More() {
		var transaction HTTP2Transaction
		if err := decoder.Decode(&transaction); err != nil {
			t.Fatal(err)
		}
		transactions = append(transactions, transaction)
	}
	if len(transactions) != 2 ||
		transactions[0].Authority != "first.example.test" ||
		transactions[0].Path != "/first" ||
		string(transactions[0].Response.Body) != "first-body" ||
		transactions[1].Authority != "second.example.test" ||
		transactions[1].Path != "/second" ||
		string(transactions[1].Response.Body) != "second-body" ||
		transactions[0].ConnectionID == transactions[1].ConnectionID ||
		!strings.HasSuffix(
			transactions[1].ConnectionID, ":generation:2",
		) {
		t.Fatalf("reused SSL address was merged: %#v", transactions)
	}
}

func encodeHPACKHeaders(t *testing.T, fields ...hpack.HeaderField) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encoder := hpack.NewEncoder(&buffer)
	for _, field := range fields {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func makeHTTP2Frame(
	frameType byte,
	flags byte,
	streamID uint32,
	payload []byte,
) []byte {
	length := len(payload)
	frame := []byte{
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
		frameType,
		flags,
		byte(streamID >> 24),
		byte(streamID >> 16),
		byte(streamID >> 8),
		byte(streamID),
	}
	return append(frame, payload...)
}

func marshalTLSCaptureEvent(
	t *testing.T,
	timestamp uint64,
	direction string,
	data []byte,
) string {
	t.Helper()
	dataType := int64(0)
	if direction == "WRITE" {
		dataType = 1
	}
	event := struct {
		EventType    string `json:"eventType"`
		CaptureLayer string `json:"captureLayer"`
		Transport    string `json:"transport"`
		Timestamp    uint64 `json:"timestamp"`
		Pid          uint32 `json:"pid"`
		Tid          uint32 `json:"tid"`
		Direction    string `json:"direction"`
		DataType     int64  `json:"dataType"`
		SSLAddr      uint64 `json:"sslAddr"`
		OriginalLen  uint32 `json:"originalLen"`
		CapturedLen  uint32 `json:"capturedLen"`
		ChunkOffset  uint32 `json:"chunkOffset"`
		DataLen      uint32 `json:"dataLen"`
		DataEncoding string `json:"dataEncoding"`
		Data         []byte `json:"data"`
	}{
		EventType:    "tls_plaintext",
		CaptureLayer: captureLayerTransport,
		Transport:    "tls",
		Timestamp:    timestamp,
		Pid:          42,
		Tid:          43,
		Direction:    direction,
		DataType:     dataType,
		SSLAddr:      0x1234,
		OriginalLen:  uint32(len(data)),
		CapturedLen:  uint32(len(data)),
		DataLen:      uint32(len(data)),
		DataEncoding: "base64",
		Data:         data,
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func marshalTLSBoundaryEvent(
	t *testing.T,
	timestamp uint64,
	direction string,
	contextID uint64,
	data []byte,
) string {
	t.Helper()
	var event map[string]any
	if err := json.Unmarshal([]byte(marshalTLSCaptureEvent(
		t, timestamp, direction, data,
	)), &event); err != nil {
		t.Fatal(err)
	}
	event["eventType"] = "boundary_data"
	event["contextId"] = contextID
	event["hookName"] = "generic-tls-" + strings.ToLower(direction)
	delete(event, "sslAddr")
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
