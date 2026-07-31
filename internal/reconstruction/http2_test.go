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
