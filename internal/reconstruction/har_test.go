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
	"strings"
	"testing"
	"time"
)

func TestExportHARPreservesBinaryBodiesAndProvenance(t *testing.T) {
	requestBody := []byte{0, 0xff, 'r', 'e', 'q'}
	responseBody := []byte{0x80, 0, 'r', 'e', 's', 'p'}
	transaction := HTTP2Transaction{
		EventType:    "http_transaction",
		Protocol:     "http2",
		CaptureLayer: captureLayerTransport,
		Transport:    "tls",
		ConnectionID: "tls:42:ssl:1234",
		StreamID:     1,
		Timestamp:    1_000_000_000,
		LastSeen:     1_025_000_000,
		WallTime:     "2026-07-30T12:34:56.123456789+08:00",
		Method:       "POST",
		Scheme:       "https",
		Authority:    "example.test",
		Path:         "/chat/completions?tag=a%20b&tag=c",
		Status:       "200",
		Request: HTTP2Message{
			Headers: []HTTP2Header{
				{Name: ":method", Value: "POST"},
				{Name: "content-type", Value: "application/octet-stream"},
			},
			Body:         requestBody,
			BodyEncoding: "base64",
			EndStream:    true,
		},
		Response: HTTP2Message{
			Headers: []HTTP2Header{
				{Name: ":status", Value: "200"},
				{Name: "content-type", Value: "application/octet-stream"},
			},
			Body:         responseBody,
			BodyEncoding: "base64",
			EndStream:    true,
		},
		Complete: true,
	}
	input, err := json.Marshal(transaction)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	summary, err := ExportHAR(
		bytes.NewReader(append(input, '\n')),
		&output,
		HAROptions{},
	)
	if err != nil {
		t.Fatalf("ExportHAR() error = %v", err)
	}
	if summary.Transactions != 1 ||
		summary.CompleteTransactions != 1 ||
		summary.RequestBodyBytes != int64(len(requestBody)) ||
		summary.ResponseBodyBytes != int64(len(responseBody)) ||
		summary.LegacyAnchoredEntries != 0 {
		t.Fatalf("unexpected summary: %#v", summary)
	}

	var document struct {
		Log struct {
			Version string     `json:"version"`
			Entries []harEntry `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("HAR is not valid JSON: %v\n%s", err, output.String())
	}
	if document.Log.Version != "1.2" || len(document.Log.Entries) != 1 {
		t.Fatalf("unexpected HAR document: %#v", document)
	}
	entry := document.Log.Entries[0]
	if entry.StartedDateTime != "2026-07-30T04:34:56.123456789Z" ||
		entry.Time != 25 ||
		entry.Request.URL !=
			"https://example.test/chat/completions?tag=a%20b&tag=c" ||
		entry.Request.HTTPVersion != "HTTP/2" ||
		entry.Response.Status != 200 ||
		entry.ECapture.ApplicationDecoding != "not-attempted" ||
		entry.ECapture.BodyTransformation != "none" {
		t.Fatalf("unexpected HAR entry: %#v", entry)
	}
	if len(entry.Request.QueryString) != 2 ||
		entry.Request.QueryString[0] !=
			(harNameValue{Name: "tag", Value: "a b"}) ||
		entry.Request.QueryString[1] !=
			(harNameValue{Name: "tag", Value: "c"}) {
		t.Fatalf("query order/duplicates not preserved: %#v",
			entry.Request.QueryString)
	}
	if entry.Request.PostData == nil ||
		entry.Request.PostData.Encoding != "base64" ||
		entry.Response.Content.Encoding != "base64" {
		t.Fatalf("binary encoding provenance missing: %#v", entry)
	}
	decodedRequest, err := base64.StdEncoding.DecodeString(
		entry.Request.PostData.Text)
	if err != nil {
		t.Fatal(err)
	}
	decodedResponse, err := base64.StdEncoding.DecodeString(
		entry.Response.Content.Text)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedRequest, requestBody) ||
		!bytes.Equal(decodedResponse, responseBody) {
		t.Fatalf(
			"HAR body mismatch: request=%x response=%x",
			decodedRequest,
			decodedResponse,
		)
	}
	if entry.ECapture.RequestBodySHA256 != bodySHA256(requestBody) ||
		entry.ECapture.ResponseBodySHA256 != bodySHA256(responseBody) {
		t.Fatalf("body hashes do not cover exact bytes: %#v", entry.ECapture)
	}
}

func TestExportHARRequiresExplicitAnchorForLegacyCapture(t *testing.T) {
	transaction := `{"eventType":"http_transaction","protocol":"http3",` +
		`"captureLayer":"transport","transport":"quic",` +
		`"connectionId":"quic:1:context:2","streamId":4,` +
		`"timestamp":100,"lastSeen":110,"request":{},"response":{}}`
	var rejected bytes.Buffer
	if _, err := ExportHAR(
		strings.NewReader(transaction),
		&rejected,
		HAROptions{},
	); err == nil || !strings.Contains(err.Error(), "wallTime is absent") {
		t.Fatalf("legacy capture should require an anchor, got %v", err)
	}
	if rejected.Len() != 0 {
		t.Fatalf("failed export leaked a partial HAR: %q", rejected.String())
	}

	anchor := time.Date(2026, 7, 30, 0, 0, 0, 0, time.UTC)
	var output bytes.Buffer
	summary, err := ExportHAR(
		strings.NewReader(transaction),
		&output,
		HAROptions{WallTimeAnchor: &anchor},
	)
	if err != nil {
		t.Fatalf("anchored ExportHAR() error = %v", err)
	}
	if summary.LegacyAnchoredEntries != 1 {
		t.Fatalf("unexpected anchored summary: %#v", summary)
	}
	var document struct {
		Log struct {
			Entries []harEntry `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	entry := document.Log.Entries[0]
	if entry.StartedDateTime != "2026-07-30T00:00:00Z" ||
		!entry.ECapture.LegacyWallTimeAnchored {
		t.Fatalf("legacy anchor was not explicit in HAR: %#v", entry)
	}
}

func TestExportHARRejectsNilIO(t *testing.T) {
	if _, err := ExportHAR(nil, &bytes.Buffer{}, HAROptions{}); err == nil {
		t.Fatal("nil HAR input accepted")
	}
	if _, err := ExportHAR(
		strings.NewReader(""),
		nil,
		HAROptions{},
	); err == nil {
		t.Fatal("nil HAR output accepted")
	}
}
