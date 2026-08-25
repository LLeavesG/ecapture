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
	"time"
)

func TestReconstructHTTP1SplitCallsChunkedAndBinaryBodies(t *testing.T) {
	requestBody := []byte{0xff, 0, 'q'}
	request := []byte(
		"POST /binary?x=1 HTTP/1.1\r\n" +
			"Host: example.test\r\n" +
			"Content-Type: application/octet-stream\r\n" +
			"Content-Length: 3\r\n\r\n",
	)
	request = append(request, requestBody...)
	responseBody := []byte{0, 'a', 'b', 'c', 'x', 'y', 'z'}
	response := []byte(
		"HTTP/1.1 200 OK\r\n" +
			"Content-Type: application/octet-stream\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"4\r\n\x00abc\r\n" +
			"3\r\nxyz\r\n" +
			"0\r\n\r\n",
	)
	anchor := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	lines := []string{
		addCaptureWallTime(
			t,
			marshalTLSCaptureEvent(t, 10, "WRITE", request[:17]),
			anchor,
		),
		addCaptureWallTime(
			t,
			marshalTLSCaptureEvent(t, 11, "WRITE", request[17:]),
			anchor,
		),
		addCaptureWallTime(
			t,
			marshalTLSCaptureEvent(t, 12, "READ", response[:23]),
			anchor,
		),
		addCaptureWallTime(
			t,
			marshalTLSCaptureEvent(t, 13, "READ", response[23:]),
			anchor,
		),
	}
	var output bytes.Buffer
	summary, err := ReconstructHTTP1(
		strings.NewReader(strings.Join(lines, "\n")),
		&output,
	)
	if err != nil {
		t.Fatalf("ReconstructHTTP1() error = %v", err)
	}
	if summary.Transactions != 1 ||
		summary.CompleteTransactions != 1 ||
		summary.Requests != 1 ||
		summary.Responses != 1 ||
		summary.ParseErrors != 0 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	var transaction HTTP1Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatal(err)
	}
	if transaction.Protocol != "http1" ||
		transaction.State != transactionStateComplete ||
		transaction.StreamID != 1 ||
		transaction.StreamIDSource != "synthetic-http1-sequence" ||
		transaction.Method != "POST" ||
		transaction.Authority != "example.test" ||
		transaction.Path != "/binary?x=1" ||
		transaction.Status != "200" ||
		transaction.Timestamp != 10 ||
		transaction.LastSeen != 13 ||
		transaction.WallTime != anchor.Add(10).Format(time.RFC3339Nano) ||
		!transaction.SchemeInferred ||
		!transaction.Complete {
		t.Fatalf("unexpected transaction: %#v", transaction)
	}
	if !bytes.Equal(transaction.Request.Body, requestBody) ||
		!bytes.Equal(transaction.Response.Body, responseBody) {
		t.Fatalf(
			"binary bodies changed: request=%x response=%x",
			transaction.Request.Body,
			transaction.Response.Body,
		)
	}
}

func TestReconstructHTTP1PipelinedTransactions(t *testing.T) {
	requests := "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n" +
		"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n"
	responses := "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1" +
		"HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\n2"
	input := strings.Join([]string{
		marshalTLSCaptureEvent(t, 20, "WRITE", []byte(requests)),
		marshalTLSCaptureEvent(t, 21, "READ", []byte(responses)),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP1(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Transactions != 2 ||
		summary.CompleteTransactions != 2 ||
		summary.ParseErrors != 0 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	decoder := json.NewDecoder(&output)
	var transactions []HTTP1Transaction
	for decoder.More() {
		var transaction HTTP1Transaction
		if err := decoder.Decode(&transaction); err != nil {
			t.Fatal(err)
		}
		transactions = append(transactions, transaction)
	}
	if len(transactions) != 2 ||
		transactions[0].Path != "/one" ||
		transactions[0].Status != "200" ||
		string(transactions[0].Response.Body) != "1" ||
		transactions[1].Path != "/two" ||
		transactions[1].Status != "201" ||
		string(transactions[1].Response.Body) != "2" {
		t.Fatalf("pipelined pairing failed: %#v", transactions)
	}
}

func TestReconstructHTTP1DoesNotClaimCaptureEOFTerminatedBodyComplete(
	t *testing.T,
) {
	input := strings.Join([]string{
		marshalTLSCaptureEvent(
			t,
			30,
			"WRITE",
			[]byte("GET /close HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		),
		marshalTLSCaptureEvent(
			t,
			31,
			"READ",
			[]byte("HTTP/1.1 200 OK\r\n\r\npartial"),
		),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP1(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Transactions != 1 ||
		summary.CompleteTransactions != 0 ||
		summary.ParseErrors != 1 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	var transaction HTTP1Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatal(err)
	}
	if transaction.Complete ||
		transaction.State != transactionStateError ||
		transaction.Response.EndStream ||
		string(transaction.Response.Body) != "partial" ||
		len(transaction.Errors) != 1 ||
		!strings.Contains(transaction.Errors[0], "without observed connection close") {
		t.Fatalf("capture EOF was misrepresented: %#v", transaction)
	}
}

func TestReconstructHTTP1IgnoresHTTP2Preface(t *testing.T) {
	input := marshalTLSCaptureEvent(
		t,
		40,
		"WRITE",
		http2ClientPreface,
	)
	var output bytes.Buffer
	summary, err := ReconstructHTTP1(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Transactions != 0 ||
		summary.RecognizedConnections != 0 ||
		output.Len() != 0 {
		t.Fatalf("HTTP/2 was misclassified: %#v %q", summary, output.String())
	}
}

func TestReconstructHTTP1StopsBeforeReusedPointerHTTP2Preface(t *testing.T) {
	input := strings.Join([]string{
		marshalTLSCaptureEvent(
			t,
			41,
			"WRITE",
			[]byte("GET /first HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		),
		marshalTLSCaptureEvent(
			t,
			42,
			"READ",
			[]byte("HTTP/1.1 204 No Content\r\n\r\n"),
		),
		marshalTLSCaptureEvent(
			t,
			43,
			"WRITE",
			http2ClientPreface,
		),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP1(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Transactions != 1 ||
		summary.CompleteTransactions != 1 ||
		summary.ParseErrors != 0 {
		t.Fatalf("reused SSL pointer was misclassified: %#v %q",
			summary, output.String())
	}
	var transaction HTTP1Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatal(err)
	}
	if transaction.Method != "GET" ||
		transaction.Path != "/first" ||
		transaction.RequestVersion != "HTTP/1.1" {
		t.Fatalf("unexpected transaction: %#v", transaction)
	}
}

func TestReconstructHTTP1StopsAtWebSocketUpgrade(t *testing.T) {
	input := strings.Join([]string{
		marshalTLSCaptureEvent(
			t,
			50,
			"WRITE",
			[]byte("GET /ws HTTP/1.1\r\nHost: example.test\r\n"+
				"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"),
		),
		marshalTLSCaptureEvent(
			t,
			51,
			"READ",
			append(
				[]byte("HTTP/1.1 101 Switching Protocols\r\n"+
					"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"),
				[]byte{0x82, 0x03, 0, 0xff, 0x01}...,
			),
		),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructHTTP1(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Transactions != 1 ||
		summary.CompleteTransactions != 1 ||
		summary.ParseErrors != 0 {
		t.Fatalf("upgrade bytes were parsed as another HTTP response: %#v %s",
			summary, output.String())
	}
	var transaction HTTP1Transaction
	if err := json.Unmarshal(output.Bytes(), &transaction); err != nil {
		t.Fatal(err)
	}
	if transaction.Status != "101" ||
		len(transaction.Response.Body) != 0 ||
		!transaction.Complete {
		t.Fatalf("unexpected upgrade transaction: %#v", transaction)
	}
}
