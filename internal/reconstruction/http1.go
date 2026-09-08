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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	maxHTTP1ConnectionBytes = 128 * 1024 * 1024
	maxHTTP1MessageBody     = 64 * 1024 * 1024
)

type HTTP1Summary struct {
	InferredProtocolSegments int     `json:"inferredProtocolSegments"`
	Reconstruction           Summary `json:"reconstruction"`
	CallsProcessed           int     `json:"callsProcessed"`
	Connections              int     `json:"connections"`
	RecognizedConnections    int     `json:"recognizedConnections"`
	Requests                 int     `json:"requests"`
	Responses                int     `json:"responses"`
	Transactions             int     `json:"transactions"`
	CompleteTransactions     int     `json:"completeTransactions"`
	OpenTransactions         int     `json:"openTransactions"`
	OrphanTransactions       int     `json:"orphanTransactions"`
	ErrorTransactions        int     `json:"errorTransactions"`
	ParseErrors              int     `json:"parseErrors"`
}

type HTTP1Transaction struct {
	ConnectionGenerationSource string       `json:"connectionGenerationSource,omitempty"`
	EventType                  string       `json:"eventType"`
	Protocol                   string       `json:"protocol"`
	CaptureLayer               string       `json:"captureLayer"`
	Transport                  string       `json:"transport"`
	ConnectionID               string       `json:"connectionId"`
	StreamID                   uint64       `json:"streamId"`
	StreamIDSource             string       `json:"streamIdSource"`
	Pid                        uint32       `json:"pid"`
	SSLAddr                    uint64       `json:"sslAddr,omitempty"`
	BIOAddr                    uint64       `json:"bioAddr,omitempty"`
	Fd                         uint32       `json:"fd,omitempty"`
	Timestamp                  uint64       `json:"timestamp"`
	LastSeen                   uint64       `json:"lastSeen"`
	WallTime                   string       `json:"wallTime,omitempty"`
	Method                     string       `json:"method,omitempty"`
	Scheme                     string       `json:"scheme,omitempty"`
	SchemeInferred             bool         `json:"schemeInferred,omitempty"`
	Authority                  string       `json:"authority,omitempty"`
	Path                       string       `json:"path,omitempty"`
	Status                     string       `json:"status,omitempty"`
	RequestVersion             string       `json:"requestVersion,omitempty"`
	ResponseVersion            string       `json:"responseVersion,omitempty"`
	Request                    HTTP2Message `json:"request"`
	Response                   HTTP2Message `json:"response"`
	Complete                   bool         `json:"complete"`
	State                      string       `json:"state"`
	Errors                     []string     `json:"errors,omitempty"`
}

type http1Span struct {
	start     int
	end       int
	timestamp uint64
}

type http1DirectionCapture struct {
	data  []byte
	spans []http1Span
}

type http1ConnectionCapture struct {
	generationSource string
	id               string
	pid              uint32
	sslAddr          uint64
	bioAddr          uint64
	fd               uint32
	wallTime         string
	wallStamp        uint64
	write            http1DirectionCapture
	read             http1DirectionCapture
	tooLarge         bool
}

type parsedHTTP1Request struct {
	message   HTTP2Message
	method    string
	scheme    string
	inferred  bool
	authority string
	path      string
	version   string
	timestamp uint64
	lastSeen  uint64
	errors    []string
	request   *http.Request
}

type parsedHTTP1Response struct {
	message   HTTP2Message
	status    string
	version   string
	timestamp uint64
	lastSeen  uint64
	errors    []string
}

func ReconstructHTTP1(
	reader io.Reader,
	writer io.Writer,
) (HTTP1Summary, error) {
	var summary HTTP1Summary
	if reader == nil {
		return summary, fmt.Errorf("HTTP/1 reconstruction input is nil")
	}
	if writer == nil {
		return summary, fmt.Errorf("HTTP/1 reconstruction output is nil")
	}
	callSummary, calls, err := collectTLSCalls(reader)
	if err != nil {
		return summary, err
	}
	summary.Reconstruction = callSummary

	connections, inferred := collectHTTP1ProtocolSegments(calls)
	summary.InferredProtocolSegments = inferred
	summary.CallsProcessed = len(calls)

	summary.Connections = len(connections)

	keys := make([]string, 0, len(connections))
	for key := range connections {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var transactions []HTTP1Transaction
	for _, key := range keys {
		connection := connections[key]
		if connection.tooLarge {
			summary.ParseErrors++
			continue
		}
		requestRecognized := looksLikeHTTP1Request(connection.write.data)
		responseRecognized := looksLikeHTTP1Response(connection.read.data)
		if !requestRecognized && !responseRecognized {
			continue
		}
		summary.RecognizedConnections++
		requests, requestErrors := parseHTTP1Requests(
			connection.write,
			requestRecognized,
		)
		responses, responseErrors := parseHTTP1Responses(
			connection.read,
			responseRecognized,
			requests,
		)
		summary.ParseErrors += requestErrors + responseErrors
		summary.Requests += len(requests)
		summary.Responses += len(responses)
		count := len(requests)
		if len(responses) > count {
			count = len(responses)
		}
		for index := 0; index < count; index++ {
			transaction := HTTP1Transaction{
				ConnectionGenerationSource: connection.generationSource,
				EventType:                  "http_transaction",
				Protocol:                   "http1",
				CaptureLayer:               captureLayerTransport,
				Transport:                  "tls",
				ConnectionID:               connection.id,
				StreamID:                   uint64(index + 1),
				StreamIDSource:             "synthetic-http1-sequence",
				Pid:                        connection.pid,
				SSLAddr:                    connection.sslAddr,
				BIOAddr:                    connection.bioAddr,
				Fd:                         connection.fd,
			}
			if index < len(requests) {
				request := requests[index]
				transaction.Request = request.message
				transaction.Method = request.method
				transaction.Scheme = request.scheme
				transaction.SchemeInferred = request.inferred
				transaction.Authority = request.authority
				transaction.Path = request.path
				transaction.RequestVersion = request.version
				transaction.Timestamp = request.timestamp
				transaction.LastSeen = request.lastSeen
				transaction.Errors = append(
					transaction.Errors,
					request.errors...,
				)
			}
			if index < len(responses) {
				response := responses[index]
				transaction.Response = response.message
				transaction.Status = response.status
				transaction.ResponseVersion = response.version
				if transaction.Timestamp == 0 ||
					response.timestamp < transaction.Timestamp {
					transaction.Timestamp = response.timestamp
				}
				if response.lastSeen > transaction.LastSeen {
					transaction.LastSeen = response.lastSeen
				}
				transaction.Errors = append(
					transaction.Errors,
					response.errors...,
				)
			}
			transaction.WallTime = wallTimeAt(
				connection.wallTime,
				connection.wallStamp,
				transaction.Timestamp,
			)
			transaction.Complete =
				index < len(requests) &&
					index < len(responses) &&
					transaction.Request.EndStream &&
					transaction.Response.EndStream &&
					len(transaction.Errors) == 0
			transaction.State = classifyTransactionState(
				transaction.Complete,
				index < len(requests),
				index < len(responses),
				false,
				len(transaction.Errors) != 0,
			)
			materializeHTTPBody(
				transaction.Request.Headers,
				transaction.Request.Body,
				&transaction.Request.HTTPBodyPresentation,
			)
			materializeHTTPBody(
				transaction.Response.Headers,
				transaction.Response.Body,
				&transaction.Response.HTTPBodyPresentation,
			)
			switch transaction.State {
			case transactionStateComplete:
				summary.CompleteTransactions++
			case transactionStateOpen:
				summary.OpenTransactions++
			case transactionStateOrphan:
				summary.OrphanTransactions++
			default:
				summary.ErrorTransactions++
			}
			transactions = append(transactions, transaction)
		}
	}
	sort.SliceStable(transactions, func(i, j int) bool {
		if transactions[i].Timestamp == transactions[j].Timestamp {
			if transactions[i].ConnectionID == transactions[j].ConnectionID {
				return transactions[i].StreamID < transactions[j].StreamID
			}
			return transactions[i].ConnectionID < transactions[j].ConnectionID
		}
		return transactions[i].Timestamp < transactions[j].Timestamp
	})
	encoder := json.NewEncoder(writer)
	for _, transaction := range transactions {
		if err := encoder.Encode(transaction); err != nil {
			return summary, fmt.Errorf("write HTTP/1 transaction: %w", err)
		}
		summary.Transactions++
	}
	return summary, nil
}

func (capture *http1DirectionCapture) append(call Call) bool {
	if len(call.Data) > maxHTTP1ConnectionBytes-len(capture.data) {
		return false
	}
	start := len(capture.data)
	capture.data = append(capture.data, call.Data...)
	capture.spans = append(capture.spans, http1Span{
		start:     start,
		end:       len(capture.data),
		timestamp: call.Timestamp,
	})
	return true
}

func (capture http1DirectionCapture) timeRange(
	start int,
	end int,
) (uint64, uint64) {
	var first uint64
	var last uint64
	for _, span := range capture.spans {
		if span.end <= start || span.start >= end {
			continue
		}
		if first == 0 || span.timestamp < first {
			first = span.timestamp
		}
		if span.timestamp > last {
			last = span.timestamp
		}
	}
	return first, last
}

func parseHTTP1Requests(
	capture http1DirectionCapture,
	recognized bool,
) ([]parsedHTTP1Request, int) {
	if !recognized {
		return nil, 0
	}
	source := bytes.NewReader(capture.data)
	reader := bufio.NewReader(source)
	var requests []parsedHTTP1Request
	errors := 0
	for remainingHTTP1Bytes(source, reader) != 0 {
		start := consumedHTTP1Bytes(len(capture.data), source, reader)
		request, err := http.ReadRequest(reader)
		if err != nil {
			errors++
			break
		}
		// An SSL* address can be reused after the original connection is
		// destroyed. The capture key is intentionally pointer based, so a
		// later HTTP/2 client preface may follow valid HTTP/1 bytes in the
		// same aggregate. net/http accepts "PRI * HTTP/2.0" as a syntactically
		// valid request; stop the HTTP/1 epoch before emitting it.
		if !isHTTP1Version(request.Proto) {
			_ = request.Body.Close()
			break
		}
		body, bodyErr := readHTTP1Body(request.Body)
		_ = request.Body.Close()
		end := consumedHTTP1Bytes(len(capture.data), source, reader)
		timestamp, lastSeen := capture.timeRange(start, end)
		parsed := parsedHTTP1Request{
			message: HTTP2Message{
				Headers:        requestHeaders(request),
				Body:           body,
				HeadersDecoded: true,
				EndStream:      bodyErr == nil,
			},
			method:    request.Method,
			scheme:    request.URL.Scheme,
			authority: request.Host,
			path:      request.RequestURI,
			version:   request.Proto,
			timestamp: timestamp,
			lastSeen:  lastSeen,
			request:   request,
		}
		if parsed.scheme == "" {
			parsed.scheme = "https"
			parsed.inferred = true
		}
		if len(body) != 0 {
			parsed.message.BodyEncoding = "base64"
		}
		if bodyErr != nil {
			errors++
			parsed.errors = append(
				parsed.errors,
				"request body incomplete: "+bodyErr.Error(),
			)
		}
		requests = append(requests, parsed)
		if bodyErr != nil {
			break
		}
	}
	return requests, errors
}

func parseHTTP1Responses(
	capture http1DirectionCapture,
	recognized bool,
	requests []parsedHTTP1Request,
) ([]parsedHTTP1Response, int) {
	if !recognized {
		return nil, 0
	}
	source := bytes.NewReader(capture.data)
	reader := bufio.NewReader(source)
	var responses []parsedHTTP1Response
	errors := 0
	for remainingHTTP1Bytes(source, reader) != 0 {
		start := consumedHTTP1Bytes(len(capture.data), source, reader)
		var request *http.Request
		if len(responses) < len(requests) {
			request = requests[len(responses)].request
		}
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			errors++
			break
		}
		if response.StatusCode == http.StatusSwitchingProtocols {
			end := consumedHTTP1Bytes(len(capture.data), source, reader)
			timestamp, lastSeen := capture.timeRange(start, end)
			responses = append(responses, parsedHTTP1Response{
				message: HTTP2Message{
					Headers:        responseHeaders(response),
					HeadersDecoded: true,
					EndStream:      true,
				},
				status:    strconv.Itoa(response.StatusCode),
				version:   response.Proto,
				timestamp: timestamp,
				lastSeen:  lastSeen,
			})
			_ = response.Body.Close()
			break
		}
		body, bodyErr := readHTTP1Body(response.Body)
		_ = response.Body.Close()
		end := consumedHTTP1Bytes(len(capture.data), source, reader)
		timestamp, lastSeen := capture.timeRange(start, end)
		if response.StatusCode >= 100 && response.StatusCode < 200 {
			if bodyErr != nil {
				errors++
				break
			}
			continue
		}
		parsed := parsedHTTP1Response{
			message: HTTP2Message{
				Headers:        responseHeaders(response),
				Body:           body,
				HeadersDecoded: true,
				EndStream:      bodyErr == nil,
			},
			status:    strconv.Itoa(response.StatusCode),
			version:   response.Proto,
			timestamp: timestamp,
			lastSeen:  lastSeen,
		}
		if len(body) != 0 {
			parsed.message.BodyEncoding = "base64"
		}
		if bodyErr != nil {
			errors++
			parsed.errors = append(
				parsed.errors,
				"response body incomplete: "+bodyErr.Error(),
			)
		}
		if isHTTP1CloseDelimited(response, request) {
			errors++
			parsed.message.EndStream = false
			parsed.errors = append(
				parsed.errors,
				"response body is capture-EOF delimited without observed connection close",
			)
		}
		responses = append(responses, parsed)
		if bodyErr != nil || isHTTP1CloseDelimited(response, request) {
			break
		}
	}
	return responses, errors
}

func readHTTP1Body(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	limited := io.LimitReader(body, maxHTTP1MessageBody+1)
	data, err := io.ReadAll(limited)
	if len(data) > maxHTTP1MessageBody {
		return data[:maxHTTP1MessageBody], fmt.Errorf(
			"body exceeds %d-byte safety limit",
			maxHTTP1MessageBody,
		)
	}
	return data, err
}

func requestHeaders(request *http.Request) []HTTP2Header {
	headers := http1Headers(request.Header)
	if request.Host != "" {
		headers = append([]HTTP2Header{{
			Name:  "host",
			Value: request.Host,
		}}, headers...)
	}
	return headers
}

func responseHeaders(response *http.Response) []HTTP2Header {
	return http1Headers(response.Header)
}

func http1Headers(headers http.Header) []HTTP2Header {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var result []HTTP2Header
	for _, key := range keys {
		for _, value := range headers.Values(key) {
			result = append(result, HTTP2Header{
				Name:  key,
				Value: value,
			})
		}
	}
	return result
}

func remainingHTTP1Bytes(
	source *bytes.Reader,
	reader *bufio.Reader,
) int {
	return source.Len() + reader.Buffered()
}

func consumedHTTP1Bytes(
	total int,
	source *bytes.Reader,
	reader *bufio.Reader,
) int {
	return total - remainingHTTP1Bytes(source, reader)
}

func looksLikeHTTP1Request(data []byte) bool {
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd < 0 || lineEnd > 8192 {
		return false
	}
	parts := bytes.Split(data[:lineEnd], []byte{' '})
	return len(parts) == 3 &&
		validHTTP1Token(parts[0]) &&
		isHTTP1Version(string(parts[2]))
}

func looksLikeHTTP1Response(data []byte) bool {
	return bytes.HasPrefix(data, []byte("HTTP/1.0 ")) ||
		bytes.HasPrefix(data, []byte("HTTP/1.1 "))
}

func isHTTP1Version(version string) bool {
	return version == "HTTP/1.0" || version == "HTTP/1.1"
}

func validHTTP1Token(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f ||
			strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(character)) {
			return false
		}
	}
	return true
}

func isHTTP1CloseDelimited(
	response *http.Response,
	request *http.Request,
) bool {
	if response == nil ||
		response.Body == http.NoBody ||
		response.ContentLength >= 0 ||
		len(response.TransferEncoding) != 0 ||
		!http1ResponseMayHaveBody(response.StatusCode, request) {
		return false
	}
	return true
}

func http1ResponseMayHaveBody(
	status int,
	request *http.Request,
) bool {
	if request != nil && request.Method == http.MethodHead {
		return false
	}
	return status >= 200 &&
		status != http.StatusNoContent &&
		status != http.StatusNotModified
}
