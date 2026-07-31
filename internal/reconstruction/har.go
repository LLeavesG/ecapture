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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type HAROptions struct {
	// WallTimeAnchor is the wall-clock time corresponding to the first input
	// transaction's monotonic timestamp. It is only used for legacy captures
	// that predate the wallTime field.
	WallTimeAnchor *time.Time
}

type HARSummary struct {
	Transactions          int   `json:"transactions"`
	CompleteTransactions  int   `json:"completeTransactions"`
	RequestBodyBytes      int64 `json:"requestBodyBytes"`
	ResponseBodyBytes     int64 `json:"responseBodyBytes"`
	LegacyAnchoredEntries int   `json:"legacyAnchoredEntries"`
}

type harTransaction struct {
	EventType       string     `json:"eventType"`
	Protocol        string     `json:"protocol"`
	CaptureLayer    string     `json:"captureLayer"`
	Transport       string     `json:"transport"`
	ConnectionID    string     `json:"connectionId"`
	StreamID        uint64     `json:"streamId"`
	Timestamp       uint64     `json:"timestamp"`
	LastSeen        uint64     `json:"lastSeen"`
	WallTime        string     `json:"wallTime"`
	Method          string     `json:"method"`
	Scheme          string     `json:"scheme"`
	Authority       string     `json:"authority"`
	Path            string     `json:"path"`
	Status          string     `json:"status"`
	RequestVersion  string     `json:"requestVersion"`
	ResponseVersion string     `json:"responseVersion"`
	Request         harMessage `json:"request"`
	Response        harMessage `json:"response"`
	Complete        bool       `json:"complete"`
	Errors          []string   `json:"errors"`
}

type harMessage struct {
	Headers []HTTP2Header `json:"headers"`
	Body    []byte        `json:"body"`
}

type harLog struct {
	Version string     `json:"version"`
	Creator harCreator `json:"creator"`
	Comment string     `json:"comment"`
}

type harCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type harEntry struct {
	StartedDateTime string         `json:"startedDateTime"`
	Time            float64        `json:"time"`
	Request         harRequest     `json:"request"`
	Response        harResponse    `json:"response"`
	Cache           map[string]any `json:"cache"`
	Timings         harTimings     `json:"timings"`
	ECapture        harProvenance  `json:"_ecapture"`
}

type harRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harNameValue `json:"headers"`
	QueryString []harNameValue `json:"queryString"`
	Cookies     []harNameValue `json:"cookies"`
	HeadersSize int64          `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
	PostData    *harPostData   `json:"postData,omitempty"`
}

type harResponse struct {
	Status      int            `json:"status"`
	StatusText  string         `json:"statusText"`
	HTTPVersion string         `json:"httpVersion"`
	Headers     []harNameValue `json:"headers"`
	Cookies     []harNameValue `json:"cookies"`
	Content     harContent     `json:"content"`
	RedirectURL string         `json:"redirectURL"`
	HeadersSize int64          `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
}

type harNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MIMEType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"_encoding"`
}

type harContent struct {
	Size     int64  `json:"size"`
	MIMEType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type harTimings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
	SSL     float64 `json:"ssl"`
}

type harProvenance struct {
	Protocol               string   `json:"protocol"`
	CaptureLayer           string   `json:"captureLayer"`
	Transport              string   `json:"transport"`
	ConnectionID           string   `json:"connectionId"`
	StreamID               uint64   `json:"streamId"`
	MonotonicTimestamp     uint64   `json:"monotonicTimestamp"`
	MonotonicLastSeen      uint64   `json:"monotonicLastSeen"`
	Complete               bool     `json:"complete"`
	Errors                 []string `json:"errors,omitempty"`
	TimingModel            string   `json:"timingModel"`
	BodyTransformation     string   `json:"bodyTransformation"`
	ApplicationDecoding    string   `json:"applicationDecoding"`
	RequestBodySHA256      string   `json:"requestBodySha256"`
	ResponseBodySHA256     string   `json:"responseBodySha256"`
	LegacyWallTimeAnchored bool     `json:"legacyWallTimeAnchored,omitempty"`
}

// ExportHAR converts canonical transaction JSONL to a streaming HAR 1.2
// compatibility view. Bodies are never interpreted: request postData uses an
// explicit _encoding extension and response content uses HAR's standard
// base64 encoding. The exact transaction JSONL remains the canonical artifact.
func ExportHAR(
	reader io.Reader,
	writer io.Writer,
	options HAROptions,
) (HARSummary, error) {
	var summary HARSummary
	if reader == nil {
		return summary, fmt.Errorf("HAR transaction input is nil")
	}
	if writer == nil {
		return summary, fmt.Errorf("HAR output is nil")
	}

	spool, err := os.CreateTemp("", "ecapture-har-*.json")
	if err != nil {
		return summary, fmt.Errorf("create private HAR spool: %w", err)
	}
	spoolPath := spool.Name()
	defer func() {
		_ = spool.Close()
		_ = os.Remove(spoolPath)
	}()
	if err := spool.Chmod(0o600); err != nil {
		return summary, fmt.Errorf("protect HAR spool: %w", err)
	}

	logHeader, err := json.Marshal(harLog{
		Version: "1.2",
		Creator: harCreator{Name: "eCapture", Version: "transport-reconstruction"},
		Comment: "Sensitive capture artifact. Bodies are base64 transport-boundary bytes; application decoding was not attempted.",
	})
	if err != nil {
		return summary, fmt.Errorf("encode HAR header: %w", err)
	}
	if len(logHeader) == 0 || logHeader[len(logHeader)-1] != '}' {
		return summary, fmt.Errorf("encode HAR header: malformed JSON object")
	}
	if _, err := fmt.Fprintf(
		spool,
		`{"log":%s,"entries":[`,
		logHeader[:len(logHeader)-1],
	); err != nil {
		return summary, fmt.Errorf("write HAR header: %w", err)
	}

	decoder := json.NewDecoder(bufio.NewReader(reader))
	var firstTimestamp uint64
	for {
		var transaction harTransaction
		if err := decoder.Decode(&transaction); err != nil {
			if err == io.EOF {
				break
			}
			return summary, fmt.Errorf(
				"decode transaction %d for HAR: %w",
				summary.Transactions+1,
				err,
			)
		}
		if transaction.EventType != "http_transaction" ||
			transaction.Protocol == "" {
			return summary, fmt.Errorf(
				"record %d is not a protocol-attributed HTTP transaction",
				summary.Transactions+1,
			)
		}
		if transaction.LastSeen < transaction.Timestamp {
			return summary, fmt.Errorf(
				"record %d has lastSeen before timestamp",
				summary.Transactions+1,
			)
		}
		if summary.Transactions == 0 {
			firstTimestamp = transaction.Timestamp
		}
		started, anchored, err := harStartedTime(
			transaction,
			options,
			firstTimestamp,
		)
		if err != nil {
			return summary, fmt.Errorf(
				"record %d: %w",
				summary.Transactions+1,
				err,
			)
		}
		entry := makeHAREntry(transaction, started, anchored)
		encoded, err := json.Marshal(entry)
		if err != nil {
			return summary, fmt.Errorf("encode HAR entry: %w", err)
		}
		if summary.Transactions != 0 {
			if _, err := spool.Write([]byte{','}); err != nil {
				return summary, fmt.Errorf("separate HAR entries: %w", err)
			}
		}
		if _, err := spool.Write(encoded); err != nil {
			return summary, fmt.Errorf("write HAR entry: %w", err)
		}
		summary.Transactions++
		if transaction.Complete {
			summary.CompleteTransactions++
		}
		summary.RequestBodyBytes += int64(len(transaction.Request.Body))
		summary.ResponseBodyBytes += int64(len(transaction.Response.Body))
		if anchored {
			summary.LegacyAnchoredEntries++
		}
	}
	if _, err := spool.WriteString(`]}}`); err != nil {
		return summary, fmt.Errorf("finish HAR document: %w", err)
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return summary, fmt.Errorf("rewind HAR spool: %w", err)
	}
	if _, err := io.Copy(writer, spool); err != nil {
		return summary, fmt.Errorf("copy HAR output: %w", err)
	}
	return summary, nil
}

func harStartedTime(
	transaction harTransaction,
	options HAROptions,
	firstTimestamp uint64,
) (time.Time, bool, error) {
	if transaction.WallTime != "" {
		value, err := time.Parse(time.RFC3339Nano, transaction.WallTime)
		if err != nil {
			return time.Time{}, false, fmt.Errorf(
				"invalid wallTime %q: %w",
				transaction.WallTime,
				err,
			)
		}
		return value, false, nil
	}
	if options.WallTimeAnchor == nil {
		return time.Time{}, false, fmt.Errorf(
			"wallTime is absent; pass a wall-time anchor for this legacy capture",
		)
	}
	return options.WallTimeAnchor.Add(
		monotonicDelta(firstTimestamp, transaction.Timestamp),
	), true, nil
}

func makeHAREntry(
	transaction harTransaction,
	started time.Time,
	anchored bool,
) harEntry {
	duration := monotonicDelta(
		transaction.Timestamp,
		transaction.LastSeen,
	)
	status, _ := strconv.Atoi(transaction.Status)
	if status < 0 || status > 999 {
		status = 0
	}
	protocol := harHTTPVersion(transaction)
	requestMIME := headerValue(transaction.Request.Headers, "content-type")
	responseMIME := headerValue(transaction.Response.Headers, "content-type")
	requestBody := transaction.Request.Body
	responseBody := transaction.Response.Body
	entry := harEntry{
		StartedDateTime: started.UTC().Format(time.RFC3339Nano),
		Time:            float64(duration) / float64(time.Millisecond),
		Request: harRequest{
			Method:      transaction.Method,
			URL:         harURL(transaction),
			HTTPVersion: protocol,
			Headers:     harHeaders(transaction.Request.Headers),
			QueryString: harQueryString(transaction.Path),
			Cookies:     []harNameValue{},
			HeadersSize: -1,
			BodySize:    int64(len(requestBody)),
		},
		Response: harResponse{
			Status:      status,
			StatusText:  http.StatusText(status),
			HTTPVersion: protocol,
			Headers:     harHeaders(transaction.Response.Headers),
			Cookies:     []harNameValue{},
			Content: harContent{
				Size:     int64(len(responseBody)),
				MIMEType: responseMIME,
			},
			RedirectURL: headerValue(
				transaction.Response.Headers,
				"location",
			),
			HeadersSize: -1,
			BodySize:    int64(len(responseBody)),
		},
		Cache: map[string]any{},
		Timings: harTimings{
			Blocked: -1,
			DNS:     -1,
			Connect: -1,
			Send:    -1,
			Wait:    -1,
			Receive: -1,
			SSL:     -1,
		},
		ECapture: harProvenance{
			Protocol:               transaction.Protocol,
			CaptureLayer:           transaction.CaptureLayer,
			Transport:              transaction.Transport,
			ConnectionID:           transaction.ConnectionID,
			StreamID:               transaction.StreamID,
			MonotonicTimestamp:     transaction.Timestamp,
			MonotonicLastSeen:      transaction.LastSeen,
			Complete:               transaction.Complete,
			Errors:                 transaction.Errors,
			TimingModel:            "capture-span-only",
			BodyTransformation:     "none",
			ApplicationDecoding:    "not-attempted",
			RequestBodySHA256:      bodySHA256(requestBody),
			ResponseBodySHA256:     bodySHA256(responseBody),
			LegacyWallTimeAnchored: anchored,
		},
	}
	if len(requestBody) != 0 {
		entry.Request.PostData = &harPostData{
			MIMEType: requestMIME,
			Text:     base64.StdEncoding.EncodeToString(requestBody),
			Encoding: "base64",
		}
	}
	if len(responseBody) != 0 {
		entry.Response.Content.Text =
			base64.StdEncoding.EncodeToString(responseBody)
		entry.Response.Content.Encoding = "base64"
	}
	return entry
}

func monotonicDelta(first, second uint64) time.Duration {
	if second < first {
		return 0
	}
	delta := second - first
	const maxDuration = uint64(1<<63 - 1)
	if delta > maxDuration {
		return time.Duration(maxDuration)
	}
	return time.Duration(delta)
}

func harHTTPVersion(transaction harTransaction) string {
	switch transaction.Protocol {
	case "http1":
		if transaction.ResponseVersion != "" {
			return transaction.ResponseVersion
		}
		if transaction.RequestVersion != "" {
			return transaction.RequestVersion
		}
		return "HTTP/1.1"
	case "http2":
		return "HTTP/2"
	case "gquic-http":
		return "gQUIC/HTTP"
	case "http3":
		return "HTTP/3"
	default:
		return transaction.Protocol
	}
}

func harURL(transaction harTransaction) string {
	path := transaction.Path
	if path == "" {
		path = "/"
	}
	if transaction.Authority == "" {
		return path
	}
	scheme := transaction.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + transaction.Authority + path
}

func harHeaders(headers []HTTP2Header) []harNameValue {
	result := make([]harNameValue, 0, len(headers))
	for _, header := range headers {
		result = append(result, harNameValue{
			Name:  header.Name,
			Value: header.Value,
		})
	}
	return result
}

func harQueryString(path string) []harNameValue {
	question := strings.IndexByte(path, '?')
	if question < 0 || question == len(path)-1 {
		return []harNameValue{}
	}
	rawQuery := path[question+1:]
	if fragment := strings.IndexByte(rawQuery, '#'); fragment >= 0 {
		rawQuery = rawQuery[:fragment]
	}
	if rawQuery == "" {
		return []harNameValue{}
	}
	parts := strings.Split(rawQuery, "&")
	result := make([]harNameValue, 0, len(parts))
	for _, part := range parts {
		name, value, _ := strings.Cut(part, "=")
		decodedName, err := url.QueryUnescape(name)
		if err != nil {
			decodedName = name
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			decodedValue = value
		}
		result = append(result, harNameValue{
			Name:  decodedName,
			Value: decodedValue,
		})
	}
	return result
}

func headerValue(headers []HTTP2Header, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value
		}
	}
	return ""
}

func bodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
