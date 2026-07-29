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
	"sort"
	"strings"
)

const (
	maxReconstructedCall = 16 * 1024 * 1024
	truncatedFlag        = 1
)

type Summary struct {
	EventsRead      int `json:"eventsRead"`
	ChunksAccepted  int `json:"chunksAccepted"`
	CallsComplete   int `json:"callsComplete"`
	CallsIncomplete int `json:"callsIncomplete"`
	EventsIgnored   int `json:"eventsIgnored"`
}

// Call is a normalized plaintext call. It remains below HTTP transaction
// semantics but preserves enough identity for HTTP/2 and HTTP/3 decoder
// plugins to multiplex correctly.
type Call struct {
	EventType     string      `json:"eventType"`
	CallID        string      `json:"callId"`
	SourceType    string      `json:"sourceType"`
	Timestamp     uint64      `json:"timestamp"`
	Pid           uint32      `json:"pid"`
	Tid           uint32      `json:"tid"`
	Comm          string      `json:"comm,omitempty"`
	Direction     string      `json:"direction"`
	HookID        uint32      `json:"hookId,omitempty"`
	HookName      string      `json:"hookName,omitempty"`
	BufferAddr    uint64      `json:"bufferAddr,omitempty"`
	ContextID     uint64      `json:"contextId,omitempty"`
	StreamID      uint64      `json:"streamId,omitempty"`
	SSLAddr       uint64      `json:"sslAddr,omitempty"`
	BIOAddr       uint64      `json:"bioAddr,omitempty"`
	Fd            uint32      `json:"fd,omitempty"`
	Tuple         string      `json:"tuple,omitempty"`
	OriginalLen   uint32      `json:"originalLen"`
	CapturedLen   uint32      `json:"capturedLen"`
	Complete      bool        `json:"complete"`
	Truncated     bool        `json:"truncated"`
	MissingRanges []ByteRange `json:"missingRanges,omitempty"`
	ProtocolHint  string      `json:"protocolHint"`
	DataEncoding  string      `json:"dataEncoding"`
	Data          []byte      `json:"data"`
}

type ByteRange struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

type structuredChunk struct {
	EventType    string `json:"eventType"`
	Timestamp    uint64 `json:"timestamp"`
	Pid          uint32 `json:"pid"`
	Tid          uint32 `json:"tid"`
	Comm         string `json:"comm"`
	Direction    string `json:"direction"`
	DataType     int64  `json:"dataType"`
	HookID       uint32 `json:"hookId"`
	HookName     string `json:"hookName"`
	BufferAddr   uint64 `json:"bufferAddr"`
	ContextID    uint64 `json:"contextId"`
	StreamID     uint64 `json:"streamId"`
	SSLAddr      uint64 `json:"sslAddr"`
	BIOAddr      uint64 `json:"bioAddr"`
	Fd           uint32 `json:"fd"`
	Tuple        string `json:"tuple"`
	Flags        uint32 `json:"flags"`
	OriginalLen  uint32 `json:"originalLen"`
	CapturedLen  uint32 `json:"capturedLen"`
	ChunkOffset  uint32 `json:"chunkOffset"`
	DataLen      uint32 `json:"dataLen"`
	DataEncoding string `json:"dataEncoding"`
	Data         []byte `json:"data"`
}

type activeCall struct {
	metadata structuredChunk
	key      string
	data     []byte
	covered  []bool
	count    uint32
}

// Reconstruct consumes compact JSON events and writes normalized calls as
// JSONL. Unknown event types are ignored. Incomplete calls are emitted at EOF
// with exact missing ranges instead of being silently discarded.
func Reconstruct(reader io.Reader, writer io.Writer) (Summary, error) {
	var summary Summary
	if reader == nil {
		return summary, fmt.Errorf("reconstruction input is nil")
	}
	if writer == nil {
		return summary, fmt.Errorf("reconstruction output is nil")
	}
	decoder := json.NewDecoder(bufio.NewReader(reader))
	encoder := json.NewEncoder(writer)
	active := make(map[string]*activeCall)
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return summary, fmt.Errorf("decode structured capture event: %w", err)
		}
		summary.EventsRead++
		var event structuredChunk
		if err := json.Unmarshal(raw, &event); err != nil {
			return summary, fmt.Errorf("decode plaintext chunk event: %w", err)
		}
		if event.EventType != "tls_plaintext" &&
			event.EventType != "application_data" {
			summary.EventsIgnored++
			continue
		}
		if err := validateChunk(event); err != nil {
			return summary, fmt.Errorf("event %d: %w", summary.EventsRead, err)
		}
		key := callKey(event)
		current := active[key]
		if current == nil {
			current = &activeCall{
				metadata: event,
				key:      key,
				data:     make([]byte, event.CapturedLen),
				covered:  make([]bool, event.CapturedLen),
			}
			active[key] = current
		} else if err := compatibleChunk(current.metadata, event); err != nil {
			return summary, fmt.Errorf("event %d: %w", summary.EventsRead, err)
		}
		if err := current.add(event); err != nil {
			return summary, fmt.Errorf("event %d: %w", summary.EventsRead, err)
		}
		summary.ChunksAccepted++
		if current.count == current.metadata.CapturedLen {
			call := current.normalized(true)
			if err := encoder.Encode(call); err != nil {
				return summary, fmt.Errorf("write reconstructed call: %w", err)
			}
			delete(active, key)
			summary.CallsComplete++
		}
	}
	keys := make([]string, 0, len(active))
	for key := range active {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		call := active[key].normalized(false)
		if err := encoder.Encode(call); err != nil {
			return summary, fmt.Errorf("write incomplete reconstructed call: %w", err)
		}
		summary.CallsIncomplete++
	}
	return summary, nil
}

func validateChunk(event structuredChunk) error {
	if event.Timestamp == 0 || event.Pid == 0 {
		return fmt.Errorf("plaintext chunk is missing timestamp or pid")
	}
	if event.CapturedLen == 0 || event.CapturedLen > maxReconstructedCall {
		return fmt.Errorf("invalid captured length %d", event.CapturedLen)
	}
	if event.OriginalLen < event.CapturedLen {
		return fmt.Errorf("original length %d is smaller than captured length %d",
			event.OriginalLen, event.CapturedLen)
	}
	if event.DataEncoding != "" && event.DataEncoding != "base64" {
		return fmt.Errorf("unsupported data encoding %q", event.DataEncoding)
	}
	if uint32(len(event.Data)) != event.DataLen {
		return fmt.Errorf("decoded data length %d differs from dataLen %d",
			len(event.Data), event.DataLen)
	}
	if event.DataLen == 0 ||
		uint64(event.ChunkOffset)+uint64(event.DataLen) > uint64(event.CapturedLen) {
		return fmt.Errorf("chunk range %d..%d exceeds captured length %d",
			event.ChunkOffset,
			uint64(event.ChunkOffset)+uint64(event.DataLen),
			event.CapturedLen)
	}
	return nil
}

func compatibleChunk(first, next structuredChunk) error {
	if first.EventType != next.EventType ||
		first.CapturedLen != next.CapturedLen ||
		first.OriginalLen != next.OriginalLen ||
		first.Flags != next.Flags {
		return fmt.Errorf("conflicting metadata for call %q", callKey(first))
	}
	return nil
}

func (call *activeCall) add(event structuredChunk) error {
	for index, value := range event.Data {
		offset := int(event.ChunkOffset) + index
		if call.covered[offset] {
			if call.data[offset] != value {
				return fmt.Errorf("conflicting overlapping byte at offset %d for call %q",
					offset, call.key)
			}
			continue
		}
		call.covered[offset] = true
		call.data[offset] = value
		call.count++
	}
	return nil
}

func (call *activeCall) normalized(complete bool) Call {
	event := call.metadata
	hint := "incomplete"
	if complete {
		hint = protocolHint(call.data, event.StreamID)
	}
	return Call{
		EventType:     "reconstructed_call",
		CallID:        call.key,
		SourceType:    event.EventType,
		Timestamp:     event.Timestamp,
		Pid:           event.Pid,
		Tid:           event.Tid,
		Comm:          event.Comm,
		Direction:     normalizeDirection(event),
		HookID:        event.HookID,
		HookName:      event.HookName,
		BufferAddr:    event.BufferAddr,
		ContextID:     event.ContextID,
		StreamID:      event.StreamID,
		SSLAddr:       event.SSLAddr,
		BIOAddr:       event.BIOAddr,
		Fd:            event.Fd,
		Tuple:         event.Tuple,
		OriginalLen:   event.OriginalLen,
		CapturedLen:   event.CapturedLen,
		Complete:      complete,
		Truncated:     event.Flags&truncatedFlag != 0,
		MissingRanges: missingRanges(call.covered),
		ProtocolHint:  hint,
		DataEncoding:  "base64",
		Data:          call.data,
	}
}

func callKey(event structuredChunk) string {
	if event.EventType == "tls_plaintext" {
		return fmt.Sprintf(
			"tls:%d:%d:%d:%d:%x:%x:%d",
			event.Pid,
			event.Tid,
			event.Timestamp,
			event.DataType,
			event.SSLAddr,
			event.BIOAddr,
			event.Fd,
		)
	}
	return fmt.Sprintf(
		"app:%d:%d:%d:%d:%x:%x:%x",
		event.Pid,
		event.Tid,
		event.Timestamp,
		event.HookID,
		event.BufferAddr,
		event.ContextID,
		event.StreamID,
	)
}

func normalizeDirection(event structuredChunk) string {
	if event.Direction != "" {
		return strings.ToUpper(event.Direction)
	}
	if event.DataType == 0 {
		return "READ"
	}
	return "WRITE"
}

func missingRanges(covered []bool) []ByteRange {
	var result []ByteRange
	for index := 0; index < len(covered); {
		if covered[index] {
			index++
			continue
		}
		start := index
		for index < len(covered) && !covered[index] {
			index++
		}
		result = append(result, ByteRange{Start: uint32(start), End: uint32(index)})
	}
	return result
}

func protocolHint(data []byte, streamID uint64) string {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "empty-or-missing"
	}
	upper := bytes.ToUpper(trimmed)
	for _, method := range [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("PATCH "),
		[]byte("DELETE "), []byte("HEAD "), []byte("OPTIONS "),
	} {
		if bytes.HasPrefix(upper, method) && bytes.Contains(upper, []byte(" HTTP/1.")) {
			return "http1-request"
		}
	}
	if bytes.HasPrefix(upper, []byte("HTTP/1.")) {
		return "http1-response"
	}
	if bytes.HasPrefix(data, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		return "http2-preface"
	}
	if len(data) >= 9 {
		frameLength := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		if frameLength <= uint32(len(data)-9) && data[3] <= 9 {
			return "http2-frame"
		}
	}
	if json.Valid(trimmed) {
		return "json"
	}
	if bytes.HasPrefix(trimmed, []byte("data:")) ||
		bytes.Contains(trimmed, []byte("\ndata:")) {
		return "server-sent-events"
	}
	if streamID != 0 {
		if _, width, ok := decodeQUICVarint(data); ok && width < len(data) {
			return "http3-or-quic-stream"
		}
		return "quic-stream-binary"
	}
	if mostlyPrintable(trimmed) {
		return "text"
	}
	return "custom-binary"
}

func decodeQUICVarint(data []byte) (uint64, int, bool) {
	if len(data) == 0 {
		return 0, 0, false
	}
	width := 1 << (data[0] >> 6)
	if len(data) < width {
		return 0, 0, false
	}
	value := uint64(data[0] & 0x3f)
	for index := 1; index < width; index++ {
		value = value<<8 | uint64(data[index])
	}
	return value, width, true
}

func mostlyPrintable(data []byte) bool {
	printable := 0
	for _, value := range data {
		if value == '\n' || value == '\r' || value == '\t' ||
			(value >= 0x20 && value < 0x7f) {
			printable++
		}
	}
	return printable*100/len(data) >= 85
}
