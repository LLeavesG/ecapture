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

const maxQUICStreamSize = 64 * 1024 * 1024

type QUICStreamSummary struct {
	Reconstruction        Summary `json:"reconstruction"`
	CallsProcessed        int     `json:"callsProcessed"`
	CallsIgnored          int     `json:"callsIgnored"`
	Connections           int     `json:"connections"`
	Streams               int     `json:"streams"`
	ExplicitOffsetStreams int     `json:"explicitOffsetStreams"`
	InferredOffsetStreams int     `json:"inferredOffsetStreams"`
	MixedOffsetStreams    int     `json:"mixedOffsetStreams"`
	FinishedStreams       int     `json:"finishedStreams"`
	CompleteStreams       int     `json:"completeStreams"`
	DuplicateBytes        uint64  `json:"duplicateBytes"`
	ConflictingBytes      uint64  `json:"conflictingBytes"`
	MissingBytes          uint64  `json:"missingBytes"`
}

type QUICByteRange struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// QUICStream is a lossless transport-boundary stream view. Explicit offsets
// come from received QUIC STREAM frames. When the send-side API exposes only
// ordered writes, offsets are inferred from call order and labeled as such.
type QUICStream struct {
	EventType    string          `json:"eventType"`
	Protocol     string          `json:"protocol"`
	CaptureLayer string          `json:"captureLayer"`
	Transport    string          `json:"transport"`
	ConnectionID string          `json:"connectionId"`
	ContextID    uint64          `json:"contextId"`
	Pid          uint32          `json:"pid"`
	Direction    string          `json:"direction"`
	StreamID     uint64          `json:"streamId"`
	Timestamp    uint64          `json:"timestamp"`
	LastSeen     uint64          `json:"lastSeen"`
	WallTime     string          `json:"wallTime,omitempty"`
	Calls        int             `json:"calls"`
	OffsetMode   string          `json:"offsetMode"`
	FinalOffset  *uint64         `json:"finalOffset,omitempty"`
	Fin          bool            `json:"fin"`
	Complete     bool            `json:"complete"`
	Truncated    bool            `json:"truncated"`
	Missing      []QUICByteRange `json:"missingRanges,omitempty"`
	Duplicate    uint64          `json:"duplicateBytes,omitempty"`
	Conflicting  uint64          `json:"conflictingBytes,omitempty"`
	Errors       []string        `json:"errors,omitempty"`
	ProtocolHint string          `json:"protocolHint"`
	DataEncoding string          `json:"dataEncoding"`
	Data         []byte          `json:"data"`

	// byteReady records the first capture timestamp for each stream byte. It is
	// intentionally not serialized. Stateful decoders such as QPACK use it to
	// distinguish encoder instructions already available when a HEADERS block
	// arrived from instructions observed later in the same capture.
	byteReady []uint64
}

type quicStreamState struct {
	stream      QUICStream
	data        []byte
	covered     []bool
	byteReady   []uint64
	inferredEnd uint64
	explicit    bool
	inferred    bool
}

func ReconstructQUICStreams(
	reader io.Reader,
	writer io.Writer,
) (QUICStreamSummary, error) {
	summary, streams, err := collectQUICStreams(reader)
	if err != nil {
		return summary, err
	}
	encoder := json.NewEncoder(writer)
	for _, stream := range streams {
		if err := encoder.Encode(stream); err != nil {
			return summary, fmt.Errorf("write reconstructed QUIC stream: %w", err)
		}
	}
	return summary, nil
}

func collectQUICStreams(
	reader io.Reader,
) (QUICStreamSummary, []QUICStream, error) {
	var summary QUICStreamSummary
	if reader == nil {
		return summary, nil, fmt.Errorf("QUIC reconstruction input is nil")
	}

	var reconstructed bytes.Buffer
	callSummary, err := Reconstruct(reader, &reconstructed)
	if err != nil {
		return summary, nil, err
	}
	summary.Reconstruction = callSummary

	var calls []Call
	decoder := json.NewDecoder(bufio.NewReader(&reconstructed))
	for {
		var call Call
		if err := decoder.Decode(&call); err != nil {
			if err == io.EOF {
				break
			}
			return summary, nil, fmt.Errorf(
				"decode reconstructed QUIC call: %w", err)
		}
		if call.SourceType != "boundary_data" ||
			call.CaptureLayer != captureLayerTransport ||
			call.Transport != "quic" ||
			!call.Complete {
			summary.CallsIgnored++
			continue
		}
		calls = append(calls, call)
	}
	sort.SliceStable(calls, func(i, j int) bool {
		if calls[i].Timestamp == calls[j].Timestamp {
			return calls[i].CallID < calls[j].CallID
		}
		return calls[i].Timestamp < calls[j].Timestamp
	})

	states := make(map[string]*quicStreamState)
	connections := make(map[string]struct{})
	for _, call := range calls {
		direction := strings.ToUpper(call.Direction)
		connectionID := quicConnectionID(call.Pid, call.ContextID)
		key := fmt.Sprintf("%s:%s:%d", connectionID, direction, call.StreamID)
		state := states[key]
		if state == nil {
			state = &quicStreamState{
				stream: QUICStream{
					EventType:    "quic_stream",
					Protocol:     "quic",
					CaptureLayer: captureLayerTransport,
					Transport:    "quic",
					ConnectionID: connectionID,
					ContextID:    call.ContextID,
					Pid:          call.Pid,
					Direction:    direction,
					StreamID:     call.StreamID,
					Timestamp:    call.Timestamp,
					LastSeen:     call.Timestamp,
					WallTime:     call.WallTime,
					DataEncoding: "base64",
				},
			}
			states[key] = state
		}
		if err := state.add(call); err != nil {
			return summary, nil, fmt.Errorf(
				"reassemble QUIC stream %s: %w", key, err)
		}
		connections[connectionID] = struct{}{}
		summary.CallsProcessed++
	}

	keys := make([]string, 0, len(states))
	for key := range states {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	streams := make([]QUICStream, 0, len(keys))
	for _, key := range keys {
		stream := states[key].normalized()
		switch stream.OffsetMode {
		case "explicit":
			summary.ExplicitOffsetStreams++
		case "inferred":
			summary.InferredOffsetStreams++
		case "mixed":
			summary.MixedOffsetStreams++
		}
		if stream.Fin {
			summary.FinishedStreams++
		}
		if stream.Complete {
			summary.CompleteStreams++
		}
		summary.DuplicateBytes += stream.Duplicate
		summary.ConflictingBytes += stream.Conflicting
		for _, missing := range stream.Missing {
			summary.MissingBytes += missing.End - missing.Start
		}
		streams = append(streams, stream)
	}
	gquicConnections := make(map[string]bool)
	for _, stream := range streams {
		if stream.ProtocolHint == "gquic-crypto" ||
			stream.ProtocolHint == "gquic-http-headers" {
			gquicConnections[stream.ConnectionID] = true
		}
	}
	for index := range streams {
		if gquicConnections[streams[index].ConnectionID] &&
			streams[index].StreamID != 1 &&
			streams[index].StreamID != 3 {
			streams[index].ProtocolHint = "gquic-http-body"
		}
	}
	sort.Slice(streams, func(i, j int) bool {
		if streams[i].Timestamp == streams[j].Timestamp {
			if streams[i].ConnectionID == streams[j].ConnectionID {
				if streams[i].Direction == streams[j].Direction {
					return streams[i].StreamID < streams[j].StreamID
				}
				return streams[i].Direction < streams[j].Direction
			}
			return streams[i].ConnectionID < streams[j].ConnectionID
		}
		return streams[i].Timestamp < streams[j].Timestamp
	})
	summary.Connections = len(connections)
	summary.Streams = len(streams)
	return summary, streams, nil
}

func quicConnectionID(pid uint32, contextID uint64) string {
	return fmt.Sprintf("quic:%d:context:%x", pid, contextID)
}

func (state *quicStreamState) add(call Call) error {
	if call.Timestamp < state.stream.Timestamp {
		state.stream.Timestamp = call.Timestamp
		state.stream.WallTime = call.WallTime
	}
	if call.Timestamp > state.stream.LastSeen {
		state.stream.LastSeen = call.Timestamp
	}
	state.stream.Calls++
	state.stream.Truncated = state.stream.Truncated || call.Truncated

	var offset uint64
	if call.StreamOffset != nil {
		offset = *call.StreamOffset
		state.explicit = true
	} else {
		offset = state.inferredEnd
		state.inferred = true
	}
	logicalLength := uint64(call.OriginalLen)
	end := offset + logicalLength
	if end < offset || end > maxQUICStreamSize {
		return fmt.Errorf("extent %d exceeds %d-byte safety limit",
			end, maxQUICStreamSize)
	}
	if err := state.ensure(end); err != nil {
		return err
	}
	for index, value := range call.Data {
		position := offset + uint64(index)
		if position >= uint64(len(state.data)) {
			return fmt.Errorf("captured byte %d exceeds logical extent %d",
				position, len(state.data))
		}
		if state.covered[position] {
			if state.data[position] == value {
				state.stream.Duplicate++
			} else {
				state.stream.Conflicting++
			}
			continue
		}
		state.covered[position] = true
		state.data[position] = value
		state.byteReady[position] = call.Timestamp
	}
	if end > state.inferredEnd {
		state.inferredEnd = end
	}
	if call.Fin != nil && *call.Fin {
		state.stream.Fin = true
		if state.stream.FinalOffset != nil && *state.stream.FinalOffset != end {
			state.addError(fmt.Sprintf(
				"conflicting final offsets %d and %d",
				*state.stream.FinalOffset, end))
		} else if state.stream.FinalOffset == nil {
			finalOffset := end
			state.stream.FinalOffset = &finalOffset
		}
	}
	return nil
}

func (state *quicStreamState) ensure(length uint64) error {
	if length <= uint64(len(state.data)) {
		return nil
	}
	if length > maxQUICStreamSize {
		return fmt.Errorf("stream length %d exceeds safety limit", length)
	}
	growth := int(length) - len(state.data)
	state.data = append(state.data, make([]byte, growth)...)
	state.covered = append(state.covered, make([]bool, growth)...)
	state.byteReady = append(state.byteReady, make([]uint64, growth)...)
	return nil
}

func (state *quicStreamState) addError(message string) {
	if len(state.stream.Errors) < 16 {
		state.stream.Errors = append(state.stream.Errors, message)
	}
}

func (state *quicStreamState) normalized() QUICStream {
	result := state.stream
	switch {
	case state.explicit && state.inferred:
		result.OffsetMode = "mixed"
	case state.explicit:
		result.OffsetMode = "explicit"
	default:
		result.OffsetMode = "inferred"
	}
	var limit uint64 = uint64(len(state.covered))
	if result.FinalOffset != nil && *result.FinalOffset < limit {
		limit = *result.FinalOffset
	}
	for index := uint64(0); index < limit; {
		if state.covered[index] {
			index++
			continue
		}
		start := index
		for index < limit && !state.covered[index] {
			index++
		}
		result.Missing = append(result.Missing, QUICByteRange{
			Start: start,
			End:   index,
		})
	}
	if result.Conflicting != 0 {
		state.addError(fmt.Sprintf(
			"%d overlapping bytes had conflicting values",
			result.Conflicting))
		result.Errors = append([]string(nil), state.stream.Errors...)
	}
	result.Complete = result.Fin &&
		len(result.Missing) == 0 &&
		result.Conflicting == 0 &&
		!result.Truncated &&
		len(result.Errors) == 0
	result.Data = append([]byte(nil), state.data...)
	result.byteReady = append([]uint64(nil), state.byteReady...)
	result.ProtocolHint = quicStreamProtocolHint(result.StreamID, result.Data)
	return result
}

func quicStreamProtocolHint(streamID uint64, data []byte) string {
	switch {
	case streamID == 1 &&
		(bytes.HasPrefix(data, []byte("CHLO")) ||
			bytes.HasPrefix(data, []byte("REJ")) ||
			bytes.HasPrefix(data, []byte("SHLO"))):
		return "gquic-crypto"
	case streamID == 3:
		if _, complete, plausible := parseHTTP2Frame(data); plausible && complete {
			return "gquic-http-headers"
		}
	}
	if streamID&0x2 != 0 {
		streamType, _, ok := decodeQUICVarint(data)
		if ok {
			switch streamType {
			case 0:
				return "http3-control"
			case 1:
				return "http3-push"
			case 2:
				return "qpack-encoder"
			case 3:
				return "qpack-decoder"
			}
		}
	}
	if frame, complete, plausible := parseHTTP3Frame(data); complete && plausible &&
		(frame.frameType == 0 || frame.frameType == 1) {
		return "http3-request-stream"
	}
	return protocolHint(data, 0)
}
