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
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

const maxHTTP3FramePayload = 64 * 1024 * 1024

type http3Frame struct {
	frameType uint64
	length    uint64
	headerLen int
	payload   []byte
}

type HTTP3Summary struct {
	StreamReconstruction QUICStreamSummary `json:"streamReconstruction"`
	Connections          int               `json:"connections"`
	StreamsProcessed     int               `json:"streamsProcessed"`
	StreamsIgnored       int               `json:"streamsIgnored"`
	Frames               int               `json:"frames"`
	DataFrames           int               `json:"dataFrames"`
	HeaderFrames         int               `json:"headerFrames"`
	ControlFrames        int               `json:"controlFrames"`
	QPACKStreams         int               `json:"qpackStreams"`
	IncompleteRecords    int               `json:"incompleteRecords"`
}

type HTTP3Record struct {
	EventType    string   `json:"eventType"`
	Protocol     string   `json:"protocol"`
	CaptureLayer string   `json:"captureLayer"`
	Transport    string   `json:"transport"`
	ConnectionID string   `json:"connectionId"`
	ContextID    uint64   `json:"contextId"`
	Pid          uint32   `json:"pid"`
	Direction    string   `json:"direction"`
	StreamID     uint64   `json:"streamId"`
	Timestamp    uint64   `json:"timestamp"`
	RecordIndex  int      `json:"recordIndex"`
	Offset       uint64   `json:"offset"`
	StreamType   *uint64  `json:"streamType,omitempty"`
	StreamName   string   `json:"streamName,omitempty"`
	PushID       *uint64  `json:"pushId,omitempty"`
	FrameType    *uint64  `json:"frameType,omitempty"`
	FrameName    string   `json:"frameName,omitempty"`
	Length       uint64   `json:"length"`
	Complete     bool     `json:"complete"`
	Errors       []string `json:"errors,omitempty"`
	DataEncoding string   `json:"dataEncoding"`
	Data         []byte   `json:"data"`
}

// parseHTTP3Frame parses one RFC 9114 frame from the beginning of data. The
// second result says the whole frame is present; the third says the prefix is
// structurally plausible and more bytes may complete it.
func parseHTTP3Frame(data []byte) (http3Frame, bool, bool) {
	frameType, typeWidth, ok := decodeQUICVarint(data)
	if !ok {
		return http3Frame{}, false, len(data) < 8
	}
	length, lengthWidth, ok := decodeQUICVarint(data[typeWidth:])
	if !ok {
		return http3Frame{}, false, len(data)-typeWidth < 8
	}
	if length > maxHTTP3FramePayload {
		return http3Frame{}, false, false
	}
	headerLen := typeWidth + lengthWidth
	if uint64(len(data)-headerLen) < length {
		return http3Frame{
			frameType: frameType,
			length:    length,
			headerLen: headerLen,
		}, false, true
	}
	return http3Frame{
		frameType: frameType,
		length:    length,
		headerLen: headerLen,
		payload:   data[headerLen : headerLen+int(length)],
	}, true, true
}

// ReconstructHTTP3Frames sequences QUIC streams and parses RFC 9114 stream
// types and frame boundaries. QPACK encoder/decoder instructions and HEADERS
// blocks remain exact bytes in this layer so a stateful QPACK decoder or a
// protocol-decoder boundary hook can consume them without losing evidence.
func ReconstructHTTP3Frames(
	reader io.Reader,
	writer io.Writer,
) (HTTP3Summary, error) {
	var summary HTTP3Summary
	if writer == nil {
		return summary, fmt.Errorf("HTTP/3 reconstruction output is nil")
	}
	streamSummary, streams, err := collectQUICStreams(reader)
	if err != nil {
		return summary, err
	}
	summary.StreamReconstruction = streamSummary

	gquicConnections := make(map[string]bool)
	for _, stream := range streams {
		if stream.ProtocolHint == "gquic-crypto" ||
			stream.ProtocolHint == "gquic-http-headers" ||
			stream.ProtocolHint == "gquic-http-body" {
			gquicConnections[stream.ConnectionID] = true
		}
	}
	connectionSet := make(map[string]struct{})
	var records []HTTP3Record
	for _, stream := range streams {
		if gquicConnections[stream.ConnectionID] ||
			len(stream.Missing) != 0 ||
			stream.Conflicting != 0 ||
			stream.Truncated {
			summary.StreamsIgnored++
			continue
		}
		streamRecords, recognized := parseHTTP3Stream(stream)
		if !recognized {
			summary.StreamsIgnored++
			continue
		}
		summary.StreamsProcessed++
		connectionSet[stream.ConnectionID] = struct{}{}
		for _, record := range streamRecords {
			switch {
			case record.EventType == "qpack_stream":
				summary.QPACKStreams++
			case record.FrameType != nil && *record.FrameType == 0:
				summary.DataFrames++
				summary.Frames++
			case record.FrameType != nil && *record.FrameType == 1:
				summary.HeaderFrames++
				summary.Frames++
			case record.FrameType != nil:
				summary.ControlFrames++
				summary.Frames++
			}
			if !record.Complete {
				summary.IncompleteRecords++
			}
			records = append(records, record)
		}
	}
	summary.Connections = len(connectionSet)
	sort.Slice(records, func(i, j int) bool {
		if records[i].Timestamp == records[j].Timestamp {
			if records[i].ConnectionID == records[j].ConnectionID {
				if records[i].Direction == records[j].Direction {
					if records[i].StreamID == records[j].StreamID {
						return records[i].RecordIndex <
							records[j].RecordIndex
					}
					return records[i].StreamID < records[j].StreamID
				}
				return records[i].Direction < records[j].Direction
			}
			return records[i].ConnectionID < records[j].ConnectionID
		}
		return records[i].Timestamp < records[j].Timestamp
	})
	encoder := json.NewEncoder(writer)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return summary, fmt.Errorf("write HTTP/3 record: %w", err)
		}
	}
	return summary, nil
}

func parseHTTP3Stream(stream QUICStream) ([]HTTP3Record, bool) {
	base := HTTP3Record{
		Protocol:     "http3",
		CaptureLayer: captureLayerTransport,
		Transport:    "quic",
		ConnectionID: stream.ConnectionID,
		ContextID:    stream.ContextID,
		Pid:          stream.Pid,
		Direction:    stream.Direction,
		StreamID:     stream.StreamID,
		Timestamp:    stream.Timestamp,
		DataEncoding: "base64",
	}
	data := stream.Data
	offset := 0
	frameStream := true
	if stream.StreamID&0x2 != 0 {
		streamType, width, ok := decodeQUICVarint(data)
		if !ok {
			return nil, false
		}
		base.StreamType = uint64Value(streamType)
		base.StreamName = http3StreamTypeName(streamType)
		offset = width
		switch streamType {
		case 0:
			// Control stream contains HTTP/3 frames.
		case 1:
			pushID, pushWidth, ok := decodeQUICVarint(data[offset:])
			if !ok {
				return []HTTP3Record{incompleteHTTP3Record(
					base, 0, uint64(offset), data[offset:],
					"incomplete push ID")}, true
			}
			base.PushID = uint64Value(pushID)
			offset += pushWidth
		case 2, 3:
			frameStream = false
		default:
			frameStream = false
		}
		if !frameStream {
			record := base
			record.EventType = "http3_stream_data"
			if streamType == 2 || streamType == 3 {
				record.EventType = "qpack_stream"
			}
			record.Offset = uint64(offset)
			record.Length = uint64(len(data) - offset)
			record.Complete = stream.Fin
			record.Data = append([]byte(nil), data[offset:]...)
			if !record.Complete {
				record.Errors = []string{"stream FIN was not observed"}
			}
			return []HTTP3Record{record}, true
		}
	}

	if offset >= len(data) {
		return nil, base.StreamType != nil
	}
	first, firstComplete, firstPlausible := parseHTTP3Frame(data[offset:])
	if !firstPlausible {
		return nil, false
	}
	if !firstComplete {
		// A bidirectional stream is only classified as HTTP/3 once a
		// request-stream frame is visible. Unknown extension/GREASE frames
		// are legal before HEADERS, but an incomplete unknown prefix alone
		// is not enough to distinguish HTTP/3 from arbitrary QUIC data.
		if base.StreamType == nil && first.frameType != 0 && first.frameType != 1 {
			return nil, false
		}
		record := incompleteHTTP3Record(
			base, 0, uint64(offset), data[offset:],
			"incomplete HTTP/3 frame")
		record.FrameType = uint64Value(first.frameType)
		record.FrameName = http3FrameTypeName(first.frameType)
		record.Length = first.length
		return []HTTP3Record{record}, true
	}

	var records []HTTP3Record
	index := 0
	recognized := base.StreamType != nil
	for offset < len(data) {
		frame, complete, plausible := parseHTTP3Frame(data[offset:])
		if !plausible {
			records = append(records, incompleteHTTP3Record(
				base, index, uint64(offset), data[offset:],
				"invalid HTTP/3 frame prefix"))
			break
		}
		record := base
		record.EventType = "http3_frame"
		record.RecordIndex = index
		record.Offset = uint64(offset)
		record.FrameType = uint64Value(frame.frameType)
		record.FrameName = http3FrameTypeName(frame.frameType)
		record.Length = frame.length
		record.Complete = complete
		if frame.frameType == 0 || frame.frameType == 1 {
			recognized = true
		}
		if complete {
			record.Data = append([]byte(nil), frame.payload...)
			offset += frame.headerLen + len(frame.payload)
		} else {
			record.Data = append([]byte(nil), data[offset:]...)
			record.Errors = []string{"frame payload is incomplete"}
			records = append(records, record)
			break
		}
		records = append(records, record)
		index++
	}
	if !recognized {
		return nil, false
	}
	return records, true
}

func incompleteHTTP3Record(
	base HTTP3Record,
	index int,
	offset uint64,
	data []byte,
	message string,
) HTTP3Record {
	record := base
	record.EventType = "http3_frame"
	record.RecordIndex = index
	record.Offset = offset
	record.Complete = false
	record.Errors = []string{message}
	record.Data = append([]byte(nil), data...)
	return record
}

func uint64Value(value uint64) *uint64 {
	return &value
}

func http3StreamTypeName(streamType uint64) string {
	switch streamType {
	case 0:
		return "control"
	case 1:
		return "push"
	case 2:
		return "qpack_encoder"
	case 3:
		return "qpack_decoder"
	default:
		return "unknown"
	}
}

func http3FrameTypeName(frameType uint64) string {
	switch frameType {
	case 0:
		return "DATA"
	case 1:
		return "HEADERS"
	case 3:
		return "CANCEL_PUSH"
	case 4:
		return "SETTINGS"
	case 5:
		return "PUSH_PROMISE"
	case 7:
		return "GOAWAY"
	case 13:
		return "MAX_PUSH_ID"
	default:
		return "UNKNOWN"
	}
}
