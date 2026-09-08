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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
)

const maxWebSocketPayloadBytes = 64 * 1024 * 1024

type WebSocketSummary struct {
	InferredProtocolSegments int     `json:"inferredProtocolSegments"`
	Reconstruction           Summary `json:"reconstruction"`
	CallsProcessed           int     `json:"callsProcessed"`
	Connections              int     `json:"connections"`
	UpgradeConnections       int     `json:"upgradeConnections"`
	Frames                   int     `json:"frames"`
	Messages                 int     `json:"messages"`
	CompleteRecords          int     `json:"completeRecords"`
	ControlFrames            int     `json:"controlFrames"`
	IncompleteRecords        int     `json:"incompleteRecords"`
	ParseErrors              int     `json:"parseErrors"`
	OpaqueBytes              int     `json:"opaqueBytes"`
}

type WebSocketMessage struct {
	ConnectionGenerationSource string   `json:"connectionGenerationSource,omitempty"`
	EventType                  string   `json:"eventType"`
	Protocol                   string   `json:"protocol"`
	CaptureLayer               string   `json:"captureLayer"`
	Transport                  string   `json:"transport"`
	ConnectionID               string   `json:"connectionId"`
	Sequence                   uint64   `json:"sequence"`
	Direction                  string   `json:"direction"`
	Pid                        uint32   `json:"pid"`
	SSLAddr                    uint64   `json:"sslAddr,omitempty"`
	BIOAddr                    uint64   `json:"bioAddr,omitempty"`
	Fd                         uint32   `json:"fd,omitempty"`
	Timestamp                  uint64   `json:"timestamp"`
	LastSeen                   uint64   `json:"lastSeen"`
	WallTime                   string   `json:"wallTime,omitempty"`
	Authority                  string   `json:"authority,omitempty"`
	Path                       string   `json:"path,omitempty"`
	Opcode                     uint8    `json:"opcode"`
	OpcodeName                 string   `json:"opcodeName"`
	FrameCount                 int      `json:"frameCount"`
	Masked                     bool     `json:"masked"`
	Compressed                 bool     `json:"compressed,omitempty"`
	PayloadEncoding            string   `json:"payloadEncoding"`
	Payload                    []byte   `json:"payload"`
	Complete                   bool     `json:"complete"`
	RawFrame                   bool     `json:"rawFrame,omitempty"`
	Errors                     []string `json:"errors,omitempty"`
}

type webSocketUpgrade struct {
	request   *http.Request
	authority string
	path      string
	writeEnd  int
	readEnd   int
}

type webSocketFrame struct {
	start      int
	end        int
	opcode     uint8
	fin        bool
	masked     bool
	compressed bool
	payload    []byte
	errors     []string
}

type webSocketMessageBuilder struct {
	record WebSocketMessage
}

// ReconstructWebSocket identifies HTTP/1.1 Upgrade handshakes in reconstructed
// TLS calls, then parses the RFC 6455 byte stream after each 101 response.
// Payloads are unmasked but otherwise byte-exact: permessage-deflate and custom
// binary application formats are labeled and retained without decompression.
func ReconstructWebSocket(
	reader io.Reader,
	writer io.Writer,
) (WebSocketSummary, error) {
	var summary WebSocketSummary
	if reader == nil {
		return summary, fmt.Errorf("WebSocket reconstruction input is nil")
	}
	if writer == nil {
		return summary, fmt.Errorf("WebSocket reconstruction output is nil")
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
	var records []WebSocketMessage
	for _, key := range keys {
		connection := connections[key]
		if connection.tooLarge {
			summary.ParseErrors++
			continue
		}
		upgrade, ok := findWebSocketUpgrade(connection)
		if !ok {
			continue
		}
		summary.UpgradeConnections++
		writeRecords, writeFrames, writeErrors, writeOpaque :=
			parseWebSocketDirection(
				connection,
				connection.write,
				upgrade.writeEnd,
				true,
				upgrade,
			)
		readRecords, readFrames, readErrors, readOpaque :=
			parseWebSocketDirection(
				connection,
				connection.read,
				upgrade.readEnd,
				false,
				upgrade,
			)
		records = append(records, writeRecords...)
		records = append(records, readRecords...)
		summary.Frames += writeFrames + readFrames
		summary.ParseErrors += writeErrors + readErrors
		summary.OpaqueBytes += writeOpaque + readOpaque
	}

	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Timestamp == records[j].Timestamp {
			if records[i].ConnectionID == records[j].ConnectionID {
				if records[i].Direction == records[j].Direction {
					return records[i].LastSeen < records[j].LastSeen
				}
				return records[i].Direction < records[j].Direction
			}
			return records[i].ConnectionID < records[j].ConnectionID
		}
		return records[i].Timestamp < records[j].Timestamp
	})
	sequences := make(map[string]uint64)
	encoder := json.NewEncoder(writer)
	for index := range records {
		record := &records[index]
		sequences[record.ConnectionID]++
		record.Sequence = sequences[record.ConnectionID]
		if record.EventType == "websocket_control" {
			summary.ControlFrames++
		} else {
			summary.Messages++
		}
		if record.Complete {
			summary.CompleteRecords++
		} else {
			summary.IncompleteRecords++
		}
		if err := encoder.Encode(record); err != nil {
			return summary, fmt.Errorf("write WebSocket record: %w", err)
		}
	}
	return summary, nil
}

func findWebSocketUpgrade(
	connection *http1ConnectionCapture,
) (webSocketUpgrade, bool) {
	request, writeEnd, ok := findWebSocketRequest(connection.write.data)
	if !ok {
		return webSocketUpgrade{}, false
	}
	readEnd, ok := findWebSocketResponse(connection.read.data, request)
	if !ok {
		return webSocketUpgrade{}, false
	}
	return webSocketUpgrade{
		request:   request,
		authority: request.Host,
		path:      request.RequestURI,
		writeEnd:  writeEnd,
		readEnd:   readEnd,
	}, true
}

func findWebSocketRequest(data []byte) (*http.Request, int, bool) {
	source := bytes.NewReader(data)
	reader := bufio.NewReader(source)
	for remainingHTTP1Bytes(source, reader) != 0 {
		request, err := http.ReadRequest(reader)
		if err != nil || !isHTTP1Version(request.Proto) {
			return nil, 0, false
		}
		if request.Body != nil {
			_, bodyErr := readHTTP1Body(request.Body)
			_ = request.Body.Close()
			if bodyErr != nil {
				return nil, 0, false
			}
		}
		end := consumedHTTP1Bytes(len(data), source, reader)
		if isWebSocketUpgradeHeader(request.Header) {
			return request, end, true
		}
	}
	return nil, 0, false
}

func findWebSocketResponse(
	data []byte,
	request *http.Request,
) (int, bool) {
	source := bytes.NewReader(data)
	reader := bufio.NewReader(source)
	for remainingHTTP1Bytes(source, reader) != 0 {
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			return 0, false
		}
		end := consumedHTTP1Bytes(len(data), source, reader)
		isUpgrade := response.StatusCode == http.StatusSwitchingProtocols &&
			isWebSocketUpgradeHeader(response.Header)
		if isUpgrade {
			_ = response.Body.Close()
			return end, true
		}
		if response.Body != nil {
			_, bodyErr := readHTTP1Body(response.Body)
			_ = response.Body.Close()
			if bodyErr != nil {
				return 0, false
			}
		}
	}
	return 0, false
}

func isWebSocketUpgradeHeader(header http.Header) bool {
	if !strings.EqualFold(strings.TrimSpace(header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, token := range strings.Split(header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

func parseWebSocketDirection(
	connection *http1ConnectionCapture,
	capture http1DirectionCapture,
	start int,
	client bool,
	upgrade webSocketUpgrade,
) ([]WebSocketMessage, int, int, int) {
	if start >= len(capture.data) {
		return nil, 0, 0, 0
	}
	direction := "server_to_client"
	if client {
		direction = "client_to_server"
	}
	var records []WebSocketMessage
	var fragmented *webSocketMessageBuilder
	frames := 0
	parseErrors := 0
	opaqueBytes := 0
	offset := start
	for offset < len(capture.data) {
		frame, next, err := parseWebSocketFrame(capture.data, offset, client)
		if err != nil {
			parseErrors++
			raw := append([]byte(nil), capture.data[offset:]...)
			first, last := capture.timeRange(offset, len(capture.data))
			records = append(records, newWebSocketRecord(
				connection,
				upgrade,
				direction,
				first,
				last,
				0,
				"opaque",
				1,
				false,
				false,
				raw,
				false,
				true,
				[]string{err.Error()},
			))
			opaqueBytes += len(raw)
			break
		}
		frames++
		frameFirst, frameLast := capture.timeRange(frame.start, frame.end)
		if len(frame.errors) != 0 {
			parseErrors += len(frame.errors)
		}
		switch frame.opcode {
		case 0x0:
			if fragmented == nil {
				records = append(records, newWebSocketRecord(
					connection,
					upgrade,
					direction,
					frameFirst,
					frameLast,
					frame.opcode,
					webSocketOpcodeName(frame.opcode),
					1,
					frame.masked,
					frame.compressed,
					frame.payload,
					false,
					false,
					append(
						[]string{"continuation frame without an open message"},
						frame.errors...,
					),
				))
				parseErrors++
			} else {
				builder := fragmented
				builder.record.FrameCount++
				builder.record.LastSeen = frameLast
				builder.record.Payload = append(
					builder.record.Payload,
					frame.payload...,
				)
				builder.record.Errors = append(
					builder.record.Errors,
					frame.errors...,
				)
				if frame.fin {
					builder.record.Complete =
						len(builder.record.Errors) == 0
					records = append(records, builder.record)
					fragmented = nil
				}
			}
		case 0x1, 0x2:
			if fragmented != nil {
				fragmented.record.Errors = append(
					fragmented.record.Errors,
					"new data frame started before fragmented message ended",
				)
				fragmented.record.Complete = false
				records = append(records, fragmented.record)
				parseErrors++
				fragmented = nil
			}
			record := newWebSocketRecord(
				connection,
				upgrade,
				direction,
				frameFirst,
				frameLast,
				frame.opcode,
				webSocketOpcodeName(frame.opcode),
				1,
				frame.masked,
				frame.compressed,
				frame.payload,
				frame.fin && len(frame.errors) == 0,
				false,
				frame.errors,
			)
			if frame.fin {
				records = append(records, record)
			} else {
				fragmented = &webSocketMessageBuilder{record: record}
			}
		case 0x8, 0x9, 0xa:
			records = append(records, newWebSocketRecord(
				connection,
				upgrade,
				direction,
				frameFirst,
				frameLast,
				frame.opcode,
				webSocketOpcodeName(frame.opcode),
				1,
				frame.masked,
				false,
				frame.payload,
				len(frame.errors) == 0,
				false,
				frame.errors,
			))
		}
		offset = next
	}
	if fragmented != nil {
		fragmented.record.Errors = append(
			fragmented.record.Errors,
			"capture ended before fragmented WebSocket message FIN",
		)
		fragmented.record.Complete = false
		records = append(records, fragmented.record)
		parseErrors++
	}
	return records, frames, parseErrors, opaqueBytes
}

func parseWebSocketFrame(
	data []byte,
	offset int,
	expectMasked bool,
) (webSocketFrame, int, error) {
	frame := webSocketFrame{start: offset}
	if len(data)-offset < 2 {
		return frame, offset, fmt.Errorf(
			"incomplete WebSocket header: %d byte(s) remain",
			len(data)-offset,
		)
	}
	first := data[offset]
	second := data[offset+1]
	frame.fin = first&0x80 != 0
	frame.compressed = first&0x40 != 0
	frame.opcode = first & 0x0f
	frame.masked = second&0x80 != 0
	if first&0x30 != 0 {
		return frame, offset, fmt.Errorf("unsupported WebSocket RSV2/RSV3 bits")
	}
	if !supportedWebSocketOpcode(frame.opcode) {
		return frame, offset, fmt.Errorf(
			"unsupported WebSocket opcode 0x%x",
			frame.opcode,
		)
	}
	if frame.masked != expectMasked {
		frame.errors = append(
			frame.errors,
			fmt.Sprintf(
				"unexpected WebSocket mask bit: got %t want %t",
				frame.masked,
				expectMasked,
			),
		)
	}

	headerLength := 2
	payloadLength := uint64(second & 0x7f)
	switch payloadLength {
	case 126:
		if len(data)-offset < headerLength+2 {
			return frame, offset, fmt.Errorf(
				"incomplete WebSocket 16-bit payload length",
			)
		}
		payloadLength = uint64(binary.BigEndian.Uint16(
			data[offset+headerLength : offset+headerLength+2],
		))
		headerLength += 2
	case 127:
		if len(data)-offset < headerLength+8 {
			return frame, offset, fmt.Errorf(
				"incomplete WebSocket 64-bit payload length",
			)
		}
		payloadLength = binary.BigEndian.Uint64(
			data[offset+headerLength : offset+headerLength+8],
		)
		headerLength += 8
		if payloadLength&(uint64(1)<<63) != 0 {
			return frame, offset, fmt.Errorf(
				"invalid WebSocket 64-bit payload length",
			)
		}
	}
	if payloadLength > maxWebSocketPayloadBytes ||
		payloadLength > math.MaxInt {
		return frame, offset, fmt.Errorf(
			"WebSocket payload length %d exceeds safety limit",
			payloadLength,
		)
	}
	if frame.opcode >= 0x8 {
		if !frame.fin {
			frame.errors = append(
				frame.errors,
				"fragmented WebSocket control frame",
			)
		}
		if payloadLength > 125 {
			return frame, offset, fmt.Errorf(
				"WebSocket control payload exceeds 125 bytes",
			)
		}
		if frame.compressed {
			frame.errors = append(
				frame.errors,
				"compressed WebSocket control frame",
			)
		}
	} else if frame.opcode == 0x0 && frame.compressed {
		frame.errors = append(
			frame.errors,
			"RSV1 set on WebSocket continuation frame",
		)
	}

	var mask [4]byte
	if frame.masked {
		if len(data)-offset < headerLength+4 {
			return frame, offset, fmt.Errorf("incomplete WebSocket masking key")
		}
		copy(mask[:], data[offset+headerLength:offset+headerLength+4])
		headerLength += 4
	}
	end := offset + headerLength + int(payloadLength)
	if end > len(data) {
		return frame, offset, fmt.Errorf(
			"incomplete WebSocket payload: have %d want %d bytes",
			len(data)-(offset+headerLength),
			payloadLength,
		)
	}
	frame.payload = append(
		[]byte(nil),
		data[offset+headerLength:end]...,
	)
	if frame.masked {
		for index := range frame.payload {
			frame.payload[index] ^= mask[index%len(mask)]
		}
	}
	frame.end = end
	return frame, end, nil
}

func newWebSocketRecord(
	connection *http1ConnectionCapture,
	upgrade webSocketUpgrade,
	direction string,
	timestamp uint64,
	lastSeen uint64,
	opcode uint8,
	opcodeName string,
	frameCount int,
	masked bool,
	compressed bool,
	payload []byte,
	complete bool,
	raw bool,
	errors []string,
) WebSocketMessage {
	eventType := "websocket_message"
	if opcode >= 0x8 && opcode <= 0xa {
		eventType = "websocket_control"
	}
	if raw {
		eventType = "websocket_opaque"
	}
	return WebSocketMessage{
		EventType:                  eventType,
		Protocol:                   "websocket",
		CaptureLayer:               captureLayerTransport,
		Transport:                  "tls",
		ConnectionID:               connection.id,
		ConnectionGenerationSource: connection.generationSource,
		Direction:                  direction,
		Pid:                        connection.pid,
		SSLAddr:                    connection.sslAddr,
		BIOAddr:                    connection.bioAddr,
		Fd:                         connection.fd,
		Timestamp:                  timestamp,
		LastSeen:                   lastSeen,
		WallTime: wallTimeAt(
			connection.wallTime,
			connection.wallStamp,
			timestamp,
		),
		Authority:       upgrade.authority,
		Path:            upgrade.path,
		Opcode:          opcode,
		OpcodeName:      opcodeName,
		FrameCount:      frameCount,
		Masked:          masked,
		Compressed:      compressed,
		PayloadEncoding: "base64",
		Payload:         append([]byte(nil), payload...),
		Complete:        complete,
		RawFrame:        raw,
		Errors:          append([]string(nil), errors...),
	}
}

func supportedWebSocketOpcode(opcode uint8) bool {
	switch opcode {
	case 0x0, 0x1, 0x2, 0x8, 0x9, 0xa:
		return true
	default:
		return false
	}
}

func webSocketOpcodeName(opcode uint8) string {
	switch opcode {
	case 0x0:
		return "continuation"
	case 0x1:
		return "text"
	case 0x2:
		return "binary"
	case 0x8:
		return "close"
	case 0x9:
		return "ping"
	case 0xa:
		return "pong"
	default:
		return fmt.Sprintf("0x%x", opcode)
	}
}
