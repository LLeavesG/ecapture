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
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const (
	http2FrameHeaderSize = 9
	http2MaxFrameSize    = 1<<24 - 1

	http2FrameData         = 0
	http2FrameHeaders      = 1
	http2FramePriority     = 2
	http2FrameRSTStream    = 3
	http2FrameSettings     = 4
	http2FramePushPromise  = 5
	http2FramePing         = 6
	http2FrameGoAway       = 7
	http2FrameWindowUpdate = 8
	http2FrameContinuation = 9

	http2FlagEndStream  = 0x1
	http2FlagAck        = 0x1
	http2FlagEndHeaders = 0x4
	http2FlagPadded     = 0x8
	http2FlagPriority   = 0x20
)

var http2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

type HTTP2Summary struct {
	Reconstruction       Summary `json:"reconstruction"`
	CallsProcessed       int     `json:"callsProcessed"`
	Connections          int     `json:"connections"`
	Frames               int     `json:"frames"`
	Transactions         int     `json:"transactions"`
	CompleteTransactions int     `json:"completeTransactions"`
	OpenTransactions     int     `json:"openTransactions"`
	ResetTransactions    int     `json:"resetTransactions"`
	OrphanTransactions   int     `json:"orphanTransactions"`
	ErrorTransactions    int     `json:"errorTransactions"`
	HeaderDecodeError    int     `json:"headerDecodeErrors"`
	Resynchronized       int     `json:"resynchronizedBytes"`
}

type HTTP2Header struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Sensitive bool   `json:"sensitive,omitempty"`
}

type HTTP2Message struct {
	Headers      []HTTP2Header `json:"headers,omitempty"`
	Body         []byte        `json:"body,omitempty"`
	BodyEncoding string        `json:"bodyEncoding,omitempty"`
	HTTPBodyPresentation
	HeadersDecoded bool `json:"headersDecoded"`
	EndStream      bool `json:"endStream"`
}

type HTTP2Transaction struct {
	EventType    string       `json:"eventType"`
	Protocol     string       `json:"protocol"`
	CaptureLayer string       `json:"captureLayer"`
	Transport    string       `json:"transport"`
	ConnectionID string       `json:"connectionId"`
	ContextID    uint64       `json:"contextId,omitempty"`
	StreamID     uint32       `json:"streamId"`
	Pid          uint32       `json:"pid"`
	SSLAddr      uint64       `json:"sslAddr,omitempty"`
	BIOAddr      uint64       `json:"bioAddr,omitempty"`
	Fd           uint32       `json:"fd,omitempty"`
	Timestamp    uint64       `json:"timestamp"`
	LastSeen     uint64       `json:"lastSeen"`
	WallTime     string       `json:"wallTime,omitempty"`
	Method       string       `json:"method,omitempty"`
	Scheme       string       `json:"scheme,omitempty"`
	Authority    string       `json:"authority,omitempty"`
	Path         string       `json:"path,omitempty"`
	Status       string       `json:"status,omitempty"`
	Request      HTTP2Message `json:"request"`
	Response     HTTP2Message `json:"response"`
	Complete     bool         `json:"complete"`
	State        string       `json:"state"`
	Errors       []string     `json:"errors,omitempty"`
}

type http2Frame struct {
	length    int
	frameType byte
	flags     byte
	streamID  uint32
	payload   []byte
}

type http2StreamState struct {
	transaction HTTP2Transaction
	seen        bool
	reset       bool
}

type http2ConnectionState struct {
	id        string
	protocol  string
	transport string
	pid       uint32
	contextID uint64
	sslAddr   uint64
	bioAddr   uint64
	fd        uint32
	wallTime  string
	wallStamp uint64
	streams   map[uint32]*http2StreamState
	write     *http2DirectionState
	read      *http2DirectionState
	summary   *HTTP2Summary
}

type http2DirectionState struct {
	connection       *http2ConnectionState
	write            bool
	buffer           []byte
	synchronized     bool
	prefaceProcessed bool
	decoder          *hpack.Decoder
	pendingStream    uint32
	pendingTarget    uint32
	pendingBlock     []byte
	pendingEndStream bool
	pendingRequest   bool
}

func ReconstructHTTP2(
	reader io.Reader,
	writer io.Writer,
) (HTTP2Summary, error) {
	var summary HTTP2Summary
	if reader == nil {
		return summary, fmt.Errorf("HTTP/2 reconstruction input is nil")
	}
	if writer == nil {
		return summary, fmt.Errorf("HTTP/2 reconstruction output is nil")
	}

	callSummary, calls, err := collectTLSCalls(reader)
	if err != nil {
		return summary, err
	}
	summary.Reconstruction = callSummary

	connections := make(map[string]*http2ConnectionState)
	activeConnections := make(map[string]*http2ConnectionState)
	connectionGenerations := make(map[string]int)
	for _, call := range calls {
		baseKey := http2ConnectionKey(call)
		connection := activeConnections[baseKey]
		if connection == nil || startsNewHTTP2Connection(call) {
			connectionGenerations[baseKey]++
			key := http2GenerationKey(
				baseKey,
				connectionGenerations[baseKey],
			)
			connection = newHTTP2Connection(key, call, &summary)
			activeConnections[baseKey] = connection
			connections[key] = connection
		}
		connection.feed(call)
		summary.CallsProcessed++
	}
	summary.Connections = len(connections)

	var transactions []HTTP2Transaction
	for _, connection := range connections {
		for _, state := range connection.streams {
			if !state.seen {
				continue
			}
			transaction := state.transaction
			transaction.Complete = transaction.Request.EndStream &&
				transaction.Response.EndStream &&
				transaction.Request.HeadersDecoded &&
				transaction.Response.HeadersDecoded &&
				len(transaction.Errors) == 0
			transaction.State = classifyTransactionState(
				transaction.Complete,
				http2MessageObserved(transaction.Request),
				http2MessageObserved(transaction.Response),
				state.reset,
				len(transaction.Errors) != 0,
			)
			switch transaction.State {
			case transactionStateComplete:
				connection.summary.CompleteTransactions++
			case transactionStateOpen:
				connection.summary.OpenTransactions++
			case transactionStateReset:
				connection.summary.ResetTransactions++
			case transactionStateOrphan:
				connection.summary.OrphanTransactions++
			default:
				connection.summary.ErrorTransactions++
			}
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
			transactions = append(transactions, transaction)
		}
	}
	sort.Slice(transactions, func(i, j int) bool {
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
			return summary, fmt.Errorf("write HTTP/2 transaction: %w", err)
		}
		summary.Transactions++
	}
	return summary, nil
}

func newHTTP2Connection(
	key string,
	call Call,
	summary *HTTP2Summary,
) *http2ConnectionState {
	return newHeaderConnection(key, call, summary, "http2", "tls")
}

func newHeaderConnection(
	key string,
	call Call,
	summary *HTTP2Summary,
	protocol string,
	transport string,
) *http2ConnectionState {
	connection := &http2ConnectionState{
		id:        key,
		protocol:  protocol,
		transport: transport,
		pid:       call.Pid,
		contextID: call.ContextID,
		sslAddr:   call.SSLAddr,
		bioAddr:   call.BIOAddr,
		fd:        call.Fd,
		wallTime:  call.WallTime,
		wallStamp: call.Timestamp,
		streams:   make(map[uint32]*http2StreamState),
		summary:   summary,
	}
	connection.write = newHTTP2Direction(connection, true)
	connection.read = newHTTP2Direction(connection, false)
	return connection
}

func newHTTP2Direction(
	connection *http2ConnectionState,
	write bool,
) *http2DirectionState {
	state := &http2DirectionState{
		connection: connection,
		write:      write,
	}
	state.resetDecoder()
	return state
}

func (state *http2DirectionState) resetDecoder() {
	state.decoder = hpack.NewDecoder(4096, nil)
	state.decoder.SetAllowedMaxDynamicTableSize(1 << 20)
	state.decoder.SetMaxStringLength(16 * 1024 * 1024)
}

func http2ConnectionKey(call Call) string {
	switch {
	case call.SSLAddr != 0:
		return fmt.Sprintf("tls:%d:ssl:%x", call.Pid, call.SSLAddr)
	case call.BIOAddr != 0:
		return fmt.Sprintf("tls:%d:bio:%x", call.Pid, call.BIOAddr)
	default:
		return fmt.Sprintf("tls:%d:fd:%d", call.Pid, call.Fd)
	}
}

func http2GenerationKey(baseKey string, generation int) string {
	if generation <= 1 {
		return baseKey
	}
	return fmt.Sprintf("%s:generation:%d", baseKey, generation)
}

func startsNewHTTP2Connection(call Call) bool {
	if !strings.EqualFold(call.Direction, "WRITE") || len(call.Data) == 0 {
		return false
	}
	return bytes.HasPrefix(call.Data, http2ClientPreface)
}

func (connection *http2ConnectionState) feed(call Call) {
	state := connection.read
	if strings.EqualFold(call.Direction, "WRITE") {
		state = connection.write
	}
	state.feed(call.Data, call.Timestamp)
}

func (state *http2DirectionState) feed(data []byte, timestamp uint64) {
	if len(data) == 0 {
		return
	}
	state.buffer = append(state.buffer, data...)
	if state.write && !state.prefaceProcessed {
		if len(state.buffer) < len(http2ClientPreface) &&
			bytes.HasPrefix(http2ClientPreface, state.buffer) {
			return
		}
		if len(state.buffer) >= len(http2ClientPreface) &&
			bytes.HasPrefix(state.buffer, http2ClientPreface) {
			state.buffer = state.buffer[len(http2ClientPreface):]
			state.synchronized = true
		}
		state.prefaceProcessed = true
	}

	for {
		if len(state.buffer) < http2FrameHeaderSize {
			return
		}
		frame, complete, plausible := parseHTTP2Frame(state.buffer)
		if !plausible {
			state.synchronized = false
			// SSL_read/SSL_write calls are our strongest available boundary.
			// When capture starts in the middle of a frame, scanning arbitrary
			// payload bytes for a nine-byte pattern creates false DATA frames
			// and corrupts bodies. Drop this unsynchronized call remainder and
			// retry at the next transport call boundary.
			state.connection.summary.Resynchronized += len(state.buffer)
			state.buffer = state.buffer[:0]
			return
		}
		if !complete {
			return
		}
		if !state.synchronized {
			state.synchronized = true
		}
		state.buffer = state.buffer[http2FrameHeaderSize+frame.length:]
		state.handleFrame(frame, timestamp)
		state.connection.summary.Frames++
	}
}

func parseHTTP2Frame(data []byte) (http2Frame, bool, bool) {
	if len(data) < http2FrameHeaderSize {
		return http2Frame{}, false, true
	}
	length := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	frame := http2Frame{
		length:    length,
		frameType: data[3],
		flags:     data[4],
		streamID: uint32(data[5]&0x7f)<<24 |
			uint32(data[6])<<16 |
			uint32(data[7])<<8 |
			uint32(data[8]),
	}
	if length > http2MaxFrameSize || !plausibleHTTP2FrameHeader(frame) {
		return frame, false, false
	}
	if len(data) < http2FrameHeaderSize+length {
		return frame, false, true
	}
	frame.payload = data[http2FrameHeaderSize : http2FrameHeaderSize+length]
	return frame, true, true
}

func plausibleHTTP2FrameHeader(frame http2Frame) bool {
	if frame.frameType > http2FrameContinuation {
		return false
	}
	switch frame.frameType {
	case http2FrameSettings, http2FramePing, http2FrameGoAway:
		return frame.streamID == 0
	case http2FrameData, http2FrameHeaders, http2FramePriority,
		http2FrameRSTStream, http2FramePushPromise, http2FrameContinuation:
		return frame.streamID != 0
	default:
		return true
	}
}

func (state *http2DirectionState) handleFrame(
	frame http2Frame,
	timestamp uint64,
) {
	switch frame.frameType {
	case http2FrameHeaders:
		state.handleHeaders(frame, timestamp)
	case http2FramePushPromise:
		state.handlePushPromise(frame, timestamp)
	case http2FrameContinuation:
		state.handleContinuation(frame, timestamp)
	case http2FrameData:
		state.handleData(frame, timestamp)
	case http2FrameRSTStream:
		stream := state.stream(frame.streamID, timestamp)
		state.message(stream).EndStream = true
		stream.reset = true
	case http2FrameSettings:
		if frame.flags&http2FlagAck == 0 {
			state.applySettings(frame.payload)
		}
	}
}

func (state *http2DirectionState) handleHeaders(
	frame http2Frame,
	timestamp uint64,
) {
	payload, ok := stripHTTP2Padding(frame.payload, frame.flags)
	if !ok {
		state.addStreamError(frame.streamID, timestamp, "invalid padded HEADERS frame")
		return
	}
	if frame.flags&http2FlagPriority != 0 {
		if len(payload) < 5 {
			state.addStreamError(frame.streamID, timestamp, "short priority HEADERS frame")
			return
		}
		payload = payload[5:]
	}
	if state.pendingStream != 0 {
		state.addStreamError(
			state.pendingStream,
			timestamp,
			"header block interrupted before END_HEADERS",
		)
		state.clearPendingHeaders()
	}
	if frame.flags&http2FlagEndHeaders != 0 {
		state.decodeHeaders(frame.streamID, payload, timestamp)
	} else {
		state.pendingStream = frame.streamID
		state.pendingTarget = frame.streamID
		state.pendingBlock = append(state.pendingBlock[:0], payload...)
		state.pendingEndStream = frame.flags&http2FlagEndStream != 0
	}
	if frame.flags&http2FlagEndStream != 0 {
		stream := state.stream(frame.streamID, timestamp)
		state.message(stream).EndStream = true
	}
}

func (state *http2DirectionState) handlePushPromise(
	frame http2Frame,
	timestamp uint64,
) {
	payload, ok := stripHTTP2Padding(frame.payload, frame.flags)
	if !ok || len(payload) < 4 {
		state.addStreamError(
			frame.streamID, timestamp, "invalid PUSH_PROMISE frame",
		)
		return
	}
	promisedStreamID := uint32(payload[0]&0x7f)<<24 |
		uint32(payload[1])<<16 |
		uint32(payload[2])<<8 |
		uint32(payload[3])
	if promisedStreamID == 0 {
		state.addStreamError(
			frame.streamID, timestamp, "zero PUSH_PROMISE stream ID",
		)
		return
	}
	block := payload[4:]
	if state.pendingStream != 0 {
		state.addStreamError(
			state.pendingTarget,
			timestamp,
			"header block interrupted before END_HEADERS",
		)
		state.clearPendingHeaders()
	}
	if frame.flags&http2FlagEndHeaders != 0 {
		state.decodeHeadersInto(promisedStreamID, block, timestamp, true)
		stream := state.stream(promisedStreamID, timestamp)
		stream.transaction.Request.EndStream = true
		return
	}
	state.pendingStream = frame.streamID
	state.pendingTarget = promisedStreamID
	state.pendingBlock = append(state.pendingBlock[:0], block...)
	state.pendingEndStream = true
	state.pendingRequest = true
}

func (state *http2DirectionState) handleContinuation(
	frame http2Frame,
	timestamp uint64,
) {
	if state.pendingStream == 0 || state.pendingStream != frame.streamID {
		state.addStreamError(frame.streamID, timestamp, "orphan CONTINUATION frame")
		return
	}
	state.pendingBlock = append(state.pendingBlock, frame.payload...)
	if frame.flags&http2FlagEndHeaders == 0 {
		return
	}
	targetStream := state.pendingTarget
	if targetStream == 0 {
		targetStream = state.pendingStream
	}
	endStream := state.pendingEndStream
	requestMessage := state.pendingRequest
	block := append([]byte(nil), state.pendingBlock...)
	state.clearPendingHeaders()
	state.decodeHeadersInto(targetStream, block, timestamp, requestMessage)
	if endStream {
		stream := state.stream(targetStream, timestamp)
		message := state.message(stream)
		if requestMessage {
			message = &stream.transaction.Request
		}
		message.EndStream = true
	}
}

func (state *http2DirectionState) handleData(
	frame http2Frame,
	timestamp uint64,
) {
	payload, ok := stripHTTP2Padding(frame.payload, frame.flags)
	if !ok {
		state.addStreamError(frame.streamID, timestamp, "invalid padded DATA frame")
		return
	}
	stream := state.stream(frame.streamID, timestamp)
	message := state.message(stream)
	message.Body = append(message.Body, payload...)
	if len(message.Body) != 0 {
		message.BodyEncoding = "base64"
	}
	if frame.flags&http2FlagEndStream != 0 {
		message.EndStream = true
	}
}

func stripHTTP2Padding(payload []byte, flags byte) ([]byte, bool) {
	if flags&http2FlagPadded == 0 {
		return payload, true
	}
	if len(payload) == 0 {
		return nil, false
	}
	padding := int(payload[0])
	payload = payload[1:]
	if padding > len(payload) {
		return nil, false
	}
	return payload[:len(payload)-padding], true
}

func (state *http2DirectionState) decodeHeaders(
	streamID uint32,
	block []byte,
	timestamp uint64,
) {
	state.decodeHeadersInto(streamID, block, timestamp, false)
}

func (state *http2DirectionState) decodeHeadersInto(
	streamID uint32,
	block []byte,
	timestamp uint64,
	requestMessage bool,
) {
	var fields []hpack.HeaderField
	state.decoder.SetEmitFunc(func(field hpack.HeaderField) {
		fields = append(fields, field)
	})
	_, writeErr := state.decoder.Write(block)
	closeErr := state.decoder.Close()
	if writeErr != nil || closeErr != nil {
		state.connection.summary.HeaderDecodeError++
		err := writeErr
		if err == nil {
			err = closeErr
		}
		state.addStreamError(
			streamID,
			timestamp,
			"HPACK decode failed: "+err.Error(),
		)
		state.resetDecoder()
		return
	}

	stream := state.stream(streamID, timestamp)
	message := state.message(stream)
	if requestMessage {
		message = &stream.transaction.Request
	}
	message.HeadersDecoded = true
	for _, field := range fields {
		message.Headers = append(message.Headers, HTTP2Header{
			Name:      field.Name,
			Value:     field.Value,
			Sensitive: field.Sensitive,
		})
		switch field.Name {
		case ":method":
			stream.transaction.Method = field.Value
		case ":scheme":
			stream.transaction.Scheme = field.Value
		case ":authority":
			stream.transaction.Authority = field.Value
		case ":path":
			stream.transaction.Path = field.Value
		case ":status":
			stream.transaction.Status = field.Value
		}
	}
}

func (state *http2DirectionState) applySettings(payload []byte) {
	if len(payload)%6 != 0 {
		return
	}
	for len(payload) >= 6 {
		id := uint16(payload[0])<<8 | uint16(payload[1])
		value := uint32(payload[2])<<24 |
			uint32(payload[3])<<16 |
			uint32(payload[4])<<8 |
			uint32(payload[5])
		payload = payload[6:]
		if id != 1 {
			continue
		}
		// SETTINGS_HEADER_TABLE_SIZE describes what this endpoint permits the
		// peer to use. Apply it to the decoder for the opposite direction.
		peer := state.connection.read
		if !state.write {
			peer = state.connection.write
		}
		peer.decoder.SetAllowedMaxDynamicTableSize(value)
	}
}

func (state *http2DirectionState) clearPendingHeaders() {
	state.pendingStream = 0
	state.pendingTarget = 0
	state.pendingBlock = state.pendingBlock[:0]
	state.pendingEndStream = false
	state.pendingRequest = false
}

func (state *http2DirectionState) stream(
	streamID uint32,
	timestamp uint64,
) *http2StreamState {
	stream := state.connection.streams[streamID]
	if stream == nil {
		stream = &http2StreamState{
			transaction: HTTP2Transaction{
				EventType:    "http_transaction",
				Protocol:     state.connection.protocol,
				CaptureLayer: captureLayerTransport,
				Transport:    state.connection.transport,
				ConnectionID: state.connection.id,
				ContextID:    state.connection.contextID,
				StreamID:     streamID,
				Pid:          state.connection.pid,
				SSLAddr:      state.connection.sslAddr,
				BIOAddr:      state.connection.bioAddr,
				Fd:           state.connection.fd,
				Timestamp:    timestamp,
				WallTime: wallTimeAt(
					state.connection.wallTime,
					state.connection.wallStamp,
					timestamp,
				),
			},
		}
		state.connection.streams[streamID] = stream
	}
	stream.seen = true
	if stream.transaction.Timestamp == 0 ||
		timestamp < stream.transaction.Timestamp {
		stream.transaction.Timestamp = timestamp
		stream.transaction.WallTime = wallTimeAt(
			state.connection.wallTime,
			state.connection.wallStamp,
			timestamp,
		)
	}
	if timestamp > stream.transaction.LastSeen {
		stream.transaction.LastSeen = timestamp
	}
	return stream
}

func (state *http2DirectionState) message(
	stream *http2StreamState,
) *HTTP2Message {
	if state.write {
		return &stream.transaction.Request
	}
	return &stream.transaction.Response
}

func (state *http2DirectionState) addStreamError(
	streamID uint32,
	timestamp uint64,
	message string,
) {
	stream := state.stream(streamID, timestamp)
	if len(stream.transaction.Errors) < 16 {
		stream.transaction.Errors = append(stream.transaction.Errors, message)
	}
}
