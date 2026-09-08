package reconstruction

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// These are protocol segments, not verified socket lifetimes. Some capture
// formats expose only an SSL address that the allocator can reuse. Split only
// at a call boundary after completed framed traffic and a bidirectional new
// handshake; never search application payloads for protocol marker text.
func collectHTTP1ProtocolSegments(calls []Call) (map[string]*http1ConnectionCapture, int) {
	grouped := make(map[string][]Call)
	for _, call := range calls {
		key := http2ConnectionKey(call)
		grouped[key] = append(grouped[key], call)
	}
	connections := make(map[string]*http1ConnectionCapture)
	inferred := 0
	for baseKey, group := range grouped {
		var connection *http1ConnectionCapture
		segmentStart := 0
		segmentOrdinal := 1
		for index, call := range group {
			split := index > segmentStart && provenProtocolBoundary(group[segmentStart:index], group[index:])
			key := baseKey
			if split {
				connection.generationSource = "observed-protocol-boundary"
				segmentStart = index
				segmentOrdinal++
				connection = nil
				inferred++
			}
			if segmentStart > 0 {
				key = fmt.Sprintf("%s:protocol-segment:%d", baseKey, segmentOrdinal)
			}
			if connection == nil {
				connection = &http1ConnectionCapture{id: key, pid: call.Pid, sslAddr: call.SSLAddr, bioAddr: call.BIOAddr, fd: call.Fd, wallTime: call.WallTime, wallStamp: call.Timestamp}
				if segmentStart > 0 {
					connection.generationSource = "observed-protocol-boundary"
				}
				connections[key] = connection
			}
			direction := &connection.read
			if strings.EqualFold(call.Direction, "WRITE") {
				direction = &connection.write
			}
			if !direction.append(call) {
				connection.tooLarge = true
			}
		}
	}
	return connections, inferred
}

func provenProtocolBoundary(previous, next []Call) bool {
	if len(next) == 0 || !strings.EqualFold(next[0].Direction, "WRITE") {
		return false
	}
	newHTTP2 := startsNewHTTP2Connection(next[0]) && hasServerSettings(next)
	newWebSocket := hasConfirmedWebSocketHandshake(next)
	if !newHTTP2 && !newWebSocket {
		return false
	}
	if completeHTTP2Segment(previous) {
		return true
	}
	return closedWebSocketSegment(previous)
}

func hasServerSettings(calls []Call) bool {
	for _, call := range calls {
		if strings.EqualFold(call.Direction, "READ") {
			frame, complete, plausible := parseHTTP2Frame(call.Data)
			return complete && plausible && frame.frameType == http2FrameSettings && frame.streamID == 0 && frame.flags == 0
		}
	}
	return false
}

func hasConfirmedWebSocketHandshake(calls []Call) bool {
	if len(calls) == 0 || !looksLikeHTTP1Request(calls[0].Data) {
		return false
	}
	request, _, ok := findWebSocketRequest(calls[0].Data)
	if !ok || request.Method != http.MethodGet {
		return false
	}
	key := request.Header.Get("Sec-WebSocket-Key")
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 {
		return false
	}
	for _, call := range calls[1:] {
		if !strings.EqualFold(call.Direction, "READ") {
			continue
		}
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(call.Data)), request)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		return response.StatusCode == http.StatusSwitchingProtocols && isWebSocketUpgradeHeader(response.Header) && response.Header.Get("Sec-WebSocket-Accept") == base64.StdEncoding.EncodeToString(digest[:])
	}
	return false
}

func completeHTTP2Segment(calls []Call) bool {
	if len(calls) == 0 || !startsNewHTTP2Connection(calls[0]) {
		return false
	}
	var summary HTTP2Summary
	connection := newHTTP2Connection("boundary-check", calls[0], &summary)
	for _, call := range calls {
		connection.feed(call)
	}
	if summary.Resynchronized != 0 || summary.HeaderDecodeError != 0 || len(connection.streams) == 0 {
		return false
	}
	for _, direction := range []*http2DirectionState{connection.write, connection.read} {
		if len(direction.buffer) != 0 || direction.pendingStream != 0 || len(direction.pendingBlock) != 0 {
			return false
		}
	}
	for _, stream := range connection.streams {
		tx := stream.transaction
		if !stream.seen || !tx.Request.EndStream || !tx.Response.EndStream || !tx.Request.HeadersDecoded || !tx.Response.HeadersDecoded || len(tx.Errors) != 0 {
			return false
		}
	}
	return true
}

func closedWebSocketSegment(calls []Call) bool {
	if !hasConfirmedWebSocketHandshake(calls) {
		return false
	}
	connection := &http1ConnectionCapture{id: "boundary-check"}
	for _, call := range calls {
		direction := &connection.read
		if strings.EqualFold(call.Direction, "WRITE") {
			direction = &connection.write
		}
		if !direction.append(call) {
			return false
		}
	}
	upgrade, ok := findWebSocketUpgrade(connection)
	if !ok {
		return false
	}
	for _, direction := range []struct {
		capture http1DirectionCapture
		start   int
		client  bool
	}{{connection.write, upgrade.writeEnd, true}, {connection.read, upgrade.readEnd, false}} {
		records, _, errors, opaque := parseWebSocketDirection(connection, direction.capture, direction.start, direction.client, upgrade)
		if errors != 0 || opaque != 0 || len(records) == 0 {
			return false
		}
		for _, record := range records {
			if !record.Complete {
				return false
			}
		}
		last := records[len(records)-1]
		if last.EventType != "websocket_control" || last.Opcode != 8 {
			return false
		}
	}
	return true
}

// http2ProtocolSegmentKeys applies the same bidirectional boundary proof before
// HTTP/2 state consumes intervening protocols. A short WebSocket close otherwise
// remains buffered as a partial HTTP/2 header and blocks the next client preface.
func http2ProtocolSegmentKeys(calls []Call) ([]string, map[string]bool) {
	keys := make([]string, len(calls))
	grouped := make(map[string][]int)
	inferred := make(map[string]bool)
	for i, call := range calls {
		key := http2ConnectionKey(call)
		grouped[key] = append(grouped[key], i)
	}
	for base, indexes := range grouped {
		group := make([]Call, len(indexes))
		for i, index := range indexes {
			group[i] = calls[index]
		}
		start, ordinal := 0, 1
		groupKeys := make([]string, len(group))
		for i := range group {
			if i > start && provenProtocolBoundary(group[start:i], group[i:]) {
				start = i
				ordinal++
			}
			key := base
			if ordinal > 1 {
				key = fmt.Sprintf("%s:protocol-segment:%d", base, ordinal)
			}
			keys[indexes[i]], groupKeys[i] = key, key
		}
		if ordinal > 1 {
			for _, key := range groupKeys {
				inferred[key] = true
			}
		}
	}
	return keys, inferred
}
