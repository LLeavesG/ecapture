package reconstruction

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

const segmentWSRequest = "GET /fixture HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
const segmentWSResponse = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"

func segmentWSCalls(t *testing.T, stamp uint64, payload []byte, closed bool) []string {
	t.Helper()
	lines := []string{
		marshalTLSCaptureEvent(t, stamp, "WRITE", []byte(segmentWSRequest)),
		marshalTLSCaptureEvent(t, stamp+1, "READ", []byte(segmentWSResponse)),
		marshalTLSCaptureEvent(t, stamp+2, "WRITE", makeReconstructionWebSocketFrame(2, true, true, payload)),
		marshalTLSCaptureEvent(t, stamp+3, "READ", makeReconstructionWebSocketFrame(2, true, false, payload)),
	}
	if closed {
		lines = append(lines,
			marshalTLSCaptureEvent(t, stamp+4, "WRITE", makeReconstructionWebSocketFrame(8, true, true, []byte{3, 232})),
			marshalTLSCaptureEvent(t, stamp+5, "READ", makeReconstructionWebSocketFrame(8, true, false, []byte{3, 232})))
	}
	return lines
}

func segmentHTTP2Calls(t *testing.T, stamp uint64, body []byte) []string {
	t.Helper()
	request := encodeHPACKHeaders(t, hpack.HeaderField{Name: ":method", Value: "POST"}, hpack.HeaderField{Name: ":path", Value: "/h2"})
	response := encodeHPACKHeaders(t, hpack.HeaderField{Name: ":status", Value: "200"})
	write := append([]byte(nil), http2ClientPreface...)
	write = append(write, makeHTTP2Frame(http2FrameHeaders, http2FlagEndHeaders, 1, request)...)
	write = append(write, makeHTTP2Frame(http2FrameData, http2FlagEndStream, 1, body)...)
	read := makeHTTP2Frame(http2FrameSettings, 0, 0, nil)
	read = append(read, makeHTTP2Frame(http2FrameHeaders, http2FlagEndHeaders|http2FlagEndStream, 1, response)...)
	return []string{marshalTLSCaptureEvent(t, stamp, "WRITE", write), marshalTLSCaptureEvent(t, stamp+1, "READ", read)}
}

func TestProtocolSegmentsRecoverClosedWSThenHTTP2ThenWS(t *testing.T) {
	lines := segmentWSCalls(t, 10, []byte("first"), true)
	lines = append(lines, segmentHTTP2Calls(t, 20, []byte{0, 255})...)
	lines = append(lines, segmentWSCalls(t, 30, []byte("second"), true)...)
	input := strings.Join(lines, "\n")
	var output bytes.Buffer
	summary, err := ReconstructTransactions(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Transactions != 3 || summary.CompleteTransactions != 3 || summary.HTTP1.InferredProtocolSegments != 2 {
		t.Fatalf("unexpected transaction summary: %+v %s", summary, &output)
	}
	output.Reset()
	ws, err := ReconstructWebSocket(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if ws.InferredProtocolSegments != 2 || ws.UpgradeConnections != 2 || ws.Messages != 4 || ws.ControlFrames != 4 || ws.IncompleteRecords != 0 || ws.ParseErrors != 0 {
		t.Fatalf("unexpected WS summary: %+v %s", ws, &output)
	}
	decoder := json.NewDecoder(&output)
	identities := map[string]bool{}
	for decoder.More() {
		var record WebSocketMessage
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		if record.ConnectionGenerationSource != "observed-protocol-boundary" {
			t.Fatal("missing inferred generation provenance")
		}
		if record.EventType == "websocket_message" {
			identities[record.ConnectionID] = true
			if !bytes.Equal(record.Payload, []byte("first")) && !bytes.Equal(record.Payload, []byte("second")) {
				t.Fatal("body corrupted")
			}
		}
	}
	if len(identities) != 2 {
		t.Fatalf("merged protocol lifetimes: %+v", identities)
	}
}

func TestProtocolSegmentsDoNotSplitHandshakeTextInsideHTTP2Body(t *testing.T) {
	for _, body := range [][]byte{append(append([]byte(nil), http2ClientPreface...), []byte(segmentWSRequest)...), []byte(segmentWSRequest)} {
		// Deliberately put the misleading text at a TLS call start while the DATA
		// frame header is in the preceding call. The incomplete frame forbids split.
		request := encodeHPACKHeaders(t, hpack.HeaderField{Name: ":method", Value: "POST"}, hpack.HeaderField{Name: ":path", Value: "/binary"})
		write := append([]byte(nil), http2ClientPreface...)
		write = append(write, makeHTTP2Frame(http2FrameHeaders, http2FlagEndHeaders, 1, request)...)
		frame := makeHTTP2Frame(http2FrameData, http2FlagEndStream, 1, body)
		write = append(write, frame[:http2FrameHeaderSize]...)
		response := encodeHPACKHeaders(t, hpack.HeaderField{Name: ":status", Value: "200"})
		read := makeHTTP2Frame(http2FrameSettings, 0, 0, nil)
		read = append(read, makeHTTP2Frame(http2FrameHeaders, http2FlagEndHeaders|http2FlagEndStream, 1, response)...)
		input := strings.Join([]string{marshalTLSCaptureEvent(t, 1, "WRITE", write), marshalTLSCaptureEvent(t, 2, "WRITE", body), marshalTLSCaptureEvent(t, 3, "READ", read)}, "\n")
		_, calls, err := collectTLSCalls(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		segments, inferred := collectHTTP1ProtocolSegments(calls)
		if inferred != 0 || len(segments) != 1 {
			t.Fatal("split binary HTTP2 body")
		}
		var output bytes.Buffer
		summary, err := ReconstructHTTP2(strings.NewReader(input), &output)
		if err != nil {
			t.Fatal(err)
		}
		var tx HTTP2Transaction
		if err := json.Unmarshal(output.Bytes(), &tx); err != nil {
			t.Fatal(err)
		}
		if summary.CompleteTransactions != 1 || !bytes.Equal(tx.Request.Body, body) {
			t.Fatalf("binary body changed: %s", &output)
		}
	}
}

func TestProtocolSegmentsDoNotSplitHandshakeTextInsideWebSocketBody(t *testing.T) {
	body := append(append([]byte(nil), http2ClientPreface...), []byte("GET /inside HTTP/1.1\r\n")...)
	frame := makeReconstructionWebSocketFrame(2, true, false, body)
	// Unmasked server data can contain literal HTTP bytes. Split at its payload.
	headerLen := len(frame) - len(body)
	input := strings.Join([]string{
		marshalTLSCaptureEvent(t, 1, "WRITE", []byte(segmentWSRequest)),
		marshalTLSCaptureEvent(t, 2, "READ", []byte(segmentWSResponse)),
		marshalTLSCaptureEvent(t, 3, "READ", frame[:headerLen]),
		marshalTLSCaptureEvent(t, 4, "READ", body),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructWebSocket(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	var message WebSocketMessage
	if err := json.Unmarshal(output.Bytes(), &message); err != nil {
		t.Fatal(err)
	}
	if summary.InferredProtocolSegments != 0 || summary.Messages != 1 || !message.Complete || !bytes.Equal(message.Payload, body) {
		t.Fatalf("split binary WebSocket body: %+v %s", summary, &output)
	}
}

func TestProtocolSegmentsKeepUnclosedOrUnconfirmedTrafficAmbiguous(t *testing.T) {
	lines := segmentWSCalls(t, 10, []byte("not closed"), false)
	lines = append(lines, segmentHTTP2Calls(t, 20, []byte("later"))...)
	_, calls, err := collectTLSCalls(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	_, inferred := collectHTTP1ProtocolSegments(calls)
	if inferred != 0 {
		t.Fatal("split without complete WS close")
	}
	lines = segmentHTTP2Calls(t, 10, []byte("before"))
	ws := segmentWSCalls(t, 20, []byte("later"), true)
	ws[1] = marshalTLSCaptureEvent(t, 21, "READ", []byte(strings.ReplaceAll(segmentWSResponse, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "invalid")))
	lines = append(lines, ws...)
	_, calls, err = collectTLSCalls(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	_, inferred = collectHTTP1ProtocolSegments(calls)
	if inferred != 0 {
		t.Fatal("split with unconfirmed WebSocket response")
	}
}

func TestProtocolSegmentsRejectInvalidPreviousWebSocketAccept(t *testing.T) {
	lines := segmentWSCalls(t, 10, []byte("first"), true)
	lines[1] = marshalTLSCaptureEvent(t, 11, "READ", []byte(strings.ReplaceAll(segmentWSResponse, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "invalid")))
	lines = append(lines, segmentHTTP2Calls(t, 20, []byte("second"))...)
	_, calls, err := collectTLSCalls(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	_, inferred := collectHTTP1ProtocolSegments(calls)
	if inferred != 0 {
		t.Fatal("invalid previous Accept treated as a proven closed WebSocket")
	}
}

func TestProtocolSegmentIDsDoNotDependOnUniqueTimestamps(t *testing.T) {
	lines := segmentWSCalls(t, 10, []byte("first"), true)
	lines = append(lines, segmentHTTP2Calls(t, 20, []byte("second"))...)
	lines = append(lines, segmentWSCalls(t, 30, []byte("third"), true)...)
	_, calls, err := collectTLSCalls(strings.NewReader(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	// Preserve supplied call order but collide the two new segment timestamps.
	// Aggregation must retain all material even with non-unique clock samples.
	calls[6].Timestamp = 20
	calls[8].Timestamp = 20
	segments, inferred := collectHTTP1ProtocolSegments(calls)
	if inferred != 2 || len(segments) != 3 {
		t.Fatalf("timestamp collision lost material: inferred=%d segments=%d", inferred, len(segments))
	}
	total := 0
	for _, segment := range segments {
		total += len(segment.write.data) + len(segment.read.data)
	}
	expected := 0
	for _, call := range calls {
		expected += len(call.Data)
	}
	if total != expected {
		t.Fatalf("bytes discarded: got=%d want=%d", total, expected)
	}
}

func TestProtocolSegmentsSeparateOnlyClosedConfirmedWebSockets(t *testing.T) {
	for _, closed := range []bool{false, true} {
		lines := segmentWSCalls(t, 10, []byte("GET /payload HTTP/1.1\r\nPRI * HTTP/2.0\r\n"), closed)
		lines = append(lines, segmentWSCalls(t, 20, []byte("next"), true)...)
		_, calls, err := collectTLSCalls(strings.NewReader(strings.Join(lines, "\n")))
		if err != nil {
			t.Fatal(err)
		}
		_, inferred := collectHTTP1ProtocolSegments(calls)
		expected := 0
		if closed {
			expected = 1
		}
		if inferred != expected {
			t.Fatalf("closed=%v inferred=%d want=%d", closed, inferred, expected)
		}
		if closed {
			var output bytes.Buffer
			summary, err := ReconstructWebSocket(strings.NewReader(strings.Join(lines, "\n")), &output)
			if err != nil {
				t.Fatal(err)
			}
			if summary.UpgradeConnections != 2 || summary.Messages != 4 || summary.IncompleteRecords != 0 || summary.ParseErrors != 0 {
				t.Fatalf("closed WebSocket segments corrupted: %+v", summary)
			}
		}
	}
}

func TestHTTP2StateSeparatedAcrossClosedWebSocket(t *testing.T) {
	lines := segmentHTTP2Calls(t, 10, []byte("first body"))
	lines = append(lines, segmentWSCalls(t, 20, []byte("echo"), true)...)
	lines = append(lines, segmentHTTP2Calls(t, 30, nil)...)
	var output bytes.Buffer
	summary, err := ReconstructHTTP2(strings.NewReader(strings.Join(lines, "\n")), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Transactions != 2 {
		t.Fatalf("merged reused stream: %+v %s", summary, &output)
	}
	decoder := json.NewDecoder(&output)
	var first, second HTTP2Transaction
	if err := decoder.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&second); err != nil {
		t.Fatal(err)
	}
	if !first.Complete || !second.Complete || first.ConnectionID == second.ConnectionID {
		t.Fatalf("wrong completion or identity: %+v %+v", first, second)
	}
	if first.ConnectionGenerationSource != "observed-protocol-boundary" || second.ConnectionGenerationSource != "observed-protocol-boundary" {
		t.Fatal("missing inferred provenance")
	}
	if !bytes.Equal(first.Request.Body, []byte("first body")) || len(second.Request.Body) != 0 {
		t.Fatalf("body inherited across protocols: %+v %+v", first.Request, second.Request)
	}
}
