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
)

func TestReconstructWebSocketSplitCallsFragmentationAndControl(t *testing.T) {
	request := []byte(
		"GET /ws?x=1 HTTP/1.1\r\n" +
			"Host: example.test\r\n" +
			"Connection: keep-alive, Upgrade\r\n" +
			"Upgrade: websocket\r\n" +
			"Sec-WebSocket-Key: test\r\n\r\n",
	)
	clientFrameOne := makeReconstructionWebSocketFrame(
		0x1,
		false,
		true,
		[]byte("hel"),
	)
	clientFrameTwo := makeReconstructionWebSocketFrame(
		0x0,
		true,
		true,
		[]byte("lo"),
	)
	response := []byte(
		"HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\n" +
			"Upgrade: websocket\r\n\r\n",
	)
	serverFrame := makeReconstructionWebSocketFrame(
		0x2,
		true,
		false,
		[]byte{0, 1, 2},
	)
	serverPing := makeReconstructionWebSocketFrame(
		0x9,
		true,
		false,
		[]byte("p"),
	)
	write := append(append(append([]byte(nil), request...), clientFrameOne...),
		clientFrameTwo...)
	read := append(append(append([]byte(nil), response...), serverFrame...),
		serverPing...)
	input := strings.Join([]string{
		marshalTLSCaptureEvent(t, 10, "WRITE", write[:len(request)+4]),
		marshalTLSCaptureEvent(t, 11, "WRITE", write[len(request)+4:]),
		marshalTLSCaptureEvent(t, 12, "READ", read[:len(response)+1]),
		marshalTLSCaptureEvent(t, 13, "READ", read[len(response)+1:]),
	}, "\n")

	var output bytes.Buffer
	summary, err := ReconstructWebSocket(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.UpgradeConnections != 1 ||
		summary.Frames != 4 ||
		summary.Messages != 2 ||
		summary.ControlFrames != 1 ||
		summary.CompleteRecords != 3 ||
		summary.IncompleteRecords != 0 ||
		summary.ParseErrors != 0 {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	decoder := json.NewDecoder(&output)
	var records []WebSocketMessage
	for decoder.More() {
		var record WebSocketMessage
		if err := decoder.Decode(&record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if len(records) != 3 {
		t.Fatalf("unexpected records: %#v", records)
	}
	var client WebSocketMessage
	var server WebSocketMessage
	var ping WebSocketMessage
	for _, record := range records {
		switch {
		case record.Direction == "client_to_server":
			client = record
		case record.Opcode == 0x9:
			ping = record
		default:
			server = record
		}
	}
	if client.Authority != "example.test" ||
		client.Path != "/ws?x=1" ||
		client.OpcodeName != "text" ||
		client.FrameCount != 2 ||
		string(client.Payload) != "hello" ||
		!client.Masked ||
		!client.Complete {
		t.Fatalf("client message changed: %#v", client)
	}
	if server.OpcodeName != "binary" ||
		!bytes.Equal(server.Payload, []byte{0, 1, 2}) ||
		server.Masked ||
		!server.Complete {
		t.Fatalf("server message changed: %#v", server)
	}
	if ping.EventType != "websocket_control" ||
		ping.OpcodeName != "ping" ||
		string(ping.Payload) != "p" ||
		!ping.Complete {
		t.Fatalf("control frame changed: %#v", ping)
	}
}

func TestReconstructWebSocketPreservesIncompleteTrailingFrame(t *testing.T) {
	request := []byte(
		"GET /ws HTTP/1.1\r\nHost: example.test\r\n" +
			"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
	)
	response := []byte(
		"HTTP/1.1 101 Switching Protocols\r\n" +
			"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
	)
	incomplete := []byte{0x82, 0x05, 0x01, 0x02}
	input := strings.Join([]string{
		marshalTLSCaptureEvent(t, 20, "WRITE", request),
		marshalTLSCaptureEvent(
			t,
			21,
			"READ",
			append(append([]byte(nil), response...), incomplete...),
		),
	}, "\n")
	var output bytes.Buffer
	summary, err := ReconstructWebSocket(strings.NewReader(input), &output)
	if err != nil {
		t.Fatal(err)
	}
	if summary.UpgradeConnections != 1 ||
		summary.Messages != 1 ||
		summary.CompleteRecords != 0 ||
		summary.IncompleteRecords != 1 ||
		summary.ParseErrors != 1 ||
		summary.OpaqueBytes != len(incomplete) {
		t.Fatalf("unexpected summary: %#v output=%s", summary, output.String())
	}
	var record WebSocketMessage
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.EventType != "websocket_opaque" ||
		record.Complete ||
		!record.RawFrame ||
		!bytes.Equal(record.Payload, incomplete) ||
		len(record.Errors) != 1 {
		t.Fatalf("incomplete bytes were not preserved: %#v", record)
	}
}

func makeReconstructionWebSocketFrame(
	opcode byte,
	fin bool,
	masked bool,
	payload []byte,
) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}
	second := byte(len(payload))
	frame := []byte{first, second}
	if masked {
		frame[1] |= 0x80
		mask := []byte{1, 2, 3, 4}
		frame = append(frame, mask...)
		for index, value := range payload {
			frame = append(frame, value^mask[index%len(mask)])
		}
		return frame
	}
	return append(frame, payload...)
}
