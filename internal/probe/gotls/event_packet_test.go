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

package gotls

import (
	"bytes"
	"encoding/binary"
	stderrors "errors"
	"testing"

	ecaptureerrors "github.com/gojue/ecapture/internal/errors"
)

func encodePacketEvent(
	t *testing.T, packetLen, capturedLen, offset uint32,
	payload []byte, chunkCount uint32,
) []byte {
	t.Helper()
	var data bytes.Buffer
	values := []any{
		uint64(1234), uint32(7), [TaskCommLen]byte{}, packetLen,
		uint32(11), uint32(1000), uint32(0), uint32(1),
		uint64(22), uint64(33),
		capturedLen, offset, uint32(len(payload)), chunkCount,
	}
	for _, value := range values {
		if err := binary.Write(&data, binary.LittleEndian, value); err != nil {
			t.Fatalf("encode packet metadata: %v", err)
		}
	}
	data.Write(payload)
	return data.Bytes()
}

func TestPacketEventReassemblesLargePacket(t *testing.T) {
	packet := bytes.Repeat([]byte{0x5a}, 65549)
	decoder := &packetEventDecoder{}
	first := encodePacketEvent(t, 65549, 65549, 0, packet[:60*1024], 2)
	if event, err := decoder.Decode(nil, first); event != nil ||
		!stderrors.Is(err, ecaptureerrors.ErrEventNotReady) {
		t.Fatalf("first Decode() = (%T,%v), want not ready", event, err)
	}
	tail := encodePacketEvent(t, 65549, 65549, 60*1024, packet[60*1024:], 2)
	decoded, err := decoder.Decode(nil, tail)
	if err != nil {
		t.Fatalf("tail Decode() error = %v", err)
	}
	event, ok := decoded.(*PacketEvent)
	if !ok {
		t.Fatalf("decoded event type = %T", decoded)
	}
	if !bytes.Equal(event.PacketData, packet) {
		t.Fatalf("captured payload length = %d, want %d", len(event.PacketData), len(packet))
	}
}

func TestPacketEventIgnoresPerfRecordPadding(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	encoded := encodePacketEvent(
		t, uint32(len(payload)), uint32(len(payload)), 0, payload, 1,
	)
	encoded = append(encoded, bytes.Repeat([]byte{0xff}, 7)...)
	event := &PacketEvent{}
	if err := event.DecodeFromBytes(encoded); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if !bytes.Equal(event.PacketData, payload) {
		t.Fatalf("captured payload = %x, want %x", event.PacketData, payload)
	}
}
