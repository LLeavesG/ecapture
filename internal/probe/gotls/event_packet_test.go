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
	"testing"
)

func encodePacketEvent(t *testing.T, packetLen uint32, payload []byte) []byte {
	t.Helper()
	var data bytes.Buffer
	values := []any{
		uint64(1234), uint32(7), [TaskCommLen]byte{}, packetLen,
		uint32(11), uint32(1000), uint32(0), uint32(1),
		uint64(22), uint64(33),
	}
	for _, value := range values {
		if err := binary.Write(&data, binary.LittleEndian, value); err != nil {
			t.Fatalf("encode packet metadata: %v", err)
		}
	}
	data.Write(payload)
	return data.Bytes()
}

func TestPacketEventPreservesTruncatedPacketPrefix(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5a}, 1024)
	event := &PacketEvent{}
	if err := event.DecodeFromBytes(encodePacketEvent(t, 65549, payload)); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if !bytes.Equal(event.PacketData, payload) {
		t.Fatalf("captured payload length = %d, want %d", len(event.PacketData), len(payload))
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestPacketEventIgnoresPerfRecordPadding(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	encoded := encodePacketEvent(t, uint32(len(payload)), payload)
	encoded = append(encoded, bytes.Repeat([]byte{0xff}, 7)...)
	event := &PacketEvent{}
	if err := event.DecodeFromBytes(encoded); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if !bytes.Equal(event.PacketData, payload) {
		t.Fatalf("captured payload = %x, want %x", event.PacketData, payload)
	}
}
