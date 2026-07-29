// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPacketEventDecodeMetadata(t *testing.T) {
	var comm [TaskCommLen]byte
	copy(comm[:], "com.larus.nova")
	packet := []byte{0x45, 0, 0, 20}
	values := []any{
		uint64(1234),
		uint32(777),
		comm,
		uint32(len(packet)),
		uint32(9),
		uint32(10290),
		uint32(PacketFlagAttributed | PacketFlagRawIP),
		uint32(PacketDirectionEgress),
		uint64(0x11223344),
		uint64(0x55667788),
	}
	var encoded bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&encoded, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	encoded.Write(packet)

	var event PacketEvent
	if err := event.DecodeFromBytes(encoded.Bytes()); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if event.Pid != 777 || event.Uid != 10290 || event.InterfaceIndex != 9 {
		t.Fatalf("decoded identity = pid:%d uid:%d ifindex:%d", event.Pid, event.Uid, event.InterfaceIndex)
	}
	if event.SocketCookie != 0x11223344 || event.CGroupID != 0x55667788 {
		t.Fatalf("decoded socket metadata = cookie:%#x cgroup:%#x", event.SocketCookie, event.CGroupID)
	}
	if event.DirectionString() != "egress" || !bytes.Equal(event.PacketData, packet) {
		t.Fatalf("decoded packet direction=%s data=%x", event.DirectionString(), event.PacketData)
	}
}

func TestPacketEventRejectsLegacyShortHeader(t *testing.T) {
	var event PacketEvent
	if err := event.DecodeFromBytes(make([]byte, PacketMetadataLen-1)); err == nil {
		t.Fatal("DecodeFromBytes() should reject a truncated metadata header")
	}
}
