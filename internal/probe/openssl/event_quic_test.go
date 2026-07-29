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

package openssl

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestQuicEventDecodeAndValidate(t *testing.T) {
	buf := new(bytes.Buffer)
	fields := []any{
		uint64(123456),
		uint64(0xabcdef),
		uint64(4096),
		uint32(123),
		uint32(456),
		uint32(2),
		uint32(QuicEventProvideData),
	}
	for _, field := range fields {
		if err := binary.Write(buf, binary.LittleEndian, field); err != nil {
			t.Fatalf("binary.Write failed: %v", err)
		}
	}
	comm := [TaskCommLen]byte{}
	copy(comm[:], "ChromiumNet")
	if err := binary.Write(buf, binary.LittleEndian, comm); err != nil {
		t.Fatalf("binary.Write comm failed: %v", err)
	}

	event := &QuicEvent{}
	if err := event.DecodeFromBytes(buf.Bytes()); err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if event.SSLAddr != 0xabcdef || event.DataLen != 4096 {
		t.Fatalf("decoded metadata = SSL:%#x len:%d", event.SSLAddr, event.DataLen)
	}
	if got := event.String(); !strings.Contains(got, "http3_plaintext=outside_SSL_read_write") {
		t.Fatalf("String() does not explain the HTTP/3 coverage boundary: %s", got)
	}
}

func TestQuicEventValidateRejectsMissingIdentity(t *testing.T) {
	event := &QuicEvent{EventType: QuicEventProvideData}
	if err := event.Validate(); err == nil {
		t.Fatal("Validate should reject an empty SSL address")
	}
}

func TestQuicLevelString(t *testing.T) {
	if got, want := quicLevelString(2), "handshake"; got != want {
		t.Fatalf("quicLevelString(2) = %q, want %q", got, want)
	}
	if got, want := quicLevelString(99), "unknown_99"; got != want {
		t.Fatalf("quicLevelString(99) = %q, want %q", got, want)
	}
}
