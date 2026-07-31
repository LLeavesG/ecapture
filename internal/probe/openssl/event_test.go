// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gojue/ecapture/internal/domain"
)

func TestEventMarshalJSONIsCompact(t *testing.T) {
	event := &Event{
		DataType:    DataTypeWrite,
		Timestamp:   1,
		Pid:         42,
		DataLen:     7,
		OriginalLen: 7,
		CapturedLen: 7,
		SSLAddr:     0x1234,
	}
	copy(event.Data[:], "payload")
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if len(data) > 1000 || !bytes.Contains(data, []byte(`"eventType":"tls_plaintext"`)) ||
		!bytes.Contains(data, []byte(`"captureLayer":"transport"`)) ||
		!bytes.Contains(data, []byte(`"transport":"tls"`)) ||
		!bytes.Contains(data, []byte(`"data":"cGF5bG9hZA=="`)) {
		t.Fatalf("unexpected structured event: %s", data)
	}
	var envelope struct {
		WallTime string `json:"wallTime"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339Nano, envelope.WallTime); err != nil {
		t.Fatalf("wallTime is not an absolute RFC3339 timestamp: %q: %v",
			envelope.WallTime, err)
	}
}

func makeWebSocketFrame(payload []byte, masked bool) []byte {
	first := byte(0x82) // FIN + binary frame
	second := byte(0)
	if masked {
		second |= 0x80
	}
	header := []byte{first}
	switch {
	case len(payload) < 126:
		header = append(header, second|byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, second|126, byte(len(payload)>>8), byte(len(payload)))
	default:
		panic("payload too large for test helper")
	}
	if !masked {
		return append(header, payload...)
	}
	maskKey := []byte{0x11, 0x22, 0x33, 0x44}
	header = append(header, maskKey...)
	maskedPayload := make([]byte, len(payload))
	for i := range payload {
		maskedPayload[i] = payload[i] ^ maskKey[i%len(maskKey)]
	}
	return append(header, maskedPayload...)
}

func TestEvent_DecodeFromBytes(t *testing.T) {
	// Create a test event in binary format
	buf := new(bytes.Buffer)
	var err error
	// Write test data in the same order as the struct
	err = binary.Write(buf, binary.LittleEndian, int64(DataTypeWrite))          // DataType
	err = binary.Write(buf, binary.LittleEndian, uint64(time.Now().UnixNano())) // Timestamp
	err = binary.Write(buf, binary.LittleEndian, uint32(1234))                  // Pid
	err = binary.Write(buf, binary.LittleEndian, uint32(5678))                  // Tid

	// Write data array
	data := [MaxDataSize]byte{}
	copy(data[:], []byte("GET / HTTP/1.1\r\n"))
	err = binary.Write(buf, binary.LittleEndian, data)

	err = binary.Write(buf, binary.LittleEndian, int32(16)) // DataLen

	// Write comm
	comm := [16]byte{}
	copy(comm[:], []byte("curl"))
	err = binary.Write(buf, binary.LittleEndian, comm)

	err = binary.Write(buf, binary.LittleEndian, uint32(3))          // Fd
	err = binary.Write(buf, binary.LittleEndian, int32(771))         // Version (TLS 1.2)
	err = binary.Write(buf, binary.LittleEndian, uint32(0))          // BioType
	err = binary.Write(buf, binary.LittleEndian, uint64(0x12345678)) // SSLAddr
	err = binary.Write(buf, binary.LittleEndian, uint64(0x87654321)) // BIOAddr
	err = binary.Write(buf, binary.LittleEndian, uint32(16))         // OriginalLen
	err = binary.Write(buf, binary.LittleEndian, uint32(16))         // CapturedLen
	err = binary.Write(buf, binary.LittleEndian, uint32(0))          // ChunkOffset
	err = binary.Write(buf, binary.LittleEndian, uint32(0))          // Flags
	if err != nil {
		t.Fatalf("binary.Write failed: %v", err)
		return
	}
	// Decode the event
	event := &Event{}
	err = event.DecodeFromBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("DecodeFromBytes failed: %v", err)
		return
	}

	// Verify fields
	if event.DataType != DataTypeWrite {
		t.Errorf("DataType = %d, want %d", event.DataType, DataTypeWrite)
		return
	}
	if event.Pid != 1234 {
		t.Errorf("Pid = %d, want 1234", event.Pid)
		return
	}
	if event.Tid != 5678 {
		t.Errorf("Tid = %d, want 5678", event.Tid)
		return
	}
	if event.DataLen != 16 {
		t.Errorf("DataLen = %d, want 16", event.DataLen)
		return
	}
	if event.Fd != 3 {
		t.Errorf("Fd = %d, want 3", event.Fd)
		return
	}
	if event.Version != 771 {
		t.Errorf("Version = %d, want 771", event.Version)
		return
	}
	if event.SSLAddr != 0x12345678 {
		t.Errorf("SSLAddr = %#x, want %#x", event.SSLAddr, uint64(0x12345678))
	}
	if event.BIOAddr != 0x87654321 {
		t.Errorf("BIOAddr = %#x, want %#x", event.BIOAddr, uint64(0x87654321))
	}
	if event.OriginalLen != 16 || event.CapturedLen != 16 || event.ChunkOffset != 0 {
		t.Errorf("call metadata = original:%d captured:%d offset:%d, want 16/16/0",
			event.OriginalLen, event.CapturedLen, event.ChunkOffset)
	}

	dataStr := string(event.GetData())
	if !strings.Contains(dataStr, "GET / HTTP/1.1") {
		t.Errorf("Data does not contain expected string, got: %s", dataStr)
		return
	}
}

func TestEvent_String(t *testing.T) {
	event := &Event{
		DataType:  DataTypeWrite,
		Timestamp: uint64(time.Now().UnixNano()),
		Pid:       1234,
		Tid:       5678,
		DataLen:   16,
		Fd:        3,
		Version:   771,
	}
	copy(event.Comm[:], []byte("curl"))
	copy(event.Data[:], []byte("GET / HTTP/1.1\r\n"))

	str := event.String()
	if !strings.Contains(str, "PID:1234") {
		t.Errorf("String() should contain PID, got: %s", str)
	}
	if !strings.Contains(str, "WRITE") {
		t.Errorf("String() should contain WRITE, got: %s", str)
	}
	if !strings.Contains(str, "GET / HTTP/1.1") {
		t.Errorf("String() should contain data, got: %s", str)
	}
}

func TestEvent_String_Read(t *testing.T) {
	event := &Event{
		DataType:  DataTypeRead,
		Timestamp: uint64(time.Now().UnixNano()),
		Pid:       1234,
		Tid:       5678,
		DataLen:   20,
		Fd:        3,
	}
	copy(event.Comm[:], []byte("curl"))
	copy(event.Data[:], []byte("HTTP/1.1 200 OK\r\n\r\n"))

	str := event.String()
	if !strings.Contains(str, "READ") {
		t.Errorf("String() should contain READ for read events, got: %s", str)
	}
}

func TestEvent_StringHex(t *testing.T) {
	event := &Event{
		DataType:  DataTypeWrite,
		Timestamp: uint64(time.Now().UnixNano()),
		Pid:       1234,
		DataLen:   4,
	}
	copy(event.Data[:], []byte("test"))

	hex := event.StringHex()
	if !strings.Contains(hex, "hex") {
		t.Errorf("StringHex() should contain 'hex', got: %s", hex)
	}
	// Check for hex representation of "test"
	if !strings.Contains(hex, "74657374") {
		t.Errorf("StringHex() should contain hex of 'test', got: %s", hex)
	}
}

func TestEvent_String_DecodesMaskedWebSocketWrite(t *testing.T) {
	payload := []byte(`{"message":"hello websocket"}`)
	frame := makeWebSocketFrame(payload, true)
	event := &Event{
		DataType:  DataTypeWrite,
		Timestamp: uint64(time.Now().UnixNano()),
		Pid:       1234,
		Tid:       5678,
		DataLen:   int32(len(frame)),
		Fd:        3,
	}
	copy(event.Comm[:], []byte("curl"))
	copy(event.Data[:], frame)

	str := event.String()
	if !strings.Contains(str, "websocket frames=1 opcode=binary masked") {
		t.Fatalf("String() should describe decoded websocket frame, got: %s", str)
	}
	if !strings.Contains(str, `{"message":"hello websocket"}`) {
		t.Fatalf("String() should contain decoded websocket payload, got: %s", str)
	}
}

func TestEvent_StringHex_DecodesMaskedWebSocketWrite(t *testing.T) {
	payload := []byte("hello websocket")
	frame := makeWebSocketFrame(payload, true)
	event := &Event{
		DataType:  DataTypeWrite,
		Timestamp: uint64(time.Now().UnixNano()),
		Pid:       1234,
		DataLen:   int32(len(frame)),
	}
	copy(event.Data[:], frame)

	hex := event.StringHex()
	if !strings.Contains(hex, "websocket frames=1 opcode=binary masked") {
		t.Fatalf("StringHex() should describe decoded websocket frame, got: %s", hex)
	}
	normalized := strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(hex)
	if !strings.Contains(normalized, "68656C6C6F20776562736F636B6574") {
		t.Fatalf("StringHex() should contain decoded websocket payload bytes, got: %s", hex)
	}
}

func TestEvent_String_DecodesUnmaskedWebSocketRead(t *testing.T) {
	payload := []byte("server says hi")
	frame := makeWebSocketFrame(payload, false)
	event := &Event{
		DataType:  DataTypeRead,
		Timestamp: uint64(time.Now().UnixNano()),
		Pid:       1234,
		Tid:       5678,
		DataLen:   int32(len(frame)),
		Fd:        3,
	}
	copy(event.Comm[:], []byte("curl"))
	copy(event.Data[:], frame)

	str := event.String()
	if !strings.Contains(str, "websocket frames=1 opcode=binary unmasked") {
		t.Fatalf("String() should describe decoded websocket read frame, got: %s", str)
	}
	if !strings.Contains(str, "server says hi") {
		t.Fatalf("String() should contain decoded server websocket payload, got: %s", str)
	}
}

func TestEvent_String_DoesNotDecodeUnmaskedWebSocketWrite(t *testing.T) {
	payload := []byte("client frame should stay raw")
	frame := makeWebSocketFrame(payload, false)
	event := &Event{
		DataType:  DataTypeWrite,
		Timestamp: uint64(time.Now().UnixNano()),
		Pid:       1234,
		DataLen:   int32(len(frame)),
	}
	copy(event.Data[:], frame)

	str := event.String()
	if strings.Contains(str, "websocket frames=") {
		t.Fatalf("String() should not decode unmasked websocket writes, got: %s", str)
	}
}

func TestEvent_MultiChunkMetadata(t *testing.T) {
	event := &Event{
		DataType:    DataTypeRead,
		Timestamp:   123,
		Pid:         42,
		DataLen:     17,
		SSLAddr:     0xabc,
		BIOAddr:     0xdef,
		OriginalLen: MaxDataSize + 17,
		CapturedLen: MaxDataSize + 17,
		ChunkOffset: MaxDataSize,
	}

	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() returned unexpected error: %v", err)
	}
	if !event.IsLastChunk() {
		t.Fatal("last segment should be recognized as the final chunk")
	}
	if got, want := event.StreamID(), "42_ssl_abc_0"; got != want {
		t.Fatalf("StreamID() = %q, want %q", got, want)
	}

	first := *event
	first.DataLen = MaxDataSize
	first.ChunkOffset = 0
	if first.IsLastChunk() {
		t.Fatal("first segment should not be recognized as the final chunk")
	}
	if first.UUID() == event.UUID() {
		t.Fatal("chunks from the same SSL call must have unique UUIDs")
	}
}

func TestEvent_TruncationMetadata(t *testing.T) {
	event := &Event{
		DataType:    DataTypeWrite,
		DataLen:     MaxDataSize,
		OriginalLen: MaxCaptureCallSize + 1,
		CapturedLen: MaxCaptureCallSize,
		ChunkOffset: MaxCaptureCallSize - MaxDataSize,
		Flags:       EventFlagTruncated,
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() returned unexpected error: %v", err)
	}
	if !event.IsTruncated() {
		t.Fatal("IsTruncated() = false, want true")
	}

	event.Flags = 0
	if err := event.Validate(); err == nil {
		t.Fatal("Validate() should reject missing truncation metadata")
	}
}

func TestEvent_RejectsInvalidChunkRange(t *testing.T) {
	event := &Event{
		DataType:    DataTypeRead,
		DataLen:     2,
		OriginalLen: 10,
		CapturedLen: 10,
		ChunkOffset: 9,
	}
	if err := event.Validate(); err == nil {
		t.Fatal("Validate() should reject a chunk that exceeds CapturedLen")
	}
}

func TestEvent_Clone(t *testing.T) {
	original := &Event{
		Pid:      1234,
		DataType: DataTypeWrite,
		DataLen:  10,
	}
	copy(original.Data[:], []byte("test data"))

	cloned := original.Clone()
	if cloned == nil {
		t.Fatal("Clone() returned nil")
		return
	}

	clonedEvent, ok := cloned.(*Event)
	if !ok {
		t.Fatal("Clone() did not return an Event")
		return
	}

	if clonedEvent.Pid != original.Pid {
		t.Error("Clone() did not copy Pid correctly")
	}
	if clonedEvent.DataLen != original.DataLen {
		t.Error("Clone() did not copy DataLen correctly")
	}
}

func TestEvent_Type(t *testing.T) {
	event := &Event{}
	if event.Type() != domain.EventTypeOutput {
		t.Errorf("Type() = %v, want %v", event.Type(), domain.EventTypeOutput)
	}
}

func TestEvent_UUID(t *testing.T) {
	event := &Event{
		Pid:       1234,
		Tid:       5678,
		Timestamp: 9999,
	}
	uuid := event.UUID()
	if uuid == "" {
		t.Error("UUID() returned empty string")
	}
	if !strings.Contains(uuid, "1234") {
		t.Errorf("UUID() should contain PID, got: %s", uuid)
	}
}

func TestEvent_Validate(t *testing.T) {
	tests := []struct {
		name    string
		event   *Event
		wantErr bool
	}{
		{
			name: "Valid write event",
			event: &Event{
				DataType: DataTypeWrite,
				DataLen:  100,
			},
			wantErr: false,
		},
		{
			name: "Valid read event",
			event: &Event{
				DataType: DataTypeRead,
				DataLen:  100,
			},
			wantErr: false,
		},
		{
			name: "Invalid data length (negative)",
			event: &Event{
				DataType: DataTypeWrite,
				DataLen:  -1,
			},
			wantErr: true,
		},
		{
			name: "Invalid data length (too large)",
			event: &Event{
				DataType: DataTypeWrite,
				DataLen:  MaxDataSize + 1,
			},
			wantErr: true,
		},
		{
			name: "Invalid data type",
			event: &Event{
				DataType: 99,
				DataLen:  100,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvent_GetPid(t *testing.T) {
	event := &Event{Pid: 1234}
	if event.GetPid() != 1234 {
		t.Errorf("GetPid() = %d, want 1234", event.GetPid())
	}
}

func TestEvent_GetComm(t *testing.T) {
	event := &Event{}
	copy(event.Comm[:], []byte("test-proc"))

	comm := event.GetComm()
	if comm != "test-proc" {
		t.Errorf("GetComm() = %s, want test-proc", comm)
	}
}

func TestEvent_GetData(t *testing.T) {
	event := &Event{
		DataLen: 10,
	}
	copy(event.Data[:], []byte("test data more"))

	data := event.GetData()
	if len(data) != 10 {
		t.Errorf("GetData() length = %d, want 10", len(data))
	}
	if string(data) != "test data " {
		t.Errorf("GetData() = %s, want 'test data '", string(data))
	}
}

func TestEvent_GetDataLen(t *testing.T) {
	event := &Event{DataLen: 100}
	if event.GetDataLen() != 100 {
		t.Errorf("GetDataLen() = %d, want 100", event.GetDataLen())
	}

	// Test negative length
	event.DataLen = -1
	if event.GetDataLen() != 0 {
		t.Errorf("GetDataLen() with negative length = %d, want 0", event.GetDataLen())
	}
}

func TestEvent_GetTimestamp(t *testing.T) {
	ts := uint64(time.Now().UnixNano())
	event := &Event{Timestamp: ts}
	if event.GetTimestamp() != ts {
		t.Errorf("GetTimestamp() = %d, want %d", event.GetTimestamp(), ts)
	}
}

func TestEvent_IsRead(t *testing.T) {
	readEvent := &Event{DataType: DataTypeRead}
	if !readEvent.IsRead() {
		t.Error("IsRead() should return true for read events")
	}

	writeEvent := &Event{DataType: DataTypeWrite}
	if writeEvent.IsRead() {
		t.Error("IsRead() should return false for write events")
	}
}

func Test_commToString(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{
			name: "Null-terminated string",
			data: []byte{'t', 'e', 's', 't', 0, 0, 0},
			want: "test",
		},
		{
			name: "No null terminator",
			data: []byte{'t', 'e', 's', 't'},
			want: "test",
		},
		{
			name: "Empty array",
			data: []byte{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := commToString(tt.data)
			if got != tt.want {
				t.Errorf("commToString() = %v, want %v", got, tt.want)
			}
		})
	}
}
