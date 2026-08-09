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

package handlers

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/output/encoders"
)

// mockWriter wraps bytes.Buffer to implement OutputWriter
type mockWriter struct {
	*bytes.Buffer
}

func newMockWriter() *mockWriter {
	return &mockWriter{Buffer: &bytes.Buffer{}}
}

func (m *mockWriter) Close() error {
	return nil
}

func (m *mockWriter) Name() string {
	return "mock-writer"
}

func (m *mockWriter) Flush() error {
	return nil
}

// mockTLSDataEvent is a mock implementation of TLSDataEvent for testing.
type mockTLSDataEvent struct {
	pid       uint32
	comm      string
	data      []byte
	dataLen   uint32
	timestamp uint64
	isRead    bool
}

type mockTextPacketEvent struct {
	mockTLSDataEvent
}

func (m *mockTextPacketEvent) GetPacketData() []byte {
	return m.data
}

func (m *mockTextPacketEvent) GetPacketLen() uint32 {
	return uint32(len(m.data))
}

func (m *mockTextPacketEvent) GetInterfaceIndex() uint32 {
	return 7
}

func (m *mockTextPacketEvent) GetSrcIP() string {
	return "192.0.2.1"
}

func (m *mockTextPacketEvent) GetDstIP() string {
	return "192.0.2.2"
}

func (m *mockTextPacketEvent) GetSrcPort() uint16 {
	return 12345
}

func (m *mockTextPacketEvent) GetDstPort() uint16 {
	return 443
}

func (m *mockTLSDataEvent) GetPid() uint32 {
	return m.pid
}

func (m *mockTLSDataEvent) GetComm() string {
	return m.comm
}

func (m *mockTLSDataEvent) GetData() []byte {
	return m.data
}

func (m *mockTLSDataEvent) GetDataLen() uint32 {
	return m.dataLen
}

func (m *mockTLSDataEvent) GetTimestamp() uint64 {
	return m.timestamp
}

func (m *mockTLSDataEvent) IsRead() bool {
	return m.isRead
}

func (m *mockTLSDataEvent) DecodeFromBytes(data []byte) error {
	return nil
}

func (m *mockTLSDataEvent) Validate() error {
	return nil
}

func (m *mockTLSDataEvent) String() string {
	return string(m.data)
}

func (m *mockTLSDataEvent) StringHex() string {
	return fmt.Sprintf("%x", m.data)
}

func (m *mockTLSDataEvent) Clone() domain.Event {
	clone := *m
	clone.data = make([]byte, len(m.data))
	copy(clone.data, m.data)
	return &clone
}

func (m *mockTLSDataEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

func (m *mockTLSDataEvent) UUID() string {
	return "mock-uuid"
}

func TestNewTextHandler(t *testing.T) {
	writer := newMockWriter()
	handler := NewTextHandler(writer, false)
	if handler == nil {
		t.Fatal("NewTextHandler returned nil")
		return
	}
}

func TestNewTextHandler_NilWriter(t *testing.T) {
	handler := NewTextHandler(nil, false)
	if handler == nil {
		t.Fatal("NewTextHandler returned nil with nil writer")
		return
	}
	// Should use StdoutWriter
	if handler.writer == nil {
		t.Error("TextHandler writer should not be nil")
	}
}

func TestTextHandler_Handle_Write(t *testing.T) {
	writer := newMockWriter()
	handler := NewTextHandler(writer, false)

	event := &mockTLSDataEvent{
		pid:       1234,
		comm:      "test-app",
		data:      []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		dataLen:   42,
		timestamp: 1704168000000000000, // 2024-01-02 00:00:00 UTC
		isRead:    false,
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
		return
	}

	output := writer.String()
	if !strings.Contains(output, "GET / HTTP/1.1") {
		t.Errorf("Output should contain request data, got: %s", output)
		return
	}
}

func TestTextHandlerSuppressesOnlyPacketEvents(t *testing.T) {
	writer := newMockWriter()
	handler := NewTextHandler(writer, false)
	handler.SuppressPacketEvents()

	packet := &mockTextPacketEvent{mockTLSDataEvent: mockTLSDataEvent{
		data: []byte("raw-packet"),
	}}
	if err := handler.Handle(packet); err != nil {
		t.Fatalf("Handle(packet) error = %v", err)
	}
	if writer.Len() != 0 {
		t.Fatalf("suppressed packet output = %q", writer.String())
	}

	transport := &mockTLSDataEvent{data: []byte("transport-stream")}
	if err := handler.Handle(transport); err != nil {
		t.Fatalf("Handle(transport) error = %v", err)
	}
	if got, want := writer.String(), "transport-stream\n"; got != want {
		t.Fatalf("transport output = %q, want %q", got, want)
	}
}

func TestTextHandler_Handle_Read(t *testing.T) {
	writer := newMockWriter()
	handler := NewTextHandler(writer, false)

	event := &mockTLSDataEvent{
		pid:       5678,
		comm:      "curl",
		data:      []byte("HTTP/1.1 200 OK\r\n\r\n"),
		dataLen:   20,
		timestamp: 1704168000000000000,
		isRead:    true,
	}

	err := handler.Handle(event)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
		return
	}

	output := writer.String()
	if !strings.Contains(output, "HTTP/1.1 200 OK") {
		t.Errorf("Output should contain response data, got: %s", output)
		return
	}
}

func TestEncodedTextHandlerJSON(t *testing.T) {
	writer := newMockWriter()
	handler := NewEncodedTextHandler(writer, encoders.NewJsonEncoder(false))
	event := &jsonMockEvent{
		Pid:  42,
		Data: []byte("payload"),
	}
	if err := handler.Handle(event); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	output := writer.String()
	if !strings.HasSuffix(output, "\n") ||
		!strings.Contains(output, `"pid":42`) ||
		!strings.Contains(output, `"data":"cGF5bG9hZA=="`) {
		t.Fatalf("unexpected JSON event output: %q", output)
	}
}

func TestTextHandler_Handle_NilEvent(t *testing.T) {
	writer := newMockWriter()
	handler := NewTextHandler(writer, false)

	err := handler.Handle(nil)
	if err == nil {
		t.Error("Handle should return error for nil event")
	}
}

// mockNonTLSEvent is a mock event that doesn't implement TLSDataEvent
type mockNonTLSEvent struct{}

func (m *mockNonTLSEvent) DecodeFromBytes(data []byte) error { return nil }
func (m *mockNonTLSEvent) Validate() error                   { return nil }
func (m *mockNonTLSEvent) String() string                    { return "" }
func (m *mockNonTLSEvent) StringHex() string                 { return "" }
func (m *mockNonTLSEvent) Clone() domain.Event               { return &mockNonTLSEvent{} }
func (m *mockNonTLSEvent) Type() domain.EventType            { return domain.EventTypeOutput }
func (m *mockNonTLSEvent) UUID() string                      { return "" }

type jsonMockEvent struct {
	Pid  uint32 `json:"pid"`
	Data []byte `json:"data"`
}

func (m *jsonMockEvent) DecodeFromBytes(data []byte) error { return nil }
func (m *jsonMockEvent) Validate() error                   { return nil }
func (m *jsonMockEvent) String() string                    { return string(m.Data) }
func (m *jsonMockEvent) StringHex() string                 { return fmt.Sprintf("%x", m.Data) }
func (m *jsonMockEvent) Clone() domain.Event {
	clone := *m
	clone.Data = append([]byte(nil), m.Data...)
	return &clone
}
func (m *jsonMockEvent) Type() domain.EventType { return domain.EventTypeOutput }
func (m *jsonMockEvent) UUID() string           { return "json-mock" }

func TestTextHandler_Handle_InvalidEventType(t *testing.T) {
	writer := newMockWriter()
	handler := NewTextHandler(writer, false)

	var event domain.Event = &mockNonTLSEvent{}
	err := handler.Handle(event)
	// Should return nil (skip silently) for non-TLS events
	if err != nil {
		t.Errorf("Handle should skip non-TLS events silently, got error: %v", err)
		return
	}
}

func TestTextHandler_Close(t *testing.T) {
	writer := newMockWriter()
	handler := NewTextHandler(writer, false)

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
		return
	}
}

// mockClosableWriter is a writer that implements OutputWriter with Close tracking
type mockClosableWriter struct {
	*bytes.Buffer
	closed bool
}

func (m *mockClosableWriter) Close() error {
	m.closed = true
	return nil
}

func (m *mockClosableWriter) Name() string {
	return "mock-closable-writer"
}

func (m *mockClosableWriter) Flush() error {
	return nil
}

func TestTextHandler_Close_ClosableWriter(t *testing.T) {
	writer := &mockClosableWriter{Buffer: &bytes.Buffer{}}
	handler := NewTextHandler(writer, false)

	err := handler.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
		return
	}
	if !writer.closed {
		t.Error("Writer should be closed")
	}
}

type blockingWriter struct {
	calls        atomic.Int32
	active       atomic.Int32
	overlapped   atomic.Bool
	firstEntered chan struct{}
	releaseFirst chan struct{}
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{
		firstEntered: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	call := w.calls.Add(1)
	active := w.active.Add(1)
	if active > 1 {
		w.overlapped.Store(true)
	}
	if call == 1 {
		close(w.firstEntered)
		<-w.releaseFirst
	}
	w.active.Add(-1)
	return len(p), nil
}

func (w *blockingWriter) Close() error { return nil }
func (w *blockingWriter) Name() string { return "blocking-writer" }
func (w *blockingWriter) Flush() error { return nil }

func TestTextHandlerSerializesConcurrentWrites(t *testing.T) {
	writer := newBlockingWriter()
	handler := NewTextHandler(writer, false)
	event := &mockTLSDataEvent{data: []byte("event")}

	firstDone := make(chan error, 1)
	go func() { firstDone <- handler.Handle(event) }()
	<-writer.firstEntered

	secondDone := make(chan error, 1)
	go func() { secondDone <- handler.Handle(event) }()
	select {
	case err := <-secondDone:
		close(writer.releaseFirst)
		<-firstDone
		t.Fatalf("second write was not serialized: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(writer.releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Handle() error = %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second Handle() error = %v", err)
	}
	if writer.overlapped.Load() {
		t.Fatal("writer observed concurrent Handle calls")
	}
}
