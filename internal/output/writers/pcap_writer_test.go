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

package writers

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/gojue/ecapture/internal/logger"
)

func TestPcapWriterUsesRawIPInterfaceAndTimestamp(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewPcapWriterInterfaces(
		&output, 65535, []string{"unit-test-interface"}, "", logger.New(io.Discard, false),
	)
	if err != nil {
		t.Fatalf("NewPcapWriterInterfaces() error = %v", err)
	}
	wantTime := time.Unix(1_800_000_000, 123456789)
	packet := []byte{0x45, 0, 0, 20}
	if err := writer.WritePacketForInterface(
		packet, wantTime, 999999, true, uint32(len(packet)),
	); err != nil {
		t.Fatalf("WritePacketForInterface() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reader, err := pcapgo.NewNgReader(bytes.NewReader(output.Bytes()), pcapgo.NgReaderOptions{
		WantMixedLinkType: true,
	})
	if err != nil {
		t.Fatalf("NewNgReader() error = %v", err)
	}
	gotPacket, captureInfo, err := reader.ReadPacketData()
	if err != nil {
		t.Fatalf("ReadPacketData() error = %v", err)
	}
	if !bytes.Equal(gotPacket, packet) {
		t.Fatalf("packet = %x, want %x", gotPacket, packet)
	}
	if !captureInfo.Timestamp.Equal(wantTime) {
		t.Fatalf("timestamp = %s, want %s", captureInfo.Timestamp, wantTime)
	}
	iface, err := reader.Interface(captureInfo.InterfaceIndex)
	if err != nil {
		t.Fatalf("Interface() error = %v", err)
	}
	if iface.LinkType != layers.LinkTypeRaw {
		t.Fatalf("link type = %v, want raw IP", iface.LinkType)
	}
}

func TestPcapWriterRegistersRuntimeInterface(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewPcapWriterInterfaces(
		&output, 65535, []string{"initial-test-interface"}, "",
		logger.New(io.Discard, false),
	)
	if err != nil {
		t.Fatalf("NewPcapWriterInterfaces() error = %v", err)
	}
	const systemIndex = uint32(424242)
	if err := writer.RegisterInterface("runtime-tun", systemIndex); err != nil {
		t.Fatalf("RegisterInterface() error = %v", err)
	}
	packet := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		0x08, 0x00, 0x45, 0, 0, 20,
	}
	if err := writer.WritePacketForInterface(
		packet, time.Unix(1_800_000_001, 0), systemIndex, false,
		uint32(len(packet)),
	); err != nil {
		t.Fatalf("WritePacketForInterface() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reader, err := pcapgo.NewNgReader(
		bytes.NewReader(output.Bytes()),
		pcapgo.NgReaderOptions{WantMixedLinkType: true},
	)
	if err != nil {
		t.Fatalf("NewNgReader() error = %v", err)
	}
	_, captureInfo, err := reader.ReadPacketData()
	if err != nil {
		t.Fatalf("ReadPacketData() error = %v", err)
	}
	iface, err := reader.Interface(captureInfo.InterfaceIndex)
	if err != nil {
		t.Fatalf("Interface() error = %v", err)
	}
	if iface.Name != "runtime-tun" {
		t.Fatalf("interface name = %q, want runtime-tun", iface.Name)
	}
	if iface.LinkType != layers.LinkTypeEthernet {
		t.Fatalf("link type = %v, want Ethernet", iface.LinkType)
	}
}

func TestPcapWriterPreservesTruncatedPacketOriginalLength(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewPcapWriterInterfaces(
		&output, 65535, []string{"unit-test-interface"}, "",
		logger.New(io.Discard, false),
	)
	if err != nil {
		t.Fatalf("NewPcapWriterInterfaces() error = %v", err)
	}
	packet := bytes.Repeat([]byte{0x5a}, 60*1024)
	const originalLength = uint32(65549)
	if err := writer.WritePacketForInterface(
		packet, time.Unix(1_800_000_002, 0), 0, false, originalLength,
	); err != nil {
		t.Fatalf("WritePacketForInterface() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reader, err := pcapgo.NewNgReader(
		bytes.NewReader(output.Bytes()),
		pcapgo.NgReaderOptions{WantMixedLinkType: true},
	)
	if err != nil {
		t.Fatalf("NewNgReader() error = %v", err)
	}
	gotPacket, captureInfo, err := reader.ReadPacketData()
	if err != nil {
		t.Fatalf("ReadPacketData() error = %v", err)
	}
	if got, want := len(gotPacket), len(packet); got != want {
		t.Fatalf("captured length = %d, want %d", got, want)
	}
	if got, want := captureInfo.Length, int(originalLength); got != want {
		t.Fatalf("original length = %d, want %d", got, want)
	}
}

func TestPcapWriterRejectsWritesAfterClose(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewPcapWriterInterfaces(
		&output, 65535, []string{"unit-test-interface"}, "",
		logger.New(io.Discard, false),
	)
	if err != nil {
		t.Fatalf("NewPcapWriterInterfaces() error = %v", err)
	}
	if err := writer.Close(); err == nil {
		t.Fatal("Close() error = nil, want empty capture error")
	}
	if err := writer.WritePacket([]byte{1}, time.Now()); err == nil {
		t.Fatal("WritePacket() error = nil after Close()")
	}
	if err := writer.WriteKeyLog([]byte("CLIENT_RANDOM value")); err == nil {
		t.Fatal("WriteKeyLog() error = nil after Close()")
	}
	if err := writer.RegisterInterface("runtime-tun", 42); err == nil {
		t.Fatal("RegisterInterface() error = nil after Close()")
	}
}

func TestPcapWriterCloseIsConcurrentSafe(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewPcapWriterInterfaces(
		&output, 65535, []string{"unit-test-interface"}, "",
		logger.New(io.Discard, false),
	)
	if err != nil {
		t.Fatalf("NewPcapWriterInterfaces() error = %v", err)
	}

	const callers = 8
	errors := make(chan error, callers)
	for range callers {
		go func() {
			errors <- writer.Close()
		}()
	}
	var first error
	for range callers {
		err := <-errors
		if first == nil {
			first = err
		}
		if (err == nil) != (first == nil) || (err != nil && err.Error() != first.Error()) {
			t.Fatalf("concurrent Close() errors differ: first=%v, got=%v", first, err)
		}
	}
}
