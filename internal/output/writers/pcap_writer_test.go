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
	if err := writer.WritePacketForInterface(packet, wantTime, 999999, true); err != nil {
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
