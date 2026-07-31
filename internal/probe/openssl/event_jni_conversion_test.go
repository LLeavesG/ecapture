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
	"encoding/json"
	"fmt"
	"testing"
)

type fakeJNIConversionFilter struct {
	state jniConversionFilterState
	err   error
}

func (f fakeJNIConversionFilter) activate(uint32) (jniConversionFilterState, error) {
	return f.state, f.err
}

func encodeJNIConversionEvent(
	t *testing.T,
	flags uint32,
	capturedLen uint32,
	data []byte,
	includeDataArray bool,
	trailingBytes []byte,
) []byte {
	t.Helper()
	var payload bytes.Buffer
	values := []any{
		uint64(123456),
		uint64(0x70001000),
		uint64(0x70002000),
		uint64(0x71000000),
		uint64(0x72000100),
		uint64(len(data)),
		uint64(len(data)),
		uint64(0),
		uint32(4242),
		uint32(4243),
		uint32(5),
		uint32(JNIConversionPhaseAcquire),
		flags,
		capturedLen,
		uint32(0),
		uint32(len(data)),
	}
	for _, value := range values {
		if err := binary.Write(&payload, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	var comm [TaskCommLen]byte
	copy(comm[:], "doubao")
	if err := binary.Write(&payload, binary.LittleEndian, comm); err != nil {
		t.Fatal(err)
	}
	if includeDataArray {
		var body [MaxDataSize]byte
		copy(body[:], data)
		if err := binary.Write(&payload, binary.LittleEndian, body); err != nil {
			t.Fatal(err)
		}
	}
	if len(trailingBytes) != 0 {
		if _, err := payload.Write(trailingBytes); err != nil {
			t.Fatal(err)
		}
	}
	return payload.Bytes()
}

func TestJNIConversionEventDecodesMetadataOnlyRecord(t *testing.T) {
	payload := encodeJNIConversionEvent(
		t,
		JNIConversionFlagHasBuffer,
		0,
		nil,
		false,
		nil,
	)
	if len(payload) != 112 {
		t.Fatalf("metadata header size = %d, want 112", len(payload))
	}
	event := &JNIConversionEvent{}
	if err := event.DecodeFromBytes(payload); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if event.RoleName() != JNIConversionGetStringUTFChars ||
		event.PhaseName() != "acquire" ||
		len(event.GetData()) != 0 {
		t.Fatalf("decoded metadata event = %#v", event)
	}
}

func TestJNIConversionEventDecodesAndMarshalsPayload(t *testing.T) {
	marker := []byte("JNI-CONVERSION-MARKER")
	payload := encodeJNIConversionEvent(
		t,
		JNIConversionFlagHasBuffer|
			JNIConversionFlagHasLength|
			JNIConversionFlagHasData|
			JNIConversionFlagJoined,
		uint32(len(marker)),
		marker,
		false,
		marker,
	)
	event := &JNIConversionEvent{}
	if err := event.DecodeFromBytes(payload); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !bytes.Equal(event.GetData(), marker) {
		t.Fatalf("captured data = %q, want %q", event.GetData(), marker)
	}
	event.CallerModulePath = "/data/app/pkg/lib/arm64/libnet.so"
	event.CallerModuleOffset = 0x1234
	event.CallerModuleBuildID = "aabbccdd"
	event.CallerFilterJustActivated = true
	event.CallerFilterPendingRules = 2
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if value["eventType"] != "jni_conversion" ||
		value["role"] != JNIConversionGetStringUTFChars ||
		value["phase"] != "acquire" ||
		value["dataEncoding"] != "base64" {
		t.Fatalf("structured event = %s", encoded)
	}
	if value["callerModuleBuildID"] != "aabbccdd" ||
		value["callerFilterJustActivated"] != true ||
		value["callerFilterPendingRules"] != float64(2) {
		t.Fatalf("structured event missing caller metadata = %s", encoded)
	}
}

func TestJNIConversionEventDecodesPaddedMetadataRecord(t *testing.T) {
	payload := encodeJNIConversionEvent(
		t,
		JNIConversionFlagHasBuffer,
		0,
		nil,
		false,
		[]byte{0, 0, 0, 0, 0, 0, 0, 0},
	)
	event := &JNIConversionEvent{}
	if err := event.DecodeFromBytes(payload); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(event.GetData()) != 0 {
		t.Fatalf("metadata event unexpectedly carried payload: %#v", event)
	}
}

func TestJNIConversionEventNormalizesCapturedLengthForLaterChunks(t *testing.T) {
	chunk := bytes.Repeat([]byte("A"), MaxDataSize)
	payload := encodeJNIConversionEvent(
		t,
		JNIConversionFlagHasBuffer|
			JNIConversionFlagHasLength|
			JNIConversionFlagHasData|
			JNIConversionFlagJoined,
		13,
		chunk,
		false,
		chunk,
	)
	// Overwrite chunk_offset to simulate a later segment whose total length
	// lower bound was reported imprecisely by the producer.
	binary.LittleEndian.PutUint32(payload[88:92], uint32(MaxDataSize*3))

	event := &JNIConversionEvent{}
	if err := event.DecodeFromBytes(payload); err != nil {
		t.Fatalf("DecodeFromBytes() error = %v", err)
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	wantCaptured := uint32(MaxDataSize * 4)
	if event.CapturedLen != wantCaptured {
		t.Fatalf("CapturedLen = %d, want %d", event.CapturedLen, wantCaptured)
	}
}

func TestJNIConversionDecoderMarksFilterTransition(t *testing.T) {
	payload := encodeJNIConversionEvent(
		t,
		JNIConversionFlagHasBuffer,
		0,
		nil,
		false,
		nil,
	)
	decoder := &jniConversionDecoder{
		filter: fakeJNIConversionFilter{
			state: jniConversionFilterState{
				JustActivated: true,
			},
		},
	}
	decoded, err := decoder.Decode(nil, payload)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	event := decoded.(*JNIConversionEvent)
	if event.CallerFilterActive ||
		!event.CallerFilterJustActivated ||
		event.CallerFilterPendingRules != 0 {
		t.Fatalf("unexpected filter transition state: %#v", event)
	}
}

func TestJNIConversionDecoderReportsPendingRules(t *testing.T) {
	payload := encodeJNIConversionEvent(
		t,
		JNIConversionFlagHasBuffer,
		0,
		nil,
		false,
		nil,
	)
	decoder := &jniConversionDecoder{
		filter: fakeJNIConversionFilter{
			state: jniConversionFilterState{
				PendingRules: 3,
			},
			err: fmt.Errorf("waiting for late module"),
		},
	}
	decoded, err := decoder.Decode(nil, payload)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	event := decoded.(*JNIConversionEvent)
	if event.CallerFilterActive ||
		event.CallerFilterJustActivated ||
		event.CallerFilterPendingRules != 3 ||
		event.CallerFilterError != "waiting for late module" {
		t.Fatalf("unexpected pending-rule state: %#v", event)
	}
}
