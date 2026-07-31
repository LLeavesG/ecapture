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
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const QuicEventProvideData = 1

// QuicEvent reports use of BoringSSL's QUIC handshake API. It intentionally
// records metadata only: SSL_provide_quic_data receives TLS CRYPTO frames, not
// HTTP/3 application plaintext.
//
// C layout:
//
//	struct quic_data_event_t {
//	    u64 timestamp_ns;
//	    u64 ssl_addr;
//	    u64 data_len;
//	    u32 pid;
//	    u32 tid;
//	    u32 level;
//	    u32 event_type;
//	    char comm[TASK_COMM_LEN];
//	};
type QuicEvent struct {
	Timestamp uint64            `json:"timestamp"`
	SSLAddr   uint64            `json:"sslAddr"`
	DataLen   uint64            `json:"dataLen"`
	Pid       uint32            `json:"pid"`
	Tid       uint32            `json:"tid"`
	Level     uint32            `json:"level"`
	EventType uint32            `json:"eventType"`
	Comm      [TaskCommLen]byte `json:"comm"`
}

func (e QuicEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		EventType     string `json:"eventType"`
		CaptureLayer  string `json:"captureLayer"`
		Transport     string `json:"transport"`
		MetadataType  string `json:"metadataType"`
		Timestamp     uint64 `json:"timestamp"`
		SSLAddr       uint64 `json:"sslAddr"`
		DataLen       uint64 `json:"dataLen"`
		Pid           uint32 `json:"pid"`
		Tid           uint32 `json:"tid"`
		Level         uint32 `json:"level"`
		QuicEventType uint32 `json:"quicEventType"`
		Comm          string `json:"comm"`
	}{
		EventType:     "quic_metadata",
		CaptureLayer:  CaptureLayerMetadata,
		Transport:     CaptureTransportQUIC,
		MetadataType:  "tls_crypto_input",
		Timestamp:     e.Timestamp,
		SSLAddr:       e.SSLAddr,
		DataLen:       e.DataLen,
		Pid:           e.Pid,
		Tid:           e.Tid,
		Level:         e.Level,
		QuicEventType: e.EventType,
		Comm:          e.GetComm(),
	})
}

func (e *QuicEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewReader(data)
	fields := []struct {
		name  string
		value any
	}{
		{"Timestamp", &e.Timestamp},
		{"SSLAddr", &e.SSLAddr},
		{"DataLen", &e.DataLen},
		{"Pid", &e.Pid},
		{"Tid", &e.Tid},
		{"Level", &e.Level},
		{"EventType", &e.EventType},
		{"Comm", &e.Comm},
	}
	for _, field := range fields {
		if err := binary.Read(buf, binary.LittleEndian, field.value); err != nil {
			return errors.NewEventDecodeError("openssl.Quic"+field.name, err)
		}
	}
	return nil
}

func (e *QuicEvent) String() string {
	return fmt.Sprintf(
		"[%s] PID:%d TID:%d Comm:%s SSL:0x%x QUIC_CRYPTO_RX (level=%s, %d bytes, http3_plaintext=outside_SSL_read_write)",
		e.eventTime().Format("2006-01-02 15:04:05.000"),
		e.Pid,
		e.Tid,
		e.GetComm(),
		e.SSLAddr,
		quicLevelString(e.Level),
		e.DataLen,
	)
}

func (e *QuicEvent) StringHex() string {
	return e.String()
}

func (e *QuicEvent) Clone() domain.Event {
	clone := *e
	return &clone
}

func (e *QuicEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

func (e *QuicEvent) UUID() string {
	return fmt.Sprintf("quic_%d_%x_%d", e.Pid, e.SSLAddr, e.Timestamp)
}

func (e *QuicEvent) Validate() error {
	if e.EventType != QuicEventProvideData {
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid QUIC event type: %d", e.EventType))
	}
	if e.SSLAddr == 0 {
		return errors.New(errors.ErrCodeEventValidation, "QUIC event has an empty SSL address")
	}
	return nil
}

func (e *QuicEvent) PerfMonoNs() uint64 {
	return e.Timestamp
}

func (e *QuicEvent) GetComm() string {
	return commToString(e.Comm[:])
}

func (e *QuicEvent) eventTime() time.Time {
	offsetNs, err := getClockOffset()
	if err != nil {
		return time.Unix(0, int64(e.Timestamp))
	}
	return time.Unix(0, int64(e.Timestamp)+offsetNs)
}

func quicLevelString(level uint32) string {
	switch level {
	case 0:
		return "initial"
	case 1:
		return "early_data"
	case 2:
		return "handshake"
	case 3:
		return "application"
	default:
		return fmt.Sprintf("unknown_%d", level)
	}
}
