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
	"encoding/binary"
	"fmt"
	"math"
)

type websocketSummary struct {
	FrameCount  int
	PayloadLen  int
	Masked      bool
	Opcode      uint8
	MixedOpcode bool
}

func (s websocketSummary) description() string {
	if s.FrameCount == 0 {
		return ""
	}
	mask := "unmasked"
	if s.Masked {
		mask = "masked"
	}
	opcode := websocketOpcodeName(s.Opcode)
	if s.MixedOpcode {
		opcode = "mixed"
	}
	return fmt.Sprintf("websocket frames=%d opcode=%s %s payload=%d bytes",
		s.FrameCount, opcode, mask, s.PayloadLen)
}

func websocketOpcodeName(opcode uint8) string {
	switch opcode {
	case 0x0:
		return "continuation"
	case 0x1:
		return "text"
	case 0x2:
		return "binary"
	case 0x8:
		return "close"
	case 0x9:
		return "ping"
	case 0xA:
		return "pong"
	default:
		return fmt.Sprintf("0x%x", opcode)
	}
}

func isSupportedWebSocketOpcode(opcode uint8) bool {
	switch opcode {
	case 0x0, 0x1, 0x2, 0x8, 0x9, 0xA:
		return true
	default:
		return false
	}
}

func decodeWebSocketFrames(data []byte, expectedMasked *bool) ([]byte, websocketSummary, bool) {
	if len(data) < 2 {
		return nil, websocketSummary{}, false
	}

	out := make([]byte, 0, len(data))
	summary := websocketSummary{}
	offset := 0

	for offset < len(data) {
		if len(data)-offset < 2 {
			return nil, websocketSummary{}, false
		}

		first := data[offset]
		second := data[offset+1]
		opcode := first & 0x0F
		masked := second&0x80 != 0
		if !isSupportedWebSocketOpcode(opcode) {
			return nil, websocketSummary{}, false
		}
		if expectedMasked != nil && masked != *expectedMasked {
			return nil, websocketSummary{}, false
		}

		headerLen := 2
		payloadLen := uint64(second & 0x7F)
		switch payloadLen {
		case 126:
			if len(data)-offset < headerLen+2 {
				return nil, websocketSummary{}, false
			}
			payloadLen = uint64(binary.BigEndian.Uint16(data[offset+headerLen : offset+headerLen+2]))
			headerLen += 2
		case 127:
			if len(data)-offset < headerLen+8 {
				return nil, websocketSummary{}, false
			}
			payloadLen = binary.BigEndian.Uint64(data[offset+headerLen : offset+headerLen+8])
			headerLen += 8
		}
		if opcode >= 0x8 && payloadLen > 125 {
			return nil, websocketSummary{}, false
		}
		if payloadLen > math.MaxInt {
			return nil, websocketSummary{}, false
		}

		var maskKey [4]byte
		if masked {
			if len(data)-offset < headerLen+4 {
				return nil, websocketSummary{}, false
			}
			copy(maskKey[:], data[offset+headerLen:offset+headerLen+4])
			headerLen += 4
		}

		payloadEnd := offset + headerLen + int(payloadLen)
		if payloadEnd > len(data) {
			return nil, websocketSummary{}, false
		}

		payload := data[offset+headerLen : payloadEnd]
		if masked {
			start := len(out)
			out = append(out, payload...)
			for i := 0; i < len(payload); i++ {
				out[start+i] ^= maskKey[i%len(maskKey)]
			}
		} else {
			out = append(out, payload...)
		}

		if summary.FrameCount == 0 {
			summary.Masked = masked
			summary.Opcode = opcode
		} else if summary.Opcode != opcode {
			summary.MixedOpcode = true
		}
		summary.FrameCount++
		summary.PayloadLen += len(payload)
		offset = payloadEnd
	}

	if summary.FrameCount == 0 || offset != len(data) {
		return nil, websocketSummary{}, false
	}
	return out, summary, true
}

func decodeWebSocketForDisplay(data []byte, dataType int64) ([]byte, string, bool) {
	if len(data) < 2 {
		return nil, "", false
	}

	wantMasked := true
	if dataType == DataTypeRead {
		wantMasked = false
	}
	decoded, summary, ok := decodeWebSocketFrames(data, &wantMasked)
	if ok {
		return decoded, summary.description(), true
	}
	return nil, "", false
}
