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

package reconstruction

const (
	transactionStateComplete = "complete"
	transactionStateOpen     = "open"
	transactionStateReset    = "reset"
	transactionStateOrphan   = "orphan"
	transactionStateError    = "error"
)

// classifyTransactionState keeps capture-horizon state separate from byte
// loss. An open request has no observed protocol terminal yet; it is not an
// incomplete capture. Orphan and error remain strict integrity failures.
func classifyTransactionState(
	complete bool,
	requestObserved bool,
	responseObserved bool,
	reset bool,
	hasErrors bool,
) string {
	switch {
	case complete:
		return transactionStateComplete
	case hasErrors:
		return transactionStateError
	case reset:
		return transactionStateReset
	case !requestObserved && responseObserved:
		return transactionStateOrphan
	case requestObserved:
		return transactionStateOpen
	default:
		return transactionStateError
	}
}

func http2MessageObserved(message HTTP2Message) bool {
	return message.HeadersDecoded || len(message.Headers) != 0 ||
		len(message.Body) != 0 || message.EndStream
}

func http3MessageObserved(message HTTP3Message) bool {
	return message.HeadersDecoded || len(message.Headers) != 0 ||
		len(message.HeaderBlocks) != 0 || len(message.Body) != 0 ||
		message.EndStream
}
