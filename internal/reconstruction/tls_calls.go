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

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

func collectTLSCalls(reader io.Reader) (Summary, []Call, error) {
	var summary Summary
	if reader == nil {
		return summary, nil, fmt.Errorf("TLS call input is nil")
	}
	var reconstructed bytes.Buffer
	callSummary, err := Reconstruct(reader, &reconstructed)
	if err != nil {
		return summary, nil, err
	}
	summary = callSummary

	var calls []Call
	decoder := json.NewDecoder(bufio.NewReader(&reconstructed))
	for {
		var call Call
		if err := decoder.Decode(&call); err != nil {
			if err == io.EOF {
				break
			}
			return summary, nil, fmt.Errorf(
				"decode reconstructed TLS call: %w",
				err,
			)
		}
		genericTLSBoundary := call.SourceType == "boundary_data" &&
			call.CaptureLayer == captureLayerTransport &&
			call.Transport == "tls"
		if call.SourceType != "tls_plaintext" && !genericTLSBoundary ||
			call.CaptureLayer != captureLayerTransport ||
			call.Transport != "tls" ||
			!call.Complete ||
			call.Truncated {
			continue
		}
		if genericTLSBoundary {
			if call.ContextID == 0 {
				continue
			}
			// Generic SSL_read/SSL_write hooks preserve SSL* as ContextID.
			// Normalize it into the identity consumed by HTTP/1, HTTP/2, and
			// WebSocket grouping without changing the captured byte layer.
			call.SSLAddr = call.ContextID
		}
		calls = append(calls, call)
	}
	sort.SliceStable(calls, func(i, j int) bool {
		if calls[i].Timestamp == calls[j].Timestamp {
			return calls[i].CallID < calls[j].CallID
		}
		return calls[i].Timestamp < calls[j].Timestamp
	})
	return summary, calls, nil
}
