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
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
)

type GQUICSummary struct {
	StreamReconstruction QUICStreamSummary `json:"streamReconstruction"`
	Connections          int               `json:"connections"`
	HeaderStreams        int               `json:"headerStreams"`
	BodyStreams          int               `json:"bodyStreams"`
	Frames               int               `json:"frames"`
	Transactions         int               `json:"transactions"`
	CompleteTransactions int               `json:"completeTransactions"`
	HeaderDecodeErrors   int               `json:"headerDecodeErrors"`
	ResynchronizedBytes  int               `json:"resynchronizedBytes"`
}

// ReconstructGQUIC reconstructs legacy gQUIC HTTP. Versions such as Q043 put
// HTTP/2 HEADERS frames with HPACK blocks on reserved stream 3, while request
// and response body bytes travel on the stream named by each HEADERS frame.
// All input is already observed at the QUIC transport boundary; no packet key
// or application-object hook is involved.
func ReconstructGQUIC(
	reader io.Reader,
	writer io.Writer,
) (GQUICSummary, error) {
	var summary GQUICSummary
	if writer == nil {
		return summary, fmt.Errorf("gQUIC reconstruction output is nil")
	}
	streamSummary, streams, err := collectQUICStreams(reader)
	if err != nil {
		return summary, err
	}
	summary.StreamReconstruction = streamSummary

	byConnection := make(map[string][]QUICStream)
	for _, stream := range streams {
		byConnection[stream.ConnectionID] = append(
			byConnection[stream.ConnectionID], stream)
	}
	var transactions []HTTP2Transaction
	for connectionID, connectionStreams := range byConnection {
		if !hasGQUICHeaderStream(connectionStreams) {
			continue
		}
		summary.Connections++
		sort.SliceStable(connectionStreams, func(i, j int) bool {
			if connectionStreams[i].Timestamp == connectionStreams[j].Timestamp {
				if connectionStreams[i].Direction == connectionStreams[j].Direction {
					return connectionStreams[i].StreamID <
						connectionStreams[j].StreamID
				}
				return connectionStreams[i].Direction <
					connectionStreams[j].Direction
			}
			return connectionStreams[i].Timestamp <
				connectionStreams[j].Timestamp
		})
		headerSummary := &HTTP2Summary{}
		first := connectionStreams[0]
		connection := newHeaderConnection(
			connectionID,
			Call{
				Pid:       first.Pid,
				ContextID: first.ContextID,
				Timestamp: first.Timestamp,
				WallTime:  first.WallTime,
			},
			headerSummary,
			"gquic-http",
			"quic",
		)
		connection.write.prefaceProcessed = true

		for _, stream := range connectionStreams {
			if stream.StreamID != 3 ||
				len(stream.Missing) != 0 ||
				stream.Conflicting != 0 ||
				stream.Truncated {
				continue
			}
			state := connection.read
			if stream.Direction == "WRITE" {
				state = connection.write
			}
			feedTimestampedQUICStream(state, stream)
			summary.HeaderStreams++
		}
		for _, stream := range connectionStreams {
			if stream.StreamID == 1 || stream.StreamID == 3 {
				continue
			}
			summary.BodyStreams++
			if stream.StreamID > math.MaxUint32 {
				continue
			}
			state := connection.read
			if stream.Direction == "WRITE" {
				state = connection.write
			}
			transaction := state.stream(
				uint32(stream.StreamID), stream.Timestamp)
			message := state.message(transaction)
			if len(stream.Missing) == 0 &&
				stream.Conflicting == 0 &&
				!stream.Truncated {
				message.Body = append(message.Body, stream.Data...)
				if len(message.Body) != 0 {
					message.BodyEncoding = "base64"
				}
			} else {
				state.addStreamError(
					uint32(stream.StreamID),
					stream.Timestamp,
					"body stream is incomplete or conflicting",
				)
			}
			if stream.Fin {
				message.EndStream = true
			}
			if stream.LastSeen > transaction.transaction.LastSeen {
				transaction.transaction.LastSeen = stream.LastSeen
			}
		}
		summary.Frames += headerSummary.Frames
		summary.HeaderDecodeErrors += headerSummary.HeaderDecodeError
		summary.ResynchronizedBytes += headerSummary.Resynchronized
		for _, state := range connection.streams {
			if !state.seen {
				continue
			}
			transaction := state.transaction
			transaction.Complete =
				transaction.Request.HeadersDecoded &&
					transaction.Response.HeadersDecoded &&
					transaction.Request.EndStream &&
					transaction.Response.EndStream &&
					len(transaction.Errors) == 0
			if transaction.Complete {
				summary.CompleteTransactions++
			}
			transactions = append(transactions, transaction)
		}
	}

	sort.Slice(transactions, func(i, j int) bool {
		if transactions[i].Timestamp == transactions[j].Timestamp {
			if transactions[i].ConnectionID == transactions[j].ConnectionID {
				return transactions[i].StreamID < transactions[j].StreamID
			}
			return transactions[i].ConnectionID < transactions[j].ConnectionID
		}
		return transactions[i].Timestamp < transactions[j].Timestamp
	})
	encoder := json.NewEncoder(writer)
	for _, transaction := range transactions {
		if err := encoder.Encode(transaction); err != nil {
			return summary, fmt.Errorf("write gQUIC transaction: %w", err)
		}
		summary.Transactions++
	}
	return summary, nil
}

// feedTimestampedQUICStream preserves the capture-call boundaries carried by
// QUICStream.byteReady. gQUIC multiplexes every request's HEADERS frame on
// stream 3, so feeding the whole reconstructed stream with its first timestamp
// incorrectly assigns the connection's first time to all later requests.
func feedTimestampedQUICStream(
	state *http2DirectionState,
	stream QUICStream,
) {
	if len(stream.Data) == 0 {
		return
	}
	if len(stream.byteReady) != len(stream.Data) {
		state.feed(stream.Data, stream.Timestamp)
		return
	}
	for start := 0; start < len(stream.Data); {
		timestamp := stream.byteReady[start]
		if timestamp == 0 {
			timestamp = stream.Timestamp
		}
		end := start + 1
		for end < len(stream.Data) &&
			stream.byteReady[end] == stream.byteReady[start] {
			end++
		}
		state.feed(stream.Data[start:end], timestamp)
		start = end
	}
}

func hasGQUICHeaderStream(streams []QUICStream) bool {
	for _, stream := range streams {
		if stream.StreamID != 3 || len(stream.Data) < http2FrameHeaderSize {
			continue
		}
		frame, complete, plausible := parseHTTP2Frame(stream.Data)
		if complete && plausible && frame.frameType == http2FrameHeaders {
			return true
		}
	}
	return false
}
