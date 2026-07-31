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
	"sort"

	"github.com/quic-go/qpack"
)

type HTTP3TransactionSummary struct {
	StreamReconstruction QUICStreamSummary `json:"streamReconstruction"`
	Connections          int               `json:"connections"`
	StreamsProcessed     int               `json:"streamsProcessed"`
	Transactions         int               `json:"transactions"`
	CompleteTransactions int               `json:"completeTransactions"`
	HeaderBlocks         int               `json:"headerBlocks"`
	HeaderBlocksDecoded  int               `json:"headerBlocksDecoded"`
	DynamicBlocksDecoded int               `json:"dynamicBlocksDecoded"`
	HeaderDecodeErrors   int               `json:"headerDecodeErrors"`
	QPACKInstructions    int               `json:"qpackInstructions"`
	QPACKStreamErrors    int               `json:"qpackStreamErrors"`
	DataFrames           int               `json:"dataFrames"`
}

type HTTP3Message struct {
	Headers        []HTTP2Header `json:"headers,omitempty"`
	HeaderBlocks   [][]byte      `json:"headerBlocks,omitempty"`
	Body           []byte        `json:"body,omitempty"`
	BodyEncoding   string        `json:"bodyEncoding,omitempty"`
	HeadersDecoded bool          `json:"headersDecoded"`
	QPACKMode      string        `json:"qpackMode,omitempty"`
	EndStream      bool          `json:"endStream"`
	Errors         []string      `json:"errors,omitempty"`
}

type HTTP3Transaction struct {
	EventType           string       `json:"eventType"`
	Protocol            string       `json:"protocol"`
	CaptureLayer        string       `json:"captureLayer"`
	Transport           string       `json:"transport"`
	ConnectionID        string       `json:"connectionId"`
	ContextID           uint64       `json:"contextId"`
	StreamID            uint64       `json:"streamId"`
	Pid                 uint32       `json:"pid"`
	Timestamp           uint64       `json:"timestamp"`
	LastSeen            uint64       `json:"lastSeen"`
	WallTime            string       `json:"wallTime,omitempty"`
	DirectionAssumption string       `json:"directionAssumption"`
	Method              string       `json:"method,omitempty"`
	Scheme              string       `json:"scheme,omitempty"`
	Authority           string       `json:"authority,omitempty"`
	Path                string       `json:"path,omitempty"`
	Status              string       `json:"status,omitempty"`
	Request             HTTP3Message `json:"request"`
	Response            HTTP3Message `json:"response"`
	Complete            bool         `json:"complete"`
	Errors              []string     `json:"errors,omitempty"`
}

// ReconstructHTTP3 converts RFC 9114 request-stream frames into transactions.
// It replays captured QPACK encoder streams with the peer's advertised
// SETTINGS capacity and uses per-byte capture timestamps to resolve Required
// Insert Count wrapping and blocked header blocks. Exact HEADERS payloads are
// retained when capture started too late to contain the required state.
func ReconstructHTTP3(
	reader io.Reader,
	writer io.Writer,
) (HTTP3TransactionSummary, error) {
	var summary HTTP3TransactionSummary
	if writer == nil {
		return summary, fmt.Errorf("HTTP/3 transaction output is nil")
	}
	streamSummary, streams, err := collectQUICStreams(reader)
	if err != nil {
		return summary, err
	}
	summary.StreamReconstruction = streamSummary
	qpackState := buildQPACKCaptureState(streams)
	summary.QPACKInstructions = qpackState.instructions
	summary.QPACKStreamErrors = qpackState.encoderStreamErrors

	gquicConnections := make(map[string]bool)
	for _, stream := range streams {
		if stream.ProtocolHint == "gquic-crypto" ||
			stream.ProtocolHint == "gquic-http-headers" ||
			stream.ProtocolHint == "gquic-http-body" {
			gquicConnections[stream.ConnectionID] = true
		}
	}
	connectionSet := make(map[string]struct{})
	states := make(map[string]*HTTP3Transaction)
	for _, stream := range streams {
		if gquicConnections[stream.ConnectionID] ||
			stream.StreamID&0x2 != 0 ||
			len(stream.Missing) != 0 ||
			stream.Conflicting != 0 ||
			stream.Truncated {
			continue
		}
		records, recognized := parseHTTP3Stream(stream)
		if !recognized {
			continue
		}
		key := fmt.Sprintf("%s:%d", stream.ConnectionID, stream.StreamID)
		transaction := states[key]
		if transaction == nil {
			transaction = &HTTP3Transaction{
				EventType:           "http_transaction",
				Protocol:            "http3",
				CaptureLayer:        captureLayerTransport,
				Transport:           "quic",
				ConnectionID:        stream.ConnectionID,
				ContextID:           stream.ContextID,
				StreamID:            stream.StreamID,
				Pid:                 stream.Pid,
				Timestamp:           stream.Timestamp,
				LastSeen:            stream.LastSeen,
				WallTime:            stream.WallTime,
				DirectionAssumption: "local-client",
			}
			states[key] = transaction
		}
		if stream.Timestamp < transaction.Timestamp {
			transaction.Timestamp = stream.Timestamp
			transaction.WallTime = stream.WallTime
		}
		if stream.LastSeen > transaction.LastSeen {
			transaction.LastSeen = stream.LastSeen
		}
		message := &transaction.Response
		if stream.Direction == "WRITE" {
			message = &transaction.Request
		}
		for _, record := range records {
			if record.FrameType == nil || !record.Complete {
				continue
			}
			switch *record.FrameType {
			case 0:
				message.Body = append(message.Body, record.Data...)
				if len(message.Body) != 0 {
					message.BodyEncoding = "base64"
				}
				summary.DataFrames++
			case 1:
				summary.HeaderBlocks++
				message.HeaderBlocks = append(
					message.HeaderBlocks,
					append([]byte(nil), record.Data...),
				)
				fields, decodeErr := decodeStaticQPACK(record.Data)
				qpackMode := "static-table-and-literals"
				if decodeErr != nil {
					table := qpackState.tables[qpackStateKey(
						stream.ConnectionID,
						stream.Direction,
					)]
					fields, decodeErr = decodeDynamicQPACK(
						record.Data,
						table,
						http3HeaderBlockReadyTimestamp(stream, record),
					)
					if decodeErr == nil {
						qpackMode = "dynamic-table"
						summary.DynamicBlocksDecoded++
					}
				}
				if decodeErr != nil {
					summary.HeaderDecodeErrors++
					message.HeadersDecoded = false
					message.QPACKMode = "exact-block-unresolved"
					appendHTTP3MessageError(message,
						"QPACK state incomplete or block invalid: "+
							decodeErr.Error())
					continue
				}
				summary.HeaderBlocksDecoded++
				message.HeadersDecoded = true
				message.QPACKMode = qpackMode
				for _, field := range fields {
					message.Headers = append(message.Headers, field)
					switch field.Name {
					case ":method":
						transaction.Method = field.Value
					case ":scheme":
						transaction.Scheme = field.Value
					case ":authority":
						transaction.Authority = field.Value
					case ":path":
						transaction.Path = field.Value
					case ":status":
						transaction.Status = field.Value
					}
				}
			}
		}
		if stream.Fin {
			message.EndStream = true
		}
		summary.StreamsProcessed++
		connectionSet[stream.ConnectionID] = struct{}{}
	}
	summary.Connections = len(connectionSet)

	transactions := make([]HTTP3Transaction, 0, len(states))
	for _, transaction := range states {
		transaction.Complete =
			transaction.Request.HeadersDecoded &&
				transaction.Response.HeadersDecoded &&
				transaction.Request.EndStream &&
				transaction.Response.EndStream &&
				len(transaction.Request.Errors) == 0 &&
				len(transaction.Response.Errors) == 0 &&
				len(transaction.Errors) == 0
		if transaction.Complete {
			summary.CompleteTransactions++
		}
		transactions = append(transactions, *transaction)
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
			return summary, fmt.Errorf("write HTTP/3 transaction: %w", err)
		}
		summary.Transactions++
	}
	return summary, nil
}

func decodeStaticQPACK(block []byte) ([]HTTP2Header, error) {
	decoder := qpack.NewDecoder()
	next := decoder.Decode(block)
	var headers []HTTP2Header
	for {
		field, err := next()
		if err != nil {
			if err == io.EOF {
				return headers, nil
			}
			return nil, err
		}
		headers = append(headers, HTTP2Header{
			Name:  field.Name,
			Value: field.Value,
		})
	}
}

func appendHTTP3MessageError(message *HTTP3Message, value string) {
	if len(message.Errors) < 16 {
		message.Errors = append(message.Errors, value)
	}
}
