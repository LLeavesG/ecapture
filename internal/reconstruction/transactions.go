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

package reconstruction

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

type TransactionSummary struct {
	InputBytes           int64                   `json:"inputBytes"`
	Transactions         int                     `json:"transactions"`
	CompleteTransactions int                     `json:"completeTransactions"`
	OpenTransactions     int                     `json:"openTransactions"`
	ResetTransactions    int                     `json:"resetTransactions"`
	OrphanTransactions   int                     `json:"orphanTransactions"`
	ErrorTransactions    int                     `json:"errorTransactions"`
	HTTP1Transactions    int                     `json:"http1Transactions"`
	HTTP2Transactions    int                     `json:"http2Transactions"`
	GQUICTransactions    int                     `json:"gquicTransactions"`
	HTTP3Transactions    int                     `json:"http3Transactions"`
	HTTP1                HTTP1Summary            `json:"http1"`
	HTTP2                HTTP2Summary            `json:"http2"`
	GQUIC                GQUICSummary            `json:"gquic"`
	HTTP3                HTTP3TransactionSummary `json:"http3"`
}

type transactionRecord struct {
	raw          json.RawMessage
	protocol     string
	connectionID string
	streamID     uint64
	timestamp    uint64
	lastSeen     uint64
	state        string
}

type transactionMetadata struct {
	Protocol     string `json:"protocol"`
	ConnectionID string `json:"connectionId"`
	StreamID     uint64 `json:"streamId"`
	Timestamp    uint64 `json:"timestamp"`
	LastSeen     uint64 `json:"lastSeen"`
	WallTime     string `json:"wallTime"`
	Complete     bool   `json:"complete"`
	State        string `json:"state"`
}

// ReconstructTransactions automatically runs every implemented HTTP
// transaction decoder over one structured capture, merges their exact JSON
// records, and sorts them by capture time. The input is securely spooled to a
// mode-0600 temporary file so stdin and multi-gigabyte captures do not need to
// be retained in memory.
func ReconstructTransactions(
	reader io.Reader,
	writer io.Writer,
) (TransactionSummary, error) {
	var summary TransactionSummary
	if reader == nil {
		return summary, fmt.Errorf("transaction reconstruction input is nil")
	}
	if writer == nil {
		return summary, fmt.Errorf("transaction reconstruction output is nil")
	}

	input, err := os.CreateTemp("", "ecapture-transaction-input-*.jsonl")
	if err != nil {
		return summary, fmt.Errorf("create private transaction spool: %w", err)
	}
	inputPath := input.Name()
	defer func() {
		_ = input.Close()
		_ = os.Remove(inputPath)
	}()
	if err := input.Chmod(0o600); err != nil {
		return summary, fmt.Errorf("protect transaction spool: %w", err)
	}
	summary.InputBytes, err = io.Copy(input, reader)
	if err != nil {
		return summary, fmt.Errorf("spool transaction input: %w", err)
	}

	var records []transactionRecord
	http1Records, http1Summary, err := runHTTP1TransactionDecoder(input)
	if err != nil {
		return summary, err
	}
	summary.HTTP1 = http1Summary
	summary.HTTP1Transactions = len(http1Records)
	records = append(records, http1Records...)

	http2Records, http2Summary, err := runHTTP2TransactionDecoder(input)
	if err != nil {
		return summary, err
	}
	summary.HTTP2 = http2Summary
	summary.HTTP2Transactions = len(http2Records)
	records = append(records, http2Records...)

	gquicRecords, gquicSummary, err := runGQUICTransactionDecoder(input)
	if err != nil {
		return summary, err
	}
	summary.GQUIC = gquicSummary
	summary.GQUICTransactions = len(gquicRecords)
	records = append(records, gquicRecords...)

	http3Records, http3Summary, err := runHTTP3TransactionDecoder(input)
	if err != nil {
		return summary, err
	}
	summary.HTTP3 = http3Summary
	summary.HTTP3Transactions = len(http3Records)
	records = append(records, http3Records...)

	sort.SliceStable(records, func(i, j int) bool {
		if records[i].timestamp != records[j].timestamp {
			return records[i].timestamp < records[j].timestamp
		}
		if records[i].lastSeen != records[j].lastSeen {
			return records[i].lastSeen < records[j].lastSeen
		}
		if records[i].connectionID != records[j].connectionID {
			return records[i].connectionID < records[j].connectionID
		}
		if records[i].streamID != records[j].streamID {
			return records[i].streamID < records[j].streamID
		}
		return records[i].protocol < records[j].protocol
	})

	for _, record := range records {
		if _, err := writer.Write(record.raw); err != nil {
			return summary, fmt.Errorf("write transaction: %w", err)
		}
		if _, err := writer.Write([]byte{'\n'}); err != nil {
			return summary, fmt.Errorf("terminate transaction record: %w", err)
		}
		switch record.state {
		case transactionStateComplete:
			summary.CompleteTransactions++
		case transactionStateOpen:
			summary.OpenTransactions++
		case transactionStateReset:
			summary.ResetTransactions++
		case transactionStateOrphan:
			summary.OrphanTransactions++
		default:
			summary.ErrorTransactions++
		}
	}
	summary.Transactions = len(records)
	return summary, nil
}

func runHTTP1TransactionDecoder(
	input *os.File,
) ([]transactionRecord, HTTP1Summary, error) {
	var summary HTTP1Summary
	output, cleanup, err := transactionDecoderOutput()
	if err != nil {
		return nil, summary, err
	}
	defer cleanup()
	if err := rewindTransactionInput(input); err != nil {
		return nil, summary, err
	}
	summary, err = ReconstructHTTP1(input, output)
	if err != nil {
		return nil, summary, fmt.Errorf("HTTP/1 transaction decoder: %w", err)
	}
	records, err := readTransactionRecords(output)
	return records, summary, err
}

func runHTTP2TransactionDecoder(
	input *os.File,
) ([]transactionRecord, HTTP2Summary, error) {
	var summary HTTP2Summary
	output, cleanup, err := transactionDecoderOutput()
	if err != nil {
		return nil, summary, err
	}
	defer cleanup()
	if err := rewindTransactionInput(input); err != nil {
		return nil, summary, err
	}
	summary, err = ReconstructHTTP2(input, output)
	if err != nil {
		return nil, summary, fmt.Errorf("HTTP/2 transaction decoder: %w", err)
	}
	records, err := readTransactionRecords(output)
	return records, summary, err
}

func runGQUICTransactionDecoder(
	input *os.File,
) ([]transactionRecord, GQUICSummary, error) {
	var summary GQUICSummary
	output, cleanup, err := transactionDecoderOutput()
	if err != nil {
		return nil, summary, err
	}
	defer cleanup()
	if err := rewindTransactionInput(input); err != nil {
		return nil, summary, err
	}
	summary, err = ReconstructGQUIC(input, output)
	if err != nil {
		return nil, summary, fmt.Errorf("gQUIC transaction decoder: %w", err)
	}
	records, err := readTransactionRecords(output)
	return records, summary, err
}

func runHTTP3TransactionDecoder(
	input *os.File,
) ([]transactionRecord, HTTP3TransactionSummary, error) {
	var summary HTTP3TransactionSummary
	output, cleanup, err := transactionDecoderOutput()
	if err != nil {
		return nil, summary, err
	}
	defer cleanup()
	if err := rewindTransactionInput(input); err != nil {
		return nil, summary, err
	}
	summary, err = ReconstructHTTP3(input, output)
	if err != nil {
		return nil, summary, fmt.Errorf("HTTP/3 transaction decoder: %w", err)
	}
	records, err := readTransactionRecords(output)
	return records, summary, err
}

func transactionDecoderOutput() (
	*os.File,
	func(),
	error,
) {
	output, err := os.CreateTemp("", "ecapture-transaction-output-*.jsonl")
	if err != nil {
		return nil, nil, fmt.Errorf(
			"create private transaction decoder output: %w", err)
	}
	path := output.Name()
	cleanup := func() {
		_ = output.Close()
		_ = os.Remove(path)
	}
	if err := output.Chmod(0o600); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf(
			"protect transaction decoder output: %w", err)
	}
	return output, cleanup, nil
}

func rewindTransactionInput(input *os.File) error {
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind transaction input: %w", err)
	}
	return nil
}

func readTransactionRecords(
	output *os.File,
) ([]transactionRecord, error) {
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind transaction decoder output: %w", err)
	}
	decoder := json.NewDecoder(output)
	var records []transactionRecord
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode transaction output: %w", err)
		}
		var metadata transactionMetadata
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return nil, fmt.Errorf("decode transaction metadata: %w", err)
		}
		if metadata.Protocol == "" {
			return nil, fmt.Errorf(
				"transaction output is missing protocol provenance")
		}
		state := metadata.State
		if state == "" {
			if metadata.Complete {
				state = transactionStateComplete
			} else {
				state = transactionStateError
			}
		}
		records = append(records, transactionRecord{
			raw:          append(json.RawMessage(nil), raw...),
			protocol:     metadata.Protocol,
			connectionID: metadata.ConnectionID,
			streamID:     metadata.StreamID,
			timestamp:    metadata.Timestamp,
			lastSeen:     metadata.LastSeen,
			state:        state,
		})
	}
	return records, nil
}
