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

package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gojue/ecapture/internal/reconstruction"
	"github.com/spf13/cobra"
)

var (
	streamReconstructInput   string
	streamReconstructOutput  string
	streamIncludeSemantic    bool
	streamHTTP1Input         string
	streamHTTP1Output        string
	streamWebSocketInput     string
	streamWebSocketOutput    string
	streamHTTP2Input         string
	streamHTTP2Output        string
	streamQUICInput          string
	streamQUICOutput         string
	streamGQUICInput         string
	streamGQUICOutput        string
	streamHTTP3Input         string
	streamHTTP3Output        string
	streamHTTP3FramesInput   string
	streamHTTP3FramesOutput  string
	streamWireInput          string
	streamWireOutput         string
	streamTransactionsInput  string
	streamTransactionsOutput string
	streamHARInput           string
	streamHAROutput          string
	streamHARWallTimeAnchor  string
)

var streamCmd = &cobra.Command{
	Use:   "stream",
	Short: "Reconstruct and decode structured communication streams.",
}

var streamReconstructCmd = &cobra.Command{
	Use:         "reconstruct",
	Short:       "Reassemble JSON boundary chunks into normalized calls.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes JSON events produced by --event-format=json. TLS, QUIC-stream,
and wire-boundary chunks are reassembled by call identity and chunk offset.
Application semantic/logging events are ignored unless --include-semantic is
set. Every output line is JSON. Incomplete calls retain exact missing ranges,
while opaque custom binary payloads remain lossless base64.`,
	Example: `ecapture stream reconstruct \
  --input capture-events.jsonl \
  --output reconstructed-calls.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamReconstruct,
}

var streamHTTP2Cmd = &cobra.Command{
	Use:         "http2",
	Short:       "Reconstruct HTTP/2 transactions from TLS transport events.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes structured TLS transport events, reassembles split SSL calls,
parses HTTP/2 frames, maintains HPACK state per connection and direction, and
emits request/response transactions. DATA bodies remain exact base64 bytes;
application-layer encryption or encoding is never reversed.`,
	Example: `ecapture stream http2 \
  --input capture-events.jsonl \
  --output http2-transactions.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamHTTP2,
}

var streamHTTP1Cmd = &cobra.Command{
	Use:         "http1",
	Short:       "Reconstruct HTTP/1.x transactions from TLS transport events.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes structured TLS transport events, pairs HTTP/1.0 and HTTP/1.1
requests and responses, and handles split calls, Content-Length, chunked
transfer coding, pipelining, and binary bodies. A response delimited only by
capture EOF is retained but marked incomplete unless a connection-close
boundary was actually observed; capture EOF is never invented as protocol EOF.`,
	Example: `ecapture stream http1 \
  --input capture-events.jsonl \
  --output http1-transactions.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamHTTP1,
}

var streamWebSocketCmd = &cobra.Command{
	Use:         "websocket",
	Short:       "Reconstruct WebSocket messages from TLS transport events.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes structured TLS transport events, locates HTTP/1.1 WebSocket
Upgrade handshakes, parses RFC 6455 frames across split SSL calls, removes the
client masking transform, and joins fragmented data messages. Control frames
are retained as separate records. Compressed and custom binary payloads remain
exact base64 bytes; application decoding is not attempted.`,
	Example: `ecapture stream websocket \
  --input capture-events.jsonl \
  --output websocket-messages.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamWebSocket,
}

var streamQUICCmd = &cobra.Command{
	Use:         "quic",
	Short:       "Reassemble QUIC transport-boundary streams.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes structured QUIC boundary events and groups bytes by process,
connection context, direction, and stream ID. Received STREAM frames use their
explicit byte offsets, including out-of-order and duplicate delivery. Ordered
send calls use labeled inferred offsets. FIN, final offset, gaps, conflicts,
and opaque binary bytes are preserved without packet or business decryption.`,
	Example: `ecapture stream quic \
  --input capture-events.jsonl \
  --output quic-streams.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamQUIC,
}

var streamGQUICCmd = &cobra.Command{
	Use:         "gquic",
	Short:       "Reconstruct legacy gQUIC HTTP transactions.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes QUIC boundary events, sequences legacy gQUIC streams, decodes
HTTP/2 HEADERS and HPACK from reserved stream 3, and joins exact request and
response body bytes from their data streams. This supports deployments such as
Q043 without client private keys because capture occurs at the transport API
boundary after QUIC packet protection and before HTTP body consumption.`,
	Example: `ecapture stream gquic \
  --input capture-events.jsonl \
  --output gquic-transactions.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamGQUIC,
}

var streamHTTP3FramesCmd = &cobra.Command{
	Use:         "http3-frames",
	Short:       "Parse HTTP/3 frames and QPACK streams.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes QUIC boundary events, sequences streams, identifies RFC 9114
control/request/push streams, parses HTTP/3 frame type and length varints, and
preserves DATA, HEADERS, and QPACK instruction bytes losslessly. This command
does not confuse legacy gQUIC stream 3 with IETF HTTP/3 and does not claim
QPACK header semantics until its connection-level state has been decoded.`,
	Example: `ecapture stream http3-frames \
  --input capture-events.jsonl \
  --output http3-records.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamHTTP3Frames,
}

var streamHTTP3Cmd = &cobra.Command{
	Use:         "http3",
	Short:       "Reconstruct HTTP/3 transactions when QPACK is resolvable.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Sequences IETF QUIC streams, parses HTTP/3 HEADERS and DATA frames,
replays captured QPACK encoder instructions using the peer's SETTINGS and
per-byte arrival state, and emits joined request/response transactions.
Static, literal, and complete dynamic-table blocks are decoded. Blocks whose
connection state was missed remain exact with an explicit unresolved status;
no guessed headers or application-object data are substituted.`,
	Example: `ecapture stream http3 \
  --input capture-events.jsonl \
  --output http3-transactions.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamHTTP3,
}

var streamTransactionsCmd = &cobra.Command{
	Use:         "transactions",
	Short:       "Automatically reconstruct every supported HTTP transaction.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Runs the HTTP/1.x, HTTP/2, legacy gQUIC, and IETF HTTP/3 decoders over
the same structured capture, preserves each decoder's exact transaction JSON,
and merges results in capture-time order. Input is securely spooled rather
than loaded into memory, so stdin and large all-traffic captures are
supported. Application-encrypted bodies remain exact base64 bytes.`,
	Example: `ecapture stream transactions \
  --input capture-events.jsonl \
  --output transactions.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamTransactions,
}

var streamHARCmd = &cobra.Command{
	Use:         "har",
	Short:       "Export reconstructed transactions as a HAR 1.2 view.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes JSONL emitted by "stream transactions" and writes a HAR 1.2
compatibility view. Request and response bodies remain byte-exact base64;
application decoding is not attempted. New captures carry a measured wallTime.
For older captures, --wall-time-anchor explicitly supplies the wall time that
corresponds to the first transaction's monotonic timestamp. HAR contains
sensitive headers and bodies; file output is forced to mode 0600.`,
	Example: `ecapture stream har \
  --input transactions.jsonl \
  --output capture.har`,
	Args: cobra.NoArgs,
	RunE: runStreamHAR,
}

var streamWireCmd = &cobra.Command{
	Use:         "correlate-wire",
	Short:       "Correlate custom TLS BIOs with captured network traffic.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes structured packet and wire-boundary events and exactly matches
TLS ciphertext observed at a custom BIO with reassembled TCP/UDP payloads.
Packet matches are network-verified. Exact matches against generic fd hooks are
reported separately as unverified candidates because an fd can be a file or
pipe. No application plaintext or timestamp-only heuristic is used.`,
	Example: `ecapture stream correlate-wire \
  --input capture-events.jsonl \
  --output wire-correlations.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamWireCorrelation,
}

func addStreamIOFlags(
	command *cobra.Command,
	input *string,
	output *string,
	inputDescription string,
	outputDescription string,
) {
	command.Flags().StringVar(input, "input", "-", inputDescription)
	command.Flags().StringVar(output, "output", "", outputDescription)
}

func init() {
	addStreamIOFlags(
		streamReconstructCmd,
		&streamReconstructInput,
		&streamReconstructOutput,
		"structured capture event file; use - for stdin.",
		"write reconstructed JSONL calls; stdout when empty.",
	)
	streamReconstructCmd.Flags().BoolVar(
		&streamIncludeSemantic,
		"include-semantic",
		false,
		"include diagnostic application-semantic events; disabled by default.",
	)
	addStreamIOFlags(
		streamHTTP1Cmd,
		&streamHTTP1Input,
		&streamHTTP1Output,
		"structured TLS capture event file; use - for stdin.",
		"write HTTP/1.x transaction JSONL; stdout when empty.",
	)
	addStreamIOFlags(
		streamHTTP2Cmd,
		&streamHTTP2Input,
		&streamHTTP2Output,
		"structured TLS capture event file; use - for stdin.",
		"write HTTP/2 transaction JSONL; stdout when empty.",
	)
	addStreamIOFlags(
		streamWebSocketCmd,
		&streamWebSocketInput,
		&streamWebSocketOutput,
		"structured TLS capture event file; use - for stdin.",
		"write reconstructed WebSocket message JSONL; stdout when empty.",
	)
	addStreamIOFlags(
		streamQUICCmd,
		&streamQUICInput,
		&streamQUICOutput,
		"structured QUIC boundary event file; use - for stdin.",
		"write reconstructed QUIC stream JSONL; stdout when empty.",
	)
	addStreamIOFlags(
		streamGQUICCmd,
		&streamGQUICInput,
		&streamGQUICOutput,
		"structured QUIC boundary event file; use - for stdin.",
		"write gQUIC HTTP transaction JSONL; stdout when empty.",
	)
	addStreamIOFlags(
		streamHTTP3FramesCmd,
		&streamHTTP3FramesInput,
		&streamHTTP3FramesOutput,
		"structured QUIC boundary event file; use - for stdin.",
		"write HTTP/3 frame and QPACK stream JSONL; stdout when empty.",
	)
	addStreamIOFlags(
		streamHTTP3Cmd,
		&streamHTTP3Input,
		&streamHTTP3Output,
		"structured QUIC boundary event file; use - for stdin.",
		"write HTTP/3 transaction JSONL; stdout when empty.",
	)
	addStreamIOFlags(
		streamTransactionsCmd,
		&streamTransactionsInput,
		&streamTransactionsOutput,
		"structured TLS/QUIC capture event file; use - for stdin.",
		"write time-ordered HTTP transaction JSONL; stdout when empty.",
	)
	addStreamIOFlags(
		streamHARCmd,
		&streamHARInput,
		&streamHAROutput,
		"transaction JSONL file; use - for stdin.",
		"write sensitive HAR with mode 0600; stdout when empty.",
	)
	streamHARCmd.Flags().StringVar(
		&streamHARWallTimeAnchor,
		"wall-time-anchor",
		"",
		"RFC3339Nano wall time of the first transaction (legacy captures only).",
	)
	addStreamIOFlags(
		streamWireCmd,
		&streamWireInput,
		&streamWireOutput,
		"structured wire-boundary event file; use - for stdin.",
		"write BIO-to-wire correlation JSONL; stdout when empty.",
	)
	streamCmd.AddCommand(streamReconstructCmd)
	streamCmd.AddCommand(streamHTTP1Cmd)
	streamCmd.AddCommand(streamHTTP2Cmd)
	streamCmd.AddCommand(streamWebSocketCmd)
	streamCmd.AddCommand(streamQUICCmd)
	streamCmd.AddCommand(streamGQUICCmd)
	streamCmd.AddCommand(streamHTTP3FramesCmd)
	streamCmd.AddCommand(streamHTTP3Cmd)
	streamCmd.AddCommand(streamTransactionsCmd)
	streamCmd.AddCommand(streamHARCmd)
	streamCmd.AddCommand(streamWireCmd)
	rootCmd.AddCommand(streamCmd)
}

func runStreamReconstruct(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command,
		streamReconstructInput,
		streamReconstructOutput,
		"reconstruction",
	)
	if err != nil {
		return err
	}
	defer closeFiles()
	summary, err := reconstruction.ReconstructWithOptions(
		input,
		output,
		reconstruction.Options{IncludeSemantic: streamIncludeSemantic},
	)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"reconstructed %d complete and %d incomplete calls from %d chunks (%d ignored events)\n",
		summary.CallsComplete,
		summary.CallsIncomplete,
		summary.ChunksAccepted,
		summary.EventsIgnored,
	)
	return nil
}

func runStreamHTTP2(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command,
		streamHTTP2Input,
		streamHTTP2Output,
		"HTTP/2",
	)
	if err != nil {
		return err
	}
	defer closeFiles()
	summary, err := reconstruction.ReconstructHTTP2(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"reconstructed %d HTTP/2 transactions from %d frames across %d TLS connections (%d HPACK errors, %d resynchronized bytes)\n",
		summary.Transactions,
		summary.Frames,
		summary.Connections,
		summary.HeaderDecodeError,
		summary.Resynchronized,
	)
	return nil
}

func runStreamHTTP1(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command,
		streamHTTP1Input,
		streamHTTP1Output,
		"HTTP/1",
	)
	if err != nil {
		return err
	}
	defer closeFiles()
	summary, err := reconstruction.ReconstructHTTP1(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"reconstructed %d HTTP/1.x transactions (%d complete) from %d requests and %d responses across %d recognized TLS connections (%d parse/incomplete errors)\n",
		summary.Transactions,
		summary.CompleteTransactions,
		summary.Requests,
		summary.Responses,
		summary.RecognizedConnections,
		summary.ParseErrors,
	)
	return nil
}

func runStreamWebSocket(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command,
		streamWebSocketInput,
		streamWebSocketOutput,
		"WebSocket",
	)
	if err != nil {
		return err
	}
	defer closeFiles()
	summary, err := reconstruction.ReconstructWebSocket(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"reconstructed %d WebSocket messages and %d control frames "+
			"from %d frames across %d upgraded TLS connections "+
			"(%d complete records, %d incomplete, %d parse errors, "+
			"%d opaque trailing bytes)\n",
		summary.Messages,
		summary.ControlFrames,
		summary.Frames,
		summary.UpgradeConnections,
		summary.CompleteRecords,
		summary.IncompleteRecords,
		summary.ParseErrors,
		summary.OpaqueBytes,
	)
	return nil
}

func runStreamQUIC(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command, streamQUICInput, streamQUICOutput, "QUIC")
	if err != nil {
		return err
	}
	defer closeFiles()
	summary, err := reconstruction.ReconstructQUICStreams(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"reconstructed %d QUIC streams across %d connections from %d calls: %d complete, %d finished, %d missing bytes, %d duplicate bytes, %d conflicting bytes\n",
		summary.Streams,
		summary.Connections,
		summary.CallsProcessed,
		summary.CompleteStreams,
		summary.FinishedStreams,
		summary.MissingBytes,
		summary.DuplicateBytes,
		summary.ConflictingBytes,
	)
	return nil
}

func runStreamGQUIC(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command, streamGQUICInput, streamGQUICOutput, "gQUIC")
	if err != nil {
		return err
	}
	defer closeFiles()
	summary, err := reconstruction.ReconstructGQUIC(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"reconstructed %d legacy gQUIC HTTP transactions (%d complete) from %d header frames and %d body streams across %d connections (%d HPACK errors, %d resynchronized bytes)\n",
		summary.Transactions,
		summary.CompleteTransactions,
		summary.Frames,
		summary.BodyStreams,
		summary.Connections,
		summary.HeaderDecodeErrors,
		summary.ResynchronizedBytes,
	)
	return nil
}

func runStreamHTTP3Frames(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command, streamHTTP3FramesInput, streamHTTP3FramesOutput,
		"HTTP/3 frame")
	if err != nil {
		return err
	}
	defer closeFiles()
	summary, err := reconstruction.ReconstructHTTP3Frames(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"parsed %d HTTP/3 frames (%d HEADERS, %d DATA, %d control) and %d QPACK streams from %d QUIC streams across %d connections (%d incomplete records, %d ignored streams)\n",
		summary.Frames,
		summary.HeaderFrames,
		summary.DataFrames,
		summary.ControlFrames,
		summary.QPACKStreams,
		summary.StreamsProcessed,
		summary.Connections,
		summary.IncompleteRecords,
		summary.StreamsIgnored,
	)
	return nil
}

func runStreamHTTP3(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command, streamHTTP3Input, streamHTTP3Output, "HTTP/3")
	if err != nil {
		return err
	}
	defer closeFiles()
	summary, err := reconstruction.ReconstructHTTP3(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"reconstructed %d HTTP/3 transactions (%d complete) across %d connections: %d/%d QPACK blocks decoded (%d dynamic), %d header errors, %d encoder instructions, %d encoder-stream errors, %d DATA frames\n",
		summary.Transactions,
		summary.CompleteTransactions,
		summary.Connections,
		summary.HeaderBlocksDecoded,
		summary.HeaderBlocks,
		summary.DynamicBlocksDecoded,
		summary.HeaderDecodeErrors,
		summary.QPACKInstructions,
		summary.QPACKStreamErrors,
		summary.DataFrames,
	)
	return nil
}

func runStreamTransactions(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command,
		streamTransactionsInput,
		streamTransactionsOutput,
		"transaction",
	)
	if err != nil {
		return err
	}
	defer closeFiles()
	summary, err := reconstruction.ReconstructTransactions(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"reconstructed %d HTTP transactions (%d complete): %d HTTP/1.x, %d HTTP/2, %d legacy gQUIC, %d HTTP/3 from %d input bytes\n",
		summary.Transactions,
		summary.CompleteTransactions,
		summary.HTTP1Transactions,
		summary.HTTP2Transactions,
		summary.GQUICTransactions,
		summary.HTTP3Transactions,
		summary.InputBytes,
	)
	return nil
}

func runStreamHAR(command *cobra.Command, _ []string) error {
	input, output, closeFiles, err := openStreamCommandIO(
		command,
		streamHARInput,
		streamHAROutput,
		"HAR",
	)
	if err != nil {
		return err
	}
	defer closeFiles()
	var options reconstruction.HAROptions
	if streamHARWallTimeAnchor != "" {
		anchor, parseErr := time.Parse(
			time.RFC3339Nano,
			streamHARWallTimeAnchor,
		)
		if parseErr != nil {
			return fmt.Errorf(
				"parse --wall-time-anchor as RFC3339Nano: %w",
				parseErr,
			)
		}
		options.WallTimeAnchor = &anchor
	}
	summary, err := reconstruction.ExportHAR(input, output, options)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"exported %d HTTP transactions (%d complete) to HAR with %d request and %d response body bytes (%d legacy wall-time anchored)\n",
		summary.Transactions,
		summary.CompleteTransactions,
		summary.RequestBodyBytes,
		summary.ResponseBodyBytes,
		summary.LegacyAnchoredEntries,
	)
	return nil
}

func openStreamCommandIO(
	command *cobra.Command,
	inputPath string,
	outputPath string,
	label string,
) (io.Reader, io.Writer, func(), error) {
	var input io.Reader = command.InOrStdin()
	var output io.Writer = command.OutOrStdout()
	var inputFile *os.File
	var outputFile *os.File
	closeFiles := func() {
		if outputFile != nil {
			_ = outputFile.Close()
		}
		if inputFile != nil {
			_ = inputFile.Close()
		}
	}
	if inputPath != "" && inputPath != "-" {
		if outputPath != "" {
			absoluteInput, inputErr := filepath.Abs(inputPath)
			absoluteOutput, outputErr := filepath.Abs(outputPath)
			if inputErr != nil {
				return nil, nil, closeFiles,
					fmt.Errorf("resolve %s input: %w", label, inputErr)
			}
			if outputErr != nil {
				return nil, nil, closeFiles,
					fmt.Errorf("resolve %s output: %w", label, outputErr)
			}
			if filepath.Clean(absoluteInput) == filepath.Clean(absoluteOutput) {
				return nil, nil, closeFiles,
					fmt.Errorf("--input and --output must name different files")
			}
		}
		var err error
		inputFile, err = os.Open(inputPath)
		if err != nil {
			return nil, nil, closeFiles,
				fmt.Errorf("open %s input: %w", label, err)
		}
		input = inputFile
	}
	if outputPath != "" {
		var err error
		outputFile, err = os.OpenFile(
			outputPath,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
			0o600,
		)
		if err != nil {
			closeFiles()
			return nil, nil, func() {},
				fmt.Errorf("open %s output: %w", label, err)
		}
		if err := outputFile.Chmod(0o600); err != nil {
			closeFiles()
			return nil, nil, func() {},
				fmt.Errorf("protect %s output: %w", label, err)
		}
		output = outputFile
	}
	return input, output, closeFiles, nil
}

func runStreamWireCorrelation(command *cobra.Command, _ []string) error {
	var input io.Reader = command.InOrStdin()
	var inputFile *os.File
	if streamWireInput != "" && streamWireInput != "-" {
		if streamWireOutput != "" {
			inputPath, inputErr := filepath.Abs(streamWireInput)
			outputPath, outputErr := filepath.Abs(streamWireOutput)
			if inputErr != nil {
				return fmt.Errorf("resolve wire correlation input: %w", inputErr)
			}
			if outputErr != nil {
				return fmt.Errorf("resolve wire correlation output: %w", outputErr)
			}
			if filepath.Clean(inputPath) == filepath.Clean(outputPath) {
				return fmt.Errorf("--input and --output must name different files")
			}
		}
		var err error
		inputFile, err = os.Open(streamWireInput)
		if err != nil {
			return fmt.Errorf("open wire correlation input: %w", err)
		}
		defer inputFile.Close()
		input = inputFile
	}

	var output io.Writer = command.OutOrStdout()
	var outputFile *os.File
	if streamWireOutput != "" {
		var err error
		outputFile, err = os.OpenFile(
			streamWireOutput,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
			0o600,
		)
		if err != nil {
			return fmt.Errorf("open wire correlation output: %w", err)
		}
		if err := outputFile.Chmod(0o600); err != nil {
			_ = outputFile.Close()
			return fmt.Errorf("protect wire correlation output: %w", err)
		}
		defer outputFile.Close()
		output = outputFile
	}

	summary, err := reconstruction.CorrelateWire(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"correlated %d/%d TLS BIO streams by exact ciphertext content: %d network-verified across %d packet flows, %d unverified fd candidates across %d fd/socket streams (%d ambiguous, %d unmatched, minimum %d bytes)\n",
		summary.Matched,
		summary.TLSBIOStreams,
		summary.WireVerified,
		summary.PacketFlows,
		summary.FDCandidates,
		summary.FDStreams,
		summary.Ambiguous,
		summary.Unmatched,
		summary.MinimumMatchLength,
	)
	return nil
}
