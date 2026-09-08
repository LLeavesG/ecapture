// ecapture-decode is an offline-only entry point into the existing parsers.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	ecerrors "github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/reconstruction"
)

type identity struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	GoVersion string `json:"goVersion"`
	Revision  string `json:"revision,omitempty"`
	Modified  string `json:"modified,omitempty"`
}

type artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type receipt struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Status        string              `json:"status"`
	Decoder       identity            `json:"decoder"`
	Input         *artifact           `json:"input,omitempty"`
	Outputs       map[string]artifact `json:"outputs,omitempty"`
	Summaries     map[string]any      `json:"summaries,omitempty"`
	Validation    *inputValidation    `json:"inputValidation,omitempty"`
	Warnings      []string            `json:"warnings,omitempty"`
	Outcome       string              `json:"outcome,omitempty"`
	Error         string              `json:"error,omitempty"`
}

func decoderIdentity() identity {
	result := identity{Name: "ecapture-decode", Version: "1", GoVersion: runtime.Version()}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				result.Revision = setting.Value
			case "vcs.modified":
				result.Modified = setting.Value
			}
		}
	}
	return result
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	result := receipt{SchemaVersion: 1, Status: "error", Decoder: decoderIdentity()}
	var err error
	if len(args) == 1 && args[0] == "version" {
		result.Status = "ok"
	} else if len(args) == 0 || args[0] != "decode" {
		err = ecerrors.New(ecerrors.ErrCodeConfigValidation, "usage: ecapture-decode version | decode --input FILE --output-prefix PREFIX")
	} else {
		flags := flag.NewFlagSet("decode", flag.ContinueOnError)
		flags.SetOutput(stderr)
		input := flags.String("input", "", "existing frozen events JSONL file")
		prefix := flags.String("output-prefix", "", "new output paths prefix; parent directory must exist")
		if err = flags.Parse(args[1:]); err == nil {
			if *input == "" || *input == "-" || *prefix == "" || flags.NArg() != 0 {
				err = ecerrors.New(ecerrors.ErrCodeConfigValidation, "--input FILE and --output-prefix PREFIX required, without positional arguments")
			} else {
				err = decode(*input, *prefix, &result)
			}
		}
	}
	if err != nil {
		result.Error = err.Error()
	}
	if encodeErr := json.NewEncoder(stdout).Encode(result); encodeErr != nil {
		return 1
	}
	if err != nil {
		return 1
	}
	return 0
}

// Snapshot once so every parser and the receipt digest describe identical bytes.
// The host is responsible for freezing the source before invoking this command.
func decode(inputPath, prefix string, result *receipt) (err error) {
	source, err := os.Open(inputPath)
	if err != nil {
		return ecerrors.Wrap(ecerrors.ErrCodeResourceNotFound, "open frozen input", err)
	}
	defer source.Close()
	stat, err := source.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() {
		return ecerrors.New(ecerrors.ErrCodeConfigValidation, "input must be a regular file")
	}
	snapshot, err := os.CreateTemp("", "ecapture-decode-input-*.jsonl")
	if err != nil {
		return err
	}
	defer func() { snapshot.Close(); os.Remove(snapshot.Name()) }()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(snapshot, hash), source)
	if err != nil {
		return err
	}
	result.Input = &artifact{Path: inputPath, SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: size}
	result.Validation = &inputValidation{EventTypes: map[string]int{}, UnknownEventTypes: map[string]int{}, Provenance: map[string]int{}}
	if _, err = snapshot.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err = validateInput(snapshot, result.Validation); err != nil {
		return err
	}
	outputs := map[string]artifact{}
	summaries := map[string]any{}
	created := []string{}
	defer func() {
		if err != nil {
			for _, path := range created {
				os.Remove(path)
			}
		}
	}()
	decoders := []struct {
		name   string
		decode func(io.Reader, io.Writer) (any, error)
	}{
		{"transactions", func(r io.Reader, w io.Writer) (any, error) { return reconstruction.ReconstructTransactions(r, w) }},
		{"websocket", func(r io.Reader, w io.Writer) (any, error) { return reconstruction.ReconstructWebSocket(r, w) }},
		{"correlations", func(r io.Reader, w io.Writer) (any, error) { return reconstruction.CorrelateWire(r, w) }},
	}
	for _, decoder := range decoders {
		if _, err = snapshot.Seek(0, io.SeekStart); err != nil {
			return err
		}
		path := prefix + "." + decoder.name + ".jsonl"
		output, openErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if openErr != nil {
			return ecerrors.Wrap(ecerrors.ErrCodeResourceAllocation, "create new decoder output", openErr)
		}
		created = append(created, path)
		hash.Reset()
		counter := &countWriter{writer: io.MultiWriter(output, hash)}
		summary, decodeErr := decoder.decode(snapshot, counter)
		if decodeErr == nil {
			decodeErr = output.Sync()
		}
		closeErr := output.Close()
		if decodeErr != nil {
			return ecerrors.Wrap(ecerrors.ErrCodeEventDecode, decoder.name+" reconstruction failed", decodeErr)
		}
		if closeErr != nil {
			return closeErr
		}
		outputs[decoder.name] = artifact{Path: path, SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: counter.bytes}
		summaries[decoder.name] = summary
	}
	result.Outcome = "no_supported_records"
	if result.Validation.Events == 0 {
		result.Outcome = "empty_input"
	}
	for _, output := range outputs {
		if output.Bytes > 0 {
			result.Outcome = "decoded"
			break
		}
	}
	if len(result.Validation.UnknownEventTypes) > 0 {
		result.Warnings = append(result.Warnings, "unknown_event_types")
	}
	if transactionSummary, ok := summaries["transactions"].(reconstruction.TransactionSummary); ok && transactionSummary.HTTP1.Reconstruction.CallsIncomplete > 0 {
		result.Warnings = append(result.Warnings, "incomplete_calls")
	}
	result.Status = "ok"
	result.Outputs = outputs
	result.Summaries = summaries
	return nil
}

type countWriter struct {
	writer io.Writer
	bytes  int64
}

func (w *countWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.bytes += int64(n)
	return n, err
}

// Validation describes source records, independently of parser recognition.
type inputValidation struct {
	Events            int            `json:"events"`
	BlankLines        int            `json:"blankLines"`
	EventTypes        map[string]int `json:"eventTypes"`
	UnknownEventTypes map[string]int `json:"unknownEventTypes"`
	Provenance        map[string]int `json:"provenance"`
	LegacyPackets     int            `json:"legacyPackets"`
}

func validateInput(reader io.Reader, summary *inputValidation) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			summary.BlankLines++
			continue
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			return ecerrors.New(ecerrors.ErrCodeEventValidation, fmt.Sprintf("line %d: expected one JSON event object", line))
		}
		var kind string
		if rawKind, present := object["eventType"]; present {
			if err := json.Unmarshal(rawKind, &kind); err != nil || strings.TrimSpace(kind) == "" {
				return ecerrors.New(ecerrors.ErrCodeEventValidation, fmt.Sprintf("line %d: eventType must be a nonempty string", line))
			}
		} else {
			// The existing packet encoder predates the eventType envelope.
			var packet struct {
				Timestamp  uint64
				PacketData []byte
			}
			if err := json.Unmarshal(raw, &packet); err != nil || packet.Timestamp == 0 || len(packet.PacketData) == 0 {
				return ecerrors.New(ecerrors.ErrCodeEventValidation, fmt.Sprintf("line %d: missing eventType and no valid legacy packet envelope", line))
			}
			kind = "@legacy_packet"
			summary.LegacyPackets++
		}
		if kind == "packet" || kind == "@legacy_packet" {
			// Match the fields consumed by the existing offline packet observer.
			// Network protocol recognition remains the observer's responsibility.
			var packet struct {
				Timestamp    uint64
				Pid          uint32
				Uid          uint32
				Flags        uint32
				Direction    uint8
				SocketCookie uint64
				PacketData   []byte
			}
			if err := json.Unmarshal(raw, &packet); err != nil || packet.Timestamp == 0 || len(packet.PacketData) == 0 {
				return ecerrors.New(ecerrors.ErrCodeEventValidation, fmt.Sprintf("line %d: invalid packet envelope (Timestamp and base64 PacketData required)", line))
			}
		}
		var provenance struct {
			CaptureLayer string
			Transport    string
		}
		if err := json.Unmarshal(raw, &provenance); err != nil {
			return ecerrors.New(ecerrors.ErrCodeEventValidation, fmt.Sprintf("line %d: invalid provenance field type", line))
		}
		summary.Events++
		summary.EventTypes[kind]++
		key, _ := json.Marshal([]string{kind, provenance.CaptureLayer, provenance.Transport})
		summary.Provenance[string(key)]++
		switch kind {
		case "tls_plaintext", "boundary_data", "application_data", "@legacy_packet", "packet", "capture_stats", "connection_metadata":
		default:
			summary.UnknownEventTypes[kind]++
		}
	}
	if err := scanner.Err(); err != nil {
		return ecerrors.Wrap(ecerrors.ErrCodeEventValidation, fmt.Sprintf("read event line %d (64 MiB maximum)", line+1), err)
	}
	return nil
}
