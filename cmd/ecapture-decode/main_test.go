package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func syntheticHTTP1(t *testing.T) []byte {
	t.Helper()
	var input bytes.Buffer
	for i, payload := range []string{
		"POST /synthetic HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\n\x00\xffx",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
	} {
		direction := "WRITE"
		if i == 1 {
			direction = "READ"
		}
		err := json.NewEncoder(&input).Encode(map[string]any{
			"eventType": "tls_plaintext", "captureLayer": "transport", "transport": "tls",
			"timestamp": i + 1, "pid": 42, "tid": 43, "direction": direction, "dataType": 1 - i,
			"sslAddr": 4660, "originalLen": len(payload), "capturedLen": len(payload),
			"dataLen": len(payload), "dataEncoding": "base64", "data": []byte(payload),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return input.Bytes()
}

func TestDecodeSyntheticHTTPAndReceipt(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "events.jsonl")
	data := syntheticHTTP1(t)
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"decode", "--input", input, "--output-prefix", filepath.Join(dir, "decoded")}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d receipt=%s stderr=%s", code, &stdout, &stderr)
	}
	var result receipt
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(data)
	if result.Status != "ok" || result.Input.SHA256 != hex.EncodeToString(expected[:]) || len(result.Outputs) != 3 {
		t.Fatalf("receipt: %+v", result)
	}
	for name, artifact := range result.Outputs {
		output, err := os.ReadFile(artifact.Path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(output)
		if artifact.Bytes != int64(len(output)) || artifact.SHA256 != hex.EncodeToString(digest[:]) {
			t.Fatal("output digest mismatch")
		}
		stat, err := os.Stat(artifact.Path)
		if err != nil {
			t.Fatal(err)
		}
		if stat.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe mode: %v", stat.Mode())
		}
		if name == "transactions" {
			var tx struct {
				Path     string `json:"path"`
				Complete bool   `json:"complete"`
				Request  struct {
					Body []byte `json:"body"`
				} `json:"request"`
			}
			if err := json.Unmarshal(output, &tx); err != nil {
				t.Fatalf("%v: %s", err, output)
			}
			if tx.Path != "/synthetic" || !tx.Complete || !bytes.Equal(tx.Request.Body, []byte{0, 255, 'x'}) {
				t.Fatalf("unexpected transaction: %s", output)
			}
		}
	}
}

func TestDecodeRefusesOverwriteAndCleansPartialFiles(t *testing.T) {
	dir := t.TempDir()
	input, prefix := filepath.Join(dir, "events.jsonl"), filepath.Join(dir, "decoded")
	if err := os.WriteFile(input, syntheticHTTP1(t), 0o600); err != nil {
		t.Fatal(err)
	}
	sentinel := prefix + ".websocket.jsonl"
	if err := os.WriteFile(sentinel, []byte("existing evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if code := run([]string{"decode", "--input", input, "--output-prefix", prefix}, &stdout, &bytes.Buffer{}); code == 0 {
		t.Fatal("expected failure")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "existing evidence" {
		t.Fatal("existing evidence changed")
	}
	if _, err := os.Stat(prefix + ".transactions.jsonl"); !os.IsNotExist(err) {
		t.Fatal("partial file left behind")
	}
	var result receipt
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "error" || result.Error == "" || len(result.Outputs) != 0 {
		t.Fatalf("invalid error receipt: %+v", result)
	}
}

func TestMalformedInputIsAnError(t *testing.T) {
	dir := t.TempDir()
	input, prefix := filepath.Join(dir, "events.jsonl"), filepath.Join(dir, "decoded")
	if err := os.WriteFile(input, []byte("{broken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if code := run([]string{"decode", "--input", input, "--output-prefix", prefix}, &stdout, &bytes.Buffer{}); code == 0 {
		t.Fatal("expected malformed input error")
	}
	if _, err := os.Stat(prefix + ".transactions.jsonl"); !os.IsNotExist(err) {
		t.Fatal("partial file left behind")
	}
}

func TestInputContract(t *testing.T) {
	tests := []struct {
		name, input, outcome string
		failure              bool
		events, unknown      int
	}{
		{"empty", "", "empty_input", false, 0, 0},
		{"whitespace", " \n\t\n", "empty_input", false, 0, 0},
		{"unknown", "{\"eventType\":\"future_diagnostic\",\"captureLayer\":\"semantic\"}\n", "no_supported_records", false, 1, 1},
		{"missing_type", "{}\n", "", true, 0, 0},
		{"null", "null\n", "", true, 0, 0},
		{"array", "[]\n", "", true, 0, 0},
		{"string", "\"hello\"\n", "", true, 0, 0},
		{"number", "42\n", "", true, 0, 0},
		{"invalid_json", "{oops\n", "", true, 0, 0},
		{"partial_json", "{\"eventType\":", "", true, 0, 0},
		{"null_type", "{\"eventType\":null}\n", "", true, 0, 0},
		{"number_type", "{\"eventType\":7}\n", "", true, 0, 0},
		{"incomplete_event", "{\"eventType\":\"tls_plaintext\"}\n", "", true, 0, 0},
		{"two_objects_one_line", "{\"eventType\":\"x\"}{\"eventType\":\"y\"}\n", "", true, 0, 0},
		{"legacy_missing_timestamp", "{\"PacketData\":\"AAAA\"}\n", "", true, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "events.jsonl")
			if err := os.WriteFile(input, []byte(tt.input), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			code := run([]string{"decode", "--input", input, "--output-prefix", filepath.Join(dir, "decoded")}, &stdout, &bytes.Buffer{})
			var result receipt
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if (code != 0) != tt.failure {
				t.Fatalf("code %d receipt %s", code, &stdout)
			}
			if tt.failure {
				if result.Status != "error" || len(result.Outputs) > 0 {
					t.Fatalf("bad failure receipt: %s", &stdout)
				}
				paths, _ := filepath.Glob(filepath.Join(dir, "decoded.*"))
				if len(paths) > 0 {
					t.Fatal("outputs survived failure")
				}
			} else {
				if result.Outcome != tt.outcome || result.Validation.Events != tt.events || len(result.Validation.UnknownEventTypes) != tt.unknown {
					t.Fatalf("bad outcome: %s", &stdout)
				}
			}
		})
	}
}

func TestOpaqueAndIncompleteEvidenceAreNotEmptyInput(t *testing.T) {
	for _, scenario := range []string{"opaque", "incomplete", "incomplete_http", "invalid_base64", "invalid_length"} {
		t.Run(scenario, func(t *testing.T) {
			var event map[string]any
			if err := json.Unmarshal(bytes.Split(syntheticHTTP1(t), []byte("\n"))[0], &event); err != nil {
				t.Fatal(err)
			}
			payload := []byte("POST /synthetic HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\n\x00\xffx")
			switch scenario {
			case "opaque":
				payload = []byte{0, 255, 1, 2}
				event["originalLen"] = len(payload)
				event["capturedLen"] = len(payload)
			case "incomplete", "incomplete_http":
				payload = payload[:len(payload)-1]
				if scenario == "incomplete_http" {
					event["originalLen"] = len(payload)
					event["capturedLen"] = len(payload)
				}
			}
			event["data"] = payload
			event["dataLen"] = len(payload)
			if scenario == "invalid_base64" {
				event["data"] = "%%%invalid%%%"
			}
			if scenario == "invalid_length" {
				event["dataLen"] = len(payload) + 1
			}
			input, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			inputPath := filepath.Join(dir, "events.jsonl")
			if err := os.WriteFile(inputPath, input, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			code := run([]string{"decode", "--input", inputPath, "--output-prefix", filepath.Join(dir, "decoded")}, &stdout, &bytes.Buffer{})
			var result receipt
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if scenario == "invalid_base64" || scenario == "invalid_length" {
				if code == 0 || result.Status != "error" {
					t.Fatalf("corrupt evidence accepted: %s", &stdout)
				}
				return
			}
			if code != 0 || result.Validation.Events != 1 || result.Outcome == "empty_input" {
				t.Fatalf("incorrect receipt: %s", &stdout)
			}
			if scenario == "opaque" && result.Outcome != "no_supported_records" {
				t.Fatalf("opaque evidence mislabeled: %s", &stdout)
			}
			if scenario == "incomplete_http" {
				output, err := os.ReadFile(result.Outputs["transactions"].Path)
				if err != nil {
					t.Fatal(err)
				}
				var transaction struct {
					Complete bool `json:"complete"`
				}
				if err := json.Unmarshal(output, &transaction); err != nil {
					t.Fatalf("missing partial HTTP transaction: %v %s", err, output)
				}
				if transaction.Complete {
					t.Fatal("incomplete HTTP claimed complete")
				}
			}

			if scenario == "incomplete" {
				found := false
				for _, warning := range result.Warnings {
					if warning == "incomplete_calls" {
						found = true
					}
				}
				if !found || result.Outcome != "no_supported_records" {
					t.Fatalf("missing incomplete evidence warning: %s", &stdout)
				}
			}
		})
	}
}

func TestKnownMetadataAndPacketEnvelopes(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		failure     bool
	}{
		{"stats_only", `{"eventType":"capture_stats","captureLayer":"metadata","reader":"synthetic","received":0}` + "\n", false},
		{"packet_only", `{"eventType":"packet","captureLayer":"wire","transport":"unknown","Timestamp":1,"PacketData":"AAAA"}` + "\n", false},
		{"packet_missing_data", `{"eventType":"packet","Timestamp":1}` + "\n", true},
		{"packet_bad_base64", `{"eventType":"packet","Timestamp":1,"PacketData":"%%%"}` + "\n", true},
		{"packet_invalid_direction", `{"eventType":"packet","Timestamp":1,"PacketData":"AAAA","Direction":"WRITE"}` + "\n", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "events.jsonl")
			if err := os.WriteFile(input, []byte(tt.input), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			code := run([]string{"decode", "--input", input, "--output-prefix", filepath.Join(dir, "decoded")}, &stdout, &bytes.Buffer{})
			var result receipt
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if (code != 0) != tt.failure {
				t.Fatalf("incorrect exit: %d %s", code, &stdout)
			}
			if tt.failure {
				return
			}
			if result.Outcome != "no_supported_records" || result.Validation.Events != 1 || len(result.Validation.UnknownEventTypes) != 0 || len(result.Warnings) != 0 {
				t.Fatalf("known metadata or packet incorrectly labeled: %s", &stdout)
			}
		})
	}
}

func TestConnectionMetadataPreservesProvenanceWithoutTransactions(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "events.jsonl")
	data := []byte(`{"eventType":"connection_metadata","captureLayer":"metadata","transport":"tcp","pid":42,"timestamp":1,"fd":3,"tuple":"127.0.0.1:40000-127.0.0.1:18080"}` + "\n")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if code := run([]string{"decode", "--input", input, "--output-prefix", filepath.Join(dir, "decoded")}, &stdout, &bytes.Buffer{}); code != 0 {
		t.Fatalf("decode failed: %s", &stdout)
	}
	var result receipt
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "no_supported_records" || result.Validation.Events != 1 || result.Validation.EventTypes["connection_metadata"] != 1 || result.Validation.Provenance[`["connection_metadata","metadata","tcp"]`] != 1 || len(result.Validation.UnknownEventTypes) != 0 || len(result.Warnings) != 0 {
		t.Fatalf("connection metadata was discarded or mislabeled: %s", &stdout)
	}
	for name, output := range result.Outputs {
		if output.Bytes != 0 {
			t.Fatalf("metadata invented %s output: %+v", name, output)
		}
	}
}
