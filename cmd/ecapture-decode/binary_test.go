package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gojue/ecapture/internal/reconstruction"
	"github.com/quic-go/qpack"
	"golang.org/x/net/http2/hpack"
)

func TestBinaryMatchesExistingReconstruction(t *testing.T) {
	binaryPath := filepath.Join(t.TempDir(), "ecapture-decode")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-trimpath", "-o", binaryPath, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	fixtures := map[string][]byte{"http1": syntheticHTTP1(t), "http2": syntheticMultiplexed(t, false), "http3": syntheticMultiplexed(t, true)}
	for protocol, input := range fixtures {
		t.Run(protocol, func(t *testing.T) {
			dir := t.TempDir()
			inputPath := filepath.Join(dir, "events.jsonl")
			if err := os.WriteFile(inputPath, input, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(binaryPath, "decode", "--input", inputPath, "--output-prefix", filepath.Join(dir, "decoded"))
			output, err := command.Output()
			if err != nil {
				t.Fatalf("binary failed: %v %s", err, output)
			}
			var result receipt
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatal(err)
			}
			if result.Decoder.Name != "ecapture-decode" || result.Decoder.Version != "1" || result.Outcome != "decoded" {
				t.Fatalf("identity/outcome: %s", output)
			}
			decoders := map[string]func(io.Reader, io.Writer) error{
				"transactions": func(r io.Reader, w io.Writer) error {
					_, err := reconstruction.ReconstructTransactions(r, w)
					return err
				},
				"websocket":    func(r io.Reader, w io.Writer) error { _, err := reconstruction.ReconstructWebSocket(r, w); return err },
				"correlations": func(r io.Reader, w io.Writer) error { _, err := reconstruction.CorrelateWire(r, w); return err },
			}
			for name, decode := range decoders {
				var expected bytes.Buffer
				if err := decode(bytes.NewReader(input), &expected); err != nil {
					t.Fatal(err)
				}
				actual, err := os.ReadFile(result.Outputs[name].Path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(actual, expected.Bytes()) {
					t.Fatalf("%s differs from existing reconstruction", name)
				}
				if name == "transactions" {
					var tx struct {
						Protocol string `json:"protocol"`
						Complete bool   `json:"complete"`
						Request  struct {
							Body []byte `json:"body"`
						} `json:"request"`
					}
					if err := json.Unmarshal(actual, &tx); err != nil {
						t.Fatal(err)
					}
					if tx.Protocol != protocol || !tx.Complete || !bytes.Equal(tx.Request.Body, []byte{0, 255, 'x'}) {
						t.Fatalf("bad protocol/body: %s", actual)
					}
				}
			}
		})
	}
}

func syntheticMultiplexed(t *testing.T, http3 bool) []byte {
	t.Helper()
	var input bytes.Buffer
	for i := 0; i < 2; i++ {
		headers := [][2]string{{":method", "POST"}, {":path", "/synthetic"}, {":scheme", "https"}, {":authority", "example.test"}}
		if i == 1 {
			headers = [][2]string{{":status", "200"}}
		}
		var encoded bytes.Buffer
		var payload []byte
		body := []byte{0, 255, 'x'}
		if i == 1 {
			body = []byte("OK")
		}
		if http3 {
			encoder := qpack.NewEncoder(&encoded)
			for _, h := range headers {
				if err := encoder.WriteField(qpack.HeaderField{Name: h[0], Value: h[1]}); err != nil {
					t.Fatal(err)
				}
			}
			if encoded.Len() >= 64 {
				t.Fatal("fixture header varint too large")
			}
			payload = append([]byte{1, byte(encoded.Len())}, encoded.Bytes()...)
			payload = append(payload, 0, byte(len(body)))
			payload = append(payload, body...)
		} else {
			encoder := hpack.NewEncoder(&encoded)
			for _, h := range headers {
				if err := encoder.WriteField(hpack.HeaderField{Name: h[0], Value: h[1]}); err != nil {
					t.Fatal(err)
				}
			}
			if i == 0 {
				payload = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
			}
			payload = append(payload, h2Frame(1, 4, encoded.Bytes())...)
			payload = append(payload, h2Frame(0, 1, body)...)
		}
		direction := "WRITE"
		if i == 1 {
			direction = "READ"
		}
		event := map[string]any{"eventType": "tls_plaintext", "captureLayer": "transport", "transport": "tls", "timestamp": i + 1, "pid": 42, "tid": 43, "direction": direction, "dataType": 1 - i, "sslAddr": 4660, "originalLen": len(payload), "capturedLen": len(payload), "dataLen": len(payload), "dataEncoding": "base64", "data": payload}
		if http3 {
			event["eventType"] = "boundary_data"
			event["transport"] = "quic"
			event["contextId"] = 4660
			event["streamId"] = 0
			event["fin"] = true
			event["streamOffset"] = 0
			event["bufferAddr"] = 4096 + i
			event["hookName"] = "synthetic_stream"
		}
		if err := json.NewEncoder(&input).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	return input.Bytes()
}

func h2Frame(kind, flags byte, payload []byte) []byte {
	header := make([]byte, 9)
	size := len(payload)
	header[0] = byte(size >> 16)
	header[1] = byte(size >> 8)
	header[2] = byte(size)
	header[3] = kind
	header[4] = flags
	binary.BigEndian.PutUint32(header[5:], 1)
	return append(header, payload...)
}
