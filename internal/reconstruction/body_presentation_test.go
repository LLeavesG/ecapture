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
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestHTTPMessagesShareFlatBodyPresentationJSON(t *testing.T) {
	t.Parallel()
	for name, message := range map[string]any{
		"http2": HTTP2Message{HTTPBodyPresentation: HTTPBodyPresentation{
			ContentDecodeState: "identity",
			BodyText:           "plaintext",
		}},
		"http3": HTTP3Message{HTTPBodyPresentation: HTTPBodyPresentation{
			ContentDecodeState: "identity",
			BodyText:           "plaintext",
		}},
	} {
		encoded, err := json.Marshal(message)
		if err != nil {
			t.Fatalf("%s marshal: %v", name, err)
		}
		text := string(encoded)
		if !strings.Contains(text, `"contentDecodeState":"identity"`) ||
			!strings.Contains(text, `"bodyText":"plaintext"`) ||
			strings.Contains(text, "HTTPBodyPresentation") {
			t.Fatalf("%s presentation is not flat JSON: %s", name, text)
		}
	}
}

func TestPresentHTTPBodyDecodesStandardContentEncodings(t *testing.T) {
	t.Parallel()
	plaintest := []byte("FLOW_PLAINTEXT_中文\n")
	tests := []struct {
		name   string
		coding string
		encode func(*testing.T, []byte) []byte
	}{
		{name: "gzip", coding: "gzip", encode: gzipBody},
		{name: "zlib deflate", coding: "deflate", encode: zlibBody},
		{name: "raw deflate", coding: "deflate", encode: rawDeflateBody},
		{name: "brotli", coding: "br", encode: brotliBody},
		{name: "zstd", coding: "zstd", encode: zstdBody},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			encoded := test.encode(t, plaintest)
			presentation := presentHTTPBody(
				[]HTTP2Header{{
					Name:  "content-encoding",
					Value: test.coding,
				}},
				encoded,
			)
			if presentation.contentDecodeState != "decoded" ||
				!bytes.Equal(presentation.decodedBody, plaintest) ||
				presentation.bodyText != string(plaintest) ||
				presentation.contentDecodeError != "" {
				t.Fatalf("unexpected presentation: %#v", presentation)
			}
		})
	}
}

func TestPresentHTTPBodyPreservesOpaqueApplicationBytes(t *testing.T) {
	t.Parallel()
	body := []byte{0xff, 0x00, 0x80, 0x7f}
	presentation := presentHTTPBody(nil, body)
	if presentation.contentDecodeState != "identity" ||
		presentation.bodyText != "" ||
		presentation.decodedBody != nil {
		t.Fatalf("opaque bytes were transformed: %#v", presentation)
	}
}

func TestPresentHTTPBodyReportsUnsupportedCodingWithoutChangingRawBody(
	t *testing.T,
) {
	t.Parallel()
	body := []byte("opaque-business-payload")
	presentation := presentHTTPBody(
		[]HTTP2Header{{Name: "Content-Encoding", Value: "custom-aead"}},
		body,
	)
	if presentation.contentDecodeState != "error" ||
		presentation.contentDecodeError == "" ||
		presentation.bodyText != "" ||
		presentation.decodedBody != nil {
		t.Fatalf("unexpected presentation: %#v", presentation)
	}
}

func gzipBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func zlibBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zlib.NewWriter(&output)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func rawDeflateBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := flate.NewWriter(&output, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func brotliBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := brotli.NewWriter(&output)
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func zstdBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := zstd.NewWriter(&output)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
