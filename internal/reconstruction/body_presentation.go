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
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const maxPresentedBodyBytes = 64 * 1024 * 1024

type bodyPresentation struct {
	contentEncoding    string
	contentDecodeState string
	contentDecodeError string
	decodedBody        []byte
	bodyText           string
}

// HTTPBodyPresentation is shared by every HTTP reconstruction path. Raw Body
// remains byte-exact; these fields are a bounded display view derived from it.
type HTTPBodyPresentation struct {
	ContentEncoding     string `json:"contentEncoding,omitempty"`
	ContentDecodeState  string `json:"contentDecodeState,omitempty"`
	ContentDecodeError  string `json:"contentDecodeError,omitempty"`
	DecodedBody         []byte `json:"decodedBody,omitempty"`
	DecodedBodyEncoding string `json:"decodedBodyEncoding,omitempty"`
	BodyText            string `json:"bodyText,omitempty"`
}

func presentHTTPBody(
	headers []HTTP2Header,
	body []byte,
) bodyPresentation {
	var presentation bodyPresentation
	if len(body) == 0 {
		return presentation
	}
	presentation.contentEncoding = bodyHeaderValue(headers, "content-encoding")
	decoded := body
	if presentation.contentEncoding == "" ||
		strings.EqualFold(strings.TrimSpace(
			presentation.contentEncoding), "identity") {
		presentation.contentDecodeState = "identity"
	} else {
		var err error
		decoded, err = decodeContentEncodings(
			body,
			presentation.contentEncoding,
		)
		if err != nil {
			presentation.contentDecodeState = "error"
			presentation.contentDecodeError = err.Error()
			return presentation
		}
		presentation.contentDecodeState = "decoded"
		presentation.decodedBody = decoded
	}
	if utf8.Valid(decoded) {
		presentation.bodyText = string(decoded)
	}
	return presentation
}

func bodyHeaderValue(headers []HTTP2Header, name string) string {
	for index := len(headers) - 1; index >= 0; index-- {
		if strings.EqualFold(headers[index].Name, name) {
			return headers[index].Value
		}
	}
	return ""
}

func decodeContentEncodings(body []byte, value string) ([]byte, error) {
	parts := strings.Split(value, ",")
	decoded := append([]byte(nil), body...)
	for index := len(parts) - 1; index >= 0; index-- {
		coding := strings.ToLower(strings.TrimSpace(parts[index]))
		if coding == "" || coding == "identity" {
			continue
		}
		var err error
		decoded, err = decodeOneContentEncoding(decoded, coding)
		if err != nil {
			return nil, fmt.Errorf("decode content-encoding %q: %w", coding, err)
		}
	}
	return decoded, nil
}

func decodeOneContentEncoding(body []byte, coding string) ([]byte, error) {
	switch coding {
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return readPresentedBody(reader)
	case "br":
		return readPresentedBody(brotli.NewReader(bytes.NewReader(body)))
	case "deflate":
		reader, err := zlib.NewReader(bytes.NewReader(body))
		if err == nil {
			defer reader.Close()
			return readPresentedBody(reader)
		}
		raw := flate.NewReader(bytes.NewReader(body))
		defer raw.Close()
		return readPresentedBody(raw)
	case "zstd":
		reader, err := zstd.NewReader(
			bytes.NewReader(body),
			zstd.WithDecoderMaxMemory(maxPresentedBodyBytes),
		)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return readPresentedBody(reader)
	default:
		return nil, fmt.Errorf("unsupported coding")
	}
}

func readPresentedBody(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxPresentedBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPresentedBodyBytes {
		return nil, fmt.Errorf(
			"decoded body exceeds %d-byte safety limit",
			maxPresentedBodyBytes,
		)
	}
	return data, nil
}

func materializeHTTPBody(
	headers []HTTP2Header,
	body []byte,
	target *HTTPBodyPresentation,
) {
	if target == nil {
		return
	}
	presentation := presentHTTPBody(headers, body)
	target.ContentEncoding = presentation.contentEncoding
	target.ContentDecodeState = presentation.contentDecodeState
	target.ContentDecodeError = presentation.contentDecodeError
	target.DecodedBody = presentation.decodedBody
	if len(target.DecodedBody) != 0 {
		target.DecodedBodyEncoding = "base64"
	}
	target.BodyText = presentation.bodyText
}
