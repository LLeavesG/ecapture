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

package profileinspector

import (
	"strings"
	"testing"
)

func TestDecodeRecipeCatalogAndMatchSymbol(t *testing.T) {
	catalog, err := DecodeRecipeCatalog(strings.NewReader(`{
  "version": 1,
  "recipes": [{
    "name": "vendor-stream-send",
    "library_glob": "/data/app/*/libvendor.so",
    "build_id": "0xAABBCCDD",
    "symbol": "vendor_quic_stream_send",
    "family": "vendor-quic",
    "layer": "plaintext",
    "role": "quic-stream-send",
    "confidence": "exact",
    "priority": 95,
    "abi": "ssize_t vendor_quic_stream_send(conn, stream, data, len)",
    "recipe": {
      "direction": "write",
      "capture_on": "return",
      "buffer_arg": 3,
      "length_source": "return",
      "context_arg": 1,
      "stream_arg": 2,
      "max_bytes": 131072
    }
  }]
}`))
	if err != nil {
		t.Fatalf("DecodeRecipeCatalog() error = %v", err)
	}
	if len(catalog.Recipes) != 1 || catalog.Recipes[0].BuildID != "aabbccdd" {
		t.Fatalf("catalog = %#v", catalog)
	}
	got, found := candidateForSymbolInCatalog(
		"vendor_quic_stream_send",
		"/data/app/abc/libvendor.so",
		"aabbccdd",
		catalog,
	)
	if !found || got.family != "vendor-quic" || got.hook == nil ||
		got.hook.BufferArg != 3 || got.hook.StreamArg != 2 {
		t.Fatalf("catalog candidate = %#v, found=%v", got, found)
	}
	if _, found := candidateForSymbolInCatalog(
		"vendor_quic_stream_send",
		"/data/app/abc/libvendor.so",
		"deadbeef",
		catalog,
	); found {
		t.Fatal("catalog recipe should not match a different Build ID")
	}
}

func TestRecipeCatalogRejectsUnsafeOffset(t *testing.T) {
	_, err := DecodeRecipeCatalog(strings.NewReader(`{
  "version": 1,
  "recipes": [{
    "name": "unsafe-offset",
    "offset": "0x1234",
    "family": "private",
    "layer": "plaintext",
    "role": "stream-send",
    "confidence": "exact",
    "priority": 80,
    "recipe": {
      "direction": "write",
      "capture_on": "entry",
      "buffer_arg": 2,
      "length_source": "argument",
      "length_arg": 3
    }
  }]
}`))
	if err == nil || !strings.Contains(err.Error(), "requires build_id") {
		t.Fatalf("DecodeRecipeCatalog() error = %v", err)
	}
}

func TestRecipeCatalogRejectsInvalidHook(t *testing.T) {
	_, err := DecodeRecipeCatalog(strings.NewReader(`{
  "version": 1,
  "recipes": [{
    "name": "bad-hook",
    "symbol": "bad_hook",
    "family": "private",
    "layer": "plaintext",
    "role": "stream-send",
    "confidence": "strong",
    "priority": 80,
    "recipe": {
      "direction": "write",
      "capture_on": "entry",
      "buffer_arg": 13,
      "length_source": "argument",
      "length_arg": 3
    }
  }]
}`))
	if err == nil || !strings.Contains(err.Error(), "buffer_arg") {
		t.Fatalf("DecodeRecipeCatalog() error = %v", err)
	}
}
