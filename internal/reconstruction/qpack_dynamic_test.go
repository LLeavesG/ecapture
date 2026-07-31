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

import "testing"

func TestDecodeQPACKRequiredInsertCount(t *testing.T) {
	testCases := []struct {
		required uint64
		max      uint64
		total    uint64
	}{
		{0, 0, 0},
		{0, 100, 500},
		{15, 100, 25},
		{20, 100, 10},
		{90, 100, 110},
		{234, 100, 180},
		{5678, 100, 5701},
		{401, 100, 500},
		{600, 100, 500},
	}
	for _, testCase := range testCases {
		encoded := uint64(0)
		if testCase.required != 0 {
			encoded = testCase.required%(2*testCase.max) + 1
		}
		decoded, err := decodeQPACKRequiredInsertCount(
			encoded, testCase.max, testCase.total)
		if err != nil {
			t.Fatalf("decode required=%d max=%d total=%d: %v",
				testCase.required, testCase.max, testCase.total, err)
		}
		if decoded != testCase.required {
			t.Fatalf("decode required=%d max=%d total=%d got %d",
				testCase.required, testCase.max, testCase.total, decoded)
		}
	}
}

func TestDecodeQPACKRequiredInsertCountRejectsInvalid(t *testing.T) {
	testCases := []struct {
		encoded uint64
		max     uint64
		total   uint64
	}{
		{1, 0, 0},
		{9, 0, 0},
		{1, 10, 2},
		{18, 10, 2},
		{400, 100, 500},
		{601, 100, 500},
	}
	for _, testCase := range testCases {
		if decoded, err := decodeQPACKRequiredInsertCount(
			testCase.encoded, testCase.max, testCase.total); err == nil {
			t.Fatalf("invalid encoded=%d max=%d total=%d decoded as %d",
				testCase.encoded, testCase.max, testCase.total, decoded)
		}
	}
}

func TestDecodeQPACKHuffmanString(t *testing.T) {
	// QPACK/HPACK Huffman bytes 94 e7 decode to "foo".
	value, consumed, err := decodeQPACKString(
		[]byte{0x82, 0x94, 0xe7}, 7, 0x80)
	if err != nil {
		t.Fatal(err)
	}
	if value != "foo" || consumed != 3 {
		t.Fatalf("got value=%q consumed=%d", value, consumed)
	}
}

func TestDecodeDynamicQPACKAllowsInitiallyBlockedBlock(t *testing.T) {
	table := &qpackDynamicTable{
		maxCapacity: 128,
		capacity:    128,
		entries: []qpackDynamicEntry{{
			Name:  ":path",
			Value: "/blocked",
			Ready: 20,
			Size:  45,
		}},
		active: []uint64{0},
		size:   45,
	}
	// Encoded Required Insert Count 2 resolves to absolute insert count 1.
	// The header arrives at timestamp 10 before the insertion at timestamp 20,
	// so the decoder must model a blocked stream and resume from captured
	// encoder history instead of rejecting it as missing state.
	headers, err := decodeDynamicQPACK(
		[]byte{2, 0, 0x80}, table, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 1 ||
		headers[0] != (HTTP2Header{Name: ":path", Value: "/blocked"}) {
		t.Fatalf("unexpected headers: %#v", headers)
	}
}
