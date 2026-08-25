// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package base

import (
	"bytes"
	"testing"
)

func testPacketKey(length uint32) PacketFragmentKey {
	return PacketFragmentKey{
		Timestamp:      1234,
		PID:            7,
		UID:            1000,
		InterfaceIndex: 11,
		Direction:      1,
		SocketCookie:   22,
		CGroupID:       33,
		PacketLength:   length,
	}
}

func TestPacketAssemblerReassembles65549BytesOutOfOrder(t *testing.T) {
	packet := make([]byte, 65549)
	for i := range packet {
		packet[i] = byte(i % 251)
	}
	assembler := NewPacketAssembler(8)
	key := testPacketKey(uint32(len(packet)))
	fragments := []PacketFragment{
		{Key: key, CapturedLength: uint32(len(packet)), Offset: 0, Length: 60 * 1024, Count: 2, Data: packet[:60*1024]},
		{Key: key, CapturedLength: uint32(len(packet)), Offset: 60 * 1024, Length: uint32(len(packet) - 60*1024), Count: 2, Data: packet[60*1024:]},
	}
	if got, ready, err := assembler.Add(fragments[1]); err != nil || ready || got != nil {
		t.Fatalf("tail Add() = (%d,%t,%v), want pending", len(got), ready, err)
	}
	got, ready, err := assembler.Add(fragments[0])
	if err != nil || !ready || !bytes.Equal(got, packet) {
		t.Fatalf("assembled packet = (%d,%t,%v), want %d bytes", len(got), ready, err, len(packet))
	}
	if assembler.IncompleteEvents() != 0 {
		t.Fatalf("IncompleteEvents() = %d, want 0", assembler.IncompleteEvents())
	}
}

func TestPacketAssemblerDeduplicatesExactFragment(t *testing.T) {
	assembler := NewPacketAssembler(8)
	key := testPacketKey(4)
	first := PacketFragment{Key: key, CapturedLength: 4, Offset: 0, Length: 2, Count: 2, Data: []byte{1, 2}}
	if _, ready, err := assembler.Add(first); err != nil || ready {
		t.Fatalf("first Add() ready=%t error=%v", ready, err)
	}
	if _, ready, err := assembler.Add(first); err != nil || ready {
		t.Fatalf("duplicate Add() ready=%t error=%v", ready, err)
	}
	got, ready, err := assembler.Add(PacketFragment{
		Key: key, CapturedLength: 4, Offset: 2, Length: 2, Count: 2, Data: []byte{3, 4},
	})
	if err != nil || !ready || !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("assembled duplicate packet = (%x,%t,%v)", got, ready, err)
	}
}

func TestPacketAssemblerRejectsConflictGapAndCeiling(t *testing.T) {
	t.Run("conflict", func(t *testing.T) {
		assembler := NewPacketAssembler(8)
		key := testPacketKey(4)
		first := PacketFragment{Key: key, CapturedLength: 4, Offset: 0, Length: 2, Count: 2, Data: []byte{1, 2}}
		_, _, _ = assembler.Add(first)
		first.Data = []byte{9, 9}
		if _, _, err := assembler.Add(first); err == nil {
			t.Fatal("conflicting duplicate should fail")
		}
		if assembler.IncompleteEvents() == 0 {
			t.Fatal("conflicting duplicate should increment incomplete evidence")
		}
	})
	t.Run("gap", func(t *testing.T) {
		assembler := NewPacketAssembler(8)
		key := testPacketKey(5)
		_, _, _ = assembler.Add(PacketFragment{Key: key, CapturedLength: 5, Offset: 0, Length: 2, Count: 2, Data: []byte{1, 2}})
		if _, _, err := assembler.Add(PacketFragment{Key: key, CapturedLength: 5, Offset: 3, Length: 2, Count: 2, Data: []byte{4, 5}}); err == nil {
			t.Fatal("fragment gap should fail")
		}
	})
	t.Run("ceiling", func(t *testing.T) {
		assembler := NewPacketAssembler(8)
		key := testPacketKey(65549)
		if _, _, err := assembler.Add(PacketFragment{
			Key: key, CapturedLength: 60 * 1024, Offset: 0, Length: 1, Count: 1, Data: []byte{1},
		}); err == nil {
			t.Fatal("kernel capture ceiling should fail")
		}
	})
}

func TestPacketAssemblerReportsMissingFinalFragment(t *testing.T) {
	assembler := NewPacketAssembler(8)
	key := testPacketKey(4)
	_, ready, err := assembler.Add(PacketFragment{
		Key: key, CapturedLength: 4, Offset: 0, Length: 2, Count: 2, Data: []byte{1, 2},
	})
	if err != nil || ready {
		t.Fatalf("partial Add() ready=%t error=%v", ready, err)
	}
	if got, want := assembler.IncompleteEvents(), uint64(1); got != want {
		t.Fatalf("IncompleteEvents() = %d, want %d", got, want)
	}
}
