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

package base

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
)

const DefaultPacketAssemblyLimit = 8192

// PacketFragmentKey identifies every perf record emitted for one skb. The
// kernel assigns one monotonic timestamp before emitting its chunks; the
// remaining fields make an accidental same-nanosecond collision fail closed.
type PacketFragmentKey struct {
	Timestamp      uint64
	PID            uint32
	UID            uint32
	InterfaceIndex uint32
	Direction      uint32
	SocketCookie   uint64
	CGroupID       uint64
	PacketLength   uint32
}

// PacketFragment is the exact bounded payload described by the TC metadata.
// CapturedLength is the total number of bytes the kernel intended to emit,
// not the size of this individual fragment.
type PacketFragment struct {
	Key            PacketFragmentKey
	CapturedLength uint32
	Offset         uint32
	Length         uint32
	Count          uint32
	Data           []byte
}

type packetAssembly struct {
	capturedLength uint32
	fragmentCount  uint32
	fragments      map[uint32][]byte
	order          uint64
}

// PacketAssembler publishes data only after every byte from zero through the
// original skb length has arrived exactly once. Pending assemblies remain
// visible through IncompleteEvents so capture shutdown cannot silently turn a
// missing perf fragment into a healthy result.
type PacketAssembler struct {
	mu         sync.Mutex
	limit      int
	nextOrder  uint64
	incomplete uint64
	pending    map[PacketFragmentKey]*packetAssembly
}

func NewPacketAssembler(limit int) *PacketAssembler {
	if limit <= 0 {
		limit = DefaultPacketAssemblyLimit
	}
	return &PacketAssembler{
		limit:   limit,
		pending: make(map[PacketFragmentKey]*packetAssembly),
	}
}

// Add returns ready=false for a valid partial packet. Invalid metadata,
// conflicting duplicates, overlaps, gaps and kernel capture ceilings are
// errors and count as incomplete capture evidence.
func (a *PacketAssembler) Add(fragment PacketFragment) ([]byte, bool, error) {
	if a == nil {
		return nil, false, fmt.Errorf("packet assembler is nil")
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := validatePacketFragment(fragment); err != nil {
		a.failLocked(fragment.Key)
		return nil, false, err
	}
	if fragment.CapturedLength != fragment.Key.PacketLength {
		a.failLocked(fragment.Key)
		return nil, false, fmt.Errorf(
			"kernel packet capture ceiling: captured=%d original=%d",
			fragment.CapturedLength, fragment.Key.PacketLength,
		)
	}
	if fragment.Count == 1 {
		if fragment.Offset != 0 || fragment.Length != fragment.CapturedLength {
			a.failLocked(fragment.Key)
			return nil, false, fmt.Errorf("single packet fragment is not complete")
		}
		return append([]byte(nil), fragment.Data...), true, nil
	}

	assembly := a.pending[fragment.Key]
	if assembly == nil {
		a.evictOldestLocked()
		a.nextOrder++
		assembly = &packetAssembly{
			capturedLength: fragment.CapturedLength,
			fragmentCount:  fragment.Count,
			fragments:      make(map[uint32][]byte, fragment.Count),
			order:          a.nextOrder,
		}
		a.pending[fragment.Key] = assembly
	} else if assembly.capturedLength != fragment.CapturedLength ||
		assembly.fragmentCount != fragment.Count {
		a.failLocked(fragment.Key)
		return nil, false, fmt.Errorf("packet fragment metadata changed during assembly")
	}

	if previous, found := assembly.fragments[fragment.Offset]; found {
		if !bytes.Equal(previous, fragment.Data) {
			a.failLocked(fragment.Key)
			return nil, false, fmt.Errorf("conflicting duplicate packet fragment")
		}
		return nil, false, nil
	}
	for offset, data := range assembly.fragments {
		if rangesOverlap(fragment.Offset, fragment.Length, offset, uint32(len(data))) {
			a.failLocked(fragment.Key)
			return nil, false, fmt.Errorf("overlapping packet fragments")
		}
	}
	assembly.fragments[fragment.Offset] = append([]byte(nil), fragment.Data...)
	if uint32(len(assembly.fragments)) < assembly.fragmentCount {
		return nil, false, nil
	}
	if uint32(len(assembly.fragments)) > assembly.fragmentCount {
		a.failLocked(fragment.Key)
		return nil, false, fmt.Errorf("packet fragment count exceeded metadata")
	}

	offsets := make([]uint32, 0, len(assembly.fragments))
	for offset := range assembly.fragments {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	packet := make([]byte, assembly.capturedLength)
	var cursor uint32
	for _, offset := range offsets {
		data := assembly.fragments[offset]
		if offset != cursor {
			a.failLocked(fragment.Key)
			return nil, false, fmt.Errorf(
				"packet fragment gap: next=%d want=%d", offset, cursor,
			)
		}
		copy(packet[offset:], data)
		cursor += uint32(len(data))
	}
	if cursor != assembly.capturedLength {
		a.failLocked(fragment.Key)
		return nil, false, fmt.Errorf(
			"packet assembly length=%d want=%d", cursor, assembly.capturedLength,
		)
	}
	delete(a.pending, fragment.Key)
	return packet, true, nil
}

func validatePacketFragment(fragment PacketFragment) error {
	if fragment.Key.PacketLength == 0 || fragment.CapturedLength == 0 {
		return fmt.Errorf("packet fragment length is zero")
	}
	if fragment.CapturedLength > fragment.Key.PacketLength {
		return fmt.Errorf("captured packet length exceeds original length")
	}
	if fragment.Count == 0 || fragment.Count > 8 {
		return fmt.Errorf("packet fragment count is outside supported bounds")
	}
	if fragment.Length == 0 || uint32(len(fragment.Data)) != fragment.Length {
		return fmt.Errorf("packet fragment payload length does not match metadata")
	}
	end := uint64(fragment.Offset) + uint64(fragment.Length)
	if end > uint64(fragment.CapturedLength) {
		return fmt.Errorf("packet fragment exceeds captured packet length")
	}
	return nil
}

func rangesOverlap(leftOffset, leftLength, rightOffset, rightLength uint32) bool {
	leftEnd := uint64(leftOffset) + uint64(leftLength)
	rightEnd := uint64(rightOffset) + uint64(rightLength)
	return uint64(leftOffset) < rightEnd && uint64(rightOffset) < leftEnd
}

func (a *PacketAssembler) evictOldestLocked() {
	if len(a.pending) < a.limit {
		return
	}
	var oldestKey PacketFragmentKey
	var oldestOrder uint64
	found := false
	for key, assembly := range a.pending {
		if !found || assembly.order < oldestOrder {
			oldestKey = key
			oldestOrder = assembly.order
			found = true
		}
	}
	if found {
		delete(a.pending, oldestKey)
		a.incomplete++
	}
}

func (a *PacketAssembler) failLocked(key PacketFragmentKey) {
	delete(a.pending, key)
	// Invalid single records and failed multi-record assemblies are both
	// capture integrity failures, even when no partial state existed yet.
	// Dynamic reports this independently from the decoder error counter.
	a.incomplete++
}

func (a *PacketAssembler) IncompleteEvents() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.incomplete + uint64(len(a.pending))
}

func (a *PacketAssembler) PendingEvents() uint64 {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return uint64(len(a.pending))
}
