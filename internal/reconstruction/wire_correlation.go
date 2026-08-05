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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
)

const (
	wireCorrelationAnchor   = 32
	wireCorrelationMinimum  = 64
	wireCorrelationMaxIndex = 4
)

type WireCorrelationSummary struct {
	Reconstruction     Summary `json:"reconstruction"`
	TLSBIOStreams      int     `json:"tlsBioStreams"`
	PacketFlows        int     `json:"packetFlows"`
	FDStreams          int     `json:"fdStreams"`
	Matched            int     `json:"matched"`
	WireVerified       int     `json:"wireVerified"`
	FDCandidates       int     `json:"fdCandidates"`
	Ambiguous          int     `json:"ambiguous"`
	Unmatched          int     `json:"unmatched"`
	CallsIgnored       int     `json:"callsIgnored"`
	MinimumMatchLength int     `json:"minimumMatchLength"`
}

// WireCorrelation joins a custom TLS BIO to a socket descriptor by exact
// ciphertext content. No timing heuristic or application plaintext is used.
type WireCorrelation struct {
	EventType          string  `json:"eventType"`
	CaptureLayer       string  `json:"captureLayer"`
	Transport          string  `json:"transport"`
	TargetKind         string  `json:"targetKind"`
	Method             string  `json:"method"`
	Pid                uint32  `json:"pid"`
	Direction          string  `json:"direction"`
	BIOAddr            uint64  `json:"bioAddr"`
	Fd                 uint32  `json:"fd,omitempty"`
	Tuple              string  `json:"tuple,omitempty"`
	SocketCookie       uint64  `json:"socketCookie,omitempty"`
	NetworkVerified    bool    `json:"networkVerified"`
	TLSCiphertextBytes int     `json:"tlsCiphertextBytes"`
	WireBytes          int     `json:"wireBytes,omitempty"`
	FDPayloadBytes     int     `json:"fdPayloadBytes,omitempty"`
	MatchedBytes       int     `json:"matchedBytes"`
	Coverage           float64 `json:"coverage"`
	BIOOffset          int     `json:"bioOffset"`
	TargetOffset       int     `json:"targetOffset"`
	FirstSeen          uint64  `json:"firstSeen"`
	LastSeen           uint64  `json:"lastSeen"`
	Confidence         string  `json:"confidence"`
	Ambiguous          bool    `json:"ambiguous,omitempty"`
}

type wireSequenceKey struct {
	pid       uint32
	direction string
	context   uint64
	role      string
	transport string
}

type wireSequence struct {
	key       wireSequenceKey
	calls     []Call
	data      []byte
	firstSeen uint64
	lastSeen  uint64
}

type wireMatch struct {
	sourceOffset int
	targetOffset int
	length       int
}

type wireCandidate struct {
	target *wireSequence
	match  wireMatch
}

type wirePacketCandidate struct {
	target *wirePacketRun
	match  wireMatch
}

type wireDirectionKey struct {
	pid       uint32
	direction string
}

// CorrelateWire consumes structured capture events and first attempts to match
// custom TLS BIO ciphertext directly to reassembled TCP/UDP packet payloads.
// Generic fd hooks are retained only as explicitly unverified fallback
// candidates: exact equality with a file descriptor does not prove that the
// descriptor was a socket.
func CorrelateWire(
	reader io.Reader,
	writer io.Writer,
) (WireCorrelationSummary, error) {
	var summary WireCorrelationSummary
	summary.MinimumMatchLength = wireCorrelationMinimum
	if reader == nil {
		return summary, fmt.Errorf("wire correlation input is nil")
	}
	if writer == nil {
		return summary, fmt.Errorf("wire correlation output is nil")
	}

	var reconstructed bytes.Buffer
	packetCollector := newWirePacketCollector()
	callSummary, err := reconstructWithObserver(
		reader,
		&reconstructed,
		Options{},
		packetCollector.observe,
	)
	if err != nil {
		return summary, err
	}
	summary.Reconstruction = callSummary

	sequences := make(map[wireSequenceKey]*wireSequence)
	decoder := json.NewDecoder(bufio.NewReader(&reconstructed))
	for {
		var call Call
		if err := decoder.Decode(&call); err != nil {
			if err == io.EOF {
				break
			}
			return summary, fmt.Errorf("decode reconstructed wire call: %w", err)
		}
		if !call.Complete || call.Truncated ||
			call.CaptureLayer != captureLayerWire ||
			(call.BoundaryRole != boundaryTLSCiphertext &&
				call.BoundaryRole != boundarySocketPayload &&
				call.BoundaryRole != boundaryFDPayload) ||
			call.ContextID == 0 ||
			len(call.Data) == 0 {
			summary.CallsIgnored++
			continue
		}
		key := wireSequenceKey{
			pid:       call.Pid,
			direction: call.Direction,
			context:   call.ContextID,
			role:      call.BoundaryRole,
			transport: call.Transport,
		}
		sequence := sequences[key]
		if sequence == nil {
			sequence = &wireSequence{key: key}
			sequences[key] = sequence
		}
		sequence.calls = append(sequence.calls, call)
	}

	var sources []*wireSequence
	var targets []*wireSequence
	for _, sequence := range sequences {
		sort.SliceStable(sequence.calls, func(i, j int) bool {
			if sequence.calls[i].Timestamp == sequence.calls[j].Timestamp {
				return sequence.calls[i].CallID < sequence.calls[j].CallID
			}
			return sequence.calls[i].Timestamp < sequence.calls[j].Timestamp
		})
		for _, call := range sequence.calls {
			if sequence.firstSeen == 0 || call.Timestamp < sequence.firstSeen {
				sequence.firstSeen = call.Timestamp
			}
			if call.Timestamp > sequence.lastSeen {
				sequence.lastSeen = call.Timestamp
			}
			sequence.data = append(sequence.data, call.Data...)
		}
		switch sequence.key.role {
		case boundaryTLSCiphertext:
			sources = append(sources, sequence)
		case boundarySocketPayload, boundaryFDPayload:
			targets = append(targets, sequence)
		}
	}
	summary.TLSBIOStreams = len(sources)
	summary.FDStreams = len(targets)
	packetRuns := packetCollector.runs()
	summary.PacketFlows = len(packetCollector.flows)

	sort.Slice(sources, func(i, j int) bool {
		if sources[i].key.pid == sources[j].key.pid {
			if sources[i].key.direction == sources[j].key.direction {
				return sources[i].key.context < sources[j].key.context
			}
			return sources[i].key.direction < sources[j].key.direction
		}
		return sources[i].key.pid < sources[j].key.pid
	})

	encoder := json.NewEncoder(writer)
	packetCandidatesBySource := correlatePacketCandidates(
		sources,
		packetRuns,
	)
	for _, source := range sources {
		packetCandidates := packetCandidatesBySource[source]
		sort.Slice(packetCandidates, func(i, j int) bool {
			if packetCandidates[i].match.length ==
				packetCandidates[j].match.length {
				return packetCandidates[i].target.key.tuple <
					packetCandidates[j].target.key.tuple
			}
			return packetCandidates[i].match.length >
				packetCandidates[j].match.length
		})
		if len(packetCandidates) != 0 {
			best := packetCandidates[0]
			ambiguous := len(packetCandidates) > 1 &&
				packetCandidates[1].match.length == best.match.length
			confidence := "exact-wire-content"
			if ambiguous {
				confidence = "ambiguous-exact-wire-content"
				summary.Ambiguous++
			}
			firstSeen, lastSeen := correlationTimeBounds(
				source.firstSeen,
				source.lastSeen,
				best.target.firstSeen,
				best.target.lastSeen,
			)
			correlation := WireCorrelation{
				EventType:          "wire_correlation",
				CaptureLayer:       "metadata",
				Transport:          best.target.key.transport,
				TargetKind:         "packet_flow",
				Method:             "exact-ciphertext-content",
				Pid:                source.key.pid,
				Direction:          source.key.direction,
				BIOAddr:            source.key.context,
				Tuple:              best.target.key.tuple,
				SocketCookie:       best.target.socketCookie,
				NetworkVerified:    true,
				TLSCiphertextBytes: len(source.data),
				WireBytes:          len(best.target.data),
				MatchedBytes:       best.match.length,
				Coverage:           float64(best.match.length) / float64(len(source.data)),
				BIOOffset:          best.match.sourceOffset,
				TargetOffset:       best.match.targetOffset,
				FirstSeen:          firstSeen,
				LastSeen:           lastSeen,
				Confidence:         confidence,
				Ambiguous:          ambiguous,
			}
			if err := encoder.Encode(correlation); err != nil {
				return summary, fmt.Errorf("write wire correlation: %w", err)
			}
			summary.Matched++
			summary.WireVerified++
			continue
		}

		var candidates []wireCandidate
		for _, target := range targets {
			if source.key.pid != target.key.pid ||
				source.key.direction != target.key.direction ||
				target.key.context > math.MaxUint32 {
				continue
			}
			match := longestExactWireMatch(source.data, target.data)
			if match.length >= wireCorrelationMinimum {
				candidates = append(candidates, wireCandidate{
					target: target,
					match:  match,
				})
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].match.length == candidates[j].match.length {
				return candidates[i].target.key.context <
					candidates[j].target.key.context
			}
			return candidates[i].match.length > candidates[j].match.length
		})
		if len(candidates) == 0 {
			summary.Unmatched++
			continue
		}
		best := candidates[0]
		ambiguous := len(candidates) > 1 &&
			candidates[1].match.length == best.match.length
		confidence := "exact-fd-content-unverified"
		if ambiguous {
			confidence = "ambiguous-exact-fd-content-unverified"
			summary.Ambiguous++
		}
		firstSeen, lastSeen := correlationTimeBounds(
			source.firstSeen,
			source.lastSeen,
			best.target.firstSeen,
			best.target.lastSeen,
		)
		correlation := WireCorrelation{
			EventType:          "wire_correlation",
			CaptureLayer:       "metadata",
			Transport:          best.target.key.transport,
			TargetKind:         "fd_candidate",
			Method:             "exact-ciphertext-content",
			Pid:                source.key.pid,
			Direction:          source.key.direction,
			BIOAddr:            source.key.context,
			Fd:                 uint32(best.target.key.context),
			NetworkVerified:    false,
			TLSCiphertextBytes: len(source.data),
			FDPayloadBytes:     len(best.target.data),
			MatchedBytes:       best.match.length,
			Coverage:           float64(best.match.length) / float64(len(source.data)),
			BIOOffset:          best.match.sourceOffset,
			TargetOffset:       best.match.targetOffset,
			FirstSeen:          firstSeen,
			LastSeen:           lastSeen,
			Confidence:         confidence,
			Ambiguous:          ambiguous,
		}
		if err := encoder.Encode(correlation); err != nil {
			return summary, fmt.Errorf("write wire correlation: %w", err)
		}
		summary.Matched++
		summary.FDCandidates++
	}
	return summary, nil
}

// correlatePacketCandidates indexes each packet run once and evaluates every
// BIO stream with the same process and direction while that compact index is
// resident. The previous source-first loop rebuilt the same byte index for
// every BIO stream, which dominated large all-traffic checkpoints.
func correlatePacketCandidates(
	sources []*wireSequence,
	packetRuns []wirePacketRun,
) map[*wireSequence][]wirePacketCandidate {
	result := make(map[*wireSequence][]wirePacketCandidate)
	groups := make(map[wireDirectionKey][]*wireSequence)
	for _, source := range sources {
		key := wireDirectionKey{
			pid:       source.key.pid,
			direction: source.key.direction,
		}
		groups[key] = append(groups[key], source)
	}
	for index := range packetRuns {
		target := &packetRuns[index]
		key := wireDirectionKey{
			pid:       target.key.pid,
			direction: target.key.direction,
		}
		relevant := groups[key]
		if len(relevant) == 0 ||
			len(target.data) < wireCorrelationAnchor {
			continue
		}
		anchorIndex := buildExactWireIndex(target.data)
		for _, source := range relevant {
			match := longestExactWireMatchIndexed(
				source.data,
				target.data,
				anchorIndex,
			)
			if match.length < wireCorrelationMinimum {
				continue
			}
			result[source] = append(
				result[source],
				wirePacketCandidate{target: target, match: match},
			)
		}
	}
	return result
}

func correlationTimeBounds(
	sourceFirst uint64,
	sourceLast uint64,
	targetFirst uint64,
	targetLast uint64,
) (uint64, uint64) {
	firstSeen := sourceFirst
	if targetFirst != 0 && (firstSeen == 0 || targetFirst < firstSeen) {
		firstSeen = targetFirst
	}
	lastSeen := sourceLast
	if targetLast > lastSeen {
		lastSeen = targetLast
	}
	return firstSeen, lastSeen
}

func longestExactWireMatch(source, target []byte) wireMatch {
	if len(source) < wireCorrelationAnchor ||
		len(target) < wireCorrelationAnchor {
		return wireMatch{}
	}
	return longestExactWireMatchIndexed(
		source,
		target,
		buildExactWireIndex(target),
	)
}

func buildExactWireIndex(
	target []byte,
) map[[wireCorrelationAnchor]byte][]int {
	index := make(map[[wireCorrelationAnchor]byte][]int)
	for offset := 0; offset+wireCorrelationAnchor <= len(target); offset++ {
		var anchor [wireCorrelationAnchor]byte
		copy(anchor[:], target[offset:offset+wireCorrelationAnchor])
		positions := index[anchor]
		if len(positions) < wireCorrelationMaxIndex {
			index[anchor] = append(positions, offset)
		}
	}
	return index
}

func longestExactWireMatchIndexed(
	source []byte,
	target []byte,
	index map[[wireCorrelationAnchor]byte][]int,
) wireMatch {
	if len(source) < wireCorrelationAnchor ||
		len(target) < wireCorrelationAnchor {
		return wireMatch{}
	}
	var best wireMatch
	for sourceOffset := 0; sourceOffset+wireCorrelationAnchor <= len(source); sourceOffset += wireCorrelationAnchor / 2 {
		var anchor [wireCorrelationAnchor]byte
		copy(anchor[:], source[sourceOffset:sourceOffset+wireCorrelationAnchor])
		for _, targetOffset := range index[anchor] {
			sourceStart := sourceOffset
			targetStart := targetOffset
			for sourceStart > 0 && targetStart > 0 &&
				source[sourceStart-1] == target[targetStart-1] {
				sourceStart--
				targetStart--
			}
			sourceEnd := sourceOffset + wireCorrelationAnchor
			targetEnd := targetOffset + wireCorrelationAnchor
			for sourceEnd < len(source) && targetEnd < len(target) &&
				source[sourceEnd] == target[targetEnd] {
				sourceEnd++
				targetEnd++
			}
			if sourceEnd-sourceStart > best.length {
				best = wireMatch{
					sourceOffset: sourceStart,
					targetOffset: targetStart,
					length:       sourceEnd - sourceStart,
				}
			}
		}
	}
	return best
}
