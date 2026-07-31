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

import (
	"fmt"
	"math"

	"golang.org/x/net/http2/hpack"
)

const qpackEntryOverhead = 32

type qpackDynamicEntry struct {
	Name  string
	Value string
	Ready uint64
	Size  uint64
}

// qpackDynamicTable retains insertion history as well as the currently active
// table. Retaining evicted history is necessary for offline decoding: an entry
// may have been valid when a captured HEADERS block referenced it and be
// evicted by later encoder-stream instructions before capture stops.
type qpackDynamicTable struct {
	maxCapacity  uint64
	capacity     uint64
	size         uint64
	entries      []qpackDynamicEntry
	active       []uint64
	errors       []string
	instructions int
}

type qpackCaptureState struct {
	tables              map[string]*qpackDynamicTable
	instructions        int
	encoderStreamErrors int
}

func qpackStateKey(connectionID, direction string) string {
	return connectionID + ":" + direction
}

func buildQPACKCaptureState(streams []QUICStream) qpackCaptureState {
	state := qpackCaptureState{
		tables: make(map[string]*qpackDynamicTable),
	}
	maximumCapacities := qpackMaximumCapacities(streams)
	for _, stream := range streams {
		if stream.StreamID&0x2 == 0 ||
			len(stream.Missing) != 0 ||
			stream.Conflicting != 0 ||
			stream.Truncated {
			continue
		}
		streamType, width, ok := decodeQUICVarint(stream.Data)
		if !ok || streamType != 2 {
			continue
		}
		key := qpackStateKey(stream.ConnectionID, stream.Direction)
		if _, exists := state.tables[key]; exists {
			table := state.tables[key]
			table.addError("multiple QPACK encoder streams in one direction")
			state.encoderStreamErrors++
			continue
		}
		table := &qpackDynamicTable{
			maxCapacity: maximumCapacities[key],
		}
		state.tables[key] = table
		if err := table.decodeEncoderStream(stream, width); err != nil {
			table.addError(err.Error())
			state.encoderStreamErrors++
		}
		state.instructions += table.instructions
	}
	return state
}

// qpackMaximumCapacities maps an encoder direction to the capacity advertised
// by its peer. A READ control stream contains the peer's settings and therefore
// constrains locally generated WRITE header blocks, and vice versa.
func qpackMaximumCapacities(streams []QUICStream) map[string]uint64 {
	result := make(map[string]uint64)
	for _, stream := range streams {
		if stream.StreamID&0x2 == 0 ||
			len(stream.Missing) != 0 ||
			stream.Conflicting != 0 ||
			stream.Truncated {
			continue
		}
		streamType, _, ok := decodeQUICVarint(stream.Data)
		if !ok || streamType != 0 {
			continue
		}
		records, recognized := parseHTTP3Stream(stream)
		if !recognized {
			continue
		}
		for _, record := range records {
			if record.FrameType == nil || *record.FrameType != 4 ||
				!record.Complete {
				continue
			}
			settings, ok := parseHTTP3Settings(record.Data)
			if !ok {
				continue
			}
			capacity, exists := settings[1]
			if !exists {
				capacity = 0
			}
			result[qpackStateKey(
				stream.ConnectionID,
				oppositeDirection(stream.Direction),
			)] = capacity
		}
	}
	return result
}

func parseHTTP3Settings(data []byte) (map[uint64]uint64, bool) {
	settings := make(map[uint64]uint64)
	for len(data) != 0 {
		identifier, width, ok := decodeQUICVarint(data)
		if !ok {
			return nil, false
		}
		data = data[width:]
		value, width, ok := decodeQUICVarint(data)
		if !ok {
			return nil, false
		}
		data = data[width:]
		if _, duplicate := settings[identifier]; duplicate {
			return nil, false
		}
		settings[identifier] = value
	}
	return settings, true
}

func oppositeDirection(direction string) string {
	if direction == "WRITE" {
		return "READ"
	}
	return "WRITE"
}

func (table *qpackDynamicTable) decodeEncoderStream(
	stream QUICStream,
	offset int,
) error {
	for offset < len(stream.Data) {
		consumed, instruction, err := table.decodeEncoderInstruction(
			stream.Data[offset:],
			streamReadyTimestamp(stream, offset, len(stream.Data)),
		)
		if err != nil {
			return fmt.Errorf("QPACK encoder stream at offset %d: %w",
				offset, err)
		}
		if consumed == 0 {
			return fmt.Errorf("QPACK encoder stream at offset %d made no progress",
				offset)
		}
		offset += consumed
		table.instructions++
		if instruction != nil {
			// The insertion becomes available only after the complete
			// instruction has arrived, not at the first byte of its prefix.
			instruction.Ready = streamReadyTimestamp(stream, 0, offset)
			table.insert(*instruction)
			if len(table.errors) != 0 {
				return fmt.Errorf("%s", table.errors[len(table.errors)-1])
			}
		}
	}
	return nil
}

func (table *qpackDynamicTable) decodeEncoderInstruction(
	data []byte,
	ready uint64,
) (int, *qpackDynamicEntry, error) {
	if len(data) == 0 {
		return 0, nil, fmt.Errorf("truncated instruction")
	}
	first := data[0]
	switch {
	case first&0x80 != 0:
		// Insert With Name Reference: 1 T NameIndex(6+), Value.
		nameIndex, width, err := decodeQPACKInteger(data, 6)
		if err != nil {
			return 0, nil, err
		}
		value, valueWidth, err := decodeQPACKString(data[width:], 7, 0x80)
		if err != nil {
			return 0, nil, err
		}
		var name string
		if first&0x40 != 0 {
			field, err := qpackStaticField(nameIndex)
			if err != nil {
				return 0, nil, err
			}
			name = field.Name
		} else {
			entry, err := table.encoderRelativeEntry(nameIndex)
			if err != nil {
				return 0, nil, err
			}
			name = entry.Name
		}
		return width + valueWidth, &qpackDynamicEntry{
			Name:  name,
			Value: value,
			Ready: ready,
		}, nil

	case first&0xc0 == 0x40:
		// Insert Without Name Reference: 01 H NameLength(5+), Name, Value.
		name, nameWidth, err := decodeQPACKString(data, 5, 0x20)
		if err != nil {
			return 0, nil, err
		}
		value, valueWidth, err := decodeQPACKString(
			data[nameWidth:], 7, 0x80)
		if err != nil {
			return 0, nil, err
		}
		return nameWidth + valueWidth, &qpackDynamicEntry{
			Name:  name,
			Value: value,
			Ready: ready,
		}, nil

	case first&0xe0 == 0x20:
		// Set Dynamic Table Capacity: 001 Capacity(5+).
		capacity, width, err := decodeQPACKInteger(data, 5)
		if err != nil {
			return 0, nil, err
		}
		if table.maxCapacity == 0 && capacity != 0 {
			return 0, nil, fmt.Errorf(
				"peer SETTINGS_QPACK_MAX_TABLE_CAPACITY was not captured")
		}
		if capacity > table.maxCapacity {
			return 0, nil, fmt.Errorf(
				"dynamic table capacity %d exceeds peer maximum %d",
				capacity, table.maxCapacity)
		}
		table.capacity = capacity
		table.evictToCapacity(0)
		return width, nil, nil

	default:
		// Duplicate: 000 Index(5+).
		index, width, err := decodeQPACKInteger(data, 5)
		if err != nil {
			return 0, nil, err
		}
		entry, err := table.encoderRelativeEntry(index)
		if err != nil {
			return 0, nil, err
		}
		duplicate := *entry
		duplicate.Ready = ready
		return width, &duplicate, nil
	}
}

func (table *qpackDynamicTable) insert(entry qpackDynamicEntry) {
	entry.Size = uint64(len(entry.Name) + len(entry.Value) + qpackEntryOverhead)
	if entry.Size > table.capacity {
		table.addError(fmt.Sprintf(
			"dynamic entry size %d exceeds capacity %d",
			entry.Size, table.capacity))
		return
	}
	table.evictToCapacity(entry.Size)
	index := uint64(len(table.entries))
	table.entries = append(table.entries, entry)
	table.active = append(table.active, index)
	table.size += entry.Size
}

func (table *qpackDynamicTable) evictToCapacity(incoming uint64) {
	for len(table.active) != 0 &&
		table.size+incoming > table.capacity {
		index := table.active[0]
		table.active = table.active[1:]
		table.size -= table.entries[index].Size
	}
}

func (table *qpackDynamicTable) encoderRelativeEntry(
	relative uint64,
) (*qpackDynamicEntry, error) {
	inserted := uint64(len(table.entries))
	if relative >= inserted {
		return nil, fmt.Errorf(
			"dynamic relative index %d exceeds insert count %d",
			relative, inserted)
	}
	absolute := inserted - relative - 1
	active := false
	for _, index := range table.active {
		if index == absolute {
			active = true
			break
		}
	}
	if !active {
		return nil, fmt.Errorf(
			"dynamic entry %d was already evicted", absolute)
	}
	return &table.entries[absolute], nil
}

func (table *qpackDynamicTable) addError(message string) {
	if len(table.errors) < 16 {
		table.errors = append(table.errors, message)
	}
}

func (table *qpackDynamicTable) knownInsertCount(timestamp uint64) uint64 {
	var count uint64
	for _, entry := range table.entries {
		if entry.Ready > timestamp {
			break
		}
		count++
	}
	return count
}

func decodeDynamicQPACK(
	block []byte,
	table *qpackDynamicTable,
	readyTimestamp uint64,
) ([]HTTP2Header, error) {
	if table == nil {
		return nil, fmt.Errorf("QPACK encoder stream was not captured")
	}
	if len(table.errors) != 0 {
		return nil, fmt.Errorf("QPACK encoder stream error: %s",
			table.errors[0])
	}
	encodedRequired, width, err := decodeQPACKInteger(block, 8)
	if err != nil {
		return nil, fmt.Errorf("required insert count: %w", err)
	}
	if width >= len(block) {
		return nil, fmt.Errorf("truncated QPACK base")
	}
	known := table.knownInsertCount(readyTimestamp)
	required, err := decodeQPACKRequiredInsertCount(
		encodedRequired,
		table.maxCapacity/qpackEntryOverhead,
		known,
	)
	if err != nil {
		return nil, err
	}
	if required > uint64(len(table.entries)) {
		return nil, fmt.Errorf(
			"required insert count %d exceeds captured insert count %d",
			required, len(table.entries))
	}
	sign := block[width]&0x80 != 0
	delta, deltaWidth, err := decodeQPACKInteger(block[width:], 7)
	if err != nil {
		return nil, fmt.Errorf("delta base: %w", err)
	}
	width += deltaWidth
	var base uint64
	if sign {
		if delta == math.MaxUint64 || required < delta+1 {
			return nil, fmt.Errorf(
				"negative base underflow: required=%d delta=%d",
				required, delta)
		}
		base = required - delta - 1
	} else {
		if delta > math.MaxUint64-required {
			return nil, fmt.Errorf("QPACK base overflow")
		}
		base = required + delta
	}

	data := block[width:]
	var headers []HTTP2Header
	var referenced uint64
	for len(data) != 0 {
		first := data[0]
		var name, value string
		var consumed int
		var absolute *uint64
		switch {
		case first&0x80 != 0:
			// Indexed Field Line: 1 T Index(6+).
			index, fieldWidth, err := decodeQPACKInteger(data, 6)
			if err != nil {
				return nil, err
			}
			consumed = fieldWidth
			if first&0x40 != 0 {
				field, err := qpackStaticField(index)
				if err != nil {
					return nil, err
				}
				name, value = field.Name, field.Value
			} else {
				index, err := qpackRelativeAbsolute(index, base)
				if err != nil {
					return nil, err
				}
				absolute = &index
			}

		case first&0xf0 == 0x10:
			// Indexed Field Line With Post-Base Index: 0001 Index(4+).
			index, fieldWidth, err := decodeQPACKInteger(data, 4)
			if err != nil {
				return nil, err
			}
			consumed = fieldWidth
			if index > math.MaxUint64-base {
				return nil, fmt.Errorf("post-base index overflow")
			}
			index += base
			absolute = &index

		case first&0xc0 == 0x40:
			// Literal Field Line With Name Reference:
			// 01 N T NameIndex(4+), Value.
			index, nameWidth, err := decodeQPACKInteger(data, 4)
			if err != nil {
				return nil, err
			}
			valueString, valueWidth, err := decodeQPACKString(
				data[nameWidth:], 7, 0x80)
			if err != nil {
				return nil, err
			}
			consumed = nameWidth + valueWidth
			value = valueString
			if first&0x10 != 0 {
				field, err := qpackStaticField(index)
				if err != nil {
					return nil, err
				}
				name = field.Name
			} else {
				index, err := qpackRelativeAbsolute(index, base)
				if err != nil {
					return nil, err
				}
				absolute = &index
			}

		case first&0xf0 == 0x00:
			// Literal Field Line With Post-Base Name Reference:
			// 0000 N NameIndex(3+), Value.
			index, nameWidth, err := decodeQPACKInteger(data, 3)
			if err != nil {
				return nil, err
			}
			valueString, valueWidth, err := decodeQPACKString(
				data[nameWidth:], 7, 0x80)
			if err != nil {
				return nil, err
			}
			if index > math.MaxUint64-base {
				return nil, fmt.Errorf("post-base name index overflow")
			}
			index += base
			absolute = &index
			consumed = nameWidth + valueWidth
			value = valueString

		default:
			// Literal Field Line With Literal Name:
			// 001 N H NameLength(3+), Name, Value.
			nameString, nameWidth, err := decodeQPACKString(data, 3, 0x08)
			if err != nil {
				return nil, err
			}
			valueString, valueWidth, err := decodeQPACKString(
				data[nameWidth:], 7, 0x80)
			if err != nil {
				return nil, err
			}
			name, value = nameString, valueString
			consumed = nameWidth + valueWidth
		}
		if absolute != nil {
			entry, err := table.requestEntry(*absolute, required)
			if err != nil {
				return nil, err
			}
			name = entry.Name
			if value == "" &&
				(first&0x80 != 0 || first&0xf0 == 0x10) {
				value = entry.Value
			}
			if *absolute+1 > referenced {
				referenced = *absolute + 1
			}
		}
		headers = append(headers, HTTP2Header{Name: name, Value: value})
		data = data[consumed:]
	}
	if referenced != required {
		return nil, fmt.Errorf(
			"required insert count %d does not match largest reference %d",
			required, referenced)
	}
	return headers, nil
}

func (table *qpackDynamicTable) requestEntry(
	absolute uint64,
	required uint64,
) (*qpackDynamicEntry, error) {
	if absolute >= required {
		return nil, fmt.Errorf(
			"dynamic absolute index %d is not below required insert count %d",
			absolute, required)
	}
	if absolute >= uint64(len(table.entries)) {
		return nil, fmt.Errorf(
			"dynamic absolute index %d was not captured", absolute)
	}
	return &table.entries[absolute], nil
}

func qpackRelativeAbsolute(relative, base uint64) (uint64, error) {
	if relative >= base {
		return 0, fmt.Errorf(
			"relative index %d is not below base %d", relative, base)
	}
	return base - relative - 1, nil
}

func decodeQPACKRequiredInsertCount(
	encoded uint64,
	maxEntries uint64,
	totalInserts uint64,
) (uint64, error) {
	if encoded == 0 {
		return 0, nil
	}
	if maxEntries == 0 || encoded > 2*maxEntries {
		return 0, fmt.Errorf(
			"invalid encoded required insert count %d for max entries %d",
			encoded, maxEntries)
	}
	required := encoded - 1
	fullRange := 2 * maxEntries
	currentWrapped := totalInserts % fullRange
	if currentWrapped >= required+maxEntries {
		required += fullRange
	} else if currentWrapped+maxEntries < required {
		currentWrapped += fullRange
	}
	if required > math.MaxUint64-totalInserts {
		return 0, fmt.Errorf("required insert count overflow")
	}
	required += totalInserts
	if currentWrapped >= required {
		return 0, fmt.Errorf("invalid zero or wrapped required insert count")
	}
	return required - currentWrapped, nil
}

func decodeQPACKInteger(
	data []byte,
	prefixBits uint8,
) (uint64, int, error) {
	if len(data) == 0 || prefixBits == 0 || prefixBits > 8 {
		return 0, 0, fmt.Errorf("truncated or invalid QPACK integer")
	}
	prefixMax := uint64(1<<prefixBits) - 1
	value := uint64(data[0]) & prefixMax
	if value < prefixMax {
		return value, 1, nil
	}
	shift := uint(0)
	for index := 1; index < len(data); index++ {
		byteValue := data[index]
		add := uint64(byteValue & 0x7f)
		if shift >= 64 || add > (math.MaxUint64-value)>>shift {
			return 0, 0, fmt.Errorf("QPACK integer overflow")
		}
		value += add << shift
		if byteValue&0x80 == 0 {
			return value, index + 1, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("truncated QPACK integer")
}

func decodeQPACKString(
	data []byte,
	prefixBits uint8,
	huffmanMask byte,
) (string, int, error) {
	length, width, err := decodeQPACKInteger(data, prefixBits)
	if err != nil {
		return "", 0, err
	}
	if length > maxHTTP3FramePayload ||
		length > uint64(len(data)-width) {
		return "", 0, fmt.Errorf(
			"truncated or oversized QPACK string length %d", length)
	}
	raw := data[width : width+int(length)]
	if data[0]&huffmanMask != 0 {
		value, err := hpack.HuffmanDecodeToString(raw)
		if err != nil {
			return "", 0, fmt.Errorf("QPACK Huffman string: %w", err)
		}
		return value, width + int(length), nil
	}
	return string(raw), width + int(length), nil
}

func qpackStaticField(index uint64) (HTTP2Header, error) {
	block := []byte{0, 0}
	block = appendQPACKInteger(block, 0xc0, 6, index)
	fields, err := decodeStaticQPACK(block)
	if err != nil || len(fields) != 1 {
		if err == nil {
			err = fmt.Errorf("static table index %d not found", index)
		}
		return HTTP2Header{}, err
	}
	return fields[0], nil
}

func appendQPACKInteger(
	destination []byte,
	prefix byte,
	prefixBits uint8,
	value uint64,
) []byte {
	prefixMax := uint64(1<<prefixBits) - 1
	if value < prefixMax {
		return append(destination, prefix|byte(value))
	}
	destination = append(destination, prefix|byte(prefixMax))
	value -= prefixMax
	for value >= 128 {
		destination = append(destination, byte(value)|0x80)
		value >>= 7
	}
	return append(destination, byte(value))
}

func streamReadyTimestamp(stream QUICStream, start, end int) uint64 {
	if start < 0 {
		start = 0
	}
	if end > len(stream.byteReady) {
		end = len(stream.byteReady)
	}
	ready := stream.Timestamp
	for index := start; index < end; index++ {
		if stream.byteReady[index] > ready {
			ready = stream.byteReady[index]
		}
	}
	return ready
}

func http3HeaderBlockReadyTimestamp(
	stream QUICStream,
	record HTTP3Record,
) uint64 {
	offset := int(record.Offset)
	if offset < 0 || offset >= len(stream.Data) {
		return stream.LastSeen
	}
	frame, complete, plausible := parseHTTP3Frame(stream.Data[offset:])
	if !complete || !plausible {
		return stream.LastSeen
	}
	return streamReadyTimestamp(
		stream,
		offset,
		offset+frame.headerLen+len(frame.payload),
	)
}
