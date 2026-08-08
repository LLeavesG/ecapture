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

package openssl

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"math"
	"sort"

	delveframe "github.com/go-delve/delve/pkg/dwarf/frame"
)

const (
	appDwarfArm64FP = 29
	appDwarfArm64LR = 30
	appDwarfArm64SP = 31
)

const (
	appDwarfUnwindFlagCommand = 1 << iota
	appDwarfUnwindFlagFrame
)

const (
	appDwarfUnwindRegInvalid = iota
	appDwarfUnwindRegCFA
	appDwarfUnwindRegPC
	appDwarfUnwindRegSP
	appDwarfUnwindRegFP
	appDwarfUnwindRegLR
)

const (
	appDwarfUnwindCommandInvalid = iota
	appDwarfUnwindCommandStop
)

var (
	appDwarfInvalidInfo = appDwarfUnwindInfo{
		Flags: appDwarfUnwindFlagCommand,
		Param: appDwarfUnwindCommandInvalid,
	}
	appDwarfStopInfo = appDwarfUnwindInfo{
		Flags: appDwarfUnwindFlagCommand,
		Param: appDwarfUnwindCommandStop,
	}
)

// appDwarfUnwindInfo is the userspace counterpart of
// struct app_dwarf_unwind_info_t in kern/app_data.h.
type appDwarfUnwindInfo struct {
	Flags       uint8
	BaseReg     uint8
	AuxBaseReg  uint8
	MergeOpcode uint8
	Param       int32
	AuxParam    int32
}

type appDwarfStackDeltaInfo struct {
	Offset uint32
	Info   appDwarfUnwindInfo
}

type appDwarfBasicBlock struct {
	Start  uint64
	End    uint64
	Deltas []appDwarfStackDeltaInfo
}

type appDwarfIntervalData struct {
	NumDeltas uint32
	Blocks    []appDwarfBasicBlock
}

// extractAppDwarfIntervals uses Delve's DWARF frame interpreter to evaluate
// each CFI row, then reduces the result to the register expressions needed by
// the arm64 BPF unwinder. Delve is used only at startup; runtime unwinding is
// performed entirely by eBPF.
func extractAppDwarfIntervals(path string) (*appDwarfIntervalData, error) {
	elfFile, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer elfFile.Close()
	return extractAppDwarfIntervalsFromELF(elfFile, path)
}

// extractAppDwarfIntervalsFromELF parses CFI from an ELF which has already
// been opened by the module resolver. Keeping the ELF lifetime outside this
// function lets APK members use an io.SectionReader and avoids opening every
// standalone module twice while preparing the BPF maps.
func extractAppDwarfIntervalsFromELF(
	elfFile *elf.File,
	label string,
) (*appDwarfIntervalData, error) {
	if elfFile.Machine != elf.EM_AARCH64 {
		return nil, fmt.Errorf("ELF %q machine is %s, want AArch64",
			label, elfFile.Machine)
	}
	section := elfFile.Section(".eh_frame")
	isEHFrame := true
	if section == nil {
		section = elfFile.Section(".debug_frame")
		isEHFrame = false
	}
	if section == nil {
		return nil, fmt.Errorf("ELF has neither .eh_frame nor .debug_frame")
	}
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", section.Name, err)
	}
	ehFrameAddress := uint64(0)
	if isEHFrame {
		ehFrameAddress = section.Addr
	}
	entries, err := delveframe.Parse(data, elfFile.ByteOrder, 0, 8, ehFrameAddress)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", section.Name, err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Begin() < entries[j].Begin()
	})

	intervals := &appDwarfIntervalData{Blocks: make([]appDwarfBasicBlock, 0, len(entries))}
	for _, entry := range entries {
		if entry.End() <= entry.Begin() || entry.End()-entry.Begin() > math.MaxUint32 {
			continue
		}
		// arm64's negate_ra_state changes PAC signing state, not the CFA or
		// saved-register locations. The BPF side normalizes PAC pointers, so
		// treating it as a no-op is correct for this compact representation.
		if err := sanitizeAppDwarfAArch64CFI(entry.CIE.InitialInstructions, elfFile.ByteOrder, 8); err != nil {
			continue
		}
		locations, err := appDwarfCFILocations(
			entry.Begin(), entry.Instructions, entry.CIE.CodeAlignmentFactor,
			elfFile.ByteOrder, 8, true,
		)
		if err != nil {
			continue
		}
		block := appDwarfBasicBlock{Start: entry.Begin(), End: entry.End()}
		for _, location := range locations {
			if location < block.Start || location >= block.End {
				continue
			}
			context := entry.EstablishFrame(location)
			info := appDwarfInfoFromFrameContext(context)
			if len(block.Deltas) != 0 && block.Deltas[len(block.Deltas)-1].Info == info {
				continue
			}
			block.Deltas = append(block.Deltas, appDwarfStackDeltaInfo{
				Offset: uint32(location - block.Start),
				Info:   info,
			})
		}
		if len(block.Deltas) == 0 {
			continue
		}
		intervals.NumDeltas += uint32(len(block.Deltas))
		intervals.Blocks = append(intervals.Blocks, block)
	}
	return intervals, nil
}

func appDwarfInfoFromFrameContext(context *delveframe.FrameContext) appDwarfUnwindInfo {
	if context == nil || context.CFA.Rule != delveframe.RuleCFA {
		return appDwarfInvalidInfo
	}
	if context.CFA.Offset < math.MinInt32 || context.CFA.Offset > math.MaxInt32 {
		return appDwarfInvalidInfo
	}
	info := appDwarfUnwindInfo{Param: int32(context.CFA.Offset)}
	switch context.CFA.Reg {
	case appDwarfArm64SP:
		info.BaseReg = appDwarfUnwindRegSP
	case appDwarfArm64FP:
		info.BaseReg = appDwarfUnwindRegFP
	default:
		return appDwarfInvalidInfo
	}
	returnRule, found := context.Regs[appDwarfArm64LR]
	if !found || returnRule.Rule == delveframe.RuleSameVal {
		info.AuxBaseReg = appDwarfUnwindRegLR
	} else {
		switch returnRule.Rule {
		case delveframe.RuleUndefined:
			return appDwarfStopInfo
		case delveframe.RuleOffset:
			if returnRule.Offset < math.MinInt32 || returnRule.Offset > math.MaxInt32 {
				return appDwarfInvalidInfo
			}
			info.AuxBaseReg = appDwarfUnwindRegCFA
			info.AuxParam = int32(returnRule.Offset)
		case delveframe.RuleRegister:
			if returnRule.Reg != appDwarfArm64LR {
				return appDwarfInvalidInfo
			}
			info.AuxBaseReg = appDwarfUnwindRegLR
		default:
			return appDwarfInvalidInfo
		}
	}
	if frameRule, ok := context.Regs[appDwarfArm64FP]; ok &&
		frameRule.Rule == delveframe.RuleOffset &&
		returnRule.Rule == delveframe.RuleOffset &&
		frameRule.Offset+8 == returnRule.Offset {
		info.Flags |= appDwarfUnwindFlagFrame
	}
	return info
}

// appDwarfCFILocations returns every PC at which a CFI row may change. It also
// optionally replaces DW_CFA_AARCH64_negate_ra_state with DW_CFA_nop so Delve's
// architecture-neutral evaluator can process PAC-enabled Android binaries.
func appDwarfCFILocations(
	begin uint64,
	instructions []byte,
	codeAlignment uint64,
	order binary.ByteOrder,
	pointerSize int,
	sanitizePAC bool,
) ([]uint64, error) {
	locations := []uint64{begin}
	location := begin
	for cursor := 0; cursor < len(instructions); {
		opcodeOffset := cursor
		opcode := instructions[cursor]
		cursor++
		switch opcode & 0xc0 {
		case 0x40:
			location += uint64(opcode&0x3f) * codeAlignment
			locations = append(locations, location)
			continue
		case 0x80:
			if _, err := readAppDwarfULEB(instructions, &cursor); err != nil {
				return nil, err
			}
			continue
		case 0xc0:
			continue
		}

		switch opcode {
		case 0x00, 0x0a, 0x0b:
		case 0x01:
			value, err := readAppDwarfUint(instructions, &cursor, pointerSize, order)
			if err != nil {
				return nil, err
			}
			location = value
			locations = append(locations, location)
		case 0x02:
			value, err := readAppDwarfUint(instructions, &cursor, 1, order)
			if err != nil {
				return nil, err
			}
			location += value * codeAlignment
			locations = append(locations, location)
		case 0x03:
			value, err := readAppDwarfUint(instructions, &cursor, 2, order)
			if err != nil {
				return nil, err
			}
			location += value * codeAlignment
			locations = append(locations, location)
		case 0x04:
			value, err := readAppDwarfUint(instructions, &cursor, 4, order)
			if err != nil {
				return nil, err
			}
			location += value * codeAlignment
			locations = append(locations, location)
		case 0x05, 0x09, 0x0c, 0x14:
			if err := skipAppDwarfULEBs(instructions, &cursor, 2); err != nil {
				return nil, err
			}
		case 0x06, 0x07, 0x08, 0x0d, 0x0e:
			if err := skipAppDwarfULEBs(instructions, &cursor, 1); err != nil {
				return nil, err
			}
		case 0x0f:
			if err := skipAppDwarfBlock(instructions, &cursor); err != nil {
				return nil, err
			}
		case 0x10, 0x16:
			if err := skipAppDwarfULEBs(instructions, &cursor, 1); err != nil {
				return nil, err
			}
			if err := skipAppDwarfBlock(instructions, &cursor); err != nil {
				return nil, err
			}
		case 0x11, 0x15:
			if err := skipAppDwarfULEBAndSLEB(instructions, &cursor); err != nil {
				return nil, err
			}
		case 0x12:
			if err := skipAppDwarfULEBAndSLEB(instructions, &cursor); err != nil {
				return nil, err
			}
		case 0x13:
			if _, err := readAppDwarfSLEB(instructions, &cursor); err != nil {
				return nil, err
			}
		case 0x2d:
			if !sanitizePAC {
				return nil, fmt.Errorf("DW_CFA_AARCH64_negate_ra_state is unsupported")
			}
			instructions[opcodeOffset] = 0x00
		case 0x2e:
			if err := skipAppDwarfULEBs(instructions, &cursor, 1); err != nil {
				return nil, err
			}
			if sanitizePAC {
				clear(instructions[opcodeOffset:cursor])
			}
		case 0x2f:
			if err := skipAppDwarfULEBs(instructions, &cursor, 2); err != nil {
				return nil, err
			}
			if sanitizePAC {
				clear(instructions[opcodeOffset:cursor])
			}
		default:
			return nil, fmt.Errorf("unsupported DWARF CFA opcode %#x", opcode)
		}
	}
	sort.Slice(locations, func(i, j int) bool { return locations[i] < locations[j] })
	unique := locations[:0]
	for _, value := range locations {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique, nil
}

func sanitizeAppDwarfAArch64CFI(instructions []byte, order binary.ByteOrder, pointerSize int) error {
	_, err := appDwarfCFILocations(0, instructions, 1, order, pointerSize, true)
	return err
}

func readAppDwarfUint(data []byte, cursor *int, size int, order binary.ByteOrder) (uint64, error) {
	if size < 1 || size > 8 || *cursor < 0 || len(data)-*cursor < size {
		return 0, fmt.Errorf("truncated %d-byte DWARF CFA operand", size)
	}
	bytes := data[*cursor : *cursor+size]
	*cursor += size
	var value uint64
	if order == binary.BigEndian {
		for _, current := range bytes {
			value = value<<8 | uint64(current)
		}
		return value, nil
	}
	for index := len(bytes) - 1; index >= 0; index-- {
		value = value<<8 | uint64(bytes[index])
	}
	return value, nil
}

func readAppDwarfULEB(data []byte, cursor *int) (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 64; shift += 7 {
		if *cursor >= len(data) {
			return 0, fmt.Errorf("truncated ULEB128 DWARF CFA operand")
		}
		current := data[*cursor]
		*cursor++
		value |= uint64(current&0x7f) << shift
		if current&0x80 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("ULEB128 DWARF CFA operand overflows uint64")
}

func readAppDwarfSLEB(data []byte, cursor *int) (int64, error) {
	var value uint64
	var current byte
	shift := uint(0)
	for ; shift < 64; shift += 7 {
		if *cursor >= len(data) {
			return 0, fmt.Errorf("truncated SLEB128 DWARF CFA operand")
		}
		current = data[*cursor]
		*cursor++
		value |= uint64(current&0x7f) << shift
		if current&0x80 == 0 {
			shift += 7
			if shift < 64 && current&0x40 != 0 {
				value |= ^uint64(0) << shift
			}
			return int64(value), nil
		}
	}
	return 0, fmt.Errorf("SLEB128 DWARF CFA operand overflows int64")
}

func skipAppDwarfULEBs(data []byte, cursor *int, count int) error {
	for index := 0; index < count; index++ {
		if _, err := readAppDwarfULEB(data, cursor); err != nil {
			return err
		}
	}
	return nil
}

func skipAppDwarfULEBAndSLEB(data []byte, cursor *int) error {
	if _, err := readAppDwarfULEB(data, cursor); err != nil {
		return err
	}
	_, err := readAppDwarfSLEB(data, cursor)
	return err
}

func skipAppDwarfBlock(data []byte, cursor *int) error {
	length, err := readAppDwarfULEB(data, cursor)
	if err != nil {
		return err
	}
	if length > uint64(len(data)-*cursor) {
		return fmt.Errorf("truncated DWARF CFA expression: need %d bytes", length)
	}
	*cursor += int(length)
	return nil
}
