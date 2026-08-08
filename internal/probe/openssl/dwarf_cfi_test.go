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
	"encoding/binary"
	"os"
	"reflect"
	"testing"

	delveframe "github.com/go-delve/delve/pkg/dwarf/frame"
)

func TestAppDwarfCFILocationsAndSanitization(t *testing.T) {
	instructions := []byte{
		0x0c, 0x1f, 0x00, // DW_CFA_def_cfa sp, 0
		0x44,       // DW_CFA_advance_loc 4
		0x0e, 0x10, // DW_CFA_def_cfa_offset 16
		0x2d,             // DW_CFA_AARCH64_negate_ra_state
		0x2e, 0x81, 0x01, // DW_CFA_GNU_args_size 129
		0x02, 0x02, // DW_CFA_advance_loc1 2
	}
	locations, err := appDwarfCFILocations(
		0x100, instructions, 1, binary.LittleEndian, 8, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint64{0x100, 0x104, 0x106}; !reflect.DeepEqual(locations, want) {
		t.Fatalf("locations = %#v, want %#v", locations, want)
	}
	for _, index := range []int{6, 7, 8, 9} {
		if instructions[index] != 0 {
			t.Fatalf("sanitized instruction[%d] = %#x", index, instructions[index])
		}
	}
}

func TestAppDwarfInfoFromFrameContext(t *testing.T) {
	context := &delveframe.FrameContext{
		CFA: delveframe.DWRule{
			Rule:   delveframe.RuleCFA,
			Reg:    appDwarfArm64SP,
			Offset: 32,
		},
		Regs: map[uint64]delveframe.DWRule{
			appDwarfArm64FP: {
				Rule:   delveframe.RuleOffset,
				Offset: -16,
			},
			appDwarfArm64LR: {
				Rule:   delveframe.RuleOffset,
				Offset: -8,
			},
		},
	}
	got := appDwarfInfoFromFrameContext(context)
	want := appDwarfUnwindInfo{
		Flags:      appDwarfUnwindFlagFrame,
		BaseReg:    appDwarfUnwindRegSP,
		AuxBaseReg: appDwarfUnwindRegCFA,
		Param:      32,
		AuxParam:   -8,
	}
	if got != want {
		t.Fatalf("unwind info = %#v, want %#v", got, want)
	}

	context.Regs = nil
	got = appDwarfInfoFromFrameContext(context)
	if got.AuxBaseReg != appDwarfUnwindRegLR {
		t.Fatalf("same-value LR rule = %#v", got)
	}
}

func TestAppDwarfExtractRealELF(t *testing.T) {
	path := os.Getenv("ECAPTURE_DWARF_TEST_ELF")
	if path == "" {
		t.Skip("ECAPTURE_DWARF_TEST_ELF is not set")
	}
	intervals, err := extractAppDwarfIntervals(path)
	if err != nil {
		t.Fatal(err)
	}
	if intervals.NumDeltas == 0 || len(intervals.Blocks) == 0 {
		t.Fatalf("no DWARF intervals extracted from %s", path)
	}
	t.Logf("extracted %d deltas in %d FDE blocks from %s",
		intervals.NumDeltas, len(intervals.Blocks), path)
}
