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
	"archive/zip"
	"debug/elf"
	"encoding/binary"
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestAppDwarfMapABILayout(t *testing.T) {
	if got := binary.Size(appDwarfUnwindInfo{}); got != 12 {
		t.Fatalf("appDwarfUnwindInfo size = %d, want 12", got)
	}
	if got := binary.Size(appDwarfStackDelta{}); got != 4 {
		t.Fatalf("appDwarfStackDelta size = %d, want 4", got)
	}
	if got := binary.Size(appDwarfStackDeltaPair{}); got != 8 {
		t.Fatalf("appDwarfStackDeltaPair size = %d, want 8", got)
	}
	if got := binary.Size(appDwarfPageTransition{}); got != 4 {
		t.Fatalf("appDwarfPageTransition size = %d, want 4", got)
	}
	if got := binary.Size(appDwarfUnwindPageKey{}); got != 16 {
		t.Fatalf("appDwarfUnwindPageKey size = %d, want 16", got)
	}
	if got := binary.Size(appDwarfUnwindPage{}); got != 40 {
		t.Fatalf("appDwarfUnwindPage size = %d, want 40", got)
	}
}

func TestAppDwarfMapSpecsUsePreparedSizes(t *testing.T) {
	probe := &Probe{config: NewConfig()}
	assertEntries := func(name string, want uint32) {
		t.Helper()
		editor, found := probe.getManagerOptions().MapSpecEditors[name]
		if !found {
			t.Fatalf("map editor %q is missing", name)
		}
		if editor.MaxEntries != want {
			t.Fatalf("map editor %q max entries = %d, want %d",
				name, editor.MaxEntries, want)
		}
	}
	assertEntries("app_dwarf_unwind_pages", 1)
	assertEntries("app_dwarf_unwind_deltas", 1)
	assertEntries("app_dwarf_unwind_infos", 1)

	probe.dwarfUnwind = &appDwarfPreparedUnwind{
		pages:  make([]appDwarfUnwindPage, 3),
		deltas: make([]appDwarfStackDeltaPair, 3),
		infos:  make([]appDwarfUnwindInfo, 7),
	}
	assertEntries("app_dwarf_unwind_pages", 3)
	assertEntries("app_dwarf_unwind_deltas", 3)
	assertEntries("app_dwarf_unwind_infos", 7)
}

func TestAppDwarfRulePagesPreserveGapsAndPageBoundaries(t *testing.T) {
	first := appDwarfUnwindInfo{
		BaseReg:    appDwarfUnwindRegSP,
		AuxBaseReg: appDwarfUnwindRegLR,
		Param:      16,
	}
	second := appDwarfUnwindInfo{
		BaseReg:    appDwarfUnwindRegSP,
		AuxBaseReg: appDwarfUnwindRegCFA,
		Param:      32,
		AuxParam:   -8,
	}
	intervals := &appDwarfIntervalData{Blocks: []appDwarfBasicBlock{
		{
			Start: 0xff8,
			End:   0x1010,
			Deltas: []appDwarfStackDeltaInfo{
				{Offset: 0, Info: first},
				{Offset: 8, Info: second},
			},
		},
		{
			Start: 0x1020,
			End:   0x1028,
			Deltas: []appDwarfStackDeltaInfo{
				{Offset: 0, Info: first},
			},
		},
	}}
	rules := newAppDwarfRuleSet(42)
	if err := rules.addIntervals(0x1000, intervals); err != nil {
		t.Fatal(err)
	}
	keys, pages, deltas, deltaCount, _, err := rules.materializePages()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || len(pages) != 2 {
		t.Fatalf("materialized %d keys and %d pages", len(keys), len(pages))
	}
	if keys[0].PID != 42 || keys[0].Page != 0x1000 || keys[1].Page != 0x2000 {
		t.Fatalf("page keys = %#v", keys)
	}
	// Page 0x2000 contains the continued rule at 0, an invalid marker at
	// 0x10, the next FDE at 0x20, and its terminating invalid marker at 0x28.
	page := pages[1]
	got := appDwarfPageDeltaSlice(page, deltas, deltaCount)
	wantOffsets := []uint16{0x00, 0x10, 0x20, 0x28}
	if len(got) != len(wantOffsets) {
		t.Fatalf("page deltas = %#v", got)
	}
	for index, want := range wantOffsets {
		if got[index].AddressLow != want {
			t.Fatalf("delta[%d].AddressLow = %#x, want %#x", index, got[index].AddressLow, want)
		}
	}
	if got[1].UnwindInfo != 0 || got[3].UnwindInfo != 0 {
		t.Fatalf("gap/terminal markers = %#v", got)
	}
}

func TestAppDwarfRuleValidationDoesNotPartiallyMutateRules(t *testing.T) {
	info := appDwarfUnwindInfo{
		BaseReg:    appDwarfUnwindRegSP,
		AuxBaseReg: appDwarfUnwindRegLR,
		Param:      16,
	}
	intervals := &appDwarfIntervalData{Blocks: []appDwarfBasicBlock{
		{
			Start:  0x100,
			End:    0x110,
			Deltas: []appDwarfStackDeltaInfo{{Offset: 0, Info: info}},
		},
		{
			Start:  math.MaxUint64,
			End:    math.MaxUint64,
			Deltas: []appDwarfStackDeltaInfo{{Offset: 1, Info: info}},
		},
	}}
	rules := newAppDwarfRuleSet(42)
	if err := rules.addIntervals(0, intervals); err == nil {
		t.Fatal("overflowing interval was accepted")
	}
	if len(rules.pages) != 0 || len(rules.infos) != 1 || rules.segments != 0 {
		t.Fatalf("failed module partially mutated rules: %#v", rules)
	}
}

func TestAppDwarfRuleHandlesFinalAddressPage(t *testing.T) {
	info := appDwarfUnwindInfo{
		BaseReg:    appDwarfUnwindRegSP,
		AuxBaseReg: appDwarfUnwindRegLR,
		Param:      16,
	}
	rules := newAppDwarfRuleSet(42)
	if err := rules.addSegment(math.MaxUint64-8, math.MaxUint64, info); err != nil {
		t.Fatal(err)
	}
	if len(rules.pages) != 1 || rules.segments != 1 {
		t.Fatalf("final address page was not recorded: %#v", rules)
	}
}

func TestAppDwarfELFLoadBiasRejectsOverflowingSegment(t *testing.T) {
	file := &elf.File{Progs: []*elf.Prog{{
		ProgHeader: elf.ProgHeader{
			Type:   elf.PT_LOAD,
			Flags:  elf.PF_X,
			Off:    math.MaxUint64 - 8,
			Filesz: 16,
			Align:  4096,
		},
	}}}
	_, err := appDwarfELFLoadBias(processModuleMapping{
		start:      0x1000,
		fileOffset: math.MaxUint64 - 4,
	}, file)
	if err == nil {
		t.Fatal("overflowing ELF segment was accepted")
	}
}

func setAppDwarfTestPage(
	rules *appDwarfRuleSet,
	key appDwarfUnwindPageKey,
	deltas map[uint16]uint16,
) {
	page := &appDwarfPageBuilder{}
	rules.pages[key] = page
	offsets := make([]int, 0, len(deltas))
	for offset := range deltas {
		offsets = append(offsets, int(offset))
	}
	sort.Ints(offsets)
	for _, offset := range offsets {
		rules.setPageDelta(page, uint16(offset), deltas[uint16(offset)])
	}
}

func appDwarfPageDeltaSlice(
	page appDwarfUnwindPage,
	deltas []appDwarfStackDeltaPair,
	deltaCount int,
) []appDwarfStackDelta {
	result := make([]appDwarfStackDelta, 0, page.Count)
	start := int(page.DeltaStart)
	end := start + int(page.Count)
	if end > deltaCount {
		return result
	}
	for index := start; index < end; index++ {
		delta, found := appDwarfDeltaAt(deltas, index)
		if !found {
			return nil
		}
		result = append(result, delta)
	}
	return result
}

func appDwarfPackTestDeltas(deltas []appDwarfStackDelta) []appDwarfStackDeltaPair {
	pairs := make([]appDwarfStackDeltaPair, (len(deltas)+1)/2)
	for index, delta := range deltas {
		pairs[index/2].Deltas[index&1] = delta
	}
	return pairs
}

func TestAppDwarfPageBucketsIndexTransitions(t *testing.T) {
	rules := newAppDwarfRuleSet(9)
	key := appDwarfUnwindPageKey{PID: 9, Page: 0x4000}
	setAppDwarfTestPage(rules, key, map[uint16]uint16{
		0x000: 0,
		0x0ff: 1,
		0x100: 2,
		0x301: 3,
	})
	keys, pages, _, _, _, err := rules.materializePages()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != key || len(pages) != 1 {
		t.Fatalf("materialized keys=%#v pages=%#v", keys, pages)
	}
	buckets := pages[0].Buckets
	want := map[int]uint16{
		0:  0,
		1:  2,
		2:  3,
		3:  3,
		4:  4,
		16: 4,
	}
	for index, value := range want {
		if buckets[index] != value {
			t.Fatalf("bucket[%d] = %d, want %d; all=%#v",
				index, buckets[index], value, buckets)
		}
	}
}

func TestAppDwarfMaterializeCompactsEquivalentTransitions(t *testing.T) {
	rules := newAppDwarfRuleSet(12)
	page := rules.page(0x8000)
	rules.setPageDelta(page, 0x000, 1)
	rules.setPageDelta(page, 0x004, 1)
	rules.setPageDelta(page, 0x008, 2)
	rules.setPageDelta(page, 0x00c, 2)
	// A later overlapping row wins at the same address.
	rules.setPageDelta(page, 0x008, 1)
	rules.setPageDelta(page, 0x010, 0)

	_, pages, deltas, deltaCount, sourceDeltas, err := rules.materializePages()
	if err != nil {
		t.Fatal(err)
	}
	if sourceDeltas != 6 {
		t.Fatalf("source deltas = %d, want 6", sourceDeltas)
	}
	got := appDwarfPageDeltaSlice(pages[0], deltas, deltaCount)
	want := []appDwarfStackDelta{
		{AddressLow: 0x000, UnwindInfo: 1},
		{AddressLow: 0x00c, UnwindInfo: 2},
		{AddressLow: 0x010, UnwindInfo: 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compacted deltas = %#v, want %#v", got, want)
	}
}

func appDwarfBucketLookupIndex(
	page appDwarfUnwindPage,
	deltas []appDwarfStackDeltaPair,
	pageOffset uint16,
) (int, bool) {
	bucket := int(pageOffset >> 8)
	low := int(page.Buckets[bucket])
	high := int(page.Buckets[bucket+1])
	if low > 0 {
		low--
	}
	for range 9 {
		if low < high {
			pivot := (low + high) >> 1
			delta, found := appDwarfDeltaAt(deltas, int(page.DeltaStart)+pivot)
			if !found {
				return 0, false
			}
			if pageOffset >= delta.AddressLow {
				low = pivot + 1
			} else {
				high = pivot
			}
		}
	}
	if low == 0 {
		return 0, false
	}
	return low - 1, true
}

func TestAppDwarfBucketLookupMatchesFullPageSearch(t *testing.T) {
	random := rand.New(rand.NewSource(0x45434150))
	for sample := 0; sample < 64; sample++ {
		count := 1 + random.Intn(512)
		unique := make(map[uint16]uint16, count)
		for len(unique) < count {
			offset := uint16(random.Intn(appDwarfPageSize))
			unique[offset] = uint16(len(unique) + 1)
		}
		rules := newAppDwarfRuleSet(11)
		key := appDwarfUnwindPageKey{PID: 11, Page: uint64(sample+1) << appDwarfPageBits}
		setAppDwarfTestPage(rules, key, unique)
		_, pages, deltas, deltaCount, _, err := rules.materializePages()
		if err != nil {
			t.Fatal(err)
		}
		page := pages[0]
		pageDeltas := appDwarfPageDeltaSlice(page, deltas, deltaCount)
		for offset := 0; offset < appDwarfPageSize; offset++ {
			got, found := appDwarfBucketLookupIndex(page, deltas, uint16(offset))
			want := sort.Search(len(pageDeltas), func(index int) bool {
				return pageDeltas[index].AddressLow > uint16(offset)
			}) - 1
			if found != (want >= 0) || found && got != want {
				t.Fatalf(
					"sample %d offset %#x: bucket lookup=(%d,%t), full lookup=(%d,%t)",
					sample, offset, got, found, want, want >= 0,
				)
			}
		}
	}
}

func TestAppDwarfRealELFFitsPageLimit(t *testing.T) {
	path := os.Getenv("ECAPTURE_DWARF_TEST_ELF")
	if path == "" {
		t.Skip("ECAPTURE_DWARF_TEST_ELF is not set")
	}
	intervals, err := extractAppDwarfIntervals(path)
	if err != nil {
		t.Fatal(err)
	}
	rules := newAppDwarfRuleSet(1)
	if err := rules.addIntervals(0, intervals); err != nil {
		t.Fatal(err)
	}
	_, pages, deltas, deltaCount, _, err := rules.materializePages()
	if err != nil {
		t.Fatal(err)
	}
	var maximum uint16
	for _, page := range pages {
		if page.Count > maximum {
			maximum = page.Count
		}
	}
	var stats appDwarfLoadStats
	measureAppDwarfDeltaDistribution(pages, deltas, deltaCount, &stats)
	t.Logf("%s: %d deltas, %d rules, %d pages, maximum %d deltas/page, maximum %d deltas/256-byte bucket",
		path, intervals.NumDeltas, len(rules.infos), len(pages), maximum,
		stats.BucketDeltasMax)
}

func writeStoredELFArchive(
	t *testing.T,
	sourcePath string,
	memberName string,
) (string, libraryTarget) {
	t.Helper()
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	archivePath := filepath.Join(t.TempDir(), "compact.apk")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archive)
	member, err := writer.CreateHeader(&zip.FileHeader{
		Name:   memberName,
		Method: zip.Store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(member, source); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	target, err := resolveLibraryTarget(archivePath + "!/" + memberName)
	if err != nil {
		t.Fatal(err)
	}
	return archivePath, target
}

func executableLoadMapping(
	t *testing.T,
	path string,
	containerOffset uint64,
	loadBias uint64,
) processModuleMapping {
	t.Helper()
	file, err := elf.Open(path)
	if err != nil {
		t.Skipf("test executable is not ELF: %v", err)
	}
	defer file.Close()
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 {
			continue
		}
		alignment := program.Align
		if alignment == 0 || alignment&(alignment-1) != 0 {
			alignment = uint64(os.Getpagesize())
		}
		alignedOffset := program.Off &^ (alignment - 1)
		alignedVaddr := program.Vaddr &^ (alignment - 1)
		mappedVaddr := alignedVaddr + program.Off - alignedOffset
		return processModuleMapping{
			start:      loadBias + mappedVaddr,
			end:        loadBias + mappedVaddr + program.Memsz,
			fileOffset: containerOffset + program.Off,
			executable: true,
			path:       path,
		}
	}
	t.Fatal("test ELF has no executable PT_LOAD segment")
	return processModuleMapping{}
}

func TestAppDwarfModuleResolverStoredAPK(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	archivePath, archiveTarget := writeStoredELFArchive(
		t,
		executable,
		"lib/arm64-v8a/libcompact.so",
	)
	const wantBias = uint64(0x7000000000)
	mapping := executableLoadMapping(
		t,
		executable,
		archiveTarget.ContainerOffset,
		wantBias,
	)
	mapping.path = archivePath

	resolver := &appDwarfModuleResolver{}
	target, relativeMapping, err := resolver.resolve(mapping)
	if err != nil {
		t.Fatalf("resolve stored APK mapping: %v", err)
	}
	if target.String() != archiveTarget.String() {
		t.Fatalf("resolved target = %q, want %q",
			target.String(), archiveTarget.String())
	}
	if relativeMapping.fileOffset != mapping.fileOffset-archiveTarget.ContainerOffset {
		t.Fatalf("relative mapping offset = %#x, want %#x",
			relativeMapping.fileOffset,
			mapping.fileOffset-archiveTarget.ContainerOffset)
	}
	err = withLibraryELF(target, func(file *elf.File) error {
		bias, biasErr := appDwarfELFLoadBias(relativeMapping, file)
		if biasErr != nil {
			return biasErr
		}
		if bias != wantBias {
			t.Fatalf("APK member load bias = %#x, want %#x", bias, wantBias)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestBuildAppDwarfRulesFromStoredAPK(t *testing.T) {
	path := os.Getenv("ECAPTURE_DWARF_TEST_ELF")
	if path == "" {
		t.Skip("ECAPTURE_DWARF_TEST_ELF is not set")
	}
	archivePath, target := writeStoredELFArchive(
		t,
		path,
		"lib/arm64-v8a/libdwarf-test.so",
	)
	mapping := executableLoadMapping(t, path, target.ContainerOffset, 0x7100000000)
	mapping.path = archivePath
	rules, stats, skipped := buildAppDwarfRules(77, []processModuleMapping{mapping})
	if stats.Modules != 1 || stats.ArchiveModules != 1 || len(rules.pages) == 0 {
		t.Fatalf("APK DWARF load stats = %#v, pages=%d, skipped=%v",
			stats, len(rules.pages), skipped)
	}
}

func TestMeasureAppDwarfDeltaDistribution(t *testing.T) {
	pages := []appDwarfUnwindPage{
		{DeltaStart: 0, Count: 3},
		{DeltaStart: 3, Count: 5},
	}
	deltas := []appDwarfStackDelta{
		{AddressLow: 0x000},
		{AddressLow: 0x010},
		{AddressLow: 0x100},
		{AddressLow: 0x000},
		{AddressLow: 0x001},
		{AddressLow: 0x002},
		{AddressLow: 0x300},
		{AddressLow: 0xf00},
	}
	var stats appDwarfLoadStats
	measureAppDwarfDeltaDistribution(
		pages,
		appDwarfPackTestDeltas(deltas),
		len(deltas),
		&stats,
	)
	if stats.PageDeltasP50 != 3 || stats.PageDeltasP90 != 5 ||
		stats.PageDeltasP99 != 5 || stats.PageDeltasMax != 5 {
		t.Fatalf("page delta distribution = %#v", stats)
	}
	if stats.BucketDeltasMax != 3 {
		t.Fatalf("bucket delta maximum = %d, want 3", stats.BucketDeltasMax)
	}
}
