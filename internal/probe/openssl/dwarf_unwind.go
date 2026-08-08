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
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	appDwarfPageBits       = 12
	appDwarfPageSize       = 1 << appDwarfPageBits
	appDwarfMaxPageDeltas  = 2048
	appDwarfMaxPages       = 131072
	appDwarfMaxTotalDeltas = 8 * 1024 * 1024
	appDwarfMaxUnwindInfos = 16384
)

type appDwarfStackDelta struct {
	AddressLow uint16
	UnwindInfo uint16
}

// Linux rounds BPF array values up to an eight-byte element stride. Pairing
// two four-byte transitions therefore halves the backing-array footprint
// without changing the logical page indexes or adding another map lookup.
type appDwarfStackDeltaPair struct {
	Deltas [2]appDwarfStackDelta
}

type appDwarfUnwindPageKey struct {
	PID      uint32
	Reserved uint32
	Page     uint64
}

type appDwarfUnwindPage struct {
	DeltaStart uint32
	Count      uint16
	Buckets    [17]uint16
}

type appDwarfPageBuilder struct {
	deltas []appDwarfPageTransition
}

type appDwarfPageTransition struct {
	AddressLow uint16
	UnwindInfo uint16
}

type appDwarfRuleSet struct {
	pid       uint32
	pages     map[appDwarfUnwindPageKey]*appDwarfPageBuilder
	infos     []appDwarfUnwindInfo
	infoIndex map[appDwarfUnwindInfo]uint16
	segments  uint64
}

type appDwarfLoadStats struct {
	Modules         int
	ArchiveModules  int
	SkippedModules  int
	Pages           int
	Deltas          int
	DeltaPairs      int
	SourceDeltas    int
	Segments        uint64
	UnwindInfos     int
	PageDeltasP50   int
	PageDeltasP90   int
	PageDeltasP99   int
	PageDeltasMax   int
	BucketDeltasP50 int
	BucketDeltasP90 int
	BucketDeltasP99 int
	BucketDeltasMax int
}

type appDwarfPreparedUnwind struct {
	pid        uint32
	keys       []appDwarfUnwindPageKey
	pages      []appDwarfUnwindPage
	deltas     []appDwarfStackDeltaPair
	deltaCount int
	infos      []appDwarfUnwindInfo
	stats      appDwarfLoadStats
	skipped    []error
}

func newAppDwarfRuleSet(pid uint32) *appDwarfRuleSet {
	rules := &appDwarfRuleSet{
		pid:       pid,
		pages:     make(map[appDwarfUnwindPageKey]*appDwarfPageBuilder),
		infoIndex: make(map[appDwarfUnwindInfo]uint16),
	}
	// Index zero is deliberately the invalid rule. Every populated page starts
	// with it so gaps between FDEs cannot inherit a rule from an earlier range.
	rules.addInfo(appDwarfInvalidInfo)
	return rules
}

func (r *appDwarfRuleSet) addInfo(info appDwarfUnwindInfo) uint16 {
	if index, found := r.infoIndex[info]; found {
		return index
	}
	if len(r.infos) >= appDwarfMaxUnwindInfos || len(r.infos) > math.MaxUint16 {
		return math.MaxUint16
	}
	index := uint16(len(r.infos))
	r.infos = append(r.infos, info)
	r.infoIndex[info] = index
	return index
}

func (r *appDwarfRuleSet) page(address uint64) *appDwarfPageBuilder {
	key := appDwarfUnwindPageKey{
		PID:  r.pid,
		Page: address &^ uint64(appDwarfPageSize-1),
	}
	page := r.pages[key]
	if page == nil {
		page = &appDwarfPageBuilder{}
		r.pages[key] = page
		r.setPageDelta(page, 0, 0)
	}
	return page
}

func (r *appDwarfRuleSet) setPageDelta(
	page *appDwarfPageBuilder,
	addressLow uint16,
	unwindInfo uint16,
) {
	transition := appDwarfPageTransition{
		AddressLow: addressLow,
		UnwindInfo: unwindInfo,
	}
	// Adjacent CFI segments normally replace the preceding end marker at the
	// same address. Handle that hot path without growing the slice.
	if last := len(page.deltas) - 1; last >= 0 &&
		page.deltas[last].AddressLow == addressLow {
		page.deltas[last] = transition
		return
	}
	page.deltas = append(page.deltas, transition)
}

func (r *appDwarfRuleSet) addSegment(start, end uint64, info appDwarfUnwindInfo) error {
	if start >= end {
		return nil
	}
	infoIndex := r.addInfo(info)
	if infoIndex == math.MaxUint16 {
		return fmt.Errorf("DWARF unwind info count exceeds %d", appDwarfMaxUnwindInfos)
	}
	for cursor := start; cursor < end; {
		pageBase := cursor &^ uint64(appDwarfPageSize-1)
		pageEnd := pageBase + appDwarfPageSize
		segmentEnd := end
		if segmentEnd > pageEnd {
			segmentEnd = pageEnd
		}
		page := r.page(cursor)
		r.setPageDelta(page, uint16(cursor-pageBase), infoIndex)
		if segmentEnd < pageEnd {
			// A following adjacent CFI segment overwrites this invalid marker at
			// the same offset. A real gap keeps the marker and terminates unwind.
			r.setPageDelta(page, uint16(segmentEnd-pageBase), 0)
		}
		cursor = segmentEnd
	}
	r.segments++
	return nil
}

func (r *appDwarfRuleSet) addIntervals(loadBias uint64, intervals *appDwarfIntervalData) error {
	for _, block := range intervals.Blocks {
		for index, delta := range block.Deltas {
			deltaStart, overflow := addUint64(block.Start, uint64(delta.Offset))
			if overflow {
				return fmt.Errorf("DWARF delta address overflows uint64")
			}
			start, overflow := addUint64(loadBias, deltaStart)
			if overflow {
				return fmt.Errorf("DWARF interval address overflows uint64")
			}
			endOffset := block.End
			if index+1 < len(block.Deltas) {
				endOffset, overflow = addUint64(
					block.Start,
					uint64(block.Deltas[index+1].Offset),
				)
				if overflow {
					return fmt.Errorf("DWARF delta end overflows uint64")
				}
			}
			end, overflow := addUint64(loadBias, endOffset)
			if overflow {
				return fmt.Errorf("DWARF interval end overflows uint64")
			}
			if err := r.addSegment(start, end, delta.Info); err != nil {
				return err
			}
		}
	}
	return nil
}

func addUint64(left, right uint64) (uint64, bool) {
	if math.MaxUint64-left < right {
		return 0, true
	}
	return left + right, false
}

func (r *appDwarfRuleSet) materializePages() (
	[]appDwarfUnwindPageKey,
	[]appDwarfUnwindPage,
	[]appDwarfStackDeltaPair,
	int,
	int,
	error,
) {
	keys := make([]appDwarfUnwindPageKey, 0, len(r.pages))
	for key := range r.pages {
		keys = append(keys, key)
	}
	if len(keys) > appDwarfMaxPages {
		return nil, nil, nil, 0, 0, fmt.Errorf(
			"DWARF unwind page count %d exceeds %d", len(keys), appDwarfMaxPages,
		)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].PID != keys[j].PID {
			return keys[i].PID < keys[j].PID
		}
		return keys[i].Page < keys[j].Page
	})
	sourceDeltas := 0
	for _, key := range keys {
		sourceDeltas += len(r.pages[key].deltas)
	}
	// The source count is a safe upper bound for the compacted output. Reserve
	// it once (within the fixed map limit) to avoid repeatedly copying a
	// multi-million-entry backing array while loading a large application.
	deltaPairCapacity := (sourceDeltas + 1) / 2
	if deltaPairCapacity > appDwarfMaxTotalDeltas/2 {
		deltaPairCapacity = appDwarfMaxTotalDeltas / 2
	}
	pages := make([]appDwarfUnwindPage, 0, len(keys))
	deltaPairs := make([]appDwarfStackDeltaPair, 0, deltaPairCapacity)
	deltaCount := 0
	for _, key := range keys {
		builder := r.pages[key]
		ordered := true
		for index := 1; index < len(builder.deltas); index++ {
			if builder.deltas[index-1].AddressLow > builder.deltas[index].AddressLow {
				ordered = false
				break
			}
		}
		if !ordered {
			// Stability retains insertion order for repeated addresses, allowing
			// the compaction pass below to preserve last-write semantics.
			sort.SliceStable(builder.deltas, func(left, right int) bool {
				return builder.deltas[left].AddressLow < builder.deltas[right].AddressLow
			})
		}
		// Resolve repeated writes to one address using last-write semantics, then
		// remove transitions which do not change the active unwind rule. This is
		// performed in place so large applications do not need a second table.
		compacted := builder.deltas[:0]
		for cursor := 0; cursor < len(builder.deltas); {
			end := cursor + 1
			for end < len(builder.deltas) &&
				builder.deltas[end].AddressLow == builder.deltas[cursor].AddressLow {
				end++
			}
			transition := builder.deltas[end-1]
			if len(compacted) == 0 ||
				compacted[len(compacted)-1].UnwindInfo != transition.UnwindInfo {
				compacted = append(compacted, transition)
			}
			cursor = end
		}
		builder.deltas = compacted
		if len(compacted) >= appDwarfMaxPageDeltas {
			return nil, nil, nil, 0, 0, fmt.Errorf(
				"DWARF page pid=%d address=%#x has %d deltas, maximum is %d",
				key.PID, key.Page, len(compacted), appDwarfMaxPageDeltas-1,
			)
		}
		if deltaCount > appDwarfMaxTotalDeltas-len(compacted) {
			return nil, nil, nil, 0, 0, fmt.Errorf(
				"DWARF stack delta count exceeds %d", appDwarfMaxTotalDeltas,
			)
		}
		page := appDwarfUnwindPage{
			DeltaStart: uint32(deltaCount),
			Count:      uint16(len(compacted)),
		}
		bucketCursor := 0
		for bucket := range page.Buckets {
			boundary := bucket << 8
			for bucketCursor < len(compacted) &&
				int(compacted[bucketCursor].AddressLow) < boundary {
				bucketCursor++
			}
			page.Buckets[bucket] = uint16(bucketCursor)
		}
		for _, transition := range compacted {
			if deltaCount&1 == 0 {
				deltaPairs = append(deltaPairs, appDwarfStackDeltaPair{})
			}
			deltaPairs[len(deltaPairs)-1].Deltas[deltaCount&1] = appDwarfStackDelta{
				AddressLow: transition.AddressLow,
				UnwindInfo: transition.UnwindInfo,
			}
			deltaCount++
		}
		pages = append(pages, page)
	}
	return keys, pages, deltaPairs, deltaCount, sourceDeltas, nil
}

func appDwarfELFLoadBias(mapping processModuleMapping, elfFile *elf.File) (uint64, error) {
	for _, program := range elfFile.Progs {
		if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 {
			continue
		}
		alignment := program.Align
		if alignment == 0 || alignment&(alignment-1) != 0 {
			alignment = uint64(os.Getpagesize())
		}
		alignedOffset := program.Off &^ (alignment - 1)
		alignedVaddr := program.Vaddr &^ (alignment - 1)
		segmentEnd := (program.Off + program.Filesz + alignment - 1) &^ (alignment - 1)
		if mapping.fileOffset < alignedOffset || mapping.fileOffset >= segmentEnd {
			continue
		}
		mappedVaddr := alignedVaddr + mapping.fileOffset - alignedOffset
		if mapping.start < mappedVaddr {
			return 0, fmt.Errorf("mapping start %#x precedes ELF virtual address %#x",
				mapping.start, mappedVaddr)
		}
		return mapping.start - mappedVaddr, nil
	}
	return 0, fmt.Errorf("executable mapping offset %#x does not match a PT_LOAD segment",
		mapping.fileOffset)
}

type appDwarfModuleResolver struct {
	locations moduleBuildIDCache
}

// resolve converts a /proc/PID/maps entry into an exact ELF source. For a
// directly mapped APK member it also converts the archive-relative file
// offset into an ELF-relative offset, which is what appDwarfELFLoadBias
// expects when matching PT_LOAD segments.
func (r *appDwarfModuleResolver) resolve(
	mapping processModuleMapping,
) (libraryTarget, processModuleMapping, error) {
	path := strings.TrimSpace(strings.TrimSuffix(mapping.path, " (deleted)"))
	if path == "" {
		return libraryTarget{}, mapping, fmt.Errorf("module path is empty")
	}
	resolvedPath, relativeOffset, err := r.locations.resolveLocation(
		path,
		mapping.fileOffset,
	)
	if err != nil {
		return libraryTarget{}, mapping, err
	}
	target, err := resolveLibraryTarget(resolvedPath)
	if err != nil {
		return libraryTarget{}, mapping, err
	}
	mapping.fileOffset = relativeOffset
	return target, mapping, nil
}

func appDwarfExecutableMappings(mappings []processModuleMapping) []processModuleMapping {
	seen := make(map[string]struct{})
	result := make([]processModuleMapping, 0, len(mappings))
	for _, mapping := range mappings {
		path := strings.TrimSpace(mapping.path)
		if !mapping.executable || path == "" || strings.HasPrefix(path, "[") {
			continue
		}
		identity := fmt.Sprintf("%s\x00%x\x00%x", path, mapping.start, mapping.fileOffset)
		if _, found := seen[identity]; found {
			continue
		}
		seen[identity] = struct{}{}
		result = append(result, mapping)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].path != result[j].path {
			return result[i].path < result[j].path
		}
		return result[i].start < result[j].start
	})
	return result
}

func buildAppDwarfRules(pid uint32, mappings []processModuleMapping) (*appDwarfRuleSet, appDwarfLoadStats, []error) {
	rules := newAppDwarfRuleSet(pid)
	stats := appDwarfLoadStats{}
	var skipped []error
	resolver := &appDwarfModuleResolver{}
	for _, mapping := range appDwarfExecutableMappings(mappings) {
		target, relativeMapping, err := resolver.resolve(mapping)
		if err != nil {
			stats.SkippedModules++
			skipped = append(skipped, fmt.Errorf("skip DWARF module %q: %w",
				mapping.path, err))
			continue
		}
		var bias uint64
		var intervals *appDwarfIntervalData
		err = withLibraryELF(target, func(elfFile *elf.File) error {
			if elfFile.Machine != elf.EM_AARCH64 {
				return fmt.Errorf("ELF machine is %s, want AArch64", elfFile.Machine)
			}
			var biasErr error
			bias, biasErr = appDwarfELFLoadBias(relativeMapping, elfFile)
			if biasErr != nil {
				return biasErr
			}
			intervals, biasErr = extractAppDwarfIntervalsFromELF(
				elfFile,
				target.String(),
			)
			return biasErr
		})
		if err != nil {
			stats.SkippedModules++
			skipped = append(skipped, fmt.Errorf("skip DWARF module %q: %w",
				target.String(), err))
			continue
		}
		if intervals.NumDeltas == 0 {
			stats.SkippedModules++
			skipped = append(skipped, fmt.Errorf("skip DWARF module %q: no usable CFI",
				target.String()))
			continue
		}
		if err := rules.addIntervals(bias, intervals); err != nil {
			stats.SkippedModules++
			skipped = append(skipped, fmt.Errorf("skip DWARF module %q: %w",
				target.String(), err))
			continue
		}
		stats.Modules++
		if target.IsArchive() {
			stats.ArchiveModules++
		}
	}
	stats.Pages = len(rules.pages)
	stats.Segments = rules.segments
	stats.UnwindInfos = len(rules.infos)
	return rules, stats, skipped
}

func appDwarfPercentile(sortedValues []int, percentile int) int {
	if len(sortedValues) == 0 {
		return 0
	}
	index := (len(sortedValues)*percentile + 99) / 100
	if index == 0 {
		index = 1
	}
	return sortedValues[index-1]
}

// measureAppDwarfDeltaDistribution reports both the original page density and
// the 256-byte hot-path search density so deployments can quantify the bucket
// index's lookup reduction.
func measureAppDwarfDeltaDistribution(
	pages []appDwarfUnwindPage,
	deltas []appDwarfStackDeltaPair,
	deltaCount int,
	stats *appDwarfLoadStats,
) {
	pageCounts := make([]int, 0, len(pages))
	bucketCounts := make([]int, 0, len(pages)*16)
	for _, page := range pages {
		start := int(page.DeltaStart)
		end := start + int(page.Count)
		if start < 0 || end < start || end > deltaCount {
			continue
		}
		pageCounts = append(pageCounts, end-start)
		var buckets [16]int
		for index := start; index < end; index++ {
			delta, found := appDwarfDeltaAt(deltas, index)
			if !found {
				continue
			}
			buckets[delta.AddressLow>>8]++
		}
		bucketCounts = append(bucketCounts, buckets[:]...)
	}
	sort.Ints(pageCounts)
	sort.Ints(bucketCounts)
	stats.PageDeltasP50 = appDwarfPercentile(pageCounts, 50)
	stats.PageDeltasP90 = appDwarfPercentile(pageCounts, 90)
	stats.PageDeltasP99 = appDwarfPercentile(pageCounts, 99)
	stats.PageDeltasMax = appDwarfPercentile(pageCounts, 100)
	stats.BucketDeltasP50 = appDwarfPercentile(bucketCounts, 50)
	stats.BucketDeltasP90 = appDwarfPercentile(bucketCounts, 90)
	stats.BucketDeltasP99 = appDwarfPercentile(bucketCounts, 99)
	stats.BucketDeltasMax = appDwarfPercentile(bucketCounts, 100)
}

func appDwarfDeltaAt(
	deltas []appDwarfStackDeltaPair,
	index int,
) (appDwarfStackDelta, bool) {
	if index < 0 || index/2 >= len(deltas) {
		return appDwarfStackDelta{}, false
	}
	return deltas[index/2].Deltas[index&1], true
}

func updateAppDwarfPages(pageMap *ebpf.Map, keys []appDwarfUnwindPageKey, pages []appDwarfUnwindPage) error {
	if len(keys) == 0 {
		return nil
	}
	updated, err := pageMap.BatchUpdate(keys, pages, nil)
	if err == nil && updated == len(keys) {
		return nil
	}
	if updated < 0 || updated > len(keys) {
		updated = 0
	}
	for index := updated; index < len(keys); index++ {
		if updateErr := pageMap.Update(&keys[index], &pages[index], ebpf.UpdateAny); updateErr != nil {
			if err != nil {
				return fmt.Errorf("batch update failed (%v); update page %d/%d: %w",
					err, index+1, len(keys), updateErr)
			}
			return fmt.Errorf("update page %d/%d: %w", index+1, len(keys), updateErr)
		}
	}
	return nil
}

func updateAppDwarfDeltas(deltaMap *ebpf.Map, deltas []appDwarfStackDeltaPair) error {
	const batchSize = 65536
	for start := 0; start < len(deltas); start += batchSize {
		end := start + batchSize
		if end > len(deltas) {
			end = len(deltas)
		}
		keys := make([]uint32, end-start)
		for index := range keys {
			keys[index] = uint32(start + index)
		}
		updated, err := deltaMap.BatchUpdate(keys, deltas[start:end], nil)
		if err == nil && updated == len(keys) {
			continue
		}
		if updated < 0 || updated > len(keys) {
			updated = 0
		}
		for index := updated; index < len(keys); index++ {
			if updateErr := deltaMap.Update(&keys[index], &deltas[start+index], ebpf.UpdateAny); updateErr != nil {
				if err != nil {
					return fmt.Errorf("batch update failed (%v); update delta %d/%d: %w",
						err, start+index+1, len(deltas), updateErr)
				}
				return fmt.Errorf("update delta %d/%d: %w",
					start+index+1, len(deltas), updateErr)
			}
		}
	}
	return nil
}

func (p *Probe) prepareDwarfUnwind() error {
	p.dwarfUnwind = nil
	if !p.config.hasDwarfStackHooks() {
		return nil
	}
	if runtime.GOARCH != "arm64" {
		return fmt.Errorf("stack_mode=%s is currently supported only on arm64, running %s",
			AppDataStackDWARF, runtime.GOARCH)
	}
	if p.config.GetPid() == 0 || p.config.GetPid() > math.MaxUint32 {
		return fmt.Errorf("stack_mode=%s requires a valid 32-bit target pid, got %d",
			AppDataStackDWARF, p.config.GetPid())
	}
	pid := uint32(p.config.GetPid())
	mappings, err := loadProcessModuleMappings(pid)
	if err != nil {
		return err
	}
	rules, stats, skipped := buildAppDwarfRules(pid, mappings)
	keys, pages, deltas, deltaCount, sourceDeltas, err := rules.materializePages()
	if err != nil {
		return err
	}
	stats.Deltas = deltaCount
	stats.DeltaPairs = len(deltas)
	stats.SourceDeltas = sourceDeltas
	measureAppDwarfDeltaDistribution(pages, deltas, deltaCount, &stats)
	if stats.Modules == 0 || len(keys) == 0 {
		return fmt.Errorf("no usable arm64 DWARF CFI found in %d executable mappings: %w",
			len(appDwarfExecutableMappings(mappings)), errors.Join(skipped...))
	}
	p.dwarfUnwind = &appDwarfPreparedUnwind{
		pid:        pid,
		keys:       keys,
		pages:      pages,
		deltas:     deltas,
		deltaCount: deltaCount,
		infos:      rules.infos,
		stats:      stats,
		skipped:    skipped,
	}
	return nil
}

func (p *Probe) configureDwarfUnwind() error {
	if !p.config.hasDwarfStackHooks() {
		return nil
	}
	prepared := p.dwarfUnwind
	if prepared == nil {
		return fmt.Errorf("DWARF unwind rules were not prepared before map creation")
	}
	defer func() {
		// The page builders and packed upload tables are startup-only. Clear the
		// final references and return their pages to the OS so a large target
		// doesn't leave eCapture with a permanently inflated resident set.
		p.dwarfUnwind = nil
		prepared.keys = nil
		prepared.pages = nil
		prepared.deltas = nil
		prepared.infos = nil
		prepared.skipped = nil
		debug.FreeOSMemory()
	}()

	pagesMap, found, err := p.bpfManager.GetMap("app_dwarf_unwind_pages")
	if err != nil {
		return fmt.Errorf("get app_dwarf_unwind_pages map: %w", err)
	}
	if !found {
		return fmt.Errorf("app_dwarf_unwind_pages map was not loaded")
	}
	deltasMap, found, err := p.bpfManager.GetMap("app_dwarf_unwind_deltas")
	if err != nil {
		return fmt.Errorf("get app_dwarf_unwind_deltas map: %w", err)
	}
	if !found {
		return fmt.Errorf("app_dwarf_unwind_deltas map was not loaded")
	}
	infosMap, found, err := p.bpfManager.GetMap("app_dwarf_unwind_infos")
	if err != nil {
		return fmt.Errorf("get app_dwarf_unwind_infos map: %w", err)
	}
	if !found {
		return fmt.Errorf("app_dwarf_unwind_infos map was not loaded")
	}

	for index := range prepared.infos {
		key := uint32(index)
		if err := infosMap.Update(&key, &prepared.infos[index], ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update DWARF unwind info %d: %w", index, err)
		}
	}
	if err := updateAppDwarfDeltas(deltasMap, prepared.deltas); err != nil {
		return err
	}
	if err := updateAppDwarfPages(pagesMap, prepared.keys, prepared.pages); err != nil {
		return err
	}

	for _, skipErr := range prepared.skipped {
		p.Logger().Debug().Err(skipErr).Msg("Skipped executable mapping during DWARF CFI load")
	}
	p.Logger().Info().
		Uint32("pid", prepared.pid).
		Int("modules", prepared.stats.Modules).
		Int("archive_modules", prepared.stats.ArchiveModules).
		Int("skipped_modules", prepared.stats.SkippedModules).
		Int("pages", prepared.stats.Pages).
		Int("deltas", prepared.stats.Deltas).
		Int("delta_pairs", prepared.stats.DeltaPairs).
		Int("source_deltas", prepared.stats.SourceDeltas).
		Int("page_deltas_p50", prepared.stats.PageDeltasP50).
		Int("page_deltas_p90", prepared.stats.PageDeltasP90).
		Int("page_deltas_p99", prepared.stats.PageDeltasP99).
		Int("page_deltas_max", prepared.stats.PageDeltasMax).
		Int("bucket_deltas_p50", prepared.stats.BucketDeltasP50).
		Int("bucket_deltas_p90", prepared.stats.BucketDeltasP90).
		Int("bucket_deltas_p99", prepared.stats.BucketDeltasP99).
		Int("bucket_deltas_max", prepared.stats.BucketDeltasMax).
		Uint64("segments", prepared.stats.Segments).
		Int("unwind_infos", prepared.stats.UnwindInfos).
		Str("parser", "go-delve/delve/pkg/dwarf/frame").
		Msg("Loaded arm64 DWARF CFI for eBPF user-stack unwinding")
	return nil
}
