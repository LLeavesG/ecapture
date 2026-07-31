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

package openssl

import (
	"fmt"
	"strings"

	manager "github.com/gojue/ebpfmanager"
)

// archiveUprobeSpec is separated from manager.Probe because upstream
// ebpfmanager validates BinaryPath as an ELF. For an Android APK mapping the
// kernel needs the APK inode plus an absolute ZIP member offset instead.
type archiveUprobeSpec struct {
	id          manager.ProbeIdentificationPair
	runtimePath string
	offset      uint64
	ret         bool
	source      string
}

func newArchiveUprobeSpec(
	probe *manager.Probe, target libraryTarget,
) archiveUprobeSpec {
	return archiveUprobeSpec{
		id: manager.ProbeIdentificationPair{
			UID:          probe.UID,
			EbpfFuncName: probe.EbpfFuncName,
		},
		runtimePath: target.RuntimePath,
		offset:      probe.UAddress,
		ret:         strings.HasPrefix(probe.Section, "uretprobe/"),
		source:      target.String(),
	}
}

func (p *Probe) attachArchiveUprobes() error {
	if len(p.archiveUprobes) == 0 {
		return nil
	}
	attached := make([]archiveUprobeCloser, 0, len(p.archiveUprobes))
	archiveIDs := make(map[manager.ProbeIdentificationPair]struct{},
		len(p.archiveUprobes))
	for _, spec := range p.archiveUprobes {
		programs, found, err := p.bpfManager.GetProgram(spec.id)
		if err != nil {
			closeArchiveUprobes(attached)
			return fmt.Errorf("get program %s: %w", spec.id.String(), err)
		}
		if !found || len(programs) != 1 || programs[0] == nil {
			closeArchiveUprobes(attached)
			return fmt.Errorf("program %s was not loaded", spec.id.String())
		}
		closer, err := attachArchiveUprobe(
			spec.runtimePath,
			spec.offset,
			spec.ret,
			int(p.config.GetPid()),
			programs[0],
		)
		if err != nil {
			closeArchiveUprobes(attached)
			return fmt.Errorf("attach %s at %s+%#x: %w",
				spec.id.String(), spec.runtimePath, spec.offset, err)
		}
		attached = append(attached, closer)
		archiveIDs[spec.id] = struct{}{}
		p.Logger().Info().
			Str("library", spec.source).
			Uint64("archive_offset", spec.offset).
			Bool("return_probe", spec.ret).
			Msg("Attached archive-backed uprobe")
	}
	for _, closer := range attached {
		p.closer = append(p.closer, closer)
	}

	// These programs are already attached through the raw perf-event path.
	// Keeping their manager probes would make manager.Start try to parse the
	// APK itself as ELF and fail.
	filtered := p.bpfManager.Probes[:0]
	for _, probe := range p.bpfManager.Probes {
		id := manager.ProbeIdentificationPair{
			UID:          probe.UID,
			EbpfFuncName: probe.EbpfFuncName,
		}
		if _, found := archiveIDs[id]; found {
			continue
		}
		filtered = append(filtered, probe)
	}
	p.bpfManager.Probes = filtered
	selectors := make([]manager.ProbesSelector, 0, len(filtered))
	for _, probe := range filtered {
		selectors = append(selectors, &manager.ProbeSelector{
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				UID:          probe.UID,
				EbpfFuncName: probe.EbpfFuncName,
			},
		})
	}
	if err := p.bpfManager.UpdateActivatedProbes(selectors); err != nil {
		return fmt.Errorf("update manager probes after archive attach: %w", err)
	}
	return nil
}

type archiveUprobeCloser interface {
	Close() error
}

func closeArchiveUprobes(values []archiveUprobeCloser) {
	for _, closer := range values {
		_ = closer.Close()
	}
}
