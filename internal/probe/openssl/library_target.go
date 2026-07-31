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
	"archive/zip"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const archiveLibrarySeparator = "!/"

// libraryTarget identifies either a standalone ELF or an uncompressed ELF
// member mapped directly from an APK/ZIP. Android's linker maps the latter
// against the archive inode, so uprobes must use RuntimePath and add
// ContainerOffset to the ELF-relative file offset.
type libraryTarget struct {
	Spec            string
	RuntimePath     string
	ArchiveMember   string
	ContainerOffset uint64
	ELFSize         uint64
}

func (t libraryTarget) IsArchive() bool {
	return t.ArchiveMember != ""
}

func (t libraryTarget) String() string {
	if t.Spec != "" {
		return t.Spec
	}
	if t.ArchiveMember != "" {
		return t.RuntimePath + archiveLibrarySeparator + t.ArchiveMember
	}
	return t.RuntimePath
}

func (t libraryTarget) runtimeOffset(elfOffset uint64) (uint64, error) {
	if elfOffset > ^uint64(0)-t.ContainerOffset {
		return 0, fmt.Errorf("library offset overflows uint64")
	}
	return t.ContainerOffset + elfOffset, nil
}

func resolveLibraryTarget(spec string) (libraryTarget, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return libraryTarget{}, fmt.Errorf("library path is empty")
	}
	archivePath, member, archive := splitArchiveLibrarySpec(spec)
	if !archive {
		info, err := os.Stat(spec)
		if err != nil {
			return libraryTarget{}, err
		}
		if info.IsDir() {
			return libraryTarget{}, fmt.Errorf("%q is a directory", spec)
		}
		path := filepath.Clean(spec)
		return libraryTarget{
			Spec:        path,
			RuntimePath: path,
			ELFSize:     uint64(info.Size()),
		}, nil
	}

	archivePath = filepath.Clean(archivePath)
	info, err := os.Stat(archivePath)
	if err != nil {
		return libraryTarget{}, fmt.Errorf("stat archive %q: %w", archivePath, err)
	}
	if info.IsDir() {
		return libraryTarget{}, fmt.Errorf("archive %q is a directory", archivePath)
	}
	reader, closer, err := openZIPReader(archivePath)
	if err != nil {
		return libraryTarget{}, err
	}
	defer closer.Close()
	for _, entry := range reader.File {
		if entry.Name != member {
			continue
		}
		return libraryTargetForZIPEntry(archivePath, entry)
	}
	return libraryTarget{}, fmt.Errorf("archive %q has no member %q",
		archivePath, member)
}

func splitArchiveLibrarySpec(spec string) (string, string, bool) {
	index := strings.Index(spec, archiveLibrarySeparator)
	if index <= 0 {
		return spec, "", false
	}
	archivePath := strings.TrimSpace(spec[:index])
	member := strings.TrimLeft(strings.TrimSpace(spec[index+1:]), "/")
	if archivePath == "" || member == "" {
		return spec, "", false
	}
	return archivePath, member, true
}

func resolveLibrarySpecGlobAll(pattern string) ([]string, error) {
	archivePattern, member, archive := splitArchiveLibrarySpec(pattern)
	globPattern := pattern
	if archive {
		globPattern = archivePattern
	}
	matches, err := filepath.Glob(globPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid library glob %q: %w", pattern, err)
	}
	if !archive {
		files := uniqueExistingPaths(matches)
		if len(files) == 0 {
			return nil, fmt.Errorf("library glob %q did not match a file",
				pattern)
		}
		return files, nil
	}
	specs := make([]string, 0, len(matches))
	for _, match := range matches {
		spec := filepath.Clean(match) + archiveLibrarySeparator + member
		target, targetErr := resolveLibraryTarget(spec)
		if targetErr != nil {
			continue
		}
		specs = append(specs, target.String())
	}
	specs = uniqueLibrarySpecs(specs)
	if len(specs) == 0 {
		return nil, fmt.Errorf(
			"library glob %q did not match an archive member", pattern)
	}
	return specs, nil
}

func libraryTargetForZIPEntry(
	archivePath string, entry *zip.File,
) (libraryTarget, error) {
	if entry.Method != zip.Store {
		return libraryTarget{}, fmt.Errorf(
			"archive member %q is compressed; Android can only directly map uncompressed native libraries",
			entry.Name,
		)
	}
	offset, err := entry.DataOffset()
	if err != nil {
		return libraryTarget{}, fmt.Errorf(
			"resolve data offset for %q in %q: %w",
			entry.Name,
			archivePath,
			err,
		)
	}
	if offset < 0 {
		return libraryTarget{}, fmt.Errorf(
			"archive member %q has a negative data offset", entry.Name)
	}
	path := filepath.Clean(archivePath)
	return libraryTarget{
		Spec:            path + archiveLibrarySeparator + entry.Name,
		RuntimePath:     path,
		ArchiveMember:   entry.Name,
		ContainerOffset: uint64(offset),
		ELFSize:         entry.UncompressedSize64,
	}, nil
}

func openZIPReader(path string) (*zip.Reader, *os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open archive %q: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("stat archive %q: %w", path, err)
	}
	reader, err := zip.NewReader(file, info.Size())
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("open ZIP archive %q: %w", path, err)
	}
	return reader, file, nil
}

func archiveLibraryTargets(path string) ([]libraryTarget, error) {
	reader, closer, err := openZIPReader(path)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	var targets []libraryTarget
	for _, entry := range reader.File {
		if entry.Method != zip.Store || entry.UncompressedSize64 == 0 {
			continue
		}
		target, targetErr := libraryTargetForZIPEntry(path, entry)
		if targetErr != nil {
			continue
		}
		if targetErr = withLibraryELF(
			target,
			func(*elf.File) error { return nil },
		); targetErr != nil {
			continue
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func withLibraryELF(target libraryTarget, fn func(*elf.File) error) error {
	if !target.IsArchive() {
		file, err := elf.Open(target.RuntimePath)
		if err != nil {
			return fmt.Errorf("open ELF %q: %w", target.RuntimePath, err)
		}
		defer file.Close()
		return fn(file)
	}

	container, err := os.Open(target.RuntimePath)
	if err != nil {
		return fmt.Errorf("open archive %q: %w", target.RuntimePath, err)
	}
	defer container.Close()
	if target.ELFSize == 0 {
		return fmt.Errorf("archive member %q is empty", target.ArchiveMember)
	}
	if target.ContainerOffset > uint64(^uint64(0)>>1) ||
		target.ELFSize > uint64(^uint64(0)>>1) {
		return fmt.Errorf("archive member %q is too large", target.ArchiveMember)
	}
	section := io.NewSectionReader(
		container,
		int64(target.ContainerOffset),
		int64(target.ELFSize),
	)
	file, err := elf.NewFile(section)
	if err != nil {
		return fmt.Errorf("open ELF %q: %w", target.String(), err)
	}
	defer file.Close()
	return fn(file)
}

// WithLibraryELF opens either a standalone ELF or an exact
// archive.apk!/member.so target for read-only inspection.
func WithLibraryELF(spec string, fn func(*elf.File) error) error {
	target, err := resolveLibraryTarget(spec)
	if err != nil {
		return err
	}
	return withLibraryELF(target, fn)
}

func validateTLSLibraryTargetArchitecture(target libraryTarget) error {
	return withLibraryELF(target, func(file *elf.File) error {
		return validateTLSLibraryELFArchitecture(file, target.String())
	})
}

func elfTargetHasDynamicSymbol(
	target libraryTarget, symbol string,
) (bool, error) {
	found := false
	err := withLibraryELF(target, func(file *elf.File) error {
		symbols, err := file.DynamicSymbols()
		if err != nil {
			if err == elf.ErrNoSymbols {
				return nil
			}
			return err
		}
		for _, current := range symbols {
			if current.Name == symbol &&
				elf.ST_TYPE(current.Info) == elf.STT_FUNC {
				found = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("inspect dynamic symbols in %q: %w",
			target.String(), err)
	}
	return found, nil
}

func librarySymbolFileOffset(
	target libraryTarget, symbol string,
) (uint64, error) {
	var offset uint64
	err := withLibraryELF(target, func(file *elf.File) error {
		symbols, symbolsErr := file.Symbols()
		if symbolsErr != nil && symbolsErr != elf.ErrNoSymbols {
			return symbolsErr
		}
		dynamic, dynamicErr := file.DynamicSymbols()
		if dynamicErr != nil && dynamicErr != elf.ErrNoSymbols {
			return dynamicErr
		}
		symbols = append(symbols, dynamic...)
		for _, current := range symbols {
			if current.Name != symbol ||
				elf.ST_TYPE(current.Info) != elf.STT_FUNC {
				continue
			}
			offset = current.Value
			for _, program := range file.Progs {
				if program.Type != elf.PT_LOAD ||
					program.Flags&elf.PF_X == 0 {
					continue
				}
				if program.Vaddr <= current.Value &&
					current.Value < program.Vaddr+program.Memsz {
					offset = current.Value - program.Vaddr + program.Off
					break
				}
			}
			if offset == 0 {
				return fmt.Errorf("symbol %q has no file address", symbol)
			}
			return nil
		}
		return fmt.Errorf("symbol %q was not found", symbol)
	})
	if err != nil {
		return 0, fmt.Errorf("resolve symbol in %q: %w", target.String(), err)
	}
	return offset, nil
}
