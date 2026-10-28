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
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveArchiveLibraryTarget(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()

	archivePath := filepath.Join(t.TempDir(), "provider.apk")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archive)
	header := &zip.FileHeader{
		Name:   "lib/test/libprovider.so",
		Method: zip.Store,
	}
	member, err := writer.CreateHeader(header)
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

	spec := archivePath + "!/lib/test/libprovider.so"
	target, err := resolveLibraryTarget(spec)
	if err != nil {
		t.Fatalf("resolveLibraryTarget() error = %v", err)
	}
	image, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(image)
	for _, path := range []string{executable, spec} {
		actual, err := ReadLibrarySHA256(path)
		if err != nil || actual != hex.EncodeToString(digest[:]) {
			t.Fatalf("ELF digest for %s: %s, %v", path, actual, err)
		}
	}
	if err := verifyLibraryTargetSHA256(target, hex.EncodeToString(digest[:])); err != nil {
		t.Fatalf("member SHA-256 must exclude APK container: %v", err)
	}
	if err := verifyLibraryTargetSHA256(target, string(make([]byte, 64))); err == nil {
		t.Fatal("wrong member SHA-256 accepted")
	}
	if !target.IsArchive() ||
		target.RuntimePath != archivePath ||
		target.ArchiveMember != "lib/test/libprovider.so" ||
		target.ContainerOffset == 0 ||
		target.ELFSize == 0 {
		t.Fatalf("unexpected target: %#v", target)
	}
	err = withLibraryELF(target, func(file *elf.File) error {
		if file.Type != elf.ET_EXEC {
			t.Fatalf("archive member ELF type = %s, want ET_EXEC", file.Type)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withLibraryELF() error = %v", err)
	}
	raw, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	magic := make([]byte, 4)
	if _, err := raw.ReadAt(magic, int64(target.ContainerOffset)); err != nil {
		t.Fatal(err)
	}
	if string(magic) != "\x7fELF" {
		t.Fatalf("member data offset points to %x, want ELF magic", magic)
	}

	directELF, err := elf.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := directELF.Symbols()
	if err == elf.ErrNoSymbols {
		symbols, err = directELF.DynamicSymbols()
	}
	directELF.Close()
	if err != nil {
		t.Fatalf("read test executable symbols: %v", err)
	}
	symbolName := ""
	for _, symbol := range symbols {
		if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC &&
			symbol.Value != 0 &&
			symbol.Name != "" {
			symbolName = symbol.Name
			break
		}
	}
	if symbolName == "" {
		t.Fatal("test executable has no function symbol")
	}
	elfOffset, err := librarySymbolFileOffset(target, symbolName)
	if err != nil {
		t.Fatalf("librarySymbolFileOffset(%q) error = %v",
			symbolName, err)
	}
	runtimeOffset, err := target.runtimeOffset(elfOffset)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeOffset != target.ContainerOffset+elfOffset {
		t.Fatalf("runtime symbol offset = %#x, want %#x",
			runtimeOffset, target.ContainerOffset+elfOffset)
	}

	globbed, err := resolveLibraryGlob(
		filepath.Join(filepath.Dir(archivePath), "*.apk") +
			"!/lib/test/libprovider.so",
	)
	if err != nil {
		t.Fatalf("resolveLibraryGlob() archive error = %v", err)
	}
	if globbed != spec {
		t.Fatalf("resolveLibraryGlob() = %q, want %q", globbed, spec)
	}

	discovered := mappedArchiveLibrarySpecs(
		archivePath,
		map[uint64]struct{}{target.ContainerOffset: {}},
	)
	if len(discovered) != 1 || discovered[0] != spec {
		t.Fatalf("mappedArchiveLibrarySpecs() = %#v, want %q",
			discovered, spec)
	}

	locationCache := &moduleBuildIDCache{}
	locationPath, locationOffset, err := locationCache.resolveLocation(
		archivePath,
		target.ContainerOffset+0x1234,
	)
	if err != nil {
		t.Fatalf("resolveLocation() error = %v", err)
	}
	if locationPath != spec || locationOffset != 0x1234 {
		t.Fatalf("resolveLocation() = %q %#x, want %q %#x",
			locationPath, locationOffset, spec, uint64(0x1234))
	}
}

func TestResolveArchiveLibraryTargetRejectsCompressedMember(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "compressed.apk")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(archive)
	member, err := writer.Create("lib/test/libprovider.so")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write([]byte("\x7fELF")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveLibraryTarget(
		archivePath + "!/lib/test/libprovider.so",
	); err == nil {
		t.Fatal("resolveLibraryTarget() should reject compressed members")
	}
}

func TestLibraryTargetRuntimeOffset(t *testing.T) {
	target := libraryTarget{ContainerOffset: 0x4000}
	got, err := target.runtimeOffset(0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x5234 {
		t.Fatalf("runtimeOffset() = %#x, want %#x", got, uint64(0x5234))
	}
}
