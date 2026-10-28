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
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

const gnuBuildIDNoteType = 3

func normalizeBuildID(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "0x")
	value = strings.ReplaceAll(value, ":", "")
	if value == "" {
		return "", nil
	}
	if len(value)%2 != 0 {
		return "", fmt.Errorf("must contain an even number of hexadecimal digits")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("must be hexadecimal: %w", err)
	}
	return value, nil
}

func verifyELFBuildID(path, expected string) error {
	actual, err := readELFBuildID(path)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("ELF build ID mismatch for %q: got %s, want %s",
			path, actual, expected)
	}
	return nil
}

func readELFBuildID(path string) (string, error) {
	file, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("open ELF %q: %w", path, err)
	}
	defer file.Close()
	return readELFBuildIDFromFile(file, path)
}

func readELFBuildIDFromFile(file *elf.File, label string) (string, error) {
	section := file.Section(".note.gnu.build-id")
	if section == nil {
		return "", fmt.Errorf("ELF %q has no .note.gnu.build-id section", label)
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("read ELF build ID note from %q: %w", label, err)
	}
	for len(data) >= 12 {
		nameSize := int(file.ByteOrder.Uint32(data[0:4]))
		descSize := int(file.ByteOrder.Uint32(data[4:8]))
		noteType := file.ByteOrder.Uint32(data[8:12])
		nameEnd := 12 + nameSize
		descStart := alignNote(nameEnd)
		descEnd := descStart + descSize
		next := alignNote(descEnd)
		if nameEnd > len(data) || descEnd > len(data) || next > len(data) {
			return "", fmt.Errorf("malformed ELF build ID note in %q", label)
		}
		name := bytes.TrimRight(data[12:nameEnd], "\x00")
		if noteType == gnuBuildIDNoteType && bytes.Equal(name, []byte("GNU")) {
			if descSize == 0 {
				return "", fmt.Errorf("empty ELF build ID in %q", label)
			}
			return hex.EncodeToString(data[descStart:descEnd]), nil
		}
		data = data[next:]
	}
	return "", fmt.Errorf("ELF %q has no GNU build ID note", label)
}

func verifyLibraryTargetBuildID(
	target libraryTarget, expected string,
) error {
	var actual string
	err := withLibraryELF(target, func(file *elf.File) error {
		var readErr error
		actual, readErr = readELFBuildIDFromFile(file, target.String())
		return readErr
	})
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("ELF build ID mismatch for %q: got %s, want %s",
			target.String(), actual, expected)
	}
	return nil
}

func alignNote(value int) int {
	return (value + 3) &^ 3
}

func verifyLibraryTargetSHA256(target libraryTarget, expected string) error {
	actual, err := readLibraryTargetSHA256(target)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("ELF SHA-256 mismatch for %q: got %s, want %s", target.String(), actual, expected)
	}
	return nil
}

// ReadLibrarySHA256 returns the ELF member digest, excluding an APK container.
// It also identifies libraries whose linker omitted a GNU Build ID.
func ReadLibrarySHA256(spec string) (string, error) {
	target, err := resolveLibraryTarget(spec)
	if err != nil {
		return "", err
	}
	return readLibraryTargetSHA256(target)
}

func readLibraryTargetSHA256(target libraryTarget) (string, error) {
	file, err := os.Open(target.RuntimePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	var reader io.Reader = file
	if target.IsArchive() {
		reader = io.NewSectionReader(file, int64(target.ContainerOffset), int64(target.ELFSize))
	}
	hash := sha256.New()
	n, err := io.Copy(hash, reader)
	if err != nil {
		return "", err
	}
	if uint64(n) != target.ELFSize {
		return "", fmt.Errorf("ELF size changed while hashing %q", target.String())
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
