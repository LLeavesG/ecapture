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
	"debug/elf"
	"encoding/hex"
	"fmt"
	"strings"
)

const gnuBuildIDNoteType = 3

func normalizeBuildID(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "0x")
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

	section := file.Section(".note.gnu.build-id")
	if section == nil {
		return "", fmt.Errorf("ELF %q has no .note.gnu.build-id section", path)
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("read ELF build ID note from %q: %w", path, err)
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
			return "", fmt.Errorf("malformed ELF build ID note in %q", path)
		}
		name := bytes.TrimRight(data[12:nameEnd], "\x00")
		if noteType == gnuBuildIDNoteType && bytes.Equal(name, []byte("GNU")) {
			if descSize == 0 {
				return "", fmt.Errorf("empty ELF build ID in %q", path)
			}
			return hex.EncodeToString(data[descStart:descEnd]), nil
		}
		data = data[next:]
	}
	return "", fmt.Errorf("ELF %q has no GNU build ID note", path)
}

func alignNote(value int) int {
	return (value + 3) &^ 3
}
