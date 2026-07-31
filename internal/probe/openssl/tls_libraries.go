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
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// TLSLibraries returns the primary TLS image followed by every compatible
// auxiliary image selected for the same capture. The primary image still owns
// bytecode/layout selection. Auxiliary images reuse only exported,
// symbol-addressed SSL hooks; profile offsets are never copied across images.
func (c *Config) TLSLibraries() []string {
	targets := c.TLSLibraryTargets()
	values := make([]string, 0, len(targets))
	for _, target := range targets {
		values = append(values, target.String())
	}
	return values
}

func (c *Config) TLSLibraryTargets() []libraryTarget {
	targets := make([]libraryTarget, 0, 1+len(c.tlsLibraryTargets))
	if primary, err := resolveLibraryTarget(c.OpensslPath); err == nil {
		targets = append(targets, primary)
	}
	targets = append(targets, c.tlsLibraryTargets...)
	return targets
}

func (c *Config) resolveTLSLibraries() error {
	explicit := append([]string(nil), c.OpensslExtraPaths...)
	for _, pattern := range c.OpensslExtraPatterns {
		matches, err := resolveLibraryGlobAll(pattern)
		if err != nil {
			return err
		}
		explicit = append(explicit, matches...)
	}
	for _, spec := range explicit {
		_, err := resolveLibraryTarget(spec)
		if err != nil {
			return fmt.Errorf("additional TLS library %q: %w", spec, err)
		}
	}

	values := explicit
	if c.AutoDiscoverTLSLibs {
		values = append(values, c.discoverPlatformTLSLibraries()...)
		values = append(values, discoverMappedTLSLibrarySpecs(c.Pid, c.Uid)...)
	}
	primary, err := resolveLibraryTarget(c.OpensslPath)
	if err != nil {
		return err
	}
	resolved := make([]libraryTarget, 0, len(values))
	seen := make(map[string]struct{}, len(values)+1)
	seen[primary.String()] = struct{}{}
	for _, spec := range uniqueLibrarySpecs(values) {
		target, err := resolveLibraryTarget(spec)
		if err != nil {
			if containsLibrarySpec(explicit, spec) {
				return fmt.Errorf("additional TLS library %q: %w", spec, err)
			}
			continue
		}
		if _, found := seen[target.String()]; found {
			continue
		}
		seen[target.String()] = struct{}{}
		if err := validateTLSLibraryTargetArchitecture(target); err != nil {
			if containsLibrarySpec(explicit, spec) {
				return err
			}
			continue
		}
		// Automatically discovered candidates are deliberately conservative:
		// require the classic plaintext API used by this BPF object. Explicit
		// paths surface a validation error instead of being silently ignored.
		readOK, readErr := elfTargetHasDynamicSymbol(target, "SSL_read")
		writeOK, writeErr := elfTargetHasDynamicSymbol(target, "SSL_write")
		if readErr != nil || writeErr != nil || !readOK || !writeOK {
			if containsLibrarySpec(explicit, spec) {
				return fmt.Errorf(
					"additional TLS library %q does not export SSL_read and SSL_write",
					spec,
				)
			}
			continue
		}
		resolved = append(resolved, target)
	}
	c.tlsLibraryTargets = resolved
	c.OpensslExtraPaths = make([]string, 0, len(resolved))
	for _, target := range resolved {
		c.OpensslExtraPaths = append(c.OpensslExtraPaths, target.String())
	}
	return nil
}

func resolveLibraryGlobAll(pattern string) ([]string, error) {
	return resolveLibrarySpecGlobAll(pattern)
}

func uniqueExistingPaths(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	infos := make([]os.FileInfo, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		value = filepath.Clean(value)
		if _, found := seen[value]; found {
			continue
		}
		info, err := os.Stat(value)
		if err != nil || info.IsDir() {
			continue
		}
		duplicate := false
		for _, existing := range infos {
			if os.SameFile(existing, info) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
		infos = append(infos, info)
	}
	return result
}

func validateTLSLibraryArchitecture(path string) error {
	file, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("inspect additional TLS library %q: %w", path, err)
	}
	defer file.Close()
	return validateTLSLibraryELFArchitecture(file, path)
}

func validateTLSLibraryELFArchitecture(file *elf.File, path string) error {
	wantClass := elf.ELFCLASS64
	wantMachine := elf.EM_NONE
	switch runtime.GOARCH {
	case "arm64":
		wantMachine = elf.EM_AARCH64
	case "amd64":
		wantMachine = elf.EM_X86_64
	case "arm":
		wantClass = elf.ELFCLASS32
		wantMachine = elf.EM_ARM
	case "386":
		wantClass = elf.ELFCLASS32
		wantMachine = elf.EM_386
	}
	if file.Class != wantClass ||
		(wantMachine != elf.EM_NONE && file.Machine != wantMachine) {
		return fmt.Errorf(
			"additional TLS library %q has architecture %s/%s, want %s",
			path,
			file.Class,
			file.Machine,
			runtime.GOARCH,
		)
	}
	return nil
}

func containsLibrarySpec(values []string, want string) bool {
	want = cleanLibrarySpec(want)
	for _, value := range values {
		if cleanLibrarySpec(value) == want {
			return true
		}
	}
	return false
}

func cleanLibrarySpec(value string) string {
	archivePath, member, archive := splitArchiveLibrarySpec(value)
	if archive {
		return filepath.Clean(archivePath) + archiveLibrarySeparator + member
	}
	return filepath.Clean(value)
}

func uniqueLibrarySpecs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		cleaned := cleanLibrarySpec(value)
		if _, found := seen[cleaned]; found {
			continue
		}
		seen[cleaned] = struct{}{}
		result = append(result, cleaned)
	}
	return result
}

func discoverMappedTLSLibraries(pid, uid uint64) []string {
	specs := discoverMappedTLSLibrarySpecs(pid, uid)
	paths := make([]string, 0, len(specs))
	for _, spec := range specs {
		if _, _, archive := splitArchiveLibrarySpec(spec); archive {
			continue
		}
		paths = append(paths, spec)
	}
	return paths
}

func discoverMappedTLSLibrarySpecs(pid, uid uint64) []string {
	if pid != 0 {
		return mappedTLSLibrarySpecsForPID(pid)
	}
	if uid == 0 {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		currentPID, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil || processUID(currentPID) != uid {
			continue
		}
		paths = append(paths, mappedTLSLibrarySpecsForPID(currentPID)...)
	}
	return uniqueLibrarySpecs(paths)
}

func processUID(pid uint64) uint64 {
	file, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) == 0 {
			return 0
		}
		value, _ := strconv.ParseUint(fields[0], 10, 64)
		return value
	}
	return 0
}

func mappedTLSLibrariesForPID(pid uint64) []string {
	specs := mappedTLSLibrarySpecsForPID(pid)
	paths := make([]string, 0, len(specs))
	for _, spec := range specs {
		if _, _, archive := splitArchiveLibrarySpec(spec); archive {
			continue
		}
		paths = append(paths, spec)
	}
	return uniqueExistingPaths(paths)
}

// MappedArchiveLibrarySpecsForPID returns executable ELF members which the
// process maps directly from APK/ZIP/JAR in archive.apk!/member.so form.
func MappedArchiveLibrarySpecsForPID(pid uint64) []string {
	specs := mappedTLSLibrarySpecsForPID(pid)
	result := make([]string, 0, len(specs))
	for _, spec := range specs {
		if _, _, archive := splitArchiveLibrarySpec(spec); archive {
			result = append(result, spec)
		}
	}
	return result
}

func mappedTLSLibrarySpecsForPID(pid uint64) []string {
	file, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	defer file.Close()
	var paths []string
	archiveOffsets := make(map[string]map[uint64]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		path := fields[len(fields)-1]
		perms := fields[1]
		offset, offsetErr := strconv.ParseUint(fields[2], 16, 64)
		base := strings.ToLower(filepath.Base(path))
		if strings.Contains(base, "libssl") ||
			strings.Contains(base, "boringssl") ||
			strings.Contains(base, "conscrypt") {
			paths = append(paths, path)
		}
		if offsetErr == nil && strings.Contains(perms, "x") &&
			isNativeLibraryArchive(path) {
			if archiveOffsets[path] == nil {
				archiveOffsets[path] = make(map[uint64]struct{})
			}
			archiveOffsets[path][offset] = struct{}{}
		}
	}
	for path, offsets := range archiveOffsets {
		paths = append(paths, mappedArchiveLibrarySpecs(path, offsets)...)
	}
	return uniqueLibrarySpecs(paths)
}

func isNativeLibraryArchive(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".apk", ".zip", ".jar":
		return true
	default:
		return false
	}
}

func mappedArchiveLibrarySpecs(
	path string, executableOffsets map[uint64]struct{},
) []string {
	targets, err := archiveLibraryTargets(path)
	if err != nil {
		return nil
	}
	var specs []string
	for _, target := range targets {
		end := target.ContainerOffset + target.ELFSize
		mapped := false
		for offset := range executableOffsets {
			if target.ContainerOffset <= offset && offset < end {
				mapped = true
				break
			}
		}
		if !mapped {
			continue
		}
		specs = append(specs, target.String())
	}
	return specs
}
