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
	goerrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

type jniConversionCallerKey struct {
	PID        uint32
	Role       uint32
	CallerAddr uint64
}

type jniConversionFilterState struct {
	Active        bool
	JustActivated bool
	PendingRules  int
}

type jniConversionCallerFilter struct {
	mu        sync.Mutex
	rules     []JNIConversionCaller
	allowed   *ebpf.Map
	enabled   *ebpf.Map
	activated map[uint32]struct{}
	buildIDs  map[string]error
	loadMaps  func(uint32) ([]processModuleMapping, error)
	verifyELF func(string, string) error
}

func newJNIConversionCallerFilter(
	rules []JNIConversionCaller,
	allowed *ebpf.Map,
	enabled *ebpf.Map,
) *jniConversionCallerFilter {
	return &jniConversionCallerFilter{
		rules:     append([]JNIConversionCaller(nil), rules...),
		allowed:   allowed,
		enabled:   enabled,
		activated: make(map[uint32]struct{}),
		buildIDs:  make(map[string]error),
		loadMaps:  loadProcessModuleMappings,
		verifyELF: verifyELFBuildID,
	}
}

// activate resolves every stable module-relative rule for pid before enabling
// the kernel gate. Until then the PID remains in bootstrap mode so a library
// loaded slightly later can still generate the event that triggers a retry.
func (f *jniConversionCallerFilter) activate(pid uint32) (jniConversionFilterState, error) {
	if f == nil || len(f.rules) == 0 {
		return jniConversionFilterState{}, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, found := f.activated[pid]; found {
		return jniConversionFilterState{Active: true}, nil
	}
	if f.allowed == nil || f.enabled == nil {
		return jniConversionFilterState{}, fmt.Errorf(
			"JNI conversion caller filter maps are unavailable",
		)
	}
	mappings, err := f.loadMaps(pid)
	if err != nil {
		return jniConversionFilterState{}, err
	}
	keys, unresolved, err := resolveJNIConversionCallerRules(
		mappings,
		f.rules,
		f.verifyBuildID,
	)
	if err != nil {
		return jniConversionFilterState{PendingRules: len(unresolved)}, err
	}
	if len(unresolved) != 0 {
		return jniConversionFilterState{PendingRules: len(unresolved)}, nil
	}
	one := uint8(1)
	for _, key := range keys {
		current := key
		current.PID = pid
		if err := f.allowed.Update(&current, &one, ebpf.UpdateAny); err != nil {
			return jniConversionFilterState{}, fmt.Errorf(
				"allow JNI conversion caller pid=%d role=%d addr=0x%x: %w",
				key.PID,
				key.Role,
				key.CallerAddr,
				err,
			)
		}
	}
	if err := f.enabled.Update(&pid, &one, ebpf.UpdateAny); err != nil {
		return jniConversionFilterState{}, fmt.Errorf(
			"enable JNI conversion caller filter for pid %d: %w",
			pid,
			err,
		)
	}
	f.activated[pid] = struct{}{}
	return jniConversionFilterState{JustActivated: true}, nil
}

func (f *jniConversionCallerFilter) verifyBuildID(path, buildID string) error {
	if buildID == "" {
		return nil
	}
	key := path + "\x00" + buildID
	if result, found := f.buildIDs[key]; found {
		return result
	}
	err := f.verifyELF(path, buildID)
	f.buildIDs[key] = err
	return err
}

func resolveJNIConversionCallerRules(
	mappings []processModuleMapping,
	rules []JNIConversionCaller,
	verifyBuildID func(string, string) error,
) ([]jniConversionCallerKey, []int, error) {
	keys := make([]jniConversionCallerKey, 0, len(rules))
	var unresolved []int
	var verificationErrors []error
	for index, rule := range rules {
		role, found := jniConversionRoleID(rule.Role)
		if !found {
			return nil, nil, fmt.Errorf("unsupported JNI conversion role %q", rule.Role)
		}
		var ruleKeys []jniConversionCallerKey
		var ruleVerificationErrors []error
		for _, mapping := range mappings {
			if !mapping.executable || !jniCallerModuleMatches(rule, mapping.path) {
				continue
			}
			offset := uint64(rule.Offset)
			mappingLength := mapping.end - mapping.start
			if offset < mapping.fileOffset ||
				offset-mapping.fileOffset >= mappingLength {
				continue
			}
			if rule.BuildID != "" && verifyBuildID != nil {
				if err := verifyBuildID(mapping.path, rule.BuildID); err != nil {
					ruleVerificationErrors = append(
						ruleVerificationErrors,
						fmt.Errorf("%s: %w", mapping.path, err),
					)
					continue
				}
			}
			ruleKeys = append(ruleKeys, jniConversionCallerKey{
				Role:       role,
				CallerAddr: mapping.start + offset - mapping.fileOffset,
			})
		}
		if len(ruleKeys) == 0 {
			unresolved = append(unresolved, index)
			verificationErrors = append(verificationErrors, ruleVerificationErrors...)
			continue
		}
		keys = append(keys, ruleKeys...)
	}
	if len(verificationErrors) != 0 {
		return nil, unresolved, fmt.Errorf(
			"verify JNI caller module Build ID: %w",
			goerrors.Join(verificationErrors...),
		)
	}
	return keys, unresolved, nil
}

func jniCallerModuleMatches(rule JNIConversionCaller, mappedPath string) bool {
	mappedPath = strings.TrimSuffix(strings.TrimSpace(mappedPath), " (deleted)")
	if mappedPath == "" {
		return false
	}
	if rule.Module != "" {
		return filepath.Base(mappedPath) == rule.Module
	}
	matched, err := filepath.Match(rule.ModuleGlob, mappedPath)
	return err == nil && matched
}

func loadProcessModuleMappings(pid uint32) ([]processModuleMapping, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	mappings, err := parseProcessModuleMappings(file)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return mappings, nil
}
