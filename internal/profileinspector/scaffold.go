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

package profileinspector

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/gojue/ecapture/internal/probe/openssl"
)

const defaultScaffoldMaxHooks = 8

type ScaffoldOptions struct {
	Name     string
	Package  string
	UID      uint64
	PID      uint64
	MaxHooks int
}

// ScaffoldProfile turns only candidates with a known direct-buffer ABI into a
// diagnostic profile. The output intentionally keeps unknown raw flows and
// must be marker-validated before production use.
func ScaffoldProfile(report *Report, options ScaffoldOptions) (*openssl.ApplicationProfile, error) {
	if report == nil {
		return nil, fmt.Errorf("inspection report is nil")
	}
	if options.PID == 0 {
		options.PID = report.PID
	}
	if options.Package == "" && options.UID == 0 && options.PID == 0 {
		return nil, fmt.Errorf("profile scaffold requires package, uid, or pid")
	}
	if options.MaxHooks == 0 {
		options.MaxHooks = defaultScaffoldMaxHooks
	}
	if options.MaxHooks < 0 || options.MaxHooks > openssl.MaxApplicationHooks {
		return nil, fmt.Errorf("max hooks must be 0 (default) or between 1 and %d",
			openssl.MaxApplicationHooks)
	}
	if strings.TrimSpace(options.Name) == "" {
		switch {
		case options.Package != "":
			options.Name = sanitizeName(options.Package) + "-discovery"
		case options.PID != 0:
			options.Name = fmt.Sprintf("pid-%d-discovery", options.PID)
		default:
			options.Name = fmt.Sprintf("uid-%d-discovery", options.UID)
		}
	}

	type rankedCandidate struct {
		library   LibraryReport
		candidate HookCandidate
	}
	var ranked []rankedCandidate
	for _, library := range report.Libraries {
		if library.Error != "" {
			continue
		}
		for _, candidate := range library.Candidates {
			if candidate.Recipe == nil {
				continue
			}
			ranked = append(ranked, rankedCandidate{library: library, candidate: candidate})
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].candidate.Priority != ranked[j].candidate.Priority {
			return ranked[i].candidate.Priority > ranked[j].candidate.Priority
		}
		if ranked[i].candidate.Layer != ranked[j].candidate.Layer {
			return ranked[i].candidate.Layer < ranked[j].candidate.Layer
		}
		if ranked[i].library.Path != ranked[j].library.Path {
			return ranked[i].library.Path < ranked[j].library.Path
		}
		return ranked[i].candidate.Symbol < ranked[j].candidate.Symbol
	})

	hooks := make([]openssl.ApplicationDataHook, 0, min(options.MaxHooks, len(ranked)))
	names := make(map[string]int)
	for _, current := range ranked {
		if len(hooks) == options.MaxHooks {
			break
		}
		candidate := current.candidate
		recipe := candidate.Recipe
		name := uniqueHookName(sanitizeName(candidate.Family+"-"+candidate.Role), names)
		hook := openssl.ApplicationDataHook{
			Name:           name,
			Library:        current.library.Path,
			BuildID:        current.library.BuildID,
			Direction:      recipe.Direction,
			CaptureOn:      recipe.CaptureOn,
			BufferArg:      recipe.BufferArg,
			BufferOffset:   openssl.OffsetValue(recipe.BufferOffset),
			BufferIndirect: recipe.BufferIndirect,
			LengthSource:   recipe.LengthSource,
			LengthArg:      recipe.LengthArg,
			FixedLength:    recipe.FixedLength,
			LengthOffset:   openssl.OffsetValue(recipe.LengthOffset),
			LengthSize:     recipe.LengthSize,
			LengthIndirect: recipe.LengthIndirect,
			MaxBytes:       recipe.MaxBytes,
			ContextArg:     recipe.ContextArg,
			StreamArg:      recipe.StreamArg,
			BufferFormat:   recipe.BufferFormat,
			VectorCountArg: recipe.VectorCountArg,
		}
		if candidate.SymbolSource == "dynamic" {
			hook.Symbol = candidate.Symbol
		} else if candidate.FileOffset != "" {
			var offset openssl.OffsetValue
			if err := offset.UnmarshalJSON([]byte(fmt.Sprintf("%q", candidate.FileOffset))); err != nil {
				return nil, fmt.Errorf("parse candidate offset %q: %w", candidate.FileOffset, err)
			}
			hook.Offset = offset
		} else {
			continue
		}
		hooks = append(hooks, hook)
	}

	strategies := []string{openssl.StrategyRawPackets}
	var jniDiscovery *openssl.JNIDiscoveryProfile
	for _, library := range report.Libraries {
		var offsets []openssl.OffsetValue
		for _, candidate := range library.Candidates {
			if candidate.Family != "art-jni" || candidate.Role != "register-natives" ||
				candidate.FileOffset == "" {
				continue
			}
			var offset openssl.OffsetValue
			if err := offset.UnmarshalJSON([]byte(fmt.Sprintf("%q", candidate.FileOffset))); err != nil {
				return nil, fmt.Errorf("parse JNI RegisterNatives offset %q: %w",
					candidate.FileOffset, err)
			}
			offsets = append(offsets, offset)
			if len(offsets) == openssl.MaxJNIRegisterHooks {
				break
			}
		}
		if len(offsets) == 0 {
			continue
		}
		jniDiscovery = &openssl.JNIDiscoveryProfile{
			Library:                library.Path,
			BuildID:                library.BuildID,
			RegisterNativesOffsets: offsets,
		}
		strategies = append(strategies, openssl.StrategyJNIDiscovery)
		break
	}
	if len(hooks) != 0 {
		strategies = append(strategies, openssl.StrategyAppData)
	}
	matchPID := options.PID
	if options.Package != "" || options.UID != 0 {
		// Package/UID profiles survive the application restart required to see
		// early RegisterNatives calls.
		matchPID = 0
	}
	perfReorder := true
	profile := &openssl.ApplicationProfile{
		Version: openssl.ApplicationProfileVersion,
		Name:    options.Name,
		Match: openssl.ApplicationMatch{
			Package: options.Package,
			UID:     options.UID,
			PID:     matchPID,
		},
		Capture: openssl.ApplicationCapture{
			Mode:             "all",
			Strategies:       strategies,
			Interfaces:       []string{"all"},
			UnknownFlows:     openssl.UnknownFlowMark,
			PcapFile:         sanitizeName(options.Name) + ".pcapng",
			PerfReorder:      &perfReorder,
			PerfReorderLagMs: 10,
		},
		DataHooks: hooks,
		JNI:       jniDiscovery,
		Metadata: map[string]string{
			"generated_by": "ecapture profile inspect",
			"validation":   "diagnostic scaffold; inject a unique marker and validate every hook before production use",
			"coverage":     "raw TCP/UDP packets plus direct-buffer candidates with known public ABIs",
		},
	}
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate generated profile: %w", err)
	}
	return profile, nil
}

var nonNameCharacters = regexp.MustCompile(`[^a-z0-9._-]+`)

func sanitizeName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = nonNameCharacters.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-.")
	if value == "" {
		return "hook"
	}
	return value
}

func uniqueHookName(base string, names map[string]int) string {
	count := names[base]
	names[base] = count + 1
	if count == 0 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, count+1)
}
