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
	Name                       string
	Package                    string
	UID                        uint64
	PID                        uint64
	MaxHooks                   int
	CollectUserStacks          bool
	IncludeSemanticDiagnostics bool
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
			if !options.IncludeSemanticDiagnostics &&
				candidate.Layer != LayerPlaintext &&
				candidate.Layer != LayerTransport {
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
			Name:                   name,
			Library:                current.library.Path,
			BuildID:                current.library.BuildID,
			Direction:              recipe.Direction,
			CaptureOn:              recipe.CaptureOn,
			BufferArg:              recipe.BufferArg,
			BufferOffset:           openssl.OffsetValue(recipe.BufferOffset),
			BufferIndirect:         recipe.BufferIndirect,
			LengthSource:           recipe.LengthSource,
			LengthArg:              recipe.LengthArg,
			FixedLength:            recipe.FixedLength,
			LengthOffset:           openssl.OffsetValue(recipe.LengthOffset),
			LengthSize:             recipe.LengthSize,
			LengthIndirect:         recipe.LengthIndirect,
			MaxBytes:               recipe.MaxBytes,
			ContextArg:             recipe.ContextArg,
			ContextOffset:          openssl.OffsetValue(recipe.ContextOffset),
			ContextSize:            recipe.ContextSize,
			StreamArg:              recipe.StreamArg,
			StreamOffset:           openssl.OffsetValue(recipe.StreamOffset),
			StreamSize:             recipe.StreamSize,
			StreamByteOffsetArg:    recipe.StreamByteOffsetArg,
			StreamByteOffsetOffset: openssl.OffsetValue(recipe.StreamByteOffsetOffset),
			StreamByteOffsetSize:   recipe.StreamByteOffsetSize,
			FinArg:                 recipe.FinArg,
			FinOffset:              openssl.OffsetValue(recipe.FinOffset),
			FinSize:                recipe.FinSize,
			BufferFormat:           recipe.BufferFormat,
			VectorCountArg:         recipe.VectorCountArg,
			VectorStride:           recipe.VectorStride,
			VectorBaseOffset:       recipe.VectorBaseOffset,
			VectorLengthOffset:     recipe.VectorLengthOffset,
			VectorLengthSize:       recipe.VectorLengthSize,
			CollectUserStack:       options.CollectUserStacks,
		}
		hook.CaptureLayer, hook.Transport = hookProvenance(candidate)
		if hook.CaptureLayer == openssl.CaptureLayerWire &&
			strings.HasPrefix(strings.ToLower(candidate.Role), "socket-") {
			hook.BoundaryRole = openssl.CaptureBoundarySocketPayload
		} else if hook.CaptureLayer == openssl.CaptureLayerWire &&
			strings.HasPrefix(strings.ToLower(candidate.Role), "fd-") {
			hook.BoundaryRole = openssl.CaptureBoundaryFDPayload
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
		if !options.IncludeSemanticDiagnostics {
			break
		}
		var offsets []openssl.OffsetValue
		conversionOffsets := make(map[string][]openssl.OffsetValue)
		offsetRoles := make(map[openssl.OffsetValue]string)
		ambiguousOffsets := make(map[openssl.OffsetValue]struct{})
		for _, candidate := range library.Candidates {
			if candidate.Family != "art-jni" || candidate.FileOffset == "" {
				continue
			}
			var offset openssl.OffsetValue
			if err := offset.UnmarshalJSON([]byte(fmt.Sprintf("%q", candidate.FileOffset))); err != nil {
				return nil, fmt.Errorf("parse JNI function offset %q: %w",
					candidate.FileOffset, err)
			}
			if candidate.Role == "register-natives" {
				if len(offsets) < openssl.MaxJNIRegisterHooks {
					offsets = append(offsets, offset)
				}
				continue
			}
			if otherRole, found := offsetRoles[offset]; found && otherRole != candidate.Role {
				ambiguousOffsets[offset] = struct{}{}
				continue
			}
			offsetRoles[offset] = candidate.Role
			if len(conversionOffsets[candidate.Role]) < openssl.MaxJNIConversionHooks {
				conversionOffsets[candidate.Role] = append(
					conversionOffsets[candidate.Role],
					offset,
				)
			}
		}
		for role, roleOffsets := range conversionOffsets {
			filtered := roleOffsets[:0]
			for _, offset := range roleOffsets {
				if _, ambiguous := ambiguousOffsets[offset]; !ambiguous {
					filtered = append(filtered, offset)
				}
			}
			if len(filtered) == 0 {
				delete(conversionOffsets, role)
			} else {
				conversionOffsets[role] = filtered
			}
		}
		if len(offsets) == 0 && len(conversionOffsets) == 0 {
			continue
		}
		jniDiscovery = &openssl.JNIDiscoveryProfile{
			Library:                library.Path,
			BuildID:                library.BuildID,
			RegisterNativesOffsets: offsets,
			ConversionOffsets:      conversionOffsets,
		}
		strategies = append(strategies, openssl.StrategyJNIDiscovery)
		break
	}
	hasBoundaryHooks := false
	hasSemanticHooks := false
	for _, hook := range hooks {
		if hook.CaptureLayer == openssl.CaptureLayerSemantic {
			hasSemanticHooks = true
		} else {
			hasBoundaryHooks = true
		}
	}
	if hasBoundaryHooks {
		strategies = append(strategies, openssl.StrategyBoundaryData)
	}
	if hasSemanticHooks {
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
			"validation":   "communication scaffold; validate every boundary ABI and correlate it with controlled packet traffic before production use",
			"coverage":     "raw TCP/UDP packets plus communication-boundary candidates with known public ABIs",
		},
	}
	if options.IncludeSemanticDiagnostics {
		profile.Metadata["semantic_diagnostics"] = "explicitly enabled; not communication evidence"
	}
	if options.CollectUserStacks {
		profile.Metadata["user_stacks"] = "discovery only; remove collect_user_stack after hook locations are validated"
	}
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate generated profile: %w", err)
	}
	return profile, nil
}

func hookProvenance(candidate HookCandidate) (string, string) {
	switch candidate.Layer {
	case LayerTransport:
		if strings.HasPrefix(strings.ToLower(candidate.Role), "fd-") {
			return openssl.CaptureLayerWire, openssl.CaptureTransportFD
		}
		return openssl.CaptureLayerWire, openssl.CaptureTransportSocket
	case LayerPlaintext:
		family := strings.ToLower(candidate.Family)
		role := strings.ToLower(candidate.Role)
		if strings.Contains(family, "quic") ||
			family == "ngtcp2" ||
			strings.HasPrefix(role, "quic-") {
			return openssl.CaptureLayerTransport, openssl.CaptureTransportQUIC
		}
		return openssl.CaptureLayerTransport, openssl.CaptureTransportTLS
	default:
		return openssl.CaptureLayerSemantic, ""
	}
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
