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
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gojue/ecapture/internal/probe/openssl"
)

// JNIConversionCandidate describes one native instruction following a call to
// a standard JNIEnv conversion function. Unlike a JNI managed reference, this
// module-relative return address is safe to promote into an exact kernel
// allowlist after ASLR translation.
type JNIConversionCandidate struct {
	Rank              int                         `json:"rank"`
	Score             int                         `json:"score"`
	Confidence        string                      `json:"confidence"`
	Role              string                      `json:"role"`
	ModulePath        string                      `json:"module_path"`
	ModuleOffset      string                      `json:"module_offset"`
	BuildID           string                      `json:"build_id,omitempty"`
	Observations      int                         `json:"observations"`
	PayloadEvents     int                         `json:"payload_events"`
	PayloadBytes      uint64                      `json:"payload_bytes"`
	TextPayloads      int                         `json:"text_payloads"`
	BinaryPayloads    int                         `json:"binary_payloads"`
	StructuredHints   int                         `json:"structured_hints"`
	MarkerHits        int                         `json:"marker_hits,omitempty"`
	MaximumByteLength uint64                      `json:"maximum_byte_length"`
	PIDs              []uint32                    `json:"pids"`
	Phases            []string                    `json:"phases"`
	Reasons           []string                    `json:"reasons"`
	ProfileRule       openssl.JNIConversionCaller `json:"profile_rule"`
	KernelFilterReady bool                        `json:"kernel_filter_ready"`
	BuildIDPinned     bool                        `json:"build_id_pinned"`
}

type jniConversionAccumulator struct {
	event             jniConversionLearningEvent
	observations      int
	payloadEvents     int
	payloadBytes      uint64
	textPayloads      int
	binaryPayloads    int
	structuredHints   int
	markerHits        int
	maximumByteLength uint64
	pids              map[uint32]struct{}
	phases            map[string]struct{}
	buildIDs          map[string]struct{}
}

func rankJNIConversionEvents(
	report *JNILearningReport,
	events []jniConversionLearningEvent,
	options JNILearningOptions,
) {
	report.ConversionEventsObserved = len(events)
	accumulators := make(map[string]*jniConversionAccumulator)
	for _, event := range events {
		event.Role = strings.ToLower(strings.TrimSpace(event.Role))
		event.Phase = strings.ToLower(strings.TrimSpace(event.Phase))
		event.CallerModulePath = strings.TrimSpace(event.CallerModulePath)
		if event.Role == "" || event.CallerModulePath == "" ||
			event.CallerModuleOffset == 0 {
			report.UnresolvedConversionEvents++
			continue
		}
		key := strings.Join([]string{
			event.CallerModulePath,
			fmt.Sprintf("%x", event.CallerModuleOffset),
			event.Role,
		}, "\x00")
		current := accumulators[key]
		if current == nil {
			current = &jniConversionAccumulator{
				event:    event,
				pids:     make(map[uint32]struct{}),
				phases:   make(map[string]struct{}),
				buildIDs: make(map[string]struct{}),
			}
			accumulators[key] = current
		}
		current.observations++
		current.pids[event.Pid] = struct{}{}
		if buildID := strings.TrimSpace(event.CallerModuleBuildID); buildID != "" {
			current.buildIDs[buildID] = struct{}{}
		}
		if event.Phase != "" {
			current.phases[event.Phase] = struct{}{}
		}
		if event.ByteLength > current.maximumByteLength {
			current.maximumByteLength = event.ByteLength
		}
		if len(event.Data) == 0 {
			continue
		}
		current.payloadEvents++
		current.payloadBytes += uint64(len(event.Data))
		isText, structured := classifyJNIConversionPayload(event.Data)
		if isText {
			current.textPayloads++
		} else {
			current.binaryPayloads++
		}
		if structured {
			current.structuredHints++
		}
		for _, marker := range options.Markers {
			if len(marker) != 0 && bytes.Contains(event.Data, marker) {
				current.markerHits++
				break
			}
		}
	}
	report.UniqueConversionCallsites = len(accumulators)
	report.ConversionCandidates = make(
		[]JNIConversionCandidate,
		0,
		len(accumulators),
	)
	for _, accumulator := range accumulators {
		report.ConversionCandidates = append(
			report.ConversionCandidates,
			buildJNIConversionCandidate(accumulator),
		)
	}
	sort.SliceStable(report.ConversionCandidates, func(i, j int) bool {
		left, right := report.ConversionCandidates[i], report.ConversionCandidates[j]
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if left.ModulePath != right.ModulePath {
			return left.ModulePath < right.ModulePath
		}
		if left.ModuleOffset != right.ModuleOffset {
			return left.ModuleOffset < right.ModuleOffset
		}
		return left.Role < right.Role
	})
	for index := range report.ConversionCandidates {
		report.ConversionCandidates[index].Rank = index + 1
	}
	report.Safety = append(report.Safety,
		"JNI conversion caller filters remain in bootstrap mode until every configured module-relative rule resolves for a PID.",
		"Pin learned caller modules to GNU Build IDs before treating offsets as durable across application upgrades.",
	)
}

func buildJNIConversionCandidate(
	accumulator *jniConversionAccumulator,
) JNIConversionCandidate {
	event := accumulator.event
	score := 0
	var reasons []string
	path := strings.ToLower(event.CallerModulePath)
	switch {
	case strings.Contains(path, "/data/app/") ||
		strings.Contains(path, "/data/user/"):
		score += 40
		reasons = append(reasons, "caller belongs to an application-private module")
	case strings.Contains(path, "/apex/") ||
		strings.Contains(path, "/system/"):
		score -= 35
		reasons = append(reasons, "caller belongs to a shared system/runtime module")
	default:
		score += 12
		reasons = append(reasons, "caller is outside the shared Android runtime paths")
	}
	switch event.Role {
	case openssl.JNIConversionGetByteArrayElements,
		openssl.JNIConversionReleaseByteArrayElements,
		openssl.JNIConversionGetByteArrayRegion,
		openssl.JNIConversionSetByteArrayRegion,
		openssl.JNIConversionGetPrimitiveArrayCritical,
		openssl.JNIConversionReleasePrimitiveArrayCritical,
		openssl.JNIConversionGetDirectBufferAddress:
		score += 25
		reasons = append(reasons, "role commonly exposes binary message bytes")
	case openssl.JNIConversionGetStringChars,
		openssl.JNIConversionReleaseStringChars,
		openssl.JNIConversionGetStringUTFChars,
		openssl.JNIConversionReleaseStringUTFChars,
		openssl.JNIConversionGetStringCritical,
		openssl.JNIConversionReleaseStringCritical:
		score += 20
		reasons = append(reasons, "role exposes string materialization")
	}
	if accumulator.payloadEvents != 0 {
		score += 30
		reasons = append(reasons, "callsite emitted captured payload bytes")
	}
	if accumulator.binaryPayloads != 0 {
		score += 15
		reasons = append(reasons, "callsite carried non-text binary payloads")
	}
	if accumulator.textPayloads != 0 {
		score += 10
		reasons = append(reasons, "callsite carried text-like payloads")
	}
	if accumulator.structuredHints != 0 {
		score += 20
		reasons = append(reasons, "payload contains URL, HTTP, JSON, or message-structure hints")
	}
	if accumulator.markerHits != 0 {
		score += 50
		reasons = append(reasons, "callsite observed an injected payload marker")
	}
	buildIDs := sortedStringKeys(accumulator.buildIDs)
	buildID := ""
	if len(buildIDs) == 1 {
		buildID = buildIDs[0]
		score += 10
		reasons = append(reasons, "caller module Build ID was observed and can be pinned")
	} else if len(buildIDs) > 1 {
		reasons = append(reasons, "caller module produced multiple Build IDs during capture; review before promotion")
	}
	if accumulator.observations >= 2 {
		score += 5
		reasons = append(reasons, "callsite was observed repeatedly")
	}
	if accumulator.observations >= 10 {
		score += 5
		reasons = append(reasons, "callsite was observed at least ten times")
	}
	if score < 0 {
		score = 0
	}
	confidence := "low"
	switch {
	case score >= 95:
		confidence = "high"
	case score >= 60:
		confidence = "medium"
	}
	return JNIConversionCandidate{
		Score:             score,
		Confidence:        confidence,
		Role:              event.Role,
		ModulePath:        event.CallerModulePath,
		ModuleOffset:      fmt.Sprintf("0x%x", event.CallerModuleOffset),
		BuildID:           buildID,
		Observations:      accumulator.observations,
		PayloadEvents:     accumulator.payloadEvents,
		PayloadBytes:      accumulator.payloadBytes,
		TextPayloads:      accumulator.textPayloads,
		BinaryPayloads:    accumulator.binaryPayloads,
		StructuredHints:   accumulator.structuredHints,
		MarkerHits:        accumulator.markerHits,
		MaximumByteLength: accumulator.maximumByteLength,
		PIDs:              sortedUint32Keys(accumulator.pids),
		Phases:            sortedStringKeys(accumulator.phases),
		Reasons:           reasons,
		ProfileRule: openssl.JNIConversionCaller{
			Module:  filepath.Base(event.CallerModulePath),
			BuildID: buildID,
			Role:    event.Role,
			Offset:  openssl.OffsetValue(event.CallerModuleOffset),
		},
		KernelFilterReady: true,
		BuildIDPinned:     buildID != "",
	}
}

func classifyJNIConversionPayload(data []byte) (bool, bool) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return false, false
	}
	printable := 0
	for _, value := range trimmed {
		if value == '\n' || value == '\r' || value == '\t' ||
			(value >= 0x20 && value < 0x7f) {
			printable++
		}
	}
	textLike := utf8.Valid(trimmed) &&
		printable*100 >= len(trimmed)*82
	if !textLike && looksLikeUTF16LE(trimmed) {
		textLike = true
	}
	lower := strings.ToLower(strings.ReplaceAll(string(trimmed), "\x00", ""))
	structured := json.Valid(trimmed) || containsAny(lower, []string{
		"http://",
		"https://",
		"content-type",
		"authorization",
		"chat/complet",
		`"messages"`,
		`"prompt"`,
		`"content"`,
		"protobuf",
		"grpc",
	})
	return textLike, structured
}

func looksLikeUTF16LE(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	pairs := len(data) / 2
	asciiPairs := 0
	for index := 0; index+1 < len(data); index += 2 {
		if data[index+1] == 0 &&
			(data[index] == '\n' || data[index] == '\r' ||
				data[index] == '\t' ||
				(data[index] >= 0x20 && data[index] < 0x7f)) {
			asciiPairs++
		}
	}
	return asciiPairs*100 >= pairs*70
}

func sortedStringKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// PromoteJNIConversionCallers replaces a diagnostic profile's caller
// allowlist with the selected ranked candidates. The caller must write to a
// different output path so the original diagnostic profile remains available.
func PromoteJNIConversionCallers(
	profile *openssl.ApplicationProfile,
	candidates []JNIConversionCandidate,
) error {
	if profile == nil {
		return fmt.Errorf("application profile is nil")
	}
	if profile.JNI == nil {
		return fmt.Errorf("application profile has no jni_discovery configuration")
	}
	if len(candidates) == 0 {
		return fmt.Errorf("no JNI conversion caller candidates were selected")
	}
	rules := make([]openssl.JNIConversionCaller, 0, len(candidates))
	for _, candidate := range candidates {
		if !candidate.KernelFilterReady {
			continue
		}
		rules = append(rules, candidate.ProfileRule)
	}
	if len(rules) == 0 {
		return fmt.Errorf("selected JNI conversion candidates are not kernel-filter ready")
	}
	profile.JNI.CallerAllowlist = rules
	if profile.Metadata == nil {
		profile.Metadata = make(map[string]string)
	}
	profile.Metadata["jni_caller_allowlist_source"] = "ecapture profile learn-jni"
	profile.Metadata["jni_caller_allowlist_entries"] = strconv.Itoa(len(rules))
	return profile.Validate()
}
