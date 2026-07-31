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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const JNILearningReportVersion = 2

// JNILearningOptions narrows conversion-callsite discovery with payload
// markers injected by a controlled request. Markers are matched as exact
// bytes so arbitrary binary protocols can use non-text sentinels through the
// programmatic API.
type JNILearningOptions struct {
	Markers [][]byte
}

// JNILearningReport turns a large RegisterNatives trace into a short,
// deterministic list of boundaries worth validating. It intentionally does
// not emit data hooks: JNI reference arguments are not native byte pointers.
type JNILearningReport struct {
	Version                    int                      `json:"version"`
	InputFormat                string                   `json:"input_format"`
	EventsObserved             int                      `json:"events_observed"`
	UniqueMethods              int                      `json:"unique_methods"`
	ResolvedMethods            int                      `json:"resolved_methods"`
	UnresolvedEvents           int                      `json:"unresolved_events"`
	Candidates                 []JNIMethodCandidate     `json:"candidates"`
	ConversionEventsObserved   int                      `json:"conversion_events_observed"`
	UniqueConversionCallsites  int                      `json:"unique_conversion_callsites"`
	UnresolvedConversionEvents int                      `json:"unresolved_conversion_events"`
	ConversionCandidates       []JNIConversionCandidate `json:"conversion_candidates"`
	Safety                     []string                 `json:"safety"`
}

type JNIMethodCandidate struct {
	Rank              int      `json:"rank"`
	Score             int      `json:"score"`
	Confidence        string   `json:"confidence"`
	MethodName        string   `json:"method_name"`
	MethodSignature   string   `json:"method_signature"`
	ModulePath        string   `json:"module_path"`
	ModuleOffset      string   `json:"module_offset"`
	FunctionAddress   string   `json:"function_address"`
	Observations      int      `json:"observations"`
	PIDs              []uint32 `json:"pids"`
	HookIDs           []uint32 `json:"register_natives_hook_ids"`
	PayloadKinds      []string `json:"payload_kinds,omitempty"`
	Reasons           []string `json:"reasons"`
	RecommendedProbes []string `json:"recommended_probes"`
	AutoHookSafe      bool     `json:"auto_hook_safe"`
}

type jniLearningEvent struct {
	EventType       string `json:"eventType"`
	FunctionAddr    uint64 `json:"functionAddr"`
	Pid             uint32 `json:"pid"`
	HookID          uint32 `json:"hookId"`
	MethodName      string `json:"methodName"`
	MethodSignature string `json:"methodSignature"`
	ModulePath      string `json:"modulePath"`
	ModuleOffset    uint64 `json:"moduleOffset"`
}

type jniConversionLearningEvent struct {
	EventType           string `json:"eventType"`
	Pid                 uint32 `json:"pid"`
	Tid                 uint32 `json:"tid"`
	Role                string `json:"role"`
	Phase               string `json:"phase"`
	Flags               uint32 `json:"flags"`
	ByteLength          uint64 `json:"byteLength"`
	ElementCount        uint64 `json:"elementCount"`
	CapturedLen         uint32 `json:"capturedLen"`
	ChunkOffset         uint32 `json:"chunkOffset"`
	DataLen             uint32 `json:"dataLen"`
	Data                []byte `json:"data"`
	CallerModulePath    string `json:"callerModulePath"`
	CallerModuleOffset  uint64 `json:"callerModuleOffset"`
	CallerModuleBuildID string `json:"callerModuleBuildID"`
}

type jniLearningInput struct {
	methods     []jniLearningEvent
	conversions []jniConversionLearningEvent
}

type jniCandidateAccumulator struct {
	event        jniLearningEvent
	observations int
	pids         map[uint32]struct{}
	hookIDs      map[uint32]struct{}
}

var plainJNIEventPattern = regexp.MustCompile(
	`PID:(\d+).*JNI RegisterNatives\[(\d+)\] ([^\s(]+)(\([^ ]+) -> (.+)\+0x([0-9a-fA-F]+) \(`,
)

// LearnJNI accepts either JSON event output produced with
// --event-format=json or the historical plain-text event stream.
func LearnJNI(reader io.Reader) (*JNILearningReport, error) {
	return LearnJNIWithOptions(reader, JNILearningOptions{})
}

// LearnJNIWithOptions accepts the same JSON/plain event streams as LearnJNI
// and additionally annotates conversion callers that observed a marker.
func LearnJNIWithOptions(
	reader io.Reader,
	options JNILearningOptions,
) (*JNILearningReport, error) {
	if reader == nil {
		return nil, fmt.Errorf("JNI learning input is nil")
	}
	buffered := bufio.NewReader(reader)
	first, err := firstNonSpaceByte(buffered)
	if err != nil {
		return nil, err
	}
	var input jniLearningInput
	format := "plain"
	if first == '{' {
		format = "json"
		input, err = decodeJNILearningJSON(buffered)
	} else {
		input.methods, err = decodeJNILearningPlain(buffered)
	}
	if err != nil {
		return nil, err
	}
	report := rankJNILearningEvents(format, input.methods)
	rankJNIConversionEvents(report, input.conversions, options)
	return report, nil
}

func firstNonSpaceByte(reader *bufio.Reader) (byte, error) {
	for {
		value, err := reader.Peek(1)
		if err != nil {
			if err == io.EOF {
				return 0, fmt.Errorf("JNI learning input is empty")
			}
			return 0, fmt.Errorf("inspect JNI learning input: %w", err)
		}
		if !isJSONSpace(value[0]) {
			return value[0], nil
		}
		if _, err := reader.ReadByte(); err != nil {
			return 0, fmt.Errorf("inspect JNI learning input: %w", err)
		}
	}
}

func isJSONSpace(value byte) bool {
	return value == ' ' || value == '\n' || value == '\r' || value == '\t'
}

func decodeJNILearningJSON(reader io.Reader) (jniLearningInput, error) {
	decoder := json.NewDecoder(reader)
	var input jniLearningInput
	for {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return jniLearningInput{}, fmt.Errorf("decode structured JNI event: %w", err)
		}
		var header struct {
			EventType string `json:"eventType"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			return jniLearningInput{}, fmt.Errorf("decode structured JNI event type: %w", err)
		}
		switch header.EventType {
		case "jni_register_natives":
			var event jniLearningEvent
			if err := json.Unmarshal(raw, &event); err != nil {
				return jniLearningInput{}, fmt.Errorf("decode RegisterNatives event: %w", err)
			}
			input.methods = append(input.methods, event)
		case "jni_conversion":
			var event jniConversionLearningEvent
			if err := json.Unmarshal(raw, &event); err != nil {
				return jniLearningInput{}, fmt.Errorf("decode JNI conversion event: %w", err)
			}
			input.conversions = append(input.conversions, event)
		}
	}
	return input, nil
}

func decodeJNILearningPlain(reader io.Reader) ([]jniLearningEvent, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var events []jniLearningEvent
	for scanner.Scan() {
		match := plainJNIEventPattern.FindStringSubmatch(scanner.Text())
		if len(match) != 7 {
			continue
		}
		pid, pidErr := strconv.ParseUint(match[1], 10, 32)
		hookID, hookErr := strconv.ParseUint(match[2], 10, 32)
		offset, offsetErr := strconv.ParseUint(match[6], 16, 64)
		if pidErr != nil || hookErr != nil || offsetErr != nil {
			continue
		}
		events = append(events, jniLearningEvent{
			Pid:             uint32(pid),
			HookID:          uint32(hookID),
			MethodName:      match[3],
			MethodSignature: match[4],
			ModulePath:      match[5],
			ModuleOffset:    offset,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan plain JNI events: %w", err)
	}
	return events, nil
}

func rankJNILearningEvents(format string, events []jniLearningEvent) *JNILearningReport {
	report := &JNILearningReport{
		Version:        JNILearningReportVersion,
		InputFormat:    format,
		EventsObserved: len(events),
		Safety: []string{
			"JNI String, array, and ByteBuffer arguments are managed references, not native byte pointers.",
			"Pin every promoted offset to the target library GNU Build ID.",
			"Require a synthetic marker in both request and response before enabling a production data hook.",
		},
	}
	accumulators := make(map[string]*jniCandidateAccumulator)
	for _, event := range events {
		event.MethodName = strings.TrimSpace(event.MethodName)
		event.MethodSignature = strings.TrimSpace(event.MethodSignature)
		event.ModulePath = strings.TrimSpace(event.ModulePath)
		if event.MethodName == "" || event.MethodSignature == "" ||
			event.ModulePath == "" {
			report.UnresolvedEvents++
			continue
		}
		report.ResolvedMethods++
		key := strings.Join([]string{
			event.ModulePath,
			fmt.Sprintf("%x", event.ModuleOffset),
			event.MethodName,
			event.MethodSignature,
		}, "\x00")
		current := accumulators[key]
		if current == nil {
			current = &jniCandidateAccumulator{
				event:   event,
				pids:    make(map[uint32]struct{}),
				hookIDs: make(map[uint32]struct{}),
			}
			accumulators[key] = current
		}
		current.observations++
		current.pids[event.Pid] = struct{}{}
		current.hookIDs[event.HookID] = struct{}{}
		if current.event.FunctionAddr == 0 {
			current.event.FunctionAddr = event.FunctionAddr
		}
	}
	report.UniqueMethods = len(accumulators)
	report.Candidates = make([]JNIMethodCandidate, 0, len(accumulators))
	for _, accumulator := range accumulators {
		report.Candidates = append(report.Candidates, buildJNICandidate(accumulator))
	}
	sort.SliceStable(report.Candidates, func(i, j int) bool {
		left, right := report.Candidates[i], report.Candidates[j]
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if left.ModulePath != right.ModulePath {
			return left.ModulePath < right.ModulePath
		}
		if left.ModuleOffset != right.ModuleOffset {
			return left.ModuleOffset < right.ModuleOffset
		}
		if left.MethodName != right.MethodName {
			return left.MethodName < right.MethodName
		}
		return left.MethodSignature < right.MethodSignature
	})
	for index := range report.Candidates {
		report.Candidates[index].Rank = index + 1
	}
	return report
}

func buildJNICandidate(accumulator *jniCandidateAccumulator) JNIMethodCandidate {
	event := accumulator.event
	score, kinds, reasons := scoreJNIMethod(event)
	recommended := recommendedJNIProbes(kinds)
	confidence := "low"
	switch {
	case score >= 90:
		confidence = "high"
	case score >= 55:
		confidence = "medium"
	}
	return JNIMethodCandidate{
		Score:             score,
		Confidence:        confidence,
		MethodName:        event.MethodName,
		MethodSignature:   event.MethodSignature,
		ModulePath:        event.ModulePath,
		ModuleOffset:      fmt.Sprintf("0x%x", event.ModuleOffset),
		FunctionAddress:   fmt.Sprintf("0x%x", event.FunctionAddr),
		Observations:      accumulator.observations,
		PIDs:              sortedUint32Keys(accumulator.pids),
		HookIDs:           sortedUint32Keys(accumulator.hookIDs),
		PayloadKinds:      kinds,
		Reasons:           reasons,
		RecommendedProbes: recommended,
		AutoHookSafe:      false,
	}
}

func scoreJNIMethod(event jniLearningEvent) (int, []string, []string) {
	name := strings.ToLower(event.MethodName)
	signature := event.MethodSignature
	path := strings.ToLower(event.ModulePath)
	score := 0
	var kinds, reasons []string
	addKind := func(kind string, points int, reason string) {
		if !containsString(kinds, kind) {
			kinds = append(kinds, kind)
			score += points
			reasons = append(reasons, reason)
		}
	}
	if strings.Contains(signature, "Ljava/nio/ByteBuffer;") {
		addKind("direct-or-heap-byte-buffer", 45, "signature contains java.nio.ByteBuffer")
	}
	if strings.Contains(signature, "[B") {
		addKind("byte-array", 40, "signature contains byte[]")
	}
	if strings.Contains(signature, "Ljava/lang/String;") {
		addKind("string", 25, "signature contains java.lang.String")
	}
	if regexp.MustCompile(`\[[ZCBSIFJD]`).MatchString(signature) {
		addKind("primitive-array", 25, "signature contains a primitive array")
	}
	semanticGroups := []struct {
		label  string
		points int
		words  []string
	}{
		{"request/response semantic name", 30, []string{"request", "response", "upload", "download", "header", "body", "url"}},
		{"stream I/O semantic name", 25, []string{"read", "write", "send", "recv", "stream", "packet", "frame"}},
		{"serialization semantic name", 25, []string{"encode", "decode", "serialize", "deserialize", "parse", "protobuf", "proto"}},
		{"cryptographic boundary name", 20, []string{"encrypt", "decrypt", "cipher", "seal", "open"}},
		{"buffer/data semantic name", 12, []string{"buffer", "bytes", "data", "message", "payload"}},
	}
	for _, group := range semanticGroups {
		if containsAny(name, group.words) {
			score += group.points
			reasons = append(reasons, group.label)
		}
	}
	if strings.Contains(path, "/data/app/") || strings.Contains(path, "/data/user/") {
		score += 10
		reasons = append(reasons, "implementation belongs to an application-private module")
	}
	if strings.Contains(path, "/apex/") || strings.Contains(path, "/system/") {
		score -= 20
		reasons = append(reasons, "system framework method is less likely to be the application semantic boundary")
	}
	if containsAny(name, []string{"init", "destroy", "delete", "register", "unregister"}) &&
		len(kinds) == 0 {
		score -= 15
		reasons = append(reasons, "lifecycle method has no obvious payload argument")
	}
	if event.ModuleOffset != 0 {
		score += 5
		reasons = append(reasons, "function resolved to a module-relative offset")
	}
	if score < 0 {
		score = 0
	}
	sort.Strings(kinds)
	return score, kinds, reasons
}

func recommendedJNIProbes(kinds []string) []string {
	var result []string
	if containsString(kinds, "direct-or-heap-byte-buffer") {
		result = append(result,
			"trace this native method as a hit boundary, then correlate JNIEnv GetDirectBufferAddress/GetDirectBufferCapacity calls",
		)
	}
	if containsString(kinds, "byte-array") || containsString(kinds, "primitive-array") {
		result = append(result,
			"correlate GetByteArrayElements/GetPrimitiveArrayCritical with the active native method and capture at release/return",
		)
	}
	if containsString(kinds, "string") {
		result = append(result,
			"correlate GetStringUTFChars/GetStringChars with the active native method; do not dereference the jstring argument directly",
		)
	}
	result = append(result,
		"disassemble the module-relative target and validate its register/memory ABI with a synthetic marker",
	)
	return result
}

func sortedUint32Keys(values map[uint32]struct{}) []uint32 {
	result := make([]uint32, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func containsAny(value string, words []string) bool {
	for _, word := range words {
		if strings.Contains(value, word) {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// learnJNIBytes is used by tests and keeps the production parser streaming.
func learnJNIBytes(data string) (*JNILearningReport, error) {
	return LearnJNI(bytes.NewBufferString(data))
}
