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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
)

const (
	JNIMethodNameSize              = 96
	JNIMethodSignatureSize         = 160
	JNIEventFlagNameTruncated      = 1
	JNIEventFlagSignatureTruncated = 2
	JNIDiscoverySegments           = 16
	JNIDiscoveryMethodsPerSegment  = 16
	JNIDiscoveryMaxMethods         = JNIDiscoverySegments * JNIDiscoveryMethodsPerSegment
)

// JNIDiscoveryEvent describes one JNINativeMethod observed at ART's
// RegisterNatives boundary. It contains registration metadata only; it never
// dereferences or copies application request/response buffers.
//
// The serialized fields through Signature exactly match
// struct jni_register_event_t in kern/jni_discovery.h.
type JNIDiscoveryEvent struct {
	Timestamp           uint64                       `json:"timestamp"`
	RegisterNativesAddr uint64                       `json:"registerNativesAddr"`
	MethodsAddr         uint64                       `json:"methodsAddr"`
	FunctionAddr        uint64                       `json:"functionAddr"`
	Pid                 uint32                       `json:"pid"`
	Tid                 uint32                       `json:"tid"`
	MethodCount         uint32                       `json:"methodCount"`
	MethodIndex         uint32                       `json:"methodIndex"`
	HookID              uint32                       `json:"hookId"`
	Flags               uint32                       `json:"flags"`
	Comm                [TaskCommLen]byte            `json:"comm"`
	Name                [JNIMethodNameSize]byte      `json:"name"`
	Signature           [JNIMethodSignatureSize]byte `json:"signature"`

	ModulePath            string `json:"modulePath,omitempty"`
	ModuleOffset          uint64 `json:"moduleOffset,omitempty"`
	RegisterModulePath    string `json:"registerModulePath,omitempty"`
	RegisterModuleOffset  uint64 `json:"registerModuleOffset,omitempty"`
	ModuleResolutionError string `json:"moduleResolutionError,omitempty"`
}

// MarshalJSON keeps discovery output compact and directly consumable by
// `profile learn-jni`. Fixed-size byte arrays are useful for the kernel ABI but
// would otherwise become hundreds of JSON integers.
func (e JNIDiscoveryEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		EventType             string `json:"eventType"`
		CaptureLayer          string `json:"captureLayer"`
		Timestamp             uint64 `json:"timestamp"`
		RegisterNativesAddr   uint64 `json:"registerNativesAddr"`
		MethodsAddr           uint64 `json:"methodsAddr"`
		FunctionAddr          uint64 `json:"functionAddr"`
		Pid                   uint32 `json:"pid"`
		Tid                   uint32 `json:"tid"`
		MethodCount           uint32 `json:"methodCount"`
		MethodIndex           uint32 `json:"methodIndex"`
		HookID                uint32 `json:"hookId"`
		Flags                 uint32 `json:"flags"`
		Comm                  string `json:"comm"`
		MethodName            string `json:"methodName"`
		MethodSignature       string `json:"methodSignature"`
		ModulePath            string `json:"modulePath,omitempty"`
		ModuleOffset          uint64 `json:"moduleOffset,omitempty"`
		RegisterModulePath    string `json:"registerModulePath,omitempty"`
		RegisterModuleOffset  uint64 `json:"registerModuleOffset,omitempty"`
		ModuleResolutionError string `json:"moduleResolutionError,omitempty"`
	}{
		EventType:             "jni_register_natives",
		CaptureLayer:          CaptureLayerSemantic,
		Timestamp:             e.Timestamp,
		RegisterNativesAddr:   e.RegisterNativesAddr,
		MethodsAddr:           e.MethodsAddr,
		FunctionAddr:          e.FunctionAddr,
		Pid:                   e.Pid,
		Tid:                   e.Tid,
		MethodCount:           e.MethodCount,
		MethodIndex:           e.MethodIndex,
		HookID:                e.HookID,
		Flags:                 e.Flags,
		Comm:                  commToString(e.Comm[:]),
		MethodName:            e.MethodName(),
		MethodSignature:       e.MethodSignature(),
		ModulePath:            e.ModulePath,
		ModuleOffset:          e.ModuleOffset,
		RegisterModulePath:    e.RegisterModulePath,
		RegisterModuleOffset:  e.RegisterModuleOffset,
		ModuleResolutionError: e.ModuleResolutionError,
	})
}

func (e *JNIDiscoveryEvent) DecodeFromBytes(data []byte) error {
	buf := bytes.NewReader(data)
	fields := []struct {
		name  string
		value any
	}{
		{"Timestamp", &e.Timestamp},
		{"RegisterNativesAddr", &e.RegisterNativesAddr},
		{"MethodsAddr", &e.MethodsAddr},
		{"FunctionAddr", &e.FunctionAddr},
		{"Pid", &e.Pid},
		{"Tid", &e.Tid},
		{"MethodCount", &e.MethodCount},
		{"MethodIndex", &e.MethodIndex},
		{"HookID", &e.HookID},
		{"Flags", &e.Flags},
		{"Comm", &e.Comm},
		{"Name", &e.Name},
		{"Signature", &e.Signature},
	}
	for _, field := range fields {
		if err := binary.Read(buf, binary.LittleEndian, field.value); err != nil {
			return errors.NewEventDecodeError("openssl.JNIDiscoveryEvent."+field.name, err)
		}
	}
	return nil
}

func (e *JNIDiscoveryEvent) PerfMonoNs() uint64 {
	return e.Timestamp
}

func (e *JNIDiscoveryEvent) String() string {
	module := fmt.Sprintf("0x%x", e.FunctionAddr)
	if e.ModulePath != "" {
		module = fmt.Sprintf("%s+0x%x", e.ModulePath, e.ModuleOffset)
	}
	truncated := ""
	if e.Flags != 0 {
		truncated = fmt.Sprintf(" flags=0x%x", e.Flags)
	}
	return fmt.Sprintf(
		"[%s] PID:%d TID:%d Comm:%s JNI RegisterNatives[%d] %s%s -> %s (%d/%d%s)",
		e.eventTime().Format("2006-01-02 15:04:05.000"),
		e.Pid,
		e.Tid,
		commToString(e.Comm[:]),
		e.HookID,
		e.MethodName(),
		e.MethodSignature(),
		module,
		e.MethodIndex+1,
		e.MethodCount,
		truncated,
	)
}

func (e *JNIDiscoveryEvent) StringHex() string {
	return e.String()
}

func (e *JNIDiscoveryEvent) Clone() domain.Event {
	clone := *e
	return &clone
}

func (e *JNIDiscoveryEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

func (e *JNIDiscoveryEvent) UUID() string {
	return fmt.Sprintf("jni_%d_%d_%d_%x", e.Pid, e.HookID, e.MethodIndex, e.Timestamp)
}

func (e *JNIDiscoveryEvent) Validate() error {
	switch {
	case e.Pid == 0:
		return errors.New(errors.ErrCodeEventValidation, "JNI discovery event has an empty PID")
	case e.FunctionAddr == 0:
		return errors.New(errors.ErrCodeEventValidation, "JNI discovery event has an empty function address")
	case e.MethodCount == 0 || e.MethodCount > 65535:
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid JNI method count: %d", e.MethodCount))
	case e.MethodIndex >= e.MethodCount:
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("JNI method index %d exceeds method count %d", e.MethodIndex, e.MethodCount))
	case e.HookID >= MaxJNIRegisterHooks:
		return errors.New(errors.ErrCodeEventValidation,
			fmt.Sprintf("invalid JNI RegisterNatives hook id: %d", e.HookID))
	case e.MethodName() == "":
		return errors.New(errors.ErrCodeEventValidation, "JNI discovery event has an empty method name")
	case e.MethodSignature() == "":
		return errors.New(errors.ErrCodeEventValidation, "JNI discovery event has an empty method signature")
	}
	return nil
}

func (e *JNIDiscoveryEvent) MethodName() string {
	return commToString(e.Name[:])
}

func (e *JNIDiscoveryEvent) MethodSignature() string {
	return commToString(e.Signature[:])
}

func (e *JNIDiscoveryEvent) eventTime() time.Time {
	offsetNs, err := getClockOffset()
	if err != nil {
		return time.Unix(0, int64(e.Timestamp))
	}
	return time.Unix(0, int64(e.Timestamp)+offsetNs)
}

type processModuleMapping struct {
	start      uint64
	end        uint64
	fileOffset uint64
	executable bool
	path       string
}

// parseProcessModuleMappings parses Linux /proc/PID/maps without assuming that
// mapped paths contain no spaces.
func parseProcessModuleMappings(reader io.Reader) ([]processModuleMapping, error) {
	var mappings []processModuleMapping
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, startErr := strconv.ParseUint(bounds[0], 16, 64)
		end, endErr := strconv.ParseUint(bounds[1], 16, 64)
		offset, offsetErr := strconv.ParseUint(fields[2], 16, 64)
		if startErr != nil || endErr != nil || offsetErr != nil || start >= end {
			continue
		}
		path := ""
		if len(fields) >= 6 {
			path = strings.Join(fields[5:], " ")
			path = strings.TrimSuffix(path, " (deleted)")
		}
		mappings = append(mappings, processModuleMapping{
			start:      start,
			end:        end,
			fileOffset: offset,
			executable: strings.Contains(fields[1], "x"),
			path:       path,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read process maps: %w", err)
	}
	return mappings, nil
}

func resolveModuleAddress(mappings []processModuleMapping, address uint64) (string, uint64, bool) {
	candidates := []uint64{address}
	// Android arm64 may expose a top-byte tag or a pointer-authenticated
	// function pointer. Try the unmodified pointer first, then the common
	// 56-, 52-, and 48-bit userspace address forms. The mapping check keeps
	// these fallbacks from manufacturing an unrelated module match.
	for _, mask := range []uint64{
		0x00ffffffffffffff,
		0x000fffffffffffff,
		0x0000ffffffffffff,
	} {
		candidate := address & mask
		if candidate == address {
			continue
		}
		duplicate := false
		for _, current := range candidates {
			if current == candidate {
				duplicate = true
				break
			}
		}
		if !duplicate {
			candidates = append(candidates, candidate)
		}
	}
	for _, candidate := range candidates {
		for _, mapping := range mappings {
			if candidate < mapping.start || candidate >= mapping.end ||
				mapping.path == "" || !mapping.executable {
				continue
			}
			return mapping.path, mapping.fileOffset + candidate - mapping.start, true
		}
	}
	return "", 0, false
}

type processModuleResolver struct {
	mu    sync.Mutex
	cache map[uint32][]processModuleMapping
}

func newProcessModuleResolver() *processModuleResolver {
	return &processModuleResolver{cache: make(map[uint32][]processModuleMapping)}
}

func (r *processModuleResolver) resolve(pid uint32, address uint64) (string, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	mappings := r.cache[pid]
	if path, offset, found := resolveModuleAddress(mappings, address); found {
		return path, offset, nil
	}
	path := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	mappings, err = parseProcessModuleMappings(file)
	if err != nil {
		return "", 0, err
	}
	r.cache[pid] = mappings
	if module, offset, found := resolveModuleAddress(mappings, address); found {
		return module, offset, nil
	}
	return "", 0, fmt.Errorf("address 0x%x is absent from %s", address, path)
}
