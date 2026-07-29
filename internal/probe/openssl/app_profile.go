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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	ApplicationProfileVersion = 1

	StrategyRawPackets   = "raw_packets"
	StrategyTLSPlaintext = "tls_plaintext"
	StrategyTLSKeys      = "tls_keys"
	StrategyQUICMetadata = "quic_metadata"
	StrategyAppData      = "application_data"
	StrategyJNIDiscovery = "jni_discovery"
	// StrategyCronet is retained as a compatibility alias for profiles that
	// predate the generic application-data hook name.
	StrategyCronet      = "cronet"
	UnknownFlowInclude  = "include"
	UnknownFlowMark     = "mark"
	UnknownFlowDrop     = "drop"
	HookSSLRead         = "ssl_read"
	HookSSLWrite        = "ssl_write"
	HookSSLSetFD        = "ssl_set_fd"
	HookSSLSetRFD       = "ssl_set_rfd"
	HookSSLSetWFD       = "ssl_set_wfd"
	HookSSLProvideQUIC  = "ssl_provide_quic_data"
	OffsetSSLRBIO       = "ssl_st_rbio"
	OffsetSSLWBIO       = "ssl_st_wbio"
	OffsetSSLVersion    = "ssl_st_version"
	OffsetSSLS3         = "ssl_st_s3"
	OffsetSSL3Version   = "ssl3_state_version"
	OffsetBIOMethod     = "bio_st_method"
	OffsetBIONum        = "bio_st_num"
	OffsetBIOMethodType = "bio_method_st_type"

	AppDataDirectionRead  = "read"
	AppDataDirectionWrite = "write"
	AppDataCaptureEntry   = "entry"
	AppDataCaptureReturn  = "return"
	AppDataLengthArgument = "argument"
	AppDataLengthMemory   = "memory"
	AppDataLengthFixed    = "fixed"
	AppDataLengthReturn   = "return"
	AppDataBufferRaw      = "raw"
	AppDataBufferLibCXX   = "libcxx_string"
	AppDataBufferIOVec    = "iovec"
	AppDataBufferMsgHdr   = "msghdr"
	AppDataStateSave      = "save"
	AppDataStateLoad      = "load"

	MaxApplicationHooks = 8
	MaxApplicationData  = 8 * MaxDataSize
	// MaxApplicationArguments covers the full register argument set plus the
	// first entry-stack arguments on the supported amd64 and arm64 ABIs. QUIC
	// APIs such as ngtcp2 expose stream buffers beyond argument eight.
	MaxApplicationArguments = 12
	MaxJNIRegisterHooks     = 4
)

var (
	supportedStrategies = map[string]struct{}{
		StrategyRawPackets:   {},
		StrategyTLSPlaintext: {},
		StrategyTLSKeys:      {},
		StrategyQUICMetadata: {},
		StrategyAppData:      {},
		StrategyJNIDiscovery: {},
		StrategyCronet:       {},
	}
	supportedHookRoles = map[string]struct{}{
		HookSSLRead:        {},
		HookSSLWrite:       {},
		HookSSLSetFD:       {},
		HookSSLSetRFD:      {},
		HookSSLSetWFD:      {},
		HookSSLProvideQUIC: {},
	}
	structOffsetConstants = map[string]string{
		OffsetSSLRBIO:       "ecapture_offset_ssl_st_rbio",
		OffsetSSLWBIO:       "ecapture_offset_ssl_st_wbio",
		OffsetSSLVersion:    "ecapture_offset_ssl_st_version",
		OffsetSSLS3:         "ecapture_offset_ssl_st_s3",
		OffsetSSL3Version:   "ecapture_offset_ssl3_state_version",
		OffsetBIOMethod:     "ecapture_offset_bio_st_method",
		OffsetBIONum:        "ecapture_offset_bio_st_num",
		OffsetBIOMethodType: "ecapture_offset_bio_method_st_type",
	}
)

// OffsetValue accepts either a JSON number or a quoted decimal/hexadecimal
// value. Quoted hexadecimal values make reverse-engineered offsets readable in
// profiles without sacrificing an exact integer representation in memory.
type OffsetValue uint64

func (v *OffsetValue) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty offset value")
	}
	var value uint64
	var err error
	if data[0] == '"' {
		var text string
		if err = json.Unmarshal(data, &text); err != nil {
			return err
		}
		value, err = strconv.ParseUint(strings.TrimSpace(text), 0, 64)
	} else {
		value, err = strconv.ParseUint(string(data), 10, 64)
	}
	if err != nil {
		return fmt.Errorf("invalid offset %q: %w", string(data), err)
	}
	*v = OffsetValue(value)
	return nil
}

func (v OffsetValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("0x%x", uint64(v)))
}

// ApplicationProfile is a portable, per-application description of capture
// scope, transport strategies, library discovery, hook symbols, and structure
// offsets. A profile is applied before Config.Validate performs platform
// detection, so Android package and library paths can be resolved at runtime.
type ApplicationProfile struct {
	Version   int                    `json:"version"`
	Name      string                 `json:"name"`
	Match     ApplicationMatch       `json:"match"`
	Capture   ApplicationCapture     `json:"capture"`
	TLS       ApplicationTLS         `json:"tls"`
	DataHooks []ApplicationDataHook  `json:"data_hooks,omitempty"`
	JNI       *JNIDiscoveryProfile   `json:"jni_discovery,omitempty"`
	Offsets   map[string]OffsetValue `json:"offsets,omitempty"`
	Metadata  map[string]string      `json:"metadata,omitempty"`
}

type ApplicationMatch struct {
	Package        string `json:"package,omitempty"`
	UID            uint64 `json:"uid,omitempty"`
	PID            uint64 `json:"pid,omitempty"`
	AndroidRelease string `json:"android_release,omitempty"`
	ABI            string `json:"abi,omitempty"`
	VersionName    string `json:"version_name,omitempty"`
	VersionCode    uint64 `json:"version_code,omitempty"`
}

type ApplicationCapture struct {
	Mode              string   `json:"mode,omitempty"`
	Strategies        []string `json:"strategies,omitempty"`
	Interfaces        []string `json:"interfaces,omitempty"`
	StrictAttribution bool     `json:"strict_attribution,omitempty"`
	UnknownFlows      string   `json:"unknown_flows,omitempty"`
	PcapFile          string   `json:"pcap_file,omitempty"`
	KeylogFile        string   `json:"keylog_file,omitempty"`
	PcapFilter        string   `json:"pcap_filter,omitempty"`
	PerfReorder       *bool    `json:"perf_reorder,omitempty"`
	PerfReorderLagMs  uint     `json:"perf_reorder_lag_ms,omitempty"`
}

type ApplicationTLS struct {
	Library         string                 `json:"library,omitempty"`
	LibraryGlob     string                 `json:"library_glob,omitempty"`
	BuildID         string                 `json:"build_id,omitempty"`
	Version         string                 `json:"version,omitempty"`
	BoringSSL       *bool                  `json:"boring_ssl,omitempty"`
	MasterHookFuncs []string               `json:"master_hook_funcs,omitempty"`
	Hooks           map[string]HookProfile `json:"hooks,omitempty"`
}

// JNIDiscoveryProfile attaches specialized RegisterNatives decoders to ART.
// The offsets can be found without private symbols by locating the standard
// JNINativeInterface table (RegisterNatives is entry 215).
type JNIDiscoveryProfile struct {
	Library                string        `json:"library,omitempty"`
	LibraryGlob            string        `json:"library_glob,omitempty"`
	BuildID                string        `json:"build_id,omitempty"`
	RegisterNativesOffsets []OffsetValue `json:"register_natives_offsets"`

	resolvedLibrary string
}

// HookProfile selects either an exported symbol or a file offset for a
// well-known probe role. Offset takes precedence when it is non-zero.
type HookProfile struct {
	Symbol   string      `json:"symbol,omitempty"`
	Offset   OffsetValue `json:"offset,omitempty"`
	Disabled bool        `json:"disabled,omitempty"`
}

// ApplicationDataHook describes a generic user-space function whose arguments
// expose application plaintext. It supports direct pointer/length arguments
// as well as one level of indirection and structure offsets, which is useful
// for Cronet buffers and private networking SDKs.
type ApplicationDataHook struct {
	Name           string      `json:"name"`
	Library        string      `json:"library,omitempty"`
	LibraryGlob    string      `json:"library_glob,omitempty"`
	BuildID        string      `json:"build_id,omitempty"`
	Symbol         string      `json:"symbol,omitempty"`
	Offset         OffsetValue `json:"offset,omitempty"`
	Direction      string      `json:"direction"`
	CaptureOn      string      `json:"capture_on,omitempty"`
	BufferArg      uint32      `json:"buffer_arg"`
	BufferFormat   string      `json:"buffer_format,omitempty"`
	BufferOffset   OffsetValue `json:"buffer_offset,omitempty"`
	BufferIndirect bool        `json:"buffer_indirect,omitempty"`
	LengthSource   string      `json:"length_source,omitempty"`
	LengthArg      uint32      `json:"length_arg,omitempty"`
	FixedLength    uint32      `json:"fixed_length,omitempty"`
	LengthOffset   OffsetValue `json:"length_offset,omitempty"`
	LengthSize     uint32      `json:"length_size,omitempty"`
	LengthIndirect bool        `json:"length_indirect,omitempty"`
	MaxBytes       uint32      `json:"max_bytes,omitempty"`
	ContextArg     uint32      `json:"context_arg,omitempty"`
	StreamArg      uint32      `json:"stream_arg,omitempty"`
	VectorCountArg uint32      `json:"vector_count_arg,omitempty"`
	StateGroup     string      `json:"state_group,omitempty"`
	StateAction    string      `json:"state_action,omitempty"`
	StateKeyArg    uint32      `json:"state_key_arg,omitempty"`
	Disabled       bool        `json:"disabled,omitempty"`

	resolvedLibrary string
	stateID         uint32
}

func LoadApplicationProfile(path string) (*ApplicationProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read application profile %q: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var profile ApplicationProfile
	if err := decoder.Decode(&profile); err != nil {
		return nil, fmt.Errorf("decode application profile %q: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("application profile %q contains trailing JSON values", path)
		}
		return nil, fmt.Errorf("decode trailing data in application profile %q: %w", path, err)
	}
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate application profile %q: %w", path, err)
	}
	return &profile, nil
}

func (p *ApplicationProfile) Validate() error {
	if p == nil {
		return fmt.Errorf("application profile is nil")
	}
	if p.Version != ApplicationProfileVersion {
		return fmt.Errorf("unsupported profile version %d, want %d", p.Version, ApplicationProfileVersion)
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return fmt.Errorf("profile name is required")
	}
	if p.Match.Package == "" && p.Match.UID == 0 && p.Match.PID == 0 {
		return fmt.Errorf("profile match requires package, uid, or pid")
	}
	if err := validateProfileStrategies(p.Capture.Strategies); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(p.Capture.Mode)) {
	case "", "text", "key", "keylog", "pcap", "pcapng", "all", "hybrid":
	default:
		return fmt.Errorf("unsupported capture mode %q", p.Capture.Mode)
	}
	switch p.Capture.UnknownFlows {
	case "", UnknownFlowInclude, UnknownFlowMark, UnknownFlowDrop:
	default:
		return fmt.Errorf("unsupported unknown_flows policy %q", p.Capture.UnknownFlows)
	}
	if p.TLS.Library != "" && p.TLS.LibraryGlob != "" {
		return fmt.Errorf("tls.library and tls.library_glob are mutually exclusive")
	}
	var err error
	p.TLS.BuildID, err = normalizeBuildID(p.TLS.BuildID)
	if err != nil {
		return fmt.Errorf("tls.build_id: %w", err)
	}
	for role, hook := range p.TLS.Hooks {
		if _, ok := supportedHookRoles[role]; !ok {
			return fmt.Errorf("unsupported hook role %q", role)
		}
		if hook.Disabled {
			continue
		}
		if hook.Symbol == "" && hook.Offset == 0 {
			return fmt.Errorf("hook %q requires symbol, offset, or disabled=true", role)
		}
	}
	if err := validateApplicationDataHooks(p.DataHooks); err != nil {
		return err
	}
	if err := validateJNIDiscovery(p); err != nil {
		return err
	}
	for name, value := range p.Offsets {
		if _, ok := structOffsetConstants[name]; !ok {
			return fmt.Errorf("unsupported structure offset %q", name)
		}
		if uint64(value) > 1<<20 {
			return fmt.Errorf("structure offset %q is unreasonably large: %#x", name, uint64(value))
		}
	}
	p.Capture.Strategies = normalizeStrings(p.Capture.Strategies)
	p.Capture.Interfaces = normalizeInterfaceNames(p.Capture.Interfaces)
	return nil
}

func validateJNIDiscovery(profile *ApplicationProfile) error {
	jni := profile.JNI
	hasStrategy := false
	for _, strategy := range profile.Capture.Strategies {
		if strings.EqualFold(strings.TrimSpace(strategy), StrategyJNIDiscovery) {
			hasStrategy = true
			break
		}
	}
	if jni == nil {
		if hasStrategy {
			return fmt.Errorf("%s strategy requires jni_discovery configuration",
				StrategyJNIDiscovery)
		}
		return nil
	}
	if !hasStrategy {
		return fmt.Errorf("jni_discovery configuration requires %s strategy",
			StrategyJNIDiscovery)
	}
	jni.Library = strings.TrimSpace(jni.Library)
	jni.LibraryGlob = strings.TrimSpace(jni.LibraryGlob)
	if (jni.Library == "") == (jni.LibraryGlob == "") {
		return fmt.Errorf("jni_discovery requires exactly one of library or library_glob")
	}
	var err error
	jni.BuildID, err = normalizeBuildID(jni.BuildID)
	if err != nil {
		return fmt.Errorf("jni_discovery build_id: %w", err)
	}
	if len(jni.RegisterNativesOffsets) == 0 {
		return fmt.Errorf("jni_discovery requires at least one register_natives_offsets entry")
	}
	if len(jni.RegisterNativesOffsets) > MaxJNIRegisterHooks {
		return fmt.Errorf("jni_discovery has %d RegisterNatives offsets, maximum is %d",
			len(jni.RegisterNativesOffsets), MaxJNIRegisterHooks)
	}
	seen := make(map[OffsetValue]struct{}, len(jni.RegisterNativesOffsets))
	normalized := make([]OffsetValue, 0, len(jni.RegisterNativesOffsets))
	for _, offset := range jni.RegisterNativesOffsets {
		if offset == 0 {
			return fmt.Errorf("jni_discovery RegisterNatives offset must be non-zero")
		}
		if _, found := seen[offset]; found {
			continue
		}
		seen[offset] = struct{}{}
		normalized = append(normalized, offset)
	}
	jni.RegisterNativesOffsets = normalized
	return nil
}

func validateApplicationDataHooks(hooks []ApplicationDataHook) error {
	if len(hooks) > MaxApplicationHooks {
		return fmt.Errorf("too many application data hooks: %d, maximum is %d",
			len(hooks), MaxApplicationHooks)
	}
	names := make(map[string]struct{}, len(hooks))
	stateIDs := make(map[string]uint32)
	stateActions := make(map[string]uint32)
	for i := range hooks {
		hook := &hooks[i]
		hook.Name = strings.TrimSpace(hook.Name)
		if hook.Name == "" {
			return fmt.Errorf("data_hooks[%d].name is required", i)
		}
		nameKey := strings.ToLower(hook.Name)
		if _, found := names[nameKey]; found {
			return fmt.Errorf("duplicate application data hook name %q", hook.Name)
		}
		names[nameKey] = struct{}{}
		if hook.Disabled {
			continue
		}

		hook.Library = strings.TrimSpace(hook.Library)
		hook.LibraryGlob = strings.TrimSpace(hook.LibraryGlob)
		var err error
		hook.BuildID, err = normalizeBuildID(hook.BuildID)
		if err != nil {
			return fmt.Errorf("application data hook %q build_id: %w", hook.Name, err)
		}
		if hook.Library == "" && hook.LibraryGlob == "" {
			return fmt.Errorf("application data hook %q requires library or library_glob", hook.Name)
		}
		if hook.Library != "" && hook.LibraryGlob != "" {
			return fmt.Errorf("application data hook %q library and library_glob are mutually exclusive",
				hook.Name)
		}
		hook.Symbol = strings.TrimSpace(hook.Symbol)
		if (hook.Symbol == "") == (hook.Offset == 0) {
			return fmt.Errorf("application data hook %q requires exactly one of symbol or offset",
				hook.Name)
		}

		hook.Direction = strings.ToLower(strings.TrimSpace(hook.Direction))
		switch hook.Direction {
		case AppDataDirectionRead, AppDataDirectionWrite:
		default:
			return fmt.Errorf("application data hook %q has unsupported direction %q",
				hook.Name, hook.Direction)
		}
		hook.CaptureOn = strings.ToLower(strings.TrimSpace(hook.CaptureOn))
		if hook.CaptureOn == "" {
			hook.CaptureOn = AppDataCaptureEntry
		}
		switch hook.CaptureOn {
		case AppDataCaptureEntry, AppDataCaptureReturn:
		default:
			return fmt.Errorf("application data hook %q has unsupported capture_on %q",
				hook.Name, hook.CaptureOn)
		}
		if hook.BufferArg < 1 || hook.BufferArg > MaxApplicationArguments {
			return fmt.Errorf("application data hook %q buffer_arg must be between 1 and %d",
				hook.Name, MaxApplicationArguments)
		}
		if hook.ContextArg > MaxApplicationArguments {
			return fmt.Errorf("application data hook %q context_arg must be between 0 and %d",
				hook.Name, MaxApplicationArguments)
		}
		if hook.StreamArg > MaxApplicationArguments {
			return fmt.Errorf("application data hook %q stream_arg must be between 0 and %d",
				hook.Name, MaxApplicationArguments)
		}
		hook.BufferFormat = strings.ToLower(strings.TrimSpace(hook.BufferFormat))
		if hook.BufferFormat == "" {
			hook.BufferFormat = AppDataBufferRaw
		}
		switch hook.BufferFormat {
		case AppDataBufferRaw, AppDataBufferLibCXX, AppDataBufferIOVec, AppDataBufferMsgHdr:
		default:
			return fmt.Errorf("application data hook %q has unsupported buffer_format %q",
				hook.Name, hook.BufferFormat)
		}
		if uint64(hook.BufferOffset) > 1<<20 {
			return fmt.Errorf("application data hook %q buffer_offset is unreasonably large: %#x",
				hook.Name, uint64(hook.BufferOffset))
		}
		if uint64(hook.LengthOffset) > 1<<20 {
			return fmt.Errorf("application data hook %q length_offset is unreasonably large: %#x",
				hook.Name, uint64(hook.LengthOffset))
		}
		hook.StateGroup = strings.ToLower(strings.TrimSpace(hook.StateGroup))
		hook.StateAction = strings.ToLower(strings.TrimSpace(hook.StateAction))
		if (hook.BufferFormat == AppDataBufferIOVec ||
			hook.BufferFormat == AppDataBufferMsgHdr) && hook.StateAction != "" {
			return fmt.Errorf("application data hook %q buffer_format=%s does not support asynchronous state pairing",
				hook.Name, hook.BufferFormat)
		}
		if hook.StateAction == "" && hook.StateGroup != "" {
			return fmt.Errorf("application data hook %q state_group requires state_action",
				hook.Name)
		}
		if hook.StateAction != "" {
			if hook.StateGroup == "" {
				return fmt.Errorf("application data hook %q state_action requires state_group",
					hook.Name)
			}
			if hook.StateKeyArg < 1 || hook.StateKeyArg > MaxApplicationArguments {
				return fmt.Errorf("application data hook %q state_key_arg must be between 1 and %d",
					hook.Name, MaxApplicationArguments)
			}
			if hook.CaptureOn != AppDataCaptureEntry {
				return fmt.Errorf("application data hook %q state_action requires capture_on=entry",
					hook.Name)
			}
			switch hook.StateAction {
			case AppDataStateSave:
				stateActions[hook.StateGroup] |= 1
			case AppDataStateLoad:
				if hook.BufferFormat != AppDataBufferRaw || hook.BufferOffset != 0 ||
					hook.BufferIndirect {
					return fmt.Errorf("application data hook %q state_action=load requires a raw buffer with no offset or indirection",
						hook.Name)
				}
				stateActions[hook.StateGroup] |= 2
			default:
				return fmt.Errorf("application data hook %q has unsupported state_action %q",
					hook.Name, hook.StateAction)
			}
			id, found := stateIDs[hook.StateGroup]
			if !found {
				id = uint32(len(stateIDs) + 1)
				stateIDs[hook.StateGroup] = id
			}
			hook.stateID = id
		} else if hook.StateKeyArg != 0 {
			return fmt.Errorf("application data hook %q state_key_arg requires state_action",
				hook.Name)
		}

		hook.LengthSource = strings.ToLower(strings.TrimSpace(hook.LengthSource))
		if hook.BufferFormat == AppDataBufferIOVec {
			if hook.VectorCountArg < 1 || hook.VectorCountArg > MaxApplicationArguments {
				return fmt.Errorf("application data hook %q buffer_format=%s requires vector_count_arg between 1 and %d",
					hook.Name, AppDataBufferIOVec, MaxApplicationArguments)
			}
			if hook.BufferOffset != 0 || hook.BufferIndirect {
				return fmt.Errorf("application data hook %q buffer_format=%s requires a direct iovec pointer",
					hook.Name, AppDataBufferIOVec)
			}
			switch hook.LengthSource {
			case "":
				if hook.LengthArg != 0 || hook.FixedLength != 0 ||
					hook.LengthOffset != 0 || hook.LengthSize != 0 ||
					hook.LengthIndirect {
					return fmt.Errorf("application data hook %q buffer_format=%s derives lengths from vector entries and the optional function return value",
						hook.Name, AppDataBufferIOVec)
				}
			case AppDataLengthReturn:
				if hook.CaptureOn != AppDataCaptureReturn {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=return requires capture_on=return",
						hook.Name, AppDataBufferIOVec)
				}
				if hook.LengthArg != 0 || hook.FixedLength != 0 ||
					hook.LengthOffset != 0 || hook.LengthSize != 0 ||
					hook.LengthIndirect {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=return does not use length fields",
						hook.Name, AppDataBufferIOVec)
				}
			case AppDataLengthMemory:
				if hook.CaptureOn != AppDataCaptureReturn {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=memory requires capture_on=return",
						hook.Name, AppDataBufferIOVec)
				}
				if hook.LengthArg < 1 || hook.LengthArg > MaxApplicationArguments {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=memory requires length_arg between 1 and %d",
						hook.Name, AppDataBufferIOVec, MaxApplicationArguments)
				}
				if hook.FixedLength != 0 {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=memory does not use fixed_length",
						hook.Name, AppDataBufferIOVec)
				}
				if hook.LengthSize == 0 {
					hook.LengthSize = 8
				}
				switch hook.LengthSize {
				case 1, 2, 4, 8:
				default:
					return fmt.Errorf("application data hook %q has unsupported memory length_size %d",
						hook.Name, hook.LengthSize)
				}
			default:
				return fmt.Errorf("application data hook %q buffer_format=%s supports only empty, return, or memory length_source",
					hook.Name, AppDataBufferIOVec)
			}
			if hook.MaxBytes > MaxApplicationData {
				return fmt.Errorf("application data hook %q max_bytes %d exceeds %d",
					hook.Name, hook.MaxBytes, MaxApplicationData)
			}
			continue
		}
		if hook.BufferFormat == AppDataBufferMsgHdr {
			if hook.VectorCountArg != 0 {
				return fmt.Errorf("application data hook %q buffer_format=%s derives the vector count from the message header",
					hook.Name, AppDataBufferMsgHdr)
			}
			if hook.BufferIndirect {
				return fmt.Errorf("application data hook %q buffer_format=%s requires a direct message-header pointer",
					hook.Name, AppDataBufferMsgHdr)
			}
			if hook.LengthSource != "" || hook.LengthArg != 0 || hook.FixedLength != 0 ||
				hook.LengthIndirect {
				return fmt.Errorf("application data hook %q buffer_format=%s derives its iovec pointer and count from the message header",
					hook.Name, AppDataBufferMsgHdr)
			}
			if hook.BufferOffset == 0 {
				hook.BufferOffset = 16
			}
			if hook.LengthOffset == 0 {
				hook.LengthOffset = 24
			}
			if hook.LengthSize == 0 {
				hook.LengthSize = 8
			}
			if hook.LengthSize != 4 && hook.LengthSize != 8 {
				return fmt.Errorf("application data hook %q buffer_format=%s length_size must be 4 or 8",
					hook.Name, AppDataBufferMsgHdr)
			}
			if hook.MaxBytes > MaxApplicationData {
				return fmt.Errorf("application data hook %q max_bytes %d exceeds %d",
					hook.Name, hook.MaxBytes, MaxApplicationData)
			}
			continue
		}
		if hook.VectorCountArg != 0 {
			return fmt.Errorf("application data hook %q vector_count_arg requires buffer_format=%s",
				hook.Name, AppDataBufferIOVec)
		}
		if hook.BufferFormat == AppDataBufferLibCXX {
			if hook.LengthSource != "" || hook.LengthArg != 0 || hook.FixedLength != 0 ||
				hook.LengthOffset != 0 || hook.LengthSize != 0 || hook.LengthIndirect {
				return fmt.Errorf("application data hook %q buffer_format=%s derives its length from the string object",
					hook.Name, AppDataBufferLibCXX)
			}
			if hook.MaxBytes > MaxApplicationData {
				return fmt.Errorf("application data hook %q max_bytes %d exceeds %d",
					hook.Name, hook.MaxBytes, MaxApplicationData)
			}
			continue
		}
		if hook.LengthSource == "" {
			hook.LengthSource = AppDataLengthArgument
		}
		switch hook.LengthSource {
		case AppDataLengthArgument:
			if hook.FixedLength != 0 {
				return fmt.Errorf("application data hook %q fixed_length requires length_source=fixed",
					hook.Name)
			}
			if hook.LengthArg < 1 || hook.LengthArg > MaxApplicationArguments {
				return fmt.Errorf("application data hook %q length_arg must be between 1 and %d",
					hook.Name, MaxApplicationArguments)
			}
		case AppDataLengthMemory:
			if hook.FixedLength != 0 {
				return fmt.Errorf("application data hook %q fixed_length requires length_source=fixed",
					hook.Name)
			}
			if hook.LengthArg > MaxApplicationArguments {
				return fmt.Errorf("application data hook %q memory length_arg must be between 0 and %d",
					hook.Name, MaxApplicationArguments)
			}
			if hook.LengthSize == 0 {
				hook.LengthSize = 8
			}
			switch hook.LengthSize {
			case 1, 2, 4, 8:
			default:
				return fmt.Errorf("application data hook %q length_size must be 1, 2, 4, or 8",
					hook.Name)
			}
		case AppDataLengthFixed:
			if hook.LengthArg != 0 {
				return fmt.Errorf("application data hook %q length_arg is unused when length_source=fixed",
					hook.Name)
			}
			if hook.FixedLength == 0 {
				return fmt.Errorf("application data hook %q fixed_length must be greater than zero",
					hook.Name)
			}
			if hook.FixedLength > MaxApplicationData {
				return fmt.Errorf("application data hook %q fixed_length %d exceeds %d",
					hook.Name, hook.FixedLength, MaxApplicationData)
			}
		case AppDataLengthReturn:
			if hook.FixedLength != 0 {
				return fmt.Errorf("application data hook %q fixed_length requires length_source=fixed",
					hook.Name)
			}
			if hook.CaptureOn != AppDataCaptureReturn {
				return fmt.Errorf("application data hook %q length_source=return requires capture_on=return",
					hook.Name)
			}
		default:
			return fmt.Errorf("application data hook %q has unsupported length_source %q",
				hook.Name, hook.LengthSource)
		}
		if hook.LengthIndirect && hook.LengthSource != AppDataLengthMemory {
			return fmt.Errorf("application data hook %q length_indirect requires length_source=memory",
				hook.Name)
		}
		if hook.MaxBytes > MaxApplicationData {
			return fmt.Errorf("application data hook %q max_bytes %d exceeds %d",
				hook.Name, hook.MaxBytes, MaxApplicationData)
		}
	}
	for group, actions := range stateActions {
		if actions != 3 {
			return fmt.Errorf("application data state group %q requires both save and load hooks",
				group)
		}
	}
	return nil
}

func validateProfileStrategies(strategies []string) error {
	for _, strategy := range strategies {
		strategy = strings.ToLower(strings.TrimSpace(strategy))
		if _, ok := supportedStrategies[strategy]; !ok {
			return fmt.Errorf("unsupported capture strategy %q", strategy)
		}
	}
	return nil
}

func normalizeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func normalizeInterfaceNames(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func resolveLibraryGlob(pattern string) (string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid library glob %q: %w", pattern, err)
	}
	candidates := make([]string, 0, len(matches))
	for _, match := range matches {
		info, statErr := os.Stat(match)
		if statErr == nil && !info.IsDir() {
			candidates = append(candidates, match)
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("library glob %q did not match a file", pattern)
	}
	sort.Strings(candidates)
	return candidates[len(candidates)-1], nil
}

func parseAssignment(assignment string) (string, string, error) {
	name, value, found := strings.Cut(assignment, "=")
	name = strings.ToLower(strings.TrimSpace(name))
	value = strings.TrimSpace(value)
	if !found || name == "" || value == "" {
		return "", "", fmt.Errorf("invalid assignment %q, want name=value", assignment)
	}
	return name, value, nil
}

func StructOffsetConstant(name string) (string, bool) {
	constant, ok := structOffsetConstants[strings.ToLower(strings.TrimSpace(name))]
	return constant, ok
}
