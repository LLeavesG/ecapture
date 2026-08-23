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
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	ApplicationProfileVersion = 1
	MaxNetworkOwnerPackages   = 16
	MaxApplicationPackageName = 255

	StrategyRawPackets   = "raw_packets"
	StrategyTLSPlaintext = "tls_plaintext"
	StrategyTLSKeys      = "tls_keys"
	StrategyQUICMetadata = "quic_metadata"
	// StrategyBoundaryData enables profile-defined hooks that observe bytes at
	// a wire or TLS/QUIC transport boundary. It is deliberately separate from
	// application_data so a communication-only profile cannot accidentally
	// enable request-object, logging, JNI, or serializer hooks.
	StrategyBoundaryData = "boundary_data"
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
	AppDataBufferVector   = "vector"
	AppDataBufferMsgHdr   = "msghdr"
	AppDataStateSave      = "save"
	AppDataStateLoad      = "load"
	AppDataStackKernel    = "kernel"
	AppDataStackDWARF     = "dwarf"

	MaxApplicationHooks = 8
	MaxApplicationData  = 8 * MaxDataSize
	// MaxApplicationArguments covers the full register argument set plus the
	// first entry-stack arguments on the supported amd64 and arm64 ABIs. QUIC
	// APIs such as ngtcp2 expose stream buffers beyond argument eight.
	MaxApplicationArguments    = 12
	MaxApplicationVectorStride = 256
	MaxJNIRegisterHooks        = 4
	MaxJNIConversionHooks      = 4
	MaxJNIConversionCallers    = 256

	JNIConversionGetStringLength               = "get_string_length"
	JNIConversionGetStringChars                = "get_string_chars"
	JNIConversionReleaseStringChars            = "release_string_chars"
	JNIConversionGetStringUTFLength            = "get_string_utf_length"
	JNIConversionGetStringUTFChars             = "get_string_utf_chars"
	JNIConversionReleaseStringUTFChars         = "release_string_utf_chars"
	JNIConversionGetArrayLength                = "get_array_length"
	JNIConversionGetByteArrayElements          = "get_byte_array_elements"
	JNIConversionReleaseByteArrayElements      = "release_byte_array_elements"
	JNIConversionGetByteArrayRegion            = "get_byte_array_region"
	JNIConversionSetByteArrayRegion            = "set_byte_array_region"
	JNIConversionGetPrimitiveArrayCritical     = "get_primitive_array_critical"
	JNIConversionReleasePrimitiveArrayCritical = "release_primitive_array_critical"
	JNIConversionGetStringCritical             = "get_string_critical"
	JNIConversionReleaseStringCritical         = "release_string_critical"
	JNIConversionGetDirectBufferAddress        = "get_direct_buffer_address"
	JNIConversionGetDirectBufferCapacity       = "get_direct_buffer_capacity"
)

var androidPackageNamePattern = regexp.MustCompile(
	`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`,
)

var (
	supportedStrategies = map[string]struct{}{
		StrategyRawPackets:   {},
		StrategyTLSPlaintext: {},
		StrategyTLSKeys:      {},
		StrategyQUICMetadata: {},
		StrategyBoundaryData: {},
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
	supportedJNIConversionRoles = map[string]struct{}{
		JNIConversionGetStringLength:               {},
		JNIConversionGetStringChars:                {},
		JNIConversionReleaseStringChars:            {},
		JNIConversionGetStringUTFLength:            {},
		JNIConversionGetStringUTFChars:             {},
		JNIConversionReleaseStringUTFChars:         {},
		JNIConversionGetArrayLength:                {},
		JNIConversionGetByteArrayElements:          {},
		JNIConversionReleaseByteArrayElements:      {},
		JNIConversionGetByteArrayRegion:            {},
		JNIConversionSetByteArrayRegion:            {},
		JNIConversionGetPrimitiveArrayCritical:     {},
		JNIConversionReleasePrimitiveArrayCritical: {},
		JNIConversionGetStringCritical:             {},
		JNIConversionReleaseStringCritical:         {},
		JNIConversionGetDirectBufferAddress:        {},
		JNIConversionGetDirectBufferCapacity:       {},
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
	Package              string   `json:"package,omitempty"`
	NetworkOwnerPackages []string `json:"network_owner_packages,omitempty"`
	UID                  uint64   `json:"uid,omitempty"`
	PID                  uint64   `json:"pid,omitempty"`
	AndroidRelease       string   `json:"android_release,omitempty"`
	ABI                  string   `json:"abi,omitempty"`
	VersionName          string   `json:"version_name,omitempty"`
	VersionCode          uint64   `json:"version_code,omitempty"`
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
	PerfBufferPages   uint     `json:"perf_buffer_pages,omitempty"`
	// EmitPacketEvents duplicates raw packets into the structured event sink.
	// PCAPNG remains authoritative when this is false. The pointer preserves
	// the historical default for profiles that do not specify the field.
	EmitPacketEvents *bool `json:"emit_packet_events,omitempty"`
	PerfReorder      *bool `json:"perf_reorder,omitempty"`
	PerfReorderLagMs uint  `json:"perf_reorder_lag_ms,omitempty"`
}

type ApplicationTLS struct {
	Library               string                 `json:"library,omitempty"`
	LibraryGlob           string                 `json:"library_glob,omitempty"`
	AdditionalLibraries   []string               `json:"additional_libraries,omitempty"`
	AdditionalLibGlobs    []string               `json:"additional_library_globs,omitempty"`
	AutoDiscoverLibraries bool                   `json:"auto_discover_libraries,omitempty"`
	BuildID               string                 `json:"build_id,omitempty"`
	Version               string                 `json:"version,omitempty"`
	BoringSSL             *bool                  `json:"boring_ssl,omitempty"`
	MasterHookFuncs       []string               `json:"master_hook_funcs,omitempty"`
	Hooks                 map[string]HookProfile `json:"hooks,omitempty"`
}

// JNIDiscoveryProfile attaches specialized RegisterNatives decoders to ART.
// The offsets can be found without private symbols by locating the standard
// JNINativeInterface table (RegisterNatives is entry 215).
type JNIDiscoveryProfile struct {
	Library                string                   `json:"library,omitempty"`
	LibraryGlob            string                   `json:"library_glob,omitempty"`
	BuildID                string                   `json:"build_id,omitempty"`
	RegisterNativesOffsets []OffsetValue            `json:"register_natives_offsets,omitempty"`
	ConversionOffsets      map[string][]OffsetValue `json:"conversion_offsets,omitempty"`
	CallerAllowlist        []JNIConversionCaller    `json:"caller_allowlist,omitempty"`

	resolvedLibrary string
}

// JNIConversionCaller is an ASLR-stable allowlist entry for one native
// callsite invoking a standard JNIEnv conversion function. Module matches an
// ELF basename while ModuleGlob matches the complete path in /proc/PID/maps.
// BuildID is optional for diagnostics but should be pinned in production.
type JNIConversionCaller struct {
	Module     string      `json:"module,omitempty"`
	ModuleGlob string      `json:"module_glob,omitempty"`
	BuildID    string      `json:"build_id,omitempty"`
	Role       string      `json:"role"`
	Offset     OffsetValue `json:"offset"`
}

// HookProfile selects either an exported symbol or a file offset for a
// well-known probe role. Offset takes precedence when it is non-zero.
type HookProfile struct {
	Symbol   string      `json:"symbol,omitempty"`
	Offset   OffsetValue `json:"offset,omitempty"`
	Disabled bool        `json:"disabled,omitempty"`
}

// ApplicationDataHook describes a generic user-space function whose arguments
// expose bytes at a declared capture boundary. It supports direct
// pointer/length arguments as well as one level of indirection and structure
// offsets, which is useful for socket APIs, custom BIOs, Cronet buffers, and
// private networking SDKs.
type ApplicationDataHook struct {
	Name                   string      `json:"name"`
	Library                string      `json:"library,omitempty"`
	LibraryGlob            string      `json:"library_glob,omitempty"`
	BuildID                string      `json:"build_id,omitempty"`
	CaptureLayer           string      `json:"capture_layer,omitempty"`
	Transport              string      `json:"transport,omitempty"`
	BoundaryRole           string      `json:"boundary_role,omitempty"`
	Symbol                 string      `json:"symbol,omitempty"`
	Offset                 OffsetValue `json:"offset,omitempty"`
	Direction              string      `json:"direction"`
	CaptureOn              string      `json:"capture_on,omitempty"`
	BufferArg              uint32      `json:"buffer_arg"`
	BufferFormat           string      `json:"buffer_format,omitempty"`
	BufferOffset           OffsetValue `json:"buffer_offset,omitempty"`
	BufferIndirect         bool        `json:"buffer_indirect,omitempty"`
	LengthSource           string      `json:"length_source,omitempty"`
	LengthArg              uint32      `json:"length_arg,omitempty"`
	FixedLength            uint32      `json:"fixed_length,omitempty"`
	LengthOffset           OffsetValue `json:"length_offset,omitempty"`
	LengthSize             uint32      `json:"length_size,omitempty"`
	LengthIndirect         bool        `json:"length_indirect,omitempty"`
	MaxBytes               uint32      `json:"max_bytes,omitempty"`
	ContextArg             uint32      `json:"context_arg,omitempty"`
	ContextOffset          OffsetValue `json:"context_offset,omitempty"`
	ContextSize            uint32      `json:"context_size,omitempty"`
	StreamArg              uint32      `json:"stream_arg,omitempty"`
	StreamOffset           OffsetValue `json:"stream_offset,omitempty"`
	StreamSize             uint32      `json:"stream_size,omitempty"`
	StreamByteOffsetArg    uint32      `json:"stream_byte_offset_arg,omitempty"`
	StreamByteOffsetOffset OffsetValue `json:"stream_byte_offset_offset,omitempty"`
	StreamByteOffsetSize   uint32      `json:"stream_byte_offset_size,omitempty"`
	FinArg                 uint32      `json:"fin_arg,omitempty"`
	FinOffset              OffsetValue `json:"fin_offset,omitempty"`
	FinSize                uint32      `json:"fin_size,omitempty"`
	VectorCountArg         uint32      `json:"vector_count_arg,omitempty"`
	VectorStride           uint32      `json:"vector_stride,omitempty"`
	VectorBaseOffset       uint32      `json:"vector_base_offset,omitempty"`
	VectorLengthOffset     uint32      `json:"vector_length_offset,omitempty"`
	VectorLengthSize       uint32      `json:"vector_length_size,omitempty"`
	StateGroup             string      `json:"state_group,omitempty"`
	StateAction            string      `json:"state_action,omitempty"`
	StateKeyArg            uint32      `json:"state_key_arg,omitempty"`
	CollectUserStack       bool        `json:"collect_user_stack,omitempty"`
	StackMode              string      `json:"stack_mode,omitempty"`
	Disabled               bool        `json:"disabled,omitempty"`

	resolvedLibrary string
	resolvedTarget  libraryTarget
	resolvedOffset  uint64
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

// ValidateActivationReadiness applies the enabled-hook runtime contract to
// every data hook while preserving the profile's configured disabled state.
// Discovery systems use this before promoting disabled static candidates into
// a live probe.
func (p *ApplicationProfile) ValidateActivationReadiness() error {
	if err := p.Validate(); err != nil {
		return err
	}
	hooks := append([]ApplicationDataHook(nil), p.DataHooks...)
	for i := range hooks {
		hooks[i].Disabled = false
	}
	if err := validateApplicationDataHooks(hooks); err != nil {
		return fmt.Errorf("data hook activation readiness: %w", err)
	}
	return nil
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
	p.Match.Package = strings.TrimSpace(p.Match.Package)
	if p.Match.Package == "" && p.Match.UID == 0 && p.Match.PID == 0 {
		return fmt.Errorf("profile match requires package, uid, or pid")
	}
	if p.Match.Package != "" &&
		(len(p.Match.Package) > MaxApplicationPackageName ||
			!androidPackageNamePattern.MatchString(p.Match.Package)) {
		return fmt.Errorf("profile match package is invalid: %q", p.Match.Package)
	}
	p.Match.NetworkOwnerPackages = normalizeRelatedPackages(
		p.Match.NetworkOwnerPackages,
		p.Match.Package,
	)
	if len(p.Match.NetworkOwnerPackages) > MaxNetworkOwnerPackages {
		return fmt.Errorf(
			"profile match network_owner_packages exceeds %d entries",
			MaxNetworkOwnerPackages,
		)
	}
	for _, packageName := range p.Match.NetworkOwnerPackages {
		if len(packageName) > MaxApplicationPackageName ||
			!androidPackageNamePattern.MatchString(packageName) {
			return fmt.Errorf(
				"profile match network owner package is invalid: %q",
				packageName,
			)
		}
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
	if p.Capture.PerfBufferPages != 0 &&
		(p.Capture.PerfBufferPages < 64 ||
			p.Capture.PerfBufferPages > 16384) {
		return fmt.Errorf(
			"perf_buffer_pages must be between 64 and 16384, got %d",
			p.Capture.PerfBufferPages,
		)
	}
	if p.TLS.Library != "" && p.TLS.LibraryGlob != "" {
		return fmt.Errorf("tls.library and tls.library_glob are mutually exclusive")
	}
	p.TLS.AdditionalLibraries = normalizePaths(p.TLS.AdditionalLibraries)
	p.TLS.AdditionalLibGlobs = normalizePaths(p.TLS.AdditionalLibGlobs)
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
	if len(jni.RegisterNativesOffsets) == 0 && len(jni.ConversionOffsets) == 0 {
		return fmt.Errorf("jni_discovery requires RegisterNatives or conversion offsets")
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
	conversionOffsets := make(map[string][]OffsetValue, len(jni.ConversionOffsets))
	usedOffsets := make(map[OffsetValue]string)
	for rawRole, offsets := range jni.ConversionOffsets {
		role := strings.ToLower(strings.TrimSpace(rawRole))
		if _, found := supportedJNIConversionRoles[role]; !found {
			return fmt.Errorf("jni_discovery has unsupported conversion role %q", rawRole)
		}
		if len(offsets) == 0 {
			return fmt.Errorf("jni_discovery conversion role %q has no offsets", role)
		}
		if len(offsets) > MaxJNIConversionHooks {
			return fmt.Errorf("jni_discovery conversion role %q has %d offsets, maximum is %d",
				role, len(offsets), MaxJNIConversionHooks)
		}
		roleSeen := make(map[OffsetValue]struct{}, len(offsets))
		for _, offset := range offsets {
			if offset == 0 {
				return fmt.Errorf("jni_discovery conversion role %q has a zero offset", role)
			}
			if _, found := roleSeen[offset]; found {
				continue
			}
			if otherRole, found := usedOffsets[offset]; found && otherRole != role {
				return fmt.Errorf(
					"jni_discovery conversion offset %#x is ambiguous between %q and %q",
					uint64(offset), otherRole, role)
			}
			roleSeen[offset] = struct{}{}
			usedOffsets[offset] = role
			conversionOffsets[role] = append(conversionOffsets[role], offset)
		}
	}
	jni.ConversionOffsets = conversionOffsets
	if len(jni.CallerAllowlist) > MaxJNIConversionCallers {
		return fmt.Errorf(
			"jni_discovery has %d caller allowlist entries, maximum is %d",
			len(jni.CallerAllowlist),
			MaxJNIConversionCallers,
		)
	}
	callers := make([]JNIConversionCaller, 0, len(jni.CallerAllowlist))
	callerSeen := make(map[string]struct{}, len(jni.CallerAllowlist))
	for index, caller := range jni.CallerAllowlist {
		caller.Module = strings.TrimSpace(caller.Module)
		caller.ModuleGlob = strings.TrimSpace(caller.ModuleGlob)
		if (caller.Module == "") == (caller.ModuleGlob == "") {
			return fmt.Errorf(
				"jni_discovery caller allowlist entry %d requires exactly one of module or module_glob",
				index,
			)
		}
		if strings.ContainsAny(caller.Module, `/\`) {
			return fmt.Errorf(
				"jni_discovery caller allowlist entry %d module must be an ELF basename; use module_glob for paths",
				index,
			)
		}
		caller.Role = strings.ToLower(strings.TrimSpace(caller.Role))
		if _, found := supportedJNIConversionRoles[caller.Role]; !found {
			return fmt.Errorf(
				"jni_discovery caller allowlist entry %d has unsupported role %q",
				index,
				caller.Role,
			)
		}
		if caller.Offset == 0 {
			return fmt.Errorf(
				"jni_discovery caller allowlist entry %d has a zero offset",
				index,
			)
		}
		caller.BuildID, err = normalizeBuildID(caller.BuildID)
		if err != nil {
			return fmt.Errorf(
				"jni_discovery caller allowlist entry %d build_id: %w",
				index,
				err,
			)
		}
		key := strings.Join([]string{
			caller.Module,
			caller.ModuleGlob,
			caller.BuildID,
			caller.Role,
			fmt.Sprintf("%x", uint64(caller.Offset)),
		}, "\x00")
		if _, found := callerSeen[key]; found {
			continue
		}
		callerSeen[key] = struct{}{}
		callers = append(callers, caller)
	}
	jni.CallerAllowlist = callers
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
		hook.CaptureLayer = strings.ToLower(strings.TrimSpace(hook.CaptureLayer))
		hook.Transport = strings.ToLower(strings.TrimSpace(hook.Transport))
		hook.BoundaryRole = strings.ToLower(strings.TrimSpace(hook.BoundaryRole))
		if hook.CaptureLayer == "" {
			// Existing data_hooks predate provenance. Treat them as semantic
			// rather than claiming that an unknown private ABI is a transport
			// boundary.
			hook.CaptureLayer = CaptureLayerSemantic
		}
		switch hook.CaptureLayer {
		case CaptureLayerWire:
			if hook.Transport == "" {
				hook.Transport = CaptureTransportSocket
			}
			if hook.Transport != CaptureTransportSocket &&
				hook.Transport != CaptureTransportTLS &&
				hook.Transport != CaptureTransportFD {
				return fmt.Errorf(
					"application data hook %q capture_layer=%s requires transport=tls, socket, or fd",
					hook.Name,
					CaptureLayerWire,
				)
			}
		case CaptureLayerTransport:
			switch hook.Transport {
			case CaptureTransportTLS, CaptureTransportQUIC:
			default:
				return fmt.Errorf(
					"application data hook %q capture_layer=%s requires transport=tls or transport=quic",
					hook.Name,
					CaptureLayerTransport,
				)
			}
		case CaptureLayerSemantic:
			if hook.Transport != "" {
				return fmt.Errorf(
					"application data hook %q capture_layer=%s cannot claim transport=%q",
					hook.Name,
					CaptureLayerSemantic,
					hook.Transport,
				)
			}
		default:
			return fmt.Errorf(
				"application data hook %q has unsupported capture_layer %q",
				hook.Name,
				hook.CaptureLayer,
			)
		}
		if hook.BoundaryRole != "" {
			switch hook.BoundaryRole {
			case CaptureBoundaryTLSCiphertext,
				CaptureBoundarySocketPayload,
				CaptureBoundaryFDPayload:
			default:
				return fmt.Errorf(
					"application data hook %q has unsupported boundary_role %q",
					hook.Name,
					hook.BoundaryRole,
				)
			}
			requiredTransport := ""
			switch hook.BoundaryRole {
			case CaptureBoundaryTLSCiphertext:
				requiredTransport = CaptureTransportTLS
			case CaptureBoundarySocketPayload:
				requiredTransport = CaptureTransportSocket
			case CaptureBoundaryFDPayload:
				requiredTransport = CaptureTransportFD
			}
			if hook.CaptureLayer != CaptureLayerWire ||
				hook.Transport != requiredTransport {
				return fmt.Errorf(
					"application data hook %q boundary_role=%s requires capture_layer=%s and transport=%s",
					hook.Name,
					hook.BoundaryRole,
					CaptureLayerWire,
					requiredTransport,
				)
			}
			if hook.ContextArg == 0 {
				return fmt.Errorf(
					"application data hook %q boundary_role=%s requires context_arg",
					hook.Name,
					hook.BoundaryRole,
				)
			}
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
		hook.StackMode = strings.ToLower(strings.TrimSpace(hook.StackMode))
		switch hook.StackMode {
		case "":
			if hook.CollectUserStack {
				hook.StackMode = AppDataStackKernel
			}
		case AppDataStackKernel, AppDataStackDWARF:
			hook.CollectUserStack = true
		default:
			return fmt.Errorf("application data hook %q has unsupported stack_mode %q",
				hook.Name, hook.StackMode)
		}
		if hook.BufferArg < 1 || hook.BufferArg > MaxApplicationArguments {
			return fmt.Errorf("application data hook %q buffer_arg must be between 1 and %d",
				hook.Name, MaxApplicationArguments)
		}
		if hook.ContextArg > MaxApplicationArguments {
			return fmt.Errorf("application data hook %q context_arg must be between 0 and %d",
				hook.Name, MaxApplicationArguments)
		}
		if uint64(hook.ContextOffset) > 1<<20 {
			return fmt.Errorf("application data hook %q context_offset is unreasonably large: %#x",
				hook.Name, uint64(hook.ContextOffset))
		}
		if hook.ContextOffset != 0 && hook.ContextSize == 0 {
			hook.ContextSize = 8
		}
		if hook.ContextSize != 0 {
			if hook.ContextArg == 0 {
				return fmt.Errorf("application data hook %q context_size requires context_arg",
					hook.Name)
			}
			switch hook.ContextSize {
			case 1, 2, 4, 8:
			default:
				return fmt.Errorf("application data hook %q context_size must be 1, 2, 4, or 8",
					hook.Name)
			}
		}
		if hook.StreamArg > MaxApplicationArguments {
			return fmt.Errorf("application data hook %q stream_arg must be between 0 and %d",
				hook.Name, MaxApplicationArguments)
		}
		if uint64(hook.StreamOffset) > 1<<20 {
			return fmt.Errorf("application data hook %q stream_offset is unreasonably large: %#x",
				hook.Name, uint64(hook.StreamOffset))
		}
		if hook.StreamOffset != 0 && hook.StreamSize == 0 {
			hook.StreamSize = 8
		}
		if hook.StreamSize != 0 {
			if hook.StreamArg == 0 {
				return fmt.Errorf("application data hook %q stream_size requires stream_arg",
					hook.Name)
			}
			switch hook.StreamSize {
			case 1, 2, 4, 8:
			default:
				return fmt.Errorf("application data hook %q stream_size must be 1, 2, 4, or 8",
					hook.Name)
			}
		}
		if hook.StreamByteOffsetArg > MaxApplicationArguments {
			return fmt.Errorf("application data hook %q stream_byte_offset_arg must be between 0 and %d",
				hook.Name, MaxApplicationArguments)
		}
		if uint64(hook.StreamByteOffsetOffset) > 1<<20 {
			return fmt.Errorf("application data hook %q stream_byte_offset_offset is unreasonably large: %#x",
				hook.Name, uint64(hook.StreamByteOffsetOffset))
		}
		if hook.StreamByteOffsetOffset != 0 && hook.StreamByteOffsetSize == 0 {
			hook.StreamByteOffsetSize = 8
		}
		if hook.StreamByteOffsetSize != 0 {
			if hook.StreamByteOffsetArg == 0 {
				return fmt.Errorf("application data hook %q stream_byte_offset_size requires stream_byte_offset_arg",
					hook.Name)
			}
			switch hook.StreamByteOffsetSize {
			case 1, 2, 4, 8:
			default:
				return fmt.Errorf("application data hook %q stream_byte_offset_size must be 1, 2, 4, or 8",
					hook.Name)
			}
		}
		if hook.FinArg > MaxApplicationArguments {
			return fmt.Errorf("application data hook %q fin_arg must be between 0 and %d",
				hook.Name, MaxApplicationArguments)
		}
		if uint64(hook.FinOffset) > 1<<20 {
			return fmt.Errorf("application data hook %q fin_offset is unreasonably large: %#x",
				hook.Name, uint64(hook.FinOffset))
		}
		if hook.FinOffset != 0 && hook.FinSize == 0 {
			hook.FinSize = 1
		}
		if hook.FinSize != 0 {
			if hook.FinArg == 0 {
				return fmt.Errorf("application data hook %q fin_size requires fin_arg",
					hook.Name)
			}
			switch hook.FinSize {
			case 1, 2, 4, 8:
			default:
				return fmt.Errorf("application data hook %q fin_size must be 1, 2, 4, or 8",
					hook.Name)
			}
		}
		if (hook.StreamByteOffsetArg != 0 || hook.FinArg != 0) &&
			(hook.CaptureLayer != CaptureLayerTransport ||
				hook.Transport != CaptureTransportQUIC) {
			return fmt.Errorf(
				"application data hook %q stream byte offset and FIN metadata require capture_layer=%s and transport=%s",
				hook.Name,
				CaptureLayerTransport,
				CaptureTransportQUIC,
			)
		}
		hook.BufferFormat = strings.ToLower(strings.TrimSpace(hook.BufferFormat))
		if hook.BufferFormat == "" {
			hook.BufferFormat = AppDataBufferRaw
		}
		switch hook.BufferFormat {
		case AppDataBufferRaw, AppDataBufferLibCXX, AppDataBufferIOVec,
			AppDataBufferVector, AppDataBufferMsgHdr:
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
			hook.BufferFormat == AppDataBufferVector ||
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
		isArgumentVector := hook.BufferFormat == AppDataBufferIOVec ||
			hook.BufferFormat == AppDataBufferVector
		if isArgumentVector {
			if hook.VectorCountArg < 1 || hook.VectorCountArg > MaxApplicationArguments {
				return fmt.Errorf("application data hook %q buffer_format=%s requires vector_count_arg between 1 and %d",
					hook.Name, hook.BufferFormat, MaxApplicationArguments)
			}
			if hook.BufferOffset != 0 || hook.BufferIndirect {
				return fmt.Errorf("application data hook %q buffer_format=%s requires a direct vector pointer",
					hook.Name, hook.BufferFormat)
			}
			if hook.BufferFormat == AppDataBufferIOVec {
				if (hook.VectorStride != 0 && hook.VectorStride != 16) ||
					hook.VectorBaseOffset != 0 ||
					(hook.VectorLengthOffset != 0 && hook.VectorLengthOffset != 8) ||
					(hook.VectorLengthSize != 0 && hook.VectorLengthSize != 8) {
					return fmt.Errorf("application data hook %q buffer_format=%s has a fixed 64-bit struct iovec layout; use buffer_format=%s for a private layout",
						hook.Name, AppDataBufferIOVec, AppDataBufferVector)
				}
				hook.VectorStride = 16
				hook.VectorBaseOffset = 0
				hook.VectorLengthOffset = 8
				hook.VectorLengthSize = 8
			} else {
				if hook.VectorStride == 0 ||
					hook.VectorStride > MaxApplicationVectorStride {
					return fmt.Errorf("application data hook %q buffer_format=%s requires vector_stride between 1 and %d",
						hook.Name, AppDataBufferVector, MaxApplicationVectorStride)
				}
				if hook.VectorLengthSize == 0 {
					hook.VectorLengthSize = 8
				}
				switch hook.VectorLengthSize {
				case 1, 2, 4, 8:
				default:
					return fmt.Errorf("application data hook %q vector_length_size must be 1, 2, 4, or 8",
						hook.Name)
				}
				if uint64(hook.VectorBaseOffset)+8 > uint64(hook.VectorStride) {
					return fmt.Errorf("application data hook %q vector base field exceeds vector_stride",
						hook.Name)
				}
				if uint64(hook.VectorLengthOffset)+uint64(hook.VectorLengthSize) >
					uint64(hook.VectorStride) {
					return fmt.Errorf("application data hook %q vector length field exceeds vector_stride",
						hook.Name)
				}
			}
			switch hook.LengthSource {
			case "":
				if hook.LengthArg != 0 || hook.FixedLength != 0 ||
					hook.LengthOffset != 0 || hook.LengthSize != 0 ||
					hook.LengthIndirect {
					return fmt.Errorf("application data hook %q buffer_format=%s derives lengths from vector entries and the optional function return value",
						hook.Name, hook.BufferFormat)
				}
			case AppDataLengthReturn:
				if hook.CaptureOn != AppDataCaptureReturn {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=return requires capture_on=return",
						hook.Name, hook.BufferFormat)
				}
				if hook.LengthArg != 0 || hook.FixedLength != 0 ||
					hook.LengthOffset != 0 || hook.LengthIndirect {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=return only accepts length_size",
						hook.Name, hook.BufferFormat)
				}
				if hook.LengthSize == 0 {
					hook.LengthSize = 8
				}
				if hook.LengthSize != 4 && hook.LengthSize != 8 {
					return fmt.Errorf("application data hook %q buffer_format=%s return length_size must be 4 or 8",
						hook.Name, hook.BufferFormat)
				}
			case AppDataLengthMemory:
				if hook.CaptureOn != AppDataCaptureReturn {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=memory requires capture_on=return",
						hook.Name, hook.BufferFormat)
				}
				if hook.LengthArg < 1 || hook.LengthArg > MaxApplicationArguments {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=memory requires length_arg between 1 and %d",
						hook.Name, hook.BufferFormat, MaxApplicationArguments)
				}
				if hook.FixedLength != 0 {
					return fmt.Errorf("application data hook %q buffer_format=%s length_source=memory does not use fixed_length",
						hook.Name, hook.BufferFormat)
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
					hook.Name, hook.BufferFormat)
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
			if (hook.VectorStride != 0 && hook.VectorStride != 16) ||
				hook.VectorBaseOffset != 0 ||
				(hook.VectorLengthOffset != 0 && hook.VectorLengthOffset != 8) ||
				(hook.VectorLengthSize != 0 && hook.VectorLengthSize != 8) {
				return fmt.Errorf("application data hook %q buffer_format=%s requires standard 64-bit iovec entries",
					hook.Name, AppDataBufferMsgHdr)
			}
			hook.VectorStride = 16
			hook.VectorBaseOffset = 0
			hook.VectorLengthOffset = 8
			hook.VectorLengthSize = 8
			if hook.MaxBytes > MaxApplicationData {
				return fmt.Errorf("application data hook %q max_bytes %d exceeds %d",
					hook.Name, hook.MaxBytes, MaxApplicationData)
			}
			continue
		}
		if hook.VectorCountArg != 0 {
			return fmt.Errorf("application data hook %q vector_count_arg requires buffer_format=%s or %s",
				hook.Name, AppDataBufferIOVec, AppDataBufferVector)
		}
		if hook.VectorStride != 0 || hook.VectorBaseOffset != 0 ||
			hook.VectorLengthOffset != 0 || hook.VectorLengthSize != 0 {
			return fmt.Errorf("application data hook %q vector layout fields require buffer_format=%s, %s, or %s",
				hook.Name, AppDataBufferIOVec, AppDataBufferVector, AppDataBufferMsgHdr)
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
			if hook.LengthArg != 0 || hook.LengthOffset != 0 ||
				hook.LengthIndirect {
				return fmt.Errorf("application data hook %q length_source=return only accepts length_size",
					hook.Name)
			}
			if hook.LengthSize == 0 {
				hook.LengthSize = 8
			}
			if hook.LengthSize != 4 && hook.LengthSize != 8 {
				return fmt.Errorf("application data hook %q return length_size must be 4 or 8",
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

func normalizeRelatedPackages(values []string, primary string) []string {
	primary = strings.TrimSpace(primary)
	seen := make(map[string]struct{}, len(values)+1)
	if primary != "" {
		seen[primary] = struct{}{}
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizePaths(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
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
	candidates, err := resolveLibrarySpecGlobAll(pattern)
	if err != nil {
		return "", err
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
