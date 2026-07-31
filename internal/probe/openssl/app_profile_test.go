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
	"os"
	"path/filepath"
	"testing"
)

func TestOffsetValueAcceptsHexAndDecimal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	data := []byte(`{
		"version": 1,
		"name": "offset-test",
		"match": {"uid": 10001},
		"offsets": {
			"ssl_st_rbio": "0x18",
			"ssl_st_wbio": 32
		}
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := LoadApplicationProfile(path)
	if err != nil {
		t.Fatalf("LoadApplicationProfile() error = %v", err)
	}
	if got := uint64(profile.Offsets[OffsetSSLRBIO]); got != 0x18 {
		t.Fatalf("ssl_st_rbio = %#x, want 0x18", got)
	}
	if got := uint64(profile.Offsets[OffsetSSLWBIO]); got != 32 {
		t.Fatalf("ssl_st_wbio = %d, want 32", got)
	}
}

func TestApplicationProfileRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	data := []byte(`{
		"version": 1,
		"name": "bad-profile",
		"match": {"uid": 10001},
		"unknown": true
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadApplicationProfile(path); err == nil {
		t.Fatal("LoadApplicationProfile() should reject unknown fields")
	}
}

func TestApplicationProfileValidation(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "doubao",
		Match:   ApplicationMatch{Package: "com.larus.nova"},
		Capture: ApplicationCapture{
			Strategies:   []string{StrategyRawPackets, StrategyTLSPlaintext, StrategyRawPackets},
			Interfaces:   []string{"WLAN0", "wlan0"},
			UnknownFlows: UnknownFlowMark,
		},
		TLS: ApplicationTLS{
			LibraryGlob: "/data/app/*/com.larus.nova-*/lib/arm64/libttboringssl.so",
			Hooks: map[string]HookProfile{
				HookSSLRead: {Symbol: "SSL_read"},
			},
		},
		Offsets: map[string]OffsetValue{
			OffsetSSLRBIO: 0x18,
		},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(profile.Capture.Strategies) != 2 {
		t.Fatalf("normalized strategies = %v", profile.Capture.Strategies)
	}
	if len(profile.Capture.Interfaces) != 1 || profile.Capture.Interfaces[0] != "WLAN0" {
		t.Fatalf("normalized interfaces = %v", profile.Capture.Interfaces)
	}
}

func TestApplicationProfileRejectsUnsupportedOffset(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "bad-offset",
		Match:   ApplicationMatch{UID: 10001},
		Offsets: map[string]OffsetValue{"made_up": 1},
	}
	if err := profile.Validate(); err == nil {
		t.Fatal("Validate() should reject an unsupported structure offset")
	}
}

func TestApplicationDataHookProvenanceValidation(t *testing.T) {
	base := ApplicationDataHook{
		Name:         "stream-send",
		Library:      "/tmp/libtransport.so",
		Symbol:       "stream_send",
		Direction:    AppDataDirectionWrite,
		BufferArg:    2,
		LengthSource: AppDataLengthArgument,
		LengthArg:    3,
	}
	validate := func(hook ApplicationDataHook) error {
		profile := &ApplicationProfile{
			Version:   ApplicationProfileVersion,
			Name:      "provenance",
			Match:     ApplicationMatch{PID: 1},
			DataHooks: []ApplicationDataHook{hook},
		}
		return profile.Validate()
	}

	legacy := base
	if err := validate(legacy); err != nil {
		t.Fatalf("legacy hook validation error = %v", err)
	}
	profile := &ApplicationProfile{
		Version:   ApplicationProfileVersion,
		Name:      "legacy-provenance",
		Match:     ApplicationMatch{PID: 1},
		DataHooks: []ApplicationDataHook{legacy},
	}
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	if profile.DataHooks[0].CaptureLayer != CaptureLayerSemantic {
		t.Fatalf("legacy hook provenance = %#v", profile.DataHooks[0])
	}

	transport := base
	transport.CaptureLayer = CaptureLayerTransport
	transport.Transport = CaptureTransportQUIC
	if err := validate(transport); err != nil {
		t.Fatalf("QUIC transport hook validation error = %v", err)
	}

	transport.Transport = CaptureTransportSocket
	if err := validate(transport); err == nil {
		t.Fatal("transport plaintext hook should reject transport=socket")
	}

	semantic := base
	semantic.CaptureLayer = CaptureLayerSemantic
	semantic.Transport = CaptureTransportTLS
	if err := validate(semantic); err == nil {
		t.Fatal("semantic hook should reject transport provenance")
	}

	wire := base
	wire.CaptureLayer = CaptureLayerWire
	wire.Transport = CaptureTransportTLS
	wire.BoundaryRole = CaptureBoundaryTLSCiphertext
	wire.ContextArg = 1
	if err := validate(wire); err != nil {
		t.Fatalf("wire boundary hook validation error = %v", err)
	}
	wire.ContextArg = 0
	if err := validate(wire); err == nil {
		t.Fatal("wire boundary hook should require context_arg")
	}
	wire.ContextArg = 1
	wire.BoundaryRole = "unknown"
	if err := validate(wire); err == nil {
		t.Fatal("wire boundary hook should reject unknown role")
	}
}

func TestApplicationProfileValidatesJNIDiscovery(t *testing.T) {
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "jni-discovery",
		Match:   ApplicationMatch{Package: "com.example.app"},
		Capture: ApplicationCapture{
			Strategies: []string{StrategyJNIDiscovery},
		},
		JNI: &JNIDiscoveryProfile{
			Library:                "/apex/com.android.art/lib64/libart.so",
			BuildID:                "AA:BB:CC:DD",
			RegisterNativesOffsets: []OffsetValue{0x1234, 0x1234, 0x5678},
			ConversionOffsets: map[string][]OffsetValue{
				" GET_STRING_UTF_CHARS ":    {0x6000, 0x6000, 0x7000},
				JNIConversionGetArrayLength: {0x8000},
			},
			CallerAllowlist: []JNIConversionCaller{
				{
					Module:  "libworker.so",
					BuildID: "11:22:33:44",
					Role:    " GET_STRING_UTF_CHARS ",
					Offset:  0x9124,
				},
				{
					Module:  "libworker.so",
					BuildID: "11223344",
					Role:    JNIConversionGetStringUTFChars,
					Offset:  0x9124,
				},
			},
		},
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if profile.JNI.BuildID != "aabbccdd" ||
		len(profile.JNI.RegisterNativesOffsets) != 2 ||
		len(profile.JNI.ConversionOffsets[JNIConversionGetStringUTFChars]) != 2 ||
		len(profile.JNI.CallerAllowlist) != 1 ||
		profile.JNI.CallerAllowlist[0].BuildID != "11223344" ||
		profile.JNI.CallerAllowlist[0].Role != JNIConversionGetStringUTFChars {
		t.Fatalf("normalized JNI configuration = %#v", profile.JNI)
	}

	missingStrategy := *profile
	missingStrategy.Capture.Strategies = nil
	if err := missingStrategy.Validate(); err == nil {
		t.Fatal("Validate() should require the jni_discovery strategy")
	}

	missingConfig := *profile
	missingConfig.JNI = nil
	missingConfig.Capture.Strategies = []string{StrategyJNIDiscovery}
	if err := missingConfig.Validate(); err == nil {
		t.Fatal("Validate() should require jni_discovery configuration")
	}

	ambiguous := *profile
	jni := *profile.JNI
	jni.ConversionOffsets = map[string][]OffsetValue{
		JNIConversionGetStringUTFChars: {0x9000},
		JNIConversionGetArrayLength:    {0x9000},
	}
	ambiguous.JNI = &jni
	if err := ambiguous.Validate(); err == nil {
		t.Fatal("Validate() should reject an offset shared by incompatible JNI ABIs")
	}

	badCaller := *profile
	badJNI := *profile.JNI
	badJNI.CallerAllowlist = []JNIConversionCaller{{
		Module:     "libworker.so",
		ModuleGlob: "/data/app/*/libworker.so",
		Role:       JNIConversionGetStringUTFChars,
		Offset:     0x9124,
	}}
	badCaller.JNI = &badJNI
	if err := badCaller.Validate(); err == nil {
		t.Fatal("Validate() should reject an ambiguous caller module selector")
	}
}

func TestResolveLibraryGlob(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "liba.so")
	second := filepath.Join(dir, "libb.so")
	if err := os.WriteFile(first, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveLibraryGlob(filepath.Join(dir, "lib*.so"))
	if err != nil {
		t.Fatalf("resolveLibraryGlob() error = %v", err)
	}
	if got != second {
		t.Fatalf("resolveLibraryGlob() = %q, want %q", got, second)
	}
}

func TestApplicationProfileConfigOverrides(t *testing.T) {
	cfg := NewConfig()
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "app-a",
		Match:   ApplicationMatch{UID: 10001},
		Capture: ApplicationCapture{
			Strategies:        []string{StrategyRawPackets, StrategyTLSPlaintext},
			Interfaces:        []string{"wlan0", "tun0"},
			StrictAttribution: true,
			UnknownFlows:      UnknownFlowDrop,
		},
		TLS: ApplicationTLS{
			Library:               "/data/app/app-a/libssl.so",
			AdditionalLibraries:   []string{"/apex/conscrypt/libssl.so"},
			AdditionalLibGlobs:    []string{"/data/app/app-a/libssl-*.so"},
			AutoDiscoverLibraries: true,
			Hooks: map[string]HookProfile{
				HookSSLRead: {Offset: 0x1234},
			},
		},
		Offsets: map[string]OffsetValue{OffsetSSLRBIO: 0x18},
	}
	if err := cfg.ApplyApplicationProfile(profile); err != nil {
		t.Fatalf("ApplyApplicationProfile() error = %v", err)
	}
	if cfg.CaptureMode != "all" {
		t.Fatalf("CaptureMode = %q, want all", cfg.CaptureMode)
	}
	if cfg.Uid != 10001 || cfg.UnknownFlowPolicyValue() != 2 {
		t.Fatalf("profile attribution values not applied: uid=%d policy=%d", cfg.Uid, cfg.UnknownFlowPolicyValue())
	}
	if got := cfg.StructOffsets[OffsetSSLRBIO]; got != 0x18 {
		t.Fatalf("rbio offset = %#x", got)
	}
	if !cfg.AutoDiscoverTLSLibs ||
		len(cfg.OpensslExtraPaths) != 1 ||
		cfg.OpensslExtraPaths[0] != "/apex/conscrypt/libssl.so" ||
		len(cfg.OpensslExtraPatterns) != 1 {
		t.Fatalf("additional TLS providers not applied: %#v", cfg)
	}
	if hook, ok := cfg.HookOverride(HookSSLRead); !ok || uint64(hook.Offset) != 0x1234 {
		t.Fatalf("SSL_read hook = %#v, found=%v", hook, ok)
	}
	if err := cfg.ApplyStructOffsetAssignment("ssl_st_wbio=0x28"); err != nil {
		t.Fatalf("ApplyStructOffsetAssignment() error = %v", err)
	}
	if err := cfg.ApplyHookAssignment("ssl_write=CustomSSLWrite"); err != nil {
		t.Fatalf("ApplyHookAssignment() error = %v", err)
	}
	if hook, ok := cfg.HookOverride(HookSSLWrite); !ok || hook.Symbol != "CustomSSLWrite" {
		t.Fatalf("SSL_write hook = %#v, found=%v", hook, ok)
	}
}

func TestApplicationProfileRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trailing.json")
	if err := os.WriteFile(path, []byte(
		`{"version":1,"name":"one","match":{"uid":10001}} {"version":1}`,
	), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadApplicationProfile(path); err == nil {
		t.Fatal("LoadApplicationProfile() should reject trailing JSON")
	}
}

func TestDoubaoExampleProfileIsValid(t *testing.T) {
	mainPath := filepath.Join(
		"..", "..", "..", "examples", "profiles",
		"doubao-13.9.0-android16.json",
	)
	mainProfile, err := LoadApplicationProfile(mainPath)
	if err != nil {
		t.Fatalf("LoadApplicationProfile(%q) error = %v", mainPath, err)
	}
	if len(mainProfile.DataHooks) != 5 {
		t.Fatalf("unexpected communication wire hooks: %#v", mainProfile.DataHooks)
	}
	if !mainProfile.TLS.AutoDiscoverLibraries {
		t.Fatal("communication profile does not auto-discover TLS providers")
	}
	seenBoundaryData := false
	for _, strategy := range mainProfile.Capture.Strategies {
		if strategy == StrategyBoundaryData {
			seenBoundaryData = true
		}
		if strategy == StrategyAppData || strategy == StrategyCronet {
			t.Fatalf("communication-only profile enables semantic/legacy strategy %q",
				strategy)
		}
		if strategy == StrategyJNIDiscovery {
			t.Fatalf("communication-only profile enables diagnostic strategy %q", strategy)
		}
	}
	if !seenBoundaryData {
		t.Fatal("communication-only profile does not enable wire boundary hooks")
	}
	for index, hook := range mainProfile.DataHooks {
		if index < 2 {
			if hook.CaptureLayer != CaptureLayerWire ||
				hook.Transport != CaptureTransportTLS ||
				hook.BoundaryRole != CaptureBoundaryTLSCiphertext {
				t.Fatalf("communication profile contains invalid TLS wire hook: %#v", hook)
			}
			continue
		}
		if hook.CaptureLayer != CaptureLayerTransport ||
			hook.Transport != CaptureTransportQUIC {
			t.Fatalf("communication profile contains invalid QUIC hook: %#v", hook)
		}
	}
	if mainProfile.DataHooks[1].LengthSource != AppDataLengthReturn ||
		mainProfile.DataHooks[1].LengthSize != 4 {
		t.Fatalf("custom BIO read return ABI was not pinned: %#v",
			mainProfile.DataHooks[1])
	}

	diagnosticPath := filepath.Join(
		"..", "..", "..", "examples", "profiles",
		"doubao-13.9.0-android16-cronet-http-diagnostic.json",
	)
	diagnosticProfile, err := LoadApplicationProfile(diagnosticPath)
	if err != nil {
		t.Fatalf("LoadApplicationProfile(%q) error = %v", diagnosticPath, err)
	}
	assertDoubaoSemanticHooks(t, diagnosticProfile.DataHooks)
}

func TestDoubaoQUICStreamValidationProfilePreservesReassemblyMetadata(t *testing.T) {
	path := filepath.Join(
		"..", "..", "..", "examples", "profiles",
		"doubao-13.9.0-android16-quic-stream-validation.json",
	)
	profile, err := LoadApplicationProfile(path)
	if err != nil {
		t.Fatalf("LoadApplicationProfile(%q) error = %v", path, err)
	}
	if len(profile.DataHooks) != 3 {
		t.Fatalf("unexpected QUIC validation hooks: %#v", profile.DataHooks)
	}
	for _, hook := range profile.DataHooks {
		if hook.CaptureLayer != CaptureLayerTransport ||
			hook.Transport != CaptureTransportQUIC ||
			hook.ContextArg != 1 ||
			hook.ContextOffset != 0x1e0 ||
			hook.ContextSize != 8 ||
			hook.StreamArg != 1 ||
			hook.StreamOffset != 0x1d8 ||
			hook.StreamSize != 4 ||
			hook.FinArg == 0 {
			t.Fatalf("QUIC hook is missing connection/stream metadata: %#v", hook)
		}
	}
	receive := profile.DataHooks[2]
	if receive.StreamByteOffsetArg != 2 ||
		receive.StreamByteOffsetOffset != 0x10 ||
		receive.StreamByteOffsetSize != 8 ||
		receive.FinArg != 2 ||
		receive.FinOffset != 1 ||
		receive.FinSize != 1 {
		t.Fatalf("QUIC receive frame layout was not pinned: %#v", receive)
	}
}

func assertDoubaoSemanticHooks(t *testing.T, hooks []ApplicationDataHook) {
	t.Helper()
	if len(hooks) != 7 {
		t.Fatalf("unexpected Doubao data hooks: %#v", hooks)
	}
	for index, hook := range hooks {
		if hook.BuildID != "771865e3ad213419d75869809dc6e2d2d7ef8977" {
			t.Fatalf("unexpected Doubao data hook: %#v", hook)
		}
		if hook.CaptureLayer != CaptureLayerSemantic || hook.Transport != "" {
			t.Fatalf("Doubao semantic hook has transport provenance: %#v", hook)
		}
		if index < 4 && hook.BufferFormat != AppDataBufferLibCXX {
			t.Fatalf("unexpected Doubao semantic string hook: %#v", hook)
		}
	}
	if hooks[4].StateAction != AppDataStateSave ||
		hooks[5].StateAction != AppDataStateLoad ||
		hooks[4].stateID != hooks[5].stateID {
		t.Fatalf("unexpected Doubao upload hooks: %#v", hooks[4:])
	}
	response := hooks[6]
	if response.Direction != AppDataDirectionRead || !response.BufferIndirect ||
		response.BufferOffset != 0x10 || response.LengthArg != 3 {
		t.Fatalf("unexpected Doubao response hook: %#v", response)
	}
}
