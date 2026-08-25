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
	"slices"
	"testing"

	manager "github.com/gojue/ebpfmanager"

	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

func TestCaptureModesDoNotImplicitlyExtractTLSKeys(t *testing.T) {
	for _, mode := range []string{
		handlers.ModePcap,
		handlers.ModePcapng,
		handlers.ModeAll,
		handlers.ModeHybrid,
	} {
		strategies := strategiesForCaptureMode(mode)
		if slices.Contains(strategies, StrategyTLSKeys) {
			t.Fatalf("mode %q implicitly enabled %q: %v",
				mode, StrategyTLSKeys, strategies)
		}
	}
}

func TestKeylogModeExplicitlyExtractsTLSKeys(t *testing.T) {
	for _, mode := range []string{handlers.ModeKey, handlers.ModeKeylog} {
		strategies := strategiesForCaptureMode(mode)
		if !slices.Equal(strategies, []string{StrategyTLSKeys}) {
			t.Fatalf("mode %q strategies = %v, want only %q",
				mode, strategies, StrategyTLSKeys)
		}
	}
}

func TestAllInterfacesEnablesRuntimeWatch(t *testing.T) {
	config := NewConfig()
	config.Ifnames = []string{"all"}
	config.normalizeInterfaces()
	if !config.WatchInterfaces {
		t.Fatal(`interfaces "all" did not preserve runtime watch intent`)
	}
	if len(config.Interfaces()) == 0 {
		t.Fatal(`interfaces "all" did not include the current interface snapshot`)
	}
	config.normalizeInterfaces()
	if !config.WatchInterfaces {
		t.Fatal("second normalization lost runtime watch intent")
	}
}

func TestProfileCanDisableStructuredPacketDuplication(t *testing.T) {
	disabled := false
	profile := &ApplicationProfile{
		Version: ApplicationProfileVersion,
		Name:    "wire-only",
		Match:   ApplicationMatch{UID: 12345},
		Capture: ApplicationCapture{
			Strategies:       []string{StrategyRawPackets},
			EmitPacketEvents: &disabled,
			PerfBufferPages:  256,
		},
	}
	config := NewConfig()
	if err := config.ApplyApplicationProfile(profile); err != nil {
		t.Fatalf("ApplyApplicationProfile: %v", err)
	}
	if config.GetEmitPacketEvents() {
		t.Fatal("wire-only profile retained structured packet duplication")
	}
	if got, want := config.GetPerCpuMapSize(), 256*os.Getpagesize(); got != want {
		t.Fatalf("perf buffer size = %d, want %d", got, want)
	}
}

func TestProfileRejectsUnsafePerfBufferPageCount(t *testing.T) {
	for _, pages := range []uint{1, 16385} {
		profile := &ApplicationProfile{
			Version: ApplicationProfileVersion,
			Name:    "invalid-buffer",
			Match:   ApplicationMatch{UID: 12345},
			Capture: ApplicationCapture{
				Strategies:      []string{StrategyRawPackets},
				PerfBufferPages: pages,
			},
		}
		if err := profile.Validate(); err == nil {
			t.Fatalf("Validate accepted perf_buffer_pages=%d", pages)
		}
	}
}

func TestBoundaryDataStrategyExcludesSemanticHooks(t *testing.T) {
	config := NewConfig()
	config.CaptureStrategies = []string{StrategyBoundaryData}
	config.ApplicationDataHooks = []ApplicationDataHook{
		{Name: "wire", CaptureLayer: CaptureLayerWire},
		{Name: "transport", CaptureLayer: CaptureLayerTransport},
		{Name: "semantic", CaptureLayer: CaptureLayerSemantic},
	}
	hooks := config.EnabledCaptureDataHooks()
	if len(hooks) != 2 || hooks[0].Name != "wire" ||
		hooks[1].Name != "transport" {
		t.Fatalf("boundary strategy selected %#v", hooks)
	}
}

func TestExplicitBoundaryAndSemanticStrategiesStaySeparated(t *testing.T) {
	config := NewConfig()
	config.CaptureStrategies = []string{
		StrategyBoundaryData,
		StrategyAppData,
	}
	config.ApplicationDataHooks = []ApplicationDataHook{
		{Name: "wire", CaptureLayer: CaptureLayerWire},
		{Name: "semantic", CaptureLayer: CaptureLayerSemantic},
	}
	hooks := config.EnabledCaptureDataHooks()
	if len(hooks) != 2 || hooks[0].Name != "wire" ||
		hooks[1].Name != "semantic" {
		t.Fatalf("combined strategies selected %#v", hooks)
	}
}

func TestLegacyApplicationDataStrategyRemainsCompatible(t *testing.T) {
	config := NewConfig()
	config.CaptureStrategies = []string{StrategyAppData}
	config.ApplicationDataHooks = []ApplicationDataHook{
		{Name: "old-boundary", CaptureLayer: CaptureLayerTransport},
		{Name: "old-semantic", CaptureLayer: CaptureLayerSemantic},
	}
	hooks := config.EnabledCaptureDataHooks()
	if len(hooks) != 2 {
		t.Fatalf("legacy strategy selected %#v", hooks)
	}
}

func TestRawPacketProgramsExcludeUnusedSemanticFamilies(t *testing.T) {
	probes := []*manager.Probe{
		{EbpfFuncName: "ingress_cls_func"},
		{EbpfFuncName: "egress_cls_func"},
		{EbpfFuncName: "tcp_sendmsg"},
		{EbpfFuncName: "udp_sendmsg"},
	}
	excluded := excludedUnconfiguredEBPFFunctions(probes)
	for _, function := range []string{
		"probe_ret_app_data_4",
		"probe_jni_register_natives_0",
		"probe_entry_SSL_read",
	} {
		if !slices.Contains(excluded, function) {
			t.Fatalf("unused function %q was not excluded", function)
		}
	}
	for _, function := range []string{
		"ingress_cls_func",
		"egress_cls_func",
		"tcp_sendmsg",
		"udp_sendmsg",
	} {
		if slices.Contains(excluded, function) {
			t.Fatalf("raw packet function %q was excluded", function)
		}
	}
}

func TestPacketAttributionProbesCanBeDisabledWhenKallsymsIsHidden(t *testing.T) {
	if got := packetAttributionProbes(false); len(got) != 0 {
		t.Fatalf("disabled packet attribution probes = %#v, want none", got)
	}
	got := packetAttributionProbes(true)
	if len(got) != 2 || got[0].EbpfFuncName != "tcp_sendmsg" ||
		got[1].EbpfFuncName != "udp_sendmsg" {
		t.Fatalf("enabled packet attribution probes = %#v", got)
	}
}

func TestKallsymsFreeProbeSetKeepsOnlyUserAndTCProbes(t *testing.T) {
	got := probesWithoutKernelSymbols([]*manager.Probe{
		{EbpfFuncName: "kernel-only"},
		{EbpfFuncName: "user", BinaryPath: "/data/app/libssl.so"},
		{EbpfFuncName: "tc", Ifname: "wlan0"},
	})
	if len(got) != 2 || got[0].EbpfFuncName != "user" || got[1].EbpfFuncName != "tc" {
		t.Fatalf("kallsyms-free probes = %#v", got)
	}
}

func TestConfiguredSemanticProgramRemainsLoadable(t *testing.T) {
	excluded := excludedUnconfiguredEBPFFunctions([]*manager.Probe{
		{EbpfFuncName: "probe_ret_app_data_4"},
	})
	if slices.Contains(excluded, "probe_ret_app_data_4") {
		t.Fatal("configured semantic function was excluded")
	}
}
