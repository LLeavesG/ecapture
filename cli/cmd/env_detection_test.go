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

package cmd

import (
	"errors"
	"testing"

	"github.com/gojue/ecapture/internal/config"
	"golang.org/x/sys/unix"
)

func capabilityData(capabilities ...int) [2]unix.CapUserData {
	var data [2]unix.CapUserData
	for _, capability := range capabilities {
		data[capability/32].Effective |= uint32(1) << uint(capability%32)
	}
	return data
}

func TestHasEffectiveBpfCapabilities(t *testing.T) {
	tests := []struct {
		name string
		data [2]unix.CapUserData
		want bool
	}{
		{name: "none"},
		{name: "bpf only", data: capabilityData(unix.CAP_BPF)},
		{name: "perfmon only", data: capabilityData(unix.CAP_PERFMON)},
		{name: "bpf and perfmon", data: capabilityData(unix.CAP_BPF, unix.CAP_PERFMON), want: true},
		{name: "sys admin", data: capabilityData(unix.CAP_SYS_ADMIN), want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hasEffectiveBpfCapabilities(test.data); got != test.want {
				t.Fatalf("hasEffectiveBpfCapabilities() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestValidateBpfAccess(t *testing.T) {
	want := errors.New("missing")
	if err := validateBpfAccess(false, func() error { return want }); err != nil {
		t.Fatalf("advisory Android capability check returned %v", err)
	}
	if err := validateBpfAccess(true, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("enforced Linux capability check returned %v, want %v", err, want)
	}
}

func TestResolveBTFMode(t *testing.T) {
	tests := []struct {
		name      string
		mode      uint8
		enabled   bool
		detectErr error
		want      uint8
		called    bool
	}{
		{name: "auto core", mode: config.BTFModeAutoDetect, enabled: true, want: config.BTFModeCore, called: true},
		{name: "auto non-core", mode: config.BTFModeAutoDetect, want: config.BTFModeNonCore, called: true},
		{name: "auto detection error", mode: config.BTFModeAutoDetect, detectErr: errors.New("unavailable"), want: config.BTFModeNonCore, called: true},
		{name: "explicit core", mode: config.BTFModeCore, want: config.BTFModeCore},
		{name: "explicit non-core", mode: config.BTFModeNonCore, want: config.BTFModeNonCore},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			got := resolveBTFMode(test.mode, func() (bool, error) {
				called = true
				return test.enabled, test.detectErr
			})
			if got != test.want {
				t.Fatalf("resolveBTFMode() = %d, want %d", got, test.want)
			}
			if called != test.called {
				t.Fatalf("detector called = %t, want %t", called, test.called)
			}
		})
	}
}
