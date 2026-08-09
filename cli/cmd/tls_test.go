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
	"testing"

	"github.com/spf13/cobra"

	opensslProbe "github.com/gojue/ecapture/internal/probe/openssl"
)

func newInterfaceOverrideCommand(t *testing.T, arguments ...string) *cobra.Command {
	t.Helper()
	command := &cobra.Command{}
	command.Flags().String("ifname", "", "")
	command.Flags().StringSlice("interfaces", nil, "")
	if err := command.ParseFlags(arguments); err != nil {
		t.Fatalf("ParseFlags() error = %v", err)
	}
	return command
}

func TestOpenSSLInterfacesFlagReplacesProfileInterfaces(t *testing.T) {
	target := opensslProbe.NewConfig()
	target.Ifname = "profile0"
	target.Ifnames = []string{"profile0", "profile1"}
	command := newInterfaceOverrideCommand(t, "--interfaces", "cli0,cli1")

	applyOpenSSLInterfaceOverrides(
		command,
		target,
		"",
		[]string{"cli0", "cli1"},
	)
	if target.Ifname != "" {
		t.Fatalf("Ifname = %q, want empty profile compatibility value", target.Ifname)
	}
	if got, want := target.Ifnames, []string{"cli0", "cli1"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Ifnames = %#v, want %#v", got, want)
	}
}

func TestOpenSSLIfnameFlagReplacesProfileInterfaces(t *testing.T) {
	target := opensslProbe.NewConfig()
	target.Ifname = "profile0"
	target.Ifnames = []string{"profile0", "profile1"}
	command := newInterfaceOverrideCommand(t, "--ifname", "cli0")

	applyOpenSSLInterfaceOverrides(command, target, "cli0", nil)
	if target.Ifname != "cli0" {
		t.Fatalf("Ifname = %q, want cli0", target.Ifname)
	}
	if target.Ifnames != nil {
		t.Fatalf("Ifnames = %#v, want nil", target.Ifnames)
	}
}

func TestOpenSSLExplicitInterfaceFlagsCombineOnlyCLIValues(t *testing.T) {
	target := opensslProbe.NewConfig()
	target.Ifname = "profile0"
	target.Ifnames = []string{"profile0", "profile1"}
	command := newInterfaceOverrideCommand(
		t,
		"--interfaces", "cli0,cli1",
		"--ifname", "cli2",
	)

	applyOpenSSLInterfaceOverrides(
		command,
		target,
		"cli2",
		[]string{"cli0", "cli1"},
	)
	if target.Ifname != "cli2" {
		t.Fatalf("Ifname = %q, want cli2", target.Ifname)
	}
	if got, want := target.Ifnames, []string{"cli0", "cli1"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Ifnames = %#v, want %#v", got, want)
	}
}
