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
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestOpenStreamCommandIOHardensExistingOutput(t *testing.T) {
	output, err := os.CreateTemp(t.TempDir(), "existing-output-*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	outputPath := output.Name()
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outputPath, 0o644); err != nil {
		t.Fatal(err)
	}

	command := &cobra.Command{}
	command.SetIn(strings.NewReader("capture"))
	_, _, closeFiles, err := openStreamCommandIO(
		command,
		"-",
		outputPath,
		"test",
	)
	if err != nil {
		t.Fatalf("openStreamCommandIO() error = %v", err)
	}
	closeFiles()
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("existing sensitive output mode = %04o, want 0600", got)
	}
}
