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
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gojue/ecapture/internal/reconstruction"
	"github.com/spf13/cobra"
)

var (
	streamReconstructInput  string
	streamReconstructOutput string
)

var streamCmd = &cobra.Command{
	Use:   "stream",
	Short: "Reconstruct and decode structured plaintext streams.",
}

var streamReconstructCmd = &cobra.Command{
	Use:         "reconstruct",
	Short:       "Reassemble JSON plaintext chunks into normalized calls.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes JSON events produced by --event-format=json. TLS and generic
application-data chunks are reassembled by call identity and chunk offset.
Every output line is JSON. Incomplete calls retain exact missing ranges, while
opaque custom binary payloads remain lossless base64.`,
	Example: `ecapture stream reconstruct \
  --input capture-events.jsonl \
  --output reconstructed-calls.jsonl`,
	Args: cobra.NoArgs,
	RunE: runStreamReconstruct,
}

func init() {
	streamReconstructCmd.Flags().StringVar(
		&streamReconstructInput,
		"input",
		"-",
		"structured capture event file; use - for stdin.",
	)
	streamReconstructCmd.Flags().StringVar(
		&streamReconstructOutput,
		"output",
		"",
		"write reconstructed JSONL calls; stdout when empty.",
	)
	streamCmd.AddCommand(streamReconstructCmd)
	rootCmd.AddCommand(streamCmd)
}

func runStreamReconstruct(command *cobra.Command, _ []string) error {
	var input io.Reader = command.InOrStdin()
	var inputFile *os.File
	if streamReconstructInput != "" && streamReconstructInput != "-" {
		if streamReconstructOutput != "" {
			inputPath, inputErr := filepath.Abs(streamReconstructInput)
			outputPath, outputErr := filepath.Abs(streamReconstructOutput)
			if inputErr != nil {
				return fmt.Errorf("resolve reconstruction input: %w", inputErr)
			}
			if outputErr != nil {
				return fmt.Errorf("resolve reconstruction output: %w", outputErr)
			}
			if filepath.Clean(inputPath) == filepath.Clean(outputPath) {
				return fmt.Errorf("--input and --output must name different files")
			}
		}
		var err error
		inputFile, err = os.Open(streamReconstructInput)
		if err != nil {
			return fmt.Errorf("open reconstruction input: %w", err)
		}
		defer inputFile.Close()
		input = inputFile
	}

	var output io.Writer = command.OutOrStdout()
	var outputFile *os.File
	if streamReconstructOutput != "" {
		var err error
		outputFile, err = os.OpenFile(
			streamReconstructOutput,
			os.O_CREATE|os.O_TRUNC|os.O_WRONLY,
			0o600,
		)
		if err != nil {
			return fmt.Errorf("open reconstruction output: %w", err)
		}
		defer outputFile.Close()
		output = outputFile
	}
	summary, err := reconstruction.Reconstruct(input, output)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(
		command.ErrOrStderr(),
		"reconstructed %d complete and %d incomplete calls from %d chunks (%d ignored events)\n",
		summary.CallsComplete,
		summary.CallsIncomplete,
		summary.ChunksAccepted,
		summary.EventsIgnored,
	)
	return nil
}
