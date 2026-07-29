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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gojue/ecapture/internal/profileinspector"
	"github.com/spf13/cobra"
)

var (
	profileInspectLibraries []string
	profileInspectOutput    string
	profileScaffoldOutput   string
	profileScaffoldName     string
	profileScaffoldPackage  string
	profileScaffoldMaxHooks int
	profileRecipeCatalog    string
	profileLearnJNIInput    string
	profileLearnJNIOutput   string
	profileLearnJNIMinScore int
	profileLearnJNIMax      int
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Inspect process libraries and build version-pinned capture profiles.",
}

var profileInspectCmd = &cobra.Command{
	Use:         "inspect",
	Short:       "Inventory ELF libraries and rank reusable plaintext hook candidates.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Inspects executable ELF mappings from --pid and any explicit --library values.
The JSON report distinguishes reusable public-ABI hooks from hints that still
need static or marker-based runtime validation. With --scaffold, it also emits
a diagnostic application profile containing raw packet capture and at most
--max-hooks direct-buffer candidates.`,
	Example: `ecapture profile inspect --pid 3423 --output report.json
ecapture profile inspect --pid 3423 --scaffold app-discovery.json
ecapture profile inspect --library /data/local/tmp/libcronet.so
ecapture profile inspect --library libprivate.so --recipe-catalog private-abi.json`,
	Args: cobra.NoArgs,
	RunE: runProfileInspect,
}

var profileLearnJNICmd = &cobra.Command{
	Use:         "learn-jni",
	Short:       "Rank dynamic JNI native methods as plaintext-boundary candidates.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes RegisterNatives events emitted by a jni_discovery profile.
Both --event-format=json output and historical plain event logs are accepted.
The report ranks methods by payload-bearing JNI signatures and semantic names,
but never treats managed JNI references as native byte pointers.`,
	Example: `ecapture tls --profile app-discovery.json \
  --event-format=json --eventaddr=/data/local/tmp/jni-events.jsonl
ecapture profile learn-jni \
  --input /data/local/tmp/jni-events.jsonl \
  --output /data/local/tmp/jni-candidates.json`,
	Args: cobra.NoArgs,
	RunE: runProfileLearnJNI,
}

func init() {
	profileInspectCmd.Flags().StringSliceVar(
		&profileInspectLibraries,
		"library",
		nil,
		"ELF library to inspect (repeatable or comma-separated).",
	)
	profileInspectCmd.Flags().StringVar(
		&profileInspectOutput,
		"output",
		"",
		"write the inspection report as JSON; stdout when empty.",
	)
	profileInspectCmd.Flags().StringVar(
		&profileScaffoldOutput,
		"scaffold",
		"",
		"write a diagnostic application profile assembled from known direct-buffer ABIs.",
	)
	profileInspectCmd.Flags().StringVar(
		&profileScaffoldName,
		"name",
		"",
		"name for the generated profile.",
	)
	profileInspectCmd.Flags().StringVar(
		&profileScaffoldPackage,
		"package",
		"",
		"Android package name for the generated profile.",
	)
	profileInspectCmd.Flags().IntVar(
		&profileScaffoldMaxHooks,
		"max-hooks",
		8,
		"maximum number of ranked direct-buffer hooks in the generated profile.",
	)
	profileInspectCmd.Flags().StringVar(
		&profileRecipeCatalog,
		"recipe-catalog",
		"",
		"external Build-ID-constrained symbol/offset ABI recipe catalog.",
	)
	profileLearnJNICmd.Flags().StringVar(
		&profileLearnJNIInput,
		"input",
		"-",
		"RegisterNatives event log; use - for stdin.",
	)
	profileLearnJNICmd.Flags().StringVar(
		&profileLearnJNIOutput,
		"output",
		"",
		"write the ranked candidate report as JSON; stdout when empty.",
	)
	profileLearnJNICmd.Flags().IntVar(
		&profileLearnJNIMinScore,
		"min-score",
		0,
		"exclude candidates below this score.",
	)
	profileLearnJNICmd.Flags().IntVar(
		&profileLearnJNIMax,
		"max-candidates",
		100,
		"maximum number of ranked candidates; 0 keeps every candidate.",
	)
	profileCmd.AddCommand(profileInspectCmd)
	profileCmd.AddCommand(profileLearnJNICmd)
	rootCmd.AddCommand(profileCmd)
}

func runProfileInspect(command *cobra.Command, _ []string) error {
	if profileInspectOutput != "" && profileScaffoldOutput != "" {
		reportPath, reportErr := filepath.Abs(profileInspectOutput)
		scaffoldPath, scaffoldErr := filepath.Abs(profileScaffoldOutput)
		if reportErr != nil {
			return fmt.Errorf("resolve profile inspection output: %w", reportErr)
		}
		if scaffoldErr != nil {
			return fmt.Errorf("resolve profile scaffold output: %w", scaffoldErr)
		}
		if filepath.Clean(reportPath) == filepath.Clean(scaffoldPath) {
			return fmt.Errorf("--output and --scaffold must name different files")
		}
	}
	var catalog *profileinspector.RecipeCatalog
	var err error
	if profileRecipeCatalog != "" {
		catalog, err = profileinspector.LoadRecipeCatalog(profileRecipeCatalog)
		if err != nil {
			return err
		}
	}
	report, err := profileinspector.InspectWithCatalog(
		globalConf.Pid,
		profileInspectLibraries,
		catalog,
	)
	if err != nil {
		return err
	}
	if err := writeIndentedJSON(command.OutOrStdout(), profileInspectOutput, report); err != nil {
		return fmt.Errorf("write profile inspection report: %w", err)
	}
	if profileScaffoldOutput == "" {
		return nil
	}
	profile, err := profileinspector.ScaffoldProfile(report, profileinspector.ScaffoldOptions{
		Name:     profileScaffoldName,
		Package:  profileScaffoldPackage,
		UID:      globalConf.Uid,
		PID:      globalConf.Pid,
		MaxHooks: profileScaffoldMaxHooks,
	})
	if err != nil {
		return err
	}
	if err := writeIndentedJSON(io.Discard, profileScaffoldOutput, profile); err != nil {
		return fmt.Errorf("write generated application profile: %w", err)
	}
	return nil
}

func runProfileLearnJNI(command *cobra.Command, _ []string) error {
	if profileLearnJNIMinScore < 0 {
		return fmt.Errorf("--min-score must be non-negative")
	}
	if profileLearnJNIMax < 0 {
		return fmt.Errorf("--max-candidates must be non-negative")
	}
	var input io.Reader = command.InOrStdin()
	var inputFile *os.File
	if profileLearnJNIInput != "" && profileLearnJNIInput != "-" {
		if profileLearnJNIOutput != "" {
			inputPath, inputErr := filepath.Abs(profileLearnJNIInput)
			outputPath, outputErr := filepath.Abs(profileLearnJNIOutput)
			if inputErr != nil {
				return fmt.Errorf("resolve JNI learning input: %w", inputErr)
			}
			if outputErr != nil {
				return fmt.Errorf("resolve JNI learning output: %w", outputErr)
			}
			if filepath.Clean(inputPath) == filepath.Clean(outputPath) {
				return fmt.Errorf("--input and --output must name different files")
			}
		}
		var err error
		inputFile, err = os.Open(profileLearnJNIInput)
		if err != nil {
			return fmt.Errorf("open JNI learning input: %w", err)
		}
		defer inputFile.Close()
		input = inputFile
	}
	report, err := profileinspector.LearnJNI(input)
	if err != nil {
		return err
	}
	filtered := report.Candidates[:0]
	for _, candidate := range report.Candidates {
		if candidate.Score < profileLearnJNIMinScore {
			continue
		}
		filtered = append(filtered, candidate)
		if profileLearnJNIMax != 0 && len(filtered) == profileLearnJNIMax {
			break
		}
	}
	report.Candidates = filtered
	for index := range report.Candidates {
		report.Candidates[index].Rank = index + 1
	}
	if err := writeIndentedJSON(command.OutOrStdout(), profileLearnJNIOutput, report); err != nil {
		return fmt.Errorf("write JNI learning report: %w", err)
	}
	return nil
}

func writeIndentedJSON(stdout io.Writer, path string, value any) error {
	var writer io.Writer = stdout
	var file *os.File
	if path != "" {
		var err error
		file, err = os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		writer = file
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
