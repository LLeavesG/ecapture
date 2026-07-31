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
	"strings"

	"github.com/gojue/ecapture/internal/probe/openssl"
	"github.com/gojue/ecapture/internal/profileinspector"
	"github.com/spf13/cobra"
)

var (
	profileInspectLibraries           []string
	profileInspectOutput              string
	profileScaffoldOutput             string
	profileScaffoldName               string
	profileScaffoldPackage            string
	profileScaffoldMaxHooks           int
	profileScaffoldCollectUserStacks  bool
	profileIncludeSemanticDiagnostics bool
	profileRecipeCatalog              string
	profileLearnJNIInput              string
	profileLearnJNIOutput             string
	profileLearnJNIMinScore           int
	profileLearnJNIMax                int
	profileLearnJNIProfile            string
	profileLearnJNIProfileOutput      string
	profileLearnJNIConversionMinScore int
	profileLearnJNIConversionMax      int
	profileLearnJNIConversionModules  []string
	profileLearnJNIMarkers            []string
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Inspect process libraries and build version-pinned capture profiles.",
}

var profileInspectCmd = &cobra.Command{
	Use:         "inspect",
	Short:       "Inventory ELF libraries and rank reusable communication-boundary candidates.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Inspects executable ELF mappings from --pid and any explicit --library values.
The JSON report distinguishes reusable public-ABI hooks from hints that still
need static or controlled-traffic runtime validation. With --scaffold, it emits
a communication-only profile containing raw packet capture and at most
--max-hooks boundary candidates. Semantic/JNI diagnostics are excluded unless
--include-semantic-diagnostics is explicitly set.`,
	Example: `ecapture profile inspect --pid 3423 --output report.json
ecapture profile inspect --pid 3423 --scaffold app-discovery.json
ecapture profile inspect --library /data/local/tmp/libcronet.so
ecapture profile inspect --library libprivate.so --recipe-catalog private-abi.json`,
	Args: cobra.NoArgs,
	RunE: runProfileInspect,
}

var profileLearnJNICmd = &cobra.Command{
	Use:         "learn-jni",
	Short:       "Rank dynamic JNI methods as optional semantic diagnostics.",
	Annotations: map[string]string{skipEnvDetection: "true"},
	Long: `Consumes RegisterNatives and managed-reference conversion events emitted by a jni_discovery profile.
Both --event-format=json output and historical plain event logs are accepted.
The report ranks methods by payload-bearing JNI signatures and semantic names,
and ranks ASLR-stable native conversion callsites carrying text or arbitrary
binary payloads. With --profile and --profile-output, the selected conversion
callsites are written into a new profile for exact kernel-side filtering.`,
	Example: `ecapture tls --profile app-discovery.json \
  --event-format=json --eventaddr=/data/local/tmp/jni-events.jsonl
ecapture profile learn-jni \
  --input /data/local/tmp/jni-events.jsonl \
  --output /data/local/tmp/jni-candidates.json \
  --marker EBPFDISCOVERY-7f91 \
  --conversion-module 'lib*cronet*.so' \
  --profile app-discovery.json \
  --profile-output app-filtered.json`,
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
		"write a communication profile assembled from known boundary ABIs.",
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
		"maximum number of ranked communication-boundary hooks in the generated profile.",
	)
	profileInspectCmd.Flags().BoolVar(
		&profileScaffoldCollectUserStacks,
		"collect-user-stacks",
		false,
		"capture bounded user call chains for scaffold hooks (discovery only; disabled by default).",
	)
	profileInspectCmd.Flags().BoolVar(
		&profileIncludeSemanticDiagnostics,
		"include-semantic-diagnostics",
		false,
		"include optional semantic/JNI reverse-engineering diagnostics in the scaffold.",
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
		"RegisterNatives/JNI conversion event log; use - for stdin.",
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
	profileLearnJNICmd.Flags().IntVar(
		&profileLearnJNIConversionMinScore,
		"min-conversion-score",
		70,
		"exclude JNI conversion callsites below this score.",
	)
	profileLearnJNICmd.Flags().IntVar(
		&profileLearnJNIConversionMax,
		"max-conversion-callers",
		64,
		"maximum conversion callsites in the report/profile; 0 keeps every callsite.",
	)
	profileLearnJNICmd.Flags().StringSliceVar(
		&profileLearnJNIConversionModules,
		"conversion-module",
		nil,
		"keep conversion callers from matching module basenames or paths (repeatable; shell globs accepted).",
	)
	profileLearnJNICmd.Flags().StringSliceVar(
		&profileLearnJNIMarkers,
		"marker",
		nil,
		"keep conversion callers whose payload contains an injected marker (repeatable).",
	)
	profileLearnJNICmd.Flags().StringVar(
		&profileLearnJNIProfile,
		"profile",
		"",
		"diagnostic application profile to refine with learned conversion callers.",
	)
	profileLearnJNICmd.Flags().StringVar(
		&profileLearnJNIProfileOutput,
		"profile-output",
		"",
		"write a new profile with the learned kernel caller allowlist.",
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
		Name:                       profileScaffoldName,
		Package:                    profileScaffoldPackage,
		UID:                        globalConf.Uid,
		PID:                        globalConf.Pid,
		MaxHooks:                   profileScaffoldMaxHooks,
		CollectUserStacks:          profileScaffoldCollectUserStacks,
		IncludeSemanticDiagnostics: profileIncludeSemanticDiagnostics,
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
	if profileLearnJNIConversionMinScore < 0 {
		return fmt.Errorf("--min-conversion-score must be non-negative")
	}
	if profileLearnJNIConversionMax < 0 {
		return fmt.Errorf("--max-conversion-callers must be non-negative")
	}
	if (profileLearnJNIProfile == "") != (profileLearnJNIProfileOutput == "") {
		return fmt.Errorf("--profile and --profile-output must be used together")
	}
	if err := validateProfileLearningPaths(); err != nil {
		return err
	}
	var input io.Reader = command.InOrStdin()
	var inputFile *os.File
	if profileLearnJNIInput != "" && profileLearnJNIInput != "-" {
		var err error
		inputFile, err = os.Open(profileLearnJNIInput)
		if err != nil {
			return fmt.Errorf("open JNI learning input: %w", err)
		}
		defer inputFile.Close()
		input = inputFile
	}
	markers := make([][]byte, 0, len(profileLearnJNIMarkers))
	for _, marker := range profileLearnJNIMarkers {
		if marker = strings.TrimSpace(marker); marker == "" {
			return fmt.Errorf("--marker contains an empty value")
		}
		markers = append(markers, []byte(marker))
	}
	report, err := profileinspector.LearnJNIWithOptions(
		input,
		profileinspector.JNILearningOptions{Markers: markers},
	)
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
	conversions := report.ConversionCandidates[:0]
	for _, candidate := range report.ConversionCandidates {
		if candidate.Score < profileLearnJNIConversionMinScore {
			continue
		}
		if len(markers) != 0 && candidate.MarkerHits == 0 {
			continue
		}
		matched, err := matchesJNIConversionModule(
			candidate.ModulePath,
			candidate.ProfileRule.Module,
			profileLearnJNIConversionModules,
		)
		if err != nil {
			return err
		}
		if !matched {
			continue
		}
		conversions = append(conversions, candidate)
		if profileLearnJNIConversionMax != 0 &&
			len(conversions) == profileLearnJNIConversionMax {
			break
		}
	}
	report.ConversionCandidates = conversions
	for index := range report.ConversionCandidates {
		report.ConversionCandidates[index].Rank = index + 1
	}
	var refined *openssl.ApplicationProfile
	if profileLearnJNIProfile != "" {
		refined, err = openssl.LoadApplicationProfile(profileLearnJNIProfile)
		if err != nil {
			return err
		}
		if err := profileinspector.PromoteJNIConversionCallers(
			refined,
			report.ConversionCandidates,
		); err != nil {
			return fmt.Errorf("promote JNI conversion callers: %w", err)
		}
	}
	if err := writeIndentedJSON(command.OutOrStdout(), profileLearnJNIOutput, report); err != nil {
		return fmt.Errorf("write JNI learning report: %w", err)
	}
	if refined != nil {
		if err := writeIndentedJSON(
			io.Discard,
			profileLearnJNIProfileOutput,
			refined,
		); err != nil {
			return fmt.Errorf("write refined application profile: %w", err)
		}
	}
	return nil
}

func matchesJNIConversionModule(
	modulePath string,
	moduleBase string,
	selectors []string,
) (bool, error) {
	if len(selectors) == 0 {
		return true, nil
	}
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			return false, fmt.Errorf("--conversion-module contains an empty selector")
		}
		baseMatched, err := filepath.Match(selector, moduleBase)
		if err != nil {
			return false, fmt.Errorf(
				"invalid --conversion-module pattern %q: %w",
				selector,
				err,
			)
		}
		pathMatched := selector == modulePath
		if !pathMatched {
			pathMatched, err = filepath.Match(selector, modulePath)
			if err != nil {
				return false, fmt.Errorf(
					"invalid --conversion-module pattern %q: %w",
					selector,
					err,
				)
			}
		}
		if baseMatched || pathMatched {
			return true, nil
		}
	}
	return false, nil
}

func validateProfileLearningPaths() error {
	type namedPath struct {
		flag string
		path string
	}
	values := []namedPath{
		{flag: "--input", path: profileLearnJNIInput},
		{flag: "--output", path: profileLearnJNIOutput},
		{flag: "--profile", path: profileLearnJNIProfile},
		{flag: "--profile-output", path: profileLearnJNIProfileOutput},
	}
	resolved := make(map[string]string)
	for _, value := range values {
		if value.path == "" || value.path == "-" {
			continue
		}
		absolute, err := filepath.Abs(value.path)
		if err != nil {
			return fmt.Errorf("resolve %s path: %w", value.flag, err)
		}
		absolute = filepath.Clean(absolute)
		if previous, found := resolved[absolute]; found {
			return fmt.Errorf("%s and %s must name different files", previous, value.flag)
		}
		resolved[absolute] = value.flag
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
