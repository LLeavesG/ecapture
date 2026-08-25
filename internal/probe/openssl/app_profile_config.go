// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/gojue/ecapture/internal/probe/base/handlers"
)

// LoadAndApplyApplicationProfile loads a profile and applies its values. CLI
// callers may apply explicit flag values afterwards to override the profile.
func (c *Config) LoadAndApplyApplicationProfile(path string) error {
	profile, err := LoadApplicationProfile(path)
	if err != nil {
		return err
	}
	c.ProfilePath = path
	return c.ApplyApplicationProfile(profile)
}

// ApplyApplicationProfile copies a validated application profile into Config.
func (c *Config) ApplyApplicationProfile(profile *ApplicationProfile) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if c.StructOffsets == nil {
		c.StructOffsets = make(map[string]uint64)
	}
	if c.HookOverrides == nil {
		c.HookOverrides = make(map[string]HookProfile)
	}

	c.ProfileName = profile.Name
	c.PackageName = profile.Match.Package
	c.RelatedPackages = append(
		[]string(nil),
		profile.Match.NetworkOwnerPackages...,
	)
	if profile.Match.UID != 0 {
		c.Uid = profile.Match.UID
	}
	if profile.Match.PID != 0 {
		c.Pid = profile.Match.PID
	}

	if profile.Capture.Mode != "" {
		c.CaptureMode = strings.ToLower(strings.TrimSpace(profile.Capture.Mode))
	}
	if len(profile.Capture.Strategies) != 0 {
		c.CaptureStrategies = append([]string(nil), profile.Capture.Strategies...)
		if profile.Capture.Mode == "" {
			c.CaptureMode = captureModeForStrategies(c.CaptureStrategies)
		}
	}
	if len(profile.Capture.Interfaces) != 0 {
		c.Ifnames = append([]string(nil), profile.Capture.Interfaces...)
		c.Ifname = c.Ifnames[0]
	}
	c.StrictAttribution = profile.Capture.StrictAttribution
	if profile.Capture.UnknownFlows != "" {
		c.UnknownFlowPolicy = profile.Capture.UnknownFlows
	} else if c.StrictAttribution {
		c.UnknownFlowPolicy = UnknownFlowDrop
	}
	if profile.Capture.PcapFile != "" {
		c.PcapFile = profile.Capture.PcapFile
	}
	if profile.Capture.KeylogFile != "" {
		c.KeylogFile = profile.Capture.KeylogFile
	}
	if profile.Capture.PcapFilter != "" {
		c.PcapFilter = profile.Capture.PcapFilter
	}
	if profile.Capture.PerfBufferPages != 0 {
		c.SetPerCpuMapSize(int(profile.Capture.PerfBufferPages))
	}
	if profile.Capture.EmitPacketEvents != nil {
		c.EmitPacketEvents = *profile.Capture.EmitPacketEvents
	}
	if profile.Capture.PerfReorder != nil {
		c.PerfReorder = *profile.Capture.PerfReorder
	}
	if profile.Capture.PerfReorderLagMs != 0 {
		c.PerfReorderLagMs = profile.Capture.PerfReorderLagMs
	}

	c.OpensslPath = profile.TLS.Library
	c.OpensslPathPattern = profile.TLS.LibraryGlob
	c.OpensslExtraPaths = append(
		[]string(nil),
		profile.TLS.AdditionalLibraries...,
	)
	c.OpensslExtraPatterns = append(
		[]string(nil),
		profile.TLS.AdditionalLibGlobs...,
	)
	c.AutoDiscoverTLSLibs = profile.TLS.AutoDiscoverLibraries
	c.OpensslBuildID = profile.TLS.BuildID
	if profile.TLS.Version != "" {
		c.SslVersion = profile.TLS.Version
	}
	if profile.TLS.BoringSSL != nil {
		c.IsBoringSSL = *profile.TLS.BoringSSL
	}
	if len(profile.TLS.MasterHookFuncs) != 0 {
		c.MasterHookFuncs = append([]string(nil), profile.TLS.MasterHookFuncs...)
	}
	for role, hook := range profile.TLS.Hooks {
		c.HookOverrides[role] = hook
	}
	c.ApplicationDataHooks = append([]ApplicationDataHook(nil), profile.DataHooks...)
	if profile.JNI != nil {
		jni := *profile.JNI
		jni.RegisterNativesOffsets = append(
			[]OffsetValue(nil),
			profile.JNI.RegisterNativesOffsets...,
		)
		jni.ConversionOffsets = make(
			map[string][]OffsetValue,
			len(profile.JNI.ConversionOffsets),
		)
		for role, offsets := range profile.JNI.ConversionOffsets {
			jni.ConversionOffsets[role] = append([]OffsetValue(nil), offsets...)
		}
		jni.CallerAllowlist = append(
			[]JNIConversionCaller(nil),
			profile.JNI.CallerAllowlist...,
		)
		c.JNIDiscovery = &jni
	} else {
		c.JNIDiscovery = nil
	}
	for name, value := range profile.Offsets {
		c.StructOffsets[name] = uint64(value)
	}

	c.applicationProfile = profile
	c.profileApplied = true
	return nil
}

func (c *Config) prepareApplicationProfile() error {
	if c.ProfilePath != "" && !c.profileApplied {
		if err := c.LoadAndApplyApplicationProfile(c.ProfilePath); err != nil {
			return err
		}
	}
	if c.StructOffsets == nil {
		c.StructOffsets = make(map[string]uint64)
	}
	if c.HookOverrides == nil {
		c.HookOverrides = make(map[string]HookProfile)
	}
	for _, spec := range c.StructOffsetSpecs {
		if err := c.ApplyStructOffsetAssignment(spec); err != nil {
			return err
		}
	}
	for _, spec := range c.HookSpecs {
		if err := c.ApplyHookAssignment(spec); err != nil {
			return err
		}
	}
	if c.PackageName != "" && c.Uid == 0 {
		uid, err := resolvePackageUID(c.PackageName)
		if err != nil {
			return err
		}
		c.Uid = uid
	}
	c.RelatedPackageUIDs = c.RelatedPackageUIDs[:0]
	for _, packageName := range c.RelatedPackages {
		uid, err := resolvePackageUID(packageName)
		if err != nil {
			return fmt.Errorf(
				"resolve related Android package %q: %w",
				packageName,
				err,
			)
		}
		if uid == 0 || uid > uint64(^uint32(0)) {
			return fmt.Errorf(
				"related Android package %q has invalid UID %d",
				packageName,
				uid,
			)
		}
		c.RelatedPackageUIDs = append(
			c.RelatedPackageUIDs,
			uint32(uid),
		)
	}
	if c.applicationProfile != nil && c.PackageName != "" &&
		(c.applicationProfile.Match.VersionName != "" || c.applicationProfile.Match.VersionCode != 0) {
		versionName, versionCode, err := resolvePackageVersion(c.PackageName)
		if err != nil {
			return err
		}
		c.packageVersionName = versionName
		c.packageVersionCode = versionCode
	}
	if c.OpensslPath == "" && c.OpensslPathPattern != "" {
		path, err := resolveLibraryGlob(c.OpensslPathPattern)
		if err != nil {
			return err
		}
		c.OpensslPath = path
	}
	c.CaptureStrategies = normalizeStrings(c.CaptureStrategies)
	if len(c.CaptureStrategies) == 0 {
		c.CaptureStrategies = strategiesForCaptureMode(c.CaptureMode)
	}
	if err := validateProfileStrategies(c.CaptureStrategies); err != nil {
		return err
	}
	if c.HasDataHookStrategy() {
		if len(c.EnabledCaptureDataHooks()) == 0 {
			return fmt.Errorf("data-hook capture strategy requires at least one matching enabled data_hooks entry")
		}
		if c.HasStrategy(StrategyBoundaryData) &&
			len(c.EnabledBoundaryDataHooks()) == 0 {
			return fmt.Errorf("%s strategy requires at least one wire or transport data_hooks entry",
				StrategyBoundaryData)
		}
		if err := c.resolveApplicationDataLibraries(); err != nil {
			return err
		}
		if c.hasDwarfStackHooks() && c.Pid == 0 {
			return fmt.Errorf("stack_mode=%s requires one target pid; set match.pid or --pid",
				AppDataStackDWARF)
		}
	}
	if c.HasStrategy(StrategyJNIDiscovery) {
		if err := c.resolveJNIDiscoveryLibrary(); err != nil {
			return err
		}
	}
	if c.UnknownFlowPolicy == "" {
		c.UnknownFlowPolicy = UnknownFlowInclude
	}
	switch c.UnknownFlowPolicy {
	case UnknownFlowInclude, UnknownFlowMark, UnknownFlowDrop:
	default:
		return fmt.Errorf("unsupported unknown flow policy %q", c.UnknownFlowPolicy)
	}
	if c.StrictAttribution && c.UnknownFlowPolicy == UnknownFlowInclude {
		c.UnknownFlowPolicy = UnknownFlowDrop
	}
	return nil
}

func (c *Config) validateApplicationMatch() error {
	profile := c.applicationProfile
	if profile == nil {
		return nil
	}
	if want := strings.TrimSpace(profile.Match.ABI); want != "" && !abiMatches(want, runtime.GOARCH) {
		return fmt.Errorf("profile %q requires ABI %q, running %q", profile.Name, want, runtime.GOARCH)
	}
	if want := strings.TrimSpace(profile.Match.AndroidRelease); want != "" {
		if !c.IsAndroid {
			return fmt.Errorf("profile %q requires Android %q, but the target is Linux", profile.Name, want)
		}
		if !strings.EqualFold(want, c.AndroidVer) {
			return fmt.Errorf("profile %q requires Android %q, running %q", profile.Name, want, c.AndroidVer)
		}
	}
	if want := strings.TrimSpace(profile.Match.VersionName); want != "" && want != c.packageVersionName {
		return fmt.Errorf("profile %q requires package version %q, running %q",
			profile.Name, want, c.packageVersionName)
	}
	if want := profile.Match.VersionCode; want != 0 && want != c.packageVersionCode {
		return fmt.Errorf("profile %q requires package version code %d, running %d",
			profile.Name, want, c.packageVersionCode)
	}
	return nil
}

func abiMatches(profileABI, goarch string) bool {
	profileABI = strings.ToLower(strings.TrimSpace(profileABI))
	switch profileABI {
	case "arm64-v8a", "aarch64":
		profileABI = "arm64"
	case "x86_64", "amd64-v8a":
		profileABI = "amd64"
	}
	return profileABI == strings.ToLower(goarch)
}

func (c *Config) normalizeInterfaces() {
	values := append([]string(nil), c.Ifnames...)
	if c.Ifname != "" {
		values = append(values, c.Ifname)
	}
	// Validation can run more than once. Once "all" has been expanded into the
	// current concrete names, retain the watcher intent on later passes.
	watchInterfaces := c.WatchInterfaces
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), "all") {
			// Preserve the intent after expanding the current snapshot. The
			// probe uses this bit to attach the running TC programs to
			// interfaces that appear later (VPN/TUN, cellular, containers).
			watchInterfaces = true
			values = allUpInterfaces()
			break
		}
	}
	c.WatchInterfaces = watchInterfaces
	values = normalizeInterfaceNames(values)
	c.Ifnames = values
	if len(values) != 0 {
		c.Ifname = values[0]
	}
}

func allUpInterfaces() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		names = append(names, iface.Name)
	}
	sort.Strings(names)
	return names
}

func (c *Config) Interfaces() []string {
	if len(c.Ifnames) != 0 {
		return append([]string(nil), c.Ifnames...)
	}
	if c.Ifname != "" {
		return []string{c.Ifname}
	}
	return nil
}

func (c *Config) HasStrategy(strategy string) bool {
	for _, current := range c.CaptureStrategies {
		if current == strategy {
			return true
		}
	}
	return false
}

func (c *Config) HasApplicationDataStrategy() bool {
	return c.HasStrategy(StrategyAppData) || c.HasStrategy(StrategyCronet)
}

func (c *Config) HasBoundaryDataStrategy() bool {
	return c.HasStrategy(StrategyBoundaryData)
}

func (c *Config) HasDataHookStrategy() bool {
	return c.HasBoundaryDataStrategy() || c.HasApplicationDataStrategy()
}

func (c *Config) HasJNIDiscoveryStrategy() bool {
	return c.HasStrategy(StrategyJNIDiscovery)
}

// EnabledBoundaryDataHooks returns only hooks with evidence-bearing wire or
// transport provenance. Semantic hooks are intentionally excluded.
func (c *Config) EnabledBoundaryDataHooks() []ApplicationDataHook {
	hooks := make([]ApplicationDataHook, 0, len(c.ApplicationDataHooks))
	for _, hook := range c.ApplicationDataHooks {
		if !hook.Disabled && hook.CaptureLayer != CaptureLayerSemantic {
			hooks = append(hooks, hook)
		}
	}
	return hooks
}

// EnabledCaptureDataHooks selects the hooks requested by the strategy layer.
// application_data/cronet alone retains the pre-boundary_data behaviour for
// old profiles. New profiles should use boundary_data for wire/transport hooks
// and application_data only for explicitly optional semantic diagnostics.
func (c *Config) EnabledCaptureDataHooks() []ApplicationDataHook {
	hooks := make([]ApplicationDataHook, 0, len(c.ApplicationDataHooks))
	for _, hook := range c.ApplicationDataHooks {
		if c.captureDataHookEnabled(hook) {
			hooks = append(hooks, hook)
		}
	}
	return hooks
}

func (c *Config) captureDataHookEnabled(hook ApplicationDataHook) bool {
	if hook.Disabled {
		return false
	}
	boundaryEnabled := c.HasBoundaryDataStrategy()
	legacyEnabled := c.HasApplicationDataStrategy()
	switch {
	case boundaryEnabled && hook.CaptureLayer != CaptureLayerSemantic:
		return true
	case legacyEnabled && (!boundaryEnabled || hook.CaptureLayer == CaptureLayerSemantic):
		return true
	default:
		return false
	}
}

func (c *Config) hasDwarfStackHooks() bool {
	for _, hook := range c.EnabledCaptureDataHooks() {
		if hook.StackMode == AppDataStackDWARF {
			return true
		}
	}
	return false
}

func (c *Config) resolveApplicationDataLibraries() error {
	for i := range c.ApplicationDataHooks {
		hook := &c.ApplicationDataHooks[i]
		if !c.captureDataHookEnabled(*hook) {
			continue
		}
		if hook.LibraryGlob != "" {
			path, err := resolveLibraryGlob(hook.LibraryGlob)
			if err != nil {
				return fmt.Errorf("resolve application data hook %q: %w", hook.Name, err)
			}
			hook.Library = path
		} else {
			hook.Library = strings.TrimSpace(hook.Library)
		}
		target, err := resolveLibraryTarget(hook.Library)
		if err != nil {
			return fmt.Errorf("resolve application data hook %q library %q: %w",
				hook.Name, hook.Library, err)
		}
		hook.resolvedTarget = target
		hook.resolvedLibrary = target.String()
		if target.IsArchive() {
			elfOffset := uint64(hook.Offset)
			if hook.Symbol != "" {
				elfOffset, err = librarySymbolFileOffset(target, hook.Symbol)
				if err != nil {
					return fmt.Errorf(
						"resolve application data hook %q symbol: %w",
						hook.Name,
						err,
					)
				}
			}
			hook.resolvedOffset, err = target.runtimeOffset(elfOffset)
			if err != nil {
				return fmt.Errorf(
					"resolve application data hook %q offset: %w",
					hook.Name,
					err,
				)
			}
		}
		if hook.BuildID != "" {
			if err := verifyLibraryTargetBuildID(target, hook.BuildID); err != nil {
				return fmt.Errorf("verify application data hook %q library: %w",
					hook.Name, err)
			}
		}
	}
	return nil
}

func (h ApplicationDataHook) ResolvedLibrary() string {
	if h.resolvedLibrary != "" {
		return h.resolvedLibrary
	}
	return h.Library
}

func (h ApplicationDataHook) ResolvedTarget() libraryTarget {
	if h.resolvedTarget.RuntimePath != "" {
		return h.resolvedTarget
	}
	target, _ := resolveLibraryTarget(h.ResolvedLibrary())
	return target
}

func (c *Config) resolveJNIDiscoveryLibrary() error {
	if c.JNIDiscovery == nil {
		return fmt.Errorf("%s strategy requires jni_discovery configuration",
			StrategyJNIDiscovery)
	}
	jni := c.JNIDiscovery
	if jni.LibraryGlob != "" {
		path, err := resolveLibraryGlob(jni.LibraryGlob)
		if err != nil {
			return fmt.Errorf("resolve JNI discovery library: %w", err)
		}
		jni.resolvedLibrary = path
	} else {
		info, err := os.Stat(jni.Library)
		if err != nil {
			return fmt.Errorf("stat JNI discovery library %q: %w", jni.Library, err)
		}
		if info.IsDir() {
			return fmt.Errorf("JNI discovery library %q is a directory", jni.Library)
		}
		jni.resolvedLibrary = jni.Library
	}
	if jni.BuildID != "" {
		if err := verifyELFBuildID(jni.resolvedLibrary, jni.BuildID); err != nil {
			return fmt.Errorf("verify JNI discovery library: %w", err)
		}
	}
	return nil
}

func (p *JNIDiscoveryProfile) ResolvedLibrary() string {
	if p == nil {
		return ""
	}
	if p.resolvedLibrary != "" {
		return p.resolvedLibrary
	}
	return p.Library
}

func (c *Config) ApplyStructOffsetAssignment(assignment string) error {
	name, text, err := parseAssignment(assignment)
	if err != nil {
		return err
	}
	if _, ok := StructOffsetConstant(name); !ok {
		return fmt.Errorf("unsupported structure offset %q", name)
	}
	value, err := strconv.ParseUint(text, 0, 64)
	if err != nil {
		return fmt.Errorf("invalid structure offset %q: %w", assignment, err)
	}
	if value > 1<<20 {
		return fmt.Errorf("structure offset %q is unreasonably large: %#x", name, value)
	}
	c.StructOffsets[name] = value
	return nil
}

func (c *Config) ApplyHookAssignment(assignment string) error {
	role, value, err := parseAssignment(assignment)
	if err != nil {
		return err
	}
	if _, ok := supportedHookRoles[role]; !ok {
		return fmt.Errorf("unsupported hook role %q", role)
	}
	hook := HookProfile{}
	switch {
	case strings.EqualFold(value, "off"), strings.EqualFold(value, "disabled"):
		hook.Disabled = true
	case strings.HasPrefix(value, "@"):
		offset, parseErr := strconv.ParseUint(strings.TrimPrefix(value, "@"), 0, 64)
		if parseErr != nil || offset == 0 {
			return fmt.Errorf("invalid hook offset %q", value)
		}
		hook.Offset = OffsetValue(offset)
	default:
		hook.Symbol = value
	}
	c.HookOverrides[role] = hook
	return nil
}

func (c *Config) HookOverride(role string) (HookProfile, bool) {
	hook, ok := c.HookOverrides[role]
	return hook, ok
}

func (c *Config) SortedStructOffsetNames() []string {
	names := make([]string, 0, len(c.StructOffsets))
	for name := range c.StructOffsets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *Config) UnknownFlowPolicyValue() uint64 {
	switch c.UnknownFlowPolicy {
	case UnknownFlowMark:
		return 1
	case UnknownFlowDrop:
		return 2
	default:
		return 0
	}
}

func captureModeForStrategies(strategies []string) string {
	raw := false
	plaintext := false
	keys := false
	for _, strategy := range strategies {
		switch strategy {
		case StrategyRawPackets:
			raw = true
		case StrategyTLSPlaintext, StrategyQUICMetadata, StrategyBoundaryData, StrategyAppData, StrategyJNIDiscovery, StrategyCronet:
			plaintext = true
		case StrategyTLSKeys:
			keys = true
		}
	}
	if raw && (plaintext || keys) {
		return handlers.ModeAll
	}
	if raw {
		return handlers.ModePcap
	}
	if plaintext {
		return handlers.ModeText
	}
	if keys {
		return handlers.ModeKeylog
	}
	return handlers.ModeText
}

func strategiesForCaptureMode(mode string) []string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case handlers.ModeAll, handlers.ModeHybrid:
		// Combined observation means packet plus communication-boundary
		// capture. Key extraction is an optional export mechanism and must be
		// requested explicitly.
		return []string{StrategyRawPackets, StrategyTLSPlaintext, StrategyQUICMetadata}
	case handlers.ModePcap, handlers.ModePcapng:
		// Packet mode preserves the on-wire bytes; it must not silently become
		// a TLS-decryption workflow.
		return []string{StrategyRawPackets}
	case handlers.ModeKey, handlers.ModeKeylog:
		return []string{StrategyTLSKeys}
	default:
		return []string{StrategyTLSPlaintext, StrategyQUICMetadata}
	}
}
