//go:build ecap_android
// +build ecap_android

// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const (
	// Android-specific default paths
	DefaultLibcPath = "/apex/com.android.runtime/lib64/bionic/libc.so"
	BuildPropPath   = "/system/build.prop"
	ReleasePrefix   = "ro.build.version.release="
	DefaultIfname   = "wlan0"
)

// Android-specific version of detectOpenSSL
func (c *Config) detectOpenSSL() error {
	// If OpenSSL path is configured, validate it
	if c.OpensslPath != "" {
		if _, err := os.Stat(c.OpensslPath); err != nil {
			return fmt.Errorf("openssl path not found: %w", err)
		}
		return nil
	}

	// Android-specific paths for BoringSSL
	androidPaths := []string{
		"/apex/com.android.conscrypt/lib64/libssl.so",
		"/apex/com.android.conscrypt/lib/libssl.so",
		"/system/lib64/libssl.so",
		"/system/lib/libssl.so",
	}

	for _, path := range androidPaths {
		if _, err := os.Stat(path); err == nil {
			c.OpensslPath = path
			c.IsBoringSSL = true
			return nil
		}
	}

	return fmt.Errorf("cannot find libssl.so (BoringSSL) in Android paths")
}

// Android-specific version of detectOS
func (c *Config) detectOS() error {
	if c.OpensslPath == "" {
		return fmt.Errorf("openssl path not set")
	}

	// set Android-specific flags
	c.IsAndroid = true

	// For Android, it's always BoringSSL
	c.IsBoringSSL = true

	// Detect Android version from build.prop
	androidVer, err := detectAndroidVersion()
	if err == nil && androidVer != "" {
		c.AndroidVer = androidVer
		if c.SslVersion == "" {
			c.SslVersion = fmt.Sprintf("boringssl_a_%s", androidVer)
		}
	} else {
		if err == nil {
			err = fmt.Errorf("Android version is empty")
		}
		return fmt.Errorf("detect Android version: %w", err)
	}

	return nil
}

func (c *Config) discoverPlatformTLSLibraries() []string {
	var candidates []string
	switch runtime.GOARCH {
	case "arm64", "amd64":
		candidates = []string{
			"/apex/com.android.conscrypt/lib64/libssl.so",
			"/system/lib64/libssl.so",
		}
	default:
		candidates = []string{
			"/apex/com.android.conscrypt/lib/libssl.so",
			"/system/lib/libssl.so",
		}
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			// APEX and /system commonly expose aliases of the same provider.
			// One successfully resolved path is sufficient for an inode-based
			// uprobe and avoids duplicate events or redundant links.
			return []string{candidate}
		}
	}
	return nil
}

func resolvePackageUID(packageName string) (uint64, error) {
	output, commandErr := exec.Command(
		"/system/bin/cmd", "package", "list", "packages", "-U", packageName,
	).Output()
	if commandErr == nil {
		prefix := "package:" + packageName
		sc := bufio.NewScanner(strings.NewReader(string(output)))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 || fields[0] != prefix {
				continue
			}
			for _, field := range fields[1:] {
				if !strings.HasPrefix(field, "uid:") {
					continue
				}
				uid, err := strconv.ParseUint(strings.TrimPrefix(field, "uid:"), 10, 64)
				if err != nil {
					return 0, fmt.Errorf("parse UID for package %q: %w", packageName, err)
				}
				return uid, nil
			}
		}
		if err := sc.Err(); err != nil {
			commandErr = err
		}
	}

	// Older Android releases may not support `cmd package ... -U`. Keep the
	// package-list parser as a fallback, although modern SELinux policy can
	// deny direct access even to a Magisk-root process.
	f, err := os.Open("/data/system/packages.list")
	if err != nil {
		if commandErr != nil {
			return 0, fmt.Errorf("query package manager: %v; open Android package list: %w",
				commandErr, err)
		}
		return 0, fmt.Errorf("Android package %q not found via package manager; open package list: %w",
			packageName, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != packageName {
			continue
		}
		uid, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return 0, fmt.Errorf("parse UID for package %q: %w", packageName, parseErr)
		}
		return uid, nil
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read Android package list: %w", err)
	}
	return 0, fmt.Errorf("Android package %q not found", packageName)
}

func resolvePackageVersion(packageName string) (string, uint64, error) {
	output, err := exec.Command("/system/bin/dumpsys", "package", packageName).Output()
	if err != nil {
		return "", 0, fmt.Errorf("query Android package %q: %w", packageName, err)
	}
	return parsePackageVersionDump(string(output), packageName)
}

// detectAndroidVersion reads the Android version from build.prop
func detectAndroidVersion() (string, error) {
	f, err := os.Open(BuildPropPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, ReleasePrefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, ReleasePrefix)), nil
		}
	}

	return "", fmt.Errorf("android version not found in build.prop")
}

// Android-specific default interface.
// On real devices wlan0 is common, but in emulators networking may use eth0
// or another interface. This function tries to find an interface that is up
// and has at least one IP address.
func (c *Config) setDefaultIfname() {
	if c.Ifname != "" {
		return
	}

	// Try the common Android default first.
	if ifaceHasAddr(DefaultIfname) {
		c.Ifname = DefaultIfname
		return
	}

	// Fallback: iterate all interfaces looking for one that is up and has an
	// address, skipping loopback.
	if name := firstUpNonLoopbackInterface(); name != "" {
		c.Ifname = name
		return
	}

	// Last resort: keep the historical default so the error message is clear.
	c.Ifname = DefaultIfname
}

// validateCgroupPath is a no-op on Android since cgroup filtering is not supported.
func (c *Config) validateCgroupPath() error {
	return nil
}
