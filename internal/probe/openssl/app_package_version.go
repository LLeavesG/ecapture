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
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// parsePackageVersionDump selects the installed package from dumpsys' active
// "Packages" section. Updated system apps also appear later under "Hidden
// system packages" with the factory-image version; that block must not
// overwrite the version of the APK that Android actually launches.
func parsePackageVersionDump(output, packageName string) (string, uint64, error) {
	versionName, versionCode, found := parsePackageVersionSection(
		output,
		packageName,
	)
	if found {
		return versionName, versionCode, nil
	}

	// Older Android releases and vendor-modified dumpsys implementations may
	// omit section labels. Preserve compatibility by taking the first complete
	// version pair rather than the last pair in the dump.
	versionName, versionCode, found = parseFirstPackageVersion(output)
	if found {
		return versionName, versionCode, nil
	}
	return "", 0, fmt.Errorf(
		"Android package version for %q not found",
		packageName,
	)
}

func parsePackageVersionSection(
	output string,
	packageName string,
) (string, uint64, bool) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	inPackages := false
	inTarget := false
	targetPrefix := "Package [" + packageName + "]"
	var versionName string
	var versionCode uint64
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "Packages:" {
			inPackages = true
			continue
		}
		if !inPackages {
			continue
		}
		if line == "Hidden system packages:" {
			break
		}
		if strings.HasPrefix(line, "Package [") {
			if inTarget {
				break
			}
			inTarget = strings.HasPrefix(line, targetPrefix)
			continue
		}
		if !inTarget {
			continue
		}
		versionName, versionCode = parsePackageVersionLine(
			line,
			versionName,
			versionCode,
		)
		if versionName != "" && versionCode != 0 {
			return versionName, versionCode, true
		}
	}
	return "", 0, false
}

func parseFirstPackageVersion(output string) (string, uint64, bool) {
	var versionName string
	var versionCode uint64
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		versionName, versionCode = parsePackageVersionLine(
			strings.TrimSpace(scanner.Text()),
			versionName,
			versionCode,
		)
		if versionName != "" && versionCode != 0 {
			return versionName, versionCode, true
		}
	}
	return "", 0, false
}

func parsePackageVersionLine(
	line string,
	versionName string,
	versionCode uint64,
) (string, uint64) {
	switch {
	case strings.HasPrefix(line, "versionName="):
		versionName = strings.TrimSpace(strings.TrimPrefix(line, "versionName="))
	case strings.HasPrefix(line, "versionCode="):
		fields := strings.Fields(strings.TrimSpace(
			strings.TrimPrefix(line, "versionCode="),
		))
		if len(fields) != 0 {
			if parsed, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
				versionCode = parsed
			}
		}
	}
	return versionName, versionCode
}
