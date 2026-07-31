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
	"strconv"
	"strings"
)

// parseAndroidRelatedProcessUIDs extracts ActivityManager ProcessRecord UIDs
// whose packageList explicitly contains the selected host package. In
// particular, an isolated WebView renderer reports its isolated UID on the
// *APP* line and its host package in packageList.
func parseAndroidRelatedProcessUIDs(
	output, packageName string,
) []uint32 {
	packageName = strings.TrimSpace(packageName)
	if packageName == "" {
		return nil
	}
	seen := make(map[uint32]struct{})
	var currentUID uint32
	haveProcess := false
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "*APP* UID ") {
			haveProcess = false
			currentUID = 0
			fields := strings.Fields(line)
			for index := 0; index+1 < len(fields); index++ {
				if fields[index] != "UID" {
					continue
				}
				value, err := strconv.ParseUint(fields[index+1], 10, 32)
				if err == nil && value != 0 {
					currentUID = uint32(value)
					haveProcess = true
				}
				break
			}
			continue
		}
		if !haveProcess || !strings.HasPrefix(line, "packageList={") {
			continue
		}
		start := strings.IndexByte(line, '{')
		end := strings.LastIndexByte(line, '}')
		if start < 0 || end <= start {
			continue
		}
		for _, currentPackage := range strings.FieldsFunc(
			line[start+1:end],
			func(value rune) bool {
				return value == ',' || value == ' ' || value == '\t'
			},
		) {
			if currentPackage == packageName {
				seen[currentUID] = struct{}{}
				break
			}
		}
	}
	values := make([]uint32, 0, len(seen))
	for uid := range seen {
		values = append(values, uid)
	}
	return values
}
