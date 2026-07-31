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

package cmd

import "testing"

func TestMatchesJNIConversionModule(t *testing.T) {
	path := "/data/app/random/pkg/lib/arm64/libsscronet.so"
	for _, test := range []struct {
		name      string
		selectors []string
		want      bool
	}{
		{name: "no filter", want: true},
		{name: "basename", selectors: []string{"libsscronet.so"}, want: true},
		{name: "basename glob", selectors: []string{"lib*cronet*.so"}, want: true},
		{name: "path", selectors: []string{path}, want: true},
		{name: "other module", selectors: []string{"libalog.so"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := matchesJNIConversionModule(
				path,
				"libsscronet.so",
				test.selectors,
			)
			if err != nil {
				t.Fatalf("matchesJNIConversionModule() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("matchesJNIConversionModule() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestMatchesJNIConversionModuleRejectsInvalidGlob(t *testing.T) {
	if _, err := matchesJNIConversionModule(
		"/data/app/pkg/libworker.so",
		"libworker.so",
		[]string{"["},
	); err == nil {
		t.Fatal("matchesJNIConversionModule() accepted an invalid glob")
	}
}
