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
	"debug/elf"
	"strings"
)

func elfHasDynamicSymbol(path, name string) (bool, error) {
	file, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	symbols, err := file.DynamicSymbols()
	if err != nil {
		return false, err
	}
	for _, symbol := range symbols {
		// ELF symbol versioning may expose names such as SSL_read@@OPENSSL_3.0.0.
		if strings.SplitN(symbol.Name, "@", 2)[0] == name {
			return true, nil
		}
	}
	return false, nil
}
