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

// bpfverify loads one program from an eCapture ELF object and reports the
// kernel verifier result. It intentionally does not attach the program. Its
// map-lookup mode reads one live value when verifier/runtime diagnostics need
// to distinguish missing map data from an eBPF lookup bug.
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "map-lookup" {
		lookupMapValue(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s BPF_OBJECT PROGRAM_NAME\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s map-lookup MAP_ID KEY_HEX\n", os.Args[0])
		os.Exit(2)
	}
	objectPath := os.Args[1]
	programName := os.Args[2]
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		fatal("parse BPF object", err)
	}
	program, found := spec.Programs[programName]
	if !found {
		names := make([]string, 0, len(spec.Programs))
		for name := range spec.Programs {
			names = append(names, name)
		}
		sort.Strings(names)
		fatal("select BPF program", fmt.Errorf("%q is absent; available: %v", programName, names))
	}
	for name := range spec.Programs {
		if name != programName {
			delete(spec.Programs, name)
		}
	}
	referencedMaps := make(map[string]struct{})
	for iterator := program.Instructions.Iterate(); iterator.Next(); {
		reference := iterator.Ins.Reference()
		if _, found := spec.Maps[reference]; found {
			referencedMaps[reference] = struct{}{}
		}
	}
	for name := range spec.Maps {
		if _, found := referencedMaps[name]; !found {
			delete(spec.Maps, name)
		}
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: remove memlock limit: %v\n", err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch | ebpf.LogLevelStats,
			LogSizeStart: 16 << 20,
		},
	})
	if err != nil {
		fatal("load BPF program", err)
	}
	collection.Close()
	mapNames := make([]string, 0, len(referencedMaps))
	for name := range referencedMaps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	fmt.Printf("verified program=%s maps=%v\n", programName, mapNames)
}

func lookupMapValue(idText, keyText string) {
	id, err := strconv.ParseUint(idText, 10, 32)
	if err != nil {
		fatal("parse map ID", err)
	}
	key, err := hex.DecodeString(keyText)
	if err != nil {
		fatal("decode map key", err)
	}
	m, err := ebpf.NewMapFromID(ebpf.MapID(id))
	if err != nil {
		fatal("open BPF map", err)
	}
	defer m.Close()
	info, err := m.Info()
	if err != nil {
		fatal("read BPF map info", err)
	}
	if len(key) != int(info.KeySize) {
		fatal("validate map key", fmt.Errorf("decoded key is %d bytes, want %d",
			len(key), info.KeySize))
	}
	value := make([]byte, info.ValueSize)
	if err := m.Lookup(key, value); err != nil {
		fatal("lookup BPF map value", err)
	}
	fmt.Printf("map_id=%d key=%x value=%x\n", id, key, value)
}

func fatal(operation string, err error) {
	var verifierError *ebpf.VerifierError
	if errors.As(err, &verifierError) {
		fmt.Fprintf(os.Stderr, "%s: %+v\n", operation, verifierError)
	} else {
		fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	}
	os.Exit(1)
}
