// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package openssl

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
)

type processNameResolver struct {
	mu     sync.Mutex
	values map[uint32]string
	read   func(string) ([]byte, error)
}

func newProcessNameResolver() *processNameResolver {
	return &processNameResolver{
		values: make(map[uint32]string),
		read:   os.ReadFile,
	}
}

func (r *processNameResolver) resolve(pid uint32) string {
	if pid == 0 {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if value, found := r.values[pid]; found {
		// Android creates application processes by specializing a zygote. A
		// globally attached uprobe can observe the PID before /proc/<pid>/cmdline
		// is updated. Never make that transient identity permanent: retry it on
		// the next event until the process exposes its final command line.
		if !isTransientAndroidProcessName(value) {
			return value
		}
	}
	value := r.readProcessFile(pid, "cmdline")
	if value == "" {
		value = r.readProcessFile(pid, "comm")
	}
	r.values[pid] = value
	return value
}

func isTransientAndroidProcessName(value string) bool {
	switch strings.TrimSpace(value) {
	case "", "zygote", "zygote32", "zygote64", "app_process", "app_process32", "app_process64":
		return true
	default:
		return false
	}
}

func (r *processNameResolver) readProcessFile(pid uint32, name string) string {
	data, err := r.read(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return ""
	}
	if index := bytes.IndexByte(data, 0); index >= 0 {
		data = data[:index]
	}
	return strings.TrimSpace(string(data))
}
