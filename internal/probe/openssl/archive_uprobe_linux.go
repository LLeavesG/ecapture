//go:build linux

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
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type archivePerfEvent struct {
	fd int
}

type archivePerfEvents struct {
	events []*archivePerfEvent
}

func (event *archivePerfEvent) Close() error {
	if event == nil || event.fd < 0 {
		return nil
	}
	_ = unix.IoctlSetInt(event.fd, unix.PERF_EVENT_IOC_DISABLE, 0)
	err := unix.Close(event.fd)
	event.fd = -1
	return err
}

func (events *archivePerfEvents) Close() error {
	var firstErr error
	for _, event := range events.events {
		if err := event.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	events.events = nil
	return firstErr
}

func attachArchiveUprobe(
	path string,
	offset uint64,
	ret bool,
	pid int,
	program *ebpf.Program,
) (archiveUprobeCloser, error) {
	if path == "" || offset == 0 {
		return nil, fmt.Errorf("path and offset are required")
	}
	if program == nil || program.FD() < 0 {
		return nil, fmt.Errorf("eBPF program is not loaded")
	}
	eventType, err := readDecimalFile(
		"/sys/bus/event_source/devices/uprobe/type",
	)
	if err != nil {
		return nil, fmt.Errorf("read uprobe PMU type: %w", err)
	}
	var config uint64
	if ret {
		retprobeBit, err := readFormatBit(
			"/sys/bus/event_source/devices/uprobe/format/retprobe",
		)
		if err != nil {
			return nil, fmt.Errorf("read uretprobe PMU format: %w", err)
		}
		config = uint64(1) << retprobeBit
	}
	pathPointer, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode uprobe path: %w", err)
	}
	targets := []struct {
		pid int
		cpu int
	}{{pid: pid, cpu: -1}}
	if pid <= 0 {
		cpus, cpuErr := onlineCPUs()
		if cpuErr != nil {
			return nil, fmt.Errorf("resolve online CPUs: %w", cpuErr)
		}
		targets = targets[:0]
		for _, cpu := range cpus {
			targets = append(targets, struct {
				pid int
				cpu int
			}{pid: -1, cpu: cpu})
		}
	}
	attr := unix.PerfEventAttr{
		Size:   unix.PERF_ATTR_SIZE_VER1,
		Type:   uint32(eventType),
		Ext1:   uint64(uintptr(unsafe.Pointer(pathPointer))),
		Ext2:   offset,
		Config: config,
	}
	events := &archivePerfEvents{
		events: make([]*archivePerfEvent, 0, len(targets)),
	}
	for _, target := range targets {
		fd, openErr := unix.PerfEventOpen(
			&attr,
			target.pid,
			target.cpu,
			-1,
			unix.PERF_FLAG_FD_CLOEXEC,
		)
		runtime.KeepAlive(pathPointer)
		if openErr != nil {
			events.Close()
			return nil, fmt.Errorf(
				"perf_event_open pid=%d cpu=%d: %w",
				target.pid,
				target.cpu,
				openErr,
			)
		}
		event := &archivePerfEvent{fd: fd}
		events.events = append(events.events, event)
		if ioctlErr := unix.IoctlSetInt(
			fd,
			unix.PERF_EVENT_IOC_SET_BPF,
			program.FD(),
		); ioctlErr != nil {
			events.Close()
			return nil, fmt.Errorf(
				"set eBPF program pid=%d cpu=%d: %w",
				target.pid,
				target.cpu,
				ioctlErr,
			)
		}
		if ioctlErr := unix.IoctlSetInt(
			fd,
			unix.PERF_EVENT_IOC_ENABLE,
			0,
		); ioctlErr != nil {
			events.Close()
			return nil, fmt.Errorf(
				"enable perf event pid=%d cpu=%d: %w",
				target.pid,
				target.cpu,
				ioctlErr,
			)
		}
	}
	return events, nil
}

func readDecimalFile(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func readFormatBit(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(data))
	_, bitText, found := strings.Cut(value, ":")
	if !found {
		return 0, fmt.Errorf("unexpected format %q", value)
	}
	if index := strings.IndexByte(bitText, '-'); index >= 0 {
		bitText = bitText[:index]
	}
	return strconv.ParseUint(strings.TrimSpace(bitText), 10, 6)
}

func onlineCPUs() ([]int, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, err
	}
	return parseCPUList(strings.TrimSpace(string(data)))
}

func parseCPUList(value string) ([]int, error) {
	if value == "" {
		return nil, fmt.Errorf("CPU list is empty")
	}
	var cpus []int
	seen := make(map[int]struct{})
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("invalid CPU list %q", value)
		}
		startText, endText, rangeFound := strings.Cut(item, "-")
		start, err := strconv.Atoi(startText)
		if err != nil || start < 0 {
			return nil, fmt.Errorf("invalid CPU %q", item)
		}
		end := start
		if rangeFound {
			end, err = strconv.Atoi(endText)
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid CPU range %q", item)
			}
		}
		for cpu := start; cpu <= end; cpu++ {
			if _, found := seen[cpu]; found {
				continue
			}
			seen[cpu] = struct{}{}
			cpus = append(cpus, cpu)
		}
	}
	if len(cpus) == 0 {
		return nil, fmt.Errorf("CPU list %q contains no CPUs", value)
	}
	return cpus, nil
}
