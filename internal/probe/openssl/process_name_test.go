// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package openssl

import (
	"errors"
	"testing"
)

func TestProcessNameResolverUsesCmdlineAndCaches(t *testing.T) {
	reads := 0
	resolver := &processNameResolver{
		values: make(map[uint32]string),
		read: func(path string) ([]byte, error) {
			reads++
			if path != "/proc/23905/cmdline" {
				t.Fatalf("unexpected path %q", path)
			}
			return []byte("com.aliyun.tongyi:channel\x00--flag"), nil
		},
	}
	if got := resolver.resolve(23905); got != "com.aliyun.tongyi:channel" {
		t.Fatalf("process name = %q", got)
	}
	if got := resolver.resolve(23905); got != "com.aliyun.tongyi:channel" {
		t.Fatalf("cached process name = %q", got)
	}
	if reads != 1 {
		t.Fatalf("read count = %d", reads)
	}
}

func TestProcessNameResolverFallsBackToComm(t *testing.T) {
	resolver := &processNameResolver{
		values: make(map[uint32]string),
		read: func(path string) ([]byte, error) {
			if path == "/proc/42/cmdline" {
				return nil, errors.New("denied")
			}
			if path == "/proc/42/comm" {
				return []byte("worker\n"), nil
			}
			return nil, errors.New("unexpected path")
		},
	}
	if got := resolver.resolve(42); got != "worker" {
		t.Fatalf("process name = %q", got)
	}
}

func TestProcessNameResolverRefreshesTransientZygoteIdentity(t *testing.T) {
	reads := 0
	resolver := &processNameResolver{
		values: make(map[uint32]string),
		read: func(path string) ([]byte, error) {
			if path != "/proc/23705/cmdline" {
				t.Fatalf("unexpected path %q", path)
			}
			reads++
			if reads == 1 {
				return []byte("zygote64\x00"), nil
			}
			return []byte("com.tencent.hunyuan.app.chat\x00"), nil
		},
	}
	if got := resolver.resolve(23705); got != "zygote64" {
		t.Fatalf("initial process name = %q", got)
	}
	if got := resolver.resolve(23705); got != "com.tencent.hunyuan.app.chat" {
		t.Fatalf("specialized process name = %q", got)
	}
	if got := resolver.resolve(23705); got != "com.tencent.hunyuan.app.chat" {
		t.Fatalf("cached specialized process name = %q", got)
	}
	if reads != 2 {
		t.Fatalf("read count = %d", reads)
	}
}
