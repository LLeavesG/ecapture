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

//go:build ecap_android

package cmd

// Android root providers can authorize BPF through kernel/root-manager policy
// while capget still reports CapEff=0 and a bounding set without CAP_BPF or
// CAP_PERFMON. The BPF loader and perf-event attach are the authoritative
// checks in this build; rejecting the process here would be a false negative.
const enforceBpfCapabilityBits = false
