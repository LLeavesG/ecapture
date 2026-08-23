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
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

const (
	relatedUIDMapName             = "target_related_uids"
	relatedUIDFastWatchInterval   = 500 * time.Millisecond
	relatedUIDSteadyWatchInterval = 2 * time.Second
	relatedUIDFastWatchDuration   = 20 * time.Second
)

func (p *Probe) configureRelatedProcessUIDs(parent context.Context) error {
	if p == nil || p.config == nil ||
		p.config.PackageName == "" ||
		p.config.GetUid() == 0 {
		return nil
	}
	uidMap, found, err := p.bpfManager.GetMap(relatedUIDMapName)
	if err != nil {
		return fmt.Errorf("get %s map: %w", relatedUIDMapName, err)
	}
	if !found {
		return fmt.Errorf("%s map was not loaded", relatedUIDMapName)
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	initial := p.configuredRelatedUIDs()
	committed := make(map[uint32]struct{}, len(initial))
	for uid := range initial {
		value := uint8(1)
		if err := uidMap.Update(&uid, &value, ebpf.UpdateAny); err != nil {
			cancel()
			for committedUID := range committed {
				_ = uidMap.Delete(&committedUID)
			}
			return fmt.Errorf("allow related Android UID %d: %w", uid, err)
		}
		committed[uid] = struct{}{}
	}
	p.relatedUIDWatcherCancel = cancel
	p.relatedUIDWatcherDone = done
	go p.watchRelatedProcessUIDs(ctx, done, uidMap, committed)
	return nil
}

func (p *Probe) stopRelatedProcessUIDWatcher() {
	if p == nil || p.relatedUIDWatcherCancel == nil {
		return
	}
	p.relatedUIDWatcherCancel()
	if p.relatedUIDWatcherDone != nil {
		<-p.relatedUIDWatcherDone
	}
	p.relatedUIDWatcherCancel = nil
	p.relatedUIDWatcherDone = nil
}

func (p *Probe) watchRelatedProcessUIDs(
	ctx context.Context,
	done chan struct{},
	uidMap *ebpf.Map,
	active map[uint32]struct{},
) {
	defer close(done)
	reconcile := func() bool {
		desired := p.desiredRelatedUIDs()
		changed := !sameUIDSet(active, desired)
		committed := make(map[uint32]struct{}, len(desired))
		for uid := range desired {
			if _, found := active[uid]; found {
				committed[uid] = struct{}{}
				continue
			}
			value := uint8(1)
			if err := uidMap.Update(&uid, &value, ebpf.UpdateAny); err != nil {
				p.Logger().Warn().Err(err).Uint32("uid", uid).
					Msg("Failed to allow related Android process UID")
				continue
			}
			committed[uid] = struct{}{}
			p.Logger().Info().Uint32("uid", uid).
				Str("packages", strings.Join(p.capturePackageNames(), ",")).
				Msg("Included related Android process UID")
		}
		for uid := range active {
			if _, found := desired[uid]; found {
				continue
			}
			if err := uidMap.Delete(&uid); err != nil &&
				err != ebpf.ErrKeyNotExist {
				p.Logger().Warn().Err(err).Uint32("uid", uid).
					Msg("Failed to remove stale related Android process UID")
				committed[uid] = struct{}{}
			}
		}
		active = committed
		return changed
	}

	fastUntil := time.Now().Add(relatedUIDFastWatchDuration)
	if reconcile() {
		fastUntil = time.Now().Add(relatedUIDFastWatchDuration)
	}
	timer := time.NewTimer(relatedUIDFastWatchInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			for uid := range active {
				_ = uidMap.Delete(&uid)
			}
			return
		case now := <-timer.C:
			if reconcile() {
				fastUntil = now.Add(relatedUIDFastWatchDuration)
			}
			timer.Reset(relatedUIDWatchInterval(now, fastUntil))
		}
	}
}

func (p *Probe) capturePackageNames() []string {
	packages := make([]string, 0, 1+len(p.config.RelatedPackages))
	if value := strings.TrimSpace(p.config.PackageName); value != "" {
		packages = append(packages, value)
	}
	packages = append(packages, p.config.RelatedPackages...)
	return packages
}

func (p *Probe) desiredRelatedUIDs() map[uint32]struct{} {
	desired := p.configuredRelatedUIDs()
	primary := uint32(p.config.GetUid())
	for _, packageName := range p.capturePackageNames() {
		for _, uid := range discoverRelatedProcessUIDs(packageName) {
			if uid != 0 && uid != primary {
				desired[uid] = struct{}{}
			}
		}
	}
	return desired
}

func (p *Probe) configuredRelatedUIDs() map[uint32]struct{} {
	primary := uint32(p.config.GetUid())
	desired := make(map[uint32]struct{}, len(p.config.RelatedPackageUIDs))
	for _, uid := range p.config.RelatedPackageUIDs {
		if uid != 0 && uid != primary {
			desired[uid] = struct{}{}
		}
	}
	return desired
}

func relatedUIDWatchInterval(now, fastUntil time.Time) time.Duration {
	if now.Before(fastUntil) {
		return relatedUIDFastWatchInterval
	}
	return relatedUIDSteadyWatchInterval
}

func sameUIDSet(left, right map[uint32]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for uid := range left {
		if _, found := right[uid]; !found {
			return false
		}
	}
	return true
}
