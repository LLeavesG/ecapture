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
	"net"
	"time"

	manager "github.com/gojue/ebpfmanager"

	"github.com/gojue/ecapture/internal/probe/base"
)

const interfaceReconcileInterval = time.Second

type dynamicTCAttachment struct {
	name            string
	index           int
	ingressUID      string
	egressUID       string
	ingressAttached bool
	egressAttached  bool
	announced       bool
}

func (p *Probe) startInterfaceWatcher(parent context.Context) {
	if p == nil || p.config == nil || p.bpfManager == nil ||
		p.pcapWriter == nil || !p.config.WatchInterfaces ||
		!p.config.HasStrategy(StrategyRawPackets) ||
		p.interfaceWatcherCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	p.interfaceWatcherCancel = cancel
	p.interfaceWatcherDone = done
	go p.watchInterfaces(ctx, done)
}

func (p *Probe) stopInterfaceWatcher() {
	if p == nil || p.interfaceWatcherCancel == nil {
		return
	}
	p.interfaceWatcherCancel()
	if p.interfaceWatcherDone != nil {
		<-p.interfaceWatcherDone
	}
	p.interfaceWatcherCancel = nil
	p.interfaceWatcherDone = nil
}

func (p *Probe) watchInterfaces(ctx context.Context, done chan struct{}) {
	defer close(done)

	configured := make(map[int]string)
	for _, name := range p.config.Interfaces() {
		if iface, err := net.InterfaceByName(name); err == nil {
			configured[iface.Index] = iface.Name
		}
	}
	initialMissing := make(map[int]bool)
	dynamic := make(map[int]*dynamicTCAttachment)
	generation := uint64(0)
	interfaces := p.config.Interfaces()
	if len(interfaces) == 0 {
		return
	}
	sourceIngressUID := "tc_ingress_" + interfaces[0]
	sourceEgressUID := "tc_egress_" + interfaces[0]

	reconcile := func() {
		up, err := upInterfaceSnapshot()
		if err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to enumerate runtime interfaces")
			return
		}

		for index := range configured {
			if _, found := up[index]; !found {
				initialMissing[index] = true
			}
		}
		for index, attachment := range dynamic {
			name, found := up[index]
			if found && name == attachment.name {
				continue
			}
			p.detachDynamicTC(attachment)
			delete(dynamic, index)
		}

		for index, name := range up {
			if initialName, found := configured[index]; found &&
				initialName == name && !initialMissing[index] {
				continue
			}
			attachment := dynamic[index]
			if attachment == nil {
				generation++
				attachment = &dynamicTCAttachment{
					name:       name,
					index:      index,
					ingressUID: fmt.Sprintf("tc_dynamic_ingress_%d_%d", index, generation),
					egressUID:  fmt.Sprintf("tc_dynamic_egress_%d_%d", index, generation),
				}
				dynamic[index] = attachment
			}
			if err := p.pcapWriter.RegisterInterface(name, uint32(index)); err != nil {
				p.Logger().Warn().Err(err).
					Str("interface", name).Int("ifindex", index).
					Msg("Failed to register runtime PCAPNG interface")
				continue
			}
			if !attachment.ingressAttached {
				attachment.ingressAttached = p.attachDynamicTC(
					sourceIngressUID, attachment.ingressUID, name,
					base.TcFuncNameIngress, manager.Ingress,
				)
			}
			if !attachment.egressAttached {
				attachment.egressAttached = p.attachDynamicTC(
					sourceEgressUID, attachment.egressUID, name,
					base.TcFuncNameEgress, manager.Egress,
				)
			}
			if attachment.ingressAttached && attachment.egressAttached &&
				!attachment.announced {
				attachment.announced = true
				p.Logger().Info().
					Str("interface", name).Int("ifindex", index).
					Msg("Attached packet capture to runtime interface")
			}
		}
	}

	reconcile()
	ticker := time.NewTicker(interfaceReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile()
		}
	}
}

func upInterfaceSnapshot() (map[int]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make(map[int]string, len(interfaces))
	for _, iface := range interfaces {
		if iface.Index <= 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		result[iface.Index] = iface.Name
	}
	return result, nil
}

func (p *Probe) attachDynamicTC(
	sourceUID, uid, ifname, functionName string,
	direction manager.TrafficType,
) bool {
	err := p.bpfManager.AddHook(sourceUID, &manager.Probe{
		Section:          "classifier",
		EbpfFuncName:     functionName,
		Ifname:           ifname,
		NetworkDirection: direction,
		UID:              uid,
	})
	if err != nil {
		p.Logger().Warn().Err(err).
			Str("interface", ifname).Str("direction", functionName).
			Msg("Failed to attach packet capture to runtime interface")
		return false
	}
	return true
}

func (p *Probe) detachDynamicTC(attachment *dynamicTCAttachment) {
	if attachment == nil || p.bpfManager == nil {
		return
	}
	if attachment.ingressAttached {
		if err := p.bpfManager.DetachHook(
			base.TcFuncNameIngress, attachment.ingressUID,
		); err != nil {
			p.Logger().Debug().Err(err).
				Str("interface", attachment.name).
				Msg("Runtime ingress hook already detached")
		}
	}
	if attachment.egressAttached {
		if err := p.bpfManager.DetachHook(
			base.TcFuncNameEgress, attachment.egressUID,
		); err != nil {
			p.Logger().Debug().Err(err).
				Str("interface", attachment.name).
				Msg("Runtime egress hook already detached")
		}
	}
}
