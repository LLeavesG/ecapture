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

package reconstruction

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const wirePacketFlagRawIP = 0x08

type wirePacketKey struct {
	pid       uint32
	direction string
	transport string
	tuple     string
}

type wirePacketSegment struct {
	sequence  uint32
	timestamp uint64
	data      []byte
}

type wirePacketRun struct {
	key          wirePacketKey
	data         []byte
	firstSeen    uint64
	lastSeen     uint64
	socketCookie uint64
}

type wirePacketFlow struct {
	key          wirePacketKey
	segments     []wirePacketSegment
	datagrams    []wirePacketSegment
	socketCookie uint64
}

type wirePacketCollector struct {
	flows map[wirePacketKey]*wirePacketFlow
}

type structuredPacketEvent struct {
	Timestamp    uint64 `json:"Timestamp"`
	Pid          uint32 `json:"Pid"`
	Flags        uint32 `json:"Flags"`
	Direction    uint8  `json:"Direction"`
	SocketCookie uint64 `json:"SocketCookie"`
	PacketData   []byte `json:"PacketData"`
}

func newWirePacketCollector() *wirePacketCollector {
	return &wirePacketCollector{flows: make(map[wirePacketKey]*wirePacketFlow)}
}

func (collector *wirePacketCollector) observe(raw json.RawMessage) {
	var event structuredPacketEvent
	if err := json.Unmarshal(raw, &event); err != nil ||
		event.Timestamp == 0 || event.Pid == 0 || len(event.PacketData) == 0 {
		return
	}

	firstLayer := gopacket.Decoder(layers.LayerTypeEthernet)
	if event.Flags&wirePacketFlagRawIP != 0 {
		switch event.PacketData[0] >> 4 {
		case 4:
			firstLayer = layers.LayerTypeIPv4
		case 6:
			firstLayer = layers.LayerTypeIPv6
		default:
			return
		}
	}
	packet := gopacket.NewPacket(event.PacketData, firstLayer, gopacket.NoCopy)
	network := packet.NetworkLayer()
	if network == nil {
		return
	}
	srcNetwork, dstNetwork := network.NetworkFlow().Endpoints()
	direction := "READ"
	if event.Direction != 0 {
		direction = "WRITE"
	}

	var (
		transport string
		srcPort   uint16
		dstPort   uint16
		sequence  uint32
		payload   []byte
	)
	switch layer := packet.TransportLayer().(type) {
	case *layers.TCP:
		transport = "tcp"
		srcPort = uint16(layer.SrcPort)
		dstPort = uint16(layer.DstPort)
		sequence = layer.Seq
		payload = layer.Payload
	case *layers.UDP:
		transport = "udp"
		srcPort = uint16(layer.SrcPort)
		dstPort = uint16(layer.DstPort)
		payload = layer.Payload
	default:
		return
	}
	if len(payload) == 0 {
		return
	}

	key := wirePacketKey{
		pid:       event.Pid,
		direction: direction,
		transport: transport,
		tuple: fmt.Sprintf(
			"%s:%d->%s:%d",
			srcNetwork.String(),
			srcPort,
			dstNetwork.String(),
			dstPort,
		),
	}
	flow := collector.flows[key]
	if flow == nil {
		flow = &wirePacketFlow{key: key}
		collector.flows[key] = flow
	}
	if event.SocketCookie != 0 {
		flow.socketCookie = event.SocketCookie
	}
	segment := wirePacketSegment{
		sequence:  sequence,
		timestamp: event.Timestamp,
		data:      append([]byte(nil), payload...),
	}
	if transport == "tcp" {
		flow.segments = append(flow.segments, segment)
	} else {
		flow.datagrams = append(flow.datagrams, segment)
	}
}

func (collector *wirePacketCollector) runs() []wirePacketRun {
	var runs []wirePacketRun
	for _, flow := range collector.flows {
		if flow.key.transport == "udp" {
			for _, datagram := range flow.datagrams {
				runs = append(runs, wirePacketRun{
					key:          flow.key,
					data:         datagram.data,
					firstSeen:    datagram.timestamp,
					lastSeen:     datagram.timestamp,
					socketCookie: flow.socketCookie,
				})
			}
			continue
		}
		runs = append(runs, assembleTCPPacketRuns(flow)...)
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].key.pid != runs[j].key.pid {
			return runs[i].key.pid < runs[j].key.pid
		}
		if runs[i].key.direction != runs[j].key.direction {
			return runs[i].key.direction < runs[j].key.direction
		}
		if runs[i].key.tuple != runs[j].key.tuple {
			return runs[i].key.tuple < runs[j].key.tuple
		}
		return runs[i].firstSeen < runs[j].firstSeen
	})
	return runs
}

func assembleTCPPacketRuns(flow *wirePacketFlow) []wirePacketRun {
	if flow == nil || len(flow.segments) == 0 {
		return nil
	}
	sort.SliceStable(flow.segments, func(i, j int) bool {
		if flow.segments[i].sequence == flow.segments[j].sequence {
			return len(flow.segments[i].data) > len(flow.segments[j].data)
		}
		return flow.segments[i].sequence < flow.segments[j].sequence
	})

	var runs []wirePacketRun
	var current *wirePacketRun
	var start uint32
	for _, segment := range flow.segments {
		if current == nil {
			current = &wirePacketRun{
				key:          flow.key,
				data:         append([]byte(nil), segment.data...),
				firstSeen:    segment.timestamp,
				lastSeen:     segment.timestamp,
				socketCookie: flow.socketCookie,
			}
			start = segment.sequence
			continue
		}
		end := uint64(start) + uint64(len(current.data))
		segmentStart := uint64(segment.sequence)
		segmentEnd := segmentStart + uint64(len(segment.data))
		if segmentStart > end {
			runs = append(runs, *current)
			current = &wirePacketRun{
				key:          flow.key,
				data:         append([]byte(nil), segment.data...),
				firstSeen:    segment.timestamp,
				lastSeen:     segment.timestamp,
				socketCookie: flow.socketCookie,
			}
			start = segment.sequence
			continue
		}
		if segment.timestamp < current.firstSeen {
			current.firstSeen = segment.timestamp
		}
		if segment.timestamp > current.lastSeen {
			current.lastSeen = segment.timestamp
		}
		if segmentEnd <= end {
			continue
		}
		overlap := end - segmentStart
		current.data = append(current.data, segment.data[overlap:]...)
	}
	if current != nil {
		runs = append(runs, *current)
	}
	return runs
}
