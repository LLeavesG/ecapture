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

package base

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gojue/ecapture/internal/domain"
)

const readerStatsEmitEveryRecords uint64 = 4096
const readerStatsEmitInterval = time.Second

type readerStatsCounters struct {
	perfRecords     atomic.Uint64
	perfRawBytes    atomic.Uint64
	ringbufRecords  atomic.Uint64
	ringbufRawBytes atomic.Uint64
	lostSamples     atomic.Uint64
	readErrors      atomic.Uint64
	decodeErrors    atomic.Uint64
	dispatchErrors  atomic.Uint64
}

// ReaderStatsSnapshot is a stable, structured view of perf/ringbuf pressure.
// It is emitted periodically and once more when the probe closes.
type ReaderStatsSnapshot struct {
	PerfRecords     uint64 `json:"perfRecords"`
	PerfRawBytes    uint64 `json:"perfRawBytes"`
	RingbufRecords  uint64 `json:"ringbufRecords"`
	RingbufRawBytes uint64 `json:"ringbufRawBytes"`
	LostSamples     uint64 `json:"lostSamples"`
	ReadErrors      uint64 `json:"readErrors"`
	DecodeErrors    uint64 `json:"decodeErrors"`
	DispatchErrors  uint64 `json:"dispatchErrors"`
}

func (p *BaseProbe) ReaderStats() ReaderStatsSnapshot {
	if p == nil {
		return ReaderStatsSnapshot{}
	}
	return ReaderStatsSnapshot{
		PerfRecords:     p.readerStats.perfRecords.Load(),
		PerfRawBytes:    p.readerStats.perfRawBytes.Load(),
		RingbufRecords:  p.readerStats.ringbufRecords.Load(),
		RingbufRawBytes: p.readerStats.ringbufRawBytes.Load(),
		LostSamples:     p.readerStats.lostSamples.Load(),
		ReadErrors:      p.readerStats.readErrors.Load(),
		DecodeErrors:    p.readerStats.decodeErrors.Load(),
		DispatchErrors:  p.readerStats.dispatchErrors.Load(),
	}
}

func (p *BaseProbe) noteReaderRecord(ringbufRecord bool, rawBytes int) {
	if p == nil {
		return
	}
	if rawBytes < 0 {
		rawBytes = 0
	}
	if ringbufRecord {
		p.readerStats.ringbufRecords.Add(1)
		p.readerStats.ringbufRawBytes.Add(uint64(rawBytes))
	} else {
		p.readerStats.perfRecords.Add(1)
		p.readerStats.perfRawBytes.Add(uint64(rawBytes))
	}
	total := p.readerStats.perfRecords.Load() +
		p.readerStats.ringbufRecords.Load()
	for {
		next := p.nextStatsAt.Load()
		if next == 0 || total < next {
			return
		}
		if p.nextStatsAt.CompareAndSwap(
			next,
			next+readerStatsEmitEveryRecords,
		) {
			p.dispatchReaderStats(false)
			return
		}
	}
}

func (p *BaseProbe) startReaderStatsReporter() {
	if p == nil {
		return
	}
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	if p.statsCancel != nil {
		return
	}
	reporterCtx, cancel := context.WithCancel(p.ctx)
	p.statsCancel = cancel
	p.statsW.Add(1)
	go func() {
		defer p.statsW.Done()
		ticker := time.NewTicker(readerStatsEmitInterval)
		defer ticker.Stop()
		for {
			select {
			case <-reporterCtx.Done():
				return
			case <-ticker.C:
				p.dispatchReaderStats(false)
			}
		}
	}()
}

func (p *BaseProbe) stopReaderStatsReporter() {
	if p == nil {
		return
	}
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	if p.statsCancel == nil {
		return
	}
	p.statsCancel()
	p.statsW.Wait()
	p.statsCancel = nil
}

func (p *BaseProbe) dispatchReaderStats(final bool) {
	if p == nil || p.dispatcher == nil {
		return
	}
	stats := p.ReaderStats()
	if stats.PerfRecords == 0 &&
		stats.RingbufRecords == 0 &&
		stats.LostSamples == 0 &&
		stats.ReadErrors == 0 &&
		stats.DecodeErrors == 0 &&
		stats.DispatchErrors == 0 {
		return
	}
	event := &ReaderStatsEvent{
		EventType:           "capture_stats",
		Probe:               p.name,
		Final:               final,
		Timestamp:           time.Now().UTC(),
		ReaderStatsSnapshot: stats,
	}
	if err := p.dispatcher.Dispatch(event); err != nil {
		p.readerStats.dispatchErrors.Add(1)
		if p.logger != nil {
			p.logger.Warn().Err(err).Msg("Failed to dispatch capture statistics")
		}
	}
}

// ReaderStatsEvent implements domain.Event so the existing event writer can
// expose loss and throughput metrics without a second output channel.
type ReaderStatsEvent struct {
	EventType string    `json:"eventType"`
	Probe     string    `json:"probe"`
	Final     bool      `json:"final"`
	Timestamp time.Time `json:"timestamp"`
	ReaderStatsSnapshot
}

func (e *ReaderStatsEvent) DecodeFromBytes([]byte) error {
	return fmt.Errorf("capture statistics are generated in userspace")
}

func (e *ReaderStatsEvent) String() string {
	return fmt.Sprintf(
		"capture stats: probe=%s perf_records=%d ringbuf_records=%d lost_samples=%d read_errors=%d decode_errors=%d dispatch_errors=%d final=%t",
		e.Probe,
		e.PerfRecords,
		e.RingbufRecords,
		e.LostSamples,
		e.ReadErrors,
		e.DecodeErrors,
		e.DispatchErrors,
		e.Final,
	)
}

func (e *ReaderStatsEvent) StringHex() string {
	return e.String()
}

func (e *ReaderStatsEvent) Clone() domain.Event {
	if e == nil {
		return (*ReaderStatsEvent)(nil)
	}
	clone := *e
	return &clone
}

func (e *ReaderStatsEvent) Type() domain.EventType {
	return domain.EventTypeOutput
}

func (e *ReaderStatsEvent) UUID() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf(
		"capture-stats-%s-%d-%t",
		e.Probe,
		e.Timestamp.UnixNano(),
		e.Final,
	)
}

func (e *ReaderStatsEvent) Validate() error {
	if e == nil {
		return fmt.Errorf("capture statistics event is nil")
	}
	if strings.TrimSpace(e.Probe) == "" {
		return fmt.Errorf("capture statistics probe is empty")
	}
	return nil
}
