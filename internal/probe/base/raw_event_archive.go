// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package base

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
)

const (
	rawEventArchiveMagic   = "ECAPRAW1"
	rawEventArchiveVersion = uint16(1)
	rawEventSourcePerf     = uint8(1)
	rawEventSourceRingbuf  = uint8(2)
	rawEventFlagLost       = uint8(1)
	rawEventFrameHeaderLen = 32
)

// rawEventArchive preserves every perf/ringbuf sample before decoding. Each
// frame records its source map and a global write sequence so independent
// readers can be replayed without treating concurrent read order as kernel
// trigger order. The decoded JSON stream remains the canonical analysis input.
type rawEventArchive struct {
	mu       sync.Mutex
	file     *os.File
	sequence uint64
}

func newRawEventArchive(path string) (*rawEventArchive, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create raw event archive: %w", err)
	}
	if _, err = file.Write([]byte(rawEventArchiveMagic)); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("write raw event archive header: %w", err)
	}
	return &rawEventArchive{file: file}, nil
}

func (archive *rawEventArchive) write(
	source uint8,
	mapName string,
	lostSamples uint64,
	raw []byte,
) error {
	if archive == nil || archive.file == nil {
		return fmt.Errorf("raw event archive is closed")
	}
	if len(mapName) > int(^uint16(0)) {
		return fmt.Errorf("raw event map name is too long: %d", len(mapName))
	}
	if uint64(len(raw)) > uint64(^uint32(0)) {
		return fmt.Errorf("raw event sample is too large: %d", len(raw))
	}

	archive.mu.Lock()
	defer archive.mu.Unlock()
	archive.sequence++
	flags := uint8(0)
	if lostSamples != 0 {
		flags |= rawEventFlagLost
	}
	recordLength := rawEventFrameHeaderLen - 4 + len(mapName) + len(raw)
	frame := make([]byte, rawEventFrameHeaderLen+len(mapName)+len(raw))
	binary.LittleEndian.PutUint32(frame[0:4], uint32(recordLength))
	binary.LittleEndian.PutUint16(frame[4:6], rawEventArchiveVersion)
	frame[6] = source
	frame[7] = flags
	binary.LittleEndian.PutUint64(frame[8:16], archive.sequence)
	binary.LittleEndian.PutUint64(frame[16:24], lostSamples)
	binary.LittleEndian.PutUint16(frame[24:26], uint16(len(mapName)))
	binary.LittleEndian.PutUint32(frame[28:32], uint32(len(raw)))
	copy(frame[rawEventFrameHeaderLen:], mapName)
	copy(frame[rawEventFrameHeaderLen+len(mapName):], raw)
	if _, err := archive.file.Write(frame); err != nil {
		return fmt.Errorf("write raw event archive frame: %w", err)
	}
	return nil
}

func (archive *rawEventArchive) Close() error {
	if archive == nil {
		return nil
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if archive.file == nil {
		return nil
	}
	err := archive.file.Close()
	archive.file = nil
	return err
}
