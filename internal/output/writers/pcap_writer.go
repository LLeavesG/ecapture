// Copyright 2024 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package writers

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/gojue/ecapture/internal/errors"
	lger "github.com/gojue/ecapture/internal/logger"
)

type TcPacket struct {
	ci   gopacket.CaptureInfo
	data []byte
}

// PcapWriter handles writing network packets in PCAPNG format
type PcapWriter struct {
	writer           *pcapgo.NgWriter
	interfaceIDs     map[uint32]pcapInterfaceIDs
	interfaceNames   map[uint32]string
	interfaceMu      sync.RWMutex
	defaultInterface pcapInterfaceIDs
	snaplen          uint32
	filter           string
	ctx              context.Context
	ctxCancel        context.CancelFunc

	tcPackets       []*TcPacket
	packetChan      chan *TcPacket
	interfaceChan   chan pcapInterfaceRegistration
	keylogChan      chan []byte // channel for DSB (keylog) writes, serialized with packet writes
	serveDone       chan struct{}
	packetCount     int
	firstDSBWritten bool // true after the first DSB has been written to the file
	expectKeylog    atomic.Bool
	isClosed        bool
	logger          *lger.Logger
}

type pcapInterfaceIDs struct {
	ethernet int
	rawIP    int
}

type pcapInterfaceRegistration struct {
	name        string
	systemIndex uint32
	done        chan error
}

// NewPcapWriter creates a new PCAPNG writer
func NewPcapWriter(w io.Writer, snaplen uint32, ifName, filter string, logger *lger.Logger) (*PcapWriter, error) {
	return NewPcapWriterInterfaces(w, snaplen, []string{ifName}, filter, logger)
}

// NewPcapWriterInterfaces creates PCAPNG interface descriptions for every
// monitored system interface. Each interface gets Ethernet and raw-IP
// descriptions so TUN traffic can be represented without corrupt link types.
func NewPcapWriterInterfaces(
	w io.Writer, snaplen uint32, ifNames []string, filter string, logger *lger.Logger,
) (*PcapWriter, error) {
	if len(ifNames) == 0 {
		return nil, fmt.Errorf("at least one pcap interface is required")
	}

	// TODO : write Application "ecapture.lua" to decode PID/Comm info.
	pcapOption := pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    "eCapture (旁观者) Hardware",
			OS:          "Linux/Android",
			Application: "ecapture.lua",
			Comment:     "see https://ecapture.cc for more information. CFC4N <cfc4n.cs@gmail.com>",
		},
	}
	firstName := ifNames[0]
	firstRaw := interfacePrefersRawIP(firstName)
	firstLinkType := layers.LinkTypeEthernet
	if firstRaw {
		firstLinkType = layers.LinkTypeRaw
	}
	pcapWriter, err := pcapgo.NewNgWriterInterface(
		w, makeNgInterface(firstName, filter, snaplen, firstLinkType), pcapOption,
	)
	if err != nil {
		return nil, err
	}

	interfaceIDs := make(map[uint32]pcapInterfaceIDs, len(ifNames))
	interfaceNames := make(map[uint32]string, len(ifNames))
	firstIDs := pcapInterfaceIDs{}
	if firstRaw {
		firstIDs.rawIP = 0
		firstIDs.ethernet, err = pcapWriter.AddInterface(
			makeNgInterface(firstName, filter, snaplen, layers.LinkTypeEthernet),
		)
	} else {
		firstIDs.ethernet = 0
		firstIDs.rawIP, err = pcapWriter.AddInterface(
			makeNgInterface(firstName, filter, snaplen, layers.LinkTypeRaw),
		)
	}
	if err != nil {
		return nil, err
	}
	if systemIndex := systemInterfaceIndex(firstName); systemIndex != 0 {
		interfaceIDs[systemIndex] = firstIDs
		interfaceNames[systemIndex] = firstName
	}

	for _, ifName := range ifNames[1:] {
		ethernetID, addErr := pcapWriter.AddInterface(
			makeNgInterface(ifName, filter, snaplen, layers.LinkTypeEthernet),
		)
		if addErr != nil {
			return nil, addErr
		}
		rawID, addErr := pcapWriter.AddInterface(
			makeNgInterface(ifName, filter, snaplen, layers.LinkTypeRaw),
		)
		if addErr != nil {
			return nil, addErr
		}
		if systemIndex := systemInterfaceIndex(ifName); systemIndex != 0 {
			interfaceIDs[systemIndex] = pcapInterfaceIDs{ethernet: ethernetID, rawIP: rawID}
			interfaceNames[systemIndex] = ifName
		}
	}

	// Flush the header
	err = pcapWriter.Flush()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	pw := &PcapWriter{
		writer:           pcapWriter,
		interfaceIDs:     interfaceIDs,
		interfaceNames:   interfaceNames,
		defaultInterface: firstIDs,
		snaplen:          snaplen,
		filter:           filter,
		packetChan:       make(chan *TcPacket, 8192),
		interfaceChan:    make(chan pcapInterfaceRegistration, 32),
		keylogChan:       make(chan []byte, 256),
		serveDone:        make(chan struct{}),
		ctx:              ctx,
		ctxCancel:        cancel,
		tcPackets:        []*TcPacket{},
		isClosed:         false,
		logger:           logger,
	}
	// Preserve the historical DSB-first behavior until the owning probe says
	// key extraction is disabled.
	pw.expectKeylog.Store(true)
	go pw.Serve()
	return pw, nil
}

// SetExpectKeylog controls the short DSB-first buffering window. Wire-only
// capture disables it so packets flush on the first timer tick.
func (pw *PcapWriter) SetExpectKeylog(expect bool) {
	if pw == nil {
		return
	}
	pw.expectKeylog.Store(expect)
}

// WritePacket writes a packet to the PCAPNG file
func (pw *PcapWriter) WritePacket(data []byte, timestamp time.Time) error {
	return pw.WritePacketForInterface(
		data, timestamp, 0, false, uint32(len(data)),
	)
}

func (pw *PcapWriter) WritePacketForInterface(
	data []byte,
	timestamp time.Time,
	systemInterfaceIndex uint32,
	rawIP bool,
	originalLength uint32,
) error {
	if originalLength < uint32(len(data)) {
		originalLength = uint32(len(data))
	}
	pw.interfaceMu.RLock()
	ids, found := pw.interfaceIDs[systemInterfaceIndex]
	if !found {
		ids = pw.defaultInterface
	}
	pw.interfaceMu.RUnlock()
	interfaceIndex := ids.ethernet
	if rawIP {
		interfaceIndex = ids.rawIP
	}
	captureInfo := gopacket.CaptureInfo{
		Timestamp:      timestamp,
		CaptureLength:  len(data),
		Length:         int(originalLength),
		InterfaceIndex: interfaceIndex,
	}

	select {
	case pw.packetChan <- &TcPacket{ci: captureInfo, data: data}:
		return nil
	case <-pw.ctx.Done():
		return fmt.Errorf("pcap writer is closed")
	}
}

// RegisterInterface adds PCAPNG interface-description blocks for an interface
// discovered after capture startup. NgWriter is not concurrency-safe, so the
// request is executed by Serve alongside packet and keylog writes.
func (pw *PcapWriter) RegisterInterface(name string, systemIndex uint32) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("pcap interface name is empty")
	}
	if systemIndex == 0 {
		return fmt.Errorf("pcap interface %q has invalid system index 0", name)
	}

	pw.interfaceMu.RLock()
	registeredName, found := pw.interfaceNames[systemIndex]
	pw.interfaceMu.RUnlock()
	if found && registeredName == name {
		return nil
	}

	request := pcapInterfaceRegistration{
		name:        name,
		systemIndex: systemIndex,
		done:        make(chan error, 1),
	}
	select {
	case pw.interfaceChan <- request:
	case <-pw.ctx.Done():
		return fmt.Errorf("pcap writer is closed")
	}
	select {
	case err := <-request.done:
		return err
	case <-pw.ctx.Done():
		return fmt.Errorf("pcap writer closed while registering interface %q", name)
	}
}

func (pw *PcapWriter) registerInterface(request pcapInterfaceRegistration) error {
	pw.interfaceMu.RLock()
	registeredName, found := pw.interfaceNames[request.systemIndex]
	pw.interfaceMu.RUnlock()
	if found && registeredName == request.name {
		return nil
	}

	ethernetID, err := pw.writer.AddInterface(
		makeNgInterface(request.name, pw.filter, pw.snaplen, layers.LinkTypeEthernet),
	)
	if err != nil {
		return fmt.Errorf("add Ethernet PCAPNG interface %q: %w", request.name, err)
	}
	rawID, err := pw.writer.AddInterface(
		makeNgInterface(request.name, pw.filter, pw.snaplen, layers.LinkTypeRaw),
	)
	if err != nil {
		return fmt.Errorf("add raw-IP PCAPNG interface %q: %w", request.name, err)
	}
	if err := pw.writer.Flush(); err != nil {
		return fmt.Errorf("flush PCAPNG interface %q: %w", request.name, err)
	}

	pw.interfaceMu.Lock()
	pw.interfaceIDs[request.systemIndex] = pcapInterfaceIDs{
		ethernet: ethernetID,
		rawIP:    rawID,
	}
	pw.interfaceNames[request.systemIndex] = request.name
	pw.interfaceMu.Unlock()
	return nil
}

// Serve processes packets and keylogs from channels and writes them to the PCAPNG writer.
// All NgWriter operations are serialized in this single goroutine to avoid concurrent access.
func (pw *PcapWriter) Serve() {
	defer close(pw.serveDone)

	ti := time.NewTicker(2 * time.Second)
	defer ti.Stop()

	// dsbGraceDeadline: don't flush packets to disk until the first DSB arrives
	// or this deadline passes, so the DSB appears before packets in the pcapng file.
	// Wireshark processes blocks sequentially and needs the DSB before encrypted packets.
	// 3 seconds is sufficient since TLS handshakes typically complete in under 1 second.
	dsbGraceDeadline := time.Now().Add(3 * time.Second)

	var i int
	for {
		select {
		case <-ti.C:
			if i == 0 || len(pw.tcPackets) == 0 {
				continue
			}
			// Delay flushing packets until the first DSB is written (or grace period expires).
			// This ensures the DSB precedes packets in the pcapng file so Wireshark can decrypt.
			if pw.expectKeylog.Load() &&
				!pw.firstDSBWritten &&
				time.Now().Before(dsbGraceDeadline) {
				continue
			}
			n, e := pw.savePcapng()
			if e != nil {
				pw.logger.Warn().Err(e).Int("count", i).Msg("save pcapng err, maybe some packets lost.")
			} else {
				pw.packetCount += n
			}

			// reset counter, and reset tcPackets array
			i = 0
			pw.tcPackets = pw.tcPackets[:0]
		case packet, ok := <-pw.packetChan:
			if !ok {
				// Channel closed — drain any remaining packets and exit
				if len(pw.tcPackets) > 0 {
					n, e := pw.savePcapng()
					if e != nil {
						pw.logger.Warn().Err(e).Int("count", i).Msg("save pcapng err on close, maybe some packets lost.")
					} else {
						pw.packetCount += n
					}
				}
				return
			}
			pw.tcPackets = append(pw.tcPackets, packet)
			i++
		case request := <-pw.interfaceChan:
			request.done <- pw.registerInterface(request)
		case keylogLine, ok := <-pw.keylogChan:
			if !ok {
				// Channel closed — nil out to remove from select, preventing CPU spin.
				// (Receiving from a closed channel returns zero value immediately.)
				pw.keylogChan = nil
				continue
			}
			// Write DSB (Decryption Secrets Block) BEFORE flushing pending packets.
			// Wireshark processes pcapng blocks sequentially and needs the DSB to appear
			// before the encrypted packet blocks in order to decrypt them.
			if e := pw.writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylogLine); e != nil {
				pw.logger.Warn().Err(e).Msg("failed to write DSB to pcapng")
			}
			if e := pw.writer.Flush(); e != nil {
				pw.logger.Warn().Err(e).Msg("failed to flush after DSB write")
			}
			pw.firstDSBWritten = true

			// Now flush any pending (buffered) packets AFTER the DSB
			if len(pw.tcPackets) > 0 {
				n, e := pw.savePcapng()
				if e != nil {
					pw.logger.Warn().Err(e).Int("count", i).Msg("save pcapng err after DSB, maybe some packets lost.")
				} else {
					pw.packetCount += n
				}
				i = 0
				pw.tcPackets = pw.tcPackets[:0]
			}
		case <-pw.ctx.Done():
			// Context canceled — drain all remaining data from channels before exiting
			pw.drainOnShutdown()
			return
		}
	}
}

// drainOnShutdown drains remaining packets and keylogs from channels and writes
// them to the PCAPNG file. Called only from Serve() on context cancellation.
// DSBs are written before packets to ensure Wireshark can decrypt the traffic.
func (pw *PcapWriter) drainOnShutdown() {
	// Drain remaining packets from packetChan into buffer (don't write yet)
drainPackets:
	for {
		select {
		case packet, ok := <-pw.packetChan:
			if !ok {
				break drainPackets
			}
			pw.tcPackets = append(pw.tcPackets, packet)
		default:
			break drainPackets
		}
	}

	// Drain remaining keylogs and write DSBs FIRST (before packets)
drainKeylogs:
	for {
		select {
		case keylog, ok := <-pw.keylogChan:
			if !ok {
				break drainKeylogs
			}
			if e := pw.writer.WriteDecryptionSecretsBlock(pcapgo.DSB_SECRETS_TYPE_TLS, keylog); e != nil {
				pw.logger.Warn().Err(e).Msg("failed to write DSB on shutdown")
			}
		default:
			break drainKeylogs
		}
	}

	// Now save all buffered packets (after DSBs)
	if len(pw.tcPackets) > 0 {
		n, e := pw.savePcapng()
		if e != nil {
			pw.logger.Info().Err(e).Msg("save pcapng err on shutdown, maybe some packets lost.")
		} else {
			pw.logger.Info().Int("count", n).Msg("packets saved into pcapng file on shutdown.")
			pw.packetCount += n
		}
		pw.tcPackets = pw.tcPackets[:0]
	}

	// Final flush after draining all data
	if e := pw.writer.Flush(); e != nil {
		pw.logger.Warn().Err(e).Msg("failed to flush on shutdown")
	}
}

// savePcapng writes all buffered packets and flushes the writer
func (pw *PcapWriter) savePcapng() (i int, err error) {
	for _, packet := range pw.tcPackets {
		err = pw.writer.WritePacket(packet.ci, packet.data)
		i++
		if err != nil {
			return
		}
	}

	if i == 0 {
		return
	}
	err = pw.writer.Flush()
	return
}

// writePacket writes a single packet to the PCAPNG writer
func (pw *PcapWriter) writePacket(pc *TcPacket) error {
	return pw.writer.WritePacket(pc.ci, pc.data)
}

// WriteKeyLog writes TLS master secret as a Decryption Secrets Block (DSB).
// The actual write is serialized through the Serve goroutine to avoid concurrent
// access to the underlying NgWriter (which is not thread-safe).
func (pw *PcapWriter) WriteKeyLog(keylogLine []byte) error {
	// Make a copy to avoid the caller modifying the data after sending
	data := make([]byte, len(keylogLine))
	copy(data, keylogLine)

	select {
	case pw.keylogChan <- data:
	default:
		return fmt.Errorf("keylog write channel full")
	}
	return nil
}

// Flush ensures all buffered data is written to disk.
// While the Serve goroutine is running, all NgWriter operations are serialized there
// and flushing happens automatically (on timer ticks, DSB writes, and shutdown).
// Direct flush is only performed after Serve has exited to avoid concurrent access.
func (pw *PcapWriter) Flush() error {
	select {
	case <-pw.serveDone:
		// Serve has exited — safe to flush directly
		return pw.writer.Flush()
	default:
		// Serve is still running — it handles flushing internally
		return nil
	}
}

// Close closes the PCAPNG writer and flushes any buffered data.
// This should be called when the program exits to ensure all data is written.
func (pw *PcapWriter) Close() error {
	if pw.isClosed {
		return nil
	}
	defer func() {
		pw.isClosed = true
	}()

	// Stop the Serve goroutine by canceling its context.
	// The Serve goroutine will flush remaining packets before exiting.
	pw.ctxCancel()

	// Wait for the Serve goroutine to finish all pending writes.
	// This ensures no concurrent access to the NgWriter after this point.
	<-pw.serveDone

	// Close channels so they don't leak (Serve has already exited).
	close(pw.packetChan)
	close(pw.keylogChan)

	// Final flush to ensure all data is written to the underlying writer
	if err := pw.Flush(); err != nil {
		return err
	}

	// Close the writer if it implements io.Closer
	if closer, ok := any(pw.writer).(io.Closer); ok {
		return closer.Close()
	}

	if pw.packetCount == 0 {
		return errors.Wrap(errors.ErrCodeEventNotReady, "nothing captured, please check your network interface, see \"ecapture tls -h\" for more information.", nil)
	}

	return nil
}

func (pw *PcapWriter) Name() string {
	return "pcap_writer"
}

func makeNgInterface(name, filter string, snaplen uint32, linkType layers.LinkType) pcapgo.NgInterface {
	return pcapgo.NgInterface{
		Name:       name,
		Comment:    "eCapture (旁观者): github.com/gojue/ecapture",
		Filter:     filter,
		LinkType:   linkType,
		SnapLength: snaplen,
	}
}

func systemInterfaceIndex(name string) uint32 {
	iface, err := net.InterfaceByName(name)
	if err != nil || iface.Index < 0 {
		return 0
	}
	return uint32(iface.Index)
}

func interfacePrefersRawIP(name string) bool {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", name, "type"))
	if err != nil {
		return false
	}
	hardwareType, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}
	const (
		arphrdNone = 0xfffe
		arphrdRaw  = 0x0300
	)
	return hardwareType == arphrdNone || hardwareType == arphrdRaw
}

// nullTerminatedString returns the string up to the first null byte
func nullTerminatedString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
