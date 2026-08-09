// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
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

package openssl

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	manager "github.com/gojue/ebpfmanager"
	"golang.org/x/sys/unix"

	pkgebpf "github.com/gojue/ecapture/pkg/util/ebpf"

	"github.com/gojue/ecapture/internal/output/writers"

	"github.com/gojue/ecapture/internal/factory"

	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/internal/domain"
	"github.com/gojue/ecapture/internal/errors"
	"github.com/gojue/ecapture/internal/probe/base"
	"github.com/gojue/ecapture/internal/probe/base/handlers"
	"github.com/gojue/ecapture/pkg/util/kernel"
)

const offsetHookPlaceholder = "__ecapture_offset__"

// Probe implements the OpenSSL TLS tracing probe.
// Supports Text mode, Keylog mode, and Pcap mode.
type Probe struct {
	*base.BaseProbe
	config           *Config
	bpfManager       *manager.Manager
	eventFuncMaps    map[*ebpf.Map]domain.EventDecoder
	mapNameToDecoder map[string]domain.EventDecoder // Maps configured in setupManager
	eventMaps        []*ebpf.Map
	output           io.Writer
	closer           []io.Closer
	pcapWriter       *writers.PcapWriter

	interfaceWatcherCancel  context.CancelFunc
	interfaceWatcherDone    chan struct{}
	relatedUIDWatcherCancel context.CancelFunc
	relatedUIDWatcherDone   chan struct{}

	sslBpfFile      string
	isBoringSSL     bool
	masterHookFuncs []string
	archiveUprobes  []archiveUprobeSpec
	dwarfUnwind     *appDwarfPreparedUnwind
}

// NewProbe creates a new OpenSSL probe instance.
func NewProbe() (*Probe, error) {
	return &Probe{
		BaseProbe:        base.NewBaseProbe(string(factory.ProbeTypeOpenSSL)),
		eventFuncMaps:    make(map[*ebpf.Map]domain.EventDecoder),
		mapNameToDecoder: make(map[string]domain.EventDecoder),
		closer:           make([]io.Closer, 0),
	}, nil
}

// Initialize sets up the probe with configuration and dispatcher.
func (p *Probe) Initialize(ctx context.Context, cfg domain.Configuration) error {
	if err := p.BaseProbe.Initialize(ctx, cfg); err != nil {
		return err
	}

	// Type assert to OpenSSL-specific config
	opensslConfig, ok := cfg.(*Config)
	if !ok {
		return errors.NewConfigurationError("invalid config type for openssl probe", nil)
	}
	p.config = opensslConfig

	// Validate that the detected version is supported
	if !p.config.IsSupportedVersion() {
		return errors.New(errors.ErrCodeConfiguration,
			fmt.Sprintf("unsupported OpenSSL version: %s", p.config.SslVersion))
	}

	// Log initialization
	p.Logger().Info().
		Str("openssl_path", opensslConfig.OpensslPath).
		Str("ssl_version", opensslConfig.SslVersion).
		Bool("is_boringssl", opensslConfig.IsBoringSSL).
		Str("capture_mode", opensslConfig.CaptureMode).
		Msg("OpenSSL probe initialized")

	return nil
}

// Start begins the OpenSSL probe operation.
func (p *Probe) Start(ctx context.Context) (startErr error) {
	if err := p.BaseProbe.Start(ctx); err != nil {
		return err
	}
	defer func() {
		if startErr == nil {
			return
		}
		// BaseProbe.Start starts the statistics reporter before probe-specific
		// setup. Roll back branch-owned background work if any later setup step
		// fails; callers embedding the probe must not need process exit for
		// startup failure cleanup.
		p.stopInterfaceWatcher()
		p.stopRelatedProcessUIDWatcher()
		_ = p.BaseProbe.Stop(ctx)
	}()

	var sslVersion string
	sslVersion = p.config.SslVersion
	sslVersion = strings.ToLower(sslVersion)

	if p.config.IsAndroid {
		p.Logger().Info().Bool("BoringSSL", p.config.IsBoringSSL).Str("sslVersion", sslVersion).Str("SslBpfFile", p.config.SslBpfFile).Str("Android", p.config.AndroidVer).Msg("OpenSSL probe started")
	} else {
		p.Logger().Info().Bool("BoringSSL", p.config.IsBoringSSL).Str("sslVersion", sslVersion).Str("SslBpfFile", p.config.SslBpfFile).Msg("OpenSSL probe started")
	}
	// Load eBPF bytecode
	bpfFileName := p.BaseProbe.GetBPFName("bytecode/" + p.config.GetBPFFileName())

	// getSslBpfFile
	p.Logger().Info().Str("file", bpfFileName).Msg("Loading eBPF bytecode")

	// Load from assets
	byteBuf, err := assets.Asset(bpfFileName)
	if err != nil {
		return errors.NewEBPFLoadError(bpfFileName, err)
	}

	// Setup eBPF manager
	if err := p.setupManager(); err != nil {
		return err
	}
	if err := p.prepareDwarfUnwind(); err != nil {
		return errors.NewConfigurationError("prepare DWARF user-stack unwinding", err)
	}
	defer p.releaseDwarfUnwind()

	// Initialize eBPF manager
	if err := p.bpfManager.InitWithOptions(bytes.NewReader(byteBuf), p.getManagerOptions()); err != nil {
		return errors.NewEBPFLoadError("openssl manager init", err)
	}
	if err := p.configureApplicationDataHooks(); err != nil {
		return errors.NewConfigurationError("configure application data hooks", err)
	}
	if err := p.configureDwarfUnwind(); err != nil {
		return errors.NewConfigurationError("configure DWARF user-stack unwinding", err)
	}
	if err := p.configureJNIConversionCallerFilter(); err != nil {
		return errors.NewConfigurationError("configure JNI conversion caller filter", err)
	}
	if err := p.configureRelatedProcessUIDs(ctx); err != nil {
		return errors.NewConfigurationError("configure related process UIDs", err)
	}
	if err := p.attachArchiveUprobes(); err != nil {
		return errors.NewEBPFAttachError("archive-backed uprobes", err)
	}

	// Start eBPF manager
	if err := p.bpfManager.Start(); err != nil {
		return errors.NewEBPFAttachError("openssl manager start", err)
	}

	// Retrieve eBPF maps and associate with decoders (configured in setupManager)
	if err := p.retrieveEventMaps(); err != nil {
		return err
	}

	// Start event readers for all configured maps
	for em, decoder := range p.eventFuncMaps {
		if err := p.StartPerfEventReader(em, decoder); err != nil {
			return err
		}
		p.Logger().Debug().
			Str("map", em.String()).
			Msg("Started perf event reader")
	}
	p.startInterfaceWatcher(ctx)

	p.Logger().Info().Msg("OpenSSL probe started successfully")
	return nil
}

// retrieveEventMaps retrieves eBPF maps from the manager and creates eventFuncMaps.
// The decoder mapping by name (mapNameToDecoder) is already configured in setupManager().
func (p *Probe) retrieveEventMaps() error {
	// Retrieve all maps that were configured in setupManager
	for mapName, decoder := range p.mapNameToDecoder {
		em, found, err := p.bpfManager.GetMap(mapName)
		if err != nil {
			return errors.Wrap(errors.ErrCodeEBPFMapAccess, fmt.Sprintf("failed to get %s map", mapName), err)
		}
		if !found {
			// Some maps might not be found (edge case)
			p.Logger().Warn().Str("map", mapName).Msg("Map not found but was configured")
			continue
		}

		// Add to eventMaps and map the actual *ebpf.Map to decoder
		p.eventMaps = append(p.eventMaps, em)
		p.eventFuncMaps[em] = decoder
	}

	p.Logger().Info().
		Int("num_maps", len(p.eventMaps)).
		Int("num_decoders", len(p.eventFuncMaps)).
		Str("capture_mode", p.config.CaptureMode).
		Msg("Event maps retrieved and decoders mapped")

	return nil
}

// Stop gracefully stops the probe.
func (p *Probe) Stop(ctx context.Context) error {
	p.stopInterfaceWatcher()
	p.stopRelatedProcessUIDWatcher()
	// Stop event readers are handled by BaseProbe
	return p.BaseProbe.Stop(ctx)
}

// Events returns the eBPF maps for event collection.
func (p *Probe) Events() []*ebpf.Map {
	if p.eventMaps == nil {
		return []*ebpf.Map{}
	}
	return p.eventMaps
}

// Close releases all probe resources.
func (p *Probe) Close() error {
	p.Logger().Debug().Msg("Closing OpenSSL probe")
	p.stopInterfaceWatcher()
	p.stopRelatedProcessUIDWatcher()

	// Stop eBPF manager
	if p.bpfManager != nil {
		p.Logger().Debug().Msg("Stopping eBPF manager")
		if err := p.bpfManager.Stop(manager.CleanAll); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to stop eBPF manager")
		}
		p.Logger().Debug().Msg("eBPF manager stopped")
	}
	for _, closer := range p.closer {
		if err := closer.Close(); err != nil {
			p.Logger().Warn().Err(err).Msg("Failed to close resource")
		}
	}
	p.Logger().Debug().Msg("Calling BaseProbe.Close()")
	err := p.BaseProbe.Close()
	p.Logger().Debug().Msg("OpenSSL probe closed")
	return err
}

// SetOutput sets the output writer for the probe (for testing purposes).
func (p *Probe) SetOutput(w io.Writer) {
	p.output = w
}

func (p *Probe) setupManagerText() error {
	opensslPath := p.config.OpensslPath
	if opensslPath == "" {
		return errors.NewConfigurationError("openssl_path is required for OpenSSL probe", nil)
	}

	var probes []*manager.Probe
	var maps []*manager.Map
	// Base TLS events map (used by all modes for SSL_read/SSL_write data)
	maps = append(maps, &manager.Map{Name: "tls_events"})
	maps = append(maps, &manager.Map{Name: "connect_events"})
	p.mapNameToDecoder["tls_events"] = &tlsEventDecoder{probe: p}
	p.mapNameToDecoder["connect_events"] = &connectDecoder{probe: p}

	// TEXT mode: SSL_read/SSL_write probes for data capture, with hook points
	// optionally replaced by an application profile.
	probes = []*manager.Probe{
		{
			Section:          "uprobe/SSL_write",
			EbpfFuncName:     "probe_entry_SSL_write",
			AttachToFuncName: "SSL_write",
			BinaryPath:       opensslPath,
		},
		{
			Section:          "uretprobe/SSL_write",
			EbpfFuncName:     "probe_ret_SSL_write",
			AttachToFuncName: "SSL_write",
			BinaryPath:       opensslPath,
		},
		{
			Section:          "uprobe/SSL_read",
			EbpfFuncName:     "probe_entry_SSL_read",
			AttachToFuncName: "SSL_read",
			BinaryPath:       opensslPath,
		},
		{
			Section:          "uretprobe/SSL_read",
			EbpfFuncName:     "probe_ret_SSL_read",
			AttachToFuncName: "SSL_read",
			BinaryPath:       opensslPath,
		},

		// --------------------------------------------------
		{
			Section:          "kprobe/sys_connect",
			EbpfFuncName:     "probe_connect",
			AttachToFuncName: "__sys_connect",
			UID:              "kprobe_sys_connect",
		},
		{
			Section:          "kprobe/inet_stream_connect",
			EbpfFuncName:     "probe_inet_stream_connect",
			AttachToFuncName: "inet_stream_connect",
			UID:              "kprobe_sys_inet_stream_connect",
		},
		{
			Section:          "kretprobe/sys_connect",
			EbpfFuncName:     "retprobe_connect",
			AttachToFuncName: "__sys_connect",
			UID:              "kretprobe_sys_connect",
		},
		{
			Section:          "kprobe/sys_connect",
			EbpfFuncName:     "probe_connect",
			AttachToFuncName: "__sys_accept4",
			UID:              "kprobe_sys_accept4",
		},
		{
			Section:          "kprobe/inet_accept",
			EbpfFuncName:     "probe_inet_accept",
			AttachToFuncName: "inet_accept",
			UID:              "kprobe_inet_accept",
		},
		{
			Section:          "kretprobe/__sys_accept4",
			EbpfFuncName:     "retprobe_accept4",
			AttachToFuncName: "__sys_accept4",
			UID:              "kretprobe_sys_accept4",
		},
		{
			Section:          "kprobe/tcp_v4_destroy_sock",
			EbpfFuncName:     "probe_tcp_v4_destroy_sock",
			AttachToFuncName: "tcp_v4_destroy_sock",
			UID:              "kprobe_tcp_v4_destroy_sock",
		},

		// --------------------------------------------------

		// openssl masterkey
		/*{
			Section:          "uprobe/SSL_write_key",
			EbpfFuncName:     "probe_ssl_master_key",
			AttachToFuncName: m.masterHookFuncs,
			BinaryPath:       binaryPath,
			UID:              "uprobe_ssl_master_key",
		},*/

		// ------------------- SSL_set_fd hook-------------------------------------
		{
			Section:          "uprobe/SSL_set_fd",
			EbpfFuncName:     "probe_SSL_set_fd",
			AttachToFuncName: "SSL_set_fd",
			BinaryPath:       opensslPath,
			UID:              "uprobe_ssl_set_fd",
		},
		{
			Section:          "uprobe/SSL_set_rfd",
			EbpfFuncName:     "probe_SSL_set_fd",
			AttachToFuncName: "SSL_set_rfd",
			BinaryPath:       opensslPath,
			UID:              "uprobe_ssl_set_rfd",
		},
		{
			Section:          "uprobe/SSL_set_wfd",
			EbpfFuncName:     "probe_SSL_set_fd",
			AttachToFuncName: "SSL_set_wfd",
			BinaryPath:       opensslPath,
			UID:              "uprobe_ssl_set_wfd",
		},
	}
	probes = p.applyHookOverrides(probes)

	if p.config.HasStrategy(StrategyQUICMetadata) {
		quicHook, configured := p.config.HookOverride(HookSSLProvideQUIC)
		hasQuicAPI := false
		var symbolErr error
		if configured {
			hasQuicAPI = !quicHook.Disabled
		} else {
			hasQuicAPI, symbolErr = elfHasDynamicSymbol(opensslPath, "SSL_provide_quic_data")
		}
		if symbolErr != nil {
			p.Logger().Debug().
				Err(symbolErr).
				Str("symbol", "SSL_provide_quic_data").
				Msg("Unable to inspect optional QUIC symbol")
		} else if hasQuicAPI {
			probe := &manager.Probe{
				Section:          "uprobe/SSL_provide_quic_data",
				EbpfFuncName:     "probe_SSL_provide_quic_data",
				AttachToFuncName: "SSL_provide_quic_data",
				BinaryPath:       opensslPath,
				UID:              "uprobe_ssl_provide_quic_data",
			}
			if configured {
				applyHookToProbe(probe, quicHook)
			}
			maps = append(maps, &manager.Map{Name: "quic_events"})
			p.mapNameToDecoder["quic_events"] = &quicEventDecoder{}
			probes = append(probes, probe)
			p.Logger().Info().
				Str("symbol", probe.AttachToFuncName).
				Uint64("offset", probe.UAddress).
				Msg("QUIC handshake detection enabled; HTTP/3 application data bypasses SSL_read/SSL_write")
		}
	}

	if !p.config.HasStrategy(StrategyTLSPlaintext) {
		probes = keepHookRoles(probes, HookSSLProvideQUIC)
		maps = removeManagerMaps(maps, "tls_events", "connect_events")
		delete(p.mapNameToDecoder, "tls_events")
		delete(p.mapNameToDecoder, "connect_events")
	}
	probes = p.appendAuxiliaryTLSProbes(probes)

	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}
	return nil
}

func (p *Probe) appendAuxiliaryTLSProbes(
	probes []*manager.Probe,
) []*manager.Probe {
	libraries := p.config.TLSLibraryTargets()
	if len(libraries) < 2 {
		return probes
	}
	primary := p.config.OpensslPath
	base := append([]*manager.Probe(nil), probes...)
	for libraryIndex, library := range libraries[1:] {
		added := 0
		for _, current := range base {
			if current.BinaryPath != primary || hookRoleForProbe(current) == "" {
				continue
			}
			// An offset recovered for one private image is not portable to a
			// second provider. Auxiliary providers are intentionally limited
			// to named exported SSL APIs.
			if current.UAddress != 0 ||
				current.AttachToFuncName == "" ||
				current.AttachToFuncName == offsetHookPlaceholder {
				continue
			}
			found, err := elfTargetHasDynamicSymbol(
				library,
				current.AttachToFuncName,
			)
			if err != nil {
				p.Logger().Debug().
					Err(err).
					Str("library", library.String()).
					Str("symbol", current.AttachToFuncName).
					Msg("Unable to inspect auxiliary TLS provider")
				continue
			}
			if !found {
				continue
			}
			// manager.Probe owns synchronization and runtime attachment
			// state, so a struct copy would duplicate a live mutex. Copy()
			// intentionally carries only declarative fields; retain the
			// uprobe-specific exported fields that auxiliary providers need.
			clone := current.Copy()
			clone.AttachPID = current.AttachPID
			clone.UprobeOffset = current.UprobeOffset
			clone.UAddress = current.UAddress
			clone.BinaryPath = library.RuntimePath
			clone.CopyProgram = true
			uidBase := clone.UID
			if uidBase == "" {
				uidBase = clone.EbpfFuncName
			}
			clone.UID = fmt.Sprintf(
				"%s_tlslib_%d",
				uidBase,
				libraryIndex+1,
			)
			if library.IsArchive() {
				elfOffset, err := librarySymbolFileOffset(
					library,
					clone.AttachToFuncName,
				)
				if err != nil {
					p.Logger().Debug().
						Err(err).
						Str("library", library.String()).
						Msg("Unable to resolve archive TLS symbol")
					continue
				}
				runtimeOffset, err := library.runtimeOffset(elfOffset)
				if err != nil {
					continue
				}
				clone.AttachToFuncName = offsetHookPlaceholder
				clone.UAddress = runtimeOffset
				p.archiveUprobes = append(
					p.archiveUprobes,
					newArchiveUprobeSpec(clone, library),
				)
			}
			probes = append(probes, clone)
			added++
		}
		p.Logger().Info().
			Str("library", library.String()).
			Int("hooks", added).
			Msg("Configured auxiliary TLS provider")
	}
	return probes
}

func (p *Probe) applyHookOverrides(probes []*manager.Probe) []*manager.Probe {
	filtered := probes[:0]
	for _, probe := range probes {
		role := hookRoleForProbe(probe)
		if role == "" {
			filtered = append(filtered, probe)
			continue
		}
		hook, configured := p.config.HookOverride(role)
		if !configured {
			filtered = append(filtered, probe)
			continue
		}
		if hook.Disabled {
			p.Logger().Info().Str("hook_role", role).Msg("Application profile disabled TLS hook")
			continue
		}
		applyHookToProbe(probe, hook)
		filtered = append(filtered, probe)
		p.Logger().Info().
			Str("hook_role", role).
			Str("symbol", probe.AttachToFuncName).
			Uint64("offset", probe.UAddress).
			Msg("Applied application-specific TLS hook")
	}
	return filtered
}

func applyHookToProbe(probe *manager.Probe, hook HookProfile) {
	if hook.Offset != 0 {
		// ebpfmanager v0.5 requires a non-empty function name even when
		// cilium/ebpf's explicit Address option takes precedence.
		probe.AttachToFuncName = offsetHookPlaceholder
		probe.UAddress = uint64(hook.Offset)
		return
	}
	if hook.Symbol != "" {
		probe.AttachToFuncName = hook.Symbol
		probe.UAddress = 0
	}
}

func hookRoleForProbe(probe *manager.Probe) string {
	switch probe.EbpfFuncName {
	case "probe_entry_SSL_read", "probe_ret_SSL_read":
		return HookSSLRead
	case "probe_entry_SSL_write", "probe_ret_SSL_write":
		return HookSSLWrite
	}
	switch probe.UID {
	case "uprobe_ssl_set_fd":
		return HookSSLSetFD
	case "uprobe_ssl_set_rfd":
		return HookSSLSetRFD
	case "uprobe_ssl_set_wfd":
		return HookSSLSetWFD
	case "uprobe_ssl_provide_quic_data":
		return HookSSLProvideQUIC
	}
	return ""
}

func removeHookRoles(probes []*manager.Probe, roles ...string) []*manager.Probe {
	remove := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		remove[role] = struct{}{}
	}
	filtered := probes[:0]
	for _, probe := range probes {
		if _, found := remove[hookRoleForProbe(probe)]; found {
			continue
		}
		filtered = append(filtered, probe)
	}
	return filtered
}

func keepHookRoles(probes []*manager.Probe, roles ...string) []*manager.Probe {
	keep := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		keep[role] = struct{}{}
	}
	filtered := probes[:0]
	for _, probe := range probes {
		if _, found := keep[hookRoleForProbe(probe)]; found {
			filtered = append(filtered, probe)
		}
	}
	return filtered
}

func removeManagerMaps(maps []*manager.Map, names ...string) []*manager.Map {
	remove := make(map[string]struct{}, len(names))
	for _, name := range names {
		remove[name] = struct{}{}
	}
	filtered := maps[:0]
	for _, current := range maps {
		if _, found := remove[current.Name]; found {
			continue
		}
		filtered = append(filtered, current)
	}
	return filtered
}

func (p *Probe) setupManagerPcapNG() error {
	var probes []*manager.Probe
	var maps []*manager.Map
	// PCAP mode: TC probes for network capture + master secret probe
	// Validate network interface is configured
	interfaces := p.config.Interfaces()
	if len(interfaces) == 0 {
		return errors.NewConfigurationError("at least one interface is required for pcap mode", nil)
	}
	// Add ingress and egress TC classifiers to every selected interface.
	for _, ifname := range interfaces {
		probes = append(probes, &manager.Probe{
			Section:          "classifier",
			EbpfFuncName:     base.TcFuncNameIngress,
			Ifname:           ifname,
			NetworkDirection: manager.Ingress,
			UID:              "tc_ingress_" + ifname,
			CopyProgram:      true,
		})
		probes = append(probes, &manager.Probe{
			Section:          "classifier",
			EbpfFuncName:     base.TcFuncNameEgress,
			Ifname:           ifname,
			NetworkDirection: manager.Egress,
			UID:              "tc_egress_" + ifname,
			CopyProgram:      true,
		})
	}

	// TC programs run outside process context, so ingress packets generally
	// cannot be attributed with bpf_get_current_pid_tgid(). Record each
	// TCP/UDP socket's tuple while sendmsg still runs in the caller's context,
	// then let both TC directions look it up in network_map.
	probes = append(probes,
		&manager.Probe{
			Section:          "kprobe/tcp_sendmsg",
			EbpfFuncName:     "tcp_sendmsg",
			AttachToFuncName: "tcp_sendmsg",
			UID:              "kprobe_tc_tcp_sendmsg",
		},
		&manager.Probe{
			Section:          "kprobe/udp_sendmsg",
			EbpfFuncName:     "udp_sendmsg",
			AttachToFuncName: "udp_sendmsg",
			UID:              "kprobe_tc_udp_sendmsg",
		},
	)

	// Add TC-related maps for network packet capture
	maps = append(maps, &manager.Map{Name: "skb_events"})
	p.mapNameToDecoder["skb_events"] = &packetEventDecoder{}

	// These maps don't need decoders (used internally by eBPF)
	maps = append(maps, &manager.Map{Name: "skb_data_buffer_heap"})
	maps = append(maps, &manager.Map{Name: "network_map"})

	p.Logger().Info().Strs("interfaces", interfaces).Int("decoder", len(p.mapNameToDecoder)).Msg("Configuring TC probes for network capture in pcapng mode")

	captureKeys := p.config.HasStrategy(StrategyTLSKeys)
	if captureKeys {
		probes, maps = p.appendMasterSecretProbes(probes, maps)
		p.Logger().Info().Strs("keylog_hook_funcs", p.config.MasterHookFuncs).
			Msg("Configuring master secret extraction probes for pcapNG mode")
	}

	keylogFile := p.config.GetKeylogFile()
	if captureKeys && keylogFile != "" {
		keylogFileWriter, err := writers.NewFileWriter(writers.FileWriterConfig{
			Path:       keylogFile,
			BufferSize: 0,
			Truncate:   true,
		})
		if err != nil {
			p.Logger().Warn().Err(err).Str("keylog file", p.config.GetKeylogFile()).Msg("Failed to create keylog handler, continuing without keylog")
		} else {
			keylogWriter := writers.NewKeylogWriter(keylogFileWriter)
			keylogHandler := handlers.NewKeylogHandler(keylogWriter)
			if err := p.BaseProbe.Dispatcher().Register(keylogHandler); err != nil {
				_ = keylogWriter.Close()
				return fmt.Errorf("failed to register keylog handler: %w", err)
			}
			// Note: keylogWriter will be closed through keylogHandler.Close() when dispatcher closes
			// Don't add it to p.closer to avoid double-close
			p.Logger().Info().Str("keylog_file", keylogFile).Msg("Keylog handler registered for pcapng mode")
		}
	}

	pcapFile := p.config.GetPcapFile()
	if pcapFile == "" {
		return fmt.Errorf("pcap mode requires pcap file path")
	}

	// Create file writer for pcap (use O_TRUNC to overwrite existing file)
	// Note: pcap files should not use rotation
	pcapWriter, err := writers.NewFileWriter(writers.FileWriterConfig{
		Path:       pcapFile,
		BufferSize: 65536, // 64KB buffer for better pcap write performance
		Truncate:   true,  // Overwrite existing pcapng file on new capture
	})
	if err != nil {
		return fmt.Errorf("failed to create pcap writer: %w", err)
	}

	pcapHandler, err := handlers.NewPcapHandlerInterfaces(
		pcapWriter, p.config.Interfaces(), p.config.PcapFilter, p.Logger(),
	)
	if err != nil {
		_ = pcapWriter.Close()
		return fmt.Errorf("failed to create pcap handler: %w", err)
	}

	if err := p.BaseProbe.Dispatcher().Register(pcapHandler); err != nil {
		_ = pcapHandler.Close()
		_ = pcapWriter.Close()
		return fmt.Errorf("failed to register pcap handler: %w", err)
	}
	p.pcapWriter = pcapHandler.PcapWriter()
	p.pcapWriter.SetExpectKeylog(captureKeys)
	// Note: pcapWriter will be closed through pcapHandler.Close() when dispatcher closes
	// Don't add it to p.closer to avoid double-close
	//p.Logger().Info().Str("Writer", pcapWriter.Name()).Msg("Pcap handler registered")

	// Pcapng 的 Keylog writer
	if captureKeys {
		pcapKeylogWriter := writers.NewPcapKeylogWriter(pcapHandler.PcapWriter())
		pcapKeylogHandler := handlers.NewKeylogHandler(pcapKeylogWriter)
		if err := p.BaseProbe.Dispatcher().Register(pcapKeylogHandler); err != nil {
			_ = pcapHandler.Close()
			_ = pcapWriter.Close()
			return fmt.Errorf("failed to register pcapkeylog handler: %w", err)
		}
	}
	// Note: pcapKeylogWriter will be closed through pcapKeylogHandler.Close()
	// Don't add it to p.closer to avoid double-close
	p.Logger().Info().Str("pcap_file", pcapFile).Msg("Pcap handler registered")
	p.Logger().Debug().
		Str("ifname", p.config.Ifname).
		Msg("Added TC probes, SSL probes, and master secret probe for pcap mode")
	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}
	return nil
}

func (p *Probe) appendMasterSecretProbes(
	probes []*manager.Probe, maps []*manager.Map,
) ([]*manager.Probe, []*manager.Map) {
	opensslPath := p.config.OpensslPath
	maps = appendUniqueManagerMaps(maps, &manager.Map{Name: "mastersecret_events"})
	p.mapNameToDecoder["mastersecret_events"] = &masterSecretEventDecoder{}
	if p.config.IsBoringSSL {
		maps = appendUniqueManagerMaps(maps, &manager.Map{Name: "bssl_do_handshake_map"})
		for _, masterFunc := range p.config.MasterHookFuncs {
			probes = append(probes, &manager.Probe{
				Section:          "uprobe/bssl_do_handshake",
				EbpfFuncName:     "uprobe_bssl_do_handshake",
				AttachToFuncName: masterFunc,
				BinaryPath:       opensslPath,
				UID:              fmt.Sprintf("uprobe_bssl_hs_%s", masterFunc),
			})
			probes = append(probes, &manager.Probe{
				Section:          "uretprobe/bssl_do_handshake",
				EbpfFuncName:     "uretprobe_bssl_do_handshake",
				AttachToFuncName: masterFunc,
				BinaryPath:       opensslPath,
				UID:              fmt.Sprintf("uretprobe_bssl_hs_%s", masterFunc),
			})
		}
		return probes, maps
	}
	for _, masterFunc := range p.config.MasterHookFuncs {
		probes = append(probes, &manager.Probe{
			Section:          "uprobe/SSL_write_key",
			EbpfFuncName:     "probe_ssl_master_key",
			AttachToFuncName: masterFunc,
			BinaryPath:       opensslPath,
			UID:              fmt.Sprintf("uprobe_smk_%s", masterFunc),
		})
	}
	return probes, maps
}

func (p *Probe) setupManagerKeyLog() error {

	keylogFile := p.config.GetKeylogFile()
	if keylogFile == "" {
		return fmt.Errorf("keylog mode requires keylog file path")
	}

	opensslPath := p.config.OpensslPath
	var probes []*manager.Probe
	var maps []*manager.Map
	// KEYLOG mode: Master secret extraction probes
	maps = append(maps, &manager.Map{Name: "mastersecret_events"})
	p.mapNameToDecoder["mastersecret_events"] = &masterSecretEventDecoder{}

	// Add master secret extraction probes based on OpenSSL version
	p.Logger().Info().Strs("keylog_hook_funcs", p.config.MasterHookFuncs).Msg("Configuring master secret extraction probes for KeyLog mode")
	probes = make([]*manager.Probe, 0)
	if p.config.IsBoringSSL {
		maps = append(maps, &manager.Map{Name: "bssl_do_handshake_map"})
		for _, masterFunc := range p.config.MasterHookFuncs {
			probes = append(probes, &manager.Probe{
				Section:          "uprobe/bssl_do_handshake",
				EbpfFuncName:     "uprobe_bssl_do_handshake",
				AttachToFuncName: masterFunc,
				BinaryPath:       opensslPath,
				UID:              fmt.Sprintf("uprobe_bssl_hs_%s", masterFunc),
			})
			probes = append(probes, &manager.Probe{
				Section:          "uretprobe/bssl_do_handshake",
				EbpfFuncName:     "uretprobe_bssl_do_handshake",
				AttachToFuncName: masterFunc,
				BinaryPath:       opensslPath,
				UID:              fmt.Sprintf("uretprobe_bssl_hs_%s", masterFunc),
			})
		}
	} else {
		for _, masterFunc := range p.config.MasterHookFuncs {
			probes = append(probes, &manager.Probe{
				Section:          "uprobe/SSL_write_key",
				EbpfFuncName:     "probe_ssl_master_key",
				AttachToFuncName: masterFunc,
				BinaryPath:       opensslPath,
				UID:              fmt.Sprintf("uprobe_smk_%s", masterFunc),
			})
		}
	}

	keylogFileWriter, err := writers.NewFileWriter(writers.FileWriterConfig{
		Path:       keylogFile,
		BufferSize: 0,
		Truncate:   true,
	})
	if err != nil {
		return fmt.Errorf("failed to create keylog writer: %w", err)
	}

	keylogWriter := writers.NewKeylogWriter(keylogFileWriter)
	keylogHandler := handlers.NewKeylogHandler(keylogWriter)
	if err := p.BaseProbe.Dispatcher().Register(keylogHandler); err != nil {
		_ = keylogWriter.Close()
		return fmt.Errorf("failed to register keylog handler: %w", err)
	}
	// Note: keylogWriter will be closed through keylogHandler.Close() when dispatcher closes
	// Don't add it to p.closer to avoid double-close
	p.Logger().Info().Str("keylog_file", keylogFile).Msg("Keylog handler registered")

	p.bpfManager = &manager.Manager{
		Probes: probes,
		Maps:   maps,
	}
	return nil
}

// setupManager configures the eBPF manager with probes and maps.
// This method also configures decoder mappings by map name (mapNameToDecoder).
// The actual *ebpf.Map to decoder mapping (eventFuncMaps) is created in retrieveEventMaps().
func (p *Probe) setupManager() error {
	var err error
	// Mode-specific probe and map setup
	switch p.config.CaptureMode {
	case handlers.ModeText:
		err = p.setupManagerText()
	case handlers.ModeKeylog, handlers.ModeKey:
		err = p.setupManagerKeyLog()
	case handlers.ModePcap, handlers.ModePcapng:
		err = p.setupManagerPcapNG()
	case handlers.ModeAll, handlers.ModeHybrid:
		err = p.setupManagerAll()
	}
	if err == nil && p.config.HasDataHookStrategy() {
		probes, maps := p.appendApplicationDataProbes(
			p.bpfManager.Probes, p.bpfManager.Maps,
		)
		p.bpfManager.Probes = probes
		p.bpfManager.Maps = maps
	}
	if err == nil && p.config.HasJNIDiscoveryStrategy() {
		probes, maps := p.appendJNIDiscoveryProbes(
			p.bpfManager.Probes, p.bpfManager.Maps,
		)
		p.bpfManager.Probes = probes
		p.bpfManager.Maps = maps
	}
	if handlers.IsModePcapng(p.config.CaptureMode) {
		if err == nil && p.config.PcapFilter != "" {
			p.Logger().Info().Str("filter", p.config.PcapFilter).Msg("Applying BPF filter to TC probes")
			ebpfFuncs := []string{base.TcFuncNameIngress, base.TcFuncNameEgress}
			p.bpfManager.InstructionPatchers = pkgebpf.PrepareInsnPatchers(p.bpfManager, ebpfFuncs, p.config.PcapFilter)
		}
	}
	if err != nil {
		return err
	}
	if p.config.PackageName != "" && p.config.GetUid() != 0 {
		p.bpfManager.Maps = appendUniqueManagerMaps(
			p.bpfManager.Maps,
			&manager.Map{Name: relatedUIDMapName},
		)
	}
	p.Logger().Info().
		Str("openssl_path", p.config.OpensslPath).
		Str("capture_mode", p.config.CaptureMode).
		Int("num_probes", len(p.bpfManager.Probes)).
		Int("num_maps", len(p.bpfManager.Maps)).
		Msg("Setting up eBPF probes")

	for _, e := range p.bpfManager.Probes {
		p.Logger().Debug().Str("probe", e.AttachToFuncName).Msg("Configured eBPF probe")
	}

	return nil
}

func (p *Probe) setupManagerAll() error {
	var probes []*manager.Probe
	var maps []*manager.Map

	mergeCurrent := func() {
		probes = append(probes, p.bpfManager.Probes...)
		maps = appendUniqueManagerMaps(maps, p.bpfManager.Maps...)
	}

	if p.config.HasStrategy(StrategyRawPackets) {
		if err := p.setupManagerPcapNG(); err != nil {
			return err
		}
		mergeCurrent()
	} else if p.config.HasStrategy(StrategyTLSKeys) {
		if err := p.setupManagerKeyLog(); err != nil {
			return err
		}
		mergeCurrent()
	}

	if p.config.HasStrategy(StrategyTLSPlaintext) || p.config.HasStrategy(StrategyQUICMetadata) {
		if err := p.setupManagerText(); err != nil {
			return err
		}
		mergeCurrent()
	}

	if len(probes) == 0 &&
		!p.config.HasDataHookStrategy() &&
		!p.config.HasJNIDiscoveryStrategy() {
		return errors.NewConfigurationError("all mode has no enabled capture strategies", nil)
	}
	p.bpfManager = &manager.Manager{Probes: probes, Maps: maps}
	return nil
}

func (p *Probe) appendApplicationDataProbes(
	probes []*manager.Probe, maps []*manager.Map,
) ([]*manager.Probe, []*manager.Map) {
	hooks := p.config.EnabledCaptureDataHooks()
	for slot, hook := range hooks {
		target := hook.ResolvedTarget()
		entry := &manager.Probe{
			Section:      fmt.Sprintf("uprobe/app_data_%d", slot),
			EbpfFuncName: fmt.Sprintf("probe_entry_app_data_%d", slot),
			BinaryPath:   target.RuntimePath,
			UID:          fmt.Sprintf("uprobe_app_data_%d", slot),
		}
		applyApplicationDataHookTarget(entry, hook)
		if target.IsArchive() {
			p.archiveUprobes = append(
				p.archiveUprobes,
				newArchiveUprobeSpec(entry, target),
			)
		}
		probes = append(probes, entry)
		if hook.CaptureOn == AppDataCaptureReturn {
			ret := &manager.Probe{
				Section:      fmt.Sprintf("uretprobe/app_data_%d", slot),
				EbpfFuncName: fmt.Sprintf("probe_ret_app_data_%d", slot),
				BinaryPath:   target.RuntimePath,
				UID:          fmt.Sprintf("uretprobe_app_data_%d", slot),
			}
			applyApplicationDataHookTarget(ret, hook)
			if target.IsArchive() {
				p.archiveUprobes = append(
					p.archiveUprobes,
					newArchiveUprobeSpec(ret, target),
				)
			}
			probes = append(probes, ret)
		}
		p.Logger().Info().
			Int("slot", slot).
			Str("name", hook.Name).
			Str("library", hook.ResolvedLibrary()).
			Str("symbol", entry.AttachToFuncName).
			Uint64("offset", entry.UAddress).
			Msg("Configured profile-defined capture boundary hook")
	}
	maps = appendUniqueManagerMaps(maps,
		&manager.Map{Name: "app_data_events"},
		&manager.Map{Name: "app_hook_configs"},
		&manager.Map{Name: "active_app_hooks"},
		&manager.Map{Name: "app_hook_states"},
		&manager.Map{Name: "app_data_buffer_heap"},
		&manager.Map{Name: "app_iovec_state_heap"},
		&manager.Map{Name: "app_dwarf_unwind_pages"},
		&manager.Map{Name: "app_dwarf_unwind_deltas"},
		&manager.Map{Name: "app_dwarf_unwind_infos"},
	)
	p.mapNameToDecoder["app_data_events"] = &applicationDataEventDecoder{
		hooks: append([]ApplicationDataHook(nil), hooks...),
	}
	return probes, maps
}

func applyApplicationDataHookTarget(
	probe *manager.Probe, hook ApplicationDataHook,
) {
	target := hook.ResolvedTarget()
	if !target.IsArchive() {
		if hook.Offset != 0 {
			probe.AttachToFuncName = offsetHookPlaceholder
			probe.UAddress = uint64(hook.Offset)
			return
		}
		probe.AttachToFuncName = hook.Symbol
		return
	}
	probe.AttachToFuncName = offsetHookPlaceholder
	probe.UAddress = hook.resolvedOffset
}

type jniConversionProbeProgram struct {
	role      string
	hasReturn bool
}

var jniConversionProbePrograms = []jniConversionProbeProgram{
	{JNIConversionGetStringLength, true},
	{JNIConversionGetStringChars, true},
	{JNIConversionReleaseStringChars, false},
	{JNIConversionGetStringUTFLength, true},
	{JNIConversionGetStringUTFChars, true},
	{JNIConversionReleaseStringUTFChars, false},
	{JNIConversionGetArrayLength, true},
	{JNIConversionGetByteArrayElements, true},
	{JNIConversionReleaseByteArrayElements, false},
	{JNIConversionGetByteArrayRegion, true},
	{JNIConversionSetByteArrayRegion, false},
	{JNIConversionGetPrimitiveArrayCritical, true},
	{JNIConversionReleasePrimitiveArrayCritical, false},
	{JNIConversionGetStringCritical, true},
	{JNIConversionReleaseStringCritical, false},
	{JNIConversionGetDirectBufferAddress, true},
	{JNIConversionGetDirectBufferCapacity, true},
}

func (p *Probe) appendJNIDiscoveryProbes(
	probes []*manager.Probe, maps []*manager.Map,
) ([]*manager.Probe, []*manager.Map) {
	jni := p.config.JNIDiscovery
	if jni == nil {
		return probes, maps
	}
	for hookID, offset := range jni.RegisterNativesOffsets {
		for segment := 0; segment < JNIDiscoverySegments; segment++ {
			probes = append(probes, &manager.Probe{
				Section:          fmt.Sprintf("uprobe/jni_register_natives_%d", segment),
				EbpfFuncName:     fmt.Sprintf("probe_jni_register_natives_%d", segment),
				AttachToFuncName: offsetHookPlaceholder,
				BinaryPath:       jni.ResolvedLibrary(),
				UAddress:         uint64(offset),
				UID: fmt.Sprintf(
					"uprobe_jni_register_natives_%d_%d",
					hookID,
					segment,
				),
			})
		}
		if p.Logger() != nil {
			p.Logger().Info().
				Int("hook_id", hookID).
				Str("library", jni.ResolvedLibrary()).
				Uint64("offset", uint64(offset)).
				Int("method_limit", JNIDiscoveryMaxMethods).
				Msg("Configured JNI RegisterNatives discovery hook")
		}
	}
	if len(jni.RegisterNativesOffsets) != 0 {
		maps = appendUniqueManagerMaps(maps,
			&manager.Map{Name: "jni_register_events"},
			&manager.Map{Name: "jni_register_buffer_heap"},
		)
		p.mapNameToDecoder["jni_register_events"] = &jniDiscoveryDecoder{
			resolver:               newProcessModuleResolver(),
			registerNativesOffsets: offsetValues(jni.RegisterNativesOffsets),
		}
	}
	hasConversions := false
	for _, program := range jniConversionProbePrograms {
		for offsetIndex, offset := range jni.ConversionOffsets[program.role] {
			entrySection := "uprobe/jni_" + program.role
			entryFunction := "probe_jni_" + program.role
			if program.hasReturn {
				entrySection += "_entry"
				entryFunction = "probe_entry_jni_" + program.role
			}
			probes = append(probes, &manager.Probe{
				Section:          entrySection,
				EbpfFuncName:     entryFunction,
				AttachToFuncName: offsetHookPlaceholder,
				BinaryPath:       jni.ResolvedLibrary(),
				UAddress:         uint64(offset),
				UID: fmt.Sprintf(
					"uprobe_jni_conversion_%s_%d",
					program.role,
					offsetIndex,
				),
			})
			if program.hasReturn {
				probes = append(probes, &manager.Probe{
					Section:          "uretprobe/jni_" + program.role + "_return",
					EbpfFuncName:     "probe_return_jni_" + program.role,
					AttachToFuncName: offsetHookPlaceholder,
					BinaryPath:       jni.ResolvedLibrary(),
					UAddress:         uint64(offset),
					UID: fmt.Sprintf(
						"uretprobe_jni_conversion_%s_%d",
						program.role,
						offsetIndex,
					),
				})
			}
			hasConversions = true
			if p.Logger() != nil {
				p.Logger().Info().
					Str("role", program.role).
					Str("library", jni.ResolvedLibrary()).
					Uint64("offset", uint64(offset)).
					Msg("Configured JNI managed-reference conversion hook")
			}
		}
	}
	if hasConversions {
		maps = appendUniqueManagerMaps(maps,
			&manager.Map{Name: "jni_conversion_events"},
			&manager.Map{Name: "active_jni_conversions"},
			&manager.Map{Name: "jni_object_states"},
			&manager.Map{Name: "jni_conversion_buffer_heap"},
		)
		if len(jni.CallerAllowlist) != 0 {
			maps = appendUniqueManagerMaps(maps,
				&manager.Map{Name: "jni_conversion_allowed_callers"},
				&manager.Map{Name: "jni_conversion_filter_pids"},
			)
		}
		p.mapNameToDecoder["jni_conversion_events"] = &jniConversionDecoder{
			resolver: newProcessModuleResolver(),
		}
	}
	return probes, maps
}

func (p *Probe) configureApplicationDataHooks() error {
	if !p.config.HasDataHookStrategy() {
		return nil
	}
	configMap, found, err := p.bpfManager.GetMap("app_hook_configs")
	if err != nil {
		return fmt.Errorf("get app_hook_configs map: %w", err)
	}
	if !found {
		return fmt.Errorf("app_hook_configs map was not loaded")
	}
	for slot, hook := range p.config.EnabledCaptureDataHooks() {
		key := uint32(slot)
		value := hook.bpfConfig()
		if err := configMap.Update(&key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update app_hook_configs slot %d (%s): %w",
				slot, hook.Name, err)
		}
	}
	return nil
}

func (p *Probe) configureJNIConversionCallerFilter() error {
	if p.config.JNIDiscovery == nil ||
		len(p.config.JNIDiscovery.CallerAllowlist) == 0 {
		return nil
	}
	decoder, found := p.mapNameToDecoder["jni_conversion_events"].(*jniConversionDecoder)
	if !found {
		return fmt.Errorf("jni_conversion_events decoder was not configured")
	}
	allowed, found, err := p.bpfManager.GetMap("jni_conversion_allowed_callers")
	if err != nil {
		return fmt.Errorf("get jni_conversion_allowed_callers map: %w", err)
	}
	if !found {
		return fmt.Errorf("jni_conversion_allowed_callers map was not loaded")
	}
	enabled, found, err := p.bpfManager.GetMap("jni_conversion_filter_pids")
	if err != nil {
		return fmt.Errorf("get jni_conversion_filter_pids map: %w", err)
	}
	if !found {
		return fmt.Errorf("jni_conversion_filter_pids map was not loaded")
	}
	decoder.filter = newJNIConversionCallerFilter(
		p.config.JNIDiscovery.CallerAllowlist,
		allowed,
		enabled,
	)
	p.Logger().Info().
		Int("rules", len(p.config.JNIDiscovery.CallerAllowlist)).
		Msg("Configured ASLR-aware JNI conversion caller filter")
	return nil
}

func appendUniqueManagerMaps(dst []*manager.Map, values ...*manager.Map) []*manager.Map {
	seen := make(map[string]struct{}, len(dst)+len(values))
	for _, current := range dst {
		seen[current.Name] = struct{}{}
	}
	for _, current := range values {
		if _, found := seen[current.Name]; found {
			continue
		}
		seen[current.Name] = struct{}{}
		dst = append(dst, current)
	}
	return dst
}

// getManagerOptions returns eBPF manager options.
func (p *Probe) getManagerOptions() manager.Options {
	opts := manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSizeStart: 2097152,
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
	pageEntries := uint32(1)
	deltaEntries := uint32(1)
	infoEntries := uint32(1)
	if p.dwarfUnwind != nil {
		pageEntries = uint32(len(p.dwarfUnwind.pages))
		deltaEntries = uint32(len(p.dwarfUnwind.deltas))
		infoEntries = uint32(len(p.dwarfUnwind.infos))
	}
	opts.MapSpecEditors = map[string]manager.MapSpecEditor{
		"app_dwarf_unwind_pages": {
			MaxEntries: pageEntries,
			EditorFlag: manager.EditMaxEntries,
		},
		"app_dwarf_unwind_deltas": {
			MaxEntries: deltaEntries,
			EditorFlag: manager.EditMaxEntries,
		},
		"app_dwarf_unwind_infos": {
			MaxEntries: infoEntries,
			EditorFlag: manager.EditMaxEntries,
		},
	}

	// Add constant editors if kernel supports global variables
	if p.config.EnableGlobalVar() {
		kv, _ := kernel.HostVersion()
		kernelLess52 := uint64(0)
		if kv < kernel.VersionCode(5, 2, 0) {
			kernelLess52 = 1
		}

		var cgroupId uint64
		if p.config.GetCGroupPath() != "" {
			var err error
			cgroupId, err = pkgebpf.GetCgroupIdFromPath(p.config.GetCGroupPath())
			if err != nil {
				p.Logger().Warn().Err(err).Str("cgroupPath", p.config.GetCGroupPath()).Msg("failed to get cgroup id, cgroup filtering disabled")
				cgroupId = 0
			}
		}

		opts.ConstantEditors = []manager.ConstantEditor{
			{Name: "target_pid", Value: p.config.GetPid()},
			{Name: "target_uid", Value: p.config.GetUid()},
			{Name: "less52", Value: kernelLess52},
			{Name: "target_cgroup_id", Value: cgroupId},
			{Name: "tc_unknown_flow_policy", Value: p.config.UnknownFlowPolicyValue()},
			{Name: "tc_strict_attribution", Value: boolToUint64(p.config.StrictAttribution)},
		}
		for _, offsetName := range p.config.SortedStructOffsetNames() {
			constantName, ok := StructOffsetConstant(offsetName)
			if !ok {
				continue
			}
			opts.ConstantEditors = append(opts.ConstantEditors, manager.ConstantEditor{
				Name:  constantName,
				Value: p.config.StructOffsets[offsetName],
			})
		}
	} else {
		// Kernel < 5.2 does not support .rodata global variables, so PID/UID/cgroup filters cannot be applied.
		if p.config.GetPid() != 0 {
			p.Logger().Warn().Uint64("pid", p.config.GetPid()).
				Msg("PID filter is not supported on kernel < 5.2, --pid filter will be ignored")
		}
		if p.config.GetUid() != 0 {
			p.Logger().Warn().Uint64("uid", p.config.GetUid()).
				Msg("UID filter is not supported on kernel < 5.2, --uid filter will be ignored")
		}
		if p.config.GetCGroupPath() != "" {
			p.Logger().Warn().Str("cgroupPath", p.config.GetCGroupPath()).
				Msg("cgroup_path filter is not supported on kernel < 5.2, --cgroup_path filter will be ignored")
		}
		if len(p.config.StructOffsets) != 0 {
			p.Logger().Warn().
				Msg("TLS structure offset overrides are not supported on kernel < 5.2 and will be ignored")
		}
	}

	return opts
}

func boolToUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func (p *Probe) DecodeFun(em *ebpf.Map) (domain.EventDecoder, bool) {
	fun, found := p.eventFuncMaps[em]
	return fun, found
}

// connectDecoder implements domain.EventDecoder for TLS data events
type connectDecoder struct {
	probe *Probe
}

func (d *connectDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &ConnDataEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *connectDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &ConnDataEvent{}, true
}

// packetEventDecoder implements domain.EventDecoder for packet events
type packetEventDecoder struct{}

func (d *packetEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &PacketEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *packetEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &PacketEvent{}, true
}

// tlsEventDecoder implements domain.EventDecoder for TLS data events
type tlsEventDecoder struct {
	probe *Probe
}

func (d *tlsEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &Event{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *tlsEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &Event{}, true
}

// quicEventDecoder implements domain.EventDecoder for QUIC handshake metadata.
type quicEventDecoder struct{}

func (d *quicEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &QuicEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *quicEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &QuicEvent{}, true
}

// applicationDataEventDecoder labels generic app-hook events with the stable
// profile name assigned to their BPF slot.
type applicationDataEventDecoder struct {
	hooks        []ApplicationDataHook
	resolver     *processModuleResolver
	moduleBuilds *moduleBuildIDCache
}

func (d *applicationDataEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &ApplicationDataEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if int(event.HookID) < len(d.hooks) {
		hook := d.hooks[event.HookID]
		event.HookName = hook.Name
		event.CaptureLayer = hook.CaptureLayer
		event.Transport = hook.Transport
		event.BoundaryRole = hook.BoundaryRole
		event.UserStackMode = hook.StackMode
	}
	if event.UserStackDepth > 0 {
		if d.resolver == nil {
			d.resolver = newProcessModuleResolver()
		}
		if d.moduleBuilds == nil {
			d.moduleBuilds = &moduleBuildIDCache{}
		}
		event.StackFrames = make(
			[]ApplicationDataStackFrame, 0, event.UserStackDepth)
		for _, address := range event.UserStack[:event.UserStackDepth] {
			if address == 0 {
				continue
			}
			frame := ApplicationDataStackFrame{Address: address}
			path, offset, resolveErr := d.resolver.resolve(event.Pid, address)
			if resolveErr != nil {
				frame.ResolutionError = resolveErr.Error()
			} else {
				path, offset, resolveErr = d.moduleBuilds.resolveLocation(
					path,
					offset,
				)
				frame.ModulePath = path
				frame.ModuleOffset = offset
				if resolveErr != nil {
					frame.ResolutionError = resolveErr.Error()
					event.StackFrames = append(event.StackFrames, frame)
					continue
				}
				buildID, buildErr := d.moduleBuilds.resolve(path)
				if buildErr != nil {
					frame.ResolutionError = buildErr.Error()
				} else {
					frame.ModuleBuildID = buildID
				}
			}
			event.StackFrames = append(event.StackFrames, frame)
		}
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	return event, nil
}

func (d *applicationDataEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &ApplicationDataEvent{}, true
}

// jniDiscoveryDecoder enriches RegisterNatives events with stable
// module-relative offsets. A cache miss reloads /proc/PID/maps so libraries
// loaded after process start are still resolved.
type jniDiscoveryDecoder struct {
	resolver               *processModuleResolver
	moduleLocations        *moduleBuildIDCache
	registerNativesOffsets []uint64
}

func (d *jniDiscoveryDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &JNIDiscoveryEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	if d.resolver == nil {
		d.resolver = newProcessModuleResolver()
	}
	if d.moduleLocations == nil {
		d.moduleLocations = &moduleBuildIDCache{}
	}
	if path, offset, err := d.resolver.resolve(event.Pid, event.FunctionAddr); err == nil {
		path, offset, err = d.moduleLocations.resolveLocation(path, offset)
		if err == nil {
			event.ModulePath = path
			event.ModuleOffset = offset
		} else {
			event.ModuleResolutionError = err.Error()
		}
	} else {
		event.ModuleResolutionError = err.Error()
	}
	if path, offset, err := d.resolver.resolve(event.Pid, event.RegisterNativesAddr); err == nil {
		path, offset, err = d.moduleLocations.resolveLocation(path, offset)
		if err == nil {
			event.RegisterModulePath = path
			event.RegisterModuleOffset = offset
			event.HookID = registerNativesHookID(
				d.registerNativesOffsets,
				offset,
			)
		} else if event.ModuleResolutionError == "" {
			event.ModuleResolutionError = err.Error()
		}
	} else if event.ModuleResolutionError == "" {
		event.ModuleResolutionError = err.Error()
	}
	return event, nil
}

type jniConversionDecoder struct {
	resolver     *processModuleResolver
	filter       jniConversionFilter
	moduleBuilds *moduleBuildIDCache
}

type jniConversionFilter interface {
	activate(uint32) (jniConversionFilterState, error)
}

type moduleBuildIDCache struct {
	mu       sync.Mutex
	results  map[string]moduleBuildIDResult
	archives map[string]archiveModuleIndexResult
}

type moduleBuildIDResult struct {
	buildID string
	err     string
}

type archiveModuleIndexResult struct {
	targets []libraryTarget
	err     string
}

// resolveLocation turns an address resolved against an APK inode into the
// exact stored ELF member and an ELF-relative file offset. Those are the
// values an application profile can pin and reuse after ASLR.
func (c *moduleBuildIDCache) resolveLocation(
	path string,
	offset uint64,
) (string, uint64, error) {
	if !isNativeLibraryArchive(path) {
		return path, offset, nil
	}
	targets, err := c.archiveTargets(path)
	if err != nil {
		return path, offset, err
	}
	for _, target := range targets {
		end := target.ContainerOffset + target.ELFSize
		if end < target.ContainerOffset ||
			offset < target.ContainerOffset ||
			offset >= end {
			continue
		}
		return target.String(), offset - target.ContainerOffset, nil
	}
	return path, offset, fmt.Errorf(
		"archive offset %#x in %q is outside every stored ELF member",
		offset,
		path,
	)
}

func (c *moduleBuildIDCache) archiveTargets(
	path string,
) ([]libraryTarget, error) {
	path = strings.TrimSpace(path)
	c.mu.Lock()
	if c.archives == nil {
		c.archives = make(map[string]archiveModuleIndexResult)
	} else if cached, found := c.archives[path]; found {
		c.mu.Unlock()
		if cached.err != "" {
			return nil, fmt.Errorf("%s", cached.err)
		}
		return cached.targets, nil
	}
	c.mu.Unlock()

	targets, err := archiveLibraryTargets(path)
	result := archiveModuleIndexResult{targets: targets}
	if err != nil {
		result.err = err.Error()
	}

	c.mu.Lock()
	c.archives[path] = result
	c.mu.Unlock()

	if err != nil {
		return nil, err
	}
	return targets, nil
}

func (c *moduleBuildIDCache) resolve(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	c.mu.Lock()
	if c.results == nil {
		c.results = make(map[string]moduleBuildIDResult)
	} else if cached, found := c.results[path]; found {
		c.mu.Unlock()
		if cached.err != "" {
			return "", fmt.Errorf("%s", cached.err)
		}
		return cached.buildID, nil
	}
	c.mu.Unlock()

	target, err := resolveLibraryTarget(path)
	var buildID string
	if err == nil {
		err = withLibraryELF(target, func(file *elf.File) error {
			var readErr error
			buildID, readErr = readELFBuildIDFromFile(
				file,
				target.String(),
			)
			return readErr
		})
	}
	result := moduleBuildIDResult{buildID: buildID}
	if err != nil {
		result.err = err.Error()
	}

	c.mu.Lock()
	c.results[path] = result
	c.mu.Unlock()

	if err != nil {
		return "", err
	}
	return buildID, nil
}

func (d *jniConversionDecoder) Decode(
	_ *ebpf.Map,
	data []byte,
) (domain.Event, error) {
	event := &JNIConversionEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	if err := event.Validate(); err != nil {
		return nil, err
	}
	if d.resolver == nil {
		d.resolver = newProcessModuleResolver()
	}
	if event.CallerAddr != 0 {
		path, offset, err := d.resolver.resolve(event.Pid, event.CallerAddr)
		if err == nil {
			if d.moduleBuilds == nil {
				d.moduleBuilds = &moduleBuildIDCache{}
			}
			path, offset, err = d.moduleBuilds.resolveLocation(
				path,
				offset,
			)
		}
		if err == nil {
			event.CallerModulePath = path
			event.CallerModuleOffset = offset
			buildID, buildErr := d.moduleBuilds.resolve(path)
			if buildErr == nil {
				event.CallerModuleBuildID = buildID
			} else {
				event.CallerModuleBuildIDError = buildErr.Error()
			}
		} else {
			event.ModuleResolutionError = err.Error()
		}
	}
	if d.filter != nil {
		state, err := d.filter.activate(event.Pid)
		event.CallerFilterActive = state.Active
		event.CallerFilterJustActivated = state.JustActivated
		event.CallerFilterPendingRules = uint32(state.PendingRules)
		if err != nil {
			event.CallerFilterError = err.Error()
		}
	}
	return event, nil
}

func (d *jniConversionDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &JNIConversionEvent{}, true
}

func offsetValues(values []OffsetValue) []uint64 {
	offsets := make([]uint64, len(values))
	for index, value := range values {
		offsets[index] = uint64(value)
	}
	return offsets
}

func registerNativesHookID(offsets []uint64, observed uint64) uint32 {
	for index, offset := range offsets {
		if observed == offset {
			return uint32(index)
		}
		// Some uprobe implementations expose the instruction immediately
		// following the trap. Accept one ARM64 instruction of skew.
		if observed == offset+4 || offset == observed+4 {
			return uint32(index)
		}
	}
	return 0
}

func (d *jniDiscoveryDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &JNIDiscoveryEvent{}, true
}

// masterSecretEventDecoder implements domain.EventDecoder for master secret events
type masterSecretEventDecoder struct {
	//probe *Probe
}

func (d *masterSecretEventDecoder) Decode(_ *ebpf.Map, data []byte) (domain.Event, error) {
	event := &MasterSecretEvent{}
	if err := event.DecodeFromBytes(data); err != nil {
		fmt.Printf("[DEBUG] mastersecret DecodeFromBytes failed: %v, data_len=%d\n", err, len(data))
		return nil, err
	}
	fmt.Printf("[DEBUG] mastersecret event: version=0x%04x client_random=%x\n", event.Version, event.ClientRandom[:8])
	if err := event.Validate(); err != nil {
		fmt.Printf("[DEBUG] mastersecret Validate failed: %v\n", err)
		return nil, err
	}

	// Event will be dispatched to registered handlers:
	// - KeylogHandler: writes master secret to keylog file
	// - MasterSecretInfoHandler: prints summary to stdout
	return event, nil
}

func (d *masterSecretEventDecoder) GetDecoder(_ *ebpf.Map) (domain.Event, bool) {
	return &MasterSecretEvent{}, true
}
