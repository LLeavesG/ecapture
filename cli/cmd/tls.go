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

package cmd

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/gojue/ecapture/internal/factory"
	opensslProbe "github.com/gojue/ecapture/internal/probe/openssl"
)

var opensslConfig = opensslProbe.NewConfig()

// opensslCmd represents the openssl command
var opensslCmd = &cobra.Command{
	Use:     "tls",
	Aliases: []string{"openssl"},
	Short:   "Used to capture TLS/SSL text content without the need for a CA certificate. (Supports OpenSSL 1.0.x/1.1.x/3.x or newer).",
	Long: `Uses eBPF uprobe/TC to capture process event data and network data. Also supports the pcap-NG format.

ecapture tls -m [text|keylog|pcap|all] [flags] [pcap filter expression]
ecapture tls -m pcap -i wlan0 -w save.pcapng host 192.168.1.1 and tcp port 443
ecapture tls -m all --profile profiles/android-app.json
ecapture tls -l save.log --pid=3423
ecapture tls --libssl=/lib/x86_64-linux-gnu/libssl.so.1.1
ecapture tls -m keylog --pcapfile save_3_0_5.pcapng --ssl_version="openssl 3.0.5" --libssl=/lib/x86_64-linux-gnu/libssl.so.3
ecapture tls -m pcap --pcapfile save_android.pcapng -i wlan0 --libssl=/apex/com.android.conscrypt/lib64/libssl.so --ssl_version="boringssl 1.1.1" tcp port 443

Docker usage:
docker pull gojue/ecapture
docker run --rm --privileged=true --net=host -v /etc:/etc -v /usr:/usr -v ${PWD}:/output gojue/ecapture tls -m pcap -i wlp3s0 --pcapfile=/output/ecapture.pcapng tcp port 443
`,
	Example: "ecapture tls -m pcap -i wlan0 -w save.pcapng host 192.168.1.1 and tcp port 443",
	RunE:    openSSLCommandFunc,
}

func init() {
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.OpensslPath, "libssl", "", "libssl.so file path, will automatically find it from curl default.")
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.OpensslPathPattern, "libssl-glob", "", "glob used to find an application-private TLS library.")
	opensslCmd.PersistentFlags().StringSliceVar(&opensslConfig.OpensslExtraPaths, "libssl-extra", nil, "additional TLS libraries that export SSL_read/SSL_write.")
	opensslCmd.PersistentFlags().StringSliceVar(&opensslConfig.OpensslExtraPatterns, "libssl-extra-glob", nil, "globs for additional TLS libraries.")
	opensslCmd.PersistentFlags().BoolVar(&opensslConfig.AutoDiscoverTLSLibs, "libssl-auto", false, "attach compatible TLS hooks to every provider mapped by the target and Android Conscrypt.")
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.ProfilePath, "profile", "", "per-application JSON capture profile.")
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.PackageName, "package", "", "Android package name; resolves its UID from packages.list.")
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.CGroupPath, "cgroup_path", "", "cgroup v2 path for container/process filtering. Empty disables cgroup filtering.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.CaptureMode, "model", "m", "text", "capture model: text, pcap/pcapng, key/keylog, or all.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.KeylogFile, "keylogfile", "k", "ecapture_openssl_key.log", "The file stores SSL/TLS keys, and eCapture captures these keys during encrypted traffic communication and saves them to the file.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.PcapFile, "pcapfile", "w", "save.pcapng", "write the raw packets to file as pcapng format.")
	opensslCmd.PersistentFlags().StringVarP(&opensslConfig.Ifname, "ifname", "i", "", "(TC Classifier) Interface name on which the probe will be attached.")
	opensslCmd.PersistentFlags().StringSliceVar(&opensslConfig.Ifnames, "interfaces", nil, "comma-separated interfaces for raw packet capture.")
	opensslCmd.PersistentFlags().StringSliceVar(&opensslConfig.CaptureStrategies, "strategy", nil, "capture strategies: raw_packets,tls_plaintext,tls_keys,quic_metadata,boundary_data,application_data,jni_discovery.")
	opensslCmd.PersistentFlags().BoolVar(&opensslConfig.StrictAttribution, "strict-attribution", false, "drop raw packets that cannot be attributed to the selected PID/UID.")
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.UnknownFlowPolicy, "unknown-flows", "include", "unknown-flow policy: include, mark, or drop.")
	opensslCmd.PersistentFlags().StringArrayVar(&opensslConfig.StructOffsetSpecs, "struct-offset", nil, "override a TLS structure offset, e.g. ssl_st_rbio=0x18 (repeatable).")
	opensslCmd.PersistentFlags().StringArrayVar(&opensslConfig.HookSpecs, "hook", nil, "override a hook, e.g. ssl_read=@0x1234, ssl_write=SSL_write, or ssl_set_fd=off (repeatable).")
	opensslCmd.PersistentFlags().StringVar(&opensslConfig.SslVersion, "ssl_version", "", "openssl/boringssl version， e.g: --ssl_version=\"openssl 1.1.1g\" or  --ssl_version=\"boringssl 1.1.1\".")
	opensslCmd.PersistentFlags().BoolVar(&opensslConfig.PerfReorder, "perf-reorder", false, "enable userland reorder of per-CPU perf events by bpf ktime before dispatch")
	opensslCmd.PersistentFlags().UintVar(&opensslConfig.PerfReorderLagMs, "perf-reorder-lag-ms", 10, "reorder batching window in ms (only with --perf-reorder; default 10)")
	rootCmd.AddCommand(opensslCmd)
}

// openSSLCommandFunc executes the "tls" command using the new probe architecture.
func openSSLCommandFunc(command *cobra.Command, args []string) error {
	if err := applyOpenSSLProfileWithCLIOverrides(command); err != nil {
		return err
	}

	if len(args) != 0 {
		opensslConfig.PcapFilter = strings.Join(args, " ")
	}

	// Set global config to openssl-specific config
	if opensslConfig.ProfilePath == "" || command.Flags().Changed("pid") {
		opensslConfig.SetPid(globalConf.Pid)
	}
	if opensslConfig.ProfilePath == "" || command.Flags().Changed("uid") {
		opensslConfig.SetUid(globalConf.Uid)
	}
	opensslConfig.SetDebug(globalConf.Debug)
	opensslConfig.SetHex(globalConf.IsHex)
	opensslConfig.SetBTF(globalConf.BtfMode)
	if opensslConfig.ProfilePath == "" || command.Flags().Changed("mapsize") {
		opensslConfig.SetPerCpuMapSize(globalConf.PerCpuMapSize)
	}
	opensslConfig.SetTruncateSize(globalConf.TruncateSize)

	// Run probe using the common entry point
	return runProbe(factory.ProbeTypeOpenSSL, opensslConfig)
}

func applyOpenSSLProfileWithCLIOverrides(command *cobra.Command) error {
	if opensslConfig.ProfilePath == "" {
		return nil
	}

	cli := *opensslConfig
	cliStrategies := append([]string(nil), opensslConfig.CaptureStrategies...)
	cliInterfaces := append([]string(nil), opensslConfig.Ifnames...)
	cliExtraPaths := append([]string(nil), opensslConfig.OpensslExtraPaths...)
	cliExtraPatterns := append([]string(nil), opensslConfig.OpensslExtraPatterns...)
	if err := opensslConfig.LoadAndApplyApplicationProfile(opensslConfig.ProfilePath); err != nil {
		return err
	}

	overrideString := func(flag string, target *string, value string) {
		if command.Flags().Changed(flag) {
			*target = value
		}
	}
	overrideString("libssl", &opensslConfig.OpensslPath, cli.OpensslPath)
	overrideString("libssl-glob", &opensslConfig.OpensslPathPattern, cli.OpensslPathPattern)
	if command.Flags().Changed("libssl-extra") {
		opensslConfig.OpensslExtraPaths = cliExtraPaths
	}
	if command.Flags().Changed("libssl-extra-glob") {
		opensslConfig.OpensslExtraPatterns = cliExtraPatterns
	}
	if command.Flags().Changed("libssl-auto") {
		opensslConfig.AutoDiscoverTLSLibs = cli.AutoDiscoverTLSLibs
	}
	overrideString("package", &opensslConfig.PackageName, cli.PackageName)
	overrideString("model", &opensslConfig.CaptureMode, cli.CaptureMode)
	overrideString("keylogfile", &opensslConfig.KeylogFile, cli.KeylogFile)
	overrideString("pcapfile", &opensslConfig.PcapFile, cli.PcapFile)
	overrideString("ifname", &opensslConfig.Ifname, cli.Ifname)
	overrideString("unknown-flows", &opensslConfig.UnknownFlowPolicy, cli.UnknownFlowPolicy)
	overrideString("ssl_version", &opensslConfig.SslVersion, cli.SslVersion)
	if command.Flags().Changed("interfaces") {
		opensslConfig.Ifnames = cliInterfaces
	}
	if command.Flags().Changed("strategy") {
		opensslConfig.CaptureStrategies = cliStrategies
	}
	if command.Flags().Changed("strict-attribution") {
		opensslConfig.StrictAttribution = cli.StrictAttribution
	}
	if command.Flags().Changed("perf-reorder") {
		opensslConfig.PerfReorder = cli.PerfReorder
	}
	if command.Flags().Changed("perf-reorder-lag-ms") {
		opensslConfig.PerfReorderLagMs = cli.PerfReorderLagMs
	}
	return nil
}
