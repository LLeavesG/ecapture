# Wire-default capture performance, 2026-07-30

## Scope

This test compares the default `wire` profile with the opt-in `semantic`
profile. Both runs captured a cold start of the same Doubao build for 25
seconds. The comparison evaluates capture cost and loss; it does not use
plaintext correctness as a success criterion.

Device and target:

- Google Pixel 6 emulator, Android 16, arm64-v8a
- kernel `6.6.66-android15-8-gb66429556fb8-ab13070261-4k`
- Doubao `com.larus.nova`, version `13.9.0` (`13090001`)
- eCapture local ARM64 build SHA-256
  `62ffca920c4ee0a244fc8b29512a25f277800bd05e177b2dce758479b7784662`
- clock tick rate: 100 Hz

The app was force-stopped before each run, eCapture was allowed to report
`probe started successfully.`, and the launcher activity was then cold-started.
CPU values are the delta of process `utime + stime` during the 25-second
capture window.

## Results

| Metric | Default wire | Opt-in semantic | Difference |
| --- | ---: | ---: | ---: |
| PCAPNG bytes | 3,364,292 | 3,401,756 | 1.1% |
| Perf records | 3,911 | 6,768 | semantic 1.73x |
| Perf raw bytes | 3,499,580 | 18,853,712 | semantic 5.39x |
| Structured event bytes | 254 | 12,600,076 | semantic 49,607x |
| Structured event lines | 1 | 6,770 | semantic 6,770x |
| CPU ticks in window | 26 | 44 | semantic 1.69x |
| Final RSS | 126,344 KiB | 173,568 KiB | semantic +37% |
| Threads at end | 11 | 18 | semantic +7 |
| Loaded maps / probes | 4 / 10 | 13 / 39 | semantic +9 / +29 |
| Active event readers | 1 | 5 | semantic +4 |
| Perf buffer per reader | 1 MiB | 4 MiB | semantic 4x |
| Lost samples | 0 | 0 | equal |
| Read/decode/dispatch errors | 0 / 0 / 0 | 0 / 0 / 0 | equal |

The one wire event is the bounded final `capture_stats` record. Packet data is
written once to PCAPNG and is not duplicated as base64 JSON. The semantic
profile intentionally retains packet events, transport-boundary events,
multiple perf readers, and reordering where required.

The near-equal PCAPNG sizes and zero loss/error counters show that suppressing
the structured packet copy did not remove the wire capture. Network traffic is
not perfectly deterministic, so the small PCAP size difference is not treated
as a throughput claim.

## Implemented efficiency controls

- The agent-facing default knowledge view contains only the wire profile.
  TLS/SSL, Frida, JavaScript, transport-boundary, and app-hook material is
  outside that view.
- `capture.emit_packet_events=false` prevents PCAP plus full-packet JSON
  duplication.
- Wire-only capture skips the three-second keylog/DSB grace period.
- `capture_stats` reports perf/ring-buffer volume, loss, read failures, decode
  failures, and dispatch failures at bounded intervals and shutdown.
- Related Android UID discovery polls quickly only during process churn and
  backs off to a slower steady-state interval.
- Perf reordering is disabled in the wire profile.
- The one wire reader uses a profile-controlled 256-page/1 MiB perf buffer;
  the tested cold-start burst retained zero loss.
- The Android ARM64 build helper preserves `GOOS=linux` for cilium/ebpf,
  targets Bionic, and validates the 64-byte `PT_TLS` alignment required by the
  Android linker.

## Reproduction

Build on macOS or Linux:

```bash
ANDROID_NDK_HOME=/path/to/android-ndk \
ECAPTURE_HOST_LLVM_BIN=/path/to/llvm/bin \
make android-arm64-a16
```

The output is `bin/ecapture-android-arm64-a16`. The default profile is the
application knowledge file at
`capture/ebpf/wire/profile.json`; the heavier comparison profile is under
`capture/ebpf/semantic/profile.json`.

Each run must end with a final event similar to:

```json
{"eventType":"capture_stats","final":true,"lostSamples":0,"readErrors":0,"decodeErrors":0,"dispatchErrors":0}
```
