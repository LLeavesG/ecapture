# Android Chromium archive-hook validation — 2026-07-30

## Scope

This validation asked whether Android WebView, Chrome, and Trichrome need
special native-library handling and whether that handling can remain generic.
The reference implementation was
[`LLeavesG/eAppAnalyzer`](https://github.com/LLeavesG/eAppAnalyzer), inspected
at commit `e5c3acba7659e6ec6e55ab86a1c9dc85329eac7b`.

The useful reference idea is correct: when Android maps a stored ELF directly
from an APK, an uprobe must target the APK inode at:

```text
ZIP member data offset + ELF file offset
```

No reference code or dependency fork was copied. In particular, eCapture does
not hard-code Chrome/WebView package names or `libmonochrome*.so`, does not
extract to an unrelated temporary inode, and does not depend on private forks
of `cilium/ebpf` or `ebpfmanager`.

## Implemented design

- Exact targets use `archive.apk!/member.so`.
- `library_glob` may glob the archive path while keeping the member exact.
- Executable APK/ZIP/JAR mappings are matched to stored ELF-member ranges from
  `/proc/PID/maps`.
- ELF class, machine, symbols, executable segments, and GNU Build ID are read
  through a bounded section reader without extracting the member.
- Archive uprobes use the upstream uprobe PMU directly. System-wide links are
  opened on every online CPU; PID-scoped links use `pid, cpu=-1`.
- Package capture follows ActivityManager `packageList` ownership and updates a
  bounded BPF allowlist for isolated renderer UIDs.
- Discovery stacks normalize `base.apk+container offset` to
  `base.apk!/member.so+ELF offset` and attach the member Build ID.
- JNI function-table scanning is restricted to `libart.so`/`libartd.so`;
  scanning Chromium writable data had produced 17,732 false candidates.

## Test device

| Property | Value |
| --- | --- |
| Device | Android emulator, Pixel 6 (`oriole`), arm64 |
| Android | 16, fingerprint `google/oriole/oriole:16/CP1A.260405.005/15001963:user/release-keys` |
| Kernel | `6.6.66-android15-8-gb66429556fb8-ab13070261-4k` |
| Online CPUs | `0-7` |

## Provider inventory

| Provider | Archive member | ZIP data offset | GNU Build ID |
| --- | --- | ---: | --- |
| Android WebView 150.0.7871.124 | `base.apk!/lib/arm64-v8a/libwebviewchromium.so` | `0xdf0000` | `90b73cbae14cab8e87bbdbc3fac1e977ff728fb6` |
| Trichrome for Chrome 150.0.7871.181 | `base.apk!/lib/arm64-v8a/libmonochrome_64.so` | `0x948000` | `abb113784eaabdb68fec9c10af7ee82d0783cab7` |

Both images are stripped and keep BoringSSL private. Neither exports
`SSL_read`/`SSL_write`, so automatic classic-TLS attachment correctly refuses
to claim a plaintext boundary.

## Runtime results

### APK discovery and uprobe attachment

- Live `/proc` discovery found the WebView and Trichrome members at the exact
  offsets above.
- Build-ID-pinned `library_glob` profiles resolved `JNI_OnLoad` and attached
  successfully to both APK inodes.
- The Trichrome validation resolved an absolute APK uprobe offset of
  `113568320` and started its event reader.
- `JNI_OnLoad` was used only as an attachment-mechanism check. A missing event
  after attachment is expected when the WebView/Trichrome zygote loaded the
  image before the probe was installed.

### WebView host process

A package-scoped Doubao run produced:

- 840 structured events;
- 120 packet events;
- 720 libc boundary events;
- 62 boundary events whose user stacks entered Doubao `libsscronet.so`;
- dynamic inclusion of the old isolated renderer UID `99068`.

No stack in that action window entered `libwebviewchromium.so`. This is valid
negative evidence: the tested launch/chat action used Doubao Cronet and did not
issue WebView network I/O. Merely mapping WebView is not proof that a request
used it.

### Chrome/Trichrome network run

Cold-starting Chrome and loading controlled HTTPS URLs produced:

- 797 packet events;
- 5,143 libc boundary events;
- 2,845 boundary events with a Trichrome APK frame;
- successful package ownership updates as isolated UIDs changed from `90016`
  to `90017` and `90018`;
- zero user-stack collection failures.

After archive-frame normalization, frames were emitted in reusable form, for
example:

```json
{
  "modulePath": "/data/app/.../base.apk!/lib/arm64-v8a/libmonochrome_64.so",
  "moduleOffset": 118909940,
  "moduleBuildId": "abb113784eaabdb68fec9c10af7ee82d0783cab7"
}
```

This proves that Chrome/Trichrome traffic can be attributed to the correct
APK-backed native owner and yields Build-ID-pinned caller offsets for the next
private-boundary search.

## Rejected candidate

The reference-style AArch64 byte-pattern search proposed an apparent WebView
write candidate at ELF offset `0x6071818`. It attached successfully but emitted
no events during controlled Google WebView and Doubao traffic. It was rejected
and was not added to a production profile. Static byte similarity without a
runtime hit and ABI proof is insufficient.

## Verification

- Android `openssl` package tests pass when run with repository profile
  fixtures; the unrelated Linux cgroup-path negative test is skipped on the
  Android binary.
- All `profileinspector` tests pass on device.
- CO-RE `boringssl_a_16` bytecode compiles with LLVM and loads through the
  Android verifier.
- Live tests validate stored-member discovery, archive glob resolution,
  Build-ID checks, all-CPU raw uprobe attachment, isolated-UID updates, TC
  packet capture, libc boundary capture, and archive-aware user stacks.

## Conclusion and remaining boundary

Additional Chromium-library handling is necessary for attribution and for
private native boundary hooks, but it is not necessary to preserve raw TCP/UDP
packets: TC capture already sees those packets independently of the library.
The implemented support is generic across APK-backed native libraries and
contains no Doubao, Chrome, WebView, or Trichrome package special case.

This result does not claim a universal Chromium plaintext hook. For the tested
stripped builds, the next step is to use the verified libc call stacks as a
search funnel, walk upward from the ranked Trichrome offsets, derive the exact
buffer/length/connection or QUIC-stream ABI, and promote only a controlled-hit,
negative-control-tested offset pinned to the member Build ID.
