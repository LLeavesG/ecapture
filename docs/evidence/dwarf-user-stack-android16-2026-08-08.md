# eBPF DWARF user-stack validation, 2026-08-08

## Goal

Validate arm64 DWARF CFI unwinding inside eBPF without Frida or an offline
userspace unwinder. The target was `com.larus.nova` on Android 16/arm64,
kernel `6.6.66`, using profile-defined `SSL_read` and `SSL_write` uprobes.

## Loaded rule set

The final optimized cold-start run parsed 454 native executable mappings and
skipped 13 unreadable or unsupported mappings. Userspace reduced their CFI to:

- 80,798 4 KiB page headers;
- 3,969,943 source transitions compacted to 2,889,696 logical transitions;
- 1,444,848 eight-byte physical delta pairs;
- 3,347 unique 12-byte unwind rules;
- 3,740,451 CFI segments.

Map `max_entries` values were rewritten to those prepared sizes before map
creation. Kernel-mode stack profiles rewrite all three DWARF maps to one entry,
so the optional backend does not reserve its worst-case array when disabled.
Each page also carries 17 lower-bound indexes for 256-byte subranges. The BPF
lookup searches only the selected subrange plus its preceding transition,
rather than the full page, while preserving the active rule across empty
subranges. Two logical four-byte transitions share each eight-byte array-map
value because Linux gives a four-byte BPF array value an eight-byte element
stride anyway.

## Verifier and runtime result

The Android kernel verifier accepted both application-data paths:

- `probe_entry_app_data_0`;
- `probe_ret_app_data_0`.

An initial runtime sample exposed pointer-authentication bits in saved return
addresses. The fixed implementation tries the supported arm64 user VA widths
and accepts a PAC/TBI-normalized PC only when it exists in the PID-scoped CFI
page table.

After that fix, one 45-second DWARF capture produced 58 TLS boundary events:

- 24 events had 14 frames and stopped normally;
- 34 events reached the configured 16-frame bound;
- all 880 emitted frames resolved to a mapped ELF module;
- lost samples and decode/dispatch errors were zero.

As a correctness oracle, the same process and hooks were captured with
`bpf_get_stack(BPF_F_USER_STACK)`. Two independently observed, distinct
16-frame stack signatures occurred in both captures, and every module-relative
offset matched at every depth. This also confirmed that repeated Cronet return
PCs in those signatures were real call-chain entries rather than CFI state
errors.

## APK and bucket-index regression

After adding archive-member resolution and the 256-byte page index, a fresh
Android 16 run used the same `com.larus.nova` process while Magisk `su`
reported `CapEff=0` and `CapBnd=0x8000c0`. Both BPF programs still passed the
real kernel verifier and the capture loaded successfully, confirming that the
old capability-bit preflight was a false negative in this Android root
environment.

The startup pass loaded 454 modules, including one directly mapped APK member,
and materialized 80,797 pages, 3,440,226 transitions, and 3,347 unique rules.
The densest page contained 512 transitions; the densest indexed 256-byte range
contained 64. A 35-second end-to-end run emitted seven TLS boundary records;
every record contained a successful 16-frame DWARF stack, with zero lost
samples, read errors, decode errors, or dispatch errors.

## Large-application optimization regression

The optimized loader uses four-byte per-page transition slices instead of one
Go hash map per page. It skips sorting already ordered pages, uses a stable
sort only for overlapping/out-of-order rows, resolves repeated writes with
last-write semantics, removes transitions which retain the same active rule,
and reserves the packed output once. This removed 1,080,247 redundant logical
transitions (27.2%) in the final Nova process.

The live kernel reported these exact CFI map charges through `/proc/PID/fdinfo`:

- delta pairs: 11,559,168 bytes;
- PID/page hash: 11,147,744 bytes;
- unwind info array: 53,936 bytes;
- total: 22,760,848 bytes (21.7 MiB).

On adjacent runs of the same application, changing the temporary page table
from eight-byte transitions to four-byte transitions and releasing all upload
buffers after map population reduced eCapture's post-start RSS from about
222 MiB to 118 MiB. Peak RSS fell from about 293 MiB to 273 MiB. The final
parse, compaction, map creation, upload, attach, and forced memory release took
nine seconds.

The final structured capture produced 240 TLS boundary events. Seventy-eight
stopped normally at 14 frames and 162 reached the configured 16-frame bound;
all 3,684 frame addresses resolved to mapped ELF modules and no event carried
a negative DWARF status. Both entry and return programs also passed the real
Android 16 kernel verifier after the packed-delta change.

## Scope

DWARF mode currently supports arm64 and requires one explicit PID. It parses
the mappings present at startup. Directly mapped `ZIP STORE` native libraries
inside base/split APKs are resolved by container offset and parsed in place
with a section reader. JIT code, compressed archive members, later `dlopen`
images, and unsupported CFI expressions terminate the bounded stack safely and
are reported through `userStackStatus`. If the target process exits and the
package starts under a new PID, the capture must currently be restarted because
both filtering and CFI page keys are scoped to the original PID.

The next scalable extension should keep the exact-sized live maps: cache
module-relative CFI by Build ID (or a validated archive-member/file identity
when no Build ID exists), monitor the target mapping generation, and rebuild a
new exact-sized capture generation when `dlopen` or PID replacement changes
the image set. Reserving a large append-only delta array would make refresh
simpler but would permanently give back much of the memory saved here.

The compact userspace-to-BPF rule-table design follows the same broad split as
[OpenTelemetry eBPF Profiler's stack-delta extraction](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/tree/main/tools/stackdeltas).
This implementation uses the MIT-licensed
[Delve DWARF frame interpreter](https://github.com/go-delve/delve/tree/master/pkg/dwarf/frame)
only during startup; all event-time frame walking remains in eBPF.

Stackplz was also reviewed, but its current path solves a different problem:
it configures perf to sample the full arm64 register set and a configurable
user-stack byte range
([source](https://github.com/SeeFlowerX/stackplz/blob/62fc9e82f025b73232f92be7faafc9fd671bb510/user/module/imodule.go#L185-L216)),
then parses those bytes after delivery
([source](https://github.com/SeeFlowerX/stackplz/blob/62fc9e82f025b73232f92be7faafc9fd671bb510/user/event/event_context.go#L291-L333))
through its preloaded C unwinder library
([source](https://github.com/SeeFlowerX/stackplz/blob/62fc9e82f025b73232f92be7faafc9fd671bb510/user/event/chelper.go#L24-L98)).
That is useful for broad offline/native/Java unwinding, but it does not meet
this implementation's pure event-time eBPF constraint and transfers much more
data per hit. eCapture therefore emits only the bounded address array and
keeps Delve, libunwindstack, temporary ELF extraction, and Frida out of the
event path.
