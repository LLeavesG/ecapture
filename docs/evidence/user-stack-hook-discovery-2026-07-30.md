# User-stack hook discovery smoke test, 2026-07-30

## Goal

Validate that short-lived eBPF user-stack collection can reduce private native
hook discovery to Build-ID-pinned caller offsets without enabling stack
collection in the production wire profile.

The target was Doubao `13.9.0` on Android 16/arm64. A temporary discovery
profile enabled `collect_user_stack` on one already-validated custom BIO write
boundary, capped each captured payload at 64 bytes, and retained raw PCAPNG.
The default `capture/ebpf/wire/profile.json` was not modified.

## Result

- Known probe site: `libsscronet.so` Build ID
  `771865e3ad213419d75869809dc6e2d2d7ef8977`, offset `0x426a9c`.
- Boundary events with resolved user stacks: 352.
- Cold-start PCAPNG: 3,339,244 bytes.
- Reader totals: 4,232 records and 3,577,752 raw bytes.
- Lost/read/decode/dispatch errors: `0/0/0/0`.
- Ranker candidates after omitting the known depth-zero probe site:

| Rank | Module offset | Hits | Average depth |
| ---: | ---: | ---: | ---: |
| 1 | `0x42c198` | 278 | 5.000 |
| 2 | `0x42c0f4` | 278 | 6.000 |
| 3 | `0x340944` | 276 | 8.254 |
| 4 | `0x34e9a4` | 273 | 9.179 |
| 5 | `0x37e5c8` | 268 | 10.071 |

The result demonstrates that the unwinder, ASLR-to-module resolution, Build ID
resolution, action event ranking, and candidate hand-off operate on the real
target. It does not prove that any caller offset has the required buffer,
length, direction, connection, or stream ABI.

The generated hand-off profile has these safety properties:

- `raw_packets` remains its only active strategy;
- structured packet duplication and perf reordering are disabled;
- every candidate data hook has `disabled: true`;
- every candidate carries the exact module path, Build ID, and file offset;
- metadata marks the profile non-production and requires disassembly plus
  runtime ABI validation.

For an actual unknown hook, collect a separate idle window and pass it with
`--baseline`; recurring idle frames are demoted. After disassembly and a
controlled runtime test, a candidate still requires packet correlation and a
wrong-Build-ID negative test before promotion.
