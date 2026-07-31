# Application capture profiles

Application profiles make TLS and raw-packet capture reproducible for apps
that ship private OpenSSL/BoringSSL forks. A profile pins the target package,
capture strategies, interfaces, library location, hook points, and runtime
structure offsets without rebuilding eCapture.

Run a profile:

```bash
ecapture tls --profile /data/local/tmp/doubao-13.9.0-android16.json
```

Before writing a profile for a new application, inventory its loaded native
libraries and generate a conservative communication-boundary scaffold:

```sh
ecapture profile inspect \
  --pid 3423 \
  --output profile-report.json \
  --scaffold profile-discovery.json
```

See [`profile-location-guide.md`](profile-location-guide.md) for the required
Build-ID, ABI, packet-correlation, and runtime-validation workflow. The default
scaffold includes only known TLS/QUIC/socket communication ABIs. Hints from
stripped private libraries are never promoted to offsets automatically.

JNI and request-object discovery remain available for unrelated, optional
reverse-engineering work. They are excluded by default and require
`profile inspect --include-semantic-diagnostics`. Those events are not accepted
as transport evidence and do not enter stream reconstruction unless
`--include-semantic` is also explicitly set.

For a private exported ABI or a previously validated internal offset, pass an
external recipe catalog to the same inspector:

```sh
ecapture profile inspect \
  --pid 3423 \
  --recipe-catalog private-network-abi.json \
  --output profile-report.json \
  --scaffold profile-discovery.json
```

A symbol recipe may optionally be Build-ID constrained. An offset recipe must
include the exact Build ID; the inspector also rejects offsets outside an
executable `PT_LOAD` segment. Catalog fields are strictly decoded and the
embedded hook is validated with the same profile rules before any ELF is
inspected. See
[`examples/recipe-catalogs/private-quic.example.json`](../examples/recipe-catalogs/private-quic.example.json).

Explicit CLI flags override profile values. This is useful when only one
offset changed in a new app build:

```bash
ecapture tls \
  --profile /data/local/tmp/doubao-13.9.0-android16.json \
  --struct-offset ssl_st_rbio=0x20 \
  --hook ssl_write=@0x48bb0
```

One capture can attach the exported `SSL_read`/`SSL_write` probes to more than
one TLS provider. The primary `tls.library` or `tls.library_glob` still selects
the bytecode family, private layout offsets, key-log hooks, and QUIC metadata
hooks. Auxiliary providers are selected with:

- `tls.additional_libraries`: exact library paths;
- `tls.additional_library_globs`: path globs, all of whose matches are used;
- `tls.auto_discover_libraries`: compatible TLS images mapped by the target
  PID/UID plus the platform TLS provider (Android Conscrypt).

The equivalent CLI flags are `--libssl-extra`, `--libssl-extra-glob`, and
`--libssl-auto`. Automatically discovered candidates must match the running
architecture and export both `SSL_read` and `SSL_write`. Auxiliary providers
receive symbol-addressed plaintext probes only: primary-library offsets and
private structure layouts are deliberately never copied to another image.
This lets one UID use an app-bundled BoringSSL and platform Conscrypt in the
same capture without pretending that their private ABIs are interchangeable.

Android can map an uncompressed native ELF directly from an APK or split APK
instead of extracting it as a standalone `.so`. Exact `library` and
`additional_libraries` values support the following archive-member syntax:

```text
/data/app/.../base.apk!/lib/arm64-v8a/libwebviewchromium.so
```

eCapture reads symbols, architecture, and GNU Build ID from the ELF member,
but registers the uprobe against the APK inode at `ZIP data offset + ELF file
offset`. The member must use ZIP `STORE`, as required for direct executable
mapping. `auto_discover_libraries` also inspects executable APK/ZIP mappings
and resolves the member from its mapped file-offset range; it does not depend
on package names such as Chrome, WebView, Trichrome, or on a fixed library
basename.

Automatic auxiliary TLS hooks still require exported `SSL_read` and
`SSL_write`. Modern Chromium/WebView images are commonly stripped and keep
BoringSSL private, so merely discovering `libwebviewchromium.so` does not
prove a usable plaintext boundary. For those builds, put a Build-ID-pinned
symbol or verified private offset in `data_hooks`; do not copy a private
offset from a different WebView release.

For Android package profiles, eCapture also watches ActivityManager's explicit
`packageList` ownership and maintains a bounded BPF UID allowlist for related
isolated processes. This includes WebView/Chrome sandbox services assigned a
temporary isolated UID without broadening the capture to every WebView on the
device. The primary package UID remains the default filter, stale isolated
UIDs are removed, and PID-only profiles remain strictly PID-scoped.

When `collect_user_stack` reaches an APK-backed native image, structured
events report the exact `archive.apk!/member.so`, the ELF-relative
`moduleOffset`, and the embedded ELF GNU `moduleBuildId`. The raw
`base.apk+container offset` form is not exposed as a reusable hook candidate.
System-wide archive uprobes are opened on every online CPU.

The supported strategies are:

- `raw_packets`: TC ingress and egress packets in PCAPNG.
- `tls_plaintext`: `SSL_read` and `SSL_write` plaintext.
- `tls_keys`: NSS key log output and PCAPNG decryption-secret blocks.
- `quic_metadata`: `SSL_provide_quic_data` handshake metadata.
- `boundary_data`: profile-defined wire and TLS/QUIC
  communication-boundary hooks. Semantic hooks are excluded even if they are
  present in `data_hooks`.
- `application_data`: optional semantic diagnostics such as request objects,
  logs, serializers, or JNI-adjacent values. Existing profiles that used this
  name before `boundary_data` remain compatible, but new communication
  profiles must use `boundary_data`.
- `jni_discovery`: ART `RegisterNatives` metadata, standard JNI
  managed-reference conversion events, and module-relative native offsets.
- `cronet`: compatibility alias for `application_data`.

Every `data_hooks` entry declares where its bytes came from:

- `capture_layer: "wire", transport: "tls"` for TLS record ciphertext at a
  custom BIO;
- `capture_layer: "wire", transport: "socket"` for a known socket API;
- `capture_layer: "wire", transport: "fd"` for a generic descriptor
  candidate that is not yet proven to be a socket;
- `capture_layer: "transport", transport: "tls"` for bytes inside TLS record
  protection;
- `capture_layer: "transport", transport: "quic"` for QUIC stream bytes inside
  packet protection;
- `capture_layer: "semantic"` for request objects, logs, JNI conversions,
  serializers, and other diagnostic copies.

Hooks created before this field existed default to `semantic`; they never gain
transport provenance implicitly. `boundary_data` selects only `wire` and
`transport` hooks. Boundary events serialize as `eventType: "boundary_data"`;
semantic events retain `eventType: "application_data"`. `ecapture stream
reconstruct` ignores semantic events by default. `--include-semantic` is an
explicit diagnostic opt-in.

`mode: "all"` enables raw packets and the selected TLS strategies together.
When no interfaces are supplied, all currently-up interfaces are selected.
The literal interface name `all` does the same thing. Each selected interface
gets both Ethernet and raw-IP PCAPNG descriptions so VPN/TUN traffic is not
written with an invalid link type.

Attribution policy controls packets for which the TC tuple map has no full
PID/UID/cgroup record:

- `include`: keep the packet and annotate its metadata as unknown.
- `mark`: keep it with the unknown-flow flag.
- `drop`: omit it.

`strict_attribution: true` changes the default policy to `drop`. TC also uses
the skb socket UID when the full tuple record is not available, while PID and
cgroup filters still require a full attribution record.

Hook values accept an exported symbol, an ELF address prefixed by `@` on the
CLI, or `off`. JSON hooks use `symbol`, `offset`, or `disabled`. Structure
offsets accept decimal numbers or quoted hexadecimal values. Supported names:

- `ssl_st_rbio`
- `ssl_st_wbio`
- `ssl_st_version`
- `ssl_st_s3`
- `ssl3_state_version`
- `bio_st_method`
- `bio_st_num`
- `bio_method_st_type`

Generic boundary hooks are declared in `data_hooks`. Up to eight hooks can be
active in one profile. A direct pointer/length API looks like this:

```json
{
  "name": "cronet-buffer-write",
  "library_glob": "/data/app/*/com.example.app-*/lib/arm64/libcronet.so",
  "symbol": "Cronet_Buffer_InitWithDataAndCallback",
  "direction": "write",
  "capture_on": "entry",
  "buffer_arg": 2,
  "length_source": "argument",
  "length_arg": 3,
  "max_bytes": 131072
}
```

`library` and `library_glob` select the hook target. An optional `build_id`
rejects a library whose GNU ELF build ID differs from the profiled build;
using it is strongly recommended for offset hooks. `symbol` can be replaced by
an ELF `offset`. Exact `library` values may use the APK member syntax shown
above. `library_glob` may glob the archive path while keeping an exact member,
for example `/data/app/*/com.google.android.webview-*/base.apk!/lib/arm64-v8a/libwebviewchromium.so`.
For an archive member, profile offsets remain relative to the embedded
ELF—eCapture adds the ZIP member offset only when attaching. Arguments are
numbered from 1 through 12. At a function-entry
uprobe, amd64 arguments 1–6 and arm64 arguments 1–8 are in registers; the
remaining supported arguments are read from their ABI-defined entry stack
slots. A mid-function offset may already have moved or overwritten both
register and stack values, so its profile must describe the state at that
exact instruction. `buffer_offset` adds a byte offset to the selected buffer
argument; `buffer_indirect` reads a pointer from that location. The optional
`buffer_format: "libcxx_string"`
decodes Android Chromium's 24-byte libc++ `std::string` layout, including its
short-string optimization; its data pointer and length are derived from the
object, so all `length_*` fields must be omitted. For the default
`buffer_format: "raw"`, length can come from:

- `argument`: the value of `length_arg`.
- `memory`: a 1, 2, 4, or 8-byte integer at
  `length_arg + length_offset`; `length_arg: 0` reuses the buffer object's
  base address, and `length_indirect` adds one pointer dereference.
- `fixed`: a constant byte count from the resolved buffer or object base.
  This uses `fixed_length` and is intended for reverse-engineering private
  message objects before exact pointer and length offsets are known.
- `return`: the positive function return value; this requires
  `capture_on: "return"`. `length_size` selects the signed return ABI width:
  `4` for callbacks returning C `int`, or `8` (the default) for `ssize_t`.

`capture_on: "return"` stores entry arguments per thread and emits after the
function returns. Each call is emitted in bounded 16 KiB chunks, up to
`max_bytes` and an absolute 128 KiB ceiling. Hook names and chunk metadata are
included in text/JSON events so different application strategies can be
correlated without rebuilding eCapture.

`collect_user_stack: true` adds a bounded 16-address user call chain to each
event. This is a discovery switch, not a production default. Its first purpose
is library attribution: group resolved frames by GNU Build ID to determine
which exact Cronet, Chromium/WebView, QUIC, TLS, or proprietary image owns an
observed boundary. Only then use return PCs inside the selected module as
static-analysis anchors. Generate a stack-enabled scaffold with:

```sh
ecapture profile inspect \
  --pid "$TARGET_PID" \
  --scaffold app-stack-discovery.json \
  --collect-user-stacks
```

Start with stable low-level boundaries such as `sendmsg`, `writev`,
`SSL_write`, or a known QUIC packet writer. Structured events report absolute
addresses plus resolved module paths, module-relative offsets, and GNU Build
IDs. A stack return PC, including an AArch64 `return_pc - 4` callsite hint, is
not a proven uprobe. Promote only a known public/catalog ABI or a disassembled
and marker-validated private buffer ABI into the production profile, then
remove `collect_user_stack`.

User unwinding is best effort. Frame-pointer omission, inlining, tail calls,
JIT code, unreadable mappings, and kernel unwind support can make a stack
shallow or incomplete. An empty or partial stack is not evidence that no caller
exists, and a frame hit alone does not prove the buffer/length ABI. A discovery
backend may instead record bounded user registers and raw stack bytes and use
DWARF/libunwindstack offline; recovered frames must be normalized to the same
module Build-ID and ELF-offset form before attribution.

Perf output includes only the fixed event header plus `data_len` bytes. It no
longer transfers an otherwise empty 16 KiB payload area for every small event;
capture limits still matter because copying the actual bytes and emitting many
events remains expensive.

For a packet-plane-only profile, set `emit_packet_events: false`. Packets still
go to the authoritative PCAPNG handler, but the structured text/JSON handler
does not encode and store a second copy. This is the recommended production
default when no stream reconstruction consumes packet JSON. Profiles that need
`stream correlate-wire` must keep packet events enabled.

`perf_buffer_pages` overrides the per-reader perf buffer size in system pages.
Values from 64 through 16384 are accepted. A wire-only profile with one reader
can use 256 pages (1 MiB on a 4 KiB-page device) after a representative burst
test proves `lostSamples: 0`. Multi-reader semantic capture should retain the
larger default unless equivalent loss evidence supports a reduction.

Every perf/ringbuf reader emits a `capture_stats` event after each 4096 records
and at shutdown. It contains `perfRecords`, `perfRawBytes`, `ringbufRecords`,
`ringbufRawBytes`, `lostSamples`, `readErrors`, `decodeErrors`, and
`dispatchErrors`. Absence of a warning is not a zero-loss claim; use the
structured counters.

`context_arg` and `stream_arg` optionally copy two scalar arguments into every
event and preserve them across a uretprobe. They are intended for a connection,
request, adapter, channel, or QUIC stream identity. For example,
`quiche_conn_stream_send(conn, stream_id, buf, len, fin)` uses:

```json
{
  "buffer_arg": 3,
  "length_arg": 4,
  "context_arg": 1,
  "stream_arg": 2,
  "fin_arg": 5
}
```

This makes multiplexed streams reconstructable; without the connection and
stream identity, capturing HTTP/3 bytes alone is insufficient.

Private QUIC objects can expose the same metadata through verified object
fields. `context_offset`/`context_size` and
`stream_offset`/`stream_size` read connection and stream identity from their
respective argument objects. `stream_byte_offset_arg` selects the argument
that owns an explicit QUIC STREAM byte offset;
`stream_byte_offset_offset` and `stream_byte_offset_size` describe the scalar
inside that object. `fin_arg`, `fin_offset`, and `fin_size` do the same for
the final flag. Scalar sizes must be 1, 2, 4, or 8 bytes.

For example, a verified `QuicStream::OnStreamFrame`-shaped private ABI can be
represented as:

```json
{
  "capture_layer": "transport",
  "transport": "quic",
  "direction": "read",
  "buffer_arg": 2,
  "buffer_offset": "0x8",
  "buffer_indirect": true,
  "length_source": "memory",
  "length_arg": 2,
  "length_offset": "0x2",
  "length_size": 2,
  "context_arg": 1,
  "context_offset": "0x1e0",
  "context_size": 8,
  "stream_arg": 1,
  "stream_offset": "0x1d8",
  "stream_size": 4,
  "stream_byte_offset_arg": 2,
  "stream_byte_offset_offset": "0x10",
  "stream_byte_offset_size": 8,
  "fin_arg": 2,
  "fin_offset": "0x1",
  "fin_size": 1
}
```

These offsets are examples from one Build-ID-pinned layout, not portable
Chromium constants. The receive offset permits out-of-order insertion and
retransmission deduplication. When an ordered send API has no byte-offset
field, `stream quic` infers send offsets from call order and labels the result
`offsetMode: "inferred"`. A zero-byte call with a valid true FIN is emitted as
a metadata-only boundary event, so bodyless FIN frames and FINs delivered
separately from the final data buffer are not lost.

Wire hooks can also declare `boundary_role`:

- `tls_ciphertext`: encrypted TLS records observed at a custom BIO, with
  `context_arg` identifying the BIO; requires `wire/tls`;
- `socket_payload`: bytes passed to or returned from a socket API, with
  `context_arg` identifying the fd; requires `wire/socket`;
- `fd_payload`: bytes passed to a generic fd API, with `context_arg`
  identifying the descriptor; requires `wire/fd` and does not itself prove a
  network boundary.

`ecapture stream correlate-wire` first joins `tls_ciphertext` directly to
reassembled TC TCP/UDP payloads when at least 64 bytes match exactly. These
results carry `networkVerified: true`. Socket/fd hooks are optional fallback
diagnostics, and generic fd matches remain explicitly unverified. This supports
custom BIOs where `SSL_set_fd` is never called and works even when BIO buffering
and socket I/O occur on different threads.

Scatter/gather APIs use `buffer_format: "iovec"`. The buffer argument is the
direct `struct iovec *`, and `vector_count_arg` selects the count:

```json
{
  "name": "socket-writev",
  "library": "/apex/com.android.runtime/lib64/bionic/libc.so",
  "symbol": "writev",
  "direction": "write",
  "capture_on": "entry",
  "buffer_arg": 2,
  "buffer_format": "iovec",
  "vector_count_arg": 3,
  "context_arg": 1,
  "max_bytes": 131072
}
```

For `readv`, use `direction: "read"` and `capture_on: "return"`; the positive
return value limits the final vector to bytes actually received. No
buffer offset/indirection or asynchronous state fields are valid for an iovec
hook. By default, a return-captured iovec uses the positive function return as
the accepted length. `length_source: "memory"` instead defers reading a signed
1/2/4/8-byte scalar at `length_arg + length_offset` until the uretprobe. This
models APIs such as ngtcp2, whose function return is encrypted packet length
while `*pdatalen` reports accepted stream plaintext. The eBPF program inspects
at most 16 vectors and emits at
most eight 16 KiB chunks (128 KiB total). Every chunk shares one call
timestamp and the iovec-array address, and uses an offset in the flattened
logical stream. More vectors, an oversized stream, or an unreadable vector is
reported as truncation or a reconstruction gap rather than silently
concatenating the wrong bytes.

The inspector safely scaffolds the public `readv` and `writev` ABIs.

The standard 64-bit `sendmsg`/`recvmsg` ABI uses
`buffer_format: "msghdr"`. `buffer_arg` selects the direct `struct msghdr *`;
the adapter obtains `msg_iov` and `msg_iovlen` from the header and then uses
the same bounded flattening path:

```json
{
  "name": "socket-recvmsg",
  "library": "/apex/com.android.runtime/lib64/bionic/libc.so",
  "symbol": "recvmsg",
  "direction": "read",
  "capture_on": "return",
  "buffer_arg": 2,
  "buffer_format": "msghdr",
  "context_arg": 1,
  "max_bytes": 131072
}
```

The defaults are `buffer_offset: 16` for `msg_iov`,
`length_offset: 24` for `msg_iovlen`, and an eight-byte count. These defaults
match the Linux/glibc and Android/bionic arm64/amd64 layouts tested by the
project. A nonstandard or private header can override those offsets only after
its exact ABI has been verified. `sendmsg` captures on entry; `recvmsg`
captures on return so the positive result bounds the flattened data.
`vector_count_arg`, `length_*`, header indirection, and asynchronous state
fields are invalid for this adapter.

The inspector automatically scaffolds all four standard public ABIs:
`readv`, `writev`, `sendmsg`, and `recvmsg`. It does not assume a
library-specific vector, chained buffer, or C++ collection has either layout;
those require a stack-specific adapter or a hook at a point where pointer and
length are already materialized.
The marker-validated integration fixture is
[`testdata/iovec_capture_profile.json`](../testdata/iovec_capture_profile.json);
its [runtime evidence](evidence/iovec-capture-2026-07-29.md) includes verifier
and reconstruction results.

The inspector also has exact public-ABI recipes for:

- `quiche_conn_stream_send`/`quiche_conn_stream_recv`;
- `lsquic_stream_write`/`read` and `writev`/`readv`;
- the current 12-argument
  `ngtcp2_conn_writev_stream_versioned`, where connection is argument 1,
  accepted plaintext is `*arg7`, stream ID is argument 9, and the
  `ngtcp2_vec` pointer/count are arguments 10/11.

ngtcp2 documents `ngtcp2_vec` as `struct iovec` compatible. Older
unversioned ngtcp2 symbols are left as hints because their argument order has
varied; their installed header and Build ID must be inspected before creating
a profile.

Asynchronous APIs can split buffer creation and completion across different
functions or threads. Pair two hooks with the same `state_group`: a
`state_action: "save"` hook resolves and stores its buffer/maximum length under
the value of `state_key_arg`; a `state_action: "load"` hook uses its own
`length_*` fields but retrieves the saved buffer using the same key. Both hooks
must capture on entry. The load consumes the saved state, preventing stale
buffers from being reused.

When a hook is intentionally dumping opaque binary objects or second-stage
pointer targets, run the profile with `--hex`. Text mode preserves payload
bytes but loggers may escape non-printable data, which makes structure recovery
harder than the explicit hex dump.

See
[`examples/profiles/doubao-13.9.0-android16.json`](../examples/profiles/doubao-13.9.0-android16.json)
for a complete communication-only Android profile. Its private custom-BIO
offsets are pinned to the exact `libsscronet.so` Build ID; it contains no
semantic hook.

Structured events can be converted into transport views with:

```sh
ecapture stream reconstruct --input capture.jsonl --output calls.jsonl
ecapture stream http1 --input capture.jsonl --output http1.jsonl
ecapture stream http2 --input capture.jsonl --output http2.jsonl
ecapture stream websocket --input capture.jsonl --output websocket.jsonl
ecapture stream quic --input capture.jsonl --output quic-streams.jsonl
ecapture stream gquic --input capture.jsonl --output gquic-http.jsonl
ecapture stream http3-frames --input capture.jsonl --output http3-frames.jsonl
ecapture stream http3 --input capture.jsonl --output http3.jsonl
ecapture stream transactions --input capture.jsonl --output transactions.jsonl
ecapture stream har --input transactions.jsonl --output capture.har
ecapture stream correlate-wire --input capture.jsonl --output correlations.jsonl
```

The HTTP/1 decoder pairs requests/responses and supports split TLS calls,
Content-Length, chunked transfer coding, pipelining, and binary bodies. A
capture-EOF-delimited response is retained as incomplete because capture EOF
does not prove protocol EOF. The HTTP/2 decoder reconstructs frames and HPACK
headers and preserves DATA bodies byte-for-byte. The WebSocket decoder locates
HTTP/1.1 Upgrade/101 handshakes, reassembles frames split across TLS calls,
unmasks client frames, joins fragmented messages, emits ping/pong/close
controls separately, and preserves compressed or private binary payloads
byte-for-byte without application decoding. The QUIC sequencer preserves
connection, stream, direction, offset, FIN, gaps, duplicates, conflicts, and
exact stream bytes.
The gQUIC decoder joins HPACK headers on reserved stream 3 to request/response
body streams. The HTTP/3 frame decoder preserves control, request, push, and
QPACK streams. The HTTP/3 transaction decoder replays captured encoder
instructions with the peer's QPACK SETTINGS and each block's availability
time, so static, literal, dynamic, wrapped, and initially blocked references
can be resolved. If capture began after the required SETTINGS or insertion,
the exact block is retained with an explicit error. None of these decoders
reverses application-layer encryption.

`stream transactions` automatically combines HTTP/1.x, HTTP/2, legacy gQUIC,
and IETF HTTP/3 transactions in capture-time order. Its JSONL output is the exact artifact;
`stream har` derives a tool-compatible view whose request and response bodies
remain base64 and whose `_ecapture` fields retain transport provenance,
monotonic timing, completeness, and body hashes. New captures include a
measured `wallTime`; use `--wall-time-anchor` only for a legacy event file that
lacks it. Capture and derived files are forced to mode `0600` because headers,
cookies, and bodies are sensitive.

Raw PCAPNG contains all selected network traffic, while TLS/QUIC transport
events expose only the bytes the transport implementation itself sees.
Application-encrypted request bodies remain opaque even after HTTP path and
headers are reconstructed.

For packet-only collection, prefer the wire profile with
`emit_packet_events: false`. The Android 16 cold-start comparison in
[`wire-default-performance-2026-07-30.md`](evidence/wire-default-performance-2026-07-30.md)
measured near-equal PCAPNG volume and zero loss while eliminating the full
packet JSON copy and reducing perf traffic, CPU time, memory, readers, maps,
and probes.
`SSL_provide_quic_data` exposes QUIC handshake activity, not HTTP/3 request
payloads. Boundary hooks emit separate eCapture events; they do not rewrite
encrypted packets inside the PCAPNG.

Legacy gQUIC does not use the TLS 1.3 `SSL_provide_quic_data` path. When
`raw_packets` is enabled, eCapture still preserves its UDP datagrams and
annotates visible TLS and gQUIC Client Hello packets with their server name.
Later application datagrams remain encrypted and are identified as the same
flow by their source/destination tuple in the PCAPNG. A proxy or UDP/443
fallback can change an application's transport to TCP/TLS, so captures made
with and without such instrumentation are not necessarily protocol-equivalent.
Legacy versions such as Q043 carry HPACK-framed headers on stream 3 rather than
using RFC 9114/QPACK. `stream gquic` and `stream http3` therefore have separate
detectors and do not feed the same connection to both decoders.
