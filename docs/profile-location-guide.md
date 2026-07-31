# Communication-boundary profile location guide

This guide defines the evidence an engineer or coding agent must collect before
adding offsets for a new application or networking-library version. The result
is a reproducible communication-capture profile, not a Frida replacement for
application objects and not a business-data decryption script.

## Scope

Production profiles target only these observations:

1. encrypted TCP/UDP packets at the kernel packet plane;
2. TLS read/write stream buffers at the networking-library boundary;
3. QUIC send/receive STREAM buffers before packet protection or after packet
   removal;
4. custom TLS BIO ciphertext for exact packet correlation;
5. socket buffers for unencrypted protocols or as a ciphertext baseline.

Request objects, logs, JNI values, serializers, parsers, and inputs or outputs
of application-specific encryption are semantic diagnostics. They are not
communication evidence and are excluded from the default scaffold. The
inspector includes them only when
`--include-semantic-diagnostics` is explicitly requested.

## Phase 1: inventory the packet and module planes

First capture raw traffic without any plaintext or key strategy. Record whether
the action produces TCP, UDP, or both, its 5-tuples, packet sizes, timing, and
the interfaces involved. Use `interfaces: ["all"]` and
`unknown_flows: "mark"` when completeness matters.

Then run the inspector:

```sh
ecapture profile inspect \
  --pid "$TARGET_PID" \
  --output /data/local/tmp/profile-report.json \
  --scaffold /data/local/tmp/profile-discovery.json
```

It reads executable mappings from `/proc/PID/maps`, records the architecture
and GNU Build ID of each accessible ELF, and ranks known communication ABIs:

- OpenSSL/BoringSSL and other supported TLS read/write APIs;
- quiche, lsquic, and supported ngtcp2 stream APIs;
- standard `readv`/`writev` and `sendmsg`/`recvmsg`;
- Build-ID-pinned recipes supplied by an external catalog.

When a reusable low-level boundary is known but its owning network library is
not, generate a short-lived stack discovery profile:

```sh
ecapture profile inspect \
  --pid "$TARGET_PID" \
  --scaffold /data/local/tmp/profile-stack-discovery.json \
  --collect-user-stacks
```

Drive one marker-bearing request at a time. First group the resulting
`userStack` frames by GNU Build ID to identify which exact Cronet, Chromium,
WebView, TLS, QUIC, or proprietary modules actually participate in each
boundary and direction. Only then rank module-relative return PCs inside the
selected owner as static-analysis anchors. This turns a broad
reverse-engineering search into a small, exact-ELF boundary search. It does not
determine the private function ABI automatically.

The repository Agent Skill can perform the action/idle difference and emit a
disabled candidate hand-off profile:

```sh
python3 .agents/skills/locate-native-network-hooks/scripts/rank_user_stacks.py \
  --input action-events.jsonl \
  --baseline idle-events.jsonl \
  --inventory /data/local/tmp/profile-report.json \
  --output network-module-attribution.json \
  --candidate-profile module-known-abi-candidates.json \
  --profile-build-id "$SELECTED_BUILD_ID" \
  --package "$TARGET_PACKAGE"
```

The report's `modules` section is the primary result. Path-derived provider
hints are separated from stronger families discovered by inspecting the exact
ELF. Stack depth zero is included in module attribution even though it is
omitted from private offset ranking by default.

The optional profile contains only known public/catalog ABI candidates joined
from `profile-report.json`, and every one remains disabled. A stripped module
with no known ABI produces a packet-only hand-off profile; its stack return PCs
remain under `static_search_anchors` and are never written as hooks.
Disassembly and runtime ABI validation are still required before promotion.
The Android 16 smoke test in
[`user-stack-hook-discovery-2026-07-30.md`](evidence/user-stack-hook-discovery-2026-07-30.md)
shows resolved Build-ID/offset candidates and the zero-loss reader metrics.

An explicit library can be inspected offline:

```sh
ecapture profile inspect \
  --library /data/local/tmp/libnetwork.so \
  --output network-report.json
```

Never promote a string, import, or symbol-name hint directly into a production
hook. It is only an anchor for the static and runtime phases below.

## Phase 2: choose the lowest sufficient communication boundary

Prefer candidates in this order:

1. a stable public TLS stream API such as `SSL_read`/`SSL_write`;
2. a stable public QUIC STREAM API with connection and stream identity;
3. a private TLS/QUIC stream function whose ABI can be pinned to a Build ID;
4. a custom TLS BIO callback for ciphertext-to-packet proof;
5. a known socket API for unencrypted payload or encrypted-wire baseline.

This order is intentionally about portability and communication provenance,
not about business semantics. A higher application object may expose a friendly
URL, but it cannot prove whether the request used TCP/TLS, QUIC, another
transport, or no network at all.

Observing an `SSL_write` input or `SSL_read` output is not eCapture decrypting
the application. It copies a transport buffer that the TLS implementation
already owns. Any encryption applied by the application above TLS remains
opaque.

## Phase 3: locate a private TLS or QUIC boundary

Use this evidence funnel when public symbols are absent or only thin wrappers
are exported:

1. Pin the exact module path, SHA-256, GNU Build ID, architecture, package
   version, and executable load segments.
2. Identify the module associated with the observed TCP/UDP flow. Imports and
   exports such as BoringSSL QUIC methods, `sendmsg`, packet writers, Cronet
   bidirectional-stream callbacks, or public QUIC names are anchors, not proof.
3. For outbound traffic, start at the socket/packet writer and walk callers
   upward until plaintext stream bytes, accepted length, connection identity,
   and stream identity are simultaneously materialized.
4. For inbound traffic, start at the socket/packet reader and follow parsed
   packet delivery until a stream callback receives a contiguous buffer or a
   proven vector.
5. Disassemble the exact entry or mid-function instruction selected for the
   uprobe. Record every register or memory dereference used for the buffer,
   length, direction, connection, stream ID, and completion/FIN state.
6. Run the candidate and require sane lengths, stable identities, correct
   direction, repeatable hits, and temporal correlation with the raw flow.
7. Store the verified ABI as a Build-ID-constrained recipe.

If stack discovery is supported on the device, use it first to prove which
private module owns the stable boundary. Resolve every frame as `(module Build
ID, file offset)` before comparing runs. Then use recurring return PCs only to
prioritize step 3 or 4 inside that module. On AArch64, `return_pc - 4` can be a
direct-`BL` callsite hint, but it is not automatically a valid uprobe.
AArch64 builds that omit frame pointers, optimized tail calls, or JIT-generated
frames may produce only a partial call chain; use bounded
register-plus-user-stack samples with DWARF/libunwindstack offline unwinding
when available. If that still fails, fall back to static cross-references,
branch tracing, or a bounded offset search.

For QUIC, `SSL_provide_quic_data` is only a handshake CRYPTO signal. It does
not carry HTTP/3 request STREAM data. A useful QUIC boundary normally has an
ABI equivalent to:

```text
send(connection, stream_id, buffer/vector, length/count, fin)
recv(connection, stream_id, buffer/vector, length/count, fin)
```

Private C++ stacks may split these fields across an object and a callsite. In
that case, use a Build-ID-pinned mid-function offset where the fields are
materialized, or add a dedicated layout adapter. Do not guess that an object
pointer is a byte pointer.

For Chromium/QUICHE-family code, an effective receive candidate is commonly a
`QuicStream::OnStreamFrame`-shaped method. Verify, from the exact disassembly
and object layout, all of:

- the stream object (`this`) and a shared session/connection pointer reachable
  from it;
- the stream ID reachable from the same object;
- the frame data pointer and length;
- the frame byte offset;
- the FIN byte, including the case where FIN accompanies zero payload.

On the send side, prefer the last function that still has the stream object,
contiguous buffer or proven vector, accepted length, and FIN value. A local
ordered-write boundary may omit an explicit byte offset; that is usable only
when call order is stable, and the reconstructed offset must be labeled
inferred rather than presented as a wire value.

Validate the reserved streams before selecting a decoder. A legacy gQUIC
connection typically exposes a crypto handshake on stream 1 and, for versions
such as Q043, HTTP/2-style HEADERS/HPACK data on stream 3 with request and
response bodies on other streams. IETF HTTP/3 instead uses unidirectional
control and QPACK encoder/decoder stream types and HEADERS/DATA frames on
request streams. Do not infer modern HTTP/3 merely from UDP/443.

When IETF HTTP/3 dynamic QPACK cannot be reconstructed from a complete encoder
instruction stream, the fallback remains inside the networking protocol stack:
locate a post-QPACK callback such as QUICHE's
`QpackProgressiveDecoder::OnHeaderDecoded` or the
`QpackDecodedHeadersAccumulator` path. Such a hook observes protocol header
fields produced by the transport's HTTP/3 decoder; it is not an application
request object or application-crypto hook. It must still carry or be correlated
to connection, direction, and request stream identity, and private offsets or
C++ layouts must be pinned to the exact Build ID. If that identity cannot be
proven, preserve the raw HEADERS block and mark it unresolved instead of
guessing a transaction.

At a function-entry uprobe, AArch64 profile arguments 1 through 8 correspond
to `x0` through `x7`; arguments 9 through 12 use the standard entry-stack
slots. On SysV amd64, arguments 1 through 6 use argument registers and 7
through 12 use entry-stack slots after the return address. At a mid-function
probe, only the disassembly at that instruction defines the ABI.

## Phase 4: describe the exact buffer layout

Supported generic layouts include:

- direct pointer plus scalar length;
- pointer stored at a verified object offset;
- length stored at a verified object offset;
- platform `iovec`;
- standard 64-bit platform `msghdr`;
- a verified libc++ string layout;
- entry arguments paired with a return value or output length.

Use `buffer_format: "iovec"` only when the vector is proven to use the platform
pointer/length pair. Configure its pointer with `buffer_arg`, count with
`vector_count_arg`, and connection or descriptor with `context_arg`.

Use `buffer_format: "msghdr"` only for a verified platform layout. On the
current 64-bit default, `msg_iov` is read at byte 16 and `msg_iovlen` at byte
24. Verify those offsets for the target ABI.

For a function that returns the number of bytes read or accepted, capture on
return and set the correct signed ABI width:

- `length_source: "return", length_size: 4` for C `int`;
- `length_source: "return", length_size: 8` for `ssize_t`;
- `length_source: "memory"` when the accepted stream length is written through
  an output pointer.

Current `ngtcp2_conn_writev_stream_versioned`, for example, uses connection
argument 1, accepted-length pointer argument 7, stream ID argument 9, and
vector/count arguments 10/11. Other versions must not inherit that layout
without header or disassembly evidence.

Chained buffers, private vectors, and C++ collections are not interchangeable
with `iovec` or `msghdr`. Add a dedicated adapter or select an instruction
where a contiguous span is already available.

## Phase 5: runtime validation

Generate controlled, non-secret network traffic and require all of the
following:

1. Raw TCP or UDP packets exist for the action.
2. The hook fires only on the expected process/module and direction.
3. Buffer addresses and lengths are nonzero, bounded, and repeatable.
4. TLS calls retain a stable SSL/BIO identity; QUIC calls retain stable
   connection and stream IDs.
5. Complete chunks reassemble without overlaps, gaps, or stale cross-call
   state.
6. TLS plaintext yields a valid protocol stream when the protocol is known;
   QUIC STREAM data is structurally plausible for the stack being tested.
7. Custom BIO ciphertext matches packet payload bytes exactly when that
   boundary is used.
8. The test runs without Frida, proxy routing, a user CA, pinning changes, or
   forced QUIC fallback.
9. A deliberately wrong Build ID prevents the offset recipe from loading.

A traffic marker may help correlate an unencrypted or transport-visible body,
but a marker is not mandatory when application encryption keeps the body
opaque. Path, header, frame, length, and packet evidence can validate the
communication boundary without reversing that encryption.

## Phase 6: production profile

Keep the exact:

- package version, process ABI, and Android/Linux release;
- target module glob and GNU Build ID;
- symbol or file offset;
- buffer, length, context, stream, vector, and return-width recipe;
- QUIC stream byte-offset and FIN layout, when exposed;
- `capture_layer`, `transport`, and any `boundary_role`;
- capture size and truncation policy;
- raw packet interfaces and unknown-flow policy.

Use `boundary_data` for every profile-defined wire or transport hook. Do not
enable `application_data`, `jni_discovery`, or `tls_keys` in a
communication-only profile. Key extraction remains a separate explicit export
mode.

For a previously verified private ABI, use a recipe catalog:

```sh
ecapture profile inspect \
  --library /data/local/tmp/libprivate.so \
  --recipe-catalog private-abi.json \
  --output private-report.json \
  --scaffold private-discovery.json \
  --pid "$TARGET_PID"
```

The inspector verifies the Build ID and that an offset lies in an executable
ELF segment. Runtime validation is still required.

## Agent hand-off checklist

An agent taking over a new application must report:

- target metadata, hashes, Build IDs, and executable mappings;
- packet-plane TCP/UDP/QUIC observations;
- inspector report and communication-boundary ranking;
- static call-graph and disassembly evidence for every private offset;
- exact register, memory, vector, and return-value ABI;
- runtime hit counts, length distributions, direction, connection/stream
  identity, truncation, and loss;
- packet correlation or controlled-traffic evidence;
- protocol reconstruction result, with opaque application-encrypted regions
  stated explicitly;
- focused unit tests, Linux BPF build, and target-device verifier result;
- unresolved protocol or version coverage.

An address copied from one build without a matching Build ID and runtime
validation is not a completed profile.

## Automation boundary

| Step | Automation | Required evidence |
| --- | --- | --- |
| ELF inventory, mapping, and Build ID | automatic | confirm target package/version |
| Stable TLS public ABI | automatic when known | runtime hit and protocol-stream test |
| `readv`/`writev` platform ABI | automatic | return-length and direction test |
| `sendmsg`/`recvmsg` platform ABI | automatic | header layout and packet-flow test |
| Public quiche/lsquic/ngtcp2 ABI | automatic when exact symbol is known | connection/stream ID and accepted-length test |
| Build-ID recipe catalog | automatic for an exact match | repeat runtime validation and wrong-Build-ID test |
| Private stripped QUIC/TLS boundary | candidate-assisted | call graph, disassembly, ABI, and flow correlation |
| Chained/private aggregate layout | adapter-assisted | exact memory layout or materialized-register ABI |
| gQUIC stream 3 HPACK decoder | automatic after stream-boundary capture | stream 1/3 signature, bidirectional FIN, framing and loss behavior |
| IETF HTTP/3 frame/stateful QPACK decoder | automatic after full stream-boundary capture | peer SETTINGS, encoder-stream history, frame timing, FIN, and loss behavior |
| Mid-connection post-QPACK adapter | version/plugin-assisted | Build-ID-pinned callback plus connection, direction, and transaction identity |
| Other protocol decoder | plugin-assisted | framing test corpus and loss behavior |
| Production promotion | never blind | complete provenance and negative validation |

The system can automate candidate ranking and profile scaffolding. It cannot
infer source-level types from arbitrary stripped machine code or claim a QUIC
stream boundary from handshake metadata alone.
