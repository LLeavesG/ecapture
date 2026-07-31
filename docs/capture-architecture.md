# Full-traffic communication capture architecture

eCapture's passive capture and protocol-viewing path is intended to replace the
corresponding mitmproxy workflow without becoming a routing proxy. It is a
side-channel observer that preserves the original application transport while
collecting evidence at several layers. This avoids CA installation, certificate
pinning bypasses, proxy routing changes, and accidental QUIC-to-TCP fallback.

No single hook can provide all of these views. A complete capture session uses
three cooperating planes.

## Scope invariant

The production path does not implement business-data decryption and does not
need request-object, JNI, log, serializer, or application-crypto hooks.

- At the packet plane it records exactly the encrypted TCP/UDP bytes carried by
  the device.
- At a TLS/QUIC communication boundary it copies the stream buffer that the
  networking library is already reading or writing. eCapture does not perform
  TLS/QUIC decryption itself: an inbound buffer is observed after the library
  has processed transport protection, and an outbound buffer before the
  library applies it.
- If the application encrypts a request body above TLS/QUIC, that body remains
  opaque. HTTP method, path, and headers can still be decoded when they are
  outside that application envelope.

This is the passive equivalent of mitmproxy's communication view, not a
business reverse-engineering pipeline. The profile strategy `boundary_data`
selects only evidence-bearing wire/transport hooks. Optional semantic
diagnostics use `application_data` and are excluded from reconstruction unless
the operator explicitly requests them.

## 1. Packet plane

TC ingress and egress programs preserve IP packets as PCAPNG and attribute
TCP/UDP flows to the selected process or UID where kernel state permits it.
This plane is protocol independent:

- TCP, UDP, TLS, DTLS, QUIC, HTTP/3, and private transports are all preserved.
- Payloads remain ciphertext when the application encrypts them.
- Unknown attribution can be included, marked, or dropped. A forensic
  all-traffic profile should use `unknown_flows: "mark"` so uncertainty is
  visible without discarding evidence.
- `interfaces: ["all"]` covers every currently-up interface and keeps a
  runtime watcher active. Newly created Wi-Fi, cellular, VPN/TUN, container,
  loopback, or emulator interfaces receive ingress/egress TC attachments and
  their own PCAPNG interface-description blocks without restarting capture.

This plane replaces the packet-routing part of a transparent proxy, but it does
not invent plaintext from ciphertext.

## 2. Communication-boundary plane

Bytes are captured where the target process crosses a transport boundary:

1. Standard TLS APIs such as `SSL_read`/`SSL_write`,
   `gnutls_record_recv`/`gnutls_record_send`, mbedTLS, wolfSSL, NSPR, and Go TLS.
2. TLS key-schedule hooks, when a supported implementation exposes enough
   state for an explicitly requested NSS key log. Key extraction is optional
   and is never implied by packet or combined communication-capture modes.
3. QUIC stream APIs such as quiche or lsquic, before or after QUIC packet
   protection.
4. Socket APIs such as `send`, `recv`, `sendmsg`, and `recvmsg`, when an
   additional syscall-boundary view is useful.
5. Custom TLS BIO callbacks, retaining the BIO pointer and encrypted TLS bytes.

A uprobe observes only the registers and user memory at its exact instruction.
It does not automatically see other functions, Java objects, a whole call
chain, or an HTTP transaction. A stripped or inlined implementation therefore
requires a version-pinned profile and runtime validation.

Android WebView, Chrome, Trichrome, and Cronet can execute a native ELF
directly from an uncompressed APK or split-APK member. eCapture resolves the
member from executable `/proc/PID/maps` file offsets and attaches against the
APK inode at `ZIP member data offset + ELF file offset`. This is a generic
archive-backed library target, not a WebView package-name special case.
System-wide archive uprobes are registered on every online CPU; otherwise a
single-CPU perf event would miss calls scheduled on the other CPUs. Discovery
stacks normalize APK container offsets back to the exact member, ELF-relative
offset, and member GNU Build ID so a candidate can be promoted directly into a
version-pinned profile.
Exported TLS APIs can be selected automatically. A stripped Chromium image
with private BoringSSL still needs a Build-ID-pinned, runtime-validated
boundary profile; APK discovery alone cannot identify the private ABI.
Package captures maintain a bounded BPF allowlist for ActivityManager-owned
isolated UIDs, so a WebView renderer remains in scope without admitting other
applications' Chromium processes.

Application request objects, logs, JNI conversions, serializers, parsers, and
business-encryption inputs are a separate optional diagnostic plane. They can
help reverse engineer an app, but they are not accepted as communication
capture evidence and are excluded from default stream reconstruction.

## 3. Reconstruction plane

User space must correlate and reconstruct events:

- packet flow: network namespace, process/UID, socket, 5-tuple, direction;
- TLS flow: SSL/BIO pointer; for a custom BIO, exact ciphertext-content
  correlation joins BIO bytes directly to reassembled TC packet payloads
  without a timestamp-only guess;
- QUIC flow: connection and stream identity;
- semantic flow: native request/adapter identity;
- ordered chunks: call identity, chunk offset, original and captured length;
- protocol decode: HTTP/1, HTTP/2, HTTP/3, WebSocket, SSE, gRPC, protobuf, or a
  user-supplied binary decoder.

Capturing bytes and presenting a mitmproxy-style request are separate
capabilities. For the verified Doubao Cronet build, communication-only capture
now recovers `POST /chat/completion` over both of the transports observed in
testing:

- TLS plus HTTP/2+HPACK, with the custom BIO ciphertext matched byte-for-byte
  in both directions to the attributed TCP packet stream;
- legacy gQUIC over UDP, with private QUIC STREAM send/receive boundaries,
  stream offsets and FIN state, stream 3 HPACK headers, and the corresponding
  body streams reconstructed into a complete transaction.

In both cases the application-encrypted body remains exact opaque bytes. For
IETF HTTP/3, QUIC stream/frame reconstruction and stateful QPACK decoding are
implemented. The decoder replays captured encoder-stream instructions using
the peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` and per-byte availability time,
including blocked header blocks and Required Insert Count wrapping. If capture
starts after the SETTINGS or required insertions, the exact HEADERS block is
retained and explicitly unresolved; a Build-ID-pinned post-QPACK protocol
boundary is the fallback for such mid-connection captures.

## Hooks implemented today

The current OpenSSL/Cronet probe can compose these hook families in one
profile:

| Hook family | Attachment | What it observes | Portability |
| --- | --- | --- | --- |
| raw packet | TC ingress/egress | attributed TCP/UDP IP packets and ciphertext | kernel/interface dependent, protocol independent |
| TLS plaintext | `SSL_read`, `SSL_write`, configured offsets or symbols | decrypted TLS stream chunks | reusable for a matching TLS ABI |
| TLS keys | TLS key-schedule/master-secret hooks | NSS-style key material where supported | TLS-build dependent |
| QUIC metadata | `SSL_provide_quic_data` | TLS handshake CRYPTO level/length | not HTTP/3 application plaintext |
| generic boundary data | `boundary_data` profile symbol/offset uprobes and optional uretprobes | direct, indirect, fixed, memory-length, return-length, libc++ string, iovec, msghdr, and arguments 1–12; every hook declares wire or transport provenance | known ABI or Build-ID-pinned |
| APK/ZIP member uprobe | exact `archive.apk!/member.so` target or executable-map discovery | the same TLS/generic boundary buffers without extracting or rewriting the app | portable container mechanism; member ABI remains Build-ID-specific |

JNI discovery and the older Doubao request-object hooks remain available only
as separately enabled reverse-engineering diagnostics. They are intentionally
omitted from this communication architecture and from the production profile;
see `application-profiles.md` and the diagnostic profiles when that unrelated
workflow is explicitly needed.

## Portability classes

| Class | Examples | Automatic reuse |
| --- | --- | --- |
| Stable public C ABI | OpenSSL, GnuTLS, mbedTLS, wolfSSL, NSPR, quiche | Usually; symbol plus known argument recipe |
| Exported iovec ABI | `readv`, `writev` | Automatically scaffolded with bounded flattening |
| Standard 64-bit msghdr ABI | `sendmsg`, `recvmsg` | Automatically scaffolded; configurable header offsets |
| Public QUIC stream ABI | quiche, lsquic, current ngtcp2 versioned writev | Automatically scaffolded; connection/stream and accepted length retained |
| Other aggregate ABI | older/private QUIC vectors, chained buffers, C++ containers | Needs an ABI-specific layout recipe |
| Stripped internal native function | private Cronet or SDK callback | String/xref/static analysis plus marker test |
| Managed networking API | Java/Kotlin callers above a native TLS/socket stack | Observe the native transport or socket boundary, not the managed request object |

Build IDs make an offset profile safe, not portable. A changed Build ID must
trigger rediscovery instead of silently reusing offsets.

## Protocol coverage

| Protocol | Raw packets | Plaintext strategy |
| --- | --- | --- |
| HTTP/1 over TLS | yes | TLS API plus HTTP/1 reconstruction |
| HTTP/2 over TLS | yes | TLS plaintext plus HTTP/2 reconstruction |
| WebSocket | yes | TLS plaintext and WebSocket frame decoder |
| QUIC / HTTP/3 | UDP ciphertext | QUIC stream boundary plus HTTP/3/QPACK reconstruction |
| legacy gQUIC | UDP ciphertext | version-pinned QUIC stream boundary; no TLS 1.3 record path |
| gRPC/protobuf | yes | capture transport stream bytes; decode compression/framing in user space |
| unencrypted private binary | yes | socket/stream boundary plus optional decoder |
| private binary over TLS/QUIC | yes | TLS/QUIC transport stream; schema remains optional |
| application-encrypted payload | yes | preserved as opaque bytes at the TLS/QUIC transport boundary |

`SSL_provide_quic_data` carries TLS handshake CRYPTO data. It cannot expose
HTTP/3 request data because QUIC protects application STREAM frames outside the
TLS record layer.

The table describes the intended boundary, not universal decoder completion.
The current implementation status is:

| Capability | Current state |
| --- | --- |
| TCP/UDP packet preservation and PCAPNG | implemented |
| runtime attachment for interfaces created after capture starts | implemented for `interfaces: ["all"]`; PCAPNG metadata is added before the TC hook |
| OpenSSL/BoringSSL stream plaintext | implemented for supported/versioned ABIs |
| APK/split-APK native-library discovery and uprobes | implemented and Android-validated against WebView `libwebviewchromium.so` and Chrome/Trichrome `libmonochrome_64.so`, including archive-aware Build-ID stack frames and isolated renderer UIDs; modern stripped Chromium still requires a validated private boundary profile |
| verified Doubao communication-only HTTP/2 chat capture | implemented and Android-validated; path, headers, status, and opaque DATA bodies reconstructed without semantic hooks |
| custom BIO to packet-flow correlation | implemented by exact TLS-ciphertext matching and Android-validated in both directions; generic fd matches are explicitly unverified |
| WebSocket frame recognition on TLS output | implemented |
| generic contiguous custom binary buffers | implemented through communication-boundary profiles |
| generic `readv`/`writev` flattened buffers | implemented and verifier/marker-validated |
| standard 64-bit `sendmsg`/`recvmsg` flattened buffers | implemented and verifier/marker-validated on Linux and Android |
| public quiche/lsquic/current ngtcp2 stream-send ABI recipes | implemented; 12-argument ngtcp2-shaped fixture verifier/marker-validated |
| QUIC handshake metadata | implemented |
| private Cronet QUIC STREAM boundary | implemented through Build-ID-pinned profiles and Android-validated for the tested Doubao build; other builds require relocation |
| generic QUIC stream sequencing | implemented; explicit receive offsets, inferred ordered send offsets, retransmission deduplication, gap/conflict reporting, and zero-length FIN events |
| verified Doubao communication-only gQUIC chat capture | implemented and Android-validated; stream 3 HPACK plus request/response body streams reconstruct a complete `/chat/completion` transaction |
| chained buffers and stack-private vectors | needs dedicated layout adapters |
| HTTP/1.0 and HTTP/1.1 transaction reconstruction | implemented for TLS boundary captures; split calls, Content-Length, chunked bodies, pipelining, and binary bodies are supported; capture-EOF-delimited bodies remain explicitly incomplete |
| HTTP/2 HPACK transaction reconstruction | implemented; complete captures decode transaction headers and bodies, while mid-connection dynamic-table state is reported as an error |
| legacy gQUIC HTTP/HPACK transaction reconstruction | implemented |
| IETF HTTP/3 frame and QPACK-stream preservation | implemented; legacy gQUIC is excluded rather than misclassified |
| IETF HTTP/3 transaction reconstruction | implemented for static, literal, and dynamic QPACK when connection SETTINGS and encoder history are captured; synthetically validated |
| mid-connection dynamic QPACK recovery | exact blocks and errors are preserved; a version-pinned post-QPACK protocol-boundary adapter is still required when earlier state was missed |
| automatic HTTP transaction aggregation | implemented for HTTP/1.x, HTTP/2, legacy gQUIC, and IETF HTTP/3 with capture-time ordering and private disk spooling |
| HAR 1.2 compatibility export | implemented; exact binary bodies remain base64, capture provenance is retained in `_ecapture`, and legacy captures require an explicit wall-time anchor |
| arbitrary protobuf/private schema decoding | captured bytes can be exported; schema/plugin is required |
| active request modification, blocking, or rerouting | outside the observer design |

For Doubao or an unrelated QUIC stack, use an exported stream ABI such as
quiche/lsquic/current ngtcp2 versioned API when present, or add a
Build-ID-pinned private-stream profile. Merely hooking BoringSSL is
insufficient because QUIC STREAM frames are outside the TLS record API.

## QUIC decoder design references

The legacy implementation follows the useful protocol-reconstruction portion
of the
[Q043 analysis](https://bbs.kanxue.com/thread-281892.htm) and
[GQUIC_043_decrypt](https://github.com/aazhuliang/GQUIC_043_decrypt):
insert STREAM data by byte offset, feed the reserved header stream through
HPACK in order, and join other stream IDs as bodies. eCapture deliberately
does not adopt that project's packet-key extraction or offline packet
decryption path because its uprobe already observes the networking library's
QUIC stream buffer.

The IETF HTTP/3 implementation follows
[Google QUICHE](https://github.com/google/quiche)'s separation of HTTP/3 frame
decoding, QPACK encoder-stream processing, Required Insert Count state, blocked
header blocks, and decoded-header callbacks. This keeps a post-QPACK callback
available as a version-pinned fallback without confusing it with an
application business-data hook.

## Automated location loop

The reusable loop is:

```text
process/ELF inventory
  -> public TLS/QUIC/socket ABI and static anchor ranking
  -> private stream callsite/ABI ranking when symbols are absent
  -> candidate hit, buffer-length, direction, and stream-identity validation
  -> packet-flow correlation and controlled traffic marker
  -> Build-ID-pinned production profile
```

`profile inspect` inventories native modules and scaffolds known public
communication ABIs. A strict `--recipe-catalog` adds Build-ID-constrained
private symbols or offsets without recompiling the inspector and rejects
non-executable offsets. Runtime promotion requires sane lengths, stable
connection/stream identity, expected direction, and correlation with controlled
traffic. These checks remain mandatory because eBPF sees registers and bytes,
not source-level types.

Structured communication-boundary chunks can be normalized immediately:

```sh
ecapture stream reconstruct \
  --input capture-events.jsonl \
  --output reconstructed-calls.jsonl

ecapture stream http1 \
  --input capture-events.jsonl \
  --output http1-transactions.jsonl

ecapture stream quic \
  --input capture-events.jsonl \
  --output quic-streams.jsonl

ecapture stream gquic \
  --input capture-events.jsonl \
  --output gquic-transactions.jsonl

ecapture stream http3-frames \
  --input capture-events.jsonl \
  --output http3-frames.jsonl

ecapture stream http3 \
  --input capture-events.jsonl \
  --output http3-transactions.jsonl

ecapture stream transactions \
  --input capture-events.jsonl \
  --output transactions.jsonl

ecapture stream har \
  --input transactions.jsonl \
  --output capture.har
```

The reassembler accepts out-of-order chunks, rejects conflicting overlaps,
groups TLS calls by SSL/BIO identity and QUIC/private streams by hook,
context/connection, and stream identity. It emits complete calls as base64 and
retains exact missing ranges for incomplete calls instead of hiding event loss.
Protocol hints distinguish HTTP/1, HTTP/2 prefaces/frames, JSON, SSE,
QUIC-stream data, text, and opaque custom binary. `stream http2` additionally
performs HTTP/2 frame and HPACK transaction decoding. `stream quic` adds QUIC
offset/FIN sequencing; `stream gquic` joins the legacy stream 3 HPACK headers
to body streams. `stream http3-frames` preserves RFC 9114 frames and QPACK
instruction streams, while `stream http3` replays the QPACK encoder stream and
emits transactions for static, literal, and dynamic-table blocks. Missing
SETTINGS, missing insertions, malformed instructions, and invalid references
are explicit decode errors, never silently guessed.

`stream transactions` runs the HTTP/1.x, HTTP/2, legacy gQUIC, and IETF
HTTP/3 transaction decoders over the same structured capture, then emits one
capture-time-ordered JSONL stream. It securely spools large/stdin inputs instead
of retaining the whole capture in memory. This JSONL is the canonical derived
transaction artifact and preserves every transaction body byte; the raw event
JSONL/PCAPNG remain the primary communication evidence. `stream har` is a
compatibility view: response content uses HAR's base64 encoding, request post
data carries an explicit `_encoding: "base64"` extension, and `_ecapture`
retains connection/stream, monotonic timing, completeness, body hashes, and
the fact that application decoding was not attempted. New structured events
include a measured RFC 3339 `wallTime`; old captures must supply
`--wall-time-anchor` rather than receiving a fabricated date.

Structured event files, reconstructed JSONL, key logs, PCAPNG, and HAR may all
contain credentials and private bodies. Local capture/export writers create
and re-protect files as mode `0600`, including an already existing output
path. Stdout and network collectors remain the operator's responsibility.

Custom BIO wire events can be correlated directly with captured packet flows:

```sh
ecapture stream correlate-wire \
  --input capture-events.jsonl \
  --output wire-correlations.jsonl
```

This command requires `boundary_role: tls_ciphertext` events and structured TC
packet events from the same capture. It reassembles TCP segments, removes
retransmission duplicates, and emits only exact byte-content matches of at
least 64 bytes. Equal-best matches are marked ambiguous. Optional
`socket_payload` and `fd_payload` hooks are fallback diagnostics; an fd-only
match is emitted with `networkVerified: false` because the descriptor may be a
file or pipe.

## Complete replacement design

A mitmproxy-like operator experience requires four more interfaces above the
capture planes:

1. **Communication-boundary adapters** for standard TLS, custom TLS BIOs,
   socket buffers, and known public QUIC stream ABIs, followed by
   version-pinned private QUIC vectors where needed.
2. **A normalized stream envelope** carrying package, PID/TID, module Build
   ID, hook identity, connection/request/stream identity, direction,
   monotonic timestamp, original length, chunk offset, and loss/truncation
   flags.
3. **Decoder plugins** for HTTP/1.x (implemented), HTTP/2+HPACK (implemented),
   legacy gQUIC+HPACK (implemented), HTTP/3 frames and stateful QPACK (implemented),
   WebSocket, SSE, gRPC framing, protobuf descriptors, and user-provided binary
   schemas.
4. **A transaction store/export API** that joins packet and TLS/QUIC stream
   evidence and exposes mitmproxy-style request/response views. The automatic
   JSONL aggregator and HAR compatibility exporter implement the offline
   portion; an indexed live store/UI remains future work. Optional semantic
   diagnostics may be displayed separately but are not required for
   communication proof.

The existing profile, packet-to-BIO exact correlation, connection/stream
fields, compact JSON event format, QUIC sequencer, and HTTP/2/gQUIC/HTTP3
offline decoders implement interfaces 1 and 2, the listed portion of interface
3, and the offline portion of interface 4.
Declaring the suite a universal mitmproxy replacement before IETF HTTP/3 is
validated against real applications, mid-connection QPACK fallback is
implemented, a live indexed view exists, and the remaining protocol decoders
are verified would be inaccurate.

## Replacement boundary

The target can replace most operational uses of mitmproxy, transparent
redirection, and Frida networking hooks:

- no proxy routing or CA;
- no pinning bypass;
- simultaneous TCP and UDP/QUIC evidence;
- exact on-device TLS/QUIC transport bytes; application encryption above the
  transport remains opaque;
- private binary payload support;
- per-package, per-version, Build-ID-pinned strategies.

It cannot promise universal semantic names for arbitrary stripped code.
Information that exists only as managed Java objects, is transformed entirely
inside JIT code, or is deliberately erased before any stable native boundary
has no universal uprobe address. The practical solution is an automated
discovery and validation loop, not a hard-coded global offset.
