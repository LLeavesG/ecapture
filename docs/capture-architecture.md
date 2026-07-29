# Full-traffic and plaintext capture architecture

eCapture should not emulate a transparent proxy. Its target architecture is a
side-channel observer that preserves the original application transport while
collecting evidence at several layers. This avoids CA installation, certificate
pinning bypasses, proxy routing changes, and accidental QUIC-to-TCP fallback.

No single hook can provide all of these views. A complete capture session uses
three cooperating planes.

## 1. Packet plane

TC ingress and egress programs preserve IP packets as PCAPNG and attribute
TCP/UDP flows to the selected process or UID where kernel state permits it.
This plane is protocol independent:

- TCP, UDP, TLS, DTLS, QUIC, HTTP/3, and private transports are all preserved.
- Payloads remain ciphertext when the application encrypts them.
- Unknown attribution can be included, marked, or dropped. A forensic
  all-traffic profile should use `unknown_flows: "mark"` so uncertainty is
  visible without discarding evidence.
- Hooking every currently-up interface covers Wi-Fi, cellular, loopback, VPN,
  and emulator interfaces that exist when capture starts. Interfaces created
  later still need dynamic attachment support.

This plane replaces the packet-routing part of a transparent proxy, but it does
not invent plaintext from ciphertext.

## 2. Plaintext-boundary plane

Plaintext is captured where the target process already owns it:

1. Standard TLS APIs such as `SSL_read`/`SSL_write`,
   `gnutls_record_recv`/`gnutls_record_send`, mbedTLS, wolfSSL, NSPR, and Go TLS.
2. TLS key-schedule hooks, when a supported implementation exposes enough
   state for an NSS key log.
3. QUIC stream APIs such as quiche or lsquic, before or after QUIC packet
   protection.
4. Application semantic APIs such as Cronet request creation, upload
   `ByteBuffer` callbacks, and response read callbacks.
5. Serializer and parser boundaries for protobuf, FlatBuffers, gRPC, or a
   private binary protocol.
6. The input/output boundary of custom application encryption when the
   serializer output is encrypted again above TLS or QUIC.

A uprobe observes only the registers and user memory at its exact instruction.
It does not automatically see other functions, Java objects, a whole call
chain, or an HTTP transaction. A stripped or inlined implementation therefore
requires a version-pinned profile and runtime validation.

## 3. Reconstruction plane

User space must correlate and reconstruct events:

- packet flow: network namespace, process/UID, socket, 5-tuple, direction;
- TLS flow: SSL/BIO pointer and file descriptor;
- QUIC flow: connection and stream identity;
- semantic flow: native request/adapter identity;
- ordered chunks: call identity, chunk offset, original and captured length;
- protocol decode: HTTP/1, HTTP/2, HTTP/3, WebSocket, SSE, gRPC, protobuf, or a
  user-supplied binary decoder.

Capturing bytes and presenting a mitmproxy-style request are separate
capabilities. The former is implemented for the verified Doubao Cronet build;
generic transaction correlation and decoder plugins remain ongoing work.

## Hooks implemented today

The current OpenSSL/Cronet probe can compose these hook families in one
profile:

| Hook family | Attachment | What it observes | Portability |
| --- | --- | --- | --- |
| raw packet | TC ingress/egress | attributed TCP/UDP IP packets and ciphertext | kernel/interface dependent, protocol independent |
| TLS plaintext | `SSL_read`, `SSL_write`, configured offsets or symbols | decrypted TLS stream chunks | reusable for a matching TLS ABI |
| TLS keys | TLS key-schedule/master-secret hooks | NSS-style key material where supported | TLS-build dependent |
| QUIC metadata | `SSL_provide_quic_data` | TLS handshake CRYPTO level/length | not HTTP/3 application plaintext |
| generic app data | profile symbol/offset uprobes and optional uretprobes | direct, indirect, fixed, memory-length, return-length, libc++ string, iovec, msghdr, arguments 1–12, and asynchronous paired buffers | known ABI or Build-ID-pinned |
| JNI discovery | ART `RegisterNatives` implementation/wrappers | method name, JNI signature, runtime function and module offset | reusable across apps on the same ART Build ID |

The JNI locator statically finds `JNINativeInterface[215]`; it does not depend
on an exported `RegisterNatives` symbol. At runtime 16 BPF programs cover 256
method-table entries and are attached to every validated ART candidate offset.
Userspace masks common arm64 TBI/PAC bits, requires an executable process
mapping, and converts every function pointer to `module+offset`.

On Android 16 the locator found `0x69be84`, `0x8171b0`, `0x4d1ef4`, and
`0x888ca4` in ART Build ID `be34fbe63ff357beb403f9cb39923ea7`.
A Doubao cold start executed hook candidate 2 and exposed registrations from
`libkeva.so`, `libnpth.so`, `libnpth_repair.so`, `libworker.so`,
`libbdheif.so`, and framework connectivity JNI. That demonstrates
cross-library discovery; it does not claim that all those functions carry
network payloads. The sanitized
[runtime evidence](evidence/doubao-jni-discovery-2026-07-29.md) records the
commands, counts, representative candidates, and artifact hashes.

## Verified Doubao 13.9.0 Cronet hooks

These offsets apply only to `libsscronet.so` with GNU Build ID
`771865e3ad213419d75869809dc6e2d2d7ef8977`.

| Slot | Offset | Observed ABI | Result |
| --- | ---: | --- | --- |
| request URL | `0x235454` | argument 4 is a 24-byte libc++ string | full URL/path |
| request method | `0x2354e4` | argument 2 is a libc++ string | `GET`/`POST` |
| header name | `0x235578` | argument 2 is a libc++ string | request header name |
| header value | `0x235578` | argument 3 is a libc++ string | request header value |
| upload save | `0x234bc4` | arg 2 + `0x10` points to data; arg 3 is capacity; arg 1 is adapter key | saves pending direct buffer |
| upload complete | `0x2348ec` | arg 3 is the same adapter; arg 5 is bytes read | emits request body |
| response complete | `0x2360bc` | arg 2 + `0x10` points to data; arg 3 is bytes read | emits decrypted response body |

The upload pair is necessary because Java fills a `DirectByteBuffer`
asynchronously and reports the actual length later, potentially on another
thread. The eBPF state map is keyed by process, adapter identity, and state
group. Its LRU policy bounds abandoned operations.

These hooks are above the transport selection. The same URL, request body, and
response body are visible whether Cronet chooses TCP/TLS, IETF QUIC, or legacy
gQUIC.

## Portability classes

| Class | Examples | Automatic reuse |
| --- | --- | --- |
| Stable public C ABI | OpenSSL, GnuTLS, mbedTLS, wolfSSL, NSPR, quiche | Usually; symbol plus known argument recipe |
| Exported iovec ABI | `readv`, `writev` | Automatically scaffolded with bounded flattening |
| Standard 64-bit msghdr ABI | `sendmsg`, `recvmsg` | Automatically scaffolded; configurable header offsets |
| Public QUIC stream ABI | quiche, lsquic, current ngtcp2 versioned writev | Automatically scaffolded; connection/stream and accepted length retained |
| Other aggregate ABI | older/private QUIC vectors, chained buffers, C++ containers | Needs an ABI-specific layout recipe |
| Dynamically registered JNI | Android Cronet `J.N.*` methods | Discover registration, then validate arguments |
| Stripped internal native function | private Cronet or SDK callback | String/xref/static analysis plus marker test |
| Pure Java/Kotlin or ART JIT code | Java serializers, OkHttp interceptors | Native uprobes are not stable; prefer JNI/native/crypto/socket boundary |
| Custom serialization/encryption | private protocol | Find serializer/parser or pre/post-encryption boundary |

Build IDs make an offset profile safe, not portable. A changed Build ID must
trigger rediscovery instead of silently reusing offsets.

## Protocol coverage

| Protocol | Raw packets | Plaintext strategy |
| --- | --- | --- |
| HTTP/1 over TLS | yes | TLS API or HTTP semantic hook |
| HTTP/2 over TLS | yes | TLS plaintext plus HTTP/2 reconstruction |
| WebSocket | yes | TLS plaintext and WebSocket frame decoder |
| QUIC / HTTP/3 | UDP ciphertext | QUIC stream or application semantic hook |
| legacy gQUIC | UDP ciphertext | application semantic hook; no TLS 1.3 record path |
| gRPC/protobuf | yes | capture serialized messages; decode compression/framing in user space |
| unencrypted private binary | yes | socket or serializer hook |
| private binary over TLS/QUIC | yes | TLS/QUIC stream or serializer hook |
| application-encrypted payload | yes | hook before encryption and after decryption |

`SSL_provide_quic_data` carries TLS handshake CRYPTO data. It cannot expose
HTTP/3 request data because QUIC protects application STREAM frames outside the
TLS record layer.

The table describes the intended boundary, not universal decoder completion.
The current implementation status is:

| Capability | Current state |
| --- | --- |
| TCP/UDP packet preservation and PCAPNG | implemented |
| OpenSSL/BoringSSL stream plaintext | implemented for supported/versioned ABIs |
| verified Doubao Cronet URL/method/header/body callbacks | implemented and marker-validated |
| WebSocket frame recognition on TLS output | implemented |
| generic contiguous custom binary buffers | implemented through application profiles |
| generic `readv`/`writev` flattened buffers | implemented and verifier/marker-validated |
| standard 64-bit `sendmsg`/`recvmsg` flattened buffers | implemented and verifier/marker-validated on Linux and Android |
| public quiche/lsquic/current ngtcp2 stream-send ABI recipes | implemented; 12-argument ngtcp2-shaped fixture verifier/marker-validated |
| dynamic JNI native inventory and ranking | implemented |
| QUIC handshake metadata | implemented |
| generic private Cronet HTTP/3 or arbitrary stripped QUIC STREAM plaintext | not yet implemented |
| chained buffers, stack-private vectors, Java heap objects | needs dedicated layout/conversion adapters |
| HTTP/2 HPACK transaction reconstruction | needs reconstruction plugin |
| HTTP/3 QPACK transaction reconstruction | needs QUIC stream capture plus reconstruction plugin |
| arbitrary protobuf/private schema decoding | captured bytes can be exported; schema/plugin is required |
| active request modification, blocking, or rerouting | outside the observer design |

For Doubao, the verified Cronet semantic hooks sit above transport selection,
so they remain useful when the same request moves from HTTP/2/TLS to
HTTP/3/QUIC. For an unrelated QUIC stack, use an exported stream ABI such as
quiche/lsquic/current ngtcp2 versioned API when present, add a
version-pinned private-stream profile, or locate the application serializer
callback. Merely hooking BoringSSL is insufficient.

## Automated location loop

The reusable loop is:

```text
process/ELF inventory
  -> public ABI and static anchor ranking
  -> ART RegisterNatives discovery for Android
  -> structured event learning
  -> candidate hit/ABI validation
  -> synthetic request+response marker
  -> Build-ID-pinned production profile
```

`profile inspect` implements the first three static steps and can scaffold a
cold-start JNI profile. A strict `--recipe-catalog` adds Build-ID-constrained
private symbols or offsets without recompiling the inspector and rejects
non-executable offsets. `--event-format=json` plus `profile learn-jni`
implements the dynamic reduction step. The final ABI and marker checks remain
mandatory because eBPF sees registers and bytes, not source-level types.

Structured plaintext chunks can be normalized immediately:

```sh
ecapture stream reconstruct \
  --input capture-events.jsonl \
  --output reconstructed-calls.jsonl
```

The reassembler accepts out-of-order chunks, rejects conflicting overlaps,
groups TLS calls by SSL/BIO identity and application calls by hook,
context/connection, and stream identity. It emits complete calls as base64 and
retains exact missing ranges for incomplete calls instead of hiding event loss.
Protocol hints currently distinguish HTTP/1, HTTP/2 prefaces/frames, JSON, SSE,
QUIC-stream data, text, and opaque custom binary. These hints are classification,
not full HPACK/QPACK transaction decoding.

## Complete replacement design

A mitmproxy-like operator experience requires four more interfaces above the
capture planes:

1. **Boundary adapters** for contiguous buffers, iovec, standard 64-bit
   msghdr, and known public QUIC stream ABIs (implemented), then private QUIC
   vectors, JNI conversions, common C++ containers, and crypto/serializer
   APIs.
2. **A normalized stream envelope** carrying package, PID/TID, module Build
   ID, hook identity, connection/request/stream identity, direction,
   monotonic timestamp, original length, chunk offset, and loss/truncation
   flags.
3. **Decoder plugins** for HTTP/1, HTTP/2+HPACK, HTTP/3+QPACK, WebSocket, SSE,
   gRPC framing, protobuf descriptors, and user-provided binary schemas.
4. **A transaction store/export API** that joins packet, TLS/QUIC stream, and
   semantic events and exposes mitmproxy-style request/response views.

The existing profile, contiguous/iovec/msghdr adapters, connection/stream
correlation fields, compact JSON event format, and offline reassembler
implement the foundation of interfaces 1 and 2. Declaring the suite a full
replacement before generic Cronet QUIC stream capture, remaining
stack-specific aggregate-buffer adapters, cross-call transaction correlation,
and full protocol decoders are verified would be inaccurate.

## Replacement boundary

The target can replace most operational uses of mitmproxy, transparent
redirection, and Frida networking hooks:

- no proxy routing or CA;
- no pinning bypass;
- simultaneous TCP and UDP/QUIC evidence;
- exact on-device pre-encryption and post-decryption bytes;
- private binary payload support;
- per-package, per-version, Build-ID-pinned strategies.

It cannot promise universal semantic names for arbitrary stripped code.
Information that exists only as managed Java objects, is transformed entirely
inside JIT code, or is deliberately erased before any stable native boundary
has no universal uprobe address. The practical solution is an automated
discovery and validation loop, not a hard-coded global offset.
