# Doubao transport and HTTP/2 evidence (2026-07-30)

This is a sanitized communication-capture verifier record. Raw JSONL, PCAPNG,
TLS keys, full URLs, headers, and bodies remain outside the repository because
they contain account and device identifiers. No JNI conversion, logging,
serializer, request-object, or application-decryption hook contributed to this
result.

## Target and capture boundary

- Package: `com.larus.nova`
- Platform: Android 16, arm64, emulator `emulator-5560`
- Process: PID `10489`
- App TLS library: `libttboringssl.so`; exported `SSL_read`, `SSL_write`,
  `SSL_set_fd`, and `SSL_provide_quic_data`
- App Cronet library: `libsscronet.so`, GNU Build ID
  `771865e3ad213419d75869809dc6e2d2d7ef8977`
- Probe binary GNU Build ID:
  `941d2d24f4e84bf14a175febc5eda7a17c263951`
- Probe binary SHA-256:
  `bd76f840572d9a1529ecd15ca473df986bf7a9d35708ec156cc4fefd3db785b6`

The enabled strategies were limited to:

- TC ingress/egress raw packets;
- BoringSSL `SSL_read`/`SSL_write` transport bytes;
- TLS key material;
- `SSL_provide_quic_data` handshake metadata.

The marker sent through the normal UI was `EBPFTLS20260730G`.

## Preserved evidence

| Artifact | Size/count | SHA-256 |
| --- | ---: | --- |
| structured capture JSONL | 688 lines, 662,489 bytes | `514ca9c343aefac12d305bebbd166871360cfad18885555596be7c1d264bbad2` |
| PCAPNG | 440 packets, 131,072 bytes | `f019f3a0507a3ef3abede1f6a5604ded142495ec8a8a2409495df80ca277142d` |
| TLS key log | 1,292 bytes | `d3e24a17c1ba289608d964eaa67cf513d3c9285584ebb7d2907720fa8e6f1212` |
| HTTP/2 transaction JSONL | 6 transactions | `3ad400aae6d31fab8f9bdb8beada804e67ce1111095db105bf74bb904ac8d10f` |

The PCAPNG contains 438 TCP packets and 2 UDP packets. Structured events
contained 478 raw packet records, 28 connection records, 180
`tls_plaintext` records, and 2 TLS master-secret records. The TLS records
covered 8 `SSL*` connections, 145 reads, 35 writes, and 37,626 transport
bytes, with no truncation, decode failure, or perf-buffer-loss warning.

## HTTP/2 reconstruction result

`ecapture stream http2` reassembled split SSL calls, parsed 169 HTTP/2 frames,
and maintained independent HPACK state for each connection and direction. It
emitted 6 transactions across 8 TLS connections. Four HPACK failures occurred
on connections first observed after their dynamic table was already in use;
2,792 bytes were discarded while resynchronizing those incomplete streams.

One complete transaction was:

| Field | Sanitized value |
| --- | --- |
| method | `POST` |
| authority | `api5-normal-lf.doubao.com` |
| path | `/chat/completion` (query removed) |
| response status | `200` |
| request content type | `application/json; encoding=utf-8` |
| response content type | `text/event-stream` |
| request DATA length | 2,684 bytes |
| response DATA length | 7,956 bytes |
| request body SHA-256 | `b20d76fe4741ec455d93b31d72044130dfa0d129a7dfa0148936a795320b687c` |
| response body SHA-256 | `af449007d25901586432efe24159ae4f9c32d3f246377f7d2d9790c09b2f387a` |

Both header blocks decoded without error, and request/response END_STREAM
states were observed. This proves that the path and transaction came from the
TLS communication stream rather than an application log.

The synthetic marker does not occur in either transport body. Those DATA bytes
remain the application's opaque business payload. That is the intended
boundary: protocol metadata is reconstructed, while application-layer
encryption or encoding is neither reversed nor claimed to be reversed.

## Custom BIO to packet-flow validation

The first run above reported `fd=0`. Cronet installs a custom BIO with
`SSL_set0_rbio`/`SSL_set0_wbio`, so `SSL_set_fd` never supplies an fd. Static
relocation analysis found the BIO write callback at
`libsscronet.so+0x426a9c` and read callback at
`libsscronet.so+0x426d40`.

A second Android run sent the normal-UI marker `EBPFWIRE20260730H`. It captured
the two custom BIO callbacks, attributed TC packets, TLS transport events, and
exploratory libc socket/fd hooks. The final correlator did not rely on the libc
hooks: it reassembled TCP payloads from the TC events and matched them directly
against BIO TLS ciphertext.

| Artifact | Size/count | SHA-256 |
| --- | ---: | --- |
| structured capture JSONL | 73,203 lines, 147,274,653 bytes | `8358842570938208b77850c141acb4c6980cea7b08f475b7d04a520496dc6182` |
| PCAPNG | 589,824 bytes | `3be7fec945fb938be1a2db00c3e0bcc251579f8d6b5f40f7f91569539816955b` |
| TLS key log | 15 lines, 3,180 bytes | `666fad80a08018b70f27389e4a1d5310c87a809859e6f5ecac575a46e96d1bfc` |
| wire correlation JSONL | 24 records, 11,349 bytes | `472070714e9b29664953e61d1e58a986ce161c44dc5e6cc110e69fb27340ecb0` |
| HTTP/2 transaction JSONL | 9 transactions, 62,595 bytes | `9db84c86c2bd6884cf334b5e219ed630d080eea4e6f58cac55dc92d27a59349f` |

The structured capture contained 1,394 packet records, 40 connection records,
513 TLS transport records, and 1,668 custom-BIO ciphertext records. The
exploratory generic `read`/`write` hooks produced 68,062 fd records and were
therefore removed from the final communication profile.

`stream correlate-wire` saw 25 BIO direction streams. It emitted:

- 23 network-verified TCP matches, totaling 255,086 exact bytes;
- 20 full-coverage matches and three partial matches with 75% or greater
  coverage;
- 12 read-direction and 12 write-direction outputs;
- no ambiguous match;
- one fd-only candidate explicitly marked `networkVerified: false`;
- one unmatched stream below the confidence requirements.

The marked chat transaction reconstructed as a complete
`POST /chat/completion`, status `200`, with a 2,551-byte request DATA body and
a 7,594-byte SSE response DATA body. Its BIO identity had an independent,
100%-coverage packet match in both directions: 16,709 outbound TLS-ciphertext
bytes and 12,772 inbound bytes. This is the missing end-to-end join: the
HTTP/2 transaction came from the TLS transport stream, and that same BIO's
encrypted TLS records were present byte-for-byte in the attributed TCP packet
stream. No application semantic or business-decryption hook is needed for this
proof.

## Reduced production-profile regression

After the exploratory run, the production profile was reduced to two private
hooks: the custom BIO read and write callbacks. Generic libc socket/fd hooks
were removed. The BIO read callback's return ABI was also pinned to a signed
32-bit C `int`, so a `-1` retry result cannot be interpreted as
`0xffffffff` bytes.

A final run sent `EBPFWIRE20260730I` through the normal UI and received a
response. The Android binary had GNU Build ID
`634699cb665e6b5a73ef5e4bd520f869f5b5126f` and SHA-256
`4622aed7beb187b931cb6f15a6ef337dc4b5df87dfcb128f33a960c67d8a1f89`.

| Artifact | Size/count | SHA-256 |
| --- | ---: | --- |
| structured capture JSONL | 2,872 lines, 3,401,014 bytes | `bd019f4467a53b7c992bc3d6099fc7c54c9eabe1099a8cc38cc694ab86a8ff2a` |
| PCAPNG | 655,360 bytes | `8293c5117bfee43cf23ac7c8e50056ccca6544cd27f288de8efb78fdb9bbd878` |
| wire correlation JSONL | 21 records, 9,971 bytes | `762fb6cf1c7efe080796901f6398e5a143095994269a574e790747cc50468ae4` |

The capture contained 1,918 attributed packet events (968 TCP and 950 UDP),
407 TLS transport events, 528 custom-BIO ciphertext events, 18 connection
metadata events, and no generic fd/socket event. It contained no
`originalLen=0xffffffff` BIO event. The log contained no decode failure,
application chunk-range error, or perf-buffer-full warning.

The correlator matched 21 of 25 BIO direction streams directly to 26 packet
flows: 10 read and 11 write, 235,109 exact bytes, 18 full-coverage matches,
minimum coverage 82%, no ambiguity, and no unverified fd fallback. The
remaining four streams did not cross the 64-byte exact-match threshold.

This short run began in the middle of existing HTTP/2 connections, so seven
HPACK dynamic-table errors prevented a second independent path-level chat
claim. That limitation is reported instead of guessed around; the preceding
G3 run supplies the complete `/chat/completion` plus bidirectional packet-join
evidence.
