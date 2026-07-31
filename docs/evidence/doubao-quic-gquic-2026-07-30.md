# Doubao QUIC/gQUIC communication evidence (2026-07-30)

This is a sanitized communication-capture verifier record. Raw JSONL and
decoded transaction output remain outside the repository because they contain
account identifiers, cookies, headers, request payloads, and response text.
No Frida, proxy, user CA, TLS key export, JNI conversion, request-object,
logging, serializer, or application-decryption hook contributed to this
result.

## Target and boundary

- Package: `com.larus.nova`, UID `10290`
- Platform: Android 16, arm64, emulator `emulator-5560`
- Network module: `libsscronet.so`
- Module GNU Build ID:
  `771865e3ad213419d75869809dc6e2d2d7ef8977`
- Probe binary GNU Build ID:
  `034e16e86c2673f05f8536cca696613562089d85`
- Probe binary SHA-256:
  `f9c75df052f0f0d2f5889a198a6957cc409a16cc5dfa6e98ef84be57f6fcc750`

The Build-ID-pinned validation profile used three private transport-boundary
hooks:

- ordered stream write at module offset `0x61d904`;
- vector stream write at `0x61e13c`;
- `OnStreamFrame`-shaped receive boundary at `0x61c9f8`.

The stream object supplied stream ID at `this+0x1d8` and a connection-shared
context pointer at `this+0x1e0`. The receive frame supplied FIN at `frame+0x1`
and the explicit stream byte offset at `frame+0x10`. These offsets are valid
only for the listed module Build ID.

## Boundary validation run

A cold-start metadata run contained 5,715 structured records:

- 5,391 attributed packet records;
- 322 QUIC `boundary_data` records;
- 2 QUIC metadata records.

The boundary records contained 88 writes totaling 186,995 bytes and 234 reads
totaling 182,186 bytes. The main connection context contributed 304 events
across 42 odd-numbered stream IDs from 1 through 83. Every receive event had
an explicit byte offset; every write had FIN metadata and used ordered inferred
offsets. Reassembled receive streams had no gap and no conflicting overlap.
There were 43 true FIN observations.

The first bytes identified the transport as legacy gQUIC rather than RFC 9114:
stream 1 carried `CHLO`/`REJ`, stream 3 carried valid HTTP/2 HEADERS frames and
HPACK blocks, and the remaining streams carried HTTP bodies. Replaying stream 3
through the header decoder produced 40 transactions from 80 header frames with
zero HPACK error and zero resynchronized byte.

## Zero-length FIN regression

The probe was changed to preserve a true FIN even when its associated data
length is zero. A normal-UI chat run then captured exactly three metadata-only
FIN events:

| Stream ID | Final byte offset |
| ---: | ---: |
| 5 | 160 |
| 9 | 123 |
| 7 | 7,920 |

This closes transactions whose final STREAM frame carries no body bytes,
without fabricating a one-byte payload.

## Complete chat transaction

The final run sent a synthetic non-secret marker through the normal UI and
received a visible response. The capture contained 2,914 packet records and
367 QUIC boundary records. `stream gquic` reconstructed three transactions;
all three were complete. It consumed six header frames and six body streams
on one gQUIC connection with zero HPACK error and zero resynchronization.

One complete transaction was:

| Field | Sanitized value |
| --- | --- |
| method | `POST` |
| path | `/chat/completion` (query removed) |
| response status | `200` |
| request body | exact opaque bytes, 2,698 bytes |
| response body | exact opaque bytes, 7,920 bytes |
| request FIN | observed |
| response FIN | observed |
| transaction state | complete |

The marker does not occur in the transport body because the application
applies its own encoding or encryption above QUIC. That is expected and does
not weaken the communication proof: method, path, headers, status, body byte
boundaries, and both end states came from QUIC STREAM data in the networking
library, while the body remains intentionally opaque.

## Artifact integrity

| Artifact | SHA-256 |
| --- | --- |
| raw structured capture | `8a91dcc24383311e97a06422a4af3cedf29d7b4cbf5e33606674cd8ecd804f35` |
| reconstructed QUIC streams | `4bcd03695ae2212f78a7a8c5b1fbd6653d9a3d6ac6f04dbace65ae43b7f69096` |
| reconstructed gQUIC transactions | `24e20aa2c59c1f7352421cb65375c77bab2ac71a65e356712307bed3f1a40148` |

These artifacts are intentionally retained outside version control. Their
hashes allow later audit without publishing sensitive material.

## Final decoder regression

After the stateful HTTP/3/QPACK decoder was added, the final Android build had
GNU Build ID `0d9671a6b0b358d4120ff89aef6639a230c85a60` and SHA-256
`a08b424b44a003b5ae3e785b756987110180cc12f63c5376c796bad978e02c56`.
Replaying the same capture produced:

- 18 QUIC direction-streams from 367 calls across two contexts;
- three complete gQUIC HTTP transactions, zero HPACK error, and zero
  resynchronized byte;
- the same gQUIC transaction artifact SHA-256
  `24e20aa2c59c1f7352421cb65375c77bab2ac71a65e356712307bed3f1a40148`;
- zero HTTP/3 frame and zero HTTP/3 transaction output, proving that the new
  RFC 9114 decoder did not misclassify the legacy gQUIC connection.

## Automatic aggregation and HAR regression

The same 3,835,446-byte raw capture was passed through `stream transactions`
without selecting a protocol. It emitted three complete transactions:
zero HTTP/1.x, zero HTTP/2, three legacy gQUIC, and zero HTTP/3. The
compatibility HAR then reported 3,807 request-body bytes and 8,203
response-body bytes in total.
For the chat transaction, byte counts derived from the base64 length and
padding remained 2,698 and 7,920. Counting decoded data as Unicode characters
is invalid for these opaque binary bodies and under-reports their byte length.

Every transaction request/response base64 value was byte-for-byte identical
to its corresponding HAR body value. Every HAR entry stated
`applicationDecoding: "not-attempted"` and `bodyTransformation: "none"`.
Because this historical capture predates the measured `wallTime` event field,
the regression used an explicit test anchor and all three entries were marked
`legacyWallTimeAnchored: true`; no test anchor is presented as observed capture
time. Both pre-existing output paths began as mode `0644` and were
automatically re-protected as `0600`.

| Derived artifact | SHA-256 |
| --- | --- |
| capture-time-ordered automatic transaction JSONL | `effd7a6e596ce8b97c0f29d14316fb19912785f656126f76d1506ac49deb29e7` |
| HAR compatibility view with explicit test time anchor | `7f25991aa3aa2c3f997e5457f20c6351daa39632062ffdb8804301db12ab6586` |

The final Linux build had GNU Build ID
`14b97c68fb0e2b8547f464153bb85061e1096001` and SHA-256
`ce6070068ee873e12d4ae8cb31ca2f57f9c65963ace3776590c755b04f8e2877`.
The final Android build had GNU Build ID
`033e448c59ad9d9a545182c1a20c7f7bd5db1226` and SHA-256
`11fb8f46652fd2635fe380a18566dee2f4e468ee8d7148069ceb8186a7e8a051`.
That Android binary was started on `emulator-5560`; its offline `stream` help
listed `http1`, `transactions`, `har`, and all protocol-specific decoders.

## Spawn-hook plus MITM versus eCapture on July 30, 2026

The same `com.larus.nova` build was then exercised twice on the Android 16
emulator:

- capture A used the existing spawn-hook plus MITM workflow;
- capture B used only the final Android eCapture binary with UID `10290`,
  raw packet capture, QUIC metadata, and the three profile-defined Cronet
  boundary hooks.

Both runs cold-started the app and sent the same synthetic marker
`ecap_ab_20260730_1600_reply_ok`. The marker is non-secret and was chosen only
to align the two traces.

### Sanitized comparison around the send action

| Observation | Spawn-hook + MITM (A) | eCapture (B) |
| --- | --- | --- |
| chat request | `POST /chat/completion` | `POST /chat/completion` |
| chat request opaque bytes | `2698` | `2698` |
| chat response opaque bytes | `8204` | `8236` |
| chat completion flag | HTTP route closed normally | decoder kept `response endStream = false` |
| read-marker side effect | `POST /im/message/mark_conv_read` | `POST /im/message/mark_conv_read` |
| read-marker opaque bytes | `226 / 122` | `226 / 123` |
| extra routes during precise send window | `POST /handshake`, `POST /collect/log/v1/`, `GET /internal/api/v1/ws` | none reconstructed |
| websocket visibility | one upgraded websocket with `95` binary messages | none reconstructed |

The eCapture run reconstructed ten legacy gQUIC transactions across the whole
cold-start-plus-send interval, six marked complete. The send-phase transaction
set still contained the two expected Doubao API routes:

- `POST /chat/completion`
- `POST /im/message/mark_conv_read`

The key point is that the chat request body boundary matched exactly at
2,698 opaque bytes without using any MITM, CA certificate, or Frida body
decryption.

### What was missing in eCapture and why

The raw event file for capture B contained:

- `10,604` wire-level packet events;
- `9,141` TCP packets and `1,422` UDP packets;
- `454` transport-level `boundary_data` events; and
- `2` QUIC metadata events.

It did **not** contain any TLS plaintext events for TCP traffic. A later audit
found that this comparison used the narrow
`doubao-13.9.0-android16-quic-stream-validation` profile, whose strategy list
did not enable `tls_plaintext`. The absence therefore cannot be used as
evidence that the mapped Conscrypt provider was unobservable.
That distinction matters:

- the wire packets for mixed TCP and UDP traffic were captured;
- the profiled Cronet gQUIC path was reconstructed into HTTP semantics;
- the missing `handshake`, telemetry, and websocket routes were therefore not
  lost at the network edge, but they were not decoded into transactions by the
  current user-space hook set.

That validation profile was centered on:

- `libttboringssl.so` for QUIC/TLS context metadata; and
- three `libsscronet.so` boundary hooks that recover gQUIC request/response
  bodies.

The live `com.larus.nova` process on July 30, 2026 also had
`/apex/com.android.conscrypt/lib64/libssl.so` mapped at the same time as
`libsscronet.so` and `libttboringssl.so`. The current eCapture profile did not
target that Conscrypt provider, but the omitted `tls_plaintext` strategy is the
first and sufficient explanation for why the trace contained no TCP plaintext.
The provider-coverage question required a new run with plaintext enabled and
both TLS images attached; that corrective run is recorded below.

That is enough for the Doubao chat API path that rides the profiled Cronet
stack, but it is not enough to replace MITM for all app traffic. The missing
routes likely use at least one unprofiled path such as:

- a different TLS provider than the app-bundled `libttboringssl.so`;
- a different networking library than the profiled `libsscronet.so`; or
- a long-lived upgraded channel whose semantics are not reconstructed by the
  current offline decoders.

### Practical interpretation

As of July 30, 2026, the Android eCapture path is strong enough to prove:

- the app really issued `/chat/completion`;
- the request boundary was captured exactly;
- the response stream was captured at roughly the same opaque size scale; and
- the read-marker follow-up request was also recovered.

It is **not** yet feature-equivalent to the spawn-hook plus MITM workflow for
mixed traffic. The gap is coverage, not basic packet capture.

### Next engineering work implied by this comparison

To move toward a MITM replacement, the next increments are:

1. add automatic provider discovery so one UID can be matched against every
   active TLS implementation, not only the current BoringSSL image;
2. add transport hooks for the non-Cronet client paths that produce the
   missing `handshake`, telemetry, and websocket traffic;
3. reconstruct upgraded websocket and other long-lived binary channels from
   the captured TCP plaintext path once those hooks are present; and
4. keep raw packet capture as a fallback so undecoded flows are still auditable
   while semantic decoders catch up.

## Corrective full-lifecycle comparison

A second comparison captured the entire interval from cold start through a
completed visible chat response, rather than only the send action. The two
runs were independent and used the same app build and emulator state as closely
as practical:

- A: spawn hook plus MITM, with the Java SSL and TTNet certificate-result
  bypass probes enabled;
- B: direct networking with eCapture, raw packets, TLS plaintext,
  auto-discovered TLS providers, Cronet custom-BIO ciphertext, and the three
  Build-ID-pinned gQUIC stream hooks.

The MITM listener and the hook's PAC endpoint were both `127.0.0.1:8384`.
A port-mismatched trial and a native-only certificate-bypass trial were
rejected before comparison. In the accepted A run all required native, Java,
TLS, QUIC, custom-verifier, and TTNet probes reported ready. It retained 142
HTTP flows, 126 WebSocket data messages, and 114 TLS events with zero TLS
failure, zero eviction, and `truncated: false`. Device proxy state was restored
to direct mode after capture.

The accepted B run began before the app was cold-started. Auto-discovery
attached plaintext probes to both the app's `libttboringssl.so` and Android's
arm64 Conscrypt `libssl.so`; the primary Cronet image continued to own its
private offsets. Its 14,203 structured records contained:

- 8,917 packet records and a 5,046,272-byte PCAPNG;
- 3,528 communication-boundary records;
- 1,493 TLS plaintext calls across 35 SSL identities: 419 writes totaling
  620,424 bytes and 1,074 reads totaling 1,127,387 bytes;
- 263 connection metadata records; and
- two QUIC metadata records.

The runtime log contained no reported loss, decode-failure, buffer-full, or
probe error. That is a diagnostic observation, not a proof that an eBPF loss
counter which was never emitted is zero.

### HTTP and route results

Offline reconstruction produced 177 HTTP transactions, 173 complete:

| Protocol | Transactions | Complete |
| --- | ---: | ---: |
| HTTP/1.x | 9 | 8 |
| HTTP/2 | 161 | 161 |
| legacy gQUIC | 7 | 4 |

The one incomplete HTTP/1 response ended at capture EOF. Three unrelated gQUIC
transactions lacked a captured end state. Every critical chat/settings
transaction below was complete and returned status 200:

| Route | Protocol | Count | Request bytes | Response bytes |
| --- | --- | ---: | ---: | ---: |
| `POST api5-normal-lf.doubao.com/chat/completion` | gQUIC | 1 | 2,702 | 8,313 |
| `GET api5-eeft-gateway-hl.feishu.cn/settings/v3/` | HTTP/2 | 2 | 0 | 144,351 |
| `POST gecko.doubao.com/gkx/api/settings/v3` | HTTP/2 | 3 | 3,268 | 1,722 |
| `GET settings-api.doubao.com/service/settings/v3/` | HTTP/2 | 2 | 0 | 12,637 |
| `POST settings-api.doubao.com/service/settings/v3/` | HTTP/2 | 4 | 2 | 82,040 |

The independent MITM chat flow was also complete and status 200, with a
2,702-byte request and an 8,405-byte response. The exact request-body boundary
matched. The 92-byte response difference is expected for two dynamic chat
responses and is not evidence of truncation.

After stripping query values and deduplicating by method, lower-case host, and
path, A had 97 routes and B had 93. Their intersection was 89 routes, or
91.75% of the MITM route set. All chat, three settings-v3 families, and all
three WebSocket upgrades were in the intersection.

Eight A-only routes were a document-domain lookup, two image resources, a TNC
domain lookup, a carrier-info lookup, onboarding risk-word check, log settings,
and an exception report. B independently contained four routes absent from A:
two cached/CDN resources, an app-monitor settings request, and a cloud-push
update. Because each side observed conditionally executed traffic missing from
the other, these set differences are cold-start/cache/server-state
non-determinism; they cannot by themselves be classified as capture loss.

### WebSocket reconstruction

The new `stream websocket` decoder recovered all three upgraded TLS
connections from B and emitted 144 complete binary data messages plus 84
complete ping/pong controls from 228 frames. It reported zero incomplete
record, zero parse error, and zero opaque trailing byte.

| Upgraded route and direction | MITM data messages | eCapture data messages |
| --- | ---: | ---: |
| `frontier5-audio-ws-hl.../internal/api/v1/ws`, client to server | 4 | 4 |
| same, server to client | 113 | 131 |
| `msg-frontier-hl.feishu.cn/ws/v2`, client to server | 1 | 1 |
| same, server to client | 2 | 2 |
| `wss5-normal-hl.doubao.com/ws/v2`, client to server | 4 | 4 |
| same, server to client | 2 | 2 |

Five of six route/direction buckets match exactly. The longer direct audio
response produced 18 additional server messages in B; both runs ended after
their respective visible response completed. MITM's message index did not
include B's 84 transport controls.

### Correct interpretation

For this tested build and lifecycle, the remaining A/B difference is no longer
the earlier broad loss of TCP routes or WebSocket visibility. eCapture retained
raw packet evidence for its selected UID scope, reconstructed every critical
route, and indexed the long-lived WebSocket channels without installing a CA,
redirecting traffic, or changing QUIC into proxy-compatible TCP.

This does not claim universal MITM replacement for every application:

- a private TLS/QUIC/binary transport still needs a known exported ABI or a
  Build-ID-pinned boundary profile;
- independent application runs cannot prove 100% route-set equality;
- application-layer encrypted or encoded bodies remain exact opaque bytes; and
- raw PCAP proves packet capture, while a path or message boundary requires a
  transport hook and matching decoder.

Sensitive raw artifacts remain outside the repository. Audit hashes for B are:

| Artifact | SHA-256 |
| --- | --- |
| structured events | `76ead8b79bd88566741f6955cff5a6c4cf0f8f3ee7f7609a67405741444af7f1` |
| raw PCAPNG | `f0e4166668580db35527719805faf3c57d616d412a6b20e5e1e9d62994ebb9c9` |
| corrected transaction JSONL | `a4da0836aed5b6b8175668776244bd96758b2612ac843d050f43822c6fec32a9` |
| WebSocket JSONL | `79e825fc0da84f1bc1140c303fe10659fda32aebc5d253c87abd843cf326a3ad` |

### Final Android build and smoke

The final static arm64 binary, including multi-provider attachment and
`stream websocket`, has GNU Build ID
`e499b6b387760afb964430e531bcb451ed03081b` and SHA-256
`6c59be39595f0381b6920ed4d14dfc26082a1d5431aa9d3be291b73514d24117`.
The host and `/data/local/tmp/ecapture-fulltraffic-ws` copies matched.

On-device startup loaded 39 probes and five event maps, configured the primary
app BoringSSL image, auxiliary Conscrypt, both Cronet custom-BIO hooks, and all
three QUIC stream hooks. A separate 12-second cold-start smoke produced 4,886
packet records, 2,313 boundary records, 935 TLS calls, eight QUIC metadata
records, and a 3,735,552-byte PCAPNG. The 935 TLS calls contained 499,191 write
bytes and 833,575 read bytes.

Replaying that smoke with the same final binary reconstructed 158 HTTP
transactions, 155 complete. All 13 settings-related transactions were complete
and status 200, including two Feishu `/settings/v3/`, three Gecko
`/gkx/api/settings/v3`, and six Doubao `/service/settings/v3/` calls. The short
window also yielded eight complete WebSocket records across two upgrades with
zero parse error. The process and app were stopped after the smoke and Android
proxy state remained `:0`.
