# Doubao `/chat/completion` marker evidence (2026-07-30)

This is a sanitized verifier record. Raw JSONL captures were kept outside the
repository because they contain account identifiers, request payloads, and
response text.

This record covers a semantic diagnostic path. It is useful for locating
application callsites, but it is not evidence that the same bytes crossed a
TLS, QUIC, or socket boundary. The independent
[transport/HTTP/2 verifier](doubao-transport-http2-2026-07-30.md) is the
communication-capture proof.

## Target

- Package: `com.larus.nova`
- Platform: Android 16, arm64, emulator `emulator-5560`
- Process: PID `10489`
- App modules proven in this run:
  - `libalog.so`, Build ID `45b8649198e380ada5ca51edf75453ab4c2f0f97`
  - `libomnisdk.so`, Build ID `701f434681172abcec34e598bc47f89ec09f1b77`
- Probe binary Build ID: `3c57ea9f44873bf2177267a6ac58ee32d7039d9c`

## Procedure

Three capture tiers were used:

1. A broad diagnostic JNI conversion run to locate marker-bearing callsites.
2. A narrowed caller allowlist built from marker hits in `libalog.so` and
   `libomnisdk.so`.
3. A final verification run with the rebuilt Android binary that emits
   `callerModuleBuildID`, `callerFilterJustActivated`, and the pinned
   `caller_allowlist` profile.

The marker strings were synthetic and non-secret:

- `EBPFPROMPT20260730D`
- `EBPFPROMPT20260730E`
- `EBPFPROMPT20260730F`

## Broad-to-narrow reduction

The broad marker capture (`D`) wrote 39,344 structured events and proved that
the relevant semantic boundary is not Cronet but the app's own JNI conversion
callers.

The narrowed marker capture (`E2`) wrote 6,230 events. The dominant callsites
were:

- `libalog.so + 0x92ec`
- `libomnisdk.so + 0xb514c8`
- `libomnisdk.so + 0xccd420`
- `libomnisdk.so + 0xb8f848`

The final rebuilt-binary verification capture (`F1`) wrote 4,631 events and
showed exactly one bootstrap transition event with
`callerFilterJustActivated=true`; the remaining 4,630 events had
`callerFilterActive=true`.

## Proven request boundary

The narrowed caller allowlist captured the full semantic request path without a
proxy, user CA, or Frida:

- `libalog.so + 0x92ec` emitted the prompt-bearing `sendMessageV2` request
  objects and serialized JSON.
- The same callsite logged a request envelope whose `url` was
  `/chat/completion`.
- The same callsite emitted `request body = {...}` with the marker at the
  correct JSON field boundary.
- The same callsite emitted
  `streamPull, url:/chat/completion, header:{Content-Type=application/json; encoding=utf-8, X-OMNI-REQUEST=1}`.
- `libomnisdk.so + 0xccd420` emitted `/chat/completion` again on the SDK side.

The observed production URL was:

- `https://api-normal.doubao.com/chat/completion?...`

The validated path for this app build is `/chat/completion` (singular), not
`/chat/completions`.

## Proven response boundary

The narrowed caller allowlist also captured the response semantics:

- `libomnisdk.so + 0xb514c8` emitted raw SSE frames such as
  `FULL_MSG_NOTIFY`, `STREAM_MSG_NOTIFY`, `STREAM_CHUNK`, and `CHUNK_DELTA`.
- `FULL_MSG_NOTIFY` echoed the prompt marker inside the request-derived
  metadata.
- `CHUNK_DELTA` records carried the incremental streamed response text.
- `libomnisdk.so + 0xb8f848` emitted the progressively reassembled plaintext
  response headed by `# EBPFPROMPT20260730E` and
  `# EBPFPROMPT20260730F`.

This proves the semantic request and streaming-response callsites. It does not
establish network-flow equivalence; that requires transport events and protocol
reconstruction.

## Final learned caller allowlist

The rebuilt binary plus `profile learn-jni` generated a production-oriented
caller allowlist with Build IDs preserved automatically:

| Module | Build ID | Role | Offset |
| --- | --- | --- | --- |
| `libalog.so` | `45b8649198e380ada5ca51edf75453ab4c2f0f97` | `get_string_utf_chars` | `0x92ec` |
| `libomnisdk.so` | `701f434681172abcec34e598bc47f89ec09f1b77` | `get_string_utf_chars` | `0xb514c8` |
| `libomnisdk.so` | `701f434681172abcec34e598bc47f89ec09f1b77` | `get_string_utf_chars` | `0xccd420` |
| `libomnisdk.so` | `701f434681172abcec34e598bc47f89ec09f1b77` | `get_string_utf_chars` | `0xb8f848` |

## Implications

- For this Doubao build, the semantic request/response boundary is observable
  at JNI conversion callsites in private app libraries.
- TLS ciphertext alone is insufficient evidence, but it is not the ceiling:
  the managed-to-native conversion boundary can surface path, headers, JSON
  body, SSE frame type, and progressively reassembled response text.
- A production profile must still be pinned to package version, ABI, Android
  release, and caller-module Build IDs, then re-validated with a synthetic
  marker after every app update.
