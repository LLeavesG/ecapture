# Offline host decoder

`cmd/ecapture-decode` is a separate executable that imports the existing
`internal/reconstruction` parsers. It has no probe registration, device access,
eBPF assets, root check, collection command, or libpcap/CGO dependency.
It accepts already frozen, authorized event JSONL only.

Build on Linux with the Go version required by `go.mod` (currently 1.25.12):

```sh
CGO_ENABLED=0 go build -trimpath -o /path/to/ecapture-decode ./cmd/ecapture-decode
```

Only Go and the referenced Go modules are needed; do not use `make all` or the
production collector build. The host runner should pin the built executable's
SHA256 and record it independently of the decoder's self-reported identity.

```sh
/path/to/ecapture-decode version
/path/to/ecapture-decode decode --input /path/to/frozen/events.jsonl \
  --output-prefix /path/to/new-attempt/decoded
```

The parent output directory must already exist. All three outputs are always
created, even when empty:

* `decoded.transactions.jsonl`
* `decoded.websocket.jsonl`
* `decoded.correlations.jsonl`

Existing files are never overwritten. Files use mode 0600; temporary input
snapshots are also private and removed when the command returns. Each parser
reads the same snapshot. On a handled failure the new output files from this
invocation are removed; a crash may leave partial files, so the host must use a
fresh attempt directory and only accept a zero exit plus a valid receipt.

Stdout contains exactly one JSON object. Success exits zero and contains:

```json
{"schemaVersion":1,"status":"ok","outcome":"decoded","inputValidation":{"events":2,"blankLines":0,"eventTypes":{"tls_plaintext":2},"unknownEventTypes":{},"legacyPackets":0,"provenance":{}},"decoder":{"name":"ecapture-decode","version":"1","goVersion":"go1.25.12"},"input":{"path":"...","sha256":"...","bytes":123},"outputs":{"transactions":{"path":"...","sha256":"...","bytes":456},"websocket":{"path":"...","sha256":"...","bytes":0},"correlations":{"path":"...","sha256":"...","bytes":0}},"summaries":{"transactions":{},"websocket":{},"correlations":{}}}
```

`decoder.revision` and `decoder.modified` are included when Go build information
contains them. `version` returns schema, status and decoder identity without
reading input. A handled failure exits nonzero with `status: "error"` and an
`error` string; no output map is advertised. Flag diagnostics may go to stderr.
The host must verify receipt hashes against frozen input and actual outputs.
Empty outputs mean no supported records were reconstructed, not proof that no
traffic existed. Success indicates parser execution, not capture completeness.

Capabilities and limitations are inherited from the existing parsers: HTTP/1.x,
HTTP/2 with observed HPACK state, gQUIC, HTTP/3 with resolvable QPACK state,
WebSocket frames following an observed upgrade, and exact wire correlation.
Missing state, gaps, incomplete captures, and opaque bodies retain parser
annotations. Protocol segmentation uses only the conservative observed boundaries
described below; it does not add collection coverage.
It does not decrypt application encryption or reconstruct traffic that was not
provided. HTTP standard content decoding is existing presentation behavior;
byte-exact body data remains preserved. The parsers can retain substantial
connection/transaction state in memory; the host should apply process timeout
and resource limits suitable for its inputs.

Validation:

```sh
CGO_ENABLED=0 go test ./cmd/ecapture-decode ./internal/reconstruction
```

## Input validity and empty results

Each nonblank line must contain exactly one JSON object (maximum line size
64 MiB), with a nonempty string `eventType`. Malformed JSON, `null`, arrays,
scalars, missing or invalid event types, and invalid recognized boundary chunks
exit nonzero without advertising outputs. The one compatibility exception is
the existing legacy packet envelope: a nonzero `Timestamp` and nonempty base64
`PacketData` are required and counted as `@legacy_packet`. This validates its
envelope, not whether the packet bytes form a decodable network protocol.

The receipt's `inputValidation` records `events`, `blankLines`, `eventTypes`,
`unknownEventTypes`, `legacyPackets`, and `provenance`. Provenance keys are JSON
arrays `[eventType, declaredCaptureLayer, declaredTransport]`; they describe
source declarations before parser normalization. Unknown event types are
permitted, counted, and accompanied by the `unknown_event_types` warning. The
input SHA256 identifies their source file, including records parsers ignore.

Successful decode has an explicit `outcome`:

* `empty_input`: zero event objects (empty or whitespace-only file).
* `no_supported_records`: event objects exist but none of the three output
  categories contain records. This includes opaque non-HTTP data.
* `decoded`: at least one output record exists; completeness remains a property
  of individual records and parser summaries.

Missing call chunks may make a call unusable by a protocol parser. The existing
parser's `callsIncomplete` counts remain in summaries and cause an
`incomplete_calls` warning; the CLI does not fabricate transactions from those
calls. Fully supplied calls containing a partial HTTP message retain the
existing incomplete transaction representation. Neither case is mislabeled as
empty input. Consumers must inspect summaries and record completeness; a zero
exit never proves complete evidence or protocol coverage.

Acceptance requires a single JSON receipt with supported `schemaVersion`,
`status: "ok"`, `decoder.name: "ecapture-decode"`, supported `decoder.version`,
valid input validation/outcome, all three outputs, and verified input/output
hashes and byte sizes. Executable pinning is independent. Do not accept outputs
merely because the process exits zero and filenames exist.

`TestBinaryMatchesExistingReconstruction` builds and executes a real pure Go
binary against synthetic HTTP/1, HTTP/2 and HTTP/3 input. It compares all three
output files byte-for-byte with direct calls to the existing reconstruction
functions and checks protocol identity, completion, and binary body bytes.
Its build disables module network fetching (`GOPROXY=off`); dependencies must
already be available from the surrounding Go test build.

`capture_stats` and `connection_metadata` are known metadata, and `packet` is
the standard packet envelope; none is an unknown event type. Metadata records
remain counted in `eventTypes` and declared `provenance`; they do not themselves
produce transactions or establish a TLS-to-socket identity. Metadata-only input remains
`no_supported_records`, without an unknown-schema warning. Reader health is
not assessed by this CLI. Standard and legacy packet envelopes require nonzero
`Timestamp`, nonempty base64 `PacketData`, and field types compatible with the
existing packet observer (including numeric `Direction`). The observer handles
Ethernet or flagged raw IP packets and existing TCP/UDP flow correlation; an
unrecognized packet payload may produce no correlation. This is a known input
shape with no supported output, not an unknown schema or proof of no traffic.


## Conservative protocol segments

An SSL object address can be reused after an earlier connection ends. Permanently
concatenating every call with the same process and SSL address can therefore mix
HTTP/2 traffic into an earlier WebSocket stream or hide a later HTTP/1 upgrade.
The HTTP/1 and WebSocket aggregators now isolate supported protocol segments
when the captured byte stream supplies enough evidence. This is offline state
separation, not a new collection feature or a verified socket-lifetime mapping.

A candidate segment begins at a captured TLS WRITE call boundary. The new
protocol must have a complete HTTP/2 client preface and observed server SETTINGS,
or a complete WebSocket request and response with the expected
`Sec-WebSocket-Accept`. The preceding segment must satisfy one of these gates:

* HTTP/2: both frame buffers and pending header blocks are fully consumed, all
  observed request/response streams have END_STREAM and decoded headers, and
  there are no resynchronization or header/transaction errors.
* WebSocket: its own handshake also has a verified `Sec-WebSocket-Accept`, every
  parsed record is complete without parse errors or opaque bytes, and both
  directions end in a close control frame.

These gates support completed HTTP/2 to new HTTP/2 or WebSocket, and closed
WebSocket to new HTTP/2 or WebSocket. The current checks require the relevant
complete handshake material at the inspected call boundaries; they do not
promise recovery for every split-handshake layout. Ordinary HTTP/1 address reuse
without these framing and handshake proofs is not inferred.

Separated HTTP/1 and WebSocket records expose
`connectionGenerationSource: "observed-protocol-boundary"`. Later segment IDs
append `:protocol-segment:<ordinal>` to the existing connection key. The ordinal
is local to that key and avoids treating timestamps as unique identifiers; it
is not a kernel socket ID. Their summaries expose `inferredProtocolSegments`.
The first segment involved in a split also receives the generation-source label.
These labels do not assert that a new socket was independently verified.
`connection_metadata` timestamps, threads, or endpoints are not heuristically
joined to an SSL address whose captured fd is unavailable.

The decoder does not search arbitrary body bytes for HTTP text. In particular,
an HTTP/2 DATA payload that begins with the client preface at a later TLS call
must remain body data while its frame is pending; the HTTP/2 generation detector
now observes that constraint too. Binary WebSocket payloads containing preface
or GET text remain intact. When close, handshake, framing, or completeness
proof is missing, the conservative split is withheld and existing incomplete,
opaque, or error reporting remains visible; those errors are not discarded to
make validation pass.

## Recorded verification

The final code verification for this change passed 105 Go test entries including
subtests: 36 in `cmd/ecapture-decode` and 69 in `internal/reconstruction`. This is
a recorded result, not a promise that future changes have been tested. The JSON
log from that run is `/tmp/ecapture-protocol-verified-tests.jsonl`. It includes
regressions for binary-body protocol text, invalid previous and next WebSocket
Accept values, unclosed WebSockets, consecutive closed WebSockets, and colliding
segment timestamps with byte preservation. `go vet` also completed successfully
for both packages; its output was empty and no separate vet log was saved.

The toolchain used was
`/data/home/lleaves/.cache/capture-decoder-toolchain/go/bin/go` (Go 1.25.12):

```sh
CGO_ENABLED=0 GOTOOLCHAIN=local /data/home/lleaves/.cache/capture-decoder-toolchain/go/bin/go test -json ./internal/reconstruction ./cmd/ecapture-decode
CGO_ENABLED=0 GOTOOLCHAIN=local /data/home/lleaves/.cache/capture-decoder-toolchain/go/bin/go vet ./internal/reconstruction ./cmd/ecapture-decode
```

A separate replay of the unchanged, authorized a02 App input with the verified
binary is retained at `/tmp/owned-a02-verified-rec2xlhk/receipt.json` and adjacent
output files. It produced nine transactions and three WebSocket upgrades with
six complete messages and six complete control records, without WebSocket parse
errors. The baseline and earlier before/after comparison remain separately under
`/tmp/owned-a02-protocol-segments-final-6_364o6r/`; that comparison used the earlier
segment binary and must not be relabeled as the final verified binary's receipt.
These temporary local paths document the actual checks and may be removed by
host cleanup; durable acceptance evidence belongs in the independent run report.
