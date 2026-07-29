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
libraries and generate a conservative diagnostic scaffold:

```sh
ecapture profile inspect \
  --pid 3423 \
  --output profile-report.json \
  --scaffold profile-discovery.json
```

See [`profile-location-guide.md`](profile-location-guide.md) for the required
Build-ID and marker-validation workflow. The scaffold includes only public ABIs
whose direct buffer/length layout is known; hints from stripped Cronet or
private libraries are never promoted to offsets automatically.

For Android applications using dynamic JNI registration, the scaffold can
also include an ART Build-ID-pinned `jni_discovery` strategy. Capture a cold
start as structured events and rank the native boundaries:

```sh
ecapture tls \
  --profile profile-discovery.json \
  --event-format=json \
  --eventaddr=jni-events.jsonl

ecapture profile learn-jni \
  --input jni-events.jsonl \
  --output jni-candidates.json
```

The learner never emits a data hook directly from a JNI object signature:
`jstring`, arrays, and `ByteBuffer` parameters are managed references. Its
output identifies which native method and JNI conversion boundary should be
validated next.

Explicit CLI flags override profile values. This is useful when only one
offset changed in a new app build:

```bash
ecapture tls \
  --profile /data/local/tmp/doubao-13.9.0-android16.json \
  --struct-offset ssl_st_rbio=0x20 \
  --hook ssl_write=@0x48bb0
```

The supported strategies are:

- `raw_packets`: TC ingress and egress packets in PCAPNG.
- `tls_plaintext`: `SSL_read` and `SSL_write` plaintext.
- `tls_keys`: NSS key log output and PCAPNG decryption-secret blocks.
- `quic_metadata`: `SSL_provide_quic_data` handshake metadata.
- `application_data`: profile-defined application function hooks.
- `jni_discovery`: ART `RegisterNatives` metadata and module-relative native
  method offsets.
- `cronet`: compatibility alias for `application_data`.

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

Generic application data hooks are declared in `data_hooks`. Up to eight hooks
can be active in one profile. A direct pointer/length API looks like this:

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
an ELF `offset`. Arguments are numbered from 1 through 5. `buffer_offset` adds
a byte offset to the selected buffer argument; `buffer_indirect` reads a
pointer from that location. The optional `buffer_format: "libcxx_string"`
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
  `capture_on: "return"`.

`capture_on: "return"` stores entry arguments per thread and emits after the
function returns. Each call is emitted in bounded 16 KiB chunks, up to
`max_bytes` and an absolute 128 KiB ceiling. Hook names and chunk metadata are
included in text/JSON events so different application strategies can be
correlated without rebuilding eCapture.

`context_arg` and `stream_arg` optionally copy two scalar arguments into every
event and preserve them across a uretprobe. They are intended for a connection,
request, adapter, channel, or QUIC stream identity. For example,
`quiche_conn_stream_send(conn, stream_id, buf, len, fin)` uses:

```json
{
  "buffer_arg": 3,
  "length_arg": 4,
  "context_arg": 1,
  "stream_arg": 2
}
```

This makes multiplexed streams reconstructable; without the connection and
stream identity, capturing HTTP/3 bytes alone is insufficient.

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
`length_*`, buffer offset/indirection, or asynchronous state fields are valid
for an iovec hook. The eBPF program inspects at most 16 vectors and emits at
most eight 16 KiB chunks (128 KiB total). Every chunk shares one call
timestamp and the iovec-array address, and uses an offset in the flattened
logical stream. More vectors, an oversized stream, or an unreadable vector is
reported as truncation or a reconstruction gap rather than silently
concatenating the wrong bytes.

The inspector safely scaffolds the public `readv` and `writev` ABIs. It does
not treat `sendmsg`/`recvmsg` or a library-specific vector structure as the
same layout: those require a dedicated `msghdr` or stack-specific adapter.
The marker-validated integration fixture is
[`testdata/iovec_capture_profile.json`](../testdata/iovec_capture_profile.json);
its [runtime evidence](evidence/iovec-capture-2026-07-29.md) includes verifier
and reconstruction results.

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
for a complete Android profile.

Raw PCAPNG contains all selected network traffic but encrypted TLS/QUIC stays
encrypted unless matching secrets or application plaintext are captured.
`SSL_provide_quic_data` exposes QUIC handshake activity, not HTTP/3 request
payloads. Application hooks emit plaintext as eCapture events; they do not
rewrite encrypted packets inside the PCAPNG.

Legacy gQUIC does not use the TLS 1.3 `SSL_provide_quic_data` path. When
`raw_packets` is enabled, eCapture still preserves its UDP datagrams and
annotates visible TLS and gQUIC Client Hello packets with their server name.
Later application datagrams remain encrypted and are identified as the same
flow by their source/destination tuple in the PCAPNG. A proxy or UDP/443
fallback can change an application's transport to TCP/TLS, so captures made
with and without such instrumentation are not necessarily protocol-equivalent.
