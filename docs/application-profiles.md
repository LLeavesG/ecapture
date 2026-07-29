# Application capture profiles

Application profiles make TLS and raw-packet capture reproducible for apps
that ship private OpenSSL/BoringSSL forks. A profile pins the target package,
capture strategies, interfaces, library location, hook points, and runtime
structure offsets without rebuilding eCapture.

Run a profile:

```bash
ecapture tls --profile /data/local/tmp/doubao-13.9.0-android16.json
```

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
pointer from that location. Length can come from:

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
