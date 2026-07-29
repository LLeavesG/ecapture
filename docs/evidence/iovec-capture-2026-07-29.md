# Iovec capture runtime evidence (2026-07-29)

This is a synthetic, non-sensitive integration record for the generic
application-data iovec adapter.

## Target and fixture

- Linux 6.8.0 arm64 virtual machine
- non-CO-RE `openssl_3_0_0_kern_noncore.o`
- exported fixture wrappers `ecapture_test_writev` and
  `ecapture_test_readv`
- three vectors per call
- fixed markers only; no application or account traffic

The reproducible sources are:

- [`iovec_capture_helper.c`](../../testdata/iovec_capture_helper.c)
- [`iovec_capture_profile.json`](../../testdata/iovec_capture_profile.json)

The profile PID placeholder was replaced with the running fixture PID before
the capture process started.

## Procedure

```sh
cc -O0 -g -rdynamic \
  -o /tmp/ecapture-iovec-helper \
  testdata/iovec_capture_helper.c

/tmp/ecapture-iovec-helper &
# Replace 999999 in the fixture profile with $!.

ecapture \
  --event-format=json \
  --eventaddr=/tmp/iovec-events.jsonl \
  tls \
  --profile=/tmp/iovec-profile.json

ecapture stream reconstruct \
  --input=/tmp/iovec-events.jsonl \
  --output=/tmp/iovec-calls.jsonl
```

## Results

- The kernel verifier accepted the iovec measurement/emission subprograms.
- Two entry/return probe pairs were configured; the profile disabled all TLS
  data hooks so only the synthetic application hooks emitted payloads.
- Six structured events were emitted: three `writev` vectors and three
  `readv` vectors.
- All events from one call shared the same timestamp, iovec address,
  context/file descriptor, original length, and captured length.
- Global chunk offsets were `0`, `9`, and `21` for both calls.
- Reconstruction produced two complete calls and zero incomplete calls:

| Hook | Direction | Original/captured | Reconstructed marker |
| --- | --- | ---: | --- |
| `fixture-writev` | write | 28 / 28 | `ECAPTURE-IOVEC-WRITE-MARKER\n` |
| `fixture-readv` | read | 27 / 27 | `ECAPTURE-IOVEC-READ-MARKER\n` |

Artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| six structured events | `6ab349d803165567fbd42bd6ad05305c57326b32f14d9b0058a4ac5df3eac34f` |
| two reconstructed calls | `ca1ac25c893f43d6a691cb9c1f005c285b38fe0b761b88092e304e525b6fb88c` |

This proves the standard `struct iovec` boundary and flattened reconstruction.
It does not prove `msghdr`, a QUIC library's private vector type, HTTP/3 QPACK,
or application semantics; those remain separate adapters/decoders.

## Android 16 follow-up

The same source was then built with the Android eCapture tag and loaded on an
arm64 Android 16 emulator. A static helper executed the identical fixed
markers from `/data/local/tmp`; eCapture ran with BPF capabilities and selected
`boringssl_a_16_kern_noncore.o`.

- The Android kernel verifier accepted the same iovec programs.
- Both symbol uprobes attached to the standalone helper.
- Six events again reconstructed as two complete calls with zero gaps.
- Reconstructed values and lengths were identical to the Linux run.
- No application package, network socket, proxy, CA, Frida process, or private
  data was involved.

Android artifact hashes:

| Artifact | SHA-256 |
| --- | --- |
| six structured events | `5578716a50ebc30a48ad89133cc3bd25e9144740cec81f2955e484dbdee433ef` |
| two reconstructed calls | `cfd3834a73c3d6098984e11e373ccba3de4683fa8b3dda158873973f093f4cae` |
| tested Android-tagged eCapture binary | `1fda10c84cc779436f219570d78c2faa52d400fc8830aed5ad83179daed02e7b` |
| static marker helper | `bb24dc2c6336e36ac7623d72b1bba464ba31692d4a352a11aa3c41e1e48594be` |
