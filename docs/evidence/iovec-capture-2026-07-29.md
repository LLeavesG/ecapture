# Iovec and msghdr capture runtime evidence (2026-07-29)

This is a synthetic, non-sensitive integration record for the generic
application-data iovec and standard 64-bit msghdr adapters.

## Target and fixture

- Linux 6.8.0 arm64 virtual machine
- non-CO-RE `openssl_3_0_0_kern_noncore.o`
- exported fixture wrappers `ecapture_test_writev` and
  `ecapture_test_readv`, followed by `ecapture_test_sendmsg` and
  `ecapture_test_recvmsg`
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
It was the initial iovec-only phase; the msghdr follow-up below uses the same
fixture and profile.

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

## Standard 64-bit msghdr follow-up

The fixture was extended with a local `AF_UNIX` datagram `socketpair`.
`sendmsg` supplied three vectors through `msg_iov`; `recvmsg` supplied three
destination vectors and relied on the positive return value to bound the
received data. There was no external network traffic.

Both Linux and Android configured six probes for the four hooks: entry-only
`writev` and `sendmsg`, plus entry/return pairs for `readv` and `recvmsg`.
Each run emitted 12 chunks and reconstructed four complete calls with zero
incomplete calls:

| Hook | Direction | Original/captured | Reconstructed marker |
| --- | --- | ---: | --- |
| `fixture-writev` | write | 28 / 28 | `ECAPTURE-IOVEC-WRITE-MARKER\n` |
| `fixture-readv` | read | 27 / 27 | `ECAPTURE-IOVEC-READ-MARKER\n` |
| `fixture-sendmsg` | write | 29 / 29 | `ECAPTURE-MSGHDR-WRITE-MARKER\n` |
| `fixture-recvmsg` | read | 28 / 28 | `ECAPTURE-MSGHDR-READ-MARKER\n` |

The Linux verifier/runtime artifact hashes were:

| Artifact | SHA-256 |
| --- | --- |
| 12 structured events | `884afb3d7dd40d2d82776a202b270028a426027d1c34e40fedd21301580748e0` |
| four reconstructed calls | `bd8f1a31bbc5348fb49fcf37d3aaed24937c84beb1560dfc1e157c809fce4202` |

The Android 16 arm64 verifier/runtime artifact hashes were:

| Artifact | SHA-256 |
| --- | --- |
| 12 structured events | `a3df8d3d2a48659e37730e920578c5dc0c08700e673c8fbde4a87f8d2db9d7d0` |
| four reconstructed calls | `ef24d5b7217c63f8d902231a6f44d270e048e0b4864914ecded4a652e85490cd` |
| tested Android-tagged eCapture binary | `1b59bf08c9db42e1b5c5419ea91ad1a9e08d8a6d78b3b37dae466b3619837b27` |
| static marker helper | `fc0e2b1b6e08820bcb883b13d115b112fef2dd2020c6be1f21bdeddb0011e3c6` |

This proves default `msg_iov`/`msg_iovlen` extraction for the tested standard
Linux and Android 64-bit ABIs, bounded vector flattening, and return-length
handling. It does not prove a QUIC library's private vector type, chained
buffers, HTTP/3 QPACK, or application semantics; those remain separate
adapters and decoders.

## Twelve-argument QUIC-shaped ABI follow-up

The fixture was extended again with
`ecapture_test_higharg_iovec`, which mirrors the current public
`ngtcp2_conn_writev_stream_versioned` argument positions without linking or
contacting a QUIC implementation:

- connection identity: argument 1, value `0x12345000`;
- accepted plaintext output pointer: argument 7;
- stream ID: argument 9, value `0x0102030405060708`;
- vector pointer/count: arguments 10/11;
- function return: 1200, deliberately different from accepted plaintext;
- vector total: 48 bytes, accepted plaintext: 36 bytes.

The 36-byte prefix was
`ECAPTURE-HIGHARG-QUIC-STREAM-MARKER\n`; the final 12-byte
`IGNORED-TAIL` vector had to be excluded. This verifies that the uretprobe
used `*arg7`, not packet-length return value or total vector capacity, while
preserving high stack argument values.

On Linux 6.8 arm64, eight probes emitted 15 chunks and reconstructed the four
earlier calls plus the high-argument call as five complete, zero incomplete:

| Artifact | SHA-256 |
| --- | --- |
| 15 structured events | `a2f676083fb0e6e82dc7b2ce95d8325a645b0139113ab6513a30c66f9936280c` |
| five reconstructed calls | `d72cc48cd5d41fc2648c8373aa46c93dbf41875417d7266c5fc885821bee1f16` |
| dynamic marker helper | `094a9c58beced7f10072959f3a70fa5c8767c43b727b46fec8998d376569833b` |

The same source and profile then passed the Android 16 arm64 non-CO-RE
verifier and runtime with the same reconstructed payload and identities:

| Artifact | SHA-256 |
| --- | --- |
| 15 structured events | `894f66de77f83da7ed450194ea029873ae59eab0e2991ef1bd873b666cc8539c` |
| five reconstructed calls | `fbc3255349311fe56fd48ef0f7f78116e8fd0d7cc29df912b81c0d8d8b56a607` |
| tested Android-tagged eCapture binary | `a4ca4be9e7624fc90e5137f140234734d55a4fac7d89c9a6e325dd0932a680d2` |
| static marker helper | `f95afc5012883298ad1012ac13f16c8fab0be819ee268b3cefcbbf99ba80b6b6` |

Both arm64 and amd64 CO-RE objects were also compiled from the same
high-argument reader. The amd64 entry-stack path has compile coverage here;
an amd64 runtime marker test remains desirable.
