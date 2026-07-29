# Doubao JNI discovery runtime evidence (2026-07-29)

This is a sanitized verifier record. No application payload, account data,
headers, cookies, or authentication material is included.

## Target

- Package: `com.larus.nova`
- Version: 13.9.0 (`versionCode` 13090001)
- Platform: Android 16, arm64
- ART library: `/apex/com.android.art/lib64/libart.so`
- ART GNU Build ID: `be34fbe63ff357beb403f9cb39923ea7`
- Static `JNINativeInterface[215]` candidates:
  `0x69be84`, `0x8171b0`, `0x4d1ef4`, `0x888ca4`

## Procedure

The capture process was started with full BPF capabilities before a force-stop
and cold start of Doubao:

```sh
ecapture \
  --event-format=json \
  --eventaddr=/data/local/tmp/jni-v4-events.jsonl \
  tls \
  --profile /data/local/tmp/doubao-jni-only.json

ecapture profile learn-jni \
  --input /data/local/tmp/jni-v4-events.jsonl \
  --output /data/local/tmp/jni-v4-candidates.json \
  --min-score 55 \
  --max-candidates 50
```

No Frida process, proxy, user CA, pinning modification, or traffic redirection
was active.

## Results

- 1,617 structured `jni_register_natives` events.
- 1,384 unique registered native methods.
- 0 unresolved function-pointer events.
- 39 implementation modules.
- Every event resolved through ART candidate 2, offset `0x4d1ef4`.
- The largest observed registration declared 147 methods. That runtime result
  motivated increasing the bounded coverage from 128 to 256 methods per call.
- The ranked top 50 candidates spanned 12 modules.

Examples proving that the learner finds different data-boundary classes:

| Method | JNI signature | Module | Offset | Reason |
| --- | --- | --- | ---: | --- |
| `nativeInvokeCallback` | `(J[BJLjava/nio/ByteBuffer;ILjava/lang/String;)V` | `liblynx.so` | `0x2ec668` | byte array, ByteBuffer, and String |
| `nativeDispatchKeyDataPacket` | `(JLjava/nio/ByteBuffer;Ljava/lang/String;I)V` | `libclay.so` | `0x87b5c` | packet semantic name and ByteBuffer |
| `ttEncrypt` | `([BI)[B` | `libEncryptor.so` | `0x7d8c` | custom application encryption boundary |

The `ttEncrypt` result was ranked 37 with score 100. It was intentionally
marked `auto_hook_safe: false`; a `jbyteArray` is a managed JNI reference.
Promotion requires correlation with `GetByteArrayElements` or
`GetPrimitiveArrayCritical`, disassembly of the module-relative target, its GNU
Build ID, and a synthetic request/response marker.

## Artifact integrity

The private runtime artifacts were kept outside the repository:

| Artifact | SHA-256 |
| --- | --- |
| structured event JSONL | `ac1b9bcfc40c19ab7329de744d38f41b09b45aa7f151c0fd195c29c093c3ab29` |
| ranked candidate report | `ca11da3f96162c5873a65a6b15f1ae20551c52c6083cbc65ed385f51b91ebabf` |
| tested arm64 binary | `d01d8aa644d50d1ba9ce371f3621fb12c91e86a8275a6d6aa01bb16d2dd1d12b` |

These hashes prove the reported run, but the private files are not required to
build or test the implementation.

## 256-method follow-up

The 16-segment build was then run through the same cold-start procedure:

- 64 uprobe attachments (16 reusable segment programs at four ART offsets)
  loaded successfully on the Android verifier.
- 1,694 events were emitted.
- The 147-method registration emitted exactly 147 events, including indices
  128 through 146.
- 26 events had an index above the previous 127 ceiling.
- Shutdown closed the structured event handler once without the prior
  double-close warning.

The follow-up JSONL SHA-256 was
`c28a71382fa18f0b0b0726f75a50a03ebe8fea3c774f520da97dcb674263a526`.
