# Application profile location guide

This guide defines the evidence an engineer or coding agent must collect before
adding offsets for a new application version. The output is a reproducible
application profile, not a one-off tracing script.

## Phase 1: inventory

Run the inspector on the target device:

```sh
ecapture profile inspect \
  --pid "$TARGET_PID" \
  --output /data/local/tmp/profile-report.json \
  --scaffold /data/local/tmp/profile-discovery.json
```

It reads executable mappings from `/proc/PID/maps`, opens every accessible ELF,
records its architecture and GNU Build ID, and ranks:

- direct-buffer and standard `readv`/`writev`/`sendmsg`/`recvmsg` public ABIs
  that can be scaffolded safely;
- other aggregate APIs that need a container/stack-specific recipe;
- Cronet/JNI/QUIC/serializer strings that are search anchors only.

An explicit library can be inspected offline:

```sh
ecapture profile inspect \
  --library /data/local/tmp/libnetwork.so \
  --output network-report.json
```

The inspector does not require BPF capabilities for explicit files or an
accessible process. Root can still be required to read another process's maps.

Never turn a `hint` into a production hook without the later phases.

If an ABI was already recovered for this or another version, put it in a
recipe catalog instead of modifying the inspector:

```sh
ecapture profile inspect \
  --library /data/local/tmp/libprivate.so \
  --recipe-catalog private-abi.json \
  --output private-report.json \
  --scaffold private-discovery.json \
  --pid "$TARGET_PID"
```

Use a symbol recipe when the exported ABI is stable. For an internal offset,
the catalog requires `build_id`, and the inspector verifies that the file
offset lies in an executable ELF segment before scaffolding it. A Build-ID
match means “apply this known ABI to this exact binary”; it does not replace
the marker test.

## Phase 2: select the highest stable boundary

Prefer candidates in this order:

1. Request/response semantic API with a stable native identity.
2. Serializer/parser output for a private binary protocol.
3. TLS or QUIC stream plaintext API.
4. Custom encryption input/output.
5. Socket API for unencrypted protocols or as a ciphertext baseline.

Higher boundaries preserve path, headers, message boundaries, and request
identity. Lower boundaries are more portable but lose semantics.

For QUIC, do not treat `SSL_provide_quic_data` as application data. Search for a
stream send/receive API or hook above transport selection.

## Phase 3: recover native registrations and offsets

For Android JNI libraries:

1. Inspect ART and scaffold a cold-start discovery profile:

   ```sh
   ecapture profile inspect \
     --library /apex/com.android.art/lib64/libart.so \
     --output /data/local/tmp/art-report.json \
     --scaffold /data/local/tmp/app-jni-discovery.json \
     --package "$PACKAGE"
   ```

   The inspector locates the standard `JNINativeInterface` table in writable
   ELF data. JNI fixes `RegisterNatives` at table index 215, so this works
   without private ART symbols. The scaffold pins the ART GNU Build ID and
   hooks up to four implementation/wrapper offsets.

2. Start eCapture before the application process and collect structured events:

   ```sh
   ecapture tls \
     --profile /data/local/tmp/app-jni-discovery.json \
     --event-format=json \
     --eventaddr=/data/local/tmp/app-jni-events.jsonl
   ```

   Then force-stop and cold-start the package. Sixteen verifier-bounded BPF
   programs inspect 16 table entries each; the same program FDs can be
   attached to every discovered ART offset. The current limit is the first 256
   native methods in one `RegisterNatives` call.

3. Reduce the trace to candidates:

   ```sh
   ecapture profile learn-jni \
     --input /data/local/tmp/app-jni-events.jsonl \
     --output /data/local/tmp/app-jni-candidates.json \
     --min-score 55
   ```

   The learner deduplicates dynamic registrations, preserves module-relative
   offsets, and ranks `ByteBuffer`, byte-array, string, request/response,
   serializer, stream, and crypto boundaries.

4. Record the process ABI, package version, library SHA-256, and GNU Build ID.
5. Enumerate exported `Java_*` functions and inspect the highest-ranked dynamic
   registrations. Dynamic registration provides the exact runtime function
   address even when the Java method name is obfuscated.
6. Convert the runtime address to a module-relative/file offset and verify that
   it lies in an executable `PT_LOAD` segment.
7. Disassemble a small caller/callee window and write down the register ABI at
   the exact instruction chosen for the uprobe.

`RegisterNatives` discovery emits metadata, not application buffers. A
`jstring`, `jbyteArray`, or `jobject` argument is a managed reference and is
never safe to dereference as a native byte pointer. Correlate the active native
method with `GetStringUTFChars`, `GetByteArrayElements`,
`GetPrimitiveArrayCritical`, or `GetDirectBufferAddress`, or locate the later
native buffer boundary in disassembly. This is why `learn-jni` ranks and guides
but deliberately does not manufacture a data hook.

At a function-entry uprobe, AArch64 profile arguments 1 through 8 correspond
to `x0` through `x7`; arguments 9 through 12 are read from the standard entry
stack slots. On SysV amd64, arguments 1 through 6 use the normal argument
registers and 7 through 12 use entry-stack slots after the return address. A
probe in the middle of a function sees the registers and stack at that exact
instruction, not necessarily the original function arguments.

Useful Cronet anchors include request adapter creation, HTTP method/header
setters, upload `readData`/`onReadSucceeded`, response
`readData`/`onReadCompleted`, and `NewDirectByteBuffer`.

## Phase 4: resolve data layouts

Classify the observed value before configuring a hook:

- raw pointer plus length argument;
- pointer stored at `buffer + offset`;
- length stored in a structure;
- libc++ `std::string` with short-string optimization;
- `DirectByteBuffer` whose pointer and actual length arrive asynchronously;
- `iovec`/`msghdr`;
- protobuf or another serialized message.

Use `buffer_format: "libcxx_string"` only after verifying the library's
24-byte alternate libc++ layout. Different libc++ ABI settings can use another
representation.

Use `buffer_format: "iovec"` only for the platform `struct iovec` ABI or a
third-party API proven to use the identical pair of native pointer-sized
fields. Configure the iovec pointer with `buffer_arg`, its count with
`vector_count_arg`, and a file descriptor/connection or stream scalar with
`context_arg`/`stream_arg` when available. `readv` must capture on return so
the result bounds bytes actually written to user memory.

Use `buffer_format: "msghdr"` for the standard 64-bit platform
`sendmsg`/`recvmsg` ABI. The direct header pointer is `buffer_arg`; defaults
read `msg_iov` at byte 16 and the eight-byte `msg_iovlen` at byte 24.
`sendmsg` captures on entry and `recvmsg` on return. Verify and override these
offsets for any nonstandard ABI. A libc socket hook observes whatever reaches
the socket—plaintext for an unencrypted protocol, but ciphertext after TLS,
QUIC, or custom encryption—so it is a baseline, not a universal decryption
boundary.

ngtcp2 vectors, chained buffers, and C++ collections are not interchangeable
with either platform adapter. Prefer a public stream ABI with accessible
pointer/count arguments, a version-pinned mid-function point where they are
materialized in registers, or a dedicated layout adapter.

For a scatter/gather API that returns packet length but writes accepted
plaintext length through an output pointer, use an iovec return hook with
`length_source: "memory"`. The scalar address is resolved from `length_arg` at
entry and read after return. Current
`ngtcp2_conn_writev_stream_versioned` uses connection argument 1,
`ngtcp2_ssize *pdatalen` argument 7, stream ID argument 9, and
`ngtcp2_vec *`/count arguments 10/11. The inspector scaffolds that exact
public symbol; it keeps older unversioned variants as hints until their header
ABI is confirmed.

Use a state pair when pointer creation and completion are split:

```json
{
  "state_group": "upload",
  "state_action": "save",
  "state_key_arg": 1
}
```

and:

```json
{
  "state_group": "upload",
  "state_action": "load",
  "state_key_arg": 3
}
```

The key must be the same stable native object in both calls. Thread ID is not a
valid cross-thread key.

## Phase 5: marker validation

Send a unique, non-secret marker such as `ECAPTURE-<timestamp>` and require all
of the following evidence:

1. The exact request URL/path is emitted.
2. Method and safe headers match the application action.
3. The request body contains the marker at the correct byte boundary.
4. The response callback contains a response derived from the marker.
5. Raw TCP or UDP packets exist during the same interval.
6. The test runs without Frida, a proxy, a user CA, or pinning changes.
7. Repeating the action does not produce stale buffers or cross-request data.
8. A deliberately wrong Build ID makes profile loading fail.

Do not publish authentication headers, cookies, account identifiers, or full
personal payloads in a report. Record lengths, hook names, timestamps, and
synthetic marker matches.

## Phase 6: production profile

Keep the exact:

- package/version/ABI/Android release;
- library glob;
- GNU Build ID;
- symbol or file offset;
- argument and structure-offset recipe;
- maximum capture size;
- raw packet interfaces and unknown-flow policy.

Run the focused semantic profile first, then combine it with `raw_packets` for
the final profile. Use `unknown_flows: "mark"` during validation; change to
`drop` only when attribution completeness has been measured.

## Agent hand-off checklist

An agent taking over a new application must report:

- target metadata and hashes;
- process map containing every selected library;
- inspector report and candidate ranking;
- static xref/disassembly evidence for every internal offset;
- exact register/memory ABI;
- marker-based request and response results;
- raw TCP/UDP/QUIC observation;
- unit tests, Linux BPF build, and target-device verifier result;
- unresolved coverage stated explicitly.

An address discovered from one build without a Build ID and runtime marker test
is not a completed profile.

## What can be automated, and what still needs evidence

| Step | Automation level | Required human/agent evidence |
| --- | --- | --- |
| ELF inventory and Build ID | automatic | confirm target package/version |
| ART `RegisterNatives` locator | automatic on standard 64-bit JNI table | cold-start event proves the offset executes |
| Dynamic JNI method identity and module offset | automatic | select semantically relevant methods |
| Public C ABI recipe | automatic when the inspector knows it | marker test |
| Standard `readv`/`writev` iovec ABI | automatic | flattened marker and return-length test |
| Standard 64-bit `sendmsg`/`recvmsg` msghdr ABI | automatic | flattened marker, header-layout, and return-length test |
| Public quiche/lsquic/current ngtcp2 stream ABI | automatic | marker, connection/stream ID, and accepted-length test |
| Validated private symbol/offset recipe catalog | automatic for matching Build ID | repeat marker and negative Build-ID test |
| Stack-specific vectors/chained buffers | candidate-assisted | exact aggregate layout or materialized-register ABI |
| Stripped C++/private SDK ABI | candidate-assisted | disassembly and register/memory layout |
| JNI object conversion | candidate-assisted | correlate the relevant `JNIEnv` conversion call |
| Serializer/custom encryption boundary | ranked hints | request and response marker proof |
| Production promotion | never blind | exact Build ID and negative wrong-Build-ID test |
