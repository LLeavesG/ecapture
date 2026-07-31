// Android's arm64 dynamic linker requires PT_TLS alignment of at least 64
// bytes. Go binaries built with GOOS=linux are required by cilium/ebpf, but
// Go's runtime TLS block otherwise has an alignment of only 8 bytes.
//
// Keep this symbol in the final link to raise the output PT_TLS alignment
// without patching the generated ELF after the fact.
__thread __attribute__((aligned(64))) unsigned char ecapture_android_tls_align_guard;
