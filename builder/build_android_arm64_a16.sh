#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [[ -z "$ndk_root" ]]; then
    echo "ANDROID_NDK_HOME or ANDROID_NDK_ROOT must point to an Android NDK" >&2
    exit 2
fi

case "$(uname -s)" in
    Darwin) ndk_host_tag="darwin-x86_64" ;;
    Linux) ndk_host_tag="linux-x86_64" ;;
    *)
        echo "unsupported build host: $(uname -s)" >&2
        exit 2
        ;;
esac

android_api="${ANDROID_API:-24}"
ndk_bin="$ndk_root/toolchains/llvm/prebuilt/$ndk_host_tag/bin"
cc="$ndk_bin/aarch64-linux-android${android_api}-clang"
ar="$ndk_bin/llvm-ar"
readelf="$ndk_bin/llvm-readelf"
output="${ECAPTURE_ANDROID_OUTPUT:-bin/ecapture-android-arm64-a16}"

cleanup() {
    local generated_file
    for generated_file in \
        "$project_dir/lib/libpcap/libpthread.a" \
        "$project_dir/builder/android_tls_align.o" \
        "$project_dir/builder/libandroidtlsalign.a"; do
        if [[ -e "$generated_file" ]]; then
            unlink "$generated_file"
        fi
    done
}
trap cleanup EXIT

for tool in "$cc" "$ar" "$readelf" go make perl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing required build tool: $tool" >&2
        exit 2
    fi
done

host_llvm_bin="${ECAPTURE_HOST_LLVM_BIN:-}"
if [[ -n "$host_llvm_bin" ]]; then
    export PATH="$host_llvm_bin:$PATH"
fi
for tool in clang llc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing host LLVM tool: $tool (set ECAPTURE_HOST_LLVM_BIN)" >&2
        exit 2
    fi
done

# cilium/ebpf needs GOOS=linux at runtime even though the output uses Android's
# dynamic linker. Build the Android 16 CO-RE object and embed only that object.
ANDROID=1 \
TARGET_ARCH=aarch64 \
GOARCH=arm64 \
LINUX_ARCH=arm64 \
# The checked-in Android vmlinux.h removes the need to execute bpftool here.
# Reuse the already-validated Go tool target to satisfy Make's autogen gate.
CMD_BPFTOOL=go \
AUTOGENCMD=true \
make kern/boringssl_a_16_kern.o
go run github.com/shuLhan/go-bindata/cmd/go-bindata \
    -pkg assets \
    -o assets/ebpf_probe.go \
    bytecode/boringssl_a_16_kern_core.o
perl -0pi -e \
    's{\A// Code generated}{//go:build ebpfassets\n// Code generated}' \
    assets/ebpf_probe.go

pushd lib/libpcap >/dev/null
make distclean >/dev/null 2>&1 || true
CC="$cc" \
AR="$ar" \
RANLIB="$ndk_bin/llvm-ranlib" \
CFLAGS="-O2 -g -gdwarf-4 -static -Wno-unused-result" \
./configure \
    --disable-shared \
    --disable-usb \
    --disable-netmap \
    --disable-bluetooth \
    --disable-dbus \
    --disable-rdma \
    --without-libnl \
    --without-dag \
    --without-septel \
    --without-snf \
    --without-turbocap \
    --host=aarch64-linux-android
make -j"${ECAPTURE_BUILD_JOBS:-8}"

# Go's Linux cgo link asks for libpthread, while Bionic provides those symbols
# from libc. An empty compatibility archive makes that relationship explicit.
"$ar" rcs libpthread.a
popd >/dev/null

# Android arm64 rejects a PT_TLS alignment below 64. Keep a 64-byte-aligned TLS
# symbol so a GOOS=linux binary remains acceptable to /system/bin/linker64.
"$cc" \
    -fPIC \
    -fno-emulated-tls \
    -c builder/android_tls_align.c \
    -o builder/android_tls_align.o
"$ar" rcs builder/libandroidtlsalign.a builder/android_tls_align.o

mkdir -p "$(dirname "$output")"
CGO_ENABLED=1 \
GOOS=linux \
GOARCH=arm64 \
CC="$cc" \
CGO_CFLAGS="-O2 -I$project_dir/lib/libpcap" \
CGO_LDFLAGS="-L$project_dir/lib/libpcap -lpcap -L$project_dir/builder -landroidtlsalign -Wl,--undefined=ecapture_android_tls_align_guard" \
go build \
    -trimpath \
    -buildmode=pie \
    -mod=readonly \
    -tags "ecap_android,netgo,ebpfassets,dynamic" \
    -ldflags "-w -s -X 'github.com/gojue/ecapture/cli/cmd.GitVersion=ecap_android_arm64:a16:local' -X 'github.com/gojue/ecapture/cli/cmd.ByteCodeFiles=core' -linkmode=external" \
    -o "$output" \
    .

tls_align="$("$readelf" -lW "$output" | awk '$1 == "TLS" {print $NF}')"
if [[ -z "$tls_align" ]] || (( tls_align < 64 )); then
    echo "invalid Android arm64 PT_TLS alignment: ${tls_align:-missing}" >&2
    exit 1
fi

file "$output"
echo "PT_TLS alignment: $tls_align"
echo "built: $output"
