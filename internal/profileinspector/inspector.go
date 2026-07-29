// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package profileinspector inventories a process's ELF libraries and ranks
// reusable plaintext hook candidates. It deliberately does not claim that an
// exported-looking function is active: candidates still need a marker-based
// runtime validation before they are promoted into a pinned application
// profile.
package profileinspector

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	ReportVersion = 1

	LayerSemantic  = "semantic"
	LayerPlaintext = "plaintext"
	LayerCrypto    = "crypto"
	LayerTransport = "transport"

	ConfidenceExact  = "exact"
	ConfidenceStrong = "strong"
	ConfidenceHint   = "hint"

	maxSignalSectionBytes = 64 << 20
	maxSignalScanBytes    = 128 << 20

	jniRegisterNativesIndex = 215
	jniFunctionTableEntries = 233
)

// Report is deterministic so it can be checked into a reverse-engineering
// workspace and compared after an application update.
type Report struct {
	Version   int             `json:"version"`
	PID       uint64          `json:"pid,omitempty"`
	Libraries []LibraryReport `json:"libraries"`
	Errors    []string        `json:"errors,omitempty"`
}

type LibraryReport struct {
	Path       string          `json:"path"`
	BuildID    string          `json:"build_id,omitempty"`
	ELFType    string          `json:"elf_type,omitempty"`
	Class      string          `json:"class,omitempty"`
	Machine    string          `json:"machine,omitempty"`
	Stripped   bool            `json:"stripped"`
	Families   []string        `json:"families,omitempty"`
	Signals    []Signal        `json:"signals,omitempty"`
	Candidates []HookCandidate `json:"candidates,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type Signal struct {
	Family   string `json:"family"`
	Evidence string `json:"evidence"`
}

// HookCandidate describes an anchor that can either be used immediately when
// Recipe is present or as a search seed for a stripped/internal function.
type HookCandidate struct {
	Family         string      `json:"family"`
	Layer          string      `json:"layer"`
	Role           string      `json:"role"`
	Symbol         string      `json:"symbol"`
	SymbolSource   string      `json:"symbol_source"`
	VirtualAddress string      `json:"virtual_address,omitempty"`
	FileOffset     string      `json:"file_offset,omitempty"`
	Confidence     string      `json:"confidence"`
	Priority       int         `json:"priority"`
	ABI            string      `json:"abi,omitempty"`
	Recipe         *HookRecipe `json:"recipe,omitempty"`
	Notes          string      `json:"notes,omitempty"`
}

// HookRecipe is the subset of an application-data profile hook that can be
// inferred safely from a stable public C ABI.
type HookRecipe struct {
	Direction      string `json:"direction"`
	CaptureOn      string `json:"capture_on"`
	BufferArg      uint32 `json:"buffer_arg"`
	LengthSource   string `json:"length_source,omitempty"`
	LengthArg      uint32 `json:"length_arg,omitempty"`
	MaxBytes       uint32 `json:"max_bytes,omitempty"`
	ContextArg     uint32 `json:"context_arg,omitempty"`
	StreamArg      uint32 `json:"stream_arg,omitempty"`
	BufferFormat   string `json:"buffer_format,omitempty"`
	VectorCountArg uint32 `json:"vector_count_arg,omitempty"`
}

type symbolRecipe struct {
	family     string
	layer      string
	role       string
	confidence string
	priority   int
	abi        string
	hook       *HookRecipe
	notes      string
}

var knownSymbolRecipes = map[string]symbolRecipe{
	"SSL_write": directWriteRecipe(
		"openssl", "tls-write", 100,
		"int SSL_write(SSL *ssl, const void *buf, int num)",
	),
	"SSL_read": directReadRecipe(
		"openssl", "tls-read", 100,
		"int SSL_read(SSL *ssl, void *buf, int num)",
	),
	"SSL_write_ex": directWriteRecipe(
		"openssl", "tls-write-ex", 96,
		"int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)",
	),
	"gnutls_record_send": directWriteRecipe(
		"gnutls", "record-send", 100,
		"ssize_t gnutls_record_send(session, const void *data, size_t size)",
	),
	"gnutls_record_recv": directReadRecipe(
		"gnutls", "record-recv", 100,
		"ssize_t gnutls_record_recv(session, void *data, size_t size)",
	),
	"mbedtls_ssl_write": directWriteRecipe(
		"mbedtls", "tls-write", 100,
		"int mbedtls_ssl_write(ctx, const unsigned char *buf, size_t len)",
	),
	"mbedtls_ssl_read": directReadRecipe(
		"mbedtls", "tls-read", 100,
		"int mbedtls_ssl_read(ctx, unsigned char *buf, size_t len)",
	),
	"wolfSSL_write": directWriteRecipe(
		"wolfssl", "tls-write", 100,
		"int wolfSSL_write(ssl, const void *data, int sz)",
	),
	"wolfSSL_read": directReadRecipe(
		"wolfssl", "tls-read", 100,
		"int wolfSSL_read(ssl, void *data, int sz)",
	),
	"PR_Write": directWriteRecipe(
		"nspr", "record-write", 98,
		"PRInt32 PR_Write(PRFileDesc *fd, const void *buf, PRInt32 amount)",
	),
	"PR_Read": directReadRecipe(
		"nspr", "record-read", 98,
		"PRInt32 PR_Read(PRFileDesc *fd, void *buf, PRInt32 amount)",
	),
	"PR_Send": directWriteRecipe(
		"nspr", "record-send", 96,
		"PRInt32 PR_Send(PRFileDesc *fd, const void *buf, PRInt32 amount, ...)",
	),
	"PR_Recv": directReadRecipe(
		"nspr", "record-recv", 96,
		"PRInt32 PR_Recv(PRFileDesc *fd, void *buf, PRInt32 amount, ...)",
	),
	"quiche_conn_stream_send": {
		family:     "quiche",
		layer:      LayerPlaintext,
		role:       "quic-stream-send",
		confidence: ConfidenceExact,
		priority:   94,
		abi:        "ssize_t quiche_conn_stream_send(conn, stream_id, buf, buf_len, fin)",
		hook: &HookRecipe{
			Direction:    "write",
			CaptureOn:    "entry",
			BufferArg:    3,
			LengthSource: "argument",
			LengthArg:    4,
			MaxBytes:     131072,
			ContextArg:   1,
			StreamArg:    2,
		},
		notes: "Captures QUIC stream plaintext before packet protection.",
	},
	"quiche_conn_stream_recv": {
		family:     "quiche",
		layer:      LayerPlaintext,
		role:       "quic-stream-recv",
		confidence: ConfidenceExact,
		priority:   94,
		abi:        "ssize_t quiche_conn_stream_recv(conn, stream_id, out, out_len, fin)",
		hook: &HookRecipe{
			Direction:    "read",
			CaptureOn:    "return",
			BufferArg:    3,
			LengthSource: "return",
			MaxBytes:     131072,
			ContextArg:   1,
			StreamArg:    2,
		},
		notes: "Captures QUIC stream plaintext after packet unprotection.",
	},
	"lsquic_stream_write": contextualRecipe(directWriteRecipe(
		"lsquic", "quic-stream-write", 92,
		"ssize_t lsquic_stream_write(stream, const void *buf, size_t len)",
	), 1),
	"lsquic_stream_read": contextualRecipe(directReadRecipe(
		"lsquic", "quic-stream-read", 92,
		"ssize_t lsquic_stream_read(stream, void *buf, size_t len)",
	), 1),
	"send": transportWriteRecipe(
		"libc", "socket-send", 40,
		"ssize_t send(int fd, const void *buf, size_t len, int flags)",
	),
	"recv": transportReadRecipe(
		"libc", "socket-recv", 40,
		"ssize_t recv(int fd, void *buf, size_t len, int flags)",
	),
	"sendto": transportWriteRecipe(
		"libc", "socket-sendto", 40,
		"ssize_t sendto(int fd, const void *buf, size_t len, ...)",
	),
	"recvfrom": transportReadRecipe(
		"libc", "socket-recvfrom", 40,
		"ssize_t recvfrom(int fd, void *buf, size_t len, ...)",
	),
	"write": transportWriteRecipe(
		"libc", "fd-write", 20,
		"ssize_t write(int fd, const void *buf, size_t count)",
	),
	"read": transportReadRecipe(
		"libc", "fd-read", 20,
		"ssize_t read(int fd, void *buf, size_t count)",
	),
	"writev": iovecRecipe(
		"libc", "fd-writev", "write", 32,
		"ssize_t writev(int fd, const struct iovec *iov, int iovcnt)",
	),
	"readv": iovecRecipe(
		"libc", "fd-readv", "read", 32,
		"ssize_t readv(int fd, const struct iovec *iov, int iovcnt)",
	),
	"SSL_provide_quic_data": {
		family:     "boringssl-quic",
		layer:      LayerCrypto,
		role:       "quic-handshake-input",
		confidence: ConfidenceExact,
		priority:   70,
		abi:        "int SSL_provide_quic_data(SSL *ssl, enum ssl_encryption_level_t level, const uint8_t *data, size_t len)",
		notes:      "Carries TLS CRYPTO handshake bytes only; it is not HTTP/3 application plaintext.",
	},
	"ngtcp2_conn_writev_stream": {
		family:     "ngtcp2",
		layer:      LayerPlaintext,
		role:       "quic-stream-writev",
		confidence: ConfidenceStrong,
		priority:   76,
		notes:      "Scatter/gather ABI requires an iovec-aware hook; no direct-buffer scaffold is emitted.",
	},
	"ngtcp2_conn_read_pkt": {
		family:     "ngtcp2",
		layer:      LayerCrypto,
		role:       "quic-packet-input",
		confidence: ConfidenceStrong,
		priority:   60,
		notes:      "Receives protected QUIC packets; locate stream callbacks for application plaintext.",
	},
	"sendmsg": msgHdrRecipe(
		"libc", "socket-sendmsg", "write", 35,
		"ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)",
	),
	"recvmsg": msgHdrRecipe(
		"libc", "socket-recvmsg", "read", 35,
		"ssize_t recvmsg(int fd, struct msghdr *msg, int flags)",
	),
	"EVP_EncryptUpdate": {
		family:     "openssl",
		layer:      LayerCrypto,
		role:       "application-encrypt",
		confidence: ConfidenceExact,
		priority:   55,
		notes:      "Useful discovery anchor for custom application encryption; validate input/output ownership before capturing.",
	},
	"EVP_DecryptUpdate": {
		family:     "openssl",
		layer:      LayerCrypto,
		role:       "application-decrypt",
		confidence: ConfidenceExact,
		priority:   55,
		notes:      "Useful discovery anchor for custom application encryption; validate input/output ownership before capturing.",
	},
}

type stringSignal struct {
	needle   string
	family   string
	evidence string
}

var knownStringSignals = []stringSignal{
	{"CronetUrlRequest", "cronet", "CronetUrlRequest runtime string"},
	{"CronetUploadDataStream", "cronet", "Cronet upload runtime string"},
	{"onReadSucceeded", "cronet", "asynchronous upload completion callback"},
	{"onReadCompleted", "cronet", "asynchronous response completion callback"},
	{"createRequestAdapter", "cronet", "request adapter JNI method"},
	{"SSL_provide_quic_data", "boringssl-quic", "BoringSSL QUIC handshake API string"},
	{"quiche_conn_stream_send", "quiche", "quiche stream API string"},
	{"ngtcp2_conn_writev_stream", "ngtcp2", "ngtcp2 stream API string"},
	{"lsquic_stream_write", "lsquic", "lsquic stream API string"},
	{"application/grpc", "grpc", "gRPC content type"},
	{"application/x-protobuf", "protobuf", "protobuf content type"},
	{"google/protobuf", "protobuf", "protobuf runtime string"},
	{"flatbuffers", "flatbuffers", "FlatBuffers runtime string"},
	{"application/json", "json", "JSON content type"},
	{"HTTP/3", "http3", "HTTP/3 protocol string"},
}

func directWriteRecipe(family, role string, priority int, abi string) symbolRecipe {
	return symbolRecipe{
		family:     family,
		layer:      LayerPlaintext,
		role:       role,
		confidence: ConfidenceExact,
		priority:   priority,
		abi:        abi,
		hook: &HookRecipe{
			Direction:    "write",
			CaptureOn:    "entry",
			BufferArg:    2,
			LengthSource: "argument",
			LengthArg:    3,
			MaxBytes:     131072,
		},
	}
}

func directReadRecipe(family, role string, priority int, abi string) symbolRecipe {
	return symbolRecipe{
		family:     family,
		layer:      LayerPlaintext,
		role:       role,
		confidence: ConfidenceExact,
		priority:   priority,
		abi:        abi,
		hook: &HookRecipe{
			Direction:    "read",
			CaptureOn:    "return",
			BufferArg:    2,
			LengthSource: "return",
			MaxBytes:     131072,
		},
	}
}

func contextualRecipe(recipe symbolRecipe, contextArg uint32) symbolRecipe {
	recipe.hook.ContextArg = contextArg
	return recipe
}

func iovecRecipe(
	family, role, direction string,
	priority int,
	abi string,
) symbolRecipe {
	captureOn := "entry"
	if direction == "read" {
		captureOn = "return"
	}
	return symbolRecipe{
		family:     family,
		layer:      LayerTransport,
		role:       role,
		confidence: ConfidenceExact,
		priority:   priority,
		abi:        abi,
		hook: &HookRecipe{
			Direction:      direction,
			CaptureOn:      captureOn,
			BufferArg:      2,
			BufferFormat:   "iovec",
			VectorCountArg: 3,
			MaxBytes:       131072,
			ContextArg:     1,
		},
		notes: "Captures a bounded flattened iovec prefix; bytes may already be encrypted by a higher layer.",
	}
}

func msgHdrRecipe(
	family, role, direction string,
	priority int,
	abi string,
) symbolRecipe {
	captureOn := "entry"
	if direction == "read" {
		captureOn = "return"
	}
	return symbolRecipe{
		family:     family,
		layer:      LayerTransport,
		role:       role,
		confidence: ConfidenceExact,
		priority:   priority,
		abi:        abi,
		hook: &HookRecipe{
			Direction:    direction,
			CaptureOn:    captureOn,
			BufferArg:    2,
			BufferFormat: "msghdr",
			MaxBytes:     131072,
			ContextArg:   1,
		},
		notes: "Captures the bounded flattened msg_iov stream from the standard 64-bit msghdr ABI; bytes may already be encrypted.",
	}
}

func transportWriteRecipe(family, role string, priority int, abi string) symbolRecipe {
	recipe := directWriteRecipe(family, role, priority, abi)
	recipe.layer = LayerTransport
	recipe.notes = "Captures the serialized socket/file bytes; they may already be encrypted by a higher layer."
	return recipe
}

func transportReadRecipe(family, role string, priority int, abi string) symbolRecipe {
	recipe := directReadRecipe(family, role, priority, abi)
	recipe.layer = LayerTransport
	recipe.notes = "Captures the serialized socket/file bytes; they may still be encrypted by a higher layer."
	return recipe
}

// Inspect inventories explicit libraries and executable ELF mappings from pid.
func Inspect(pid uint64, libraries []string) (*Report, error) {
	report := &Report{Version: ReportVersion, PID: pid}
	paths := append([]string(nil), libraries...)
	if pid != 0 {
		mapped, err := ProcessLibraries(pid)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
		} else {
			paths = append(paths, mapped...)
		}
	}
	paths = uniqueSortedPaths(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no ELF libraries supplied or discovered")
	}

	for _, path := range paths {
		report.Libraries = append(report.Libraries, InspectLibrary(path))
	}
	return report, nil
}

// ProcessLibraries returns executable, file-backed mappings for a process.
func ProcessLibraries(pid uint64) ([]string, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open process maps %q: %w", path, err)
	}
	defer file.Close()
	return ParseProcessMaps(file)
}

// ParseProcessMaps is exported for agents that collect /proc/PID/maps on a
// device and inspect it later in a Linux analysis VM.
func ParseProcessMaps(reader io.Reader) ([]string, error) {
	var paths []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || !strings.Contains(fields[1], "x") {
			continue
		}
		path := strings.Join(fields[5:], " ")
		path = strings.TrimSuffix(path, " (deleted)")
		if !filepath.IsAbs(path) {
			continue
		}
		paths = append(paths, path)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read process maps: %w", err)
	}
	return uniqueSortedPaths(paths), nil
}

func uniqueSortedPaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, found := seen[path]; found {
			continue
		}
		seen[path] = struct{}{}
		result = append(result, path)
	}
	sort.Strings(result)
	return result
}

func InspectLibrary(path string) LibraryReport {
	report := LibraryReport{Path: path}
	file, err := elf.Open(path)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	defer file.Close()

	report.ELFType = file.Type.String()
	report.Class = file.Class.String()
	report.Machine = file.Machine.String()
	if buildID, buildErr := readBuildID(file); buildErr == nil {
		report.BuildID = buildID
	}

	symbols, hasStaticSymbols := collectSymbols(file)
	report.Stripped = !hasStaticSymbols
	for _, current := range symbols {
		recipe, found := candidateForSymbol(current.name)
		if !found {
			continue
		}
		report.Candidates = append(report.Candidates, HookCandidate{
			Family:         recipe.family,
			Layer:          recipe.layer,
			Role:           recipe.role,
			Symbol:         current.name,
			SymbolSource:   current.source,
			VirtualAddress: hexUint64(current.value),
			FileOffset:     hexUint64(symbolFileOffset(file, current.value)),
			Confidence:     recipe.confidence,
			Priority:       recipe.priority,
			ABI:            recipe.abi,
			Recipe:         cloneHookRecipe(recipe.hook),
			Notes:          recipe.notes,
		})
	}
	report.Candidates = append(report.Candidates, inspectJNIFunctionTables(file)...)

	report.Signals = scanSignals(file)
	families := make(map[string]struct{})
	for _, candidate := range report.Candidates {
		families[candidate.Family] = struct{}{}
	}
	for _, signal := range report.Signals {
		families[signal.Family] = struct{}{}
	}
	for family := range families {
		report.Families = append(report.Families, family)
	}
	sort.Strings(report.Families)
	sort.SliceStable(report.Candidates, func(i, j int) bool {
		if report.Candidates[i].Priority != report.Candidates[j].Priority {
			return report.Candidates[i].Priority > report.Candidates[j].Priority
		}
		if report.Candidates[i].Layer != report.Candidates[j].Layer {
			return report.Candidates[i].Layer < report.Candidates[j].Layer
		}
		return report.Candidates[i].Symbol < report.Candidates[j].Symbol
	})
	return report
}

type jniTableCandidate struct {
	tableAddress    uint64
	registerAddress uint64
	validEntries    int
}

// inspectJNIFunctionTables locates JNINativeInterface tables without relying
// on private ART symbols. The JNI ABI fixes RegisterNatives at table index 215;
// Android's tables start with four reserved null pointers followed by a dense
// array of executable function addresses.
func inspectJNIFunctionTables(file *elf.File) []HookCandidate {
	if file.Class != elf.ELFCLASS64 {
		return nil
	}
	isExecutable := func(address uint64) bool {
		for _, program := range file.Progs {
			if program.Type != elf.PT_LOAD || program.Flags&elf.PF_X == 0 {
				continue
			}
			if address >= program.Vaddr && address < program.Vaddr+program.Memsz {
				return true
			}
		}
		return false
	}
	seen := make(map[uint64]struct{})
	var result []HookCandidate
	for _, section := range file.Sections {
		if section.Type != elf.SHT_PROGBITS || section.Flags&elf.SHF_ALLOC == 0 ||
			section.Flags&elf.SHF_WRITE == 0 || section.Size < jniFunctionTableEntries*8 {
			continue
		}
		data, err := section.Data()
		if err != nil {
			continue
		}
		for _, table := range scanJNIFunctionTableData(
			data,
			section.Addr,
			file.ByteOrder,
			isExecutable,
		) {
			if _, found := seen[table.registerAddress]; found {
				continue
			}
			seen[table.registerAddress] = struct{}{}
			result = append(result, HookCandidate{
				Family:         "art-jni",
				Layer:          LayerSemantic,
				Role:           "register-natives",
				Symbol:         "JNINativeInterface.RegisterNatives",
				SymbolSource:   "jni-table",
				VirtualAddress: hexUint64(table.registerAddress),
				FileOffset:     hexUint64(symbolFileOffset(file, table.registerAddress)),
				Confidence:     ConfidenceExact,
				Priority:       99,
				ABI:            "jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint method_count)",
				Notes: fmt.Sprintf(
					"JNI table %s has %d/%d executable entries; attach the specialized registration decoder at this file offset.",
					hexUint64(table.tableAddress),
					table.validEntries,
					jniFunctionTableEntries-4,
				),
			})
		}
	}
	return result
}

func scanJNIFunctionTableData(
	data []byte,
	sectionAddress uint64,
	byteOrder binary.ByteOrder,
	isExecutable func(uint64) bool,
) []jniTableCandidate {
	const tableBytes = jniFunctionTableEntries * 8
	var result []jniTableCandidate
	for offset := 0; offset+tableBytes <= len(data); offset += 8 {
		if byteOrder.Uint64(data[offset:offset+8]) != 0 ||
			byteOrder.Uint64(data[offset+8:offset+16]) != 0 ||
			byteOrder.Uint64(data[offset+16:offset+24]) != 0 ||
			byteOrder.Uint64(data[offset+24:offset+32]) != 0 {
			continue
		}
		valid := 0
		for index := 4; index < jniFunctionTableEntries; index++ {
			start := offset + index*8
			if isExecutable(byteOrder.Uint64(data[start : start+8])) {
				valid++
			}
		}
		// Permit a few architecture/version-specific null or external entries,
		// but reject arbitrary data arrays that happen to start with four zeros.
		if valid*100 < (jniFunctionTableEntries-4)*90 {
			continue
		}
		registerStart := offset + jniRegisterNativesIndex*8
		registerAddress := byteOrder.Uint64(data[registerStart : registerStart+8])
		if !isExecutable(registerAddress) {
			continue
		}
		result = append(result, jniTableCandidate{
			tableAddress:    sectionAddress + uint64(offset),
			registerAddress: registerAddress,
			validEntries:    valid,
		})
	}
	return result
}

type inspectedSymbol struct {
	name   string
	value  uint64
	source string
}

func collectSymbols(file *elf.File) ([]inspectedSymbol, bool) {
	seen := make(map[string]struct{})
	var result []inspectedSymbol
	add := func(symbols []elf.Symbol, source string) {
		for _, symbol := range symbols {
			if symbol.Section == elf.SHN_UNDEF {
				continue
			}
			symbolType := elf.ST_TYPE(symbol.Info)
			if symbolType != elf.STT_FUNC && symbolType != elf.STT_NOTYPE {
				continue
			}
			name := strings.SplitN(symbol.Name, "@", 2)[0]
			if name == "" {
				continue
			}
			key := name + "\x00" + strconv.FormatUint(symbol.Value, 16)
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, inspectedSymbol{name: name, value: symbol.Value, source: source})
		}
	}
	dynamic, _ := file.DynamicSymbols()
	add(dynamic, "dynamic")
	static, staticErr := file.Symbols()
	add(static, "symtab")
	return result, staticErr == nil && len(static) != 0
}

func candidateForSymbol(name string) (symbolRecipe, bool) {
	if recipe, found := knownSymbolRecipes[name]; found {
		return recipe, true
	}
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(name, "Java_") && strings.Contains(lower, "cronet"):
		return symbolRecipe{
			family:     "cronet",
			layer:      LayerSemantic,
			role:       "jni-entry",
			confidence: ConfidenceStrong,
			priority:   84,
			notes:      "Inspect the JNI signature or RegisterNatives table before assigning buffer arguments.",
		}, true
	case strings.Contains(lower, "onreadsucceeded") && strings.Contains(lower, "cronet"):
		return symbolRecipe{
			family:     "cronet",
			layer:      LayerSemantic,
			role:       "upload-complete",
			confidence: ConfidenceStrong,
			priority:   90,
			notes:      "Pair with the DirectByteBuffer creation/read callback to recover the buffer and actual length.",
		}, true
	case strings.Contains(lower, "onreadcompleted") && strings.Contains(lower, "cronet"):
		return symbolRecipe{
			family:     "cronet",
			layer:      LayerSemantic,
			role:       "response-complete",
			confidence: ConfidenceStrong,
			priority:   90,
			notes:      "The callback normally carries an IOBuffer wrapper and bytes_read.",
		}, true
	case strings.Contains(lower, "createrequestadapter") && strings.Contains(lower, "cronet"):
		return symbolRecipe{
			family:     "cronet",
			layer:      LayerSemantic,
			role:       "request-create",
			confidence: ConfidenceStrong,
			priority:   92,
			notes:      "Use this anchor to locate URL conversion and the returned native request identity.",
		}, true
	default:
		return symbolRecipe{}, false
	}
}

func cloneHookRecipe(recipe *HookRecipe) *HookRecipe {
	if recipe == nil {
		return nil
	}
	copy := *recipe
	return &copy
}

func symbolFileOffset(file *elf.File, address uint64) uint64 {
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || address < program.Vaddr {
			continue
		}
		delta := address - program.Vaddr
		if delta >= program.Filesz {
			continue
		}
		return program.Off + delta
	}
	return address
}

func scanSignals(file *elf.File) []Signal {
	found := make(map[string]Signal)
	scanned := uint64(0)
	for _, section := range file.Sections {
		if section.Flags&elf.SHF_ALLOC == 0 || section.Flags&elf.SHF_EXECINSTR != 0 ||
			section.Size == 0 || section.Size > maxSignalSectionBytes ||
			scanned+section.Size > maxSignalScanBytes {
			continue
		}
		data, err := section.Data()
		if err != nil {
			continue
		}
		scanned += uint64(len(data))
		for _, signal := range knownStringSignals {
			if !bytes.Contains(data, []byte(signal.needle)) {
				continue
			}
			key := signal.family + "\x00" + signal.evidence
			found[key] = Signal{Family: signal.family, Evidence: signal.evidence}
		}
	}
	result := make([]Signal, 0, len(found))
	for _, signal := range found {
		result = append(result, signal)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Family != result[j].Family {
			return result[i].Family < result[j].Family
		}
		return result[i].Evidence < result[j].Evidence
	})
	return result
}

func readBuildID(file *elf.File) (string, error) {
	section := file.Section(".note.gnu.build-id")
	if section == nil {
		return "", fmt.Errorf("missing GNU build ID")
	}
	data, err := section.Data()
	if err != nil {
		return "", err
	}
	for len(data) >= 12 {
		nameSize := int(file.ByteOrder.Uint32(data[0:4]))
		descSize := int(file.ByteOrder.Uint32(data[4:8]))
		noteType := file.ByteOrder.Uint32(data[8:12])
		nameEnd := 12 + nameSize
		descStart := align4(nameEnd)
		descEnd := descStart + descSize
		next := align4(descEnd)
		if nameEnd > len(data) || descEnd > len(data) || next > len(data) {
			return "", fmt.Errorf("malformed GNU build ID note")
		}
		name := bytes.TrimRight(data[12:nameEnd], "\x00")
		if noteType == 3 && bytes.Equal(name, []byte("GNU")) && descSize != 0 {
			return hex.EncodeToString(data[descStart:descEnd]), nil
		}
		data = data[next:]
	}
	return "", fmt.Errorf("missing GNU build ID")
}

func align4(value int) int {
	return (value + 3) &^ 3
}

func hexUint64(value uint64) string {
	if value == 0 {
		return ""
	}
	return fmt.Sprintf("0x%x", value)
}
