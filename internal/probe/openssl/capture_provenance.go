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

package openssl

// CaptureLayer records where bytes were observed. Keeping this provenance in
// every structured event prevents application logs or serializer objects from
// being mistaken for bytes that crossed a transport boundary.
const (
	CaptureLayerWire      = "wire"
	CaptureLayerTransport = "transport"
	CaptureLayerSemantic  = "semantic"
	CaptureLayerMetadata  = "metadata"

	CaptureTransportTLS    = "tls"
	CaptureTransportQUIC   = "quic"
	CaptureTransportSocket = "socket"
	CaptureTransportFD     = "fd"

	// CaptureBoundaryTLSCiphertext identifies encrypted TLS bytes at a custom
	// BIO boundary. CaptureBoundarySocketPayload identifies bytes passed to or
	// returned from a known socket API. CaptureBoundaryFDPayload is deliberately
	// weaker: a generic descriptor may be a socket, file, or pipe. The preferred
	// network proof matches TLS ciphertext directly to captured packet payloads.
	CaptureBoundaryTLSCiphertext = "tls_ciphertext"
	CaptureBoundarySocketPayload = "socket_payload"
	CaptureBoundaryFDPayload     = "fd_payload"
)
