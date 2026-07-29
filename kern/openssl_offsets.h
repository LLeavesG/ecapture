// Copyright 2026 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ECAPTURE_OPENSSL_OFFSETS_H
#define ECAPTURE_OPENSSL_OFFSETS_H

// Structure layouts vary across OpenSSL/BoringSSL forks and application
// builds. Keep the generated object's historical offsets as defaults while
// allowing userspace to rewrite individual values through .rodata.
const volatile u64 ecapture_offset_ssl_st_rbio = SSL_ST_RBIO;
const volatile u64 ecapture_offset_ssl_st_wbio = SSL_ST_WBIO;
#ifdef SSL_ST_VERSION
const volatile u64 ecapture_offset_ssl_st_version = SSL_ST_VERSION;
#else
const volatile u64 ecapture_offset_ssl_st_version = 0;
#endif
#ifdef SSL_ST_S3
const volatile u64 ecapture_offset_ssl_st_s3 = SSL_ST_S3;
#else
const volatile u64 ecapture_offset_ssl_st_s3 = 0;
#endif
#ifdef BSSL__SSL3_STATE_VERSION
const volatile u64 ecapture_offset_ssl3_state_version = BSSL__SSL3_STATE_VERSION;
#else
const volatile u64 ecapture_offset_ssl3_state_version = 0;
#endif
const volatile u64 ecapture_offset_bio_st_method = BIO_ST_METHOD;
const volatile u64 ecapture_offset_bio_st_num = BIO_ST_NUM;
const volatile u64 ecapture_offset_bio_method_st_type = BIO_METHOD_ST_TYPE;

#endif
