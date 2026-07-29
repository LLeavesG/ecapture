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

/*
 * Safe integration fixture for application-data iovec hooks.
 *
 * Build:
 *   cc -O0 -g -rdynamic -o /tmp/ecapture-iovec-helper \
 *      testdata/iovec_capture_helper.c
 *
 * The initial delay gives eCapture time to attach to the exported wrapper
 * functions. Both calls operate only on fixed, non-sensitive marker strings.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define EXPORTED __attribute__((noinline, visibility("default")))

EXPORTED ssize_t ecapture_test_writev(int fd, const struct iovec *iov, int iovcnt) {
    return writev(fd, iov, iovcnt);
}

EXPORTED ssize_t ecapture_test_readv(int fd, const struct iovec *iov, int iovcnt) {
    return readv(fd, iov, iovcnt);
}

EXPORTED ssize_t ecapture_test_sendmsg(int fd, const struct msghdr *message, int flags) {
    return sendmsg(fd, message, flags);
}

EXPORTED ssize_t ecapture_test_recvmsg(int fd, struct msghdr *message, int flags) {
    return recvmsg(fd, message, flags);
}

/*
 * Mirrors ngtcp2_conn_writev_stream_versioned's 12-argument shape without
 * linking any QUIC implementation. The accepted plaintext length is written
 * through argument seven; stream/vector/count live at arguments 9/10/11.
 */
EXPORTED ssize_t ecapture_test_higharg_iovec(
    void *context, void *path, int packet_info_version, void *packet_info,
    void *destination, size_t destination_length, ssize_t *accepted_length,
    uint32_t flags, int64_t stream_id, const struct iovec *vectors,
    size_t vector_count, uint64_t timestamp) {
    (void)context;
    (void)path;
    (void)packet_info_version;
    (void)packet_info;
    (void)destination;
    (void)flags;
    (void)stream_id;
    (void)vectors;
    (void)vector_count;
    (void)timestamp;
    *accepted_length = 36;
    return (ssize_t)destination_length;
}

int main(void) {
    static const char write_part_1[] = "ECAPTURE-";
    static const char write_part_2[] = "IOVEC-WRITE-";
    static const char write_part_3[] = "MARKER\n";
    struct iovec write_vectors[] = {
        {(void *)write_part_1, sizeof(write_part_1) - 1},
        {(void *)write_part_2, sizeof(write_part_2) - 1},
        {(void *)write_part_3, sizeof(write_part_3) - 1},
    };

    int null_fd = open("/dev/null", O_WRONLY);
    int pipe_fds[2];
    int message_fds[2];
    if (null_fd < 0 || pipe(pipe_fds) != 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM, 0, message_fds) != 0)
        return 1;

    printf("ready pid=%ld\n", (long)getpid());
    fflush(stdout);
    sleep(8);

    if (ecapture_test_writev(
            null_fd,
            write_vectors,
            (int)(sizeof(write_vectors) / sizeof(write_vectors[0]))) < 0)
        return 2;

    static const char read_marker[] = "ECAPTURE-IOVEC-READ-MARKER\n";
    if (write(pipe_fds[1], read_marker, sizeof(read_marker) - 1) < 0)
        return 3;
    char read_part_1[9] = {};
    char read_part_2[12] = {};
    char read_part_3[32] = {};
    struct iovec read_vectors[] = {
        {read_part_1, sizeof(read_part_1)},
        {read_part_2, sizeof(read_part_2)},
        {read_part_3, sizeof(read_part_3)},
    };
    if (ecapture_test_readv(
            pipe_fds[0],
            read_vectors,
            (int)(sizeof(read_vectors) / sizeof(read_vectors[0]))) < 0)
        return 4;

    static const char message_part_1[] = "ECAPTURE-";
    static const char message_part_2[] = "MSGHDR-WRITE-";
    static const char message_part_3[] = "MARKER\n";
    struct iovec message_vectors[] = {
        {(void *)message_part_1, sizeof(message_part_1) - 1},
        {(void *)message_part_2, sizeof(message_part_2) - 1},
        {(void *)message_part_3, sizeof(message_part_3) - 1},
    };
    struct msghdr outgoing = {
        .msg_iov = message_vectors,
        .msg_iovlen = sizeof(message_vectors) / sizeof(message_vectors[0]),
    };
    if (ecapture_test_sendmsg(message_fds[0], &outgoing, 0) < 0)
        return 5;
    char drain[64];
    if (read(message_fds[1], drain, sizeof(drain)) < 0)
        return 6;

    static const char receive_marker[] = "ECAPTURE-MSGHDR-READ-MARKER\n";
    if (write(message_fds[0], receive_marker, sizeof(receive_marker) - 1) < 0)
        return 7;
    char message_read_part_1[9] = {};
    char message_read_part_2[13] = {};
    char message_read_part_3[32] = {};
    struct iovec message_read_vectors[] = {
        {message_read_part_1, sizeof(message_read_part_1)},
        {message_read_part_2, sizeof(message_read_part_2)},
        {message_read_part_3, sizeof(message_read_part_3)},
    };
    struct msghdr incoming = {
        .msg_iov = message_read_vectors,
        .msg_iovlen = sizeof(message_read_vectors) / sizeof(message_read_vectors[0]),
    };
    if (ecapture_test_recvmsg(message_fds[1], &incoming, 0) < 0)
        return 8;

    static const char high_part_1[] = "ECAPTURE-";
    static const char high_part_2[] = "HIGHARG-QUIC-";
    static const char high_part_3[] = "STREAM-MARKER\n";
    static const char high_ignored_tail[] = "IGNORED-TAIL";
    struct iovec high_vectors[] = {
        {(void *)high_part_1, sizeof(high_part_1) - 1},
        {(void *)high_part_2, sizeof(high_part_2) - 1},
        {(void *)high_part_3, sizeof(high_part_3) - 1},
        {(void *)high_ignored_tail, sizeof(high_ignored_tail) - 1},
    };
    ssize_t accepted_length = -1;
    if (ecapture_test_higharg_iovec(
            (void *)(uintptr_t)0x12345000, NULL, 1, NULL, NULL, 1200,
            &accepted_length, 0, 0x102030405060708LL, high_vectors,
            sizeof(high_vectors) / sizeof(high_vectors[0]), 123456789ULL) < 0)
        return 9;
    if (accepted_length != 36)
        return 10;

    close(pipe_fds[0]);
    close(pipe_fds[1]);
    close(message_fds[0]);
    close(message_fds[1]);
    close(null_fd);
    sleep(2);
    return 0;
}
