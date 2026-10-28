#include <stddef.h>
#include <stdio.h>

__attribute__((noinline)) int fixture_write_ex(void* ssl, const char* buffer, size_t length, size_t* written) {
    if (length == 0) return 0; /* Failure leaves the previous output value untouched. */
    if (written) *written = length == 2 ? 0 : 7;
    return 1;
}

int main(void) {
    puts("ready");
    fflush(stdout);
    getchar();
    size_t written = 999;
    const char* data = "payload-remaining";
    fixture_write_ex((void*)0x1234, data, 0, &written);
    fixture_write_ex((void*)0x1234, data, 99, &written);
    fixture_write_ex((void*)0x1234, data, 2, &written);
    fixture_write_ex((void*)0x1234, data, 7, NULL);
    return 0;
}
