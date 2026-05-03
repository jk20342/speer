#ifndef TEST_CRYPTO_H
#define TEST_CRYPTO_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#define TEST_ASSERT(condition)                                                                  \
    do {                                                                                        \
        if (!(condition)) {                                                                     \
            fprintf(stderr, "ASSERTION FAILED: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
            return 1;                                                                           \
        }                                                                                       \
    } while (0)

#define TEST_ASSERT_EQ(a, b)       TEST_ASSERT((a) == (b))
#define TEST_ASSERT_NE(a, b)       TEST_ASSERT((a) != (b))
#define TEST_ASSERT_MEMEQ(a, b, n) TEST_ASSERT(memcmp((a), (b), (n)) == 0)

int test_sha256(void);
int test_sha384(void);
int test_sha512(void);
int test_chacha20_poly1305(void);
int test_aes128_gcm(void);
int test_aes256_gcm(void);
int test_aes(void);
int test_ed25519(void);
int test_x25519(void);
int test_hkdf(void);
int test_hmac(void);
int test_poly1305(void);

static inline int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) { return -1; }
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1) { return -1; }
        out[i] = (uint8_t)byte;
    }
    return (int)(hex_len / 2);
}

static inline void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) { printf("%02x", data[i]); }
    printf("\n");
}

#endif
