#include "speer_internal.h"

#include "aead_iface.h"
#include "test_crypto.h"

typedef struct {
    const char *key_hex;
    const char *msg_hex;
    const char *tag_hex;
} poly1305_test_vector_t;

static const poly1305_test_vector_t poly1305_tests[] = {
    {"0000000000000000000000000000000000000000000000000000000000000000",
     "00000000000000000000000000000000",                                     "00000000000000000000000000000000"},
    {"85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
     "43727970746f6772617068696320466f72756d2052657365617263682047726f7570", "a8061dc1305136c6c22b8baf0c0127a9"},
};

static int test_poly1305_known_answers(void) {
    uint8_t key[32];
    uint8_t msg[256];
    uint8_t tag[16];
    uint8_t expected[16];
    size_t num_tests = sizeof(poly1305_tests) / sizeof(poly1305_tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        int msg_len = hex_to_bytes(poly1305_tests[i].msg_hex, msg, sizeof(msg));
        if (hex_to_bytes(poly1305_tests[i].key_hex, key, 32) != 32 || msg_len < 0 ||
            hex_to_bytes(poly1305_tests[i].tag_hex, expected, 16) != 16) {
            fprintf(stderr, "Poly1305 test %zu has invalid hex\n", i + 1);
            return 1;
        }

        speer_poly1305(tag, msg, (size_t)msg_len, key);

        if (memcmp(tag, expected, 16) != 0) {
            fprintf(stderr, "Poly1305 test %zu mismatch\n", i + 1);
            print_hex("Got     ", tag, 16);
            print_hex("Expected", expected, 16);
            return 1;
        }
    }

    return 0;
}

static int test_poly1305_behavior(void) {
    uint8_t key[32];
    uint8_t msg[256];
    uint8_t tag1[16];
    uint8_t tag2[16];

    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 256; i++) msg[i] = (uint8_t)(i + 32);

    speer_poly1305(tag1, msg, 64, key);
    speer_poly1305(tag2, msg, 64, key);
    if (memcmp(tag1, tag2, 16) != 0) return 1;

    msg[0] ^= 1;
    speer_poly1305(tag2, msg, 64, key);
    if (memcmp(tag1, tag2, 16) == 0) return 1;

    msg[0] ^= 1;
    key[0] ^= 1;
    speer_poly1305(tag2, msg, 64, key);
    if (memcmp(tag1, tag2, 16) == 0) return 1;

    for (size_t len = 0; len <= 256; len += 16) speer_poly1305(tag1, msg, len, key);
    for (size_t len = 1; len < 32; len++) speer_poly1305(tag1, msg, len, key);

    memset(key, 0xff, 32);
    speer_poly1305(tag1, msg, 32, key);

    return 0;
}

static int test_poly1305_aead_integration(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t aad[16] = {0};
    uint8_t pt[32] = "Test message for AEAD";
    uint8_t ct[32];
    uint8_t tag[16];
    uint8_t decrypted[32];

    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i + 32);

    int ret = speer_aead_chacha20_poly1305.seal(key, nonce, aad, 16, pt, 32, ct, tag);
    if (ret != 0) return 1;

    ret = speer_aead_chacha20_poly1305.open(key, nonce, aad, 16, ct, 32, tag, decrypted);
    if (ret != 0 || memcmp(decrypted, pt, 32) != 0) return 1;

    ct[0] ^= 0xff;
    ret = speer_aead_chacha20_poly1305.open(key, nonce, aad, 16, ct, 32, tag, decrypted);
    if (ret == 0) return 1;

    return 0;
}

int test_poly1305(void) {
    uint8_t key[32] = {0};
    uint8_t tag[16];
    uint8_t *long_msg;

    if (test_poly1305_known_answers() != 0) return 1;
    if (test_poly1305_behavior() != 0) return 1;
    if (test_poly1305_aead_integration() != 0) return 1;

    speer_poly1305(tag, NULL, 0, key);

    long_msg = (uint8_t *)malloc(10000);
    if (long_msg) {
        memset(long_msg, 0xab, 10000);
        speer_poly1305(tag, long_msg, 10000, key);
        free(long_msg);
    }

    return 0;
}
