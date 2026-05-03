#include "speer_internal.h"

#include "aes.h"
#include "test_crypto.h"

typedef struct {
    const char *key_hex;
    const char *pt_hex;
    const char *ct_hex;
} aes_test_vector_t;

static const aes_test_vector_t aes128_tests[] = {
    {"000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
     "69c4e0d86a7b0430d8cdb78070b4c55a"},
    {"2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a",
     "3ad77bb40d7a3660a89ecaf32466ef97"},
    {"00000000000000000000000000000000", "00000000000000000000000000000000",
     "66e94bd4ef8a2c3b884cfa59ca342b2e"},
    {"ffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffff",
     "bcbf217cb280cf30b2517052193ab979"},
};

static int run_aes_tests(const aes_test_vector_t *tests, size_t num_tests, int key_bits,
                         const char *name) {
    for (size_t i = 0; i < num_tests; i++) {
        uint8_t key[32];
        uint8_t pt[16];
        uint8_t expected_ct[16];
        uint8_t output[16];
        speer_aes_key_t aes_key;
        size_t key_len = key_bits / 8;
        if (hex_to_bytes(tests[i].key_hex, key, (int)key_len) != (int)key_len) {
            fprintf(stderr, "%s test %zu: Invalid key hex\n", name, i + 1);
            return 1;
        }
        if (hex_to_bytes(tests[i].pt_hex, pt, 16) != 16) {
            fprintf(stderr, "%s test %zu: Invalid PT hex\n", name, i + 1);
            return 1;
        }
        if (hex_to_bytes(tests[i].ct_hex, expected_ct, 16) != 16) {
            fprintf(stderr, "%s test %zu: Invalid CT hex\n", name, i + 1);
            return 1;
        }
        speer_aes_set_encrypt_key(&aes_key, key, (size_t)key_bits);
        speer_aes_encrypt(&aes_key, pt, output);
        if (memcmp(output, expected_ct, 16) != 0) {
            fprintf(stderr, "%s test %zu: encryption mismatch:\n", name, i + 1);
            print_hex("Got     ", output, 16);
            print_hex("Expected", expected_ct, 16);
            return 1;
        }
    }
    return 0;
}

static int test_aes_ctr_mode(void) {
    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t nonce[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                         0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    uint8_t pt[32] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
                      0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
                      0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
    uint8_t expected_ct[32] = {0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68,
                               0x64, 0x99, 0x0d, 0xb6, 0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70,
                               0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff};
    uint8_t ct[32];
    speer_aes_key_t aes_key;
    speer_aes_set_encrypt_key(&aes_key, key, 128);
    speer_aes_ctr(&aes_key, nonce, ct, pt, 32);
    if (memcmp(ct, expected_ct, 32) != 0) {
        fprintf(stderr, "AES-128-CTR test failed:\n");
        print_hex("Got     ", ct, 32);
        print_hex("Expected", expected_ct, 32);
        return 1;
    }
    uint8_t decrypted[32];
    uint8_t nonce_copy[16];
    memcpy(nonce_copy, nonce, 16);
    speer_aes_ctr(&aes_key, nonce_copy, decrypted, ct, 32);
    if (memcmp(decrypted, pt, 32) != 0) {
        fprintf(stderr, "AES-128-CTR round-trip test failed:\n");
        print_hex("Got     ", decrypted, 32);
        print_hex("Expected", pt, 32);
        return 1;
    }
    return 0;
}

int test_aes(void) {
    size_t num_tests = sizeof(aes128_tests) / sizeof(aes128_tests[0]);
    if (run_aes_tests(aes128_tests, num_tests, 128, "AES-128") != 0) { return 1; }
    if (test_aes_ctr_mode() != 0) { return 1; }
    {
        uint8_t key[16] = {0};
        uint8_t nonce[16] = {0};
        uint8_t pt[20] = "Hello, World!";
        uint8_t ct[20];
        uint8_t decrypted[20];
        speer_aes_key_t aes_key;
        speer_aes_set_encrypt_key(&aes_key, key, 128);
        speer_aes_ctr(&aes_key, nonce, ct, pt, 13);
        uint8_t nonce_copy[16] = {0};
        speer_aes_ctr(&aes_key, nonce_copy, decrypted, ct, 13);
        if (memcmp(decrypted, pt, 13) != 0) {
            fprintf(stderr, "AES-CTR partial block test failed\n");
            return 1;
        }
    }
    return 0;
}
