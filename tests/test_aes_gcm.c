#include "speer_internal.h"

#include "aead_aes_gcm.c"
#include "aead_iface.h"
#include "test_crypto.h"

typedef struct {
    const char *key_hex;
    const char *iv_hex;
    const char *aad_hex;
    const char *pt_hex;
    const char *ct_hex;
    const char *tag_hex;
} aes_gcm_test_vector_t;

static const aes_gcm_test_vector_t aes128_gcm_tests[] = {
    {"00000000000000000000000000000000", "000000000000000000000000", "",
     "00000000000000000000000000000000",                                                                     "0388dace60b6a392f328c2b971b2fe78",
     "ab6e47d42cec13bdf53a67b21257bddf"                                                                                                                                            },
    {"00000000000000000000000000000000", "000000000000000000000000",
     "00000000000000000000000000000000",                                 "00000000000000000000000000000000",
     "0388dace60b6a392f328c2b971b2fe78",                                                                                                         "d24e503a1bb037071c71b35d987b8657"},
};

static const aes_gcm_test_vector_t aes256_gcm_tests[] = {
    {"0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
     "", "00000000000000000000000000000000", "cea7403d4d606b6e074ec5d3baf39d18",
     "d0d1c8a799996bf0265b98b5d48ab919"                                                                            },
    {"0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
     "", "",                                 "",                                 "530f8afbc74536b9a963b4f1c4cb738b"},
};

static int run_aes_gcm_tests(const aes_gcm_test_vector_t *tests, size_t num_tests, const char *name,
                             int is_aes256) {
    for (size_t i = 0; i < num_tests; i++) {
        uint8_t key[32];
        uint8_t iv[12];
        uint8_t aad[128];
        uint8_t pt[128];
        uint8_t ct[128];
        uint8_t tag[16];
        uint8_t expected_ct[128];
        uint8_t expected_tag[16];
        uint8_t decrypted[128];
        size_t key_len = is_aes256 ? 32 : 16;
        int aad_len = hex_to_bytes(tests[i].aad_hex, aad, sizeof(aad));
        int pt_len = hex_to_bytes(tests[i].pt_hex, pt, sizeof(pt));
        int expected_ct_len = hex_to_bytes(tests[i].ct_hex, expected_ct, sizeof(expected_ct));
        const speer_aead_iface_t *aead = is_aes256 ? &speer_aead_aes256_gcm
                                                   : &speer_aead_aes128_gcm;

        if (hex_to_bytes(tests[i].key_hex, key, key_len) != (int)key_len ||
            hex_to_bytes(tests[i].iv_hex, iv, 12) != 12 || aad_len < 0 || pt_len < 0 ||
            expected_ct_len < 0 || hex_to_bytes(tests[i].tag_hex, expected_tag, 16) != 16) {
            fprintf(stderr, "%s test %zu has invalid hex\n", name, i + 1);
            return 1;
        }

        if (aead->seal(key, iv, aad, (size_t)aad_len, pt, (size_t)pt_len, ct, tag) != 0 ||
            memcmp(ct, expected_ct, (size_t)expected_ct_len) != 0 ||
            memcmp(tag, expected_tag, 16) != 0 ||
            aead->open(key, iv, aad, (size_t)aad_len, ct, (size_t)pt_len, tag, decrypted) != 0 ||
            memcmp(decrypted, pt, (size_t)pt_len) != 0) {
            fprintf(stderr, "%s test %zu failed\n", name, i + 1);
            return 1;
        }
    }

    return 0;
}

int test_aes128_gcm(void) {
    if (run_aes_gcm_tests(aes128_gcm_tests, sizeof(aes128_gcm_tests) / sizeof(aes128_gcm_tests[0]),
                          "AES-128-GCM", 0) != 0) {
        return 1;
    }

    {
        uint8_t key[16] = {0};
        uint8_t iv[12] = {0};
        uint8_t pt[16] = "test message!!";
        uint8_t ct[16];
        uint8_t tag[16];
        uint8_t decrypted[16];
        speer_aead_aes128_gcm.seal(key, iv, NULL, 0, pt, 16, ct, tag);
        ct[0] ^= 0xff;
        if (speer_aead_aes128_gcm.open(key, iv, NULL, 0, ct, 16, tag, decrypted) == 0) { return 1; }
    }

    return 0;
}

int test_aes256_gcm(void) {
    if (run_aes_gcm_tests(aes256_gcm_tests, sizeof(aes256_gcm_tests) / sizeof(aes256_gcm_tests[0]),
                          "AES-256-GCM", 1) != 0) {
        return 1;
    }

    {
        uint8_t key[32] = {0};
        uint8_t iv[12] = {0};
        uint8_t pt[32] = "Hello, AES-256-GCM test!";
        uint8_t ct[32];
        uint8_t tag[16];
        uint8_t decrypted[32];

        if (speer_aes_gcm_encrypt(ct, pt, 32, key, iv, NULL, 0, tag) != 0 ||
            speer_aes_gcm_decrypt(decrypted, ct, 32, key, iv, NULL, 0, tag) != 0 ||
            memcmp(decrypted, pt, 32) != 0) {
            return 1;
        }
    }

    return 0;
}
