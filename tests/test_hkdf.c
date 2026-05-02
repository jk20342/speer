#include "speer_internal.h"

#include "hash_iface.h"
#include "test_crypto.h"

typedef struct {
    const char *salt_hex;
    const char *ikm_hex;
    const char *info_hex;
    size_t okm_len;
    const char *prk_hex;
    const char *okm_hex;
} hkdf_test_vector_t;

static const hkdf_test_vector_t hkdf_sha256_tests[] = {
    {"000102030405060708090a0b0c",            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
     "f0f1f2f3f4f5f6f7f8f9",                                                                                                  42, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"        },
    {"606162636465666768696a6b6c6d6e6f"
     "707172737475767778797a7b7c7d7e7f"
     "808182838485868788898a8b8c8d8e8f"
     "909192939495969798999a9b9c9d9e9f"
     "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "000102030405060708090a0b0c0d0e0f"
     "101112131415161718191a1b1c1d1e1f"
     "202122232425262728292a2b2c2d2e2f"
     "303132333435363738393a3b3c3d3e3f"
     "404142434445464748494a4b4c4d4e4f",         "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
     "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
     "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
     "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
     "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", 82, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
     "b11e398dc80327a1c8e7f78c596a4934"
     "4f012eda2d4efad8a050cc4c19afa97c"
     "59045a99cac7827271cb41c65e590e09"
     "da3275600c2f09b8367793a9aca3db71"
     "cc30c58179ec3e87c14c01d5c1f3434f1d87"                                                        },
    {"",                                      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "",                             42,
     "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",                                                                                                                              "8da4e775a563c18f715f802a063c5a31"
     "b8a11f5c5ee1879ec3454e5f3c738d2d"
     "9d201395faa4b61a96c8"},
};

static int test_hkdf_expand_label(void) {
    uint8_t secret[32] = {0};
    uint8_t out[32];
    uint8_t out2[32];
    uint8_t out3[32];

    speer_hkdf_expand_label(&speer_hash_sha256, out, 32, secret, 32, "test", NULL, 0);
    speer_hkdf_expand_label(&speer_hash_sha256, out2, 32, secret, 32, "test", NULL, 0);
    speer_hkdf_expand_label(&speer_hash_sha256, out3, 32, secret, 32, "different", NULL, 0);

    if (memcmp(out, out2, 32) != 0 || memcmp(out, out3, 32) == 0) {
        fprintf(stderr, "HKDF expand label test failed\n");
        return 1;
    }

    return 0;
}

int test_hkdf(void) {
    uint8_t salt[256];
    uint8_t ikm[256];
    uint8_t info[256];
    uint8_t prk[64];
    uint8_t okm[128];
    uint8_t okm2[128];
    uint8_t expected_prk[64];
    uint8_t expected_okm[128];
    size_t num_tests = sizeof(hkdf_sha256_tests) / sizeof(hkdf_sha256_tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        int salt_len_i = hex_to_bytes(hkdf_sha256_tests[i].salt_hex, salt, sizeof(salt));
        int ikm_len_i = hex_to_bytes(hkdf_sha256_tests[i].ikm_hex, ikm, sizeof(ikm));
        int info_len_i = hex_to_bytes(hkdf_sha256_tests[i].info_hex, info, sizeof(info));

        if (salt_len_i < 0 || ikm_len_i < 0 || info_len_i < 0 ||
            hex_to_bytes(hkdf_sha256_tests[i].prk_hex, expected_prk, 32) != 32 ||
            hex_to_bytes(hkdf_sha256_tests[i].okm_hex, expected_okm,
                         hkdf_sha256_tests[i].okm_len) != (int)hkdf_sha256_tests[i].okm_len) {
            fprintf(stderr, "HKDF test %zu has invalid hex\n", i + 1);
            return 1;
        }

        speer_hkdf2_extract(&speer_hash_sha256, prk, salt, (size_t)salt_len_i, ikm,
                            (size_t)ikm_len_i);
        speer_hkdf2_expand(&speer_hash_sha256, okm, hkdf_sha256_tests[i].okm_len, prk, 32, info,
                           (size_t)info_len_i);
        speer_hkdf2(&speer_hash_sha256, okm2, hkdf_sha256_tests[i].okm_len, salt,
                    (size_t)salt_len_i, ikm, (size_t)ikm_len_i, info, (size_t)info_len_i);

        if (memcmp(prk, expected_prk, 32) != 0 ||
            memcmp(okm, expected_okm, hkdf_sha256_tests[i].okm_len) != 0 ||
            memcmp(okm2, expected_okm, hkdf_sha256_tests[i].okm_len) != 0) {
            fprintf(stderr, "HKDF test %zu mismatch\n", i + 1);
            return 1;
        }
    }

    if (test_hkdf_expand_label() != 0) return 1;

    speer_hkdf2(&speer_hash_sha384, okm, 48, salt, 0, ikm, 0, info, 0);
    speer_hkdf2(&speer_hash_sha512, okm, 48, salt, 0, ikm, 0, info, 0);

    return 0;
}
