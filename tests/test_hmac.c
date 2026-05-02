#include "speer_internal.h"

#include "hash_iface.h"
#include "test_crypto.h"

typedef struct {
    const char *key_hex;
    const char *data_hex;
    const char *mac_hex;
} hmac_sha256_test_vector_t;

static const hmac_sha256_test_vector_t hmac_sha256_tests[] = {
    {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",           "4869205468657265",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"                                                                                                                  },
    {"4a656665",                                           "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"                                                                                                                  },
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
     "ddddddd",                                                                                                        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"},
    {"0102030405060708090a0b0c0d0e0f10111213141516171819",
     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdc"
     "dcdcdcd",                                                                                                        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"},
};

int test_hmac(void) {
    uint8_t key[256];
    uint8_t data[256];
    uint8_t mac[64];
    uint8_t mac2[64];
    uint8_t expected[64];
    size_t num_tests = sizeof(hmac_sha256_tests) / sizeof(hmac_sha256_tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        int key_len = hex_to_bytes(hmac_sha256_tests[i].key_hex, key, sizeof(key));
        int data_len = hex_to_bytes(hmac_sha256_tests[i].data_hex, data, sizeof(data));

        if (key_len < 0 || data_len < 0 ||
            hex_to_bytes(hmac_sha256_tests[i].mac_hex, expected, 32) != 32) {
            fprintf(stderr, "HMAC-SHA256 test %zu has invalid hex\n", i + 1);
            return 1;
        }

        speer_hmac(&speer_hash_sha256, mac, key, (size_t)key_len, data, (size_t)data_len);

        if (memcmp(mac, expected, 32) != 0) {
            fprintf(stderr, "HMAC-SHA256 test %zu mismatch\n", i + 1);
            print_hex("Got     ", mac, 32);
            print_hex("Expected", expected, 32);
            return 1;
        }
    }

    memset(key, 0, sizeof(key));
    memset(data, 0, sizeof(data));
    speer_hmac(&speer_hash_sha256, mac, key, 64, data, 0);
    speer_hmac(&speer_hash_sha256, mac2, key, 64, data, 0);
    if (memcmp(mac, mac2, 32) != 0) return 1;

    data[0] = 1;
    speer_hmac(&speer_hash_sha256, mac2, key, 64, data, 64);
    if (memcmp(mac, mac2, 32) == 0) return 1;

    speer_hmac(&speer_hash_sha384, mac, key, 128, data, 128);
    speer_hmac(&speer_hash_sha512, mac, key, 128, data, 128);
    speer_hmac(&speer_hash_sha256, mac, NULL, 0, data, 32);
    speer_hmac(&speer_hash_sha256, mac, key, 32, NULL, 0);
    speer_hmac(&speer_hash_sha256, mac, NULL, 0, NULL, 0);

    for (int i = 0; i < 256; i++) key[i] = (uint8_t)i;
    speer_hmac(&speer_hash_sha256, mac, key, 256, data, 32);

    return 0;
}
