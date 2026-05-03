#include "speer_internal.h"

#include "aead_iface.h"
#include "test_crypto.h"

typedef struct {
    const char *key_hex;
    const char *nonce_hex;
    const char *aad_hex;
    const char *pt_hex;
    const char *ct_hex;
    const char *tag_hex;
} chacha20_poly1305_test_vector_t;

static const chacha20_poly1305_test_vector_t chacha20_poly1305_tests[] = {
    {"1c9240a5eb55d38af333888604f6b5b0debb63c77a5a27278eb590ba17b94e08", "000000000102030405060708",
     "fbafc5c0bf26d6a03e73917b860dc08b", "4a656666", "5ca94343",
     "fbbc91c9f823e4890d1509971387ee06"},
};

static int test_chacha20_core(void) {
    speer_chacha_ctx_t ctx;
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t block[64];
    uint8_t expected_start[] = {0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
                                0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28};

    memset(key, 0, 32);
    memset(nonce, 0, 12);
    speer_chacha_init(&ctx, key, nonce);
    speer_chacha_block(&ctx, block);

    if (memcmp(block, expected_start, 16) != 0) {
        fprintf(stderr, "ChaCha20 core test failed\n");
        print_hex("Got     ", block, 16);
        print_hex("Expected", expected_start, 16);
        return 1;
    }

    return 0;
}

int test_chacha20_poly1305(void) {
    size_t num_tests = sizeof(chacha20_poly1305_tests) / sizeof(chacha20_poly1305_tests[0]);

    if (test_chacha20_core() != 0) return 1;

    for (size_t i = 0; i < num_tests; i++) {
        uint8_t key[32];
        uint8_t nonce[12];
        uint8_t aad[64];
        uint8_t pt[128];
        uint8_t ct[128];
        uint8_t tag[16];
        uint8_t expected_ct[128];
        uint8_t expected_tag[16];
        uint8_t decrypted[128];
        int aad_len = hex_to_bytes(chacha20_poly1305_tests[i].aad_hex, aad, sizeof(aad));
        int pt_len = hex_to_bytes(chacha20_poly1305_tests[i].pt_hex, pt, sizeof(pt));
        int expected_ct_len = hex_to_bytes(chacha20_poly1305_tests[i].ct_hex, expected_ct,
                                           sizeof(expected_ct));

        if (hex_to_bytes(chacha20_poly1305_tests[i].key_hex, key, 32) != 32 ||
            hex_to_bytes(chacha20_poly1305_tests[i].nonce_hex, nonce, 12) != 12 || aad_len < 0 ||
            pt_len < 0 || expected_ct_len < 0 ||
            hex_to_bytes(chacha20_poly1305_tests[i].tag_hex, expected_tag, 16) != 16) {
            fprintf(stderr, "ChaCha20-Poly1305 test %zu has invalid hex\n", i + 1);
            return 1;
        }

        if (speer_aead_chacha20_poly1305.seal(key, nonce, aad, (size_t)aad_len, pt, (size_t)pt_len,
                                              ct, tag) != 0 ||
            memcmp(ct, expected_ct, (size_t)expected_ct_len) != 0 ||
            memcmp(tag, expected_tag, 16) != 0 ||
            speer_aead_chacha20_poly1305.open(key, nonce, aad, (size_t)aad_len, ct, (size_t)pt_len,
                                              tag, decrypted) != 0 ||
            memcmp(decrypted, pt, (size_t)pt_len) != 0) {
            fprintf(stderr, "ChaCha20-Poly1305 test %zu failed\n", i + 1);
            return 1;
        }
    }

    {
        uint8_t key[32] = {0};
        uint8_t nonce[12] = {0};
        uint8_t pt[16] = "test message";
        uint8_t ct[16];
        uint8_t tag[16];
        uint8_t decrypted[16];
        speer_aead_chacha20_poly1305.seal(key, nonce, NULL, 0, pt, 16, ct, tag);
        ct[0] ^= 0xff;
        if (speer_aead_chacha20_poly1305.open(key, nonce, NULL, 0, ct, 16, tag, decrypted) == 0) {
            fprintf(stderr, "ChaCha20-Poly1305 tamper detection failed\n");
            return 1;
        }
    }

    return 0;
}
