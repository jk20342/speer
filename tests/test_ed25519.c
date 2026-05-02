#include "speer_internal.h"

#include "ed25519.h"
#include "test_crypto.h"

typedef struct {
    const char *seed_hex;
    const char *public_key_hex;
    const char *message_hex;
    const char *signature_hex;
} ed25519_test_vector_t;

static const ed25519_test_vector_t ed25519_tests[] = {
    {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b"
     "46bd25bf5f0595bbe24655141438e7a100b"},
};

int test_ed25519(void) {
    size_t num_tests = sizeof(ed25519_tests) / sizeof(ed25519_tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        uint8_t seed[32];
        uint8_t public_key[32];
        uint8_t private_key[32];
        uint8_t message[128];
        uint8_t signature[64];
        uint8_t expected_pk[32];
        uint8_t expected_sig[64];
        int msg_len = hex_to_bytes(ed25519_tests[i].message_hex, message, sizeof(message));

        if (hex_to_bytes(ed25519_tests[i].seed_hex, seed, 32) != 32 ||
            hex_to_bytes(ed25519_tests[i].public_key_hex, expected_pk, 32) != 32 ||
            hex_to_bytes(ed25519_tests[i].signature_hex, expected_sig, 64) != 64 || msg_len < 0) {
            fprintf(stderr, "Ed25519 test %zu has invalid hex\n", i + 1);
            return 1;
        }

        speer_ed25519_keypair(public_key, private_key, seed);
        speer_ed25519_sign(signature, message, (size_t)msg_len, public_key, private_key);

        if (memcmp(public_key, expected_pk, 32) != 0 || memcmp(signature, expected_sig, 64) != 0 ||
            speer_ed25519_verify(signature, message, (size_t)msg_len, public_key) != 0) {
            fprintf(stderr, "Ed25519 test %zu failed\n", i + 1);
            return 1;
        }
    }

    {
        uint8_t seed[32] = {0};
        uint8_t public_key[32];
        uint8_t private_key[32];
        uint8_t message[32] = "test message for ed25519";
        uint8_t wrong_message[32] = "wrong message for ed25519";
        uint8_t signature[64];

        speer_ed25519_keypair(public_key, private_key, seed);
        speer_ed25519_sign(signature, message, 32, public_key, private_key);

        if (speer_ed25519_verify(signature, wrong_message, 32, public_key) == 0) return 1;

        signature[0] ^= 0xff;
        if (speer_ed25519_verify(signature, message, 32, public_key) == 0) return 1;
    }

    return 0;
}
