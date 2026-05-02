#include "speer_internal.h"

#include "test_crypto.h"

typedef struct {
    const char *scalar_hex;
    const char *u_hex;
    const char *out_hex;
} x25519_test_vector_t;

static const x25519_test_vector_t x25519_tests[] = {
    {"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
    {"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"},
};

static int test_x25519_dh_exchange(void) {
    uint8_t alice_private[32];
    uint8_t alice_public[32];
    uint8_t bob_private[32];
    uint8_t bob_public[32];
    uint8_t alice_shared[32];
    uint8_t bob_shared[32];
    uint8_t expected_alice_public[32];
    uint8_t expected_bob_public[32];
    uint8_t expected_shared[32];

    hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice_private,
                 32);
    hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bob_private,
                 32);
    hex_to_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                 expected_alice_public, 32);
    hex_to_bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                 expected_bob_public, 32);
    hex_to_bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                 expected_shared, 32);

    speer_x25519_base(alice_public, alice_private);
    speer_x25519_base(bob_public, bob_private);

    if (memcmp(alice_public, expected_alice_public, 32) != 0) {
        fprintf(stderr, "X25519 DH Alice public key mismatch\n");
        print_hex("Got     ", alice_public, 32);
        print_hex("Expected", expected_alice_public, 32);
        return 1;
    }
    if (memcmp(bob_public, expected_bob_public, 32) != 0) {
        fprintf(stderr, "X25519 DH Bob public key mismatch\n");
        print_hex("Got     ", bob_public, 32);
        print_hex("Expected", expected_bob_public, 32);
        return 1;
    }

    speer_x25519(alice_shared, alice_private, bob_public);
    speer_x25519(bob_shared, bob_private, alice_public);

    if (memcmp(alice_shared, bob_shared, 32) != 0) {
        fprintf(stderr, "X25519 shared secrets differ\n");
        return 1;
    }
    if (memcmp(alice_shared, expected_shared, 32) != 0) {
        fprintf(stderr, "X25519 shared secret mismatch\n");
        print_hex("Got     ", alice_shared, 32);
        print_hex("Expected", expected_shared, 32);
        return 1;
    }

    return 0;
}

int test_x25519(void) {
    uint8_t scalar[32];
    uint8_t u[32];
    uint8_t out[32];
    uint8_t expected[32];
    size_t num_tests = sizeof(x25519_tests) / sizeof(x25519_tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        if (hex_to_bytes(x25519_tests[i].scalar_hex, scalar, 32) != 32 ||
            hex_to_bytes(x25519_tests[i].u_hex, u, 32) != 32 ||
            hex_to_bytes(x25519_tests[i].out_hex, expected, 32) != 32) {
            fprintf(stderr, "X25519 test %zu has invalid hex\n", i + 1);
            return 1;
        }

        speer_x25519(out, scalar, u);

        if (memcmp(out, expected, 32) != 0) {
            fprintf(stderr, "X25519 test %zu mismatch\n", i + 1);
            print_hex("Got     ", out, 32);
            print_hex("Expected", expected, 32);
            return 1;
        }
    }

    return test_x25519_dh_exchange();
}
