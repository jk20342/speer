#include "speer_internal.h"

#include "sha2.c"
#include "test_crypto.h"

typedef struct {
    const char *msg;
    const char *expected;
} sha256_test_vector_t;

static const sha256_test_vector_t sha256_tests[] = {
    {"abc",                                                      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"",                                                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"                                                            },
    {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnop"
     "qrsmnopqrstnopqrstu",                                 "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
    {NULL,                                                       "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
};

int test_sha256(void) {
    uint8_t result[32];
    uint8_t expected[32];
    size_t num_tests = sizeof(sha256_tests) / sizeof(sha256_tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        if (sha256_tests[i].msg == NULL) {
            uint8_t *million_as = (uint8_t *)malloc(1000000);
            if (!million_as) return 1;
            memset(million_as, 'a', 1000000);
            speer_sha256(result, million_as, 1000000);
            free(million_as);
        } else {
            size_t msg_len = strlen(sha256_tests[i].msg);
            speer_sha256(result, (const uint8_t *)sha256_tests[i].msg, msg_len);
        }
        if (hex_to_bytes(sha256_tests[i].expected, expected, 32) != 32) {
            fprintf(stderr, "Invalid expected hex for test %zu\n", i + 1);
            return 1;
        }
        if (memcmp(result, expected, 32) != 0) {
            fprintf(stderr, "SHA-256 test %zu failed:\n", i + 1);
            print_hex("Got     ", result, 32);
            print_hex("Expected", expected, 32);
            return 1;
        }
    }

    sha256_ctx_t ctx;
    uint8_t incremental_result[32];
    speer_sha256_init(&ctx);
    speer_sha256_update(&ctx, (const uint8_t *)"a", 1);
    speer_sha256_update(&ctx, (const uint8_t *)"b", 1);
    speer_sha256_update(&ctx, (const uint8_t *)"c", 1);
    speer_sha256_final(&ctx, incremental_result);
    if (hex_to_bytes(sha256_tests[0].expected, expected, 32) != 32) { return 1; }
    if (memcmp(incremental_result, expected, 32) != 0) {
        fprintf(stderr, "SHA-256 incremental test failed\n");
        return 1;
    }

    return 0;
}

typedef struct {
    const char *msg;
    const char *expected;
} sha384_test_vector_t;

static const sha384_test_vector_t sha384_tests[] = {
    {"abc",                      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baec"
            "a134c825a7"       },
    {"",                         "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14"
         "898b95b"                },
    {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnop"
     "qrsmnopqrstnopqrstu", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746"
     "039"},
    {NULL,                       "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd"
           "87f3d8985"          },
};

int test_sha384(void) {
    uint8_t result[48];
    uint8_t expected[48];
    size_t num_tests = sizeof(sha384_tests) / sizeof(sha384_tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        if (sha384_tests[i].msg == NULL) {
            uint8_t *million_as = (uint8_t *)malloc(1000000);
            if (!million_as) return 1;
            memset(million_as, 'a', 1000000);
            speer_sha384(result, million_as, 1000000);
            free(million_as);
        } else {
            size_t msg_len = strlen(sha384_tests[i].msg);
            speer_sha384(result, (const uint8_t *)sha384_tests[i].msg, msg_len);
        }
        if (hex_to_bytes(sha384_tests[i].expected, expected, 48) != 48) {
            fprintf(stderr, "Invalid expected hex for SHA-384 test %zu\n", i + 1);
            return 1;
        }
        if (memcmp(result, expected, 48) != 0) {
            fprintf(stderr, "SHA-384 test %zu failed:\n", i + 1);
            print_hex("Got     ", result, 48);
            print_hex("Expected", expected, 48);
            return 1;
        }
    }

    sha512_ctx_t ctx;
    uint8_t incremental_result[48];
    speer_sha384_init(&ctx);
    speer_sha512_update(&ctx, (const uint8_t *)"a", 1);
    speer_sha512_update(&ctx, (const uint8_t *)"b", 1);
    speer_sha512_update(&ctx, (const uint8_t *)"c", 1);
    speer_sha512_final(&ctx, incremental_result);
    if (hex_to_bytes(sha384_tests[0].expected, expected, 48) != 48) { return 1; }
    if (memcmp(incremental_result, expected, 48) != 0) {
        fprintf(stderr, "SHA-384 incremental test failed\n");
        return 1;
    }

    return 0;
}

typedef struct {
    const char *msg;
    const char *expected;
} sha512_test_vector_t;

static const sha512_test_vector_t sha512_tests[] = {
    {"abc",                                                      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c"
            "23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"       },
    {"",                                                         "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d28"
         "77eec2f63b931bd47417a81a538327af927da3e"                },
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789"
     "ca031ad85c7a71dd70354ec631238ca3445"                                },
    {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnop"
     "qrsmnopqrstnopqrstu",                                 "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b54"
     "33ac7d329eeb6dd26545e96e55b874be909"},
    {NULL,                                                       "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432"
           "ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"          },
};

int test_sha512(void) {
    uint8_t result[64];
    uint8_t expected[64];
    size_t num_tests = sizeof(sha512_tests) / sizeof(sha512_tests[0]);

    for (size_t i = 0; i < num_tests; i++) {
        if (sha512_tests[i].msg == NULL) {
            uint8_t *million_as = (uint8_t *)malloc(1000000);
            if (!million_as) return 1;
            memset(million_as, 'a', 1000000);
            speer_sha512(result, million_as, 1000000);
            free(million_as);
        } else {
            size_t msg_len = strlen(sha512_tests[i].msg);
            speer_sha512(result, (const uint8_t *)sha512_tests[i].msg, msg_len);
        }
        if (hex_to_bytes(sha512_tests[i].expected, expected, 64) != 64) {
            fprintf(stderr, "Invalid expected hex for SHA-512 test %zu\n", i + 1);
            return 1;
        }
        if (memcmp(result, expected, 64) != 0) {
            fprintf(stderr, "SHA-512 test %zu failed:\n", i + 1);
            print_hex("Got     ", result, 64);
            print_hex("Expected", expected, 64);
            return 1;
        }
    }

    sha512_ctx_t ctx;
    uint8_t incremental_result[64];
    speer_sha512_init(&ctx);
    speer_sha512_update(&ctx, (const uint8_t *)"a", 1);
    speer_sha512_update(&ctx, (const uint8_t *)"b", 1);
    speer_sha512_update(&ctx, (const uint8_t *)"c", 1);
    speer_sha512_final(&ctx, incremental_result);
    if (hex_to_bytes(sha512_tests[0].expected, expected, 64) != 64) { return 1; }
    if (memcmp(incremental_result, expected, 64) != 0) {
        fprintf(stderr, "SHA-512 incremental test failed\n");
        return 1;
    }

    return 0;
}
