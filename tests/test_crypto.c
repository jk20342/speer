#include "test_crypto.h"

int main(void) {
    int failed = 0;
    int total = 0;

#define RUN_TEST(name)                   \
    do {                                 \
        total++;                         \
        printf("Running " #name "... "); \
        fflush(stdout);                  \
        if (name() == 0) {               \
            printf("PASSED\n");          \
        } else {                         \
            printf("FAILED\n");          \
            failed++;                    \
        }                                \
    } while (0)

    RUN_TEST(test_sha256);
    RUN_TEST(test_sha384);
    RUN_TEST(test_sha512);
    RUN_TEST(test_chacha20_poly1305);
    RUN_TEST(test_aes128_gcm);
    RUN_TEST(test_aes256_gcm);
    RUN_TEST(test_aes);
    RUN_TEST(test_ed25519);
    RUN_TEST(test_x25519);
    RUN_TEST(test_hkdf);
    RUN_TEST(test_hmac);
    RUN_TEST(test_poly1305);

#undef RUN_TEST

    printf("Results: %d passed, %d failed out of %d tests\n", total - failed, failed, total);

    return failed > 0 ? 1 : 0;
}
