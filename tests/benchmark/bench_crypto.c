#include "speer_internal.h"

#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "aead_iface.h"
#include "ed25519.h"

extern const speer_aead_iface_t speer_aead_aes128_gcm;
extern const speer_aead_iface_t speer_aead_aes256_gcm;

static uint64_t get_time_ns(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000000ULL / freq.QuadPart);
}

static double mb_per_sec(size_t bytes, uint64_t ns) {
    return (double)bytes * 1000.0 / (double)ns;
}

static void bench_ed25519_sign(void) {
    uint8_t pk[32], sk[32], seed[32] = {0};
    speer_ed25519_keypair(pk, sk, seed);

    uint8_t msg[64] = {0};
    uint8_t sig[64];

    int iterations = 10000;
    uint64_t start = get_time_ns();

    for (int i = 0; i < iterations; i++) { speer_ed25519_sign(sig, msg, sizeof(msg), pk, sk); }

    uint64_t elapsed = get_time_ns() - start;
    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;

    printf("ed25519_sign:      %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_ed25519_verify(void) {
    uint8_t pk[32], sk[32], seed[32] = {0};
    speer_ed25519_keypair(pk, sk, seed);

    uint8_t msg[64] = {0};
    uint8_t sig[64];
    speer_ed25519_sign(sig, msg, sizeof(msg), pk, sk);

    int iterations = 10000;
    uint64_t start = get_time_ns();

    for (int i = 0; i < iterations; i++) { speer_ed25519_verify(sig, msg, sizeof(msg), pk); }

    uint64_t elapsed = get_time_ns() - start;
    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;

    printf("ed25519_verify:    %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_chacha20_poly1305(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t aad[13] = {"header_data"};

    uint8_t plaintext[16384];
    uint8_t ciphertext[16384];
    uint8_t tag[16];

    memset(plaintext, 0xAA, sizeof(plaintext));

    speer_chacha_ctx_t ctx;

    int iterations = 10000;
    size_t msg_size = 1024;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_chacha_init(&ctx, key, nonce);
        speer_chacha_crypt(&ctx, ciphertext, plaintext, msg_size);
    }
    uint64_t elapsed = get_time_ns() - start;

    printf("chacha20_encrypt:  %10.2f MB/s    (%llu ns/op for %zu bytes)\n",
           mb_per_sec(msg_size * iterations, elapsed), elapsed / iterations, msg_size);
}

static void bench_aes128_gcm(void) {
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[13] = {"header_data"};

    uint8_t plaintext[16384];
    uint8_t ciphertext[16384];
    uint8_t tag[16];

    memset(plaintext, 0xAA, sizeof(plaintext));

    int iterations = 10000;
    size_t msg_size = 1024;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_aead_aes128_gcm.seal(key, iv, aad, sizeof(aad), plaintext, msg_size, ciphertext, tag);
    }
    uint64_t elapsed = get_time_ns() - start;

    printf("aes128_gcm_seal:   %10.2f MB/s    (%llu ns/op for %zu bytes)\n",
           mb_per_sec(msg_size * iterations, elapsed), elapsed / iterations, msg_size);
}

static void bench_aes256_gcm(void) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[13] = {"header_data"};

    uint8_t plaintext[16384];
    uint8_t ciphertext[16384];
    uint8_t tag[16];

    memset(plaintext, 0xAA, sizeof(plaintext));

    int iterations = 10000;
    size_t msg_size = 1024;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_aead_aes256_gcm.seal(key, iv, aad, sizeof(aad), plaintext, msg_size, ciphertext, tag);
    }
    uint64_t elapsed = get_time_ns() - start;

    printf("aes256_gcm_seal:   %10.2f MB/s    (%llu ns/op for %zu bytes)\n",
           mb_per_sec(msg_size * iterations, elapsed), elapsed / iterations, msg_size);
}

static void bench_sha256(void) {
    uint8_t data[8192];
    uint8_t hash[32];

    memset(data, 0xBB, sizeof(data));

    int iterations = 100000;
    size_t data_size = 1024;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) { speer_sha256(hash, data, data_size); }
    uint64_t elapsed = get_time_ns() - start;

    printf("sha256:            %10.2f MB/s    (%llu ns/op for %zu bytes)\n",
           mb_per_sec(data_size * iterations, elapsed), elapsed / iterations, data_size);
}

static void bench_x25519(void) {
    uint8_t shared[32];
    uint8_t scalar[32] = {0};
    uint8_t point[32] = {9};

    int iterations = 5000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_x25519(shared, scalar, point);
        scalar[0]++;
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("x25519_scalarmult: %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

int main(void) {
    printf("=== Crypto Benchmarks ===\n");
    printf("(results are approximate and depend on CPU, compiler, and optimization)\n\n");

    bench_ed25519_sign();
    bench_ed25519_verify();
    bench_chacha20_poly1305();
    bench_aes128_gcm();
    bench_aes256_gcm();
    bench_sha256();
    bench_x25519();

    printf("\n");
    return 0;
}
