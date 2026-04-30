#include "speer_internal.h"

#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "aead_iface.h"
#include "ed25519.h"

static uint64_t get_time_ns(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000000ULL / freq.QuadPart);
}

static double mb_per_sec(size_t bytes, uint64_t ns) {
    return (double)bytes * 1000.0 / (double)ns;
}

static void bench_chacha20_encrypt(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};

    uint8_t plaintext[16384];
    uint8_t ciphertext[16384];

    memset(plaintext, 0xCC, sizeof(plaintext));

    speer_chacha_ctx_t ctx;

    int iterations = 100000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_chacha_init(&ctx, key, nonce);
        speer_chacha_crypt(&ctx, ciphertext, plaintext, sizeof(plaintext));
    }
    uint64_t elapsed = get_time_ns() - start;

    size_t total_bytes = (size_t)iterations * sizeof(plaintext);
    printf("chacha20_encrypt:  %10.2f MB/s    (16KB chunks)\n", mb_per_sec(total_bytes, elapsed));
}

static void bench_sha256_throughput(void) {
    uint8_t data[8192];
    uint8_t hash[32];

    memset(data, 0xDD, sizeof(data));

    int iterations = 100000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) { speer_sha256(hash, data, sizeof(data)); }
    uint64_t elapsed = get_time_ns() - start;

    size_t total_bytes = (size_t)iterations * sizeof(data);
    printf("sha256_throughput: %10.2f MB/s    (8KB chunks)\n", mb_per_sec(total_bytes, elapsed));
}

static void bench_bulk_hash(void) {
    uint8_t data[1350];
    uint8_t hash[32];

    memset(data, 0xEE, sizeof(data));

    size_t total_transfer = 100ULL * 1024 * 1024;
    size_t blocks_needed = total_transfer / sizeof(data);

    uint64_t start = get_time_ns();
    for (size_t i = 0; i < blocks_needed; i++) { speer_sha256(hash, data, sizeof(data)); }
    uint64_t elapsed = get_time_ns() - start;

    printf("bulk_100mb_hash:   %10.2f MB/s    (simulated transfer)\n",
           mb_per_sec(total_transfer, elapsed));
    printf("                   (%.2f seconds for 100MB)\n", (double)elapsed / 1000000000.0);
}

int main(void) {
    printf("=== Throughput Benchmarks ===\n\n");

    bench_chacha20_encrypt();
    bench_sha256_throughput();
    bench_bulk_hash();

    printf("\n");
    return 0;
}
