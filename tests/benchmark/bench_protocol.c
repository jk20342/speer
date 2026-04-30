#include "speer_internal.h"

#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "multiaddr.h"
#include "peer_id.h"
#include "yamux.h"

static uint64_t get_time_ns(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000000ULL / freq.QuadPart);
}

static int dummy_send(void *user, const uint8_t *data, size_t len) {
    (void)user;
    (void)data;
    (void)len;
    return 0;
}

static int dummy_recv(void *user, uint8_t *buf, size_t cap, size_t *out_n) {
    (void)user;
    (void)buf;
    (void)cap;
    *out_n = 0;
    return 0;
}

static void bench_peer_id_encode(void) {
    uint8_t pubkey[32] = {0};
    for (int i = 0; i < 32; i++) pubkey[i] = i + 1;

    uint8_t pubkey_proto[256];
    size_t pubkey_proto_len;
    speer_libp2p_pubkey_proto_encode(pubkey_proto, sizeof(pubkey_proto), SPEER_LIBP2P_KEY_ED25519,
                                     pubkey, 32, &pubkey_proto_len);

    uint8_t peer_id[64];
    size_t peer_id_len;

    int iterations = 100000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_peer_id_from_pubkey_bytes(peer_id, sizeof(peer_id), pubkey_proto, pubkey_proto_len,
                                        &peer_id_len);
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("peer_id_encode:    %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_peer_id_to_b58(void) {
    uint8_t pubkey[32] = {0};
    for (int i = 0; i < 32; i++) pubkey[i] = i + 1;

    uint8_t pubkey_proto[256];
    size_t pubkey_proto_len;
    speer_libp2p_pubkey_proto_encode(pubkey_proto, sizeof(pubkey_proto), SPEER_LIBP2P_KEY_ED25519,
                                     pubkey, 32, &pubkey_proto_len);

    uint8_t peer_id[64];
    size_t peer_id_len;
    speer_peer_id_from_pubkey_bytes(peer_id, sizeof(peer_id), pubkey_proto, pubkey_proto_len,
                                    &peer_id_len);

    char b58[128];

    int iterations = 100000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_peer_id_to_b58(b58, sizeof(b58), peer_id, peer_id_len);
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("peer_id_to_b58:    %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_yamux_hdr_pack(void) {
    speer_yamux_hdr_t hdr = {
        .version = 0,
        .type = YAMUX_TYPE_DATA,
        .flags = 0,
        .stream_id = 1,
        .length = 1024,
    };

    uint8_t buf[12];

    int iterations = 100000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_yamux_hdr_pack(buf, &hdr);
        hdr.stream_id++;
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("yamux_hdr_pack:    %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_yamux_hdr_unpack(void) {
    uint8_t buf[] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00};
    speer_yamux_hdr_t hdr;

    int iterations = 100000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) { speer_yamux_hdr_unpack(&hdr, buf); }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("yamux_hdr_unpack:  %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_yamux_session(void) {
    speer_yamux_session_t mux;
    speer_yamux_init(&mux, 1, dummy_send, dummy_recv, NULL);

    int iterations = 50000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_yamux_stream_t *st = speer_yamux_open_stream(&mux);
        if (st) {
            uint8_t data[256] = {0};
            speer_yamux_stream_write(&mux, st, data, sizeof(data));
            speer_yamux_stream_close(&mux, st);
        }
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("yamux_stream_open: %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);

    speer_yamux_close(&mux);
}

int main(void) {
    printf("=== Protocol Benchmarks ===\n\n");

    bench_peer_id_encode();
    bench_peer_id_to_b58();
    bench_yamux_hdr_pack();
    bench_yamux_hdr_unpack();
    bench_yamux_session();

    printf("\n");
    return 0;
}
