#include "speer_internal.h"

#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "length_prefix.h"
#include "protobuf.h"
#include "varint.h"

static uint64_t get_time_ns(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000000ULL / freq.QuadPart);
}

static void bench_varint_encode(void) {
    uint8_t buf[16];

    int iterations = 1000000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_uvarint_encode(buf, sizeof(buf), (uint64_t)i * 123456789);
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("varint_encode:     %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_varint_decode(void) {
    uint8_t buf[16] = {0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01};
    uint64_t val;

    int iterations = 1000000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) { speer_uvarint_decode(buf, sizeof(buf), &val); }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("varint_decode:     %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_lp_write(void) {
    uint8_t buf[1024];
    size_t written;
    uint8_t payload[512] = {0};

    int iterations = 1000000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_lp_uvar_write(buf, sizeof(buf), payload, sizeof(payload), &written);
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("lp_write:          %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_lp_read(void) {
    uint8_t buf[1024] = {0x80, 0x04, 0x00, 0x00};
    memcpy(buf + 4, buf + 4, 512);
    const uint8_t *payload;
    size_t payload_len;
    size_t consumed;

    int iterations = 1000000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_lp_uvar_read(buf, sizeof(buf), &payload, &payload_len, &consumed);
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("lp_read:           %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_pb_encode(void) {
    uint8_t buf[1024];
    speer_pb_writer_t w;

    int iterations = 500000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_pb_writer_init(&w, buf, sizeof(buf));
        speer_pb_write_bytes_field(&w, 1, (uint8_t *)"test", 4);
        speer_pb_write_string_field(&w, 2, "hello");
        speer_pb_write_int64_field(&w, 3, (uint64_t)i);
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("pb_encode_simple:  %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

static void bench_pb_decode(void) {
    uint8_t buf[64] = {0x0a, 0x04, 't', 'e', 's', 't',  0x12, 0x05,
                       'h',  'e',  'l', 'l', 'o', 0x18, 0x7b};
    speer_pb_reader_t r;
    uint32_t field, wire;
    uint64_t val;

    int iterations = 500000;

    uint64_t start = get_time_ns();
    for (int i = 0; i < iterations; i++) {
        speer_pb_reader_init(&r, buf, sizeof(buf));
        while (speer_pb_read_tag(&r, &field, &wire) == 0) {
            if (wire == 0) {
                speer_pb_read_varint(&r, &val);
            } else if (wire == 2) {
                const uint8_t *v;
                size_t len;
                speer_pb_read_bytes(&r, &v, &len);
            }
        }
    }
    uint64_t elapsed = get_time_ns() - start;

    double ops_per_sec = (double)iterations * 1000000000.0 / (double)elapsed;
    printf("pb_decode_simple:  %10.0f ops/sec  (%llu ns/op)\n", ops_per_sec, elapsed / iterations);
}

int main(void) {
    printf("=== Wire Format Benchmarks ===\n\n");

    bench_varint_encode();
    bench_varint_decode();
    bench_lp_write();
    bench_lp_read();
    bench_pb_encode();
    bench_pb_decode();

    printf("\n");
    return 0;
}
