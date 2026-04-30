#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "tls13_handshake.h"

static uint8_t cert_priv[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
static uint8_t cert_pub[32] = {33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
                               49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64};
static uint8_t libp2p_priv[32] = {65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
                                  81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96};
static uint8_t libp2p_pub[32] = {97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107,
                                 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
                                 119, 120, 121, 122, 123, 124, 125, 126, 127, 128};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t role = data[0] & 0x01;

    speer_tls13_t tls;
    int rc = speer_tls13_init_handshake(&tls, role ? SPEER_TLS_ROLE_SERVER : SPEER_TLS_ROLE_CLIENT,
                                        cert_priv, cert_pub, SPEER_LIBP2P_KEY_ED25519, libp2p_pub,
                                        32, libp2p_priv, 32, NULL, NULL);
    if (rc != 0) return 0;

    uint8_t out[8192];
    size_t out_len;

    speer_tls13_handshake_start(&tls);
    speer_tls13_handshake_take_output(&tls, out, sizeof(out), &out_len);

    if (size > 4) {
        uint8_t msg_type = data[1];
        speer_tls13_handshake_consume(&tls, msg_type, data + 4, size - 4);
    }

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t *)"", 0);

        uint8_t client_hello[32] = {0};
        client_hello[0] = 0x00;
        client_hello[1] = 0x01;
        client_hello[2] = 0x02;
        client_hello[3] = 0x03;
        memset(client_hello + 4, 0xaa, 28);
        LLVMFuzzerTestOneInput(client_hello, sizeof(client_hello));

        uint8_t server_hello[32] = {0};
        server_hello[0] = 0x01;
        server_hello[1] = 0x02;
        server_hello[2] = 0x02;
        server_hello[3] = 0x03;
        memset(server_hello + 4, 0xbb, 28);
        LLVMFuzzerTestOneInput(server_hello, sizeof(server_hello));

        return 0;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(sz);
    if (!data) {
        fclose(f);
        return 1;
    }

    fread(data, 1, sz, f);
    fclose(f);

    LLVMFuzzerTestOneInput(data, sz);
    free(data);

    return 0;
}
#endif
