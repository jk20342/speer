#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "peer_id.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;

    uint8_t mode = data[0] % 3;

    switch (mode) {
    case 0: {
        if (size > 10) {
            uint8_t pubkey_proto[256];
            size_t pubkey_proto_len;
            uint8_t key[32] = {0};
            memcpy(key, data + 1, size - 1 > 32 ? 32 : size - 1);
            speer_libp2p_pubkey_proto_encode(pubkey_proto, sizeof(pubkey_proto),
                                             SPEER_LIBP2P_KEY_ED25519, key, 32, &pubkey_proto_len);
        }
        break;
    }
    case 1: {
        if (size > 10) {
            speer_libp2p_keytype_t kt;
            const uint8_t *key;
            size_t key_len;
            speer_libp2p_pubkey_proto_decode(data + 1, size - 1, &kt, &key, &key_len);
        }
        break;
    }
    case 2: {
        if (size > 10) {
            uint8_t peer_id[64];
            size_t peer_id_len;
            speer_peer_id_from_pubkey_bytes(peer_id, sizeof(peer_id), data + 1, size - 1,
                                            &peer_id_len);

            if (peer_id_len > 0) {
                char b58[128];
                speer_peer_id_to_b58(b58, sizeof(b58), peer_id, peer_id_len);
            }
        }
        break;
    }
    }

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        LLVMFuzzerTestOneInput(NULL, 0);
        LLVMFuzzerTestOneInput((const uint8_t *)"", 0);

        uint8_t encode[40];
        encode[0] = 0x00;
        memset(encode + 1, 0xab, 32);
        LLVMFuzzerTestOneInput(encode, sizeof(encode));

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
