#ifndef SPEER_TLS13_RECORD_H
#define SPEER_TLS13_RECORD_H

#include <stdint.h>
#include <stddef.h>
#include "tls13_keysched.h"

#define TLS_CT_INVALID            0
#define TLS_CT_CHANGE_CIPHER_SPEC 20
#define TLS_CT_ALERT              21
#define TLS_CT_HANDSHAKE          22
#define TLS_CT_APPLICATION_DATA   23

typedef struct {
    const speer_tls13_suite_t* suite;
    speer_tls13_keys_t keys;
    uint64_t seq;
    int active;
} speer_tls13_record_dir_t;

void speer_tls13_record_dir_init(speer_tls13_record_dir_t* d,
                                   const speer_tls13_suite_t* suite,
                                   const speer_tls13_keys_t* k);

int  speer_tls13_record_seal(speer_tls13_record_dir_t* d,
                               uint8_t inner_type,
                               const uint8_t* plaintext, size_t pt_len,
                               uint8_t* out_record, size_t out_cap, size_t* out_len);

int  speer_tls13_record_open(speer_tls13_record_dir_t* d,
                               const uint8_t* record, size_t record_len,
                               uint8_t* out_plain, size_t out_cap,
                               size_t* out_len, uint8_t* out_inner_type);

#endif
