#include "tls13_record.h"

#include "speer_internal.h"

void speer_tls13_record_dir_init(speer_tls13_record_dir_t *d, const speer_tls13_suite_t *suite,
                                 const speer_tls13_keys_t *k) {
    ZERO(d, sizeof(*d));
    d->suite = suite;
    d->keys = *k;
    d->active = 1;
}

static void make_nonce(uint8_t out[12], const uint8_t iv[12], uint64_t seq) {
    COPY(out, iv, 12);
    for (int i = 0; i < 8; i++) { out[11 - i] ^= (uint8_t)(seq >> (8 * i)); }
}

int speer_tls13_record_seal(speer_tls13_record_dir_t *d, uint8_t inner_type,
                            const uint8_t *plaintext, size_t pt_len, uint8_t *out_record,
                            size_t out_cap, size_t *out_len) {
    if (!d->active) return -1;
    size_t inner_len = pt_len + 1;
    size_t total = 5 + inner_len + 16;
    if (total > out_cap) return -1;

    out_record[0] = TLS_CT_APPLICATION_DATA;
    out_record[1] = 0x03;
    out_record[2] = 0x03;
    out_record[3] = (uint8_t)((inner_len + 16) >> 8);
    out_record[4] = (uint8_t)(inner_len + 16);

    uint8_t *body = out_record + 5;
    uint8_t *tag = body + inner_len;
    if (pt_len > 0) COPY(body, plaintext, pt_len);
    body[pt_len] = inner_type;

    uint8_t nonce[12];
    make_nonce(nonce, d->keys.iv, d->seq);
    if (d->suite->aead->seal(d->keys.key, nonce, out_record, 5, body, inner_len, body, tag) != 0)
        return -1;
    d->seq++;
    if (out_len) *out_len = total;
    return 0;
}

int speer_tls13_record_open(speer_tls13_record_dir_t *d, const uint8_t *record, size_t record_len,
                            uint8_t *out_plain, size_t out_cap, size_t *out_len,
                            uint8_t *out_inner_type) {
    if (!d->active) return -1;
    if (record_len < 5 + 16) return -1;
    if (record[0] != TLS_CT_APPLICATION_DATA) return -1;
    size_t body_len = ((size_t)record[3] << 8) | record[4];
    if (body_len < 16 || 5 + body_len > record_len) return -1;
    size_t ct_len = body_len - 16;
    if (ct_len > out_cap) return -1;

    uint8_t nonce[12];
    make_nonce(nonce, d->keys.iv, d->seq);
    if (d->suite->aead->open(d->keys.key, nonce, record, 5, record + 5, ct_len, record + 5 + ct_len,
                             out_plain) != 0)
        return -1;
    d->seq++;

    size_t pt_len = ct_len;
    while (pt_len > 0 && out_plain[pt_len - 1] == 0) pt_len--;
    if (pt_len == 0) return -1;
    if (out_inner_type) *out_inner_type = out_plain[pt_len - 1];
    if (out_len) *out_len = pt_len - 1;
    return 0;
}
