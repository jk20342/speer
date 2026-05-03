#include "quic_pkt.h"

#include "speer_internal.h"

#include <string.h>

#include "aead_iface.h"
#include "hash_iface.h"
#include "varint.h"

static const uint8_t kInitialSaltV1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                           0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                           0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

static void hp_init_aes128(speer_hp_ctx_t *h, const uint8_t *k) {
    speer_hp_init(h, SPEER_HP_AES_128, k);
}

uint64_t speer_quic_decode_pn(uint64_t largest_pn, uint64_t truncated_pn, size_t pn_nbits) {
    uint64_t expected_pn = largest_pn + 1;
    uint64_t pn_win = (uint64_t)1 << pn_nbits;
    uint64_t pn_hwin = pn_win >> 1;
    uint64_t pn_mask = pn_win - 1;
    uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
    if (candidate_pn + pn_hwin <= expected_pn && candidate_pn < ((uint64_t)1 << 62) - pn_win)
        candidate_pn += pn_win;
    else if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
        candidate_pn -= pn_win;
    return candidate_pn;
}

int speer_quic_keys_init_initial(speer_quic_keys_t *ck, speer_quic_keys_t *sk, const uint8_t *dcid,
                                 size_t dcid_len, uint32_t version) {
    if (dcid_len > QUIC_MAX_CID_LEN) return -1;
    if (version != QUIC_VERSION_V1) return -1;
    ZERO(ck, sizeof(*ck));
    ZERO(sk, sizeof(*sk));
    uint8_t initial_secret[32];
    speer_hkdf2_extract(&speer_hash_sha256, initial_secret, kInitialSaltV1, sizeof(kInitialSaltV1),
                        dcid, dcid_len);

    uint8_t client_secret[32], server_secret[32];
    speer_hkdf_expand_label(&speer_hash_sha256, client_secret, 32, initial_secret, 32, "client in",
                            NULL, 0);
    speer_hkdf_expand_label(&speer_hash_sha256, server_secret, 32, initial_secret, 32, "server in",
                            NULL, 0);

    speer_hkdf_expand_label(&speer_hash_sha256, ck->key, 16, client_secret, 32, "quic key", NULL,
                            0);
    speer_hkdf_expand_label(&speer_hash_sha256, ck->iv, 12, client_secret, 32, "quic iv", NULL, 0);
    uint8_t hp_key[16];
    speer_hkdf_expand_label(&speer_hash_sha256, hp_key, 16, client_secret, 32, "quic hp", NULL, 0);
    ck->aead = &speer_aead_aes128_gcm;
    ck->key_len = 16;
    hp_init_aes128(&ck->hp, hp_key);

    speer_hkdf_expand_label(&speer_hash_sha256, sk->key, 16, server_secret, 32, "quic key", NULL,
                            0);
    speer_hkdf_expand_label(&speer_hash_sha256, sk->iv, 12, server_secret, 32, "quic iv", NULL, 0);
    speer_hkdf_expand_label(&speer_hash_sha256, hp_key, 16, server_secret, 32, "quic hp", NULL, 0);
    sk->aead = &speer_aead_aes128_gcm;
    sk->key_len = 16;
    hp_init_aes128(&sk->hp, hp_key);
    return 0;
}

static void make_nonce(uint8_t out[12], const uint8_t iv[12], uint64_t pn) {
    COPY(out, iv, 12);
    for (int i = 0; i < 8; i++) out[11 - i] ^= (uint8_t)(pn >> (8 * i));
}

static int recv_replay_check(uint64_t pn, uint64_t top, uint64_t bits) {
    if (pn > top) return 0;
    uint64_t diff = top - pn;
    if (diff >= QUIC_REPLAY_WINDOW) return -1;
    if (bits & (UINT64_C(1) << diff)) return -1;
    return 0;
}

static void recv_replay_record(speer_quic_keys_t *keys, uint64_t pn) {
    if (pn > keys->recv_window_top) {
        uint64_t shift = pn - keys->recv_window_top;
        if (shift >= QUIC_REPLAY_WINDOW) {
            keys->recv_window_bits = 0;
        } else {
            keys->recv_window_bits <<= shift;
        }
        keys->recv_window_top = pn;
        keys->recv_window_bits |= UINT64_C(1);
    } else {
        uint64_t diff = keys->recv_window_top - pn;
        keys->recv_window_bits |= (UINT64_C(1) << diff);
    }
}

static size_t encoded_pn_length(uint64_t pn) {
    if (pn < 0x100) return 1;
    if (pn < 0x10000) return 2;
    if (pn < 0x1000000) return 3;
    return 4;
}

int speer_quic_pkt_encode_long(uint8_t *out, size_t out_cap, size_t *out_len,
                               const speer_quic_pkt_t *p, speer_quic_keys_t *keys) {
    if (p->dcid_len > QUIC_MAX_CID_LEN || p->scid_len > QUIC_MAX_CID_LEN) return -1;
    size_t pos = 0;
    if (pos + 1 + 4 + 1 + p->dcid_len + 1 + p->scid_len > out_cap) return -1;

    size_t pn_len = p->pn_length ? p->pn_length : encoded_pn_length(p->pkt_num);
    if (pn_len < 1 || pn_len > 4) return -1;

    out[pos++] = 0xc0 | ((p->pkt_type & 0x3) << 4) | (uint8_t)(pn_len - 1);
    out[pos++] = (uint8_t)(p->version >> 24);
    out[pos++] = (uint8_t)(p->version >> 16);
    out[pos++] = (uint8_t)(p->version >> 8);
    out[pos++] = (uint8_t)(p->version);
    out[pos++] = (uint8_t)p->dcid_len;
    if (p->dcid_len > 0) {
        COPY(out + pos, p->dcid, p->dcid_len);
        pos += p->dcid_len;
    }
    out[pos++] = (uint8_t)p->scid_len;
    if (p->scid_len > 0) {
        COPY(out + pos, p->scid, p->scid_len);
        pos += p->scid_len;
    }

    if (p->pkt_type == QUIC_PT_INITIAL) {
        size_t n = speer_qvarint_encode(out + pos, out_cap - pos, p->token_len);
        if (n == 0) return -1;
        pos += n;
        if (pos + p->token_len > out_cap) return -1;
        if (p->token_len > 0) {
            COPY(out + pos, p->token, p->token_len);
            pos += p->token_len;
        }
    }

    size_t length_field = pn_len + p->payload_len + 16;
    size_t lvar = speer_qvarint_encode(out + pos, out_cap - pos, length_field);
    if (lvar == 0) return -1;
    pos += lvar;

    size_t pn_offset = pos;
    for (size_t i = 0; i < pn_len; i++) {
        out[pos + i] = (uint8_t)(p->pkt_num >> (8 * (pn_len - 1 - i)));
    }
    pos += pn_len;

    if (pos + p->payload_len + 16 > out_cap) return -1;
    if (p->payload_len > 0) COPY(out + pos, p->payload, p->payload_len);
    size_t payload_offset = pos;
    pos += p->payload_len;
    uint8_t *tag = out + pos;
    pos += 16;

    uint8_t nonce[12];
    make_nonce(nonce, keys->iv, p->pkt_num);
    if (keys->aead->seal(keys->key, nonce, out, payload_offset, out + payload_offset,
                         p->payload_len, out + payload_offset, tag) != 0)
        return -1;

    if (speer_hp_protect(&keys->hp, out, pos, pn_offset, pn_len) != 0) return -1;
    if (out_len) *out_len = pos;
    return 0;
}

int speer_quic_pkt_decode_long(speer_quic_pkt_t *p, uint8_t *pkt, size_t pkt_len,
                               speer_quic_keys_t *keys) {
    ZERO(p, sizeof(*p));
    if (pkt_len < 7) return -1;
    if ((pkt[0] & 0x80) == 0) return -1;
    p->is_long = 1;
    p->version = ((uint32_t)pkt[1] << 24) | ((uint32_t)pkt[2] << 16) | ((uint32_t)pkt[3] << 8) |
                 pkt[4];
    if (p->version != QUIC_VERSION_V1) return -1;
    size_t pos = 5;

    /* pkt_len >= 7 guarantees index 5 is in range for dcil_len. */
    p->dcid_len = pkt[pos++];
    if (p->dcid_len > QUIC_MAX_CID_LEN) return -1;
    if (p->dcid_len > pkt_len - pos) return -1;
    if (p->dcid_len > 0) COPY(p->dcid, pkt + pos, p->dcid_len);
    pos += p->dcid_len;
    if (pos >= pkt_len) return -1;
    p->scid_len = pkt[pos++];
    if (p->scid_len > QUIC_MAX_CID_LEN) return -1;
    if (p->scid_len > pkt_len - pos) return -1;
    if (p->scid_len > 0) COPY(p->scid, pkt + pos, p->scid_len);
    pos += p->scid_len;

    p->pkt_type = (pkt[0] >> 4) & 0x3;

    if (p->pkt_type == QUIC_PT_INITIAL) {
        uint64_t tlen;
        size_t n = speer_qvarint_decode(pkt + pos, pkt_len - pos, &tlen);
        if (n == 0) return -1;
        if (tlen > (uint64_t)(pkt_len - pos - n)) return -1;
        pos += n;
        p->token = pkt + pos;
        p->token_len = (size_t)tlen;
        pos += (size_t)tlen;
    }

    uint64_t length_field;
    size_t n = speer_qvarint_decode(pkt + pos, pkt_len - pos, &length_field);
    if (n == 0) return -1;
    pos += n;
    if (length_field > (uint64_t)(pkt_len - pos)) return -1;
    if (length_field > (uint64_t)pkt_len) return -1;

    size_t pn_offset = pos;
    size_t pn_length;
    if (speer_hp_unprotect(&keys->hp, pkt, pkt_len, pn_offset, &pn_length) != 0) return -1;
    p->pn_length = pn_length;
    if (length_field < (uint64_t)pn_length + 16) return -1;

    uint64_t pn = 0;
    for (size_t i = 0; i < pn_length; i++) pn = (pn << 8) | pkt[pn_offset + i];
    p->pkt_num = speer_quic_decode_pn(keys->largest_acked, pn, pn_length * 8);

    if (recv_replay_check(p->pkt_num, keys->recv_window_top, keys->recv_window_bits) != 0)
        return -1;

    size_t hdr_len = pn_offset + pn_length;
    size_t ct_len = (size_t)length_field - pn_length - 16;
    if (hdr_len + ct_len + 16 > pkt_len) return -1;

    uint8_t nonce[12];
    make_nonce(nonce, keys->iv, p->pkt_num);
    if (keys->aead->open(keys->key, nonce, pkt, hdr_len, pkt + hdr_len, ct_len,
                         pkt + hdr_len + ct_len, pkt + hdr_len) != 0)
        return -1;

    recv_replay_record(keys, p->pkt_num);
    if (p->pkt_num > keys->largest_acked) keys->largest_acked = p->pkt_num;
    p->payload = pkt + hdr_len;
    p->payload_len = ct_len;
    return 0;
}

int speer_quic_pkt_encode_short(uint8_t *out, size_t out_cap, size_t *out_len, const uint8_t *dcid,
                                size_t dcid_len, uint64_t pn, size_t pn_length,
                                const uint8_t *payload, size_t payload_len, speer_quic_keys_t *keys,
                                int spin_bit, int key_phase) {
    if (pn_length < 1 || pn_length > 4) return -1;
    if (1 + dcid_len + pn_length + payload_len + 16 > out_cap) return -1;

    size_t pos = 0;
    out[pos++] = 0x40 | ((spin_bit & 1) << 5) | ((key_phase & 1) << 2) | (uint8_t)(pn_length - 1);
    if (dcid_len > 0) {
        COPY(out + pos, dcid, dcid_len);
        pos += dcid_len;
    }

    size_t pn_offset = pos;
    for (size_t i = 0; i < pn_length; i++) {
        out[pos + i] = (uint8_t)(pn >> (8 * (pn_length - 1 - i)));
    }
    pos += pn_length;

    size_t payload_offset = pos;
    if (payload_len > 0) COPY(out + pos, payload, payload_len);
    pos += payload_len;
    uint8_t *tag = out + pos;
    pos += 16;

    uint8_t nonce[12];
    make_nonce(nonce, keys->iv, pn);
    if (keys->aead->seal(keys->key, nonce, out, payload_offset, out + payload_offset, payload_len,
                         out + payload_offset, tag) != 0)
        return -1;
    if (speer_hp_protect(&keys->hp, out, pos, pn_offset, pn_length) != 0) return -1;
    if (out_len) *out_len = pos;
    return 0;
}

int speer_quic_pkt_decode_short(speer_quic_pkt_t *p, uint8_t *pkt, size_t pkt_len,
                                size_t expected_dcid_len, speer_quic_keys_t *keys) {
    ZERO(p, sizeof(*p));
    if (pkt_len < 1 + expected_dcid_len + 1 + 16) return -1;
    if ((pkt[0] & 0x80) != 0) return -1;
    p->is_long = 0;

    if (expected_dcid_len > QUIC_MAX_CID_LEN) return -1;
    p->dcid_len = expected_dcid_len;
    COPY(p->dcid, pkt + 1, expected_dcid_len);

    size_t pn_offset = 1 + expected_dcid_len;
    size_t pn_length;
    if (speer_hp_unprotect(&keys->hp, pkt, pkt_len, pn_offset, &pn_length) != 0) return -1;
    p->pn_length = pn_length;

    uint64_t pn = 0;
    for (size_t i = 0; i < pn_length; i++) pn = (pn << 8) | pkt[pn_offset + i];
    p->pkt_num = speer_quic_decode_pn(keys->largest_acked, pn, pn_length * 8);

    if (recv_replay_check(p->pkt_num, keys->recv_window_top, keys->recv_window_bits) != 0)
        return -1;

    size_t hdr_len = pn_offset + pn_length;
    if (hdr_len + 16 > pkt_len) return -1;
    size_t ct_len = pkt_len - hdr_len - 16;

    uint8_t nonce[12];
    make_nonce(nonce, keys->iv, p->pkt_num);
    if (keys->aead->open(keys->key, nonce, pkt, hdr_len, pkt + hdr_len, ct_len,
                         pkt + hdr_len + ct_len, pkt + hdr_len) != 0)
        return -1;

    recv_replay_record(keys, p->pkt_num);
    if (p->pkt_num > keys->largest_acked) keys->largest_acked = p->pkt_num;
    p->payload = pkt + hdr_len;
    p->payload_len = ct_len;
    return 0;
}
