#include "rsa.h"

#include "speer_internal.h"

#include "bignum.h"
#include "ct_helpers.h"

static int rsa_public_op(uint8_t *out, size_t out_len, const uint8_t *sig, size_t sig_len,
                         const uint8_t *n_be, size_t n_len, const uint8_t *e_be, size_t e_len) {
    speer_bn_t n, e, s, m;
    if (speer_bn_from_bytes_be(&n, n_be, n_len) != 0) return -1;
    if (speer_bn_from_bytes_be(&e, e_be, e_len) != 0) return -1;
    if (speer_bn_from_bytes_be(&s, sig, sig_len) != 0) return -1;
    if (speer_bn_cmp(&s, &n) >= 0) return -1;

    speer_bn_modexp(&m, &s, &e, &n);
    return speer_bn_to_bytes_be(out, out_len, &m);
}

static const uint8_t sha256_oid[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                     0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
static const uint8_t sha384_oid[] = {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                     0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
static const uint8_t sha512_oid[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                     0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

int speer_rsa_pkcs1_v15_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                               const speer_hash_iface_t *hash, const uint8_t *msg_hash,
                               size_t msg_hash_len, const uint8_t *sig, size_t sig_len) {
    if (sig_len < 11) return -1;

    uint8_t *em = (uint8_t *)malloc(sig_len);
    if (!em) return -1;

    if (rsa_public_op(em, sig_len, sig, sig_len, n, n_len, e, e_len) != 0) {
        free(em);
        return -1;
    }

    if (em[0] != 0x00 || em[1] != 0x01) {
        free(em);
        return -1;
    }
    size_t i = 2;
    while (i < sig_len && em[i] == 0xff) i++;
    if (i >= sig_len || em[i] != 0x00) {
        free(em);
        return -1;
    }
    if (i - 2 < 8) {
        free(em);
        return -1;
    }
    i++;

    const uint8_t *prefix;
    size_t prefix_len;
    if (hash == &speer_hash_sha256) {
        prefix = sha256_oid;
        prefix_len = sizeof(sha256_oid);
    } else if (hash == &speer_hash_sha384) {
        prefix = sha384_oid;
        prefix_len = sizeof(sha384_oid);
    } else if (hash == &speer_hash_sha512) {
        prefix = sha512_oid;
        prefix_len = sizeof(sha512_oid);
    } else {
        free(em);
        return -1;
    }

    if (sig_len - i != prefix_len + msg_hash_len) {
        free(em);
        return -1;
    }
    if (!EQUAL(em + i, prefix, prefix_len)) {
        free(em);
        return -1;
    }
    if (!EQUAL(em + i + prefix_len, msg_hash, msg_hash_len)) {
        free(em);
        return -1;
    }

    free(em);
    return 0;
}

static void mgf1(uint8_t *out, size_t out_len, const uint8_t *seed, size_t seed_len,
                 const speer_hash_iface_t *hash) {
    uint8_t buf[SPEER_HASH_MAX_BLOCK + 4];
    uint8_t digest[SPEER_HASH_MAX_DIGEST];
    uint32_t counter = 0;
    size_t pos = 0;
    while (pos < out_len) {
        size_t in_len = seed_len + 4;
        COPY(buf, seed, seed_len);
        buf[seed_len + 0] = (uint8_t)(counter >> 24);
        buf[seed_len + 1] = (uint8_t)(counter >> 16);
        buf[seed_len + 2] = (uint8_t)(counter >> 8);
        buf[seed_len + 3] = (uint8_t)counter;
        hash->oneshot(digest, buf, in_len);
        size_t to_copy = MIN(hash->digest_size, out_len - pos);
        COPY(out + pos, digest, to_copy);
        pos += to_copy;
        counter++;
    }
}

int speer_rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                         const speer_hash_iface_t *hash, const uint8_t *msg_hash,
                         size_t msg_hash_len, const uint8_t *sig, size_t sig_len, size_t salt_len) {
    if (msg_hash_len != hash->digest_size) return -1;

    uint8_t *em = (uint8_t *)malloc(sig_len);
    if (!em) return -1;

    if (rsa_public_op(em, sig_len, sig, sig_len, n, n_len, e, e_len) != 0) {
        free(em);
        return -1;
    }

    size_t em_len = sig_len;
    size_t hash_len = hash->digest_size;

    if (em_len < hash_len + salt_len + 2) {
        free(em);
        return -1;
    }
    if (em[em_len - 1] != 0xbc) {
        free(em);
        return -1;
    }

    size_t db_len = em_len - hash_len - 1;
    uint8_t *db_mask = (uint8_t *)malloc(db_len);
    if (!db_mask) {
        free(em);
        return -1;
    }

    mgf1(db_mask, db_len, em + db_len, hash_len, hash);
    for (size_t i = 0; i < db_len; i++) em[i] ^= db_mask[i];
    free(db_mask);

    if (em[0] & 0x80) {
        free(em);
        return -1;
    }

    for (size_t i = 0; i < db_len - salt_len - 1; i++) {
        if (em[i] != 0) {
            free(em);
            return -1;
        }
    }
    if (em[db_len - salt_len - 1] != 0x01) {
        free(em);
        return -1;
    }

    uint8_t mprime[8 + SPEER_HASH_MAX_DIGEST + 256];
    if (salt_len > 256) {
        free(em);
        return -1;
    }
    ZERO(mprime, 8);
    COPY(mprime + 8, msg_hash, hash_len);
    COPY(mprime + 8 + hash_len, em + db_len - salt_len, salt_len);

    uint8_t check[SPEER_HASH_MAX_DIGEST];
    hash->oneshot(check, mprime, 8 + hash_len + salt_len);

    int rc = speer_ct_memeq(check, em + db_len, hash_len) ? 0 : -1;
    free(em);
    return rc;
}
