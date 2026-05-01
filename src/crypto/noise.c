#include "speer_internal.h"

#include "aead_iface.h"
#include "ct_helpers.h"

static const uint8_t noise_protocol_name[] = "Noise_XX_25519_ChaChaPoly_SHA256";

static void mix_hash(uint8_t hash[32], const uint8_t *data, size_t len) {
    sha256_ctx_t ctx;
    speer_sha256_init(&ctx);
    speer_sha256_update(&ctx, hash, 32);
    speer_sha256_update(&ctx, data, len);
    speer_sha256_final(&ctx, hash);
}

static void mix_key(speer_handshake_t *hs, const uint8_t input_key_material[32]) {
    uint8_t temp[64];
    speer_hkdf(temp, 64, hs->chaining_key, 32, input_key_material, 32, NULL, 0);
    COPY(hs->chaining_key, temp, 32);
    COPY(hs->send_key, temp + 32, 32);
    COPY(hs->recv_key, temp + 32, 32);
    hs->cipher_n = 0;
}

static void cipher_nonce(uint8_t out[12], uint64_t n) {
    ZERO(out, 4);
    out[4] = (uint8_t)(n >> 0);
    out[5] = (uint8_t)(n >> 8);
    out[6] = (uint8_t)(n >> 16);
    out[7] = (uint8_t)(n >> 24);
    out[8] = (uint8_t)(n >> 32);
    out[9] = (uint8_t)(n >> 40);
    out[10] = (uint8_t)(n >> 48);
    out[11] = (uint8_t)(n >> 56);
}

static void encrypt_and_hash(speer_handshake_t *hs, uint8_t *out, const uint8_t *plaintext,
                             size_t len) {
    uint8_t nonce[12];
    cipher_nonce(nonce, hs->cipher_n);

    uint8_t tag[16];
    speer_aead_chacha20_poly1305.seal(hs->send_key, nonce, hs->handshake_hash, 32, plaintext, len,
                                      out, tag);
    COPY(out + len, tag, 16);
    hs->cipher_n++;

    mix_hash(hs->handshake_hash, out, len + 16);
}

static int decrypt_and_hash(speer_handshake_t *hs, uint8_t *out, const uint8_t *ciphertext,
                            size_t len) {
    if (len < 16) return -1;

    size_t plaintext_len = len - 16;
    const uint8_t *tag = ciphertext + plaintext_len;

    uint8_t nonce[12];
    cipher_nonce(nonce, hs->cipher_n);

    if (speer_aead_chacha20_poly1305.open(hs->recv_key, nonce, hs->handshake_hash, 32, ciphertext,
                                          plaintext_len, tag, out) != 0) {
        return -1;
    }
    hs->cipher_n++;

    mix_hash(hs->handshake_hash, ciphertext, len);
    return 0;
}

static void derive_keys(speer_handshake_t *hs, uint8_t send_key[32], uint8_t recv_key[32]) {
    uint8_t temp[64];
    speer_hkdf(temp, 64, hs->chaining_key, 32, NULL, 0, NULL, 0);
    COPY(send_key, temp, 32);
    COPY(recv_key, temp + 32, 32);
}

int speer_noise_xx_init(speer_handshake_t *hs, const uint8_t local_pubkey[32],
                        const uint8_t local_privkey[32]) {
    ZERO(hs, sizeof(*hs));

    COPY(hs->local_pubkey, local_pubkey, 32);
    COPY(hs->local_privkey, local_privkey, 32);

    /* InitializeSymmetric sets h = protocol_name (since the name
       is exactly HASHLEN = 32 bytes here), ck = h. Then HandshakeState.Initialize
       calls MixHash(prologue) which, for libp2p's empty prologue, computes
       SHA256(protocol_name || "") = SHA256(protocol_name). We fold the two
       into a single SHA256 here. ck stays at protocol_name -- MixHash does
       not touch ck. */
    COPY(hs->chaining_key, noise_protocol_name, 32);
    speer_sha256(hs->handshake_hash, noise_protocol_name, 32);

    hs->state = SPEER_STATE_HANDSHAKE;
    hs->step = 0;
    return 0;
}

int speer_noise_xx_write_e(speer_handshake_t *hs, uint8_t *out, size_t *len) {
    if (speer_random_bytes_or_fail(hs->ephemeral_key, 32) != 0) return -1;

    uint8_t ephemeral_pubkey[32];
    speer_x25519_base(ephemeral_pubkey, hs->ephemeral_key);

    mix_hash(hs->handshake_hash, ephemeral_pubkey, 32);

    COPY(out, ephemeral_pubkey, 32);
    *len = 32;

    return 0;
}

int speer_noise_xx_read_e(speer_handshake_t *hs, const uint8_t *in, size_t len) {
    if (len < 32) return -1;

    uint8_t ephemeral_pubkey[32];
    COPY(ephemeral_pubkey, in, 32);
    COPY(hs->remote_ephemeral, in, 32);

    mix_hash(hs->handshake_hash, ephemeral_pubkey, 32);

    uint8_t shared_secret[32];
    speer_x25519(shared_secret, hs->ephemeral_key, ephemeral_pubkey);

    mix_key(hs, shared_secret);
    WIPE(shared_secret, 32);

    return 32;
}

int speer_noise_xx_write_s(speer_handshake_t *hs, uint8_t *out, size_t *len) {
    uint8_t temp[48];
    encrypt_and_hash(hs, temp, hs->local_pubkey, 32);
    COPY(out, temp, 48);
    *len = 48;
    return 0;
}

int speer_noise_xx_read_s(speer_handshake_t *hs, const uint8_t *in, size_t len) {
    if (len < 48) return -1;

    uint8_t plaintext[32];
    if (decrypt_and_hash(hs, plaintext, in, 48) != 0) { return -1; }

    COPY(hs->remote_pubkey, plaintext, 32);

    uint8_t shared_secret[32];
    speer_x25519(shared_secret, hs->ephemeral_key, hs->remote_pubkey);

    mix_key(hs, shared_secret);
    WIPE(shared_secret, 32);

    return 48;
}

void speer_noise_xx_split(speer_handshake_t *hs, uint8_t send_key[32], uint8_t recv_key[32]) {
    derive_keys(hs, send_key, recv_key);
}

int speer_noise_xx_write_msg1(speer_handshake_t *hs, uint8_t out[32]) {
    size_t len = 0;
    int rc = speer_noise_xx_write_e(hs, out, &len);
    if (rc == 0) {
        /* Per Noise spec: EncryptAndHash() runs on the (here empty) payload
         * after the `e` token. With no key set this reduces to MixHash("").
         * Without this step, h diverges from a spec-compliant peer (e.g.
         * rust-libp2p / snow) and the AEAD MAC on msg2's static key fails. */
        mix_hash(hs->handshake_hash, NULL, 0);
    }
    hs->step = 1;
    return rc;
}

int speer_noise_xx_read_msg1(speer_handshake_t *hs, const uint8_t in[32]) {
    COPY(hs->remote_ephemeral, in, 32);
    mix_hash(hs->handshake_hash, in, 32);
    /* Per Noise spec: DecryptAndHash() on the (empty) payload of msg1.
     * With no key set, plaintext == ciphertext and we just MixHash(""). */
    mix_hash(hs->handshake_hash, NULL, 0);
    hs->step = 1;
    return 0;
}

int speer_noise_xx_write_msg2(speer_handshake_t *hs, uint8_t out[80]) {
    uint8_t dh[32];
    size_t len = 0, n = 0;

    if (speer_noise_xx_write_e(hs, out, &len) != 0) return -1;
    speer_x25519(dh, hs->ephemeral_key, hs->remote_ephemeral);
    mix_key(hs, dh);

    speer_noise_xx_write_s(hs, out + len, &n);
    len += n;

    speer_x25519(dh, hs->local_privkey, hs->remote_ephemeral);
    mix_key(hs, dh);
    WIPE(dh, 32);

    hs->step = 2;
    return len == 80 ? 0 : -1;
}

int speer_noise_xx_read_msg2(speer_handshake_t *hs, const uint8_t in[80]) {
    uint8_t dh[32];

    COPY(hs->remote_ephemeral, in, 32);
    mix_hash(hs->handshake_hash, in, 32);

    speer_x25519(dh, hs->ephemeral_key, hs->remote_ephemeral);
    mix_key(hs, dh);

    if (speer_noise_xx_read_s(hs, in + 32, 48) < 0) return -1;

    WIPE(dh, 32);

    hs->step = 2;
    return 0;
}

int speer_noise_xx_write_msg3(speer_handshake_t *hs, uint8_t out[48]) {
    uint8_t dh[32];
    size_t len = 0;

    speer_noise_xx_write_s(hs, out, &len);

    speer_x25519(dh, hs->local_privkey, hs->remote_ephemeral);
    mix_key(hs, dh);
    WIPE(dh, 32);

    hs->step = 3;
    return len == 48 ? 0 : -1;
}

int speer_noise_xx_read_msg3(speer_handshake_t *hs, const uint8_t in[48]) {
    if (speer_noise_xx_read_s(hs, in, 48) < 0) return -1;
    hs->step = 3;
    return 0;
}

int speer_noise_xx_write_msg2_p(speer_handshake_t *hs, const uint8_t *payload, size_t payload_len,
                                uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!hs || !out) return -1;
    if (out_cap < 80 + payload_len + 16) return -1;

    if (speer_noise_xx_write_msg2(hs, out) != 0) return -1;

    uint8_t scratch[1024];
    if (payload_len > sizeof(scratch)) return -1;
    if (payload_len > 0) COPY(scratch, payload, payload_len);
    encrypt_and_hash(hs, out + 80, scratch, payload_len);
    if (out_len) *out_len = 80 + payload_len + 16;
    WIPE(scratch, payload_len);
    return 0;
}

int speer_noise_xx_read_msg2_p(speer_handshake_t *hs, const uint8_t *in, size_t in_len,
                               uint8_t *payload_out, size_t payload_cap, size_t *payload_len) {
    if (!hs || !in || in_len < 80 + 16) return -1;
    if (speer_noise_xx_read_msg2(hs, in) != 0) return -1;
    size_t pl = in_len - 80 - 16;
    if (pl > payload_cap) return -1;
    if (decrypt_and_hash(hs, payload_out, in + 80, pl + 16) != 0) return -1;
    if (payload_len) *payload_len = pl;
    return 0;
}

int speer_noise_xx_write_msg3_p(speer_handshake_t *hs, const uint8_t *payload, size_t payload_len,
                                uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!hs || !out) return -1;
    if (out_cap < 48 + payload_len + 16) return -1;

    if (speer_noise_xx_write_msg3(hs, out) != 0) return -1;

    uint8_t scratch[1024];
    if (payload_len > sizeof(scratch)) return -1;
    if (payload_len > 0) COPY(scratch, payload, payload_len);
    encrypt_and_hash(hs, out + 48, scratch, payload_len);
    if (out_len) *out_len = 48 + payload_len + 16;
    WIPE(scratch, payload_len);
    return 0;
}

int speer_noise_xx_read_msg3_p(speer_handshake_t *hs, const uint8_t *in, size_t in_len,
                               uint8_t *payload_out, size_t payload_cap, size_t *payload_len) {
    if (!hs || !in || in_len < 48 + 16) return -1;
    if (speer_noise_xx_read_msg3(hs, in) != 0) return -1;
    size_t pl = in_len - 48 - 16;
    if (pl > payload_cap) return -1;
    if (decrypt_and_hash(hs, payload_out, in + 48, pl + 16) != 0) return -1;
    if (payload_len) *payload_len = pl;
    return 0;
}
