#include "speer_libp2p_identify.h"

#include "speer_internal.h"

#include "identify.h"

static int to_internal(const speer_libp2p_identify_info_t *src, speer_identify_t *dst) {
    if (!src || !dst) return -1;
    ZERO(dst, sizeof(*dst));
    if (src->pubkey_proto_len > sizeof(dst->pubkey_proto)) return -1;
    COPY(dst->pubkey_proto, src->pubkey_proto, src->pubkey_proto_len);
    dst->pubkey_proto_len = src->pubkey_proto_len;
    if (src->num_listen_addrs > IDENTIFY_MAX_LISTEN_ADDRS ||
        src->num_protocols > IDENTIFY_MAX_PROTOCOLS)
        return -1;
    for (size_t i = 0; i < src->num_listen_addrs; i++) {
        if (src->listen_addr_lens[i] > sizeof(dst->listen_addrs[i].bytes)) return -1;
        COPY(dst->listen_addrs[i].bytes, src->listen_addrs[i], src->listen_addr_lens[i]);
        dst->listen_addrs[i].len = src->listen_addr_lens[i];
    }
    dst->num_listen_addrs = src->num_listen_addrs;
    for (size_t i = 0; i < src->num_protocols; i++) {
        COPY(dst->protocols[i], src->protocols[i], sizeof(dst->protocols[i]));
        dst->protocols[i][sizeof(dst->protocols[i]) - 1] = 0;
    }
    dst->num_protocols = src->num_protocols;
    COPY(dst->agent_version, src->agent_version, sizeof(dst->agent_version));
    dst->agent_version[sizeof(dst->agent_version) - 1] = 0;
    COPY(dst->protocol_version, src->protocol_version, sizeof(dst->protocol_version));
    dst->protocol_version[sizeof(dst->protocol_version) - 1] = 0;
    if (src->has_observed) {
        if (src->observed_addr_len > sizeof(dst->observed_addr.bytes)) return -1;
        COPY(dst->observed_addr.bytes, src->observed_addr, src->observed_addr_len);
        dst->observed_addr.len = src->observed_addr_len;
        dst->has_observed = 1;
    }
    return 0;
}

static int from_internal(const speer_identify_t *src, speer_libp2p_identify_info_t *dst) {
    if (!src || !dst) return -1;
    ZERO(dst, sizeof(*dst));
    COPY(dst->pubkey_proto, src->pubkey_proto, src->pubkey_proto_len);
    dst->pubkey_proto_len = src->pubkey_proto_len;
    dst->num_listen_addrs = src->num_listen_addrs;
    for (size_t i = 0; i < src->num_listen_addrs; i++) {
        if (src->listen_addrs[i].len > SPEER_LIBP2P_IDENTIFY_MULTIADDR_MAX) return -1;
        COPY(dst->listen_addrs[i], src->listen_addrs[i].bytes, src->listen_addrs[i].len);
        dst->listen_addr_lens[i] = src->listen_addrs[i].len;
    }
    dst->num_protocols = src->num_protocols;
    for (size_t i = 0; i < src->num_protocols; i++) {
        COPY(dst->protocols[i], src->protocols[i], sizeof(dst->protocols[i]));
        dst->protocols[i][sizeof(dst->protocols[i]) - 1] = 0;
    }
    COPY(dst->agent_version, src->agent_version, sizeof(dst->agent_version));
    dst->agent_version[sizeof(dst->agent_version) - 1] = 0;
    COPY(dst->protocol_version, src->protocol_version, sizeof(dst->protocol_version));
    dst->protocol_version[sizeof(dst->protocol_version) - 1] = 0;
    if (src->has_observed) {
        if (src->observed_addr.len > SPEER_LIBP2P_IDENTIFY_MULTIADDR_MAX) return -1;
        COPY(dst->observed_addr, src->observed_addr.bytes, src->observed_addr.len);
        dst->observed_addr_len = src->observed_addr.len;
        dst->has_observed = 1;
    }
    return 0;
}

int speer_libp2p_identify_encode(const speer_libp2p_identify_info_t *info, uint8_t *out, size_t cap,
                                 size_t *out_len) {
    speer_identify_t internal;
    if (to_internal(info, &internal) != 0) return -1;
    return speer_identify_encode(&internal, out, cap, out_len);
}

int speer_libp2p_identify_decode(speer_libp2p_identify_info_t *info, const uint8_t *in,
                                 size_t in_len) {
    speer_identify_t internal;
    if (speer_identify_decode(&internal, in, in_len) != 0) return -1;
    return from_internal(&internal, info);
}
