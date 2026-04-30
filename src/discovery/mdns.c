#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "mdns.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>

#include <ws2tcpip.h>
typedef int socklen_t;
#define CLOSESOCKET closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#define CLOSESOCKET close
#endif

#if defined(_WIN32)
static void mdns_ensure_wsa(void) {
    static int done;
    if (!done) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0)
            done = 1;
    }
}
#endif

#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define COPY(dst, src, len) memcpy((dst), (src), (len))
#define ZERO(p, len)        memset((p), 0, (len))

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority;
    uint16_t additional;
} dns_header_t;

#define DNS_FLAG_RESPONSE     0x8000
#define DNS_CLASS_IN          1
#define DNS_CLASS_FLUSH_CACHE 0x8001

static void mdns_format_ipv4(char out[16], uint32_t addr_be) {
    const uint8_t *b = (const uint8_t *)&addr_be;
    snprintf(out, 16, "%u.%u.%u.%u", (unsigned)b[0], (unsigned)b[1], (unsigned)b[2],
             (unsigned)b[3]);
}

static uint16_t read_u16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_u16(uint8_t *p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}

static void write_u32(uint8_t *p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

static size_t encode_name(uint8_t *out, const char *name) {
    size_t pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len > 63)
            len = 63;
        out[pos++] = (uint8_t)len;
        COPY(out + pos, p, len);
        pos += len;
        if (!dot)
            break;
        p = dot + 1;
    }
    out[pos++] = 0;
    return pos;
}

static size_t decode_name(const uint8_t *pkt, size_t pkt_len, size_t offset, char *out,
                          size_t out_cap, int depth) {
    if (depth > 10)
        return 0;
    size_t out_pos = 0;
    int jumped = 0;
    size_t jump_target = 0;
    while (offset < pkt_len) {
        uint8_t len = pkt[offset];
        if (len == 0) {
            offset++;
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= pkt_len)
                return 0;
            if (!jumped) {
                jump_target = offset + 2;
                jumped = 1;
            }
            offset = ((len & 0x3F) << 8) | pkt[offset + 1];
            if (offset >= pkt_len)
                return 0;
            continue;
        }
        offset++;
        if (offset + len > pkt_len)
            return 0;
        if (out_pos > 0 && out_pos < out_cap)
            out[out_pos++] = '.';
        size_t to_copy = len;
        if (out_pos + to_copy > out_cap - 1)
            to_copy = out_cap - out_pos - 1;
        COPY(out + out_pos, pkt + offset, to_copy);
        out_pos += to_copy;
        offset += len;
    }
    if (out_pos < out_cap)
        out[out_pos] = 0;
    return jumped ? jump_target : offset;
}

int mdns_init(mdns_ctx_t *ctx) {
#if defined(_WIN32)
    mdns_ensure_wsa();
#endif
    ZERO(ctx, sizeof(mdns_ctx_t));
    ctx->socket_ipv4 = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->socket_ipv4 < 0)
        return -1;
    int reuse = 1;
    setsockopt(ctx->socket_ipv4, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(ctx->socket_ipv4, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuse, sizeof(reuse));
#endif
    int loop = 1;
    setsockopt(ctx->socket_ipv4, IPPROTO_IP, IP_MULTICAST_LOOP, (const char *)&loop, sizeof(loop));
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_MULTICAST_ADDR_IPV4);
    mreq.imr_interface.s_addr = INADDR_ANY;
    setsockopt(ctx->socket_ipv4, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
    struct sockaddr_in sin;
    ZERO(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(MDNS_PORT);
    sin.sin_addr.s_addr = INADDR_ANY;
    if (bind(ctx->socket_ipv4, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        CLOSESOCKET(ctx->socket_ipv4);
        ctx->socket_ipv4 = -1;
        return -1;
    }
#if defined(_WIN32)
    u_long mode = 1;
    ioctlsocket(ctx->socket_ipv4, FIONBIO, &mode);
#else
    int flags = fcntl(ctx->socket_ipv4, F_GETFL, 0);
    fcntl(ctx->socket_ipv4, F_SETFL, flags | O_NONBLOCK);
#endif
    ctx->socket_ipv6 = -1;
    return 0;
}

void mdns_free(mdns_ctx_t *ctx) {
    if (ctx->socket_ipv4 >= 0) {
        CLOSESOCKET(ctx->socket_ipv4);
    }
    if (ctx->socket_ipv6 >= 0) {
        CLOSESOCKET(ctx->socket_ipv6);
    }
    ZERO(ctx, sizeof(mdns_ctx_t));
    ctx->socket_ipv4 = -1;
    ctx->socket_ipv6 = -1;
}

int mdns_register_service(mdns_ctx_t *ctx, const char *instance_name, const char *service_type,
                          uint16_t port, const uint8_t *txt_data, size_t txt_len) {
    if (ctx->num_services >= MDNS_MAX_SERVICES)
        return -1;
    mdns_service_t *svc = &ctx->services[ctx->num_services++];
    ZERO(svc, sizeof(mdns_service_t));
    size_t len = strlen(instance_name);
    COPY(svc->instance_name, instance_name, MIN(len, MDNS_MAX_NAME_LENGTH - 1));
    len = strlen(service_type);
    COPY(svc->service_type, service_type, MIN(len, MDNS_MAX_NAME_LENGTH - 1));
    COPY(svc->domain, "local", 6);
    svc->srv.port = port;
    svc->ttl = MDNS_TTL;
    if (txt_data && txt_len > 0) {
        size_t pos = 0;
        while (pos < txt_len && svc->txt.num_fields < 16) {
            uint8_t txt_len_byte = txt_data[pos++];
            if (pos + txt_len_byte > txt_len)
                break;
            char txt_str[256];
            size_t copy_len = txt_len_byte < 255 ? txt_len_byte : 255;
            COPY(txt_str, txt_data + pos, copy_len);
            txt_str[copy_len] = 0;
            char *eq = strchr(txt_str, '=');
            if (eq) {
                size_t key_len = (size_t)(eq - txt_str);
                if (key_len < 64) {
                    COPY(svc->txt.fields[svc->txt.num_fields].key, txt_str, key_len);
                    svc->txt.fields[svc->txt.num_fields].key[key_len] = 0;
                    size_t val_len = (txt_str + copy_len) - (eq + 1);
                    if (val_len > sizeof(svc->txt.fields[0].value) - 1)
                        val_len = sizeof(svc->txt.fields[0].value) - 1;
                    COPY(svc->txt.fields[svc->txt.num_fields].value, eq + 1, val_len);
                    svc->txt.fields[svc->txt.num_fields].value[val_len] = 0;
                    svc->txt.num_fields++;
                }
            }
            pos += txt_len_byte;
        }
    }
    return 0;
}

int mdns_build_announcement(uint8_t *out, size_t *out_len, const mdns_service_t *svc) {
    size_t pos = 0;
    size_t max = *out_len;
    if (pos + 12 > max)
        return -1;
    dns_header_t *hdr = (dns_header_t *)(out + pos);
    ZERO(hdr, sizeof(dns_header_t));
    hdr->flags = htons(DNS_FLAG_RESPONSE);
    hdr->answers = htons(3);
    pos += 12;
    char full_name[MDNS_MAX_NAME_LENGTH * 3 + 2];
    snprintf(full_name, sizeof(full_name), "%s.%s.%s", svc->instance_name, svc->service_type,
             svc->domain);
    size_t name_len = encode_name(out + pos, svc->service_type);
    if (pos + name_len + 10 > max)
        return -1;
    pos += name_len;
    write_u16(out + pos, MDNS_TYPE_PTR);
    pos += 2;
    write_u16(out + pos, htons(DNS_CLASS_FLUSH_CACHE));
    pos += 2;
    write_u32(out + pos, htonl(svc->ttl));
    pos += 4;
    size_t ptr_len = encode_name(out + pos + 2, full_name);
    write_u16(out + pos, (uint16_t)ptr_len);
    pos += 2 + ptr_len;
    name_len = encode_name(out + pos, full_name);
    if (pos + name_len + 10 + 6 > max)
        return -1;
    pos += name_len;
    write_u16(out + pos, MDNS_TYPE_SRV);
    pos += 2;
    write_u16(out + pos, htons(DNS_CLASS_FLUSH_CACHE));
    pos += 2;
    write_u32(out + pos, htonl(svc->ttl));
    pos += 4;
    write_u16(out + pos, 6);
    pos += 2;
    write_u16(out + pos, htons(svc->srv.priority));
    pos += 2;
    write_u16(out + pos, htons(svc->srv.weight));
    pos += 2;
    write_u16(out + pos, htons(svc->srv.port));
    pos += 2;
    out[pos++] = 0;
    name_len = encode_name(out + pos, full_name);
    if (pos + name_len + 10 > max)
        return -1;
    pos += name_len;
    write_u16(out + pos, MDNS_TYPE_TXT);
    pos += 2;
    write_u16(out + pos, htons(DNS_CLASS_FLUSH_CACHE));
    pos += 2;
    write_u32(out + pos, htonl(svc->ttl));
    pos += 4;
    size_t txt_start = pos;
    pos += 2;
    for (uint32_t i = 0; i < svc->txt.num_fields; i++) {
        char txt_field[256];
        int len = snprintf(txt_field, sizeof(txt_field), "%s=%s", svc->txt.fields[i].key,
                           svc->txt.fields[i].value);
        if (len > 255)
            len = 255;
        out[pos++] = (uint8_t)len;
        COPY(out + pos, txt_field, len);
        pos += len;
    }
    if (svc->txt.num_fields == 0)
        out[pos++] = 0;
    write_u16(out + txt_start, (uint16_t)(pos - txt_start - 2));
    *out_len = pos;
    return 0;
}

int mdns_announce(mdns_ctx_t *ctx) {
    uint8_t packet[MDNS_MAX_PACKET_SIZE];
    for (uint32_t i = 0; i < ctx->num_services; i++) {
        size_t len = sizeof(packet);
        if (mdns_build_announcement(packet, &len, &ctx->services[i]) == 0) {
            struct sockaddr_in dest;
            ZERO(&dest, sizeof(dest));
            dest.sin_family = AF_INET;
            dest.sin_port = htons(MDNS_PORT);
            dest.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDR_IPV4);
            sendto(ctx->socket_ipv4, (const char *)packet, (int)len, 0, (struct sockaddr *)&dest,
                   sizeof(dest));
        }
    }
    return 0;
}

int mdns_poll(mdns_ctx_t *ctx, int timeout_ms) {
    (void)timeout_ms;
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int received = 0;
    while (1) {
        int n = recvfrom(ctx->socket_ipv4, (char *)ctx->recv_buffer, MDNS_MAX_PACKET_SIZE, 0,
                         (struct sockaddr *)&from, &from_len);
        if (n < 0) {
#if defined(_WIN32)
            if (WSAGetLastError() == WSAEWOULDBLOCK)
                break;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
#endif
            break;
        }
        if (n < 12)
            continue;
        char peer_id[128];
        char multiaddr[256];
        if (mdns_parse_packet(ctx, ctx->recv_buffer, (size_t)n, peer_id, sizeof(peer_id), multiaddr,
                              sizeof(multiaddr), from.sin_addr.s_addr) == 0) {
            if (ctx->on_peer_discovered && peer_id[0]) {
                ctx->on_peer_discovered(ctx->user, peer_id, multiaddr);
            }
        }
        received++;
    }
    return received;
}

int mdns_parse_packet(mdns_ctx_t *ctx, const uint8_t *data, size_t len, char *out_peer_id,
                      size_t peer_id_cap, char *out_multiaddr, size_t multiaddr_cap,
                      uint32_t sender_ipv4_s_addr) {
    (void)ctx;
    ZERO(out_peer_id, peer_id_cap);
    ZERO(out_multiaddr, multiaddr_cap);
    if (len < 12)
        return -1;
    dns_header_t hdr;
    hdr.id = read_u16(data);
    hdr.flags = read_u16(data + 2);
    hdr.questions = ntohs(read_u16(data + 4));
    hdr.answers = ntohs(read_u16(data + 6));
    hdr.authority = ntohs(read_u16(data + 8));
    hdr.additional = ntohs(read_u16(data + 10));
    size_t pos = 12;
    for (uint16_t i = 0; i < hdr.questions && pos < len; i++) {
        char name[MDNS_MAX_NAME_LENGTH];
        size_t name_len = decode_name(data, len, pos, name, sizeof(name), 0);
        if (name_len == 0)
            return -1;
        pos = name_len + 4;
    }
    char service_name[MDNS_MAX_NAME_LENGTH] = {0};
    uint16_t port = 0;
    char txt_peer_id[MDNS_MAX_NAME_LENGTH] = {0};
    uint16_t total_records = hdr.answers + hdr.authority + hdr.additional;
    for (uint16_t i = 0; i < total_records && pos < len; i++) {
        char name[MDNS_MAX_NAME_LENGTH];
        size_t name_len = decode_name(data, len, pos, name, sizeof(name), 0);
        if (name_len == 0 || name_len >= len)
            break;
        pos = name_len;
        if (pos + 10 > len)
            break;
        uint16_t rtype = read_u16(data + pos);
        pos += 2;
        uint16_t rclass = read_u16(data + pos);
        pos += 2;
        (void)rclass;
        uint32_t ttl = read_u32(data + pos);
        pos += 4;
        (void)ttl;
        uint16_t rdlen = read_u16(data + pos);
        pos += 2;
        if (pos + rdlen > len)
            break;
        if (rtype == MDNS_TYPE_SRV) {
            if (rdlen >= 6) {
                port = ntohs(read_u16(data + pos + 4));
                char *dot = strchr(name, '.');
                if (dot) {
                    size_t svc_len = dot - name;
                    if (svc_len < MDNS_MAX_NAME_LENGTH) {
                        COPY(service_name, name, svc_len);
                        service_name[svc_len] = 0;
                    }
                }
            }
        } else if (rtype == MDNS_TYPE_TXT) {
            size_t txt_pos = pos;
            size_t txt_end = pos + rdlen;
            while (txt_pos < txt_end) {
                uint8_t txt_len = data[txt_pos++];
                if (txt_pos + txt_len > txt_end)
                    break;
                char txt_field[256];
                size_t copy_len = txt_len < 255 ? txt_len : 255;
                COPY(txt_field, data + txt_pos, copy_len);
                txt_field[copy_len] = 0;
                if (strncmp(txt_field, "id=", 3) == 0) {
                    size_t id_len = strlen(txt_field + 3);
                    if (id_len < MDNS_MAX_NAME_LENGTH) {
                        COPY(txt_peer_id, txt_field + 3, id_len + 1);
                    }
                }
                txt_pos += txt_len;
            }
        }
        pos += rdlen;
    }
    if (port > 0 && service_name[0]) {
        size_t id_len = strlen(txt_peer_id);
        if (id_len > 0 && id_len < peer_id_cap) {
            COPY(out_peer_id, txt_peer_id, id_len + 1);
        }
        char host[16];
        mdns_format_ipv4(host, sender_ipv4_s_addr);
        snprintf(out_multiaddr, multiaddr_cap, "/ip4/%s/tcp/%u", host, port);
        return 0;
    }
    return -1;
}

void mdns_set_discovery_callback(mdns_ctx_t *ctx,
                                 void (*callback)(void *user, const char *peer_id,
                                                  const char *multiaddr),
                                 void *user) {
    ctx->on_peer_discovered = callback;
    ctx->user = user;
}

int mdns_build_libp2p_service_name(char *out, size_t cap, const uint8_t *peer_id) {
    char hex_id[65];
    for (int i = 0; i < 32; i++) {
        snprintf(hex_id + i * 2, 3, "%02x", peer_id[i]);
    }
    snprintf(out, cap, "%s._p2p._tcp.local", hex_id);
    return 0;
}

int mdns_unregister_service(mdns_ctx_t *ctx, const char *instance_name) {
    (void)ctx;
    (void)instance_name;
    return 0;
}

int mdns_build_probe(uint8_t *out, size_t *out_len, const char *service_name) {
    (void)out;
    (void)out_len;
    (void)service_name;
    return 0;
}
