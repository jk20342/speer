#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "mdns.h"

#include "speer_internal.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#if defined(_WIN32)
#include <iphlpapi.h>
#include <winerror.h>
#else
#include <ifaddrs.h>
#include <net/if.h>
#endif

static int mdns_strcasecmp(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb) return (int)ca - (int)cb;
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answers;
    uint16_t authority;
    uint16_t additional;
} dns_header_t;

#define DNS_FLAG_RESPONSE     0x8000
#define DNS_FLAG_AA           0x0400
#define DNS_CLASS_IN          1
#define DNS_CLASS_FLUSH_CACHE 0x8001

static int append_name(uint8_t *out, size_t *pos, size_t max, const char *name) {
    size_t start = *pos;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len > 63 || *pos + 1 + len > max) {
            *pos = start;
            return -1;
        }
        out[(*pos)++] = (uint8_t)len;
        memcpy(out + *pos, p, len);
        *pos += len;
        if (!dot) break;
        p = dot + 1;
    }
    if (*pos + 1 > max) {
        *pos = start;
        return -1;
    }
    out[(*pos)++] = 0;
    return 0;
}

static size_t decode_name(const uint8_t *pkt, size_t pkt_len, size_t offset, char *out,
                          size_t out_cap, int depth) {
    (void)depth;
    size_t out_pos = 0;
    int jumped = 0;
    size_t jump_target = 0;
    int pointer_follows = 0;
    size_t total_label_bytes = 0;
    while (offset < pkt_len) {
        uint8_t len = pkt[offset];
        if (len == 0) {
            offset++;
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= pkt_len) return 0;
            if (++pointer_follows > 10) return 0;
            size_t new_offset = ((size_t)(len & 0x3F) << 8) | pkt[offset + 1];
            if (!jumped) {
                jump_target = offset + 2;
                jumped = 1;
            }
            if (new_offset >= offset) return 0;
            offset = new_offset;
            continue;
        }
        offset++;
        if (offset + len > pkt_len) return 0;
        total_label_bytes += (size_t)len + 1;
        if (total_label_bytes > 255) return 0;
        if (out_cap > 0) {
            if (out_pos > 0 && out_pos + 1 < out_cap) out[out_pos++] = '.';
            size_t to_copy = len;
            size_t room = out_cap - out_pos - 1;
            if (to_copy > room) to_copy = room;
            if (to_copy > 0) memcpy(out + out_pos, pkt + offset, to_copy);
            out_pos += to_copy;
        }
        offset += len;
    }
    if (out_pos < out_cap) out[out_pos] = 0;
    return jumped ? jump_target : offset;
}

int mdns_init(mdns_ctx_t *ctx) {
    SPEER_INIT_WINSOCK();
    memset(ctx, 0, sizeof(mdns_ctx_t));
    ctx->socket_ipv4 = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->socket_ipv4 < 0) return -1;
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
    memset(&sin, 0, sizeof(sin));
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
    if (ctx->socket_ipv4 >= 0) { CLOSESOCKET(ctx->socket_ipv4); }
    if (ctx->socket_ipv6 >= 0) { CLOSESOCKET(ctx->socket_ipv6); }
    memset(ctx, 0, sizeof(mdns_ctx_t));
    ctx->socket_ipv4 = -1;
    ctx->socket_ipv6 = -1;
}

int mdns_register_service(mdns_ctx_t *ctx, const char *instance_name, const char *service_type,
                          uint16_t port, const uint8_t *txt_data, size_t txt_len) {
    if (ctx->num_services >= MDNS_MAX_SERVICES) return -1;
    mdns_service_t *svc = &ctx->services[ctx->num_services++];
    memset(svc, 0, sizeof(mdns_service_t));
    size_t len = strlen(instance_name);
    size_t name_copy_len = len < MDNS_MAX_NAME_LENGTH - 1 ? len : MDNS_MAX_NAME_LENGTH - 1;
    memcpy(svc->instance_name, instance_name, name_copy_len);
    len = strlen(service_type);
    name_copy_len = len < MDNS_MAX_NAME_LENGTH - 1 ? len : MDNS_MAX_NAME_LENGTH - 1;
    memcpy(svc->service_type, service_type, name_copy_len);
    memcpy(svc->domain, "local", 6);
    svc->srv.port = port;
    svc->ttl = MDNS_TTL;
    if (txt_data && txt_len > 0) {
        size_t pos = 0;
        while (pos < txt_len && svc->txt.num_fields < 16) {
            uint8_t txt_len_byte = txt_data[pos++];
            if (pos + txt_len_byte > txt_len) break;
            char txt_str[256];
            size_t copy_len = txt_len_byte < 255 ? txt_len_byte : 255;
            memcpy(txt_str, txt_data + pos, copy_len);
            txt_str[copy_len] = 0;
            char *eq = memchr(txt_str, '=', copy_len);
            size_t key_len = eq ? (size_t)(eq - txt_str) : copy_len;
            if (key_len > 0 && key_len < sizeof(svc->txt.fields[0].key)) {
                mdns_txt_field_t *field = &svc->txt.fields[svc->txt.num_fields];
                memcpy(field->key, txt_str, key_len);
                field->key[key_len] = 0;
                field->has_value = eq != NULL;
                if (eq) {
                    size_t val_len = (txt_str + copy_len) - (eq + 1);
                    if (val_len > sizeof(field->value) - 1) val_len = sizeof(field->value) - 1;
                    memcpy(field->value, eq + 1, val_len);
                    field->value[val_len] = 0;
                }
                svc->txt.num_fields++;
            }
            pos += txt_len_byte;
        }
    }
    return 0;
}

int mdns_build_announcement(uint8_t *out, size_t *out_len, const mdns_service_t *svc) {
    size_t pos = 0;
    size_t max = *out_len;
    if (pos + 12 > max) return -1;
    memset(out + pos, 0, 12);
    STORE16_BE(out + 2, DNS_FLAG_RESPONSE | DNS_FLAG_AA);
    STORE16_BE(out + 4, 0);
    STORE16_BE(out + 6, 1);
    STORE16_BE(out + 8, 0);
    uint16_t txt_count = svc->txt.num_fields ? (uint16_t)svc->txt.num_fields : (uint16_t)1;
    STORE16_BE(out + 10, txt_count);
    pos += 12;

    char service_name[MDNS_MAX_NAME_LENGTH * 2 + 2];
    size_t type_len = strlen(svc->service_type);
    int n;
    if (type_len >= 6 && strcmp(svc->service_type + type_len - 6, ".local") == 0) {
        n = snprintf(service_name, sizeof(service_name), "%s", svc->service_type);
    } else {
        n = snprintf(service_name, sizeof(service_name), "%s.%s", svc->service_type, svc->domain);
    }
    if (n < 0 || (size_t)n >= sizeof(service_name)) return -1;

    if (append_name(out, &pos, max, service_name) != 0) return -1;
    if (pos + 10 > max) return -1;
    STORE16_BE(out + pos, MDNS_TYPE_PTR);
    pos += 2;
    STORE16_BE(out + pos, DNS_CLASS_IN);
    pos += 2;
    STORE32_BE(out + pos, svc->ttl);
    pos += 4;
    size_t ptr_rdlen_pos = pos;
    pos += 2;
    size_t ptr_rdata_start = pos;
    size_t peer_name_offset = pos;
    if (append_name(out, &pos, max, svc->instance_name) != 0) return -1;
    STORE16_BE(out + ptr_rdlen_pos, (uint16_t)(pos - ptr_rdata_start));

    for (uint32_t i = 0; i < txt_count; i++) {
        if (peer_name_offset <= 0x3FFF) {
            if (pos + 2 > max) return -1;
            out[pos++] = (uint8_t)(0xC0 | (peer_name_offset >> 8));
            out[pos++] = (uint8_t)(peer_name_offset & 0xFF);
        } else {
            if (append_name(out, &pos, max, svc->instance_name) != 0) return -1;
        }
        if (pos + 10 > max) return -1;
        STORE16_BE(out + pos, MDNS_TYPE_TXT);
        pos += 2;
        STORE16_BE(out + pos, DNS_CLASS_FLUSH_CACHE);
        pos += 2;
        STORE32_BE(out + pos, svc->ttl);
        pos += 4;
        size_t txt_rdlen_pos = pos;
        pos += 2;
        size_t txt_rdata_start = pos;
        if (svc->txt.num_fields == 0) {
            if (pos + 1 > max) return -1;
            out[pos++] = 0;
        } else {
            char txt_field[256];
            int len;
            const mdns_txt_field_t *f = &svc->txt.fields[i];
            if (f->has_value) {
                len = snprintf(txt_field, sizeof(txt_field), "%s=%s", f->key, f->value);
            } else {
                len = snprintf(txt_field, sizeof(txt_field), "%s", f->key);
            }
            if (len < 0) return -1;
            if (len > 255) len = 255;
            if (pos + 1 + (size_t)len > max) return -1;
            out[pos++] = (uint8_t)len;
            memcpy(out + pos, txt_field, (size_t)len);
            pos += (size_t)len;
        }
        STORE16_BE(out + txt_rdlen_pos, (uint16_t)(pos - txt_rdata_start));
    }

    *out_len = pos;
    return 0;
}

static int mdns_enum_local_ipv4(uint32_t *out, int cap) {
    int count = 0;
    if (cap > 0) { out[count++] = htonl(INADDR_LOOPBACK); }
#if defined(_WIN32)
    ULONG buf_len = 16 * 1024;
    IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES *)malloc(buf_len);
    if (!addrs) return count;
    ULONG ret = GetAdaptersAddresses(AF_INET,
                                     GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                         GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
                                     NULL, addrs, &buf_len);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(addrs);
        addrs = (IP_ADAPTER_ADDRESSES *)malloc(buf_len);
        if (!addrs) return count;
        ret = GetAdaptersAddresses(AF_INET,
                                   GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                                       GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
                                   NULL, addrs, &buf_len);
    }
    if (ret == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *a = addrs; a && count < cap; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp) continue;
            for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u && count < cap;
                 u = u->Next) {
                if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
                struct sockaddr_in *si = (struct sockaddr_in *)u->Address.lpSockaddr;
                uint32_t addr = si->sin_addr.s_addr;
                if (addr == htonl(INADDR_LOOPBACK)) continue;
                /* skip APIPA 169.254/16 */
                if ((ntohl(addr) & 0xFFFF0000U) == 0xA9FE0000U) continue;
                out[count++] = addr;
            }
        }
    }
    free(addrs);
#else
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) == 0) {
        for (struct ifaddrs *cur = ifa; cur && count < cap; cur = cur->ifa_next) {
            if (!cur->ifa_addr || cur->ifa_addr->sa_family != AF_INET) continue;
            if (!(cur->ifa_flags & IFF_UP)) continue;
            struct sockaddr_in *si = (struct sockaddr_in *)cur->ifa_addr;
            uint32_t addr = si->sin_addr.s_addr;
            if (addr == htonl(INADDR_LOOPBACK)) continue;
            out[count++] = addr;
        }
        freeifaddrs(ifa);
    }
#endif
    return count;
}

int mdns_query(mdns_ctx_t *ctx, const char *service_name) {
    uint8_t pkt[256];
    size_t pos = 0;
    memset(pkt, 0, 12);
    STORE16_BE(pkt + 4, 1);
    pos += 12;
    if (append_name(pkt, &pos, sizeof(pkt), service_name) != 0) return -1;
    if (pos + 4 > sizeof(pkt)) return -1;
    STORE16_BE(pkt + pos, MDNS_TYPE_PTR);
    pos += 2;
    STORE16_BE(pkt + pos, DNS_CLASS_IN);
    pos += 2;
    uint32_t ifaces[16];
    int n_ifaces = mdns_enum_local_ipv4(ifaces, (int)(sizeof(ifaces) / sizeof(ifaces[0])));
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(MDNS_PORT);
    dest.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDR_IPV4);
    for (int k = 0; k < n_ifaces; k++) {
        struct in_addr if_addr;
        if_addr.s_addr = ifaces[k];
        setsockopt(ctx->socket_ipv4, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&if_addr,
                   sizeof(if_addr));
        sendto(ctx->socket_ipv4, (const char *)pkt, (int)pos, 0, (struct sockaddr *)&dest,
               sizeof(dest));
    }
    if (n_ifaces == 0) {
        sendto(ctx->socket_ipv4, (const char *)pkt, (int)pos, 0, (struct sockaddr *)&dest,
               sizeof(dest));
    }
    return 0;
}

int mdns_announce(mdns_ctx_t *ctx) {
    uint8_t packet[MDNS_MAX_PACKET_SIZE];
    uint32_t ifaces[16];
    int n_ifaces = mdns_enum_local_ipv4(ifaces, (int)(sizeof(ifaces) / sizeof(ifaces[0])));
    for (uint32_t i = 0; i < ctx->num_services; i++) {
        size_t len = sizeof(packet);
        if (mdns_build_announcement(packet, &len, &ctx->services[i]) != 0) continue;
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(MDNS_PORT);
        dest.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDR_IPV4);
        for (int k = 0; k < n_ifaces; k++) {
            struct in_addr if_addr;
            if_addr.s_addr = ifaces[k];
            setsockopt(ctx->socket_ipv4, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&if_addr,
                       sizeof(if_addr));
            sendto(ctx->socket_ipv4, (const char *)packet, (int)len, 0, (struct sockaddr *)&dest,
                   sizeof(dest));
        }
        if (n_ifaces == 0) {
            sendto(ctx->socket_ipv4, (const char *)packet, (int)len, 0, (struct sockaddr *)&dest,
                   sizeof(dest));
        }
    }
    return 0;
}

static void mdns_handle_query(mdns_ctx_t *ctx, const uint8_t *data, size_t len,
                              const struct sockaddr_in *from) {
    if (len < 12) return;
    uint16_t qcount = LOAD16_BE(data + 4);
    size_t pos = 12;
    int matched_any = 0;
    for (uint16_t i = 0; i < qcount && pos < len; i++) {
        char qname[MDNS_MAX_NAME_LENGTH];
        size_t name_end = decode_name(data, len, pos, qname, sizeof(qname), 0);
        if (name_end == 0) return;
        if (name_end + 4 > len) return;
        uint16_t qtype = LOAD16_BE(data + name_end);
        pos = name_end + 4;
        for (uint32_t s = 0; s < ctx->num_services && !matched_any; s++) {
            const mdns_service_t *svc = &ctx->services[s];
            char service_name[MDNS_MAX_NAME_LENGTH * 2 + 2];
            size_t type_len = strlen(svc->service_type);
            int n;
            if (type_len >= 6 && strcmp(svc->service_type + type_len - 6, ".local") == 0) {
                n = snprintf(service_name, sizeof(service_name), "%s", svc->service_type);
            } else {
                n = snprintf(service_name, sizeof(service_name), "%s.%s", svc->service_type,
                             svc->domain);
            }
            if (n < 0 || (size_t)n >= sizeof(service_name)) continue;
            if (mdns_strcasecmp(qname, service_name) == 0 &&
                (qtype == MDNS_TYPE_PTR || qtype == MDNS_TYPE_ANY)) {
                matched_any = 1;
            }
        }
    }
    if (!matched_any) return;
    uint8_t packet[MDNS_MAX_PACKET_SIZE];
    for (uint32_t i = 0; i < ctx->num_services; i++) {
        size_t plen = sizeof(packet);
        if (mdns_build_announcement(packet, &plen, &ctx->services[i]) != 0) continue;
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(MDNS_PORT);
        dest.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDR_IPV4);
        sendto(ctx->socket_ipv4, (const char *)packet, (int)plen, 0, (struct sockaddr *)&dest,
               sizeof(dest));
        if (from && from->sin_addr.s_addr != 0) {
            sendto(ctx->socket_ipv4, (const char *)packet, (int)plen, 0,
                   (const struct sockaddr *)from, sizeof(*from));
        }
    }
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
            if (WSAGetLastError() == WSAEWOULDBLOCK) break;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
#endif
            break;
        }
        if (n < 12) continue;
        uint16_t flags = LOAD16_BE(ctx->recv_buffer + 2);
        uint16_t qcount = LOAD16_BE(ctx->recv_buffer + 4);
        if ((flags & 0x8000) == 0 && qcount > 0) {
            mdns_handle_query(ctx, ctx->recv_buffer, (size_t)n, &from);
        }
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

/*
 * parse dns/mdns answer section and extract txt peer id plus multiaddr ascii hint
 * skips unrelated records; uses sender ipv4 only for ip4 multiaddr construction
 */
int mdns_parse_packet(mdns_ctx_t *ctx, const uint8_t *data, size_t len, char *out_peer_id,
                      size_t peer_id_cap, char *out_multiaddr, size_t multiaddr_cap,
                      uint32_t sender_ipv4_s_addr) {
    (void)ctx;
    memset(out_peer_id, 0, peer_id_cap);
    memset(out_multiaddr, 0, multiaddr_cap);
    if (len < 12) return -1;
    dns_header_t hdr;
    hdr.id = LOAD16_BE(data);
    hdr.flags = LOAD16_BE(data + 2);
    hdr.questions = LOAD16_BE(data + 4);
    hdr.answers = LOAD16_BE(data + 6);
    hdr.authority = LOAD16_BE(data + 8);
    hdr.additional = LOAD16_BE(data + 10);
    size_t pos = 12;
    for (uint16_t i = 0; i < hdr.questions && pos < len; i++) {
        char name[MDNS_MAX_NAME_LENGTH];
        size_t name_len = decode_name(data, len, pos, name, sizeof(name), 0);
        if (name_len == 0) return -1;
        if (name_len + 4 > len) return -1;
        pos = name_len + 4;
    }
    char service_name[MDNS_MAX_NAME_LENGTH] = {0};
    uint16_t port = 0;
    char txt_peer_id[MDNS_MAX_NAME_LENGTH] = {0};
    char txt_dnsaddr[256] = {0};
    uint32_t total_records = (uint32_t)hdr.answers + hdr.authority + hdr.additional;
    if (total_records > 64) total_records = 64;
    for (uint32_t i = 0; i < total_records && pos < len; i++) {
        char name[MDNS_MAX_NAME_LENGTH];
        size_t name_len = decode_name(data, len, pos, name, sizeof(name), 0);
        if (name_len == 0 || name_len >= len) break;
        pos = name_len;
        if (pos + 10 > len) break;
        uint16_t rtype = LOAD16_BE(data + pos);
        pos += 2;
        uint16_t rclass = LOAD16_BE(data + pos);
        pos += 2;
        (void)rclass;
        uint32_t ttl = LOAD32_BE(data + pos);
        pos += 4;
        (void)ttl;
        uint16_t rdlen = LOAD16_BE(data + pos);
        pos += 2;
        if (pos + rdlen > len) break;
        if (rtype == MDNS_TYPE_SRV) {
            if (rdlen >= 6) {
                port = LOAD16_BE(data + pos + 4);
                char *dot = strchr(name, '.');
                if (dot) {
                    size_t svc_len = dot - name;
                    if (svc_len < MDNS_MAX_NAME_LENGTH) {
                        memcpy(service_name, name, svc_len);
                        service_name[svc_len] = 0;
                    }
                }
            }
        } else if (rtype == MDNS_TYPE_TXT) {
            size_t txt_pos = pos;
            size_t txt_end = pos + rdlen;
            while (txt_pos < txt_end) {
                uint8_t txt_len = data[txt_pos++];
                if (txt_pos + txt_len > txt_end) break;
                char txt_field[256];
                size_t copy_len = txt_len < 255 ? txt_len : 255;
                memcpy(txt_field, data + txt_pos, copy_len);
                txt_field[copy_len] = 0;
                if (strncmp(txt_field, "id=", 3) == 0) {
                    size_t id_len = strlen(txt_field + 3);
                    if (id_len < MDNS_MAX_NAME_LENGTH) {
                        memcpy(txt_peer_id, txt_field + 3, id_len + 1);
                    }
                } else if (strncmp(txt_field, "dnsaddr=", 8) == 0) {
                    const char *addr = txt_field + 8;
                    size_t addr_len = strlen(addr);
                    if (addr_len < sizeof(txt_dnsaddr)) memcpy(txt_dnsaddr, addr, addr_len + 1);
                    const char *p2p = strstr(addr, "/p2p/");
                    size_t p2p_prefix = 5;
                    if (!p2p) {
                        p2p = strstr(addr, "/ipfs/");
                        p2p_prefix = 6;
                    }
                    if (p2p) {
                        p2p += p2p_prefix;
                        size_t id_len = strcspn(p2p, "/");
                        if (id_len > 0 && id_len < sizeof(txt_peer_id)) {
                            memcpy(txt_peer_id, p2p, id_len);
                            txt_peer_id[id_len] = 0;
                        }
                    }
                }
                txt_pos += txt_len;
            }
        }
        pos += rdlen;
    }
    if (txt_peer_id[0] && txt_dnsaddr[0]) {
        size_t id_len = strlen(txt_peer_id);
        size_t addr_len = strlen(txt_dnsaddr);
        if (id_len < peer_id_cap) memcpy(out_peer_id, txt_peer_id, id_len + 1);
        if (addr_len < multiaddr_cap) memcpy(out_multiaddr, txt_dnsaddr, addr_len + 1);
        return 0;
    }
    (void)port;
    (void)service_name;
    (void)sender_ipv4_s_addr;
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
    (void)peer_id;
    if (cap == 0) return -1;
    int n = snprintf(out, cap, "_p2p._udp.local");
    return (n >= 0 && (size_t)n < cap) ? 0 : -1;
}

int mdns_unregister_service(mdns_ctx_t *ctx, const char *instance_name) {
    for (uint32_t i = 0; i < ctx->num_services; i++) {
        if (strcmp(ctx->services[i].instance_name, instance_name) == 0) {
            if (i + 1 < ctx->num_services) {
                memmove(&ctx->services[i], &ctx->services[i + 1],
                        (ctx->num_services - i - 1) * sizeof(ctx->services[0]));
            }
            ctx->num_services--;
            memset(&ctx->services[ctx->num_services], 0, sizeof(ctx->services[0]));
            return 0;
        }
    }
    return -1;
}

int mdns_build_probe(uint8_t *out, size_t *out_len, const char *service_name) {
    size_t pos = 0;
    size_t max = *out_len;
    if (max < 12) return -1;
    memset(out, 0, 12);
    STORE16_BE(out + 4, 1);
    pos = 12;
    if (append_name(out, &pos, max, service_name) != 0) return -1;
    if (pos + 4 > max) return -1;
    STORE16_BE(out + pos, MDNS_TYPE_ANY);
    pos += 2;
    STORE16_BE(out + pos, DNS_CLASS_IN);
    pos += 2;
    *out_len = pos;
    return 0;
}
