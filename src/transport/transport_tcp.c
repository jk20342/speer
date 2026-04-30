#include "speer_internal.h"
#include "transport_tcp.h"
#include "transport_iface.h"

#include <stdio.h>

#if defined(_WIN32)
static int winsock_init_done_tcp = 0;
static void winsock_init_tcp(void) {
    if (!winsock_init_done_tcp) {
        WSADATA d; WSAStartup(MAKEWORD(2,2), &d);
        winsock_init_done_tcp = 1;
    }
}
#else
#include <sys/types.h>
#endif

static int sock_v4_addr(struct sockaddr_in* sin, const char* host, uint16_t port) {
    ZERO(sin, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    if (!host || host[0] == 0) {
        sin->sin_addr.s_addr = htonl(INADDR_ANY);
        return 0;
    }
#if defined(_WIN32)
    struct in_addr v4;
    int sz = sizeof(v4);
    if (WSAStringToAddressA((char*)host, AF_INET, NULL, (struct sockaddr*)&v4, &sz) != 0) {
        return -1;
    }
    sin->sin_addr = v4;
#else
    if (inet_pton(AF_INET, host, &sin->sin_addr) != 1) return -1;
#endif
    return 0;
}

int speer_tcp_listen(int* out_listen_fd, const char* host, uint16_t port) {
#if defined(_WIN32)
    winsock_init_tcp();
#endif
    int fd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return -1;
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    struct sockaddr_in sin;
    if (sock_v4_addr(&sin, host, port) != 0) { CLOSESOCKET(fd); return -1; }
    if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) { CLOSESOCKET(fd); return -1; }
    if (listen(fd, 16) < 0) { CLOSESOCKET(fd); return -1; }
    if (out_listen_fd) *out_listen_fd = fd;
    return 0;
}

int speer_tcp_dial(int* out_fd, const char* host, uint16_t port) {
#if defined(_WIN32)
    winsock_init_tcp();
#endif
    int fd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return -1;
    struct sockaddr_in sin;
    if (sock_v4_addr(&sin, host, port) != 0) { CLOSESOCKET(fd); return -1; }
    if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) { CLOSESOCKET(fd); return -1; }
    if (out_fd) *out_fd = fd;
    return 0;
}

int speer_tcp_accept(int listen_fd, int* out_fd, char* peer_out, size_t peer_cap) {
    struct sockaddr_in sin;
    socklen_t sz = sizeof(sin);
    int fd = (int)accept(listen_fd, (struct sockaddr*)&sin, &sz);
    if (fd < 0) return -1;
    if (peer_out && peer_cap > 0) {
#if defined(_WIN32)
        DWORD len = (DWORD)peer_cap;
        WSAAddressToStringA((struct sockaddr*)&sin, sizeof(sin), NULL, peer_out, &len);
#else
        char abuf[46];
        if (inet_ntop(AF_INET, &sin.sin_addr, abuf, sizeof(abuf))) {
            snprintf(peer_out, peer_cap, "%s:%u", abuf, (unsigned)ntohs(sin.sin_port));
        } else {
            peer_out[0] = 0;
        }
#endif
    }
    if (out_fd) *out_fd = fd;
    return 0;
}

int speer_tcp_recv(int fd, uint8_t* buf, size_t cap, size_t* out_n) {
    int n = (int)recv(fd, (char*)buf, (int)cap, 0);
    if (n < 0) return -1;
    if (out_n) *out_n = (size_t)n;
    return n == 0 ? 1 : 0;
}

int speer_tcp_send(int fd, const uint8_t* data, size_t len, size_t* out_sent) {
    int n = (int)send(fd, (const char*)data, (int)len, 0);
    if (n < 0) return -1;
    if (out_sent) *out_sent = (size_t)n;
    return 0;
}

int speer_tcp_recv_all(int fd, uint8_t* buf, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        size_t got = 0;
        int rc = speer_tcp_recv(fd, buf + pos, len - pos, &got);
        if (rc < 0) return -1;
        if (rc == 1 || got == 0) return -1;
        pos += got;
    }
    return 0;
}

int speer_tcp_send_all(int fd, const uint8_t* data, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        size_t sent = 0;
        if (speer_tcp_send(fd, data + pos, len - pos, &sent) < 0) return -1;
        if (sent == 0) return -1;
        pos += sent;
    }
    return 0;
}

void speer_tcp_close(int fd) {
    if (fd >= 0) CLOSESOCKET(fd);
}

int speer_tcp_set_nonblocking(int fd, int yes) {
#if defined(_WIN32)
    u_long mode = yes ? 1 : 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    if (yes) fl |= O_NONBLOCK; else fl &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, fl);
#endif
}

struct speer_transport_endpoint_s {
    int listen_fd;
};

struct speer_transport_conn_s {
    int fd;
    char peer_addr[64];
};

static int tcp_listen_op(speer_transport_endpoint_t** out_ep, const char* addr, void* cfg) {
    (void)cfg;
    if (!addr) return SPEER_TR_INVALID;
    char host[64] = {0};
    uint16_t port = 0;
    const char* colon = NULL;
    for (const char* p = addr; *p; p++) if (*p == ':') colon = p;
    if (!colon) return SPEER_TR_INVALID;
    size_t hl = (size_t)(colon - addr);
    if (hl >= sizeof(host)) return SPEER_TR_INVALID;
    if (hl > 0) COPY(host, addr, hl);
    port = (uint16_t)atoi(colon + 1);

    speer_transport_endpoint_t* ep = (speer_transport_endpoint_t*)calloc(1, sizeof(*ep));
    if (!ep) return SPEER_TR_FAIL;
    if (speer_tcp_listen(&ep->listen_fd, hl > 0 ? host : NULL, port) < 0) { free(ep); return SPEER_TR_FAIL; }
    *out_ep = ep;
    return SPEER_TR_OK;
}

static int tcp_dial_op(speer_transport_conn_t** out_conn, const char* addr, void* cfg) {
    (void)cfg;
    if (!addr) return SPEER_TR_INVALID;
    char host[46] = {0};
    const char* colon = NULL;
    for (const char* p = addr; *p; p++) if (*p == ':') colon = p;
    if (!colon) return SPEER_TR_INVALID;
    size_t hl = (size_t)(colon - addr);
    if (hl >= sizeof(host)) return SPEER_TR_INVALID;
    COPY(host, addr, hl);
    uint16_t port = (uint16_t)atoi(colon + 1);

    speer_transport_conn_t* c = (speer_transport_conn_t*)calloc(1, sizeof(*c));
    if (!c) return SPEER_TR_FAIL;
    if (speer_tcp_dial(&c->fd, host, port) < 0) { free(c); return SPEER_TR_REFUSED; }
    snprintf(c->peer_addr, sizeof(c->peer_addr), "%s:%u", host, (unsigned)port);
    *out_conn = c;
    return SPEER_TR_OK;
}

static int tcp_accept_op(speer_transport_endpoint_t* ep, speer_transport_conn_t** out_conn) {
    speer_transport_conn_t* c = (speer_transport_conn_t*)calloc(1, sizeof(*c));
    if (!c) return SPEER_TR_FAIL;
    if (speer_tcp_accept(ep->listen_fd, &c->fd, c->peer_addr, sizeof(c->peer_addr)) < 0) {
        free(c); return SPEER_TR_AGAIN;
    }
    *out_conn = c;
    return SPEER_TR_OK;
}

static int tcp_send_op(speer_transport_conn_t* c, const uint8_t* d, size_t l, size_t* sent) {
    return speer_tcp_send(c->fd, d, l, sent) < 0 ? SPEER_TR_FAIL : SPEER_TR_OK;
}
static int tcp_recv_op(speer_transport_conn_t* c, uint8_t* b, size_t cap, size_t* rl) {
    int rc = speer_tcp_recv(c->fd, b, cap, rl);
    if (rc < 0) return SPEER_TR_FAIL;
    if (rc == 1) return SPEER_TR_EOF;
    return SPEER_TR_OK;
}
static int tcp_close_conn_op(speer_transport_conn_t* c) { speer_tcp_close(c->fd); free(c); return SPEER_TR_OK; }
static int tcp_close_endpoint_op(speer_transport_endpoint_t* ep) { speer_tcp_close(ep->listen_fd); free(ep); return SPEER_TR_OK; }
static int tcp_peer_addr_op(speer_transport_conn_t* c, char* o, size_t cap) {
    size_t l = 0; while (c->peer_addr[l] && l < cap - 1) { o[l] = c->peer_addr[l]; l++; }
    o[l] = 0; return SPEER_TR_OK;
}
static int tcp_local_addr_op(speer_transport_endpoint_t* ep, char* o, size_t cap) {
    (void)ep; if (cap > 0) o[0] = 0; return SPEER_TR_OK;
}
static int tcp_set_nb_op(speer_transport_conn_t* c, int y) { return speer_tcp_set_nonblocking(c->fd, y); }

const speer_transport_ops_t speer_transport_tcp_ops = {
    .name = "tcp", .kind = SPEER_TR_STREAM,
    .listen = tcp_listen_op, .dial = tcp_dial_op, .accept = tcp_accept_op,
    .send = tcp_send_op, .recv = tcp_recv_op,
    .close_conn = tcp_close_conn_op, .close_endpoint = tcp_close_endpoint_op,
    .peer_addr = tcp_peer_addr_op, .local_addr = tcp_local_addr_op,
    .set_nonblocking = tcp_set_nb_op
};
