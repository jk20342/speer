#include "transport_tcp.h"

#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "multistream.h"
#include "transport_iface.h"
#include "varint.h"

#if !defined(_WIN32)
#include <sys/select.h>
#include <sys/types.h>

#include <errno.h>
#endif

struct speer_transport_endpoint_s {
    int listen_fd;
};

struct speer_transport_conn_s {
    int fd;
    char peer_addr[64];
};

int speer_tcp_listen(int *out_listen_fd, const char *host, uint16_t port) {
    SPEER_INIT_WINSOCK();
    int fd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return -1;
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in sin;
    if (speer_sockaddr_in_resolve(&sin, host, port) != 0) {
        CLOSESOCKET(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        CLOSESOCKET(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        CLOSESOCKET(fd);
        return -1;
    }
    if (out_listen_fd) *out_listen_fd = fd;
    return 0;
}

int speer_tcp_dial(int *out_fd, const char *host, uint16_t port) {
    SPEER_INIT_WINSOCK();
    int fd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return -1;
    struct sockaddr_in sin;
    if (speer_sockaddr_in_resolve(&sin, host, port) != 0) {
        CLOSESOCKET(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        int saved = SPEER_SOCK_ERR_GET();
        CLOSESOCKET(fd);
        SPEER_SOCK_ERR_SET(saved);
        return -1;
    }
    if (out_fd) *out_fd = fd;
    return 0;
}

int speer_tcp_accept(int listen_fd, int *out_fd, char *peer_out, size_t peer_cap) {
    struct sockaddr_in sin;
    socklen_t sz = sizeof(sin);
    int fd = (int)accept(listen_fd, (struct sockaddr *)&sin, &sz);
    if (fd < 0) return -1;
    /* On Windows, the accepted socket inherits the non-blocking flag from
     * the listener (see WSAAccept docs). Force it back to blocking so
     * SO_RCVTIMEO / SO_SNDTIMEO behave the same as on Linux/macOS and
     * callers don't get surprise EWOULDBLOCK on their first recv. */
    (void)speer_tcp_set_nonblocking(fd, 0);
    if (peer_out && peer_cap > 0) {
#if defined(_WIN32)
        DWORD len = (DWORD)peer_cap;
        WSAAddressToStringA((struct sockaddr *)&sin, sizeof(sin), NULL, peer_out, &len);
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

int speer_tcp_recv(int fd, uint8_t *buf, size_t cap, size_t *out_n) {
    int n = (int)recv(fd, (char *)buf, (int)cap, 0);
    if (n < 0) return -1;
    if (out_n) *out_n = (size_t)n;
    return n == 0 ? 1 : 0;
}

int speer_tcp_send(int fd, const uint8_t *data, size_t len, size_t *out_sent) {
    int n = (int)send(fd, (const char *)data, (int)len, 0);
    if (n < 0) return -1;
    if (out_sent) *out_sent = (size_t)n;
    return 0;
}

int speer_tcp_recv_all(int fd, uint8_t *buf, size_t len) {
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

int speer_tcp_send_all(int fd, const uint8_t *data, size_t len) {
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
    if (fd < 0) return;
    /* Send FIN before closing so the peer sees a graceful shutdown rather than
     * a connection abort (RST). On Windows, omitting shutdown() before
     * closesocket() makes the peer's recv() fail with WSAECONNABORTED (10053).
     * shutdown() failing on a non-connected socket is harmless and ignored. */
    (void)shutdown(fd, SHUT_WR);
    CLOSESOCKET(fd);
}

int speer_tcp_set_nonblocking(int fd, int yes) {
    return speer_fd_set_nonblocking(fd, yes);
}

int speer_tcp_set_io_timeout(int fd, int timeout_ms) {
    if (fd < 0 || timeout_ms < 0) return -1;
    unsigned u = (unsigned)timeout_ms;
    if (speer_fd_set_rcvtimeo_ms(fd, u) != 0) return -1;
    return speer_fd_set_sndtimeo_ms(fd, u);
}

int speer_tcp_peek_libp2p_multistream_client_hello(int fd) {
    uint8_t buf[64];
#if defined(_WIN32)
    int n = recv(fd, (char *)buf, (int)sizeof(buf), MSG_PEEK);
    if (n == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK || e == WSAETIMEDOUT) return -1;
        return 0;
    }
#else
    ssize_t n = recv(fd, (void *)buf, sizeof(buf), MSG_PEEK);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ETIMEDOUT)
            return -1;
        return 0;
    }
#endif
    if (n == 0) return 0;

    uint64_t plen = 0;
    size_t vlen = speer_uvarint_decode(buf, (size_t)n, &plen);
    const size_t proto_line = strlen(MULTISTREAM_PROTO) + 1;

    if (vlen == 0) {
        if ((size_t)n < 10) return -1;
        return 0;
    }
    if (plen != proto_line) return 0;
    if ((size_t)n < vlen + (size_t)plen) return -1;
    if (memcmp(buf + vlen, MULTISTREAM_PROTO, strlen(MULTISTREAM_PROTO)) != 0) return 0;
    if (buf[vlen + strlen(MULTISTREAM_PROTO)] != '\n') return 0;
    return 1;
}

int speer_tcp_dial_timeout(int *out_fd, const char *host, uint16_t port, int connect_ms) {
    if (connect_ms <= 0) return speer_tcp_dial(out_fd, host, port);
    SPEER_INIT_WINSOCK();
    int fd = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return -1;
    struct sockaddr_in sin;
    if (speer_sockaddr_in_resolve(&sin, host, port) != 0) {
        CLOSESOCKET(fd);
        return -1;
    }
    if (speer_tcp_set_nonblocking(fd, 1) != 0) {
        CLOSESOCKET(fd);
        return -1;
    }
    int rc = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
    if (rc != 0) {
        int err = SPEER_SOCK_ERR_GET();
#if defined(_WIN32)
        int in_progress = (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS);
#else
        int in_progress = (err == EINPROGRESS);
#endif
        if (!in_progress) {
            CLOSESOCKET(fd);
            return -1;
        }
#if !defined(_WIN32)
        if (fd < 0 || fd >= FD_SETSIZE) {
            CLOSESOCKET(fd);
            return -1;
        }
#endif
        fd_set wset, eset;
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        FD_SET((unsigned)fd, &wset);
        FD_SET((unsigned)fd, &eset);
        struct timeval tv;
        tv.tv_sec = connect_ms / 1000;
        tv.tv_usec = (connect_ms % 1000) * 1000;
        int sr = select(fd + 1, NULL, &wset, &eset, &tv);
        if (sr <= 0) {
            CLOSESOCKET(fd);
            return -1;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&soerr, &slen) != 0 || soerr != 0) {
            CLOSESOCKET(fd);
            return -1;
        }
    }
    if (speer_tcp_set_nonblocking(fd, 0) != 0) {
        CLOSESOCKET(fd);
        return -1;
    }
    if (out_fd) *out_fd = fd;
    return 0;
}

static int tcp_listen_op(speer_transport_endpoint_t **out_ep, const char *addr, void *cfg) {
    (void)cfg;
    if (!addr) return SPEER_TR_INVALID;
    char host[64] = {0};
    uint16_t port = 0;
    const char *colon = NULL;
    for (const char *p = addr; *p; p++)
        if (*p == ':') colon = p;
    if (!colon) return SPEER_TR_INVALID;
    size_t hl = (size_t)(colon - addr);
    if (hl >= sizeof(host)) return SPEER_TR_INVALID;
    if (hl > 0) COPY(host, addr, hl);
    port = (uint16_t)atoi(colon + 1);

    speer_transport_endpoint_t *ep = (speer_transport_endpoint_t *)calloc(1, sizeof(*ep));
    if (!ep) return SPEER_TR_FAIL;
    if (speer_tcp_listen(&ep->listen_fd, hl > 0 ? host : NULL, port) < 0) {
        free(ep);
        return SPEER_TR_FAIL;
    }
    *out_ep = ep;
    return SPEER_TR_OK;
}

#define SPEER_TCP_MAX_CONN    1024
#define SPEER_TCP_MAX_PER_SEC 128

static uint64_t g_tcp_window_start_ms = 0;
static uint32_t g_tcp_window_count = 0;
static uint32_t g_tcp_active_conns = 0;

static int tcp_rate_limit(void) {
    uint64_t now = speer_timestamp_ms();
    if (now - g_tcp_window_start_ms >= 1000) {
        g_tcp_window_start_ms = now;
        g_tcp_window_count = 0;
    }
    if (g_tcp_window_count >= SPEER_TCP_MAX_PER_SEC) return -1;
    if (g_tcp_active_conns >= SPEER_TCP_MAX_CONN) return -1;
    g_tcp_window_count++;
    g_tcp_active_conns++;
    return 0;
}

static void tcp_rate_release(void) {
    if (g_tcp_active_conns > 0) g_tcp_active_conns--;
}

static int tcp_dial_op(speer_transport_conn_t **out_conn, const char *addr, void *cfg) {
    (void)cfg;
    if (!addr) return SPEER_TR_INVALID;
    if (tcp_rate_limit() != 0) return SPEER_TR_AGAIN;
    char host[46] = {0};
    const char *colon = NULL;
    for (const char *p = addr; *p; p++)
        if (*p == ':') colon = p;
    if (!colon) {
        tcp_rate_release();
        return SPEER_TR_INVALID;
    }
    size_t hl = (size_t)(colon - addr);
    if (hl >= sizeof(host)) {
        tcp_rate_release();
        return SPEER_TR_INVALID;
    }
    COPY(host, addr, hl);
    uint16_t port = (uint16_t)atoi(colon + 1);

    speer_transport_conn_t *c = (speer_transport_conn_t *)calloc(1, sizeof(*c));
    if (!c) {
        tcp_rate_release();
        return SPEER_TR_FAIL;
    }
    if (speer_tcp_dial(&c->fd, host, port) < 0) {
        free(c);
        tcp_rate_release();
        return SPEER_TR_REFUSED;
    }
    snprintf(c->peer_addr, sizeof(c->peer_addr), "%s:%u", host, (unsigned)port);
    *out_conn = c;
    return SPEER_TR_OK;
}

static int tcp_accept_op(speer_transport_endpoint_t *ep, speer_transport_conn_t **out_conn) {
    if (tcp_rate_limit() != 0) return SPEER_TR_AGAIN;
    speer_transport_conn_t *c = (speer_transport_conn_t *)calloc(1, sizeof(*c));
    if (!c) {
        tcp_rate_release();
        return SPEER_TR_FAIL;
    }
    if (speer_tcp_accept(ep->listen_fd, &c->fd, c->peer_addr, sizeof(c->peer_addr)) < 0) {
        free(c);
        tcp_rate_release();
        return SPEER_TR_AGAIN;
    }
    *out_conn = c;
    return SPEER_TR_OK;
}

static int tcp_send_op(speer_transport_conn_t *c, const uint8_t *d, size_t l, size_t *sent) {
    return speer_tcp_send(c->fd, d, l, sent) < 0 ? SPEER_TR_FAIL : SPEER_TR_OK;
}
static int tcp_recv_op(speer_transport_conn_t *c, uint8_t *b, size_t cap, size_t *rl) {
    int rc = speer_tcp_recv(c->fd, b, cap, rl);
    if (rc < 0) return SPEER_TR_FAIL;
    if (rc == 1) return SPEER_TR_EOF;
    return SPEER_TR_OK;
}
static int tcp_close_conn_op(speer_transport_conn_t *c) {
    speer_tcp_close(c->fd);
    free(c);
    tcp_rate_release();
    return SPEER_TR_OK;
}
static int tcp_close_endpoint_op(speer_transport_endpoint_t *ep) {
    speer_tcp_close(ep->listen_fd);
    free(ep);
    return SPEER_TR_OK;
}
static int tcp_peer_addr_op(speer_transport_conn_t *c, char *o, size_t cap) {
    if (!o || cap == 0) return SPEER_TR_INVALID;
    size_t i = 0;
    for (; i + 1 < cap && i < sizeof(c->peer_addr) && c->peer_addr[i] != '\0'; i++) {
        o[i] = c->peer_addr[i];
    }
    o[i] = '\0';
    return SPEER_TR_OK;
}
static int tcp_local_addr_op(speer_transport_endpoint_t *ep, char *o, size_t cap) {
    (void)ep;
    if (cap > 0) o[0] = 0;
    return SPEER_TR_OK;
}
static int tcp_set_nb_op(speer_transport_conn_t *c, int y) {
    return speer_tcp_set_nonblocking(c->fd, y);
}

const speer_transport_ops_t speer_transport_tcp_ops = {.name = "tcp",
                                                       .kind = SPEER_TR_STREAM,
                                                       .listen = tcp_listen_op,
                                                       .dial = tcp_dial_op,
                                                       .accept = tcp_accept_op,
                                                       .send = tcp_send_op,
                                                       .recv = tcp_recv_op,
                                                       .close_conn = tcp_close_conn_op,
                                                       .close_endpoint = tcp_close_endpoint_op,
                                                       .peer_addr = tcp_peer_addr_op,
                                                       .local_addr = tcp_local_addr_op,
                                                       .set_nonblocking = tcp_set_nb_op};
