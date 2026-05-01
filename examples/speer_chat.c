#include "speer_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ed25519.h"
#include "identify.h"
#include "libp2p_noise.h"
#include "mdns.h"
#include "multistream.h"
#include "peer_id.h"
#include "protobuf.h"
#include "transport_tcp.h"
#include "varint.h"
#include "yamux.h"

#if defined(_WIN32)
#include <windows.h>

#include <conio.h>
#define THREAD_T HANDLE
#define THREAD_CREATE(t, fn, arg) \
    (*(t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(fn), (arg), 0, NULL))
#define THREAD_RET       DWORD WINAPI
#define THREAD_RET_VAL   0
#define MUTEX_T          CRITICAL_SECTION
#define MUTEX_INIT(m)    InitializeCriticalSection(m)
#define MUTEX_LOCK(m)    EnterCriticalSection(m)
#define MUTEX_UNLOCK(m)  LeaveCriticalSection(m)
#define MUTEX_DESTROY(m) DeleteCriticalSection(m)
static void thread_sleep_ms(int ms) {
    Sleep((DWORD)ms);
}
#else
#include <sys/time.h>
#include <pthread.h>
#define THREAD_T                  pthread_t
#define THREAD_CREATE(t, fn, arg) pthread_create((t), NULL, (fn), (arg))
#define THREAD_RET                void *
#define THREAD_RET_VAL            NULL
#define MUTEX_T                   pthread_mutex_t
#define MUTEX_INIT(m)             pthread_mutex_init((m), NULL)
#define MUTEX_LOCK(m)             pthread_mutex_lock(m)
#define MUTEX_UNLOCK(m)           pthread_mutex_unlock(m)
#define MUTEX_DESTROY(m)          pthread_mutex_destroy(m)
static void thread_sleep_ms(int ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000};
    nanosleep(&ts, NULL);
}
#endif

#define CHAT_PROTO          "/speer/chat/1.0.0"
#define CHAT_SERVICE_TYPE   "_speer-chat._tcp"
#define MAX_PEERS           16
#define MAX_NICK_LEN        32
#define MAX_TEXT_LEN        1024
#define POLL_TIMEOUT_MS     200
#define HANDSHAKE_TIMEOUT_S 10

#define CHAT_TYPE_HELLO     1
#define CHAT_TYPE_MSG       2
#define CHAT_TYPE_BYE       3

#define MAX_NOISE_FRAME     65535

#define ANSI_RESET      "\033[0m"
#define ANSI_DIM        "\033[2m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_CYAN       "\033[36m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_RED        "\033[31m"
#define ANSI_BLUE       "\033[34m"
#define ANSI_CLEAR_LINE "\r\033[K"

typedef struct outmsg {
    struct outmsg *next;
    uint32_t type;
    size_t text_len;
    char text[MAX_TEXT_LEN];
} outmsg_t;

typedef struct peer_s {
    int active;
    int initiator;
    int fd;
    char addr[64];
    char remote_nick[MAX_NICK_LEN];
    char remote_pid[64];

    speer_libp2p_noise_t noise;
    speer_yamux_session_t mux;
    speer_yamux_stream_t *chat_st;

    MUTEX_T out_mu;
    outmsg_t *out_head;
    outmsg_t *out_tail;

    THREAD_T thread;
    int handshake_done;
    int dead;
} peer_t;

typedef struct {
    peer_t peers[MAX_PEERS];
    MUTEX_T mu;
} peer_table_t;

static peer_table_t g_peers;
static MUTEX_T g_log_mu;
static volatile int g_quit = 0;
static char g_my_nick[MAX_NICK_LEN] = "anon";
static char g_my_pid_b58[64] = "";
static uint16_t g_listen_port = 0;
static uint8_t g_my_static_pub[32], g_my_static_priv[32];
static uint8_t g_my_ed_pub[32], g_my_ed_seed[32];

static void log_event(const char *colour, const char *prefix, const char *fmt, ...) {
    MUTEX_LOCK(&g_log_mu);
    fprintf(stderr, ANSI_CLEAR_LINE);
    fprintf(stderr, "%s%s%s ", colour ? colour : "", prefix ? prefix : "", ANSI_RESET);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n%s> %s", ANSI_DIM, ANSI_RESET);
    fflush(stderr);
    MUTEX_UNLOCK(&g_log_mu);
}

static void discover_lan_ip(char *out, size_t cap) {
    snprintf(out, cap, "127.0.0.1");
#if defined(_WIN32)
    static int wsa_inited = 0;
    if (!wsa_inited) {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
        wsa_inited = 1;
    }
#endif
    int s = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    if (speer_tcp_set_nonblocking(s, 1) != 0) {
        CLOSESOCKET(s);
        return;
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = htonl(0x01010101);
    (void)connect(s, (struct sockaddr *)&dst, sizeof(dst));
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    socklen_t ll = sizeof(local);
    if (getsockname(s, (struct sockaddr *)&local, &ll) == 0 && local.sin_addr.s_addr != 0) {
        unsigned long a = ntohl(local.sin_addr.s_addr);
        snprintf(out, cap, "%lu.%lu.%lu.%lu", (a >> 24) & 0xff, (a >> 16) & 0xff, (a >> 8) & 0xff,
                 a & 0xff);
    }
    CLOSESOCKET(s);
}

static void truncate_pid(char *out, size_t cap, const char *full) {
    size_t fl = strlen(full);
    if (fl <= 14 || cap < 16) {
        snprintf(out, cap, "%s", full);
        return;
    }
    snprintf(out, cap, "%.6s..%.6s", full, full + fl - 6);
}

static int chat_frame_encode(uint8_t *out, size_t cap, size_t *out_len, uint32_t type,
                             const char *nick, const char *text) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, (int32_t)type) != 0) return -1;
    if (nick && nick[0])
        if (speer_pb_write_string_field(&w, 2, nick) != 0) return -1;
    if (text && text[0])
        if (speer_pb_write_string_field(&w, 3, text) != 0) return -1;
    *out_len = w.pos;
    return 0;
}

static int chat_frame_decode(const uint8_t *in, size_t len, uint32_t *type, char *nick,
                             size_t nick_cap, char *text, size_t text_cap) {
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, in, len);
    *type = 0;
    nick[0] = 0;
    text[0] = 0;
    while (r.pos < r.len) {
        uint32_t f, w;
        if (speer_pb_read_tag(&r, &f, &w) != 0) return -1;
        if (f == 1 && w == PB_WIRE_VARINT) {
            uint64_t v;
            if (speer_pb_read_varint(&r, &v) != 0) return -1;
            *type = (uint32_t)v;
        } else if (f == 2 && w == PB_WIRE_LEN) {
            const uint8_t *d;
            size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
            if (l >= nick_cap) l = nick_cap - 1;
            memcpy(nick, d, l);
            nick[l] = 0;
        } else if (f == 3 && w == PB_WIRE_LEN) {
            const uint8_t *d;
            size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
            if (l >= text_cap) l = text_cap - 1;
            memcpy(text, d, l);
            text[l] = 0;
        } else {
            if (speer_pb_skip(&r, w) != 0) return -1;
        }
    }
    return 0;
}

typedef struct {
    int fd;
    speer_libp2p_noise_t *noise;
    uint8_t q[MAX_NOISE_FRAME];
    size_t q_len;
    size_t q_off;
} ioctx_t;

static int tcp_plain_send(void *user, const uint8_t *d, size_t n) {
    int fd = *(int *)user;
    return speer_tcp_send_all(fd, d, n);
}
static int tcp_plain_recv(void *user, uint8_t *b, size_t cap, size_t *out_n) {
    int fd = *(int *)user;
    if (speer_tcp_recv_all(fd, b, cap) != 0) return -1;
    if (out_n) *out_n = cap;
    return 0;
}
static int noise_send_frame(int fd, const uint8_t *m, size_t n) {
    if (n > 0xffff) return -1;
    uint8_t h[2] = {(uint8_t)(n >> 8), (uint8_t)n};
    if (speer_tcp_send_all(fd, h, 2) != 0) return -1;
    return speer_tcp_send_all(fd, m, n);
}
static int noise_recv_frame(int fd, uint8_t *m, size_t cap, size_t *o) {
    uint8_t h[2];
    if (speer_tcp_recv_all(fd, h, 2) != 0) return -1;
    size_t n = ((size_t)h[0] << 8) | h[1];
    if (n > cap) return -1;
    if (speer_tcp_recv_all(fd, m, n) != 0) return -1;
    *o = n;
    return 0;
}
static int io_crypt_send(void *user, const uint8_t *d, size_t n) {
    ioctx_t *io = (ioctx_t *)user;
    while (n > 0) {
        size_t chunk = n > 65519 ? 65519 : n;
        uint8_t ct[65535 + 16];
        size_t ct_len;
        if (speer_libp2p_noise_seal(io->noise, d, chunk, ct, &ct_len) != 0) return -1;
        if (ct_len > 0xffff) return -1;
        uint8_t h[2] = {(uint8_t)(ct_len >> 8), (uint8_t)ct_len};
        if (speer_tcp_send_all(io->fd, h, 2) != 0) return -1;
        if (speer_tcp_send_all(io->fd, ct, ct_len) != 0) return -1;
        d += chunk;
        n -= chunk;
    }
    return 0;
}
static int io_crypt_recv(void *user, uint8_t *b, size_t cap, size_t *out_n) {
    ioctx_t *io = (ioctx_t *)user;
    size_t got = 0;
    while (got < cap) {
        if (io->q_off < io->q_len) {
            size_t take = io->q_len - io->q_off;
            if (take > cap - got) take = cap - got;
            memcpy(b + got, io->q + io->q_off, take);
            io->q_off += take;
            got += take;
            if (io->q_off >= io->q_len) io->q_off = io->q_len = 0;
            continue;
        }
        uint8_t lb[2];
        if (speer_tcp_recv_all(io->fd, lb, 2) != 0) return -1;
        size_t ct_len = ((size_t)lb[0] << 8) | lb[1];
        if (ct_len < 16 || ct_len > sizeof(io->q)) return -1;
        uint8_t ct[MAX_NOISE_FRAME];
        if (speer_tcp_recv_all(io->fd, ct, ct_len) != 0) return -1;
        size_t pt = 0;
        if (speer_libp2p_noise_open(io->noise, ct, ct_len, io->q, &pt) != 0) return -1;
        io->q_len = pt;
        io->q_off = 0;
    }
    *out_n = got;
    return 0;
}

typedef struct {
    speer_yamux_session_t *mux;
    speer_yamux_stream_t *st;
} ymux_io_t;
static int ymux_send(void *user, const uint8_t *d, size_t n) {
    ymux_io_t *io = (ymux_io_t *)user;
    return speer_yamux_stream_write(io->mux, io->st, d, n);
}
static int ymux_recv(void *user, uint8_t *b, size_t cap, size_t *out_n) {
    ymux_io_t *io = (ymux_io_t *)user;
    while (io->st->recv_buf_len < cap) {
        if (io->st->reset) return -1;
        if (io->st->remote_closed && io->st->recv_buf_len < cap) return -1;
        if (speer_yamux_pump(io->mux) != 0) return -1;
    }
    memcpy(b, io->st->recv_buf, cap);
    memmove(io->st->recv_buf, io->st->recv_buf + cap, io->st->recv_buf_len - cap);
    io->st->recv_buf_len -= cap;
    *out_n = cap;
    return 0;
}

static int build_id_payload(speer_libp2p_noise_t *n, uint8_t *out, size_t cap, size_t *out_len) {
    uint8_t sig[64];
    size_t sig_len = 0;
    if (speer_libp2p_noise_sign_static(sig, sizeof(sig), &sig_len, n->local_keytype,
                                       n->local_libp2p_priv, n->local_libp2p_priv_len,
                                       n->local_static_pub) != 0)
        return -1;
    return speer_libp2p_noise_payload_make(out, cap, out_len, n->local_keytype, n->local_libp2p_pub,
                                           n->local_libp2p_pub_len, sig, sig_len);
}
static int verify_id_payload(speer_libp2p_noise_t *n, const uint8_t *p, size_t pl) {
    speer_libp2p_keytype_t kt;
    const uint8_t *id = NULL, *sig = NULL;
    size_t idl = 0, sl = 0;
    if (speer_libp2p_noise_payload_parse(p, pl, &kt, &id, &idl, &sig, &sl) != 0) return -1;
    if (speer_libp2p_noise_verify_static(kt, id, idl, n->hs.remote_pubkey, sig, sl) != 0) return -1;
    if (idl > sizeof(n->remote_libp2p_pub)) return -1;
    memcpy(n->remote_libp2p_pub, id, idl);
    n->remote_libp2p_pub_len = idl;
    n->remote_keytype = kt;
    memcpy(n->remote_static_pub, n->hs.remote_pubkey, 32);
    return 0;
}
static int noise_handshake_initiator(int fd, speer_libp2p_noise_t *n) {
    uint8_t m1[32];
    if (speer_noise_xx_write_msg1(&n->hs, m1) != 0) return -1;
    if (noise_send_frame(fd, m1, 32) != 0) return -1;
    uint8_t m2[2048];
    size_t m2l = 0;
    if (noise_recv_frame(fd, m2, sizeof(m2), &m2l) != 0) return -1;
    uint8_t pl[2048];
    size_t pll = 0;
    if (speer_noise_xx_read_msg2_p(&n->hs, m2, m2l, pl, sizeof(pl), &pll) != 0) return -1;
    if (verify_id_payload(n, pl, pll) != 0) return -1;
    uint8_t ip[1024];
    size_t ipl = 0;
    if (build_id_payload(n, ip, sizeof(ip), &ipl) != 0) return -1;
    uint8_t m3[2048];
    size_t m3l = 0;
    if (speer_noise_xx_write_msg3_p(&n->hs, ip, ipl, m3, sizeof(m3), &m3l) != 0) return -1;
    if (noise_send_frame(fd, m3, m3l) != 0) return -1;
    speer_noise_xx_split(&n->hs, n->send_key, n->recv_key);
    n->send_nonce = n->recv_nonce = 0;
    return 0;
}
static int noise_handshake_responder(int fd, speer_libp2p_noise_t *n) {
    uint8_t m1[64];
    size_t m1l = 0;
    if (noise_recv_frame(fd, m1, sizeof(m1), &m1l) != 0) return -1;
    if (m1l != 32) return -1;
    if (speer_noise_xx_read_msg1(&n->hs, m1) != 0) return -1;
    uint8_t ip[1024];
    size_t ipl = 0;
    if (build_id_payload(n, ip, sizeof(ip), &ipl) != 0) return -1;
    uint8_t m2[2048];
    size_t m2l = 0;
    if (speer_noise_xx_write_msg2_p(&n->hs, ip, ipl, m2, sizeof(m2), &m2l) != 0) return -1;
    if (noise_send_frame(fd, m2, m2l) != 0) return -1;
    uint8_t m3[2048];
    size_t m3l = 0;
    if (noise_recv_frame(fd, m3, sizeof(m3), &m3l) != 0) return -1;
    uint8_t pl[2048];
    size_t pll = 0;
    if (speer_noise_xx_read_msg3_p(&n->hs, m3, m3l, pl, sizeof(pl), &pll) != 0) return -1;
    if (verify_id_payload(n, pl, pll) != 0) return -1;
    speer_noise_xx_split(&n->hs, n->recv_key, n->send_key);
    n->send_nonce = n->recv_nonce = 0;
    return 0;
}

static int derive_remote_pid_b58(const speer_libp2p_noise_t *n, char *out, size_t cap) {
    uint8_t pkproto[1024];
    size_t pkpl = 0;
    if (speer_libp2p_pubkey_proto_encode(pkproto, sizeof(pkproto), n->remote_keytype,
                                         n->remote_libp2p_pub, n->remote_libp2p_pub_len,
                                         &pkpl) != 0)
        return -1;
    uint8_t pid[64];
    size_t pidl = 0;
    if (speer_peer_id_from_pubkey_bytes(pid, sizeof(pid), pkproto, pkpl, &pidl) != 0) return -1;
    return speer_peer_id_to_b58(out, cap, pid, pidl);
}

static peer_t *peer_alloc(void) {
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!g_peers.peers[i].active) {
            peer_t *p = &g_peers.peers[i];
            memset(p, 0, sizeof(*p));
            MUTEX_INIT(&p->out_mu);
            p->active = 1;
            p->fd = -1;
            MUTEX_UNLOCK(&g_peers.mu);
            return p;
        }
    }
    MUTEX_UNLOCK(&g_peers.mu);
    return NULL;
}

static void peer_release(peer_t *p) {
    MUTEX_LOCK(&g_peers.mu);
    if (p->fd >= 0) speer_tcp_close(p->fd);
    p->fd = -1;
    p->active = 0;
    p->dead = 1;
    MUTEX_LOCK(&p->out_mu);
    outmsg_t *m = p->out_head;
    while (m) {
        outmsg_t *n = m->next;
        free(m);
        m = n;
    }
    p->out_head = p->out_tail = NULL;
    MUTEX_UNLOCK(&p->out_mu);
    MUTEX_DESTROY(&p->out_mu);
    MUTEX_UNLOCK(&g_peers.mu);
}

static int peer_already_connected(const char *pid_b58) {
    if (!pid_b58 || !pid_b58[0]) return 0;
    int found = 0;
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && strcmp(p->remote_pid, pid_b58) == 0) {
            found = 1;
            break;
        }
    }
    MUTEX_UNLOCK(&g_peers.mu);
    return found;
}

static void peer_enqueue(peer_t *p, uint32_t type, const char *text) {
    outmsg_t *m = (outmsg_t *)calloc(1, sizeof(*m));
    if (!m) return;
    m->type = type;
    if (text) {
        size_t l = strlen(text);
        if (l >= sizeof(m->text)) l = sizeof(m->text) - 1;
        memcpy(m->text, text, l);
        m->text_len = l;
    }
    MUTEX_LOCK(&p->out_mu);
    if (p->out_tail)
        p->out_tail->next = m;
    else
        p->out_head = m;
    p->out_tail = m;
    MUTEX_UNLOCK(&p->out_mu);
}

static outmsg_t *peer_dequeue(peer_t *p) {
    MUTEX_LOCK(&p->out_mu);
    outmsg_t *m = p->out_head;
    if (m) {
        p->out_head = m->next;
        if (!p->out_head) p->out_tail = NULL;
    }
    MUTEX_UNLOCK(&p->out_mu);
    return m;
}

static void broadcast(uint32_t type, const char *text) {
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && p->handshake_done) peer_enqueue(p, type, text);
    }
    MUTEX_UNLOCK(&g_peers.mu);
}

static THREAD_RET peer_pump(void *arg) {
    peer_t *p = (peer_t *)arg;

    if (speer_libp2p_noise_init(&p->noise, g_my_static_pub, g_my_static_priv,
                                SPEER_LIBP2P_KEY_ED25519, g_my_ed_pub, 32, g_my_ed_seed, 32) != 0) {
        log_event(ANSI_RED, "[err]", "noise_init failed for %s", p->addr);
        peer_release(p);
        return THREAD_RET_VAL;
    }

    speer_tcp_set_io_timeout(p->fd, HANDSHAKE_TIMEOUT_S * 1000);

    if (p->initiator) {
        if (speer_ms_negotiate_initiator(&p->fd, tcp_plain_send, tcp_plain_recv, "/noise") != 0) {
            log_event(ANSI_RED, "[err]", "%s: noise multistream failed", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
        if (noise_handshake_initiator(p->fd, &p->noise) != 0) {
            log_event(ANSI_RED, "[err]", "%s: noise handshake failed", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
    } else {
        const char *protos[1] = {"/noise"};
        size_t sel = 0;
        if (speer_ms_negotiate_listener(&p->fd, tcp_plain_send, tcp_plain_recv, protos, 1, &sel) !=
            0) {
            log_event(ANSI_RED, "[err]", "%s: noise multistream (listener) failed", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
        if (noise_handshake_responder(p->fd, &p->noise) != 0) {
            log_event(ANSI_RED, "[err]", "%s: noise handshake (responder) failed", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
    }

    char pid_b58[64];
    if (derive_remote_pid_b58(&p->noise, pid_b58, sizeof(pid_b58)) != 0)
        snprintf(pid_b58, sizeof(pid_b58), "(unknown)");
    truncate_pid(p->remote_pid, sizeof(p->remote_pid), pid_b58);

    if (strcmp(pid_b58, g_my_pid_b58) == 0) {
        peer_release(p);
        return THREAD_RET_VAL;
    }

    ioctx_t io = {.fd = p->fd, .noise = &p->noise};
    if (p->initiator) {
        if (speer_ms_negotiate_initiator(&io, io_crypt_send, io_crypt_recv, "/yamux/1.0.0") != 0) {
            log_event(ANSI_RED, "[err]", "%s: yamux multistream failed", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
    } else {
        const char *protos[1] = {"/yamux/1.0.0"};
        size_t sel = 0;
        if (speer_ms_negotiate_listener(&io, io_crypt_send, io_crypt_recv, protos, 1, &sel) != 0) {
            log_event(ANSI_RED, "[err]", "%s: yamux multistream (listener) failed", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
    }

    speer_yamux_init(&p->mux, p->initiator, io_crypt_send, io_crypt_recv, &io);

    if (p->initiator) {
        p->chat_st = speer_yamux_open_stream(&p->mux);
        if (!p->chat_st) {
            log_event(ANSI_RED, "[err]", "%s: yamux open stream failed", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
        ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};
        if (speer_ms_negotiate_initiator(&sio, ymux_send, ymux_recv, CHAT_PROTO) != 0) {
            log_event(ANSI_RED, "[err]", "%s: chat-stream negotiate failed", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
    } else {
        for (int waited_ms = 0; !p->chat_st && waited_ms < HANDSHAKE_TIMEOUT_S * 1000;
             waited_ms += 50) {
            (void)speer_yamux_pump(&p->mux);
            if (p->mux.streams) p->chat_st = p->mux.streams;
            if (!p->chat_st) thread_sleep_ms(50);
        }
        if (!p->chat_st) {
            log_event(ANSI_RED, "[err]", "%s: no inbound chat stream", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
        const char *protos[1] = {CHAT_PROTO};
        size_t sel = 0;
        ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};
        if (speer_ms_negotiate_listener(&sio, ymux_send, ymux_recv, protos, 1, &sel) != 0) {
            log_event(ANSI_RED, "[err]", "%s: chat-stream negotiate (listener) failed", p->addr);
            peer_release(p);
            return THREAD_RET_VAL;
        }
    }

    {
        uint8_t frame[256 + MAX_NICK_LEN];
        size_t fl = 0;
        if (chat_frame_encode(frame, sizeof(frame), &fl, CHAT_TYPE_HELLO, g_my_nick, NULL) == 0) {
            uint8_t lp[10];
            size_t hl = speer_uvarint_encode(lp, sizeof(lp), fl);
            ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};
            (void)ymux_send(&sio, lp, hl);
            (void)ymux_send(&sio, frame, fl);
        }
    }

    p->handshake_done = 1;
    log_event(ANSI_GREEN, "[+joined]", "%s%s%s %s(%s)%s from %s", ANSI_BOLD,
              p->remote_nick[0] ? p->remote_nick : "?", ANSI_RESET, ANSI_DIM, p->remote_pid,
              ANSI_RESET, p->addr);

    speer_tcp_set_io_timeout(p->fd, POLL_TIMEOUT_MS);

    while (!g_quit && !p->dead) {
        outmsg_t *m;
        while ((m = peer_dequeue(p)) != NULL) {
            uint8_t frame[MAX_TEXT_LEN + 256];
            size_t fl = 0;
            if (chat_frame_encode(frame, sizeof(frame), &fl, m->type, g_my_nick, m->text) == 0) {
                uint8_t lp[10];
                size_t hl = speer_uvarint_encode(lp, sizeof(lp), fl);
                ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};
                if (ymux_send(&sio, lp, hl) != 0) {
                    free(m);
                    p->dead = 1;
                    goto done;
                }
                if (ymux_send(&sio, frame, fl) != 0) {
                    free(m);
                    p->dead = 1;
                    goto done;
                }
            }
            free(m);
        }

        ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};
        uint8_t lp[10];
        size_t lp_off = 0;
        size_t got = 0;
        int read_ok = 1;
        while (lp_off < sizeof(lp)) {
            if (ymux_recv(&sio, lp + lp_off, 1, &got) != 0 || got != 1) {
                read_ok = 0;
                break;
            }
            lp_off++;
            if ((lp[lp_off - 1] & 0x80) == 0) break;
        }
        if (!read_ok) continue;
        uint64_t flen = 0;
        if (speer_uvarint_decode(lp, lp_off, &flen) == 0 || flen == 0 || flen > MAX_TEXT_LEN + 64) {
            p->dead = 1;
            break;
        }
        uint8_t frame[MAX_TEXT_LEN + 256];
        if (ymux_recv(&sio, frame, (size_t)flen, &got) != 0 || got != flen) {
            p->dead = 1;
            break;
        }
        uint32_t type = 0;
        char nick[MAX_NICK_LEN], text[MAX_TEXT_LEN];
        if (chat_frame_decode(frame, (size_t)flen, &type, nick, sizeof(nick), text, sizeof(text)) !=
            0)
            continue;
        if (nick[0]) {
            size_t l = strlen(nick);
            if (l >= sizeof(p->remote_nick)) l = sizeof(p->remote_nick) - 1;
            memcpy(p->remote_nick, nick, l);
            p->remote_nick[l] = 0;
        }
        if (type == CHAT_TYPE_MSG) {
            log_event(ANSI_CYAN, "", "%s<%s>%s %s%s%s %s", ANSI_BOLD,
                      p->remote_nick[0] ? p->remote_nick : "?", ANSI_RESET, ANSI_DIM, p->remote_pid,
                      ANSI_RESET, text);
        } else if (type == CHAT_TYPE_HELLO) {
            log_event(ANSI_GREEN, "[hello]", "from %s%s%s (%s%s%s)", ANSI_BOLD,
                      p->remote_nick[0] ? p->remote_nick : "?", ANSI_RESET, ANSI_DIM, p->remote_pid,
                      ANSI_RESET);
        } else if (type == CHAT_TYPE_BYE) {
            break;
        }
    }

done:
    log_event(ANSI_YELLOW, "[-left]", "%s (%s)", p->remote_nick[0] ? p->remote_nick : p->addr,
              p->remote_pid);
    peer_release(p);
    return THREAD_RET_VAL;
}

typedef struct {
    int listen_fd;
    mdns_ctx_t *mctx;
    char self_pid[64];
    char self_lan_ip[64];
    MUTEX_T attempted_mu;
    char attempted_pids[MAX_PEERS * 2][64];
    int num_attempted;
} disc_state_t;

static int already_attempted(disc_state_t *st, const char *pid) {
    int found = 0;
    MUTEX_LOCK(&st->attempted_mu);
    for (int i = 0; i < st->num_attempted; i++) {
        if (strcmp(st->attempted_pids[i], pid) == 0) {
            found = 1;
            break;
        }
    }
    if (!found && st->num_attempted < (int)(sizeof(st->attempted_pids) / sizeof(st->attempted_pids[0]))) {
        snprintf(st->attempted_pids[st->num_attempted], sizeof(st->attempted_pids[0]), "%s", pid);
        st->num_attempted++;
    }
    MUTEX_UNLOCK(&st->attempted_mu);
    return found;
}

static void on_mdns_discover(void *user, const char *peer_id, const char *multiaddr) {
    disc_state_t *st = (disc_state_t *)user;
    if (!peer_id || !peer_id[0] || !multiaddr) return;
    if (strcmp(peer_id, st->self_pid) == 0) return;
    if (peer_already_connected(peer_id)) return;
    if (already_attempted(st, peer_id)) return;

    const char *ip_p = strstr(multiaddr, "/ip4/");
    const char *tcp_p = strstr(multiaddr, "/tcp/");
    if (!ip_p || !tcp_p) return;
    char host[64];
    size_t hl = (size_t)(tcp_p - (ip_p + 5));
    if (hl >= sizeof(host)) return;
    memcpy(host, ip_p + 5, hl);
    host[hl] = 0;
    int port = atoi(tcp_p + 5);
    if (port <= 0 || port > 65535) return;

    if (strcmp(st->self_pid, peer_id) > 0) return;

    int fd = -1;
    if (speer_tcp_dial_timeout(&fd, host, (uint16_t)port, 3000) != 0) return;

    peer_t *p = peer_alloc();
    if (!p) {
        speer_tcp_close(fd);
        return;
    }
    p->fd = fd;
    p->initiator = 1;
    snprintf(p->addr, sizeof(p->addr), "%s:%d", host, port);
    truncate_pid(p->remote_pid, sizeof(p->remote_pid), peer_id);
    log_event(ANSI_BLUE, "[dial]", "%s (%s)", p->addr, p->remote_pid);
    THREAD_CREATE(&p->thread, peer_pump, p);
}

static THREAD_RET disc_accept_thread(void *arg) {
    disc_state_t *st = (disc_state_t *)arg;

    speer_tcp_set_nonblocking(st->listen_fd, 1);

    while (!g_quit) {
        int fd = -1;
        char peer_addr[64] = "";
        if (speer_tcp_accept(st->listen_fd, &fd, peer_addr, sizeof(peer_addr)) == 0 && fd >= 0) {
            peer_t *p = peer_alloc();
            if (!p) {
                speer_tcp_close(fd);
            } else {
                p->fd = fd;
                p->initiator = 0;
                snprintf(p->addr, sizeof(p->addr), "%s", peer_addr);
                log_event(ANSI_BLUE, "[accept]", "%s", p->addr);
                THREAD_CREATE(&p->thread, peer_pump, p);
            }
        }
        static int announce_acc = 0;
        announce_acc += POLL_TIMEOUT_MS;
        if (announce_acc >= 1000) {
            mdns_announce(st->mctx);
            mdns_query(st->mctx, CHAT_SERVICE_TYPE ".local");
            announce_acc = 0;
        }
        (void)mdns_poll(st->mctx, POLL_TIMEOUT_MS);
    }
    return THREAD_RET_VAL;
}

static void print_banner(void) {
    fprintf(stderr, "\n");
    fprintf(stderr, "  %sspeer-chat%s\n", ANSI_BOLD ANSI_GREEN, ANSI_RESET);
    fprintf(stderr, "  %snick=%s   peer-id=%s%s   listening :%u%s\n", ANSI_DIM, g_my_nick,
            g_my_pid_b58, ANSI_RESET, (unsigned)g_listen_port, "");
    fprintf(stderr,
            "  %send-to-end-encrypted (Noise XX) over libp2p TCP+Yamux  -  type /quit to "
            "exit%s\n",
            ANSI_DIM, ANSI_RESET);
    fprintf(stderr, "\n%s> %s", ANSI_DIM, ANSI_RESET);
    fflush(stderr);
}

int main(int argc, char **argv) {
    if (argc >= 2) {
        size_t l = strlen(argv[1]);
        if (l >= sizeof(g_my_nick)) l = sizeof(g_my_nick) - 1;
        memcpy(g_my_nick, argv[1], l);
        g_my_nick[l] = 0;
    }

    MUTEX_INIT(&g_log_mu);
    MUTEX_INIT(&g_peers.mu);

    if (speer_random_bytes_or_fail(g_my_static_priv, 32) != 0) return 1;
    speer_x25519_base(g_my_static_pub, g_my_static_priv);
    if (speer_random_bytes_or_fail(g_my_ed_seed, 32) != 0) return 1;
    speer_ed25519_keypair(g_my_ed_pub, g_my_ed_seed, g_my_ed_seed);

    uint8_t pkproto[64];
    size_t pkpl = 0;
    if (speer_libp2p_pubkey_proto_encode(pkproto, sizeof(pkproto), SPEER_LIBP2P_KEY_ED25519,
                                         g_my_ed_pub, 32, &pkpl) != 0) {
        fprintf(stderr, "pubkey encode failed\n");
        return 1;
    }
    uint8_t pid[64];
    size_t pidl = 0;
    if (speer_peer_id_from_pubkey_bytes(pid, sizeof(pid), pkproto, pkpl, &pidl) != 0) return 1;
    if (speer_peer_id_to_b58(g_my_pid_b58, sizeof(g_my_pid_b58), pid, pidl) != 0) return 1;

    int lfd = -1;
    if (speer_tcp_listen(&lfd, NULL, 0) != 0) {
        fprintf(stderr, "tcp listen failed\n");
        return 1;
    }
#if defined(_WIN32)
    SOCKET ls = (SOCKET)lfd;
    struct sockaddr_in sa;
    int sl = sizeof(sa);
#else
    int ls = lfd;
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
#endif
    memset(&sa, 0, sizeof(sa));
    if (getsockname((int)ls, (struct sockaddr *)&sa, &sl) != 0) {
        fprintf(stderr, "getsockname failed\n");
        return 1;
    }
    g_listen_port = ntohs(sa.sin_port);

    mdns_ctx_t mctx;
    if (mdns_init(&mctx) != 0) {
        fprintf(stderr, "mdns init failed (multicast might be blocked)\n");
        return 1;
    }
    char lan_ip[64];
    discover_lan_ip(lan_ip, sizeof(lan_ip));
    char multiaddr[256];
    snprintf(multiaddr, sizeof(multiaddr), "/ip4/%s/tcp/%u/p2p/%s", lan_ip, (unsigned)g_listen_port,
             g_my_pid_b58);
    char txt_field[512];
    int tfl = snprintf(txt_field, sizeof(txt_field), "dnsaddr=%s", multiaddr);
    if (tfl <= 0 || tfl >= 256) return 1;
    uint8_t txt_data[260];
    txt_data[0] = (uint8_t)tfl;
    memcpy(txt_data + 1, txt_field, (size_t)tfl);
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char rand_name[33];
    uint8_t rb[32];
    speer_random_bytes(rb, sizeof(rb));
    for (size_t i = 0; i < sizeof(rb); i++) rand_name[i] = alpha[rb[i] % (sizeof(alpha) - 1)];
    rand_name[sizeof(rb)] = 0;
    if (mdns_register_service(&mctx, rand_name, CHAT_SERVICE_TYPE, g_listen_port, txt_data,
                              (size_t)(tfl + 1)) != 0) {
        fprintf(stderr, "mdns register failed\n");
        return 1;
    }
    disc_state_t dst;
    memset(&dst, 0, sizeof(dst));
    dst.listen_fd = lfd;
    dst.mctx = &mctx;
    snprintf(dst.self_pid, sizeof(dst.self_pid), "%s", g_my_pid_b58);
    snprintf(dst.self_lan_ip, sizeof(dst.self_lan_ip), "%s", lan_ip);
    MUTEX_INIT(&dst.attempted_mu);
    mdns_set_discovery_callback(&mctx, on_mdns_discover, &dst);

    print_banner();

    THREAD_T disc_thread;
    THREAD_CREATE(&disc_thread, disc_accept_thread, &dst);

    mdns_announce(&mctx);
    mdns_query(&mctx, CHAT_SERVICE_TYPE ".local");

    char line[MAX_TEXT_LEN];
    while (fgets(line, sizeof(line), stdin)) {
        size_t l = strlen(line);
        while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) line[--l] = 0;
        if (l == 0) {
            fprintf(stderr, "%s> %s", ANSI_DIM, ANSI_RESET);
            fflush(stderr);
            continue;
        }
        if (strcmp(line, "/quit") == 0) break;
        if (strcmp(line, "/peers") == 0) {
            MUTEX_LOCK(&g_peers.mu);
            int n = 0;
            for (int i = 0; i < MAX_PEERS; i++) {
                peer_t *p = &g_peers.peers[i];
                if (p->active && !p->dead && p->handshake_done) n++;
            }
            fprintf(stderr, "  %d peer%s connected:\n", n, n == 1 ? "" : "s");
            for (int i = 0; i < MAX_PEERS; i++) {
                peer_t *p = &g_peers.peers[i];
                if (p->active && !p->dead && p->handshake_done) {
                    fprintf(stderr, "    %s%s%s  %s%s%s  %s\n", ANSI_BOLD,
                            p->remote_nick[0] ? p->remote_nick : "?", ANSI_RESET, ANSI_DIM,
                            p->remote_pid, ANSI_RESET, p->addr);
                }
            }
            MUTEX_UNLOCK(&g_peers.mu);
            fprintf(stderr, "%s> %s", ANSI_DIM, ANSI_RESET);
            fflush(stderr);
            continue;
        }

        broadcast(CHAT_TYPE_MSG, line);
        log_event(ANSI_GREEN, "", "%s<%s>%s (you) %s", ANSI_BOLD, g_my_nick, ANSI_RESET, line);
    }

    g_quit = 1;
    broadcast(CHAT_TYPE_BYE, NULL);
    thread_sleep_ms(200);

    speer_tcp_close(lfd);
    mdns_unregister_service(&mctx, rand_name);
    mdns_free(&mctx);

    return 0;
}
