#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#if !defined(_WIN32)
#define _GNU_SOURCE
#include <sys/random.h>
#endif

#include "speer_internal.h"

#if defined(_WIN32)
#include <windows.h>

#include <wincrypt.h>
#else
#include <sys/time.h>

#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
static int my_inet_pton(int af, const char *src, void *dst) {
    struct sockaddr_storage ss;
    char src_copy[256];
    size_t src_len = strlen(src);
    if (src_len >= sizeof(src_copy)) return 0;
    memcpy(src_copy, src, src_len + 1);

    ss.ss_family = (short)af;
    int size = sizeof(ss);
    if (WSAStringToAddressA(src_copy, af, NULL, (struct sockaddr *)&ss, &size) != 0) { return 0; }

    if (af == AF_INET) {
        memcpy(dst, &((struct sockaddr_in *)&ss)->sin_addr, 4);
    } else if (af == AF_INET6) {
        memcpy(dst, &((struct sockaddr_in6 *)&ss)->sin6_addr, 16);
    }
    return 1;
}

#define inet_pton my_inet_pton
#endif

int speer_socket_create(uint16_t port, const char *bind_addr) {
    SPEER_INIT_WINSOCK();

    int sock = (int)socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_storage addr;
    socklen_t addr_len;

    ZERO(&addr, sizeof(addr));

    struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
    addr_len = sizeof(struct sockaddr_in);

    if (bind_addr) {
        struct in_addr v4;
        struct in6_addr v6;
        if (inet_pton(AF_INET, bind_addr, &v4) == 1) {
            sin->sin_family = AF_INET;
            sin->sin_port = htons(port);
            sin->sin_addr = v4;
            addr_len = sizeof(struct sockaddr_in);
        } else if (inet_pton(AF_INET6, bind_addr, &v6) == 1) {
            CLOSESOCKET(sock);
            return -1;
        }
    }

    if (bind(sock, (struct sockaddr *)&addr, addr_len) < 0) {
        CLOSESOCKET(sock);
        return -1;
    }

    if (speer_fd_set_rcvtimeo_ms(sock, 1u) != 0) {
        CLOSESOCKET(sock);
        return -1;
    }

    return sock;
}

int speer_socket_recv(int sock, uint8_t *buf, size_t len, struct sockaddr_storage *addr,
                      socklen_t *addr_len) {
    *addr_len = sizeof(struct sockaddr_storage);
    int n = recvfrom(sock, (char *)buf, (int)len, 0, (struct sockaddr *)addr, addr_len);
    return n;
}

int speer_socket_send(int sock, const uint8_t *buf, size_t len, const struct sockaddr_storage *addr,
                      socklen_t addr_len) {
    int n = sendto(sock, (const char *)buf, (int)len, 0, (const struct sockaddr *)addr, addr_len);
    return n;
}

void speer_socket_close(int sock) {
    CLOSESOCKET(sock);
}

int speer_fd_set_nonblocking(int fd, int on) {
#if defined(_WIN32)
    u_long mode = on ? 1u : 0u;
    return ioctlsocket((SOCKET)fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    if (on)
        fl |= O_NONBLOCK;
    else
        fl &= ~O_NONBLOCK;
    if (fcntl(fd, F_SETFL, fl) < 0) return -1;
    return 0;
#endif
}

int speer_socket_set_nonblocking(int sock) {
    return speer_fd_set_nonblocking(sock, 1);
}

int speer_sockaddr_in_resolve(struct sockaddr_in *sin, const char *host, uint16_t port) {
    ZERO(sin, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    if (!host || host[0] == 0) {
        sin->sin_addr.s_addr = htonl(INADDR_ANY);
        return 0;
    }
#if defined(_WIN32)
    {
        struct sockaddr_in parsed;
        int sz = sizeof(parsed);
        ZERO(&parsed, sizeof(parsed));
        if (WSAStringToAddressA((char *)host, AF_INET, NULL, (struct sockaddr *)&parsed, &sz) ==
            0) {
            sin->sin_addr = parsed.sin_addr;
            return 0;
        }
    }
#else
    if (inet_pton(AF_INET, host, &sin->sin_addr) == 1) return 0;
#endif
    struct addrinfo hints;
    ZERO(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    int ok = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET && ai->ai_addrlen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in *r = (struct sockaddr_in *)ai->ai_addr;
            sin->sin_addr = r->sin_addr;
            ok = 0;
            break;
        }
    }
    freeaddrinfo(res);
    return ok;
}

static int sock_set_timeout_ms(int fd, int optname, unsigned ms) {
#if defined(_WIN32)
    DWORD tv = (DWORD)ms;
    return setsockopt(fd, SOL_SOCKET, optname, (const char *)&tv, sizeof(tv)) != 0 ? -1 : 0;
#else
    struct timeval tv;
    tv.tv_sec = (long)(ms / 1000u);
    tv.tv_usec = (long)((ms % 1000u) * 1000u);
    return setsockopt(fd, SOL_SOCKET, optname, (const char *)&tv, sizeof(tv)) != 0 ? -1 : 0;
#endif
}

int speer_fd_set_rcvtimeo_ms(int fd, unsigned ms) {
    return sock_set_timeout_ms(fd, SO_RCVTIMEO, ms);
}

int speer_fd_set_sndtimeo_ms(int fd, unsigned ms) {
    return sock_set_timeout_ms(fd, SO_SNDTIMEO, ms);
}

static int parse_address(const char *str, struct sockaddr_storage *addr, socklen_t *addr_len) {
    char host[256];
    char *port_str = NULL;

    COPY(host, str, sizeof(host) - 1);
    host[sizeof(host) - 1] = 0;

    char *bracket = strrchr(host, ']');
    if (host[0] == '[' && bracket) {
        *bracket = 0;
        port_str = bracket + 1;
        if (*port_str == ':') port_str++;

        struct in6_addr v6;
        if (inet_pton(AF_INET6, host + 1, &v6) == 1) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons(port_str ? (uint16_t)atoi(port_str) : 3478);
            sin6->sin6_addr = v6;
            *addr_len = sizeof(struct sockaddr_in6);
            return 0;
        }
    } else {
        char *colon = strrchr(host, ':');
        if (colon) {
            *colon = 0;
            port_str = colon + 1;
        }

        struct in_addr v4;
        if (inet_pton(AF_INET, host, &v4) == 1) {
            struct sockaddr_in *sin = (struct sockaddr_in *)addr;
            sin->sin_family = AF_INET;
            sin->sin_port = htons(port_str ? (uint16_t)atoi(port_str) : 3478);
            sin->sin_addr = v4;
            *addr_len = sizeof(struct sockaddr_in);
            return 0;
        }
    }

    return -1;
}

typedef struct {
    uint16_t msg_type;
    uint16_t msg_len;
    uint32_t magic;
    uint8_t tid[12];
} stun_header_t;

#define STUN_MAGIC_COOKIE            0x2112A442u
#define STUN_BINDING_REQUEST         0x0001
#define STUN_BINDING_RESPONSE        0x0101
#define STUN_ATTR_MAPPED_ADDRESS     0x0001
#define STUN_ATTR_XOR_MAPPED_ADDRESS 0x0020

int speer_stun_get_mapped_addr(const char *stun_server, struct sockaddr_storage *mapped_addr,
                               socklen_t *mapped_len) {
    struct sockaddr_storage stun_addr;
    socklen_t stun_addr_len;

    if (parse_address(stun_server, &stun_addr, &stun_addr_len) != 0) { return -1; }

    int sock = (int)socket(stun_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;

    uint8_t tid[12];
    if (speer_random_bytes_or_fail(tid, 12) != 0) {
        CLOSESOCKET(sock);
        return -1;
    }

    uint8_t req[20];
    STORE16_BE(req, STUN_BINDING_REQUEST);
    STORE16_BE(req + 2, 0);
    req[4] = (uint8_t)((STUN_MAGIC_COOKIE >> 24) & 0xffu);
    req[5] = (uint8_t)((STUN_MAGIC_COOKIE >> 16) & 0xffu);
    req[6] = (uint8_t)((STUN_MAGIC_COOKIE >> 8) & 0xffu);
    req[7] = (uint8_t)(STUN_MAGIC_COOKIE & 0xffu);
    COPY(req + 8, tid, 12);

    if (sendto(sock, (char *)req, 20, 0, (struct sockaddr *)&stun_addr, stun_addr_len) < 0) {
        CLOSESOCKET(sock);
        return -1;
    }

#if defined(_WIN32)
    DWORD timeout = 5000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
#else
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    uint8_t resp[256];
    int n = recv(sock, (char *)resp, sizeof(resp), 0);
    CLOSESOCKET(sock);

    if (n < 20) return -1;

    uint16_t resp_type = LOAD16_BE(resp);
    if (resp_type != STUN_BINDING_RESPONSE) return -1;

    if (!EQUAL(resp + 8, tid, 12)) return -1;

    uint16_t attr_len = LOAD16_BE(resp + 2);
    size_t pos = 20;

    while (pos < 20u + attr_len && pos + 4 <= (size_t)n) {
        uint16_t attr_type = LOAD16_BE(resp + pos);
        uint16_t attr_val_len = LOAD16_BE(resp + pos + 2);

        if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && attr_val_len >= 8) {
            uint8_t family = resp[pos + 5];
            uint16_t xport = LOAD16_BE(resp + pos + 6);
            uint16_t port = xport ^ (STUN_MAGIC_COOKIE >> 16);

            if (family == 0x01) {
                struct sockaddr_in *sin = (struct sockaddr_in *)mapped_addr;
                sin->sin_family = AF_INET;
                sin->sin_port = htons(port);
                uint32_t xaddr = LOAD32_BE(resp + pos + 8);
                sin->sin_addr.s_addr = htonl(xaddr ^ STUN_MAGIC_COOKIE);
                *mapped_len = sizeof(struct sockaddr_in);
                return 0;
            } else if (family == 0x02 && attr_val_len >= 20) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)mapped_addr;
                sin6->sin6_family = AF_INET6;
                sin6->sin6_port = htons(port);
                for (int i = 0; i < 16; i++) {
                    sin6->sin6_addr.s6_addr[i] = resp[pos + 8 + i] ^
                                                 ((i < 4)
                                                      ? ((STUN_MAGIC_COOKIE >> (24 - i * 8)) & 0xff)
                                                      : tid[i - 4]);
                }
                *mapped_len = sizeof(struct sockaddr_in6);
                return 0;
            }
        }

        pos += 4 + attr_val_len;
        if (attr_val_len % 4 != 0) pos += 4 - (attr_val_len % 4);
    }

    return -1;
}

uint64_t speer_timestamp_ms(void) {
#if defined(_WIN32)
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000) / freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

int speer_random_bytes_or_fail(uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    if (!buf) return -1;
#if defined(_WIN32)
    const size_t total = len;
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        ZERO(buf, total);
        return -1;
    }
    uint8_t *p = buf;
    while (len > 0) {
        DWORD chunk = (len > (size_t)0xFFFFFFF0u) ? 0xFFFFFFF0u : (DWORD)len;
        if (!CryptGenRandom(hProvider, chunk, p)) {
            ZERO(buf, total);
            CryptReleaseContext(hProvider, 0);
            return -1;
        }
        p += chunk;
        len -= chunk;
    }
    CryptReleaseContext(hProvider, 0);
    return 0;
#else
    size_t total = len;
    size_t offset = 0;
#if defined(__linux__) && defined(__GLIBC__) && \
    (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    while (offset < len) {
        ssize_t ret = getrandom(buf + offset, len - offset, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        offset += (size_t)ret;
    }
#endif
    if (offset < len) {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            while (offset < len) {
                ssize_t ret = read(fd, buf + offset, len - offset);
                if (ret < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                offset += (size_t)ret;
            }
            close(fd);
        }
    }
    if (offset < total) {
        ZERO(buf, total);
        return -1;
    }
    return 0;
#endif
}

void speer_random_bytes(uint8_t *buf, size_t len) {
    (void)speer_random_bytes_or_fail(buf, len);
}

int speer_generate_keypair(uint8_t public_key[SPEER_PUBLIC_KEY_SIZE],
                           uint8_t private_key[SPEER_PRIVATE_KEY_SIZE], const uint8_t seed[32]) {
    if (seed) {
        COPY(private_key, seed, 32);
    } else {
        if (speer_random_bytes_or_fail(private_key, 32) != 0) return -1;
    }

    private_key[0] &= 0xf8;
    private_key[31] = (private_key[31] & 0x7f) | 0x40;

    speer_x25519_base(public_key, private_key);

    return 0;
}
