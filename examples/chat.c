#include "speer.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#define THREAD_T HANDLE
#define THREAD_CREATE(t, fn, arg) \
    (*(t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(fn), (arg), 0, NULL))
#define THREAD_JOIN(t) WaitForSingleObject((t), INFINITE)
#else
#include <pthread.h>
#define THREAD_T                  pthread_t
#define THREAD_CREATE(t, fn, arg) pthread_create((t), NULL, (fn), (arg))
#define THREAD_JOIN(t)            pthread_join((t), NULL)
#endif

static speer_host_t *g_host = NULL;
static speer_peer_t *g_peer = NULL;
static volatile int g_running = 1;

static void on_event(speer_host_t *host, const speer_event_t *ev, void *user) {
    (void)host;
    (void)user;

    switch (ev->type) {
    case SPEER_EVENT_PEER_CONNECTED:
        printf("\n[connected]\n");
        g_peer = ev->peer;
        break;

    case SPEER_EVENT_PEER_DISCONNECTED:
        printf("\n[disconnected]\n");
        g_peer = NULL;
        break;

    case SPEER_EVENT_STREAM_DATA:
        if (ev->len > 0) {
            char buf[1024];
            size_t n = ev->len < sizeof(buf) - 1 ? ev->len : sizeof(buf) - 1;
            memcpy(buf, ev->data, n);
            buf[n] = 0;
            printf("\r[peer] %s\n> ", buf);
            fflush(stdout);
        }
        break;

    default:
        break;
    }
}

#if defined(_WIN32)
static DWORD WINAPI poll_thread(LPVOID arg) {
    (void)arg;
    while (g_host) { speer_host_poll(g_host, 100); }
    return 0;
}
#else
static void *poll_thread(void *arg) {
    (void)arg;
    while (g_host) { speer_host_poll(g_host, 100); }
    return NULL;
}
#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <connect_pubkey_hex> <host:port>\n", argv[0]);
        printf("       %s listen\n", argv[0]);
        return 1;
    }

    uint8_t seed[32] = {8};
    speer_config_t cfg;
    speer_config_default(&cfg);
    cfg.bind_port = 0;

    g_host = speer_host_new(seed, &cfg);
    if (!g_host) {
        fprintf(stderr, "failed to create host\n");
        return 1;
    }

    speer_host_set_callback(g_host, on_event, NULL);

    printf("speer chat\n");
    printf("my public key: ");
    const uint8_t *pk = speer_host_get_public_key(g_host);
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\n");

    if (strcmp(argv[1], "listen") != 0) {
        if (argc < 3) {
            printf("error: need peer address (host:port)\n");
            return 1;
        }

        uint8_t peer_pk[32];
        for (int i = 0; i < 32 && i * 2 < (int)strlen(argv[1]); i++) {
            unsigned int byte;
            sscanf(argv[1] + i * 2, "%2x", &byte);
            peer_pk[i] = (uint8_t)byte;
        }

        printf("connecting to %s...\n", argv[2]);
        speer_connect(g_host, peer_pk, argv[2]);
    } else {
        printf("listening for connections on port %d...\n", speer_host_get_port(g_host));
    }

    THREAD_T thread;
    THREAD_CREATE(&thread, poll_thread, NULL);

    char line[1024];
    printf("> ");
    fflush(stdout);

    while (fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = 0;

        if (strcmp(line, "/quit") == 0) break;

        if (g_peer) {
            speer_stream_t *s = speer_stream_open(g_peer, 0);
            if (s) {
                int written = speer_stream_write(s, (uint8_t *)line, len);
                if (written < 0) printf("write failed: %d\n", written);
                speer_stream_close(s);
            } else
                printf("open stream failed\n");
        } else {
            printf("not connected\n");
        }

        printf("> ");
        fflush(stdout);
    }

    speer_host_t *tmp = g_host;
    g_host = NULL;
    speer_host_free(tmp);

    THREAD_JOIN(thread);

    return 0;
}
