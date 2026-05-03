#if defined(_WIN32)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "speer_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <string.h>
#include <time.h>

#include "ed25519.h"
#include "identify.h"
#include "libp2p_noise.h"
#include "mdns.h"
#include "multistream.h"
#include "peer_id.h"
#include "protobuf.h"
#include "speer_libp2p_tcp.h"
#include "transport_tcp.h"
#include "varint.h"
#include "yamux.h"

#if defined(_WIN32)
#include <windows.h>

#include <conio.h>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#define THREAD_T HANDLE
#define THREAD_CREATE(t, fn, arg) \
    ((*(t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(fn), (arg), 0, NULL)) != NULL ? 0 : -1)
#define THREAD_JOIN(t)   WaitForSingleObject(t, INFINITE)
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
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>

#include <fcntl.h>

#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#define THREAD_T                  pthread_t
#define THREAD_CREATE(t, fn, arg) pthread_create((t), NULL, (fn), (arg))
#define THREAD_JOIN(t)            pthread_join((t), NULL)
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

#define CHAT_PROTO            "/speer/chat/1.0.0"
#define CHAT_SERVICE_TYPE     "_speer-chat._tcp"
#define MAX_PEERS             16
#define MAX_NICK_LEN          32
#define MAX_TEXT_LEN          1024
#define WRITER_POLL_MS        50
#define HANDSHAKE_TIMEOUT_S   10

#define CHAT_TYPE_HELLO       1
#define CHAT_TYPE_MSG         2
#define CHAT_TYPE_BYE         3
#define CHAT_TYPE_FILE_META   4
#define CHAT_TYPE_FILE_CHUNK  5
#define CHAT_TYPE_FILE_DONE   6
#define CHAT_TYPE_FILE_ACCEPT 7

#define MAX_NOISE_FRAME       65535
#define FILE_CHUNK_BYTES      384
#define MAX_RX_FILES          8

/* ============================================================
 * Theme System - Catppuccin Mocha & Nord palettes
 * ============================================================ */

typedef struct {
    uint32_t bg;             /* Main background */
    uint32_t bg_panel;       /* Panel/header backgrounds */
    uint32_t fg;             /* Main text */
    uint32_t fg_dim;         /* Muted/secondary text */
    uint32_t border;         /* Border color */
    uint32_t accent;         /* Highlight/accent */
    uint32_t timestamp;      /* Timestamp color */
    uint32_t peer_colors[6]; /* Peer color rotation */
    const char *name;
} theme_t;

/* Modern Dark Theme - neon purple terminal UI */
static const theme_t THEME_MODERN = {
    .bg = 0x070711, /* Near-black violet */
    .bg_panel = 0x111026, /* Inky panel purple */
    .fg = 0xf2efff, /* Soft white */
    .fg_dim = 0x8a84a6, /* Muted lavender */
    .border = 0x9d2cff, /* Electric violet */
    .accent = 0xff2bd6, /* Neon magenta */
    .timestamp = 0x6d668f, /* Dusty violet */
    .peer_colors =
        {
                      0xff2bd6, /* Magenta */
            0x9d2cff, /* Violet */
            0x35f7c8, /* Mint */
            0x61d6ff, /* Cyan */
            0xffc857, /* Amber */
            0xff7ab6, /* Pink */
        },
    .name = "modern"
};

/* Midnight Theme - High contrast */
static const theme_t THEME_MIDNIGHT = {
    .bg = 0x000000,
    .bg_panel = 0x111111,
    .fg = 0xffffff,
    .fg_dim = 0x666666,
    .border = 0x333333,
    .accent = 0x00ff88,
    .timestamp = 0x444444,
    .peer_colors =
        {
                      0xff3366, /* Red-pink */
            0x9966ff, /* Purple */
            0x00ff88, /* Green */
            0x3399ff, /* Blue */
            0xffaa00, /* Orange */
            0xff66cc, /* Pink */
        },
    .name = "midnight"
};

/* Original Pink/Lavender theme */
static const theme_t THEME_ORIGINAL = {
    .bg = 0x1a1a2e,
    .bg_panel = 0x252542,
    .fg = 0xe6e6fa,
    .fg_dim = 0x6b6b8a,
    .border = 0x4b4b6b,
    .accent = 0xff8ab5,
    .timestamp = 0x7878a0,
    .peer_colors =
        {
                      0xff8ab5, /* Pink */
            0xc7a8ff, /* Lavender */
            0x90e1a0, /* Mint */
            0x88ccff, /* Sky */
            0xffb088, /* Peach */
            0xffe588, /* Butter */
        },
    .name = "original"
};

static const theme_t *g_theme = &THEME_MODERN;

/* ============================================================
 * Screen Buffer System - Double buffered with diff engine
 * ============================================================ */

#define MAX_COLS      512
#define MAX_ROWS      256
#define MAX_HISTORY   1000
#define SIDEBAR_WIDTH 28

typedef struct {
    uint32_t fg;
    uint32_t bg;
    uint8_t bold;
    uint8_t dim;
    uint32_t ch; /* Unicode codepoint */
} cell_t;

typedef struct {
    cell_t front[MAX_ROWS][MAX_COLS]; /* Displayed */
    cell_t back[MAX_ROWS][MAX_COLS];  /* Being built */
    int rows;
    int cols;
    int dirty;
} screen_buf_t;

typedef struct {
    int x, y, w, h;
} rect_t;

/* Layout regions */
typedef struct {
    rect_t header;   /* Title bar */
    rect_t messages; /* Scrollable message area */
    rect_t input;    /* Input bar */
    rect_t netlog;   /* Verbose network console */
    rect_t status;   /* Status bar */
} layout_t;

/* Message types */
typedef enum { MSG_CHAT, MSG_SYSTEM, MSG_JOIN, MSG_LEAVE, MSG_ERROR } msg_type_t;

typedef struct msg_entry {
    msg_type_t type;
    time_t timestamp;
    char nick[MAX_NICK_LEN];
    char pid[64];
    char text[MAX_TEXT_LEN];
    int peer_color_idx;
} msg_entry_t;

typedef struct {
    msg_entry_t entries[MAX_HISTORY];
    int head;   /* Write position */
    int count;  /* Total messages stored */
    int scroll; /* Scroll offset from bottom */
} msg_history_t;

#define MAX_NETLOG  256
#define NETLOG_TEXT 160

typedef enum { NETLOG_INFO, NETLOG_OK, NETLOG_WARN, NETLOG_ERROR, NETLOG_TRAFFIC } netlog_level_t;

typedef struct {
    time_t timestamp;
    netlog_level_t level;
    char text[NETLOG_TEXT];
} netlog_entry_t;

typedef struct {
    netlog_entry_t entries[MAX_NETLOG];
    int head;
    int count;
} netlog_t;

typedef struct {
    int active;
    uint32_t id;
    unsigned long long expected;
    unsigned long long received;
    FILE *fp;
    char sender[64];
    char name[128];
    char path[260];
} rx_file_t;

typedef struct {
    int active;
    uint32_t id;
    unsigned long long size;
    char name[128];
    char path[512];
} tx_file_t;

/* Input state */
typedef struct {
    char buf[MAX_TEXT_LEN];
    int len;
    int cursor;
    int history_idx;
} input_state_t;

static screen_buf_t g_screen;
static layout_t g_layout;
static msg_history_t g_history;
static netlog_t g_netlog;
static MUTEX_T g_log_mu;
static MUTEX_T g_file_mu;
static rx_file_t g_rx_files[MAX_RX_FILES];
static tx_file_t g_tx_files[MAX_RX_FILES];
static input_state_t g_input;
static volatile int g_screen_resized = 0;
static int g_alt_screen = 0;

/* ============================================================
 * Terminal Control
 * ============================================================ */

#if defined(_WIN32)
static HANDLE g_hStdout = NULL;
static HANDLE g_hStdin = NULL;
static DWORD g_oldOutMode = 0;
static DWORD g_oldInMode = 0;
#else
static struct termios g_oldTermios;
static volatile sig_atomic_t g_got_sigwinch = 0;

static void on_sigwinch(int sig) {
    (void)sig;
    g_got_sigwinch = 1;
}
#endif

static void term_get_size(int *rows, int *cols) {
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(g_hStdout, &csbi)) {
        *cols = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        *rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
    } else {
        *cols = 80;
        *rows = 24;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        *cols = ws.ws_col;
        *rows = ws.ws_row;
    } else {
        *cols = 80;
        *rows = 24;
    }
#endif
    if (*cols < 40) *cols = 40;
    if (*cols > MAX_COLS) *cols = MAX_COLS;
    if (*rows < 6) *rows = 6;
    if (*rows > MAX_ROWS) *rows = MAX_ROWS;
}

static void term_altscreen_enter(void) {
    /* Enter alternate screen buffer */
    fputs("\x1b[?1049h", stdout);
    /* Hide cursor */
    fputs("\x1b[?25l", stdout);
    /* Clear screen */
    fputs("\x1b[2J", stdout);
    /* Move to top-left */
    fputs("\x1b[H", stdout);
    fflush(stdout);
    g_alt_screen = 1;
}

static void term_altscreen_exit(void) {
    if (!g_alt_screen) return;
    /* Show cursor */
    fputs("\x1b[?25h", stdout);
    /* Exit alternate screen */
    fputs("\x1b[?1049l", stdout);
    fflush(stdout);
    g_alt_screen = 0;
}

static void term_raw_mode_enter(void) {
#if defined(_WIN32)
    g_hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    g_hStdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(g_hStdout, &g_oldOutMode);
    GetConsoleMode(g_hStdin, &g_oldInMode);
    SetConsoleMode(g_hStdout, g_oldOutMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleMode(g_hStdin, ENABLE_VIRTUAL_TERMINAL_INPUT);
#else
    tcgetattr(STDIN_FILENO, &g_oldTermios);
    struct termios raw = g_oldTermios;
    raw.c_iflag &= ~(IXON | ICRNL | INPCK | ISTRIP);
    raw.c_oflag &= ~(OPOST);
    raw.c_cflag |= (CS8);
    raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    signal(SIGWINCH, on_sigwinch);
#endif
}

static void term_raw_mode_exit(void) {
#if defined(_WIN32)
    if (g_hStdout) SetConsoleMode(g_hStdout, g_oldOutMode);
    if (g_hStdin) SetConsoleMode(g_hStdin, g_oldInMode);
#else
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_oldTermios);
#endif
}

/* ============================================================
 * Screen Buffer Operations
 * ============================================================ */

static void screen_init(void) {
    memset(&g_screen, 0, sizeof(g_screen));
    term_get_size(&g_screen.rows, &g_screen.cols);
    g_screen.dirty = 1;
}

static void screen_clear(cell_t *fill) {
    for (int y = 0; y < g_screen.rows; y++) {
        for (int x = 0; x < g_screen.cols; x++) { g_screen.back[y][x] = *fill; }
    }
}

static void screen_put_cell(int x, int y, const cell_t *c) {
    if (x < 0 || x >= g_screen.cols || y < 0 || y >= g_screen.rows) return;
    g_screen.back[y][x] = *c;
}

static void screen_put_char(int x, int y, uint32_t ch, uint32_t fg, uint32_t bg, int bold,
                            int dim) {
    cell_t c = {.ch = ch, .fg = fg, .bg = bg, .bold = (uint8_t)bold, .dim = (uint8_t)dim};
    screen_put_cell(x, y, &c);
}

static void screen_put_string(int x, int y, const char *str, uint32_t fg, uint32_t bg, int bold,
                              int dim) {
    while (*str && x < g_screen.cols) {
        screen_put_char(x++, y, (uint32_t)(unsigned char)*str++, fg, bg, bold, dim);
    }
}

static void screen_put_string_clipped(int x, int y, const char *str, int max_len, uint32_t fg,
                                      uint32_t bg, int bold, int dim) {
    int n = 0;
    while (*str && x < g_screen.cols && n < max_len) {
        screen_put_char(x++, y, (uint32_t)(unsigned char)*str++, fg, bg, bold, dim);
        n++;
    }
}

static void screen_fill_rect(const rect_t *r, uint32_t bg) {
    cell_t c = {.ch = ' ', .fg = g_theme->fg, .bg = bg, .bold = 0, .dim = 0};
    for (int y = r->y; y < r->y + r->h && y < g_screen.rows; y++) {
        for (int x = r->x; x < r->x + r->w && x < g_screen.cols; x++) { screen_put_cell(x, y, &c); }
    }
}

static void screen_draw_hline_bg(int x, int y, int len, uint32_t fg, uint32_t bg, uint32_t ch) {
    for (int i = 0; i < len && x + i < g_screen.cols; i++) {
        screen_put_char(x + i, y, ch, fg, bg, 0, 0);
    }
}

static void screen_draw_vline_bg(int x, int y, int len, uint32_t fg, uint32_t bg, uint32_t ch) {
    for (int i = 0; i < len && y + i < g_screen.rows; i++) {
        screen_put_char(x, y + i, ch, fg, bg, 0, 0);
    }
}

static void screen_draw_box(const rect_t *r, uint32_t fg, uint32_t bg) {
    if (r->w < 2 || r->h < 2) return;
    screen_put_char(r->x, r->y, 0x250c, fg, bg, 0, 0);
    screen_put_char(r->x + r->w - 1, r->y, 0x2510, fg, bg, 0, 0);
    screen_put_char(r->x, r->y + r->h - 1, 0x2514, fg, bg, 0, 0);
    screen_put_char(r->x + r->w - 1, r->y + r->h - 1, 0x2518, fg, bg, 0, 0);
    screen_draw_hline_bg(r->x + 1, r->y, r->w - 2, fg, bg, 0x2500);
    screen_draw_hline_bg(r->x + 1, r->y + r->h - 1, r->w - 2, fg, bg, 0x2500);
    screen_draw_vline_bg(r->x, r->y + 1, r->h - 2, fg, bg, 0x2502);
    screen_draw_vline_bg(r->x + r->w - 1, r->y + 1, r->h - 2, fg, bg, 0x2502);
}

static int ui_sidebar_width(void) {
    if (g_screen.cols > 96) return SIDEBAR_WIDTH;
    if (g_screen.cols > 68) return 23;
    return 0;
}

static int ui_netlog_width(void) {
    if (g_screen.cols > 138) return 42;
    if (g_screen.cols > 116) return 34;
    return 0;
}


#if defined(_WIN32)
static FILE *fopen_write_bin_private(const char *path) {
    int fd =
        _open(path, _O_CREAT | _O_TRUNC | _O_BINARY | _O_WRONLY, _S_IREAD | _S_IWRITE);
    if (fd < 0) return NULL;
    FILE *fp = _fdopen(fd, "wb");
    if (!fp) {
        _close(fd);
        return NULL;
    }
    return fp;
}
#else
static FILE *fopen_write_bin_private(const char *path) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) return NULL;
    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);
        return NULL;
    }
    return fp;
}
#endif

static void esc_buf_flush(char *buf, int *pos) {
    if (*pos <= 0) return;
    fwrite(buf, 1, (size_t)*pos, stdout);
    *pos = 0;
}

static void esc_fmt_append(char *buf, size_t cap, int *pos, const char *fmt, ...) {
    if (*pos < 0 || (size_t)*pos >= cap - 96) esc_buf_flush(buf, pos);

    va_list ap;
    va_start(ap, fmt);

    va_list aq;
    va_copy(aq, ap);
    size_t room = cap - (size_t)*pos;
    int n = vsnprintf(buf + *pos, room, fmt, aq);
    va_end(aq);

    if (n >= 0 && (size_t)n >= room) {
        esc_buf_flush(buf, pos);
        room = cap - (size_t)*pos;
        va_copy(aq, ap);
        n = vsnprintf(buf + *pos, room, fmt, aq);
        va_end(aq);
    }
    va_end(ap);

    room = cap - (size_t)*pos;
    if (n >= 0 && (size_t)n < room) {
        *pos += n;
    }
}

static void utf8_emit(char *buf, size_t cap, int *pos, uint32_t ch) {
    int need =
        ch < 128 ? 1 : (ch < 0x800 ? 2 : 3); /* widest UTF-8 rune we emit below */
    if (*pos >= 0 && (size_t)*pos + (size_t)need >= cap - 32) esc_buf_flush(buf, pos);
    if (ch < 128) {
        buf[(*pos)++] = (char)ch;
    } else if (ch < 0x800) {
        buf[(*pos)++] = (char)(0xc0 | (ch >> 6));
        buf[(*pos)++] = (char)(0x80 | (ch & 0x3f));
    } else {
        buf[(*pos)++] = (char)(0xe0 | (ch >> 12));
        buf[(*pos)++] = (char)(0x80 | ((ch >> 6) & 0x3f));
        buf[(*pos)++] = (char)(0x80 | (ch & 0x3f));
    }
}

/* Diff and render to terminal */
static void screen_present(void) {
    /* Build output string with minimal escape sequences */
    static char buf[65536];
    int pos = 0;

    uint32_t cur_fg = 0xffffffff;
    uint32_t cur_bg = 0xffffffff;
    int cur_bold = -1;
    int cur_dim = -1;

    for (int y = 0; y < g_screen.rows; y++) {
        int line_dirty = 0;
        for (int x = 0; x < g_screen.cols; x++) {
            if (memcmp(&g_screen.front[y][x], &g_screen.back[y][x], sizeof(cell_t)) != 0) {
                line_dirty = 1;
                break;
            }
        }
        if (!line_dirty) continue;

        esc_fmt_append(buf, sizeof(buf), &pos, "\x1b[%d;1H", y + 1);

        for (int x = 0; x < g_screen.cols; x++) {
            cell_t *c = &g_screen.back[y][x];

            /* Set attributes if changed */
            if (c->bold != cur_bold || c->dim != cur_dim) {
                esc_fmt_append(buf, sizeof(buf), &pos, "\x1b[22m");
                cur_bold = 0;
                cur_dim = 0;
                if (c->bold) {
                    esc_fmt_append(buf, sizeof(buf), &pos, "\x1b[1m");
                    cur_bold = 1;
                }
                if (c->dim) {
                    esc_fmt_append(buf, sizeof(buf), &pos, "\x1b[2m");
                    cur_dim = 1;
                }
            }
            if (c->fg != cur_fg) {
                esc_fmt_append(buf, sizeof(buf), &pos, "\x1b[38;2;%u;%u;%um",
                               (unsigned)((c->fg >> 16) & 0xff), (unsigned)((c->fg >> 8) & 0xff),
                               (unsigned)(c->fg & 0xff));
                cur_fg = c->fg;
            }
            if (c->bg != cur_bg) {
                esc_fmt_append(buf, sizeof(buf), &pos, "\x1b[48;2;%u;%u;%um",
                               (unsigned)((c->bg >> 16) & 0xff), (unsigned)((c->bg >> 8) & 0xff),
                               (unsigned)(c->bg & 0xff));
                cur_bg = c->bg;
            }
            /* Output character */
            utf8_emit(buf, sizeof(buf), &pos, c->ch);

            /* Flush periodically */
            if (pos > 60000) esc_buf_flush(buf, &pos);
        }

        /* Copy back to front */
        memcpy(g_screen.front[y], g_screen.back[y], g_screen.cols * sizeof(cell_t));
    }

    if (pos > 0) esc_buf_flush(buf, &pos);
    fflush(stdout);
}

/* ============================================================
 * Layout Management
 * ============================================================ */

static void layout_calc(void) {
    int rows = g_screen.rows;
    int cols = g_screen.cols;
    int sidebar_w = ui_sidebar_width();
    int netlog_w = ui_netlog_width();
    int header_h = rows >= 10 ? 3 : 1;
    int input_h = rows >= 10 ? 3 : 1;

    /* Header: title and connection strip */
    g_layout.header.x = 0;
    g_layout.header.y = 0;
    g_layout.header.w = cols;
    g_layout.header.h = header_h;

    /* Status bar: 1 line at bottom, full width */
    g_layout.status.x = 0;
    g_layout.status.y = rows - 1;
    g_layout.status.w = cols;
    g_layout.status.h = 1;

    g_layout.netlog.x = cols - netlog_w;
    g_layout.netlog.y = header_h;
    g_layout.netlog.w = netlog_w;
    g_layout.netlog.h = rows - header_h - 1;

    /* Input panel above status, starts after sidebar */
    g_layout.input.x = sidebar_w;
    g_layout.input.y = rows - 1 - input_h;
    g_layout.input.w = cols - sidebar_w - netlog_w;
    g_layout.input.h = input_h;

    /* Message area: starts after sidebar */
    g_layout.messages.x = sidebar_w;
    g_layout.messages.y = header_h;
    g_layout.messages.w = cols - sidebar_w - netlog_w;
    g_layout.messages.h = g_layout.input.y - g_layout.messages.y;
}

/* ============================================================
 * Message History
 * ============================================================ */

static void history_init(void) {
    memset(&g_history, 0, sizeof(g_history));
}

static void netlog_clear(void) {
    MUTEX_LOCK(&g_log_mu);
    memset(&g_netlog, 0, sizeof(g_netlog));
    MUTEX_UNLOCK(&g_log_mu);
}

static void netlog_add(netlog_level_t level, const char *fmt, ...) {
    char buf[NETLOG_TEXT];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    MUTEX_LOCK(&g_log_mu);
    netlog_entry_t *e = &g_netlog.entries[g_netlog.head];
    e->timestamp = time(NULL);
    e->level = level;
    snprintf(e->text, sizeof(e->text), "%s", buf);
    g_netlog.head = (g_netlog.head + 1) % MAX_NETLOG;
    if (g_netlog.count < MAX_NETLOG) g_netlog.count++;
    MUTEX_UNLOCK(&g_log_mu);
}

static void history_add(msg_type_t type, const char *nick, const char *pid, const char *text) {
    msg_entry_t *e = &g_history.entries[g_history.head];
    e->type = type;
    e->timestamp = time(NULL);
    snprintf(e->nick, sizeof(e->nick), "%s", nick ? nick : "");
    snprintf(e->pid, sizeof(e->pid), "%s", pid ? pid : "");
    snprintf(e->text, sizeof(e->text), "%s", text ? text : "");

    /* Calculate peer color index */
    if (pid && *pid) {
        uint32_t h = 2166136261u;
        for (const char *c = pid; *c; c++) {
            h ^= (uint8_t)*c;
            h *= 16777619u;
        }
        e->peer_color_idx = h % 6;
    } else {
        e->peer_color_idx = 0;
    }

    g_history.head = (g_history.head + 1) % MAX_HISTORY;
    if (g_history.count < MAX_HISTORY) g_history.count++;

    /* Auto-scroll to bottom if already there */
    if (g_history.scroll > 0) g_history.scroll = 0;
}

/* ============================================================
 * Forward declarations for networking structs (needed by UI)
 * ============================================================ */

typedef struct outmsg {
    struct outmsg *next;
    uint32_t type;
    size_t text_len;
    char text[MAX_TEXT_LEN];
} outmsg_t;

typedef struct ioctx_s {
    int fd;
    speer_libp2p_noise_t *noise;
    uint8_t q[MAX_NOISE_FRAME];
    size_t q_len;
    size_t q_off;
    MUTEX_T *send_mu;
} ioctx_t;

typedef struct peer_s {
    int active;
    int initiator;
    int fd;
    char addr[64];
    char remote_nick[MAX_NICK_LEN];
    char remote_pid_short[64];
    char remote_pid_full[64];
    time_t connected_at;
    time_t last_seen;
    unsigned long long msgs_rx;
    unsigned long long msgs_tx;
    unsigned long long bytes_rx;
    unsigned long long bytes_tx;

    speer_libp2p_noise_t noise;
    speer_yamux_session_t mux;
    speer_yamux_stream_t *chat_st;
    ioctx_t io;

    MUTEX_T out_mu;
    outmsg_t *out_head;
    outmsg_t *out_tail;

    MUTEX_T send_mu;

    THREAD_T writer_thread;
    THREAD_T reader_thread;
    int reader_started;

    int handshake_done;
    int dead;
} peer_t;

typedef struct {
    peer_t peers[MAX_PEERS];
    MUTEX_T mu;
} peer_table_t;

/* Global variables needed by UI */
static peer_table_t g_peers;
static volatile int g_quit = 0;
static char g_my_nick[MAX_NICK_LEN] = "anon";
static char g_my_pid_b58[64] = "";
static char g_lan_ip[64] = "127.0.0.1";
static time_t g_started_at = 0;
static uint16_t g_listen_port = 0;
static uint8_t g_my_static_pub[32], g_my_static_priv[32];
static uint8_t g_my_ed_pub[32], g_my_ed_seed[32];
static uint32_t g_next_file_id = 1;

/* ============================================================
 * Rendering Functions
 * ============================================================ */

static void format_timestamp(time_t t, char *out, size_t cap);
static void hex_encode(const uint8_t *in, size_t len, char *out, size_t cap);

static void draw_gradient_title(int x, int y, const char *t, int start_r, int start_g, int start_b,
                                int end_r, int end_g, int end_b) {
    int n = (int)strlen(t);
    if (n <= 0) return;
    for (int i = 0; i < n && x + i < g_screen.cols; i++) {
        int denom = n > 1 ? n - 1 : 1;
        int r = start_r + (end_r - start_r) * i / denom;
        int g = start_g + (end_g - start_g) * i / denom;
        int b = start_b + (end_b - start_b) * i / denom;
        uint32_t fg = ((r & 0xff) << 16) | ((g & 0xff) << 8) | (b & 0xff);
        screen_put_char(x + i, y, (uint32_t)(unsigned char)t[i], fg, g_theme->bg_panel, 1, 0);
    }
}

static void format_duration(time_t since, char *out, size_t cap) {
    long secs = 0;
    if (since != 0) secs = (long)difftime(time(NULL), since);
    if (secs < 0) secs = 0;
    if (secs >= 3600) {
        snprintf(out, cap, "%ldh%02ldm", secs / 3600, (secs / 60) % 60);
    } else if (secs >= 60) {
        snprintf(out, cap, "%ldm%02lds", secs / 60, secs % 60);
    } else {
        snprintf(out, cap, "%lds", secs);
    }
}

static void collect_peer_stats(int *connected, unsigned long long *rx_msgs,
                               unsigned long long *tx_msgs, unsigned long long *rx_bytes,
                               unsigned long long *tx_bytes) {
    *connected = 0;
    *rx_msgs = *tx_msgs = *rx_bytes = *tx_bytes = 0;
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && p->handshake_done) {
            (*connected)++;
            *rx_msgs += p->msgs_rx;
            *tx_msgs += p->msgs_tx;
            *rx_bytes += p->bytes_rx;
            *tx_bytes += p->bytes_tx;
        }
    }
    MUTEX_UNLOCK(&g_peers.mu);
}

static uint32_t netlog_level_color(netlog_level_t level) {
    switch (level) {
    case NETLOG_OK:
        return 0x35f7c8;
    case NETLOG_WARN:
        return 0xffc857;
    case NETLOG_ERROR:
        return g_theme->peer_colors[0];
    case NETLOG_TRAFFIC:
        return 0x61d6ff;
    case NETLOG_INFO:
    default:
        return g_theme->fg_dim;
    }
}

static void render_header(void) {
    screen_fill_rect(&g_layout.header, g_theme->bg_panel);

    draw_gradient_title(2, 0, "speer-chat", 255, 43, 214, 97, 214, 255);

    /* Connection info on right */
    char info[64];
    int peer_count = 0;
    unsigned long long rx_msgs = 0, tx_msgs = 0, rx_bytes = 0, tx_bytes = 0;
    collect_peer_stats(&peer_count, &rx_msgs, &tx_msgs, &rx_bytes, &tx_bytes);

    snprintf(info, sizeof(info), " %d connected ", peer_count);

    int info_len = (int)strlen(info);
    if (info_len < g_layout.header.w - 4) {
        screen_put_string(g_layout.header.w - info_len - 2, 0, info,
                          peer_count > 0 ? 0x35f7c8 : g_theme->fg_dim, g_theme->bg_panel, 1, 0);
    }

    if (g_layout.header.h > 1) {
        char room[96];
        snprintf(room, sizeof(room), " Noise XX + Yamux + mDNS   %s:%u   rx %llu / tx %llu ",
                 g_lan_ip, (unsigned)g_listen_port, rx_msgs, tx_msgs);
        screen_put_string_clipped(2, 1, room, g_layout.header.w - 4, g_theme->fg_dim,
                                  g_theme->bg_panel, 0, 0);
        screen_draw_hline_bg(0, g_layout.header.h - 1, g_layout.header.w, g_theme->border,
                             g_theme->bg_panel, 0x2500);
    }
}

static void render_sidebar(void) {
    int sidebar_w = ui_sidebar_width();
    if (sidebar_w == 0) return;

    rect_t sidebar = {0, g_layout.header.h, sidebar_w, g_layout.status.y - g_layout.header.h};
    screen_fill_rect(&sidebar, g_theme->bg_panel);
    screen_draw_box(&sidebar, g_theme->border, g_theme->bg_panel);

    screen_put_string(2, sidebar.y, " Collection ", g_theme->accent, g_theme->bg_panel, 1, 0);
    screen_put_string(2, sidebar.y + 2, "local", g_theme->fg_dim, g_theme->bg_panel, 1, 0);
    screen_put_char(2, sidebar.y + 3, 0x25cf, g_theme->peer_colors[0], g_theme->bg_panel, 0, 0);
    screen_put_string_clipped(4, sidebar.y + 3, g_my_nick, sidebar_w - 6, g_theme->fg,
                              g_theme->bg_panel, 1, 0);
    if (g_my_pid_b58[0] && sidebar.h > 8) {
        char pid_short[20];
        snprintf(pid_short, sizeof(pid_short), "%.16s", g_my_pid_b58);
        screen_put_string(4, sidebar.y + 4, pid_short, g_theme->fg_dim, g_theme->bg_panel, 0, 1);
    }
    if (sidebar.h > 11) {
        char uptime[32];
        char line[48];
        format_duration(g_started_at, uptime, sizeof(uptime));
        snprintf(line, sizeof(line), "uptime %s", uptime);
        screen_put_string_clipped(2, sidebar.y + 6, line, sidebar_w - 4, g_theme->fg_dim,
                                  g_theme->bg_panel, 0, 0);
    }

    int y = sidebar.y + 9;
    if (y < sidebar.y + sidebar.h - 2) {
        screen_put_string(2, y, "peers", g_theme->fg_dim, g_theme->bg_panel, 1, 0);
        y += 2;
    }

    /* List connected peers */
    int listed = 0;
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS && y < sidebar.y + sidebar.h - 3; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && p->handshake_done) {
            uint32_t col = g_theme->peer_colors[i % 6];
            char name[32];
            snprintf(name, sizeof(name), "%s",
                     p->remote_nick[0] ? p->remote_nick : p->remote_pid_short);
            screen_put_char(2, y, 0x25cf, col, g_theme->bg_panel, 0, 0);
            screen_put_string_clipped(4, y, name, sidebar_w - 6, col, g_theme->bg_panel, 1, 0);
            y++;
            if (y < sidebar.y + sidebar.h - 3) {
                char active_for[24];
                char detail[48];
                format_duration(p->connected_at, active_for, sizeof(active_for));
                snprintf(detail, sizeof(detail), "%s  rx%llu tx%llu", active_for, p->msgs_rx,
                         p->msgs_tx);
                screen_put_string_clipped(4, y, detail, sidebar_w - 6, g_theme->fg_dim,
                                          g_theme->bg_panel, 0, 1);
                y++;
            }
            listed++;
        }
    }
    MUTEX_UNLOCK(&g_peers.mu);

    /* Show empty state */
    if (listed == 0 && y < sidebar.y + sidebar.h - 2) {
        screen_put_string(2, y, "discovering...", g_theme->fg_dim, g_theme->bg_panel, 0, 1);
    }
}

static void render_status(void) {
    screen_fill_rect(&g_layout.status, g_theme->bg_panel);

    screen_put_string(1, g_layout.status.y, "/status /inspect /id /peers /clear   PgUp/PgDn Scroll",
                      g_theme->fg_dim, g_theme->bg_panel, 0, 0);

    /* Show peer count */
    int peer_count = 0;
    unsigned long long rx_msgs = 0, tx_msgs = 0, rx_bytes = 0, tx_bytes = 0;
    collect_peer_stats(&peer_count, &rx_msgs, &tx_msgs, &rx_bytes, &tx_bytes);

    char peers_str[32];
    snprintf(peers_str, sizeof(peers_str), " %d peers  %llu/%llu msg ", peer_count, rx_msgs,
             tx_msgs);
    int len = (int)strlen(peers_str);
    screen_put_string(g_layout.status.w - len - 1, g_layout.status.y, peers_str,
                      peer_count > 0 ? 0x35f7c8 : g_theme->accent, g_theme->bg_panel, 1, 0);
}

static void render_netlog(void) {
    if (g_layout.netlog.w <= 0 || g_layout.netlog.h <= 0) return;

    rect_t panel = g_layout.netlog;
    screen_fill_rect(&panel, g_theme->bg_panel);
    screen_draw_box(&panel, g_theme->border, g_theme->bg_panel);
    screen_put_string(panel.x + 2, panel.y, " Network Console ", g_theme->accent, g_theme->bg_panel,
                      1, 0);

    int inner_x = panel.x + 2;
    int inner_w = panel.w - 4;
    int y = panel.y + 2;
    if (inner_w < 12) return;

    int peer_count = 0;
    unsigned long long rx_msgs = 0, tx_msgs = 0, rx_bytes = 0, tx_bytes = 0;
    collect_peer_stats(&peer_count, &rx_msgs, &tx_msgs, &rx_bytes, &tx_bytes);

    char line[NETLOG_TEXT];
    char uptime[32];
    format_duration(g_started_at, uptime, sizeof(uptime));

    snprintf(line, sizeof(line), "mDNS  advertising");
    screen_put_string_clipped(inner_x, y++, line, inner_w, 0x35f7c8, g_theme->bg_panel, 1, 0);
    snprintf(line, sizeof(line), "TCP   %s:%u", g_lan_ip, (unsigned)g_listen_port);
    screen_put_string_clipped(inner_x, y++, line, inner_w, g_theme->fg, g_theme->bg_panel, 0, 0);
    snprintf(line, sizeof(line), "Peers %d  Up %s", peer_count, uptime);
    screen_put_string_clipped(inner_x, y++, line, inner_w, g_theme->fg_dim, g_theme->bg_panel, 0,
                              0);
    snprintf(line, sizeof(line), "RX %llu msg / %llu B", rx_msgs, rx_bytes);
    screen_put_string_clipped(inner_x, y++, line, inner_w, 0x61d6ff, g_theme->bg_panel, 0, 0);
    snprintf(line, sizeof(line), "TX %llu msg / %llu B", tx_msgs, tx_bytes);
    screen_put_string_clipped(inner_x, y++, line, inner_w, 0xffc857, g_theme->bg_panel, 0, 0);

    y++;
    if (y < panel.y + panel.h - 1) {
        screen_put_string(inner_x, y++, "stack", g_theme->accent, g_theme->bg_panel, 1, 0);
        screen_put_string_clipped(inner_x, y++, "mDNS -> TCP", inner_w, g_theme->fg_dim,
                                  g_theme->bg_panel, 0, 0);
        screen_put_string_clipped(inner_x, y++, "Noise XX auth", inner_w, g_theme->fg_dim,
                                  g_theme->bg_panel, 0, 0);
        screen_put_string_clipped(inner_x, y++, "Yamux streams", inner_w, g_theme->fg_dim,
                                  g_theme->bg_panel, 0, 0);
        screen_put_string_clipped(inner_x, y++, CHAT_PROTO, inner_w, g_theme->fg_dim,
                                  g_theme->bg_panel, 0, 0);
    }

    y++;
    if (y < panel.y + panel.h - 1) {
        screen_put_string(inner_x, y++, "events", g_theme->accent, g_theme->bg_panel, 1, 0);
    }

    MUTEX_LOCK(&g_log_mu);
    int max_events = panel.y + panel.h - 1 - y;
    if (max_events < 0) max_events = 0;
    if (max_events > g_netlog.count) max_events = g_netlog.count;
    for (int i = max_events - 1; i >= 0; i--) {
        int idx = (g_netlog.head - 1 - i + MAX_NETLOG) % MAX_NETLOG;
        netlog_entry_t *e = &g_netlog.entries[idx];
        char ts[16];
        format_timestamp(e->timestamp, ts, sizeof(ts));
        snprintf(line, sizeof(line), "%s %s", ts, e->text);
        screen_put_string_clipped(inner_x, y++, line, inner_w, netlog_level_color(e->level),
                                  g_theme->bg_panel, e->level == NETLOG_ERROR,
                                  e->level == NETLOG_INFO);
    }
    MUTEX_UNLOCK(&g_log_mu);
}

static void render_input(void) {
    uint32_t input_bg = g_layout.input.h > 1 ? g_theme->bg_panel : g_theme->bg;
    screen_fill_rect(&g_layout.input, input_bg);
    if (g_layout.input.h > 1) {
        rect_t box = g_layout.input;
        box.x += 1;
        box.w -= 2;
        screen_draw_box(&box, g_theme->border, input_bg);
        screen_put_string(box.x + 2, box.y, " Message ", g_theme->accent, input_bg, 1, 0);
        screen_put_string(g_layout.input.x + g_layout.input.w - 16, box.y, " Enter to send ",
                          g_theme->fg_dim, input_bg, 0, 0);
    }

    /* Nick with peer color */
    uint32_t nick_col = g_theme->peer_colors[0];
    if (g_my_pid_b58[0]) {
        uint32_t h = 2166136261u;
        for (const char *c = g_my_pid_b58; *c; c++) {
            h ^= (uint8_t)*c;
            h *= 16777619u;
        }
        nick_col = g_theme->peer_colors[h % 6];
    }

    int input_line = g_layout.input.h > 1 ? g_layout.input.y + 1 : g_layout.input.y;
    int prompt_x = g_layout.input.x + (g_layout.input.h > 1 ? 4 : 1);

    screen_put_string(prompt_x, input_line, g_my_nick, nick_col, input_bg, 1, 0);

    int nick_len = (int)strlen(g_my_nick);
    screen_put_string(prompt_x + nick_len + 1, input_line, ">", g_theme->accent, input_bg, 1, 0);
    screen_put_string(prompt_x + nick_len + 3, input_line, "", g_theme->fg_dim, input_bg, 0, 0);

    /* Input text */
    int prompt_offset = prompt_x + nick_len + 3;
    int max_input = g_layout.input.x + g_layout.input.w - prompt_offset -
                    (g_layout.input.h > 1 ? 4 : 1);
    if (max_input < 1) max_input = 1;
    if (g_input.len > max_input) {
        /* Scroll input if too long */
        screen_put_string(prompt_offset, input_line, g_input.buf + (g_input.len - max_input),
                          g_theme->fg, input_bg, 0, 0);
    } else {
        screen_put_string(prompt_offset, input_line, g_input.buf, g_theme->fg, input_bg, 0, 0);
    }
}

static void format_timestamp(time_t t, char *out, size_t cap) {
    struct tm tm_buf;
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    strftime(out, cap, "%H:%M:%S", &tm_buf);
}

static void render_messages(void) {
    /* Fill background */
    screen_fill_rect(&g_layout.messages, g_theme->bg);
    if (g_layout.messages.w > 3 && g_layout.messages.h > 2) {
        rect_t box = g_layout.messages;
        box.x += 1;
        box.w -= 2;
        screen_draw_box(&box, g_theme->border, g_theme->bg);
        screen_put_string(box.x + 2, box.y, " Chat ", g_theme->accent, g_theme->bg, 1, 0);
    }

    int inner_x = g_layout.messages.x + (g_layout.messages.w > 3 ? 3 : 1);
    int inner_y = g_layout.messages.y + (g_layout.messages.h > 2 ? 1 : 0);
    int inner_w = g_layout.messages.w - (g_layout.messages.w > 3 ? 6 : 2);
    int inner_h = g_layout.messages.h - (g_layout.messages.h > 2 ? 2 : 0);
    if (inner_w < 10 || inner_h <= 0) return;

    /* Check if we have any real messages (not uninitialized) */
    int real_count = 0;
    for (int i = 0; i < g_history.count; i++) {
        int idx = (g_history.head - 1 - i + MAX_HISTORY) % MAX_HISTORY;
        if (g_history.entries[idx].timestamp != 0) {
            real_count++;
            break;
        }
    }

    if (real_count == 0) {
        /* Show welcome message in the center */
        const char *line1 = "Welcome to speer-chat!";
        const char *line2 = "Type /help for commands or just start typing.";
        int x1 = inner_x + (inner_w - (int)strlen(line1)) / 2;
        int x2 = inner_x + (inner_w - (int)strlen(line2)) / 2;
        int y = inner_y + inner_h / 2;
        screen_put_string(x1, y, line1, g_theme->accent, g_theme->bg, 1, 0);
        screen_put_string(x2, y + 1, line2, g_theme->fg_dim, g_theme->bg, 0, 1);
        return;
    }

    int line = inner_y + inner_h - 1;
    int msgs_to_show = inner_h;
    int start_idx = (g_history.head - 1 + MAX_HISTORY) % MAX_HISTORY;

    /* Apply scroll: move start_idx back, but never past the oldest real message. */
    if (g_history.scroll > 0 && g_history.count > 0) {
        int max_steps = g_history.count - 1;
        int steps =
            g_history.scroll < max_steps ? g_history.scroll : max_steps;
        for (int i = 0; i < steps; i++)
            start_idx = (start_idx - 1 + MAX_HISTORY) % MAX_HISTORY;
    }

    for (int i = 0; i < msgs_to_show && line >= inner_y; i++) {
        msg_entry_t *e = &g_history.entries[start_idx];

        /* Skip uninitialized entries (timestamp 0 means empty) */
        if (e->timestamp == 0) {
            start_idx = (start_idx - 1 + MAX_HISTORY) % MAX_HISTORY;
            continue;
        }

        char ts[16];
        format_timestamp(e->timestamp, ts, sizeof(ts));

        int x = inner_x;

        /* Timestamp */
        screen_put_string(x, line, "[", g_theme->timestamp, g_theme->bg, 0, 1);
        x++;
        screen_put_string(x, line, ts, g_theme->timestamp, g_theme->bg, 0, 1);
        x += 8;
        screen_put_string(x, line, "]", g_theme->timestamp, g_theme->bg, 0, 1);
        x += 2;

        /* Color bar - simple ASCII */
        uint32_t col = g_theme->peer_colors[e->peer_color_idx];
        if (e->type == MSG_SYSTEM) col = g_theme->fg_dim;
        if (e->type == MSG_ERROR) col = g_theme->peer_colors[0]; /* Red-ish */

        screen_put_char(x, line, 0x258c, col, g_theme->bg, 0, 0);
        x += 2;

        /* Nick or message marker */
        if (e->type == MSG_CHAT || e->type == MSG_JOIN || e->type == MSG_LEAVE) {
            const char *display_nick = e->nick[0] ? e->nick : "unknown";
            char nick_buf[32];
            snprintf(nick_buf, sizeof(nick_buf), "%-12s", display_nick);
            screen_put_string(x, line, nick_buf, col, g_theme->bg, 1, 0);
            x += 13;
        } else if (e->type == MSG_SYSTEM) {
            screen_put_string(x, line, "* ", g_theme->fg_dim, g_theme->bg, 0, 0);
            x += 2;
        } else if (e->type == MSG_ERROR) {
            screen_put_string(x, line, "! ", g_theme->peer_colors[0], g_theme->bg, 0, 0);
            x += 2;
        }

        /* Message text with wrapping */
        int avail = inner_x + inner_w - x - 1;
        const char *text = e->text;
        int first_line = 1;

        while (*text && line >= inner_y) {
            int take = 0;
            const char *p = text;
            while (*p && take < avail) {
                if (*p == ' ' && take > avail - 10) break; /* Soft break */
                take++;
                p++;
            }
            if (take == 0 && *text) take = 1; /* Force at least one char */

            uint32_t fg = g_theme->fg;
            if (e->type == MSG_SYSTEM || e->type == MSG_JOIN || e->type == MSG_LEAVE)
                fg = g_theme->fg_dim;

            for (int j = 0; j < take && text[j]; j++) {
                screen_put_char(x + j, line, (uint32_t)(unsigned char)text[j], fg, g_theme->bg, 0,
                                0);
            }

            text += take;
            if (*text == ' ') text++; /* Skip space at break */

            if (!first_line) line--; /* Continue on next line if wrapped */
            first_line = 0;

            if (*text) {
                line--;
                x = inner_x + 15; /* Indent wrapped lines */
            }
        }

        start_idx = (start_idx - 1 + MAX_HISTORY) % MAX_HISTORY;
        line--;
    }

    /* Scroll indicator - ASCII */
    if (g_history.scroll > 0) {
        screen_put_string(g_layout.messages.x + g_layout.messages.w - 7, g_layout.messages.y,
                          "^ more", g_theme->accent, g_theme->bg, 1, 0);
    }
}

static void render_full(void) {
    /* Clear back buffer with theme background */
    cell_t bg_cell = {.ch = ' ', .fg = g_theme->fg, .bg = g_theme->bg, .bold = 0, .dim = 0};
    screen_clear(&bg_cell);

    /* Draw layout */
    render_header();
    render_sidebar();

    render_messages();
    render_input();
    render_netlog();
    render_status();

    /* Present to terminal */
    screen_present();

    /* Position cursor at input */
    int input_line = g_layout.input.h > 1 ? g_layout.input.y + 1 : g_layout.input.y;
    int prompt_x = g_layout.input.x + (g_layout.input.h > 1 ? 4 : 1);
    int cursor_x = prompt_x + (int)strlen(g_my_nick) + 3;
    int max_input = g_layout.input.x + g_layout.input.w - cursor_x - (g_layout.input.h > 1 ? 4 : 1);
    if (max_input < 1) max_input = 1;
    if (g_input.len > max_input) {
        cursor_x = g_layout.input.x + g_layout.input.w - (g_layout.input.h > 1 ? 4 : 1);
    } else {
        cursor_x += g_input.cursor;
    }
    printf("\x1b[%d;%dH", input_line + 1, cursor_x + 1);
    printf("\x1b[?25h"); /* Show cursor */
    fflush(stdout);
}

/* ============================================================
 * Input Handling
 * ============================================================ */

#define KEY_CTRL_C    3
#define KEY_CTRL_D    4
#define KEY_CTRL_W    23
#define KEY_CTRL_U    21
#define KEY_ENTER     13
#define KEY_ESC       27
#define KEY_BACKSPACE 127
#define KEY_DELETE    126
#define KEY_TAB       9
#define KEY_UP        1000
#define KEY_DOWN      1001
#define KEY_LEFT      1002
#define KEY_RIGHT     1003
#define KEY_HOME      1004
#define KEY_END       1005
#define KEY_PGUP      1006
#define KEY_PGDN      1007

#if defined(_WIN32)
static int input_read_key(void) {
    if (_kbhit()) {
        int c = _getch();
        if (c == 0 || c == 224) {
            int ext = _getch();
            switch (ext) {
            case 72:
                return KEY_UP;
            case 80:
                return KEY_DOWN;
            case 75:
                return KEY_LEFT;
            case 77:
                return KEY_RIGHT;
            case 73:
                return KEY_PGUP;
            case 81:
                return KEY_PGDN;
            case 71:
                return KEY_HOME;
            case 79:
                return KEY_END;
            }
            return 0;
        }
        return c;
    }
    return -1;
}
#else
static int input_read_key(void) {
    char c;
    int n = read(STDIN_FILENO, &c, 1);
    if (n <= 0) return -1;

    if (c == '\x1b') {
        char seq[3];
        if (read(STDIN_FILENO, &seq[0], 1) != 1) return '\x1b';
        if (read(STDIN_FILENO, &seq[1], 1) != 1) return '\x1b';

        if (seq[0] == '[') {
            if (seq[1] >= '0' && seq[1] <= '9') {
                if (read(STDIN_FILENO, &seq[2], 1) != 1) return '\x1b';
                if (seq[2] == '~') {
                    switch (seq[1]) {
                    case '1':
                        return KEY_HOME;
                    case '3':
                        return KEY_DELETE;
                    case '4':
                        return KEY_END;
                    case '5':
                        return KEY_PGUP;
                    case '6':
                        return KEY_PGDN;
                    case '7':
                        return KEY_HOME;
                    case '8':
                        return KEY_END;
                    }
                }
            } else {
                switch (seq[1]) {
                case 'A':
                    return KEY_UP;
                case 'B':
                    return KEY_DOWN;
                case 'C':
                    return KEY_RIGHT;
                case 'D':
                    return KEY_LEFT;
                case 'H':
                    return KEY_HOME;
                case 'F':
                    return KEY_END;
                }
            }
        } else if (seq[0] == 'O') {
            switch (seq[1]) {
            case 'H':
                return KEY_HOME;
            case 'F':
                return KEY_END;
            }
        }
        return '\x1b';
    }
    return c;
}
#endif

static int process_input(void) {
    int c = input_read_key();
    if (c < 0) return 0;

    switch (c) {
    case KEY_CTRL_C:
    case KEY_CTRL_D:
        return -1; /* Exit */

    case KEY_ENTER:
        if (g_input.len > 0) {
            g_input.buf[g_input.len] = '\0';
            return 1; /* Have input */
        }
        return 0;

    case KEY_BACKSPACE:
        if (g_input.cursor > 0) {
            memmove(&g_input.buf[g_input.cursor - 1], &g_input.buf[g_input.cursor],
                    g_input.len - g_input.cursor + 1);
            g_input.cursor--;
            g_input.len--;
        }
        break;

    case KEY_DELETE:
        if (g_input.cursor < g_input.len) {
            memmove(&g_input.buf[g_input.cursor], &g_input.buf[g_input.cursor + 1],
                    g_input.len - g_input.cursor);
            g_input.len--;
        }
        break;

    case KEY_LEFT:
        if (g_input.cursor > 0) g_input.cursor--;
        break;

    case KEY_RIGHT:
        if (g_input.cursor < g_input.len) g_input.cursor++;
        break;

    case KEY_HOME:
        g_input.cursor = 0;
        break;

    case KEY_END:
        g_input.cursor = g_input.len;
        break;

    case KEY_PGUP:
        if (g_history.scroll < g_history.count - g_layout.messages.h + 2) g_history.scroll++;
        break;

    case KEY_PGDN:
        if (g_history.scroll > 0) g_history.scroll--;
        break;

    case KEY_CTRL_U:
        g_input.len = 0;
        g_input.cursor = 0;
        break;

    case KEY_CTRL_W:
        /* Delete word backward */
        while (g_input.cursor > 0 && g_input.buf[g_input.cursor - 1] == ' ') {
            g_input.cursor--;
            g_input.len--;
        }
        while (g_input.cursor > 0 && g_input.buf[g_input.cursor - 1] != ' ') {
            g_input.cursor--;
            g_input.len--;
        }
        memmove(&g_input.buf[g_input.cursor], &g_input.buf[g_input.len],
                MAX_TEXT_LEN - g_input.len);
        break;

    default:
        if (c >= 32 && c < 127 && g_input.len < MAX_TEXT_LEN - 1) {
            memmove(&g_input.buf[g_input.cursor + 1], &g_input.buf[g_input.cursor],
                    g_input.len - g_input.cursor + 1);
            g_input.buf[g_input.cursor] = (char)c;
            g_input.cursor++;
            g_input.len++;
        }
        break;
    }
    return 0;
}

/* ============================================================
 * Original Network Code (preserved)
 * ============================================================ */

/* [Rest of original networking code goes here...] */
/* Include the unchanged definitions for: */
/* - peer_t, ioctx_t, outmsg_t structures */
/* - Network functions (tcp, noise, yamux) */
/* - Handshake functions */
/* - mDNS discovery */
/* - Main networking loop */

/* ============================================================
 * Emit Functions (Updated for new TUI)
 * ============================================================ */

static void emit_chat(const char *pid, const char *nick, const char *text) {
    history_add(MSG_CHAT, nick, pid, text);
}

static void emit_system_msg(const char *text) {
    history_add(MSG_SYSTEM, NULL, NULL, text);
    netlog_add(NETLOG_INFO, "%s", text);
}

static void emit_join(const char *nick, const char *pid) {
    char buf[MAX_TEXT_LEN];
    snprintf(buf, sizeof(buf), "%s joined (%s)", nick, pid);
    history_add(MSG_JOIN, nick, pid, buf);
    netlog_add(NETLOG_OK, "peer joined %s", nick);
}

static void emit_leave(const char *nick) {
    char buf[MAX_TEXT_LEN];
    snprintf(buf, sizeof(buf), "%s left", nick);
    history_add(MSG_LEAVE, nick, NULL, buf);
    netlog_add(NETLOG_WARN, "peer left %s", nick);
}

static void emit_error_msg(const char *text) {
    history_add(MSG_ERROR, NULL, NULL, text);
    netlog_add(NETLOG_ERROR, "%s", text);
}

/* [All the original networking code from the previous version goes here...] */
/* For brevity in this implementation, I'll include the key functions: */

static peer_t *peer_alloc(void) {
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!g_peers.peers[i].active) {
            peer_t *p = &g_peers.peers[i];
            memset(p, 0, sizeof(*p));
            MUTEX_INIT(&p->out_mu);
            MUTEX_INIT(&p->send_mu);
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
    MUTEX_DESTROY(&p->send_mu);
    MUTEX_UNLOCK(&g_peers.mu);
}

static int peer_already_connected(const char *pid_b58) {
    if (!pid_b58 || !pid_b58[0]) return 0;
    int found = 0;
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && strcmp(p->remote_pid_full, pid_b58) == 0) {
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

static int connected_peer_count(void) {
    int n = 0;
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && p->handshake_done) n++;
    }
    MUTEX_UNLOCK(&g_peers.mu);
    return n;
}

static void send_file_to_peer(peer_t *p, uint32_t file_id) {
    tx_file_t tx;
    int found = 0;

    MUTEX_LOCK(&g_file_mu);
    for (int i = 0; i < MAX_RX_FILES; i++) {
        if (g_tx_files[i].active && g_tx_files[i].id == file_id) {
            tx = g_tx_files[i];
            found = 1;
            break;
        }
    }
    MUTEX_UNLOCK(&g_file_mu);

    if (!found) {
        netlog_add(NETLOG_WARN, "accept for unknown file %lu", (unsigned long)file_id);
        return;
    }

    FILE *fp = fopen(tx.path, "rb");
    if (!fp) {
        netlog_add(NETLOG_ERROR, "could not reopen %s", tx.name);
        return;
    }

    uint8_t chunk[FILE_CHUNK_BYTES];
    char hex[FILE_CHUNK_BYTES * 2 + 1];
    char payload[MAX_TEXT_LEN];
    unsigned long long sent = 0;
    size_t n = 0;
    while ((n = fread(chunk, 1, sizeof(chunk), fp)) > 0) {
        hex_encode(chunk, n, hex, sizeof(hex));
        snprintf(payload, sizeof(payload), "%lu|%s", (unsigned long)file_id, hex);
        peer_enqueue(p, CHAT_TYPE_FILE_CHUNK, payload);
        sent += n;
        netlog_add(NETLOG_TRAFFIC, "file tx %s %llu/%lluB", tx.name, sent, tx.size);
    }
    fclose(fp);

    snprintf(payload, sizeof(payload), "%lu", (unsigned long)file_id);
    peer_enqueue(p, CHAT_TYPE_FILE_DONE, payload);
    netlog_add(sent == tx.size ? NETLOG_OK : NETLOG_WARN, "file tx done %s", tx.name);
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

static const char *path_basename(const char *path) {
    const char *base = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\') base = p + 1;
    }
    return base;
}

static void sanitize_file_name(char *out, size_t cap, const char *name) {
    size_t j = 0;
    if (cap == 0) return;
    for (size_t i = 0; name[i] && j + 1 < cap; i++) {
        char c = name[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '.' || c == '_' || c == '-') {
            out[j++] = c;
        } else if (c == ' ') {
            out[j++] = '_';
        }
    }
    if (j == 0) {
        snprintf(out, cap, "blob");
        return;
    }
    out[j] = 0;
}

static int ensure_recv_dir(void) {
#if defined(_WIN32)
    return _mkdir("speer_received") == 0 || errno == EEXIST ? 0 : -1;
#else
    return mkdir("speer_received", 0755) == 0 || errno == EEXIST ? 0 : -1;
#endif
}

static void hex_encode(const uint8_t *in, size_t len, char *out, size_t cap) {
    static const char hx[] = "0123456789abcdef";
    size_t j = 0;
    for (size_t i = 0; i < len && j + 2 < cap; i++) {
        out[j++] = hx[(in[i] >> 4) & 0xf];
        out[j++] = hx[in[i] & 0xf];
    }
    out[j] = 0;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *in, uint8_t *out, size_t cap, size_t *out_len) {
    size_t n = strlen(in);
    if ((n & 1) != 0 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hex_val(in[i]);
        int lo = hex_val(in[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

static void handle_file_frame(peer_t *p, uint32_t type, const char *payload) {
    if (type == CHAT_TYPE_FILE_META) {
        unsigned long id = 0;
        unsigned long long size = 0;
        char name[128] = "";
        if (sscanf(payload, "%lu|%llu|%127[^\n]", &id, &size, name) != 3 || id == 0) {
            netlog_add(NETLOG_WARN, "bad file metadata");
            return;
        }
        char clean_name[128];
        char clean_sender[64];
        sanitize_file_name(clean_name, sizeof(clean_name), name);
        sanitize_file_name(clean_sender, sizeof(clean_sender),
                           p->remote_nick[0] ? p->remote_nick : p->remote_pid_short);

        char path[260];
#if defined(_WIN32)
        snprintf(path, sizeof(path), "speer_received\\%s_%lu_%s", clean_sender, id, clean_name);
#else
        snprintf(path, sizeof(path), "speer_received/%s_%lu_%s", clean_sender, id, clean_name);
#endif

        int slot = -1;
        MUTEX_LOCK(&g_file_mu);
        for (int i = 0; i < MAX_RX_FILES; i++) {
            if (!g_rx_files[i].active) {
                slot = i;
                break;
            }
        }
        if (slot >= 0) {
            rx_file_t *rx = &g_rx_files[slot];
            memset(rx, 0, sizeof(*rx));
            rx->active = 1;
            rx->id = (uint32_t)id;
            rx->expected = size;
            rx->fp = NULL;
            snprintf(rx->sender, sizeof(rx->sender), "%s", p->remote_pid_full);
            snprintf(rx->name, sizeof(rx->name), "%s", clean_name);
            snprintf(rx->path, sizeof(rx->path), "%s", path);
        }
        MUTEX_UNLOCK(&g_file_mu);

        if (slot < 0) {
            emit_error_msg("too many incoming files");
            return;
        }

        char msg[MAX_TEXT_LEN];
        snprintf(msg, sizeof(msg), "incoming file %s (%llu bytes). type /accept %lu to receive",
                 clean_name, size, id);
        emit_system_msg(msg);
        netlog_add(NETLOG_WARN, "file pending %s id %lu", clean_name, id);
        return;
    }

    if (type == CHAT_TYPE_FILE_CHUNK) {
        unsigned long id = 0;
        const char *bar = strchr(payload, '|');
        if (!bar || sscanf(payload, "%lu", &id) != 1 || id == 0) {
            netlog_add(NETLOG_WARN, "bad file chunk");
            return;
        }
        const char *hex = bar + 1;
        uint8_t chunk[FILE_CHUNK_BYTES];
        size_t chunk_len = 0;
        if (hex_decode(hex, chunk, sizeof(chunk), &chunk_len) != 0) {
            netlog_add(NETLOG_WARN, "bad file chunk hex");
            return;
        }

        unsigned long long received = 0;
        unsigned long long expected = 0;
        char name[128] = "";
        int found = 0;
        MUTEX_LOCK(&g_file_mu);
        for (int i = 0; i < MAX_RX_FILES; i++) {
            rx_file_t *rx = &g_rx_files[i];
            if (rx->active && rx->id == (uint32_t)id &&
                strcmp(rx->sender, p->remote_pid_full) == 0) {
                if (!rx->fp) {
                    snprintf(name, sizeof(name), "%s", rx->name);
                    found = -1;
                } else if (fwrite(chunk, 1, chunk_len, rx->fp) == chunk_len) {
                    rx->received += chunk_len;
                    received = rx->received;
                    expected = rx->expected;
                    snprintf(name, sizeof(name), "%s", rx->name);
                    found = 1;
                }
                break;
            }
        }
        MUTEX_UNLOCK(&g_file_mu);

        if (found < 0) {
            netlog_add(NETLOG_WARN, "ignored unaccepted chunk %s", name);
            return;
        }
        if (!found) {
            netlog_add(NETLOG_WARN, "chunk for unknown file %lu", id);
            return;
        }
        netlog_add(NETLOG_TRAFFIC, "file rx %s %llu/%lluB", name, received, expected);
        return;
    }

    if (type == CHAT_TYPE_FILE_DONE) {
        unsigned long id = 0;
        if (sscanf(payload, "%lu", &id) != 1 || id == 0) return;

        char path[260] = "";
        char name[128] = "";
        unsigned long long received = 0;
        unsigned long long expected = 0;
        int ok = 0;
        MUTEX_LOCK(&g_file_mu);
        for (int i = 0; i < MAX_RX_FILES; i++) {
            rx_file_t *rx = &g_rx_files[i];
            if (rx->active && rx->id == (uint32_t)id &&
                strcmp(rx->sender, p->remote_pid_full) == 0) {
                if (rx->fp) fclose(rx->fp);
                rx->fp = NULL;
                snprintf(path, sizeof(path), "%s", rx->path);
                snprintf(name, sizeof(name), "%s", rx->name);
                received = rx->received;
                expected = rx->expected;
                ok = received == expected;
                memset(rx, 0, sizeof(*rx));
                break;
            }
        }
        MUTEX_UNLOCK(&g_file_mu);

        if (path[0]) {
            char msg[MAX_TEXT_LEN];
            snprintf(msg, sizeof(msg), "received file %s -> %s (%llu/%llu bytes)%s", name, path,
                     received, expected, ok ? "" : " incomplete");
            emit_system_msg(msg);
            netlog_add(ok ? NETLOG_OK : NETLOG_WARN, "file saved %s", name);
        }
    }

    if (type == CHAT_TYPE_FILE_ACCEPT) {
        unsigned long id = 0;
        if (sscanf(payload, "%lu", &id) != 1 || id == 0) return;
        netlog_add(NETLOG_OK, "file accepted by %s",
                   p->remote_nick[0] ? p->remote_nick : p->remote_pid_short);
        send_file_to_peer(p, (uint32_t)id);
        return;
    }
}

static void truncate_pid(char *out, size_t cap, const char *full) {
    size_t fl = strlen(full);
    if (fl <= 14 || cap < 16) {
        snprintf(out, cap, "%s", full);
        return;
    }
    snprintf(out, cap, "%.6s..%.6s", full, full + fl - 6);
}

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
    int rc = 0;
    if (io->send_mu) MUTEX_LOCK(io->send_mu);
    while (n > 0) {
        size_t chunk = n > 65519 ? 65519 : n;
        uint8_t ct[65535 + 16];
        size_t ct_len;
        if (speer_libp2p_noise_seal(io->noise, d, chunk, ct, &ct_len) != 0) {
            rc = -1;
            break;
        }
        if (ct_len > 0xffff) {
            rc = -1;
            break;
        }
        uint8_t h[2] = {(uint8_t)(ct_len >> 8), (uint8_t)ct_len};
        if (speer_tcp_send_all(io->fd, h, 2) != 0) {
            rc = -1;
            break;
        }
        if (speer_tcp_send_all(io->fd, ct, ct_len) != 0) {
            rc = -1;
            break;
        }
        d += chunk;
        n -= chunk;
    }
    if (io->send_mu) MUTEX_UNLOCK(io->send_mu);
    return rc;
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

static THREAD_RET peer_reader(void *arg) {
    peer_t *p = (peer_t *)arg;
    ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};

    while (!g_quit && !p->dead) {
        uint8_t frame[MAX_TEXT_LEN + 256];
        size_t flen = 0;
        if (speer_libp2p_uvar_frame_recv(&sio, ymux_recv, frame, sizeof(frame), &flen) != 0) break;
        p->bytes_rx += (unsigned long long)speer_uvarint_size((uint64_t)flen) +
                       (unsigned long long)flen;
        p->last_seen = time(NULL);
        uint32_t type = 0;
        char nick[MAX_NICK_LEN], text[MAX_TEXT_LEN];
        if (chat_frame_decode(frame, flen, &type, nick, sizeof(nick), text, sizeof(text)) != 0)
            continue;
        if (nick[0]) {
            size_t l = strlen(nick);
            if (l >= sizeof(p->remote_nick)) l = sizeof(p->remote_nick) - 1;
            memcpy(p->remote_nick, nick, l);
            p->remote_nick[l] = 0;
        }
        if (type == CHAT_TYPE_MSG) {
            p->msgs_rx++;
            netlog_add(NETLOG_TRAFFIC, "rx chat %s %lluB",
                       p->remote_nick[0] ? p->remote_nick : p->remote_pid_short,
                       (unsigned long long)flen);
            emit_chat(p->remote_pid_full, p->remote_nick, text);
        } else if (type == CHAT_TYPE_FILE_META || type == CHAT_TYPE_FILE_CHUNK ||
                   type == CHAT_TYPE_FILE_DONE || type == CHAT_TYPE_FILE_ACCEPT) {
            handle_file_frame(p, type, text);
        } else if (type == CHAT_TYPE_HELLO) {
            netlog_add(NETLOG_OK, "hello %s",
                       p->remote_nick[0] ? p->remote_nick : p->remote_pid_short);
            emit_system_msg(" waved");
        } else if (type == CHAT_TYPE_BYE) {
            netlog_add(NETLOG_WARN, "bye %s",
                       p->remote_nick[0] ? p->remote_nick : p->remote_pid_short);
            break;
        }
    }
    p->dead = 1;
    return THREAD_RET_VAL;
}

static THREAD_RET peer_writer(void *arg) {
    peer_t *p = (peer_t *)arg;

    if (speer_libp2p_noise_init(&p->noise, g_my_static_pub, g_my_static_priv,
                                SPEER_LIBP2P_KEY_ED25519, g_my_ed_pub, 32, g_my_ed_seed, 32) != 0) {
        emit_error_msg("noise_init failed");
        peer_release(p);
        return THREAD_RET_VAL;
    }
    speer_tcp_set_io_timeout(p->fd, HANDSHAKE_TIMEOUT_S * 1000);

    if (p->initiator) {
        netlog_add(NETLOG_INFO, "dial tcp %s", p->addr);
        if (speer_ms_negotiate_initiator(&p->fd, tcp_plain_send, tcp_plain_recv, "/noise") != 0) {
            emit_error_msg("noise multistream failed");
            peer_release(p);
            return THREAD_RET_VAL;
        }
        if (noise_handshake_initiator(p->fd, &p->noise) != 0) {
            emit_error_msg("noise handshake failed");
            peer_release(p);
            return THREAD_RET_VAL;
        }
    } else {
        netlog_add(NETLOG_INFO, "accept tcp %s", p->addr);
        const char *protos[1] = {"/noise"};
        size_t sel = 0;
        if (speer_ms_negotiate_listener(&p->fd, tcp_plain_send, tcp_plain_recv, protos, 1, &sel) !=
            0) {
            emit_error_msg("noise multistream (listener) failed");
            peer_release(p);
            return THREAD_RET_VAL;
        }
        if (noise_handshake_responder(p->fd, &p->noise) != 0) {
            emit_error_msg("noise handshake (responder) failed");
            peer_release(p);
            return THREAD_RET_VAL;
        }
    }
    netlog_add(NETLOG_OK, "noise xx authenticated");

    char pid_b58[64];
    if (derive_remote_pid_b58(&p->noise, pid_b58, sizeof(pid_b58)) != 0)
        snprintf(pid_b58, sizeof(pid_b58), "(unknown)");
    snprintf(p->remote_pid_full, sizeof(p->remote_pid_full), "%s", pid_b58);
    truncate_pid(p->remote_pid_short, sizeof(p->remote_pid_short), pid_b58);
    netlog_add(NETLOG_OK, "peer id %s", p->remote_pid_short);

    if (strcmp(pid_b58, g_my_pid_b58) == 0) {
        peer_release(p);
        return THREAD_RET_VAL;
    }

    p->io.fd = p->fd;
    p->io.noise = &p->noise;
    p->io.q_len = p->io.q_off = 0;
    p->io.send_mu = NULL;

    if (p->initiator) {
        if (speer_ms_negotiate_initiator(&p->io, io_crypt_send, io_crypt_recv, "/yamux/1.0.0") !=
            0) {
            emit_error_msg("yamux multistream failed");
            peer_release(p);
            return THREAD_RET_VAL;
        }
    } else {
        const char *protos[1] = {"/yamux/1.0.0"};
        size_t sel = 0;
        if (speer_ms_negotiate_listener(&p->io, io_crypt_send, io_crypt_recv, protos, 1, &sel) !=
            0) {
            emit_error_msg("yamux multistream (listener) failed");
            peer_release(p);
            return THREAD_RET_VAL;
        }
    }
    netlog_add(NETLOG_OK, "yamux negotiated");

    speer_yamux_init(&p->mux, p->initiator, io_crypt_send, io_crypt_recv, &p->io);

    if (p->initiator) {
        p->chat_st = speer_yamux_open_stream(&p->mux);
        if (!p->chat_st) {
            emit_error_msg("yamux open stream failed");
            peer_release(p);
            return THREAD_RET_VAL;
        }
        ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};
        if (speer_ms_negotiate_initiator(&sio, ymux_send, ymux_recv, CHAT_PROTO) != 0) {
            emit_error_msg("chat-stream negotiate failed");
            peer_release(p);
            return THREAD_RET_VAL;
        }
        netlog_add(NETLOG_OK, "opened chat stream");
    } else {
        for (int waited_ms = 0; !p->chat_st && waited_ms < HANDSHAKE_TIMEOUT_S * 1000;
             waited_ms += 50) {
            (void)speer_yamux_pump(&p->mux);
            if (p->mux.streams) p->chat_st = p->mux.streams;
            if (!p->chat_st) thread_sleep_ms(50);
        }
        if (!p->chat_st) {
            emit_error_msg("no inbound chat stream");
            peer_release(p);
            return THREAD_RET_VAL;
        }
        const char *protos[1] = {CHAT_PROTO};
        size_t sel = 0;
        ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};
        if (speer_ms_negotiate_listener(&sio, ymux_send, ymux_recv, protos, 1, &sel) != 0) {
            emit_error_msg("chat-stream negotiate (listener) failed");
            peer_release(p);
            return THREAD_RET_VAL;
        }
        netlog_add(NETLOG_OK, "accepted chat stream");
    }

    {
        uint8_t frame[256 + MAX_NICK_LEN];
        size_t fl = 0;
        if (chat_frame_encode(frame, sizeof(frame), &fl, CHAT_TYPE_HELLO, g_my_nick, NULL) == 0) {
            ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};
            if (speer_libp2p_uvar_frame_send(&sio, ymux_send, frame, fl) == 0) {
                netlog_add(NETLOG_TRAFFIC, "tx hello %lluB",
                           (unsigned long long)(speer_uvarint_size((uint64_t)fl) + fl));
            }
        }
    }

    p->handshake_done = 1;
    p->connected_at = time(NULL);
    p->last_seen = p->connected_at;
    emit_join(p->remote_nick[0] ? p->remote_nick : "(unknown)", p->remote_pid_short);

    speer_tcp_set_io_timeout(p->fd, 0);
    p->io.send_mu = &p->send_mu;

    if (THREAD_CREATE(&p->reader_thread, peer_reader, p) != 0) {
        emit_error_msg("failed to spawn reader thread");
        p->dead = 1;
        goto done;
    }
    p->reader_started = 1;
    netlog_add(NETLOG_OK, "reader online");

    while (!g_quit && !p->dead) {
        outmsg_t *m;
        while ((m = peer_dequeue(p)) != NULL) {
            uint8_t frame[MAX_TEXT_LEN + 256];
            size_t fl = 0;
            if (chat_frame_encode(frame, sizeof(frame), &fl, m->type, g_my_nick, m->text) == 0) {
                ymux_io_t sio = {.mux = &p->mux, .st = p->chat_st};
                if (speer_libp2p_uvar_frame_send(&sio, ymux_send, frame, fl) != 0) {
                    free(m);
                    p->dead = 1;
                    goto done;
                }
                p->bytes_tx += (unsigned long long)speer_uvarint_size((uint64_t)fl) +
                               (unsigned long long)fl;
                p->last_seen = time(NULL);
                if (m->type == CHAT_TYPE_MSG) {
                    p->msgs_tx++;
                    netlog_add(NETLOG_TRAFFIC, "tx chat %s %lluB",
                               p->remote_nick[0] ? p->remote_nick : p->remote_pid_short,
                               (unsigned long long)fl);
                } else if (m->type == CHAT_TYPE_FILE_META || m->type == CHAT_TYPE_FILE_CHUNK ||
                           m->type == CHAT_TYPE_FILE_DONE || m->type == CHAT_TYPE_FILE_ACCEPT) {
                    netlog_add(NETLOG_TRAFFIC, "tx file frame %s %lluB",
                               p->remote_nick[0] ? p->remote_nick : p->remote_pid_short,
                               (unsigned long long)fl);
                } else if (m->type == CHAT_TYPE_BYE) {
                    netlog_add(NETLOG_TRAFFIC, "tx bye %s",
                               p->remote_nick[0] ? p->remote_nick : p->remote_pid_short);
                }
            }
            free(m);
        }
        thread_sleep_ms(WRITER_POLL_MS);
    }

done:
    if (p->fd >= 0) {
        speer_tcp_close(p->fd);
        p->fd = -1;
    }
    if (p->reader_started) THREAD_JOIN(p->reader_thread);

    emit_leave(p->remote_nick[0] ? p->remote_nick : p->remote_pid_short);
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
    if (!found &&
        st->num_attempted < (int)(sizeof(st->attempted_pids) / sizeof(st->attempted_pids[0]))) {
        snprintf(st->attempted_pids[st->num_attempted], sizeof(st->attempted_pids[0]), "%s", pid);
        st->num_attempted++;
    }
    MUTEX_UNLOCK(&st->attempted_mu);
    return found;
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
    netlog_add(NETLOG_INFO, "mDNS %s", multiaddr);

    int fd = -1;
    if (speer_tcp_dial_timeout(&fd, host, (uint16_t)port, 3000) != 0) {
        netlog_add(NETLOG_WARN, "dial failed %s:%d", host, port);
        return;
    }

    peer_t *p = peer_alloc();
    if (!p) {
        speer_tcp_close(fd);
        return;
    }
    p->fd = fd;
    p->initiator = 1;
    snprintf(p->addr, sizeof(p->addr), "%s:%d", host, port);
    char short_pid[64];
    truncate_pid(short_pid, sizeof(short_pid), peer_id);
    snprintf(p->remote_pid_full, sizeof(p->remote_pid_full), "%s", peer_id);
    snprintf(p->remote_pid_short, sizeof(p->remote_pid_short), "%s", short_pid);
    emit_system_msg("dialing peer...");
    THREAD_CREATE(&p->writer_thread, peer_writer, p);
}

static THREAD_RET disc_accept_thread(void *arg) {
    disc_state_t *st = (disc_state_t *)arg;
    speer_tcp_set_nonblocking(st->listen_fd, 1);

    int announce_acc = 0;
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
                netlog_add(NETLOG_INFO, "tcp accept %s", peer_addr);
                emit_system_msg("incoming connection");
                THREAD_CREATE(&p->writer_thread, peer_writer, p);
            }
        }
        announce_acc += 100;
        if (announce_acc >= 1000) {
            mdns_announce(st->mctx);
            mdns_query(st->mctx, CHAT_SERVICE_TYPE ".local");
            announce_acc = 0;
        }
        (void)mdns_poll(st->mctx, 100);
    }
    return THREAD_RET_VAL;
}

static void cmd_peers(void) {
    int n = 0;
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && p->handshake_done) n++;
    }
    MUTEX_UNLOCK(&g_peers.mu);

    char buf[MAX_TEXT_LEN];
    snprintf(buf, sizeof(buf), "%d peer%s connected", n, n == 1 ? "" : "s");
    emit_system_msg(buf);

    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && p->handshake_done) {
            char active_for[32];
            format_duration(p->connected_at, active_for, sizeof(active_for));
            snprintf(buf, sizeof(buf), "%s  %s  %s  up %s  rx%llu tx%llu",
                     p->remote_nick[0] ? p->remote_nick : "?", p->remote_pid_short, p->addr,
                     active_for, p->msgs_rx, p->msgs_tx);
            emit_system_msg(buf);
        }
    }
    MUTEX_UNLOCK(&g_peers.mu);
}

static void cmd_status(void) {
    int peer_count = 0;
    unsigned long long rx_msgs = 0, tx_msgs = 0, rx_bytes = 0, tx_bytes = 0;
    collect_peer_stats(&peer_count, &rx_msgs, &tx_msgs, &rx_bytes, &tx_bytes);
    char uptime[32];
    char buf[MAX_TEXT_LEN];
    format_duration(g_started_at, uptime, sizeof(uptime));
    snprintf(buf, sizeof(buf),
             "status: %s:%u  uptime %s  peers %d  rx %llu msg/%llu B  tx %llu msg/%llu B", g_lan_ip,
             (unsigned)g_listen_port, uptime, peer_count, rx_msgs, rx_bytes, tx_msgs, tx_bytes);
    emit_system_msg(buf);
    emit_system_msg("stack: mDNS discovery -> TCP -> Noise XX authenticated encryption -> Yamux "
                    "stream mux -> /speer/chat/1.0.0");
}

static void cmd_id(void) {
    char buf[MAX_TEXT_LEN];
    snprintf(buf, sizeof(buf), "nick: %s", g_my_nick);
    emit_system_msg(buf);
    snprintf(buf, sizeof(buf), "peer id: %s", g_my_pid_b58);
    emit_system_msg(buf);
    snprintf(buf, sizeof(buf), "multiaddr: /ip4/%s/tcp/%u/p2p/%s", g_lan_ip,
             (unsigned)g_listen_port, g_my_pid_b58);
    emit_system_msg(buf);
}

static void cmd_inspect(void) {
    int shown = 0;
    char buf[MAX_TEXT_LEN];
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && p->handshake_done) {
            char active_for[32];
            char idle_for[32];
            format_duration(p->connected_at, active_for, sizeof(active_for));
            format_duration(p->last_seen, idle_for, sizeof(idle_for));
            snprintf(buf, sizeof(buf), "peer %d: %s  %s", shown + 1,
                     p->remote_nick[0] ? p->remote_nick : "?",
                     p->remote_pid_full[0] ? p->remote_pid_full : p->remote_pid_short);
            emit_system_msg(buf);
            snprintf(buf, sizeof(buf),
                     "  addr %s  role %s  up %s  idle %s  rx %llu/%lluB  tx %llu/%lluB", p->addr,
                     p->initiator ? "dialer" : "listener", active_for, idle_for, p->msgs_rx,
                     p->bytes_rx, p->msgs_tx, p->bytes_tx);
            emit_system_msg(buf);
            shown++;
        }
    }
    MUTEX_UNLOCK(&g_peers.mu);
    if (shown == 0) emit_system_msg("inspect: no connected peers yet");
}

static void trim_send_path(const char *in, char *out, size_t cap) {
    while (*in == ' ' || *in == '\t') in++;
    if (*in == '"') {
        in++;
        size_t n = 0;
        while (*in && *in != '"' && n + 1 < cap) out[n++] = *in++;
        out[n] = 0;
        return;
    }
    snprintf(out, cap, "%s", in);
    size_t n = strlen(out);
    while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\t')) out[--n] = 0;
}

static void cmd_send_file(const char *arg) {
    char path[512];
    trim_send_path(arg, path, sizeof(path));
    if (!path[0]) {
        emit_error_msg("usage: /send <path>");
        return;
    }
    if (connected_peer_count() == 0) {
        emit_error_msg("no connected peers for file transfer");
        return;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        char msg[MAX_TEXT_LEN];
        snprintf(msg, sizeof(msg), "could not open file: %s", path);
        emit_error_msg(msg);
        return;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        emit_error_msg("could not size file");
        return;
    }
    long fsize_long = ftell(fp);
    if (fsize_long < 0) {
        fclose(fp);
        emit_error_msg("could not size file");
        return;
    }
    rewind(fp);

    char clean_name[128];
    sanitize_file_name(clean_name, sizeof(clean_name), path_basename(path));
    uint32_t file_id = (uint32_t)time(NULL) ^ g_next_file_id++;
    unsigned long long fsize = (unsigned long long)fsize_long;
    fclose(fp);

    int stored = 0;
    MUTEX_LOCK(&g_file_mu);
    for (int i = 0; i < MAX_RX_FILES; i++) {
        if (!g_tx_files[i].active) {
            tx_file_t *tx = &g_tx_files[i];
            memset(tx, 0, sizeof(*tx));
            tx->active = 1;
            tx->id = file_id;
            tx->size = fsize;
            snprintf(tx->name, sizeof(tx->name), "%s", clean_name);
            snprintf(tx->path, sizeof(tx->path), "%s", path);
            stored = 1;
            break;
        }
    }
    MUTEX_UNLOCK(&g_file_mu);

    if (!stored) {
        emit_error_msg("too many outgoing files pending");
        return;
    }

    char payload[MAX_TEXT_LEN];
    snprintf(payload, sizeof(payload), "%lu|%llu|%s", (unsigned long)file_id, fsize, clean_name);
    broadcast(CHAT_TYPE_FILE_META, payload);

    char msg[MAX_TEXT_LEN];
    snprintf(msg, sizeof(msg), "offered file %s (%llu bytes), waiting for peer acceptance",
             clean_name, fsize);
    emit_system_msg(msg);
    netlog_add(NETLOG_OK, "file offered %s id %lu", clean_name, (unsigned long)file_id);
}

static void cmd_accept_file(const char *arg) {
    while (*arg == ' ' || *arg == '\t') arg++;
    uint32_t wanted = (uint32_t)strtoul(arg, NULL, 10);
    int chosen = -1;
    int pending = 0;

    MUTEX_LOCK(&g_file_mu);
    for (int i = 0; i < MAX_RX_FILES; i++) {
        rx_file_t *rx = &g_rx_files[i];
        if (rx->active && !rx->fp) {
            pending++;
            if ((wanted != 0 && rx->id == wanted) || (wanted == 0 && chosen < 0)) { chosen = i; }
        }
    }
    MUTEX_UNLOCK(&g_file_mu);

    if (chosen < 0 || (wanted == 0 && pending > 1)) {
        emit_error_msg(wanted == 0 && pending > 1 ? "multiple pending files; use /accept <id>"
                                                  : "no pending file to accept");
        return;
    }

    if (ensure_recv_dir() != 0) {
        emit_error_msg("could not create speer_received directory");
        return;
    }

    char sender[64] = "";
    char path[260] = "";
    char name[128] = "";
    uint32_t id = 0;
    FILE *fp = NULL;

    MUTEX_LOCK(&g_file_mu);
    rx_file_t *rx = &g_rx_files[chosen];
    if (rx->active && !rx->fp) {
        fp = fopen_write_bin_private(rx->path);
        if (fp) {
            rx->fp = fp;
            id = rx->id;
            snprintf(sender, sizeof(sender), "%s", rx->sender);
            snprintf(path, sizeof(path), "%s", rx->path);
            snprintf(name, sizeof(name), "%s", rx->name);
        }
    }
    MUTEX_UNLOCK(&g_file_mu);

    if (!fp) {
        emit_error_msg("could not open receive file");
        return;
    }

    char payload[32];
    snprintf(payload, sizeof(payload), "%lu", (unsigned long)id);
    MUTEX_LOCK(&g_peers.mu);
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_t *p = &g_peers.peers[i];
        if (p->active && !p->dead && p->handshake_done && strcmp(p->remote_pid_full, sender) == 0) {
            peer_enqueue(p, CHAT_TYPE_FILE_ACCEPT, payload);
            break;
        }
    }
    MUTEX_UNLOCK(&g_peers.mu);

    char msg[MAX_TEXT_LEN];
    snprintf(msg, sizeof(msg), "accepted file %s -> %s", name, path);
    emit_system_msg(msg);
    netlog_add(NETLOG_OK, "file accept %s id %lu", name, (unsigned long)id);
}

#if defined(_WIN32)
static void win_console_setup(void) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD m = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &m)) {
        SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &m)) {
        SetConsoleMode(h, m | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}
#endif

/* ============================================================
 * Main
 * ============================================================ */

int main(int argc, char **argv) {
#if defined(_WIN32)
    win_console_setup();
#endif

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--nick") == 0 && i + 1 < argc) {
            arg = argv[++i];
        } else if (strncmp(arg, "--nick=", 7) == 0) {
            arg = arg + 7;
        } else if (strcmp(arg, "--theme") == 0 && i + 1 < argc) {
            const char *theme = argv[++i];
            if (strcmp(theme, "midnight") == 0)
                g_theme = &THEME_MIDNIGHT;
            else if (strcmp(theme, "original") == 0)
                g_theme = &THEME_ORIGINAL;
            else
                g_theme = &THEME_MODERN;
            continue;
        } else if (arg[0] == '-') {
            continue;
        }
        size_t l = strlen(arg);
        if (l >= sizeof(g_my_nick)) l = sizeof(g_my_nick) - 1;
        memcpy(g_my_nick, arg, l);
        g_my_nick[l] = 0;
        break;
    }

    MUTEX_INIT(&g_log_mu);
    MUTEX_INIT(&g_file_mu);
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
    g_started_at = time(NULL);

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
    snprintf(g_lan_ip, sizeof(g_lan_ip), "%s", lan_ip);
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

    /* Initialize TUI */
    term_raw_mode_enter();
    term_altscreen_enter();
    screen_init();
    layout_calc();
    history_init();
    netlog_clear();
    memset(&g_input, 0, sizeof(g_input));

    emit_system_msg(
        "Welcome to speer-chat. Type /status, /inspect, or /id for the network console.");
    netlog_add(NETLOG_OK, "identity ready %s", g_my_pid_b58);
    netlog_add(NETLOG_OK, "tcp listen %s:%u", g_lan_ip, (unsigned)g_listen_port);
    netlog_add(NETLOG_OK, "mDNS service %s", CHAT_SERVICE_TYPE);

    THREAD_T disc_thread;
    THREAD_CREATE(&disc_thread, disc_accept_thread, &dst);

    mdns_announce(&mctx);
    mdns_query(&mctx, CHAT_SERVICE_TYPE ".local");

    /* Main input loop */
    int running = 1;
    while (running) {
        /* Check for resize */
#if defined(_WIN32)
        int old_rows = g_screen.rows, old_cols = g_screen.cols;
        term_get_size(&g_screen.rows, &g_screen.cols);
        if (old_rows != g_screen.rows || old_cols != g_screen.cols) { layout_calc(); }
#else
        if (g_got_sigwinch) {
            g_got_sigwinch = 0;
            term_get_size(&g_screen.rows, &g_screen.cols);
            layout_calc();
        }
#endif

        /* Process input */
        int result = process_input();
        if (result < 0) {
            running = 0;
            break;
        }
        if (result > 0) {
            /* Have complete input in g_input.buf */
            if (strcmp(g_input.buf, "/quit") == 0 || strcmp(g_input.buf, "/exit") == 0) {
                running = 0;
            } else if (strcmp(g_input.buf, "/peers") == 0 || strcmp(g_input.buf, "/who") == 0) {
                cmd_peers();
            } else if (strcmp(g_input.buf, "/status") == 0) {
                cmd_status();
            } else if (strcmp(g_input.buf, "/id") == 0 || strcmp(g_input.buf, "/me") == 0) {
                cmd_id();
            } else if (strcmp(g_input.buf, "/inspect") == 0 || strcmp(g_input.buf, "/diag") == 0) {
                cmd_inspect();
            } else if (strcmp(g_input.buf, "/clear") == 0) {
                history_init();
                emit_system_msg("timeline cleared");
            } else if (strcmp(g_input.buf, "/log clear") == 0) {
                netlog_clear();
                netlog_add(NETLOG_OK, "network console cleared");
            } else if (strcmp(g_input.buf, "/help") == 0) {
                emit_system_msg("Commands: /send <path> /accept [id] /status /inspect /id /peers "
                                "/clear /log clear /theme modern|midnight|original /quit");
            } else if (strncmp(g_input.buf, "/send ", 6) == 0) {
                cmd_send_file(g_input.buf + 6);
            } else if (strncmp(g_input.buf, "send ", 5) == 0) {
                cmd_send_file(g_input.buf + 5);
            } else if (strcmp(g_input.buf, "/accept") == 0) {
                cmd_accept_file("");
            } else if (strncmp(g_input.buf, "/accept ", 8) == 0) {
                cmd_accept_file(g_input.buf + 8);
            } else if (strncmp(g_input.buf, "/theme ", 7) == 0) {
                const char *t = g_input.buf + 7;
                if (strcmp(t, "midnight") == 0)
                    g_theme = &THEME_MIDNIGHT;
                else if (strcmp(t, "original") == 0)
                    g_theme = &THEME_ORIGINAL;
                else if (strcmp(t, "modern") == 0)
                    g_theme = &THEME_MODERN;
                emit_system_msg("Theme changed");
            } else if (g_input.buf[0] == '/') {
                emit_error_msg("Unknown command");
            } else {
                broadcast(CHAT_TYPE_MSG, g_input.buf);
                emit_chat(g_my_pid_b58, g_my_nick, g_input.buf);
            }
            /* Clear input */
            memset(&g_input, 0, sizeof(g_input));
        }

        /* Render */
        render_full();

        /* Small delay to prevent busy looping */
        thread_sleep_ms(10);
    }

    /* Cleanup */
    g_quit = 1;
    broadcast(CHAT_TYPE_BYE, NULL);
    thread_sleep_ms(200);

    speer_tcp_close(lfd);
    mdns_unregister_service(&mctx, rand_name);
    mdns_free(&mctx);

    term_altscreen_exit();
    term_raw_mode_exit();

    printf("  - bye\n");
    return 0;
}
