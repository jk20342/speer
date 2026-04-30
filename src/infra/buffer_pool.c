#include "buffer_pool.h"

#include "speer_internal.h"

#if defined(_WIN32)
#include <windows.h>
typedef CRITICAL_SECTION speer_pool_mutex_t;
#define POOL_MUTEX_INIT(m)    InitializeCriticalSection(m)
#define POOL_MUTEX_DESTROY(m) DeleteCriticalSection(m)
#define POOL_MUTEX_LOCK(m)    EnterCriticalSection(m)
#define POOL_MUTEX_UNLOCK(m)  LeaveCriticalSection(m)
#else
#include <pthread.h>
typedef pthread_mutex_t speer_pool_mutex_t;
#define POOL_MUTEX_INIT(m)    pthread_mutex_init((m), NULL)
#define POOL_MUTEX_DESTROY(m) pthread_mutex_destroy(m)
#define POOL_MUTEX_LOCK(m)    pthread_mutex_lock(m)
#define POOL_MUTEX_UNLOCK(m)  pthread_mutex_unlock(m)
#endif

struct speer_buf_pool_s {
    uint8_t *storage;
    uint8_t *free_flags;
    size_t buffer_size;
    size_t count;
    size_t in_use;
    size_t next_hint;
    speer_pool_mutex_t mutex;
};

speer_buf_pool_t *speer_buf_pool_create(size_t buffer_size, size_t count) {
    if (buffer_size == 0 || count == 0) return NULL;
    speer_buf_pool_t *p = (speer_buf_pool_t *)calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->storage = (uint8_t *)calloc(count, buffer_size);
    p->free_flags = (uint8_t *)calloc(count, 1);
    if (!p->storage || !p->free_flags) {
        free(p->storage);
        free(p->free_flags);
        free(p);
        return NULL;
    }
    p->buffer_size = buffer_size;
    p->count = count;
    POOL_MUTEX_INIT(&p->mutex);
    return p;
}

void speer_buf_pool_destroy(speer_buf_pool_t *p) {
    if (!p) return;
    POOL_MUTEX_DESTROY(&p->mutex);
    free(p->storage);
    free(p->free_flags);
    free(p);
}

uint8_t *speer_buf_pool_acquire(speer_buf_pool_t *p, size_t *out_size) {
    if (!p) return NULL;
    uint8_t *result = NULL;
    POOL_MUTEX_LOCK(&p->mutex);
    for (size_t off = 0; off < p->count; off++) {
        size_t i = (p->next_hint + off) % p->count;
        if (!p->free_flags[i]) {
            p->free_flags[i] = 1;
            p->in_use++;
            p->next_hint = (i + 1) % p->count;
            if (out_size) *out_size = p->buffer_size;
            result = p->storage + i * p->buffer_size;
            break;
        }
    }
    POOL_MUTEX_UNLOCK(&p->mutex);
    return result;
}

void speer_buf_pool_release(speer_buf_pool_t *p, uint8_t *buf) {
    if (!p || !buf) return;
    if (buf < p->storage) return;
    size_t off = (size_t)(buf - p->storage);
    if (off % p->buffer_size != 0) return;
    size_t i = off / p->buffer_size;
    if (i >= p->count) return;
    POOL_MUTEX_LOCK(&p->mutex);
    if (p->free_flags[i]) {
        p->free_flags[i] = 0;
        p->in_use--;
    }
    POOL_MUTEX_UNLOCK(&p->mutex);
}

size_t speer_buf_pool_in_use(const speer_buf_pool_t *p) {
    if (!p) return 0;
    POOL_MUTEX_LOCK((speer_pool_mutex_t *)&p->mutex);
    size_t v = p->in_use;
    POOL_MUTEX_UNLOCK((speer_pool_mutex_t *)&p->mutex);
    return v;
}

size_t speer_buf_pool_capacity(const speer_buf_pool_t *p) {
    return p ? p->count : 0;
}
