#include "speer_internal.h"
#include "buffer_pool.h"
#include <stdio.h>
#include <string.h>

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); return 1; } while (0)

int main(void) {
    if (speer_buf_pool_create(0, 4) != NULL) FAIL("reject zero size\n");
    if (speer_buf_pool_create(16, 0) != NULL) FAIL("reject zero count\n");

    speer_buf_pool_t* p = speer_buf_pool_create(16, 3);
    if (!p) FAIL("create\n");

    if (speer_buf_pool_in_use(p) != 0 || speer_buf_pool_capacity(p) != 3) FAIL("initial stats\n");

    size_t sz = 0;
    uint8_t* a = speer_buf_pool_acquire(p, &sz);
    uint8_t* b = speer_buf_pool_acquire(p, &sz);
    uint8_t* c = speer_buf_pool_acquire(p, &sz);
    if (!a || !b || !c || sz != 16) FAIL("acquire three\n");
    if (speer_buf_pool_acquire(p, &sz) != NULL) FAIL("pool exhausted\n");
    if (speer_buf_pool_in_use(p) != 3) FAIL("in_use 3\n");

    memset(a, 0x11, 16);
    speer_buf_pool_release(p, a);
    if (speer_buf_pool_in_use(p) != 2) FAIL("after release\n");

    uint8_t* a2 = speer_buf_pool_acquire(p, &sz);
    if (!a2 || a2 != a) FAIL("reuse slot\n");

    speer_buf_pool_release(p, NULL);
    speer_buf_pool_release(NULL, a2);
    speer_buf_pool_release(p, a + 1);

    speer_buf_pool_release(p, b);
    speer_buf_pool_release(p, c);
    speer_buf_pool_release(p, a2);

    speer_buf_pool_destroy(p);
    speer_buf_pool_destroy(NULL);

    puts("buffer_pool: ok");
    return 0;
}
