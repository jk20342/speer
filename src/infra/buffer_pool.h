#ifndef SPEER_BUFFER_POOL_H
#define SPEER_BUFFER_POOL_H

#include <stddef.h>
#include <stdint.h>

typedef struct speer_buf_pool_s speer_buf_pool_t;

speer_buf_pool_t *speer_buf_pool_create(size_t buffer_size, size_t count);
void speer_buf_pool_destroy(speer_buf_pool_t *p);
uint8_t *speer_buf_pool_acquire(speer_buf_pool_t *p, size_t *out_size);
void speer_buf_pool_release(speer_buf_pool_t *p, uint8_t *buf);
size_t speer_buf_pool_in_use(const speer_buf_pool_t *p);
size_t speer_buf_pool_capacity(const speer_buf_pool_t *p);

#endif
