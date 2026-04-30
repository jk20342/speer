#include "ghash.h"

#include "cpu_features.h"

void speer_ghash_init(speer_ghash_state_t *s, const uint8_t h[16]) {
#ifdef SPEER_GHASH_CLMUL_AVAILABLE
    if (speer_cpu_has_aes_clmul()) {
        speer_ghash_clmul_init(s, h);
        return;
    }
#endif
    speer_ghash_soft_init(s, h);
}

void speer_ghash_absorb(speer_ghash_state_t *s, uint8_t y[16], const uint8_t *data, size_t len) {
#ifdef SPEER_GHASH_CLMUL_AVAILABLE
    if (s->use_clmul) {
        speer_ghash_clmul_absorb(s, y, data, len);
        return;
    }
#endif
    speer_ghash_soft_absorb(s, y, data, len);
}
