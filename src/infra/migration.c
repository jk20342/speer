#include "speer_internal.h"
#include "migration.h"

void speer_migration_init(speer_migration_t* m, uint64_t timeout_ms) {
    ZERO(m, sizeof(*m));
    m->timeout_ms = timeout_ms ? timeout_ms : 3000;
}

int speer_migration_emit_challenge(speer_migration_t* m, uint64_t now_ms, uint8_t out_data[8]) {
    int slot = -1;
    for (int i = 0; i < SPEER_MIG_MAX_OUTSTANDING; i++) {
        if (!m->challenges[i].active) { slot = i; break; }
    }
    if (slot < 0) return -1;
    speer_random_bytes(out_data, 8);
    COPY(m->challenges[slot].data, out_data, 8);
    m->challenges[slot].sent_ms = now_ms;
    m->challenges[slot].active = 1;
    return 0;
}

int speer_migration_on_response(speer_migration_t* m, const uint8_t data[8], uint64_t now_ms) {
    for (int i = 0; i < SPEER_MIG_MAX_OUTSTANDING; i++) {
        if (m->challenges[i].active && EQUAL(m->challenges[i].data, data, 8)) {
            m->challenges[i].active = 0;
            m->validated = 1;
            m->validated_ms = now_ms;
            return 0;
        }
    }
    return -1;
}

int speer_migration_is_validated(const speer_migration_t* m) {
    return m->validated;
}

int speer_migration_check_timeouts(speer_migration_t* m, uint64_t now_ms) {
    int expired = 0;
    for (int i = 0; i < SPEER_MIG_MAX_OUTSTANDING; i++) {
        if (m->challenges[i].active && now_ms - m->challenges[i].sent_ms > m->timeout_ms) {
            m->challenges[i].active = 0;
            expired++;
        }
    }
    return expired;
}
