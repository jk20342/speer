#ifndef SPEER_MIGRATION_H
#define SPEER_MIGRATION_H

#include <stdint.h>
#include <stddef.h>

#define SPEER_MIG_MAX_OUTSTANDING 4

typedef struct {
    uint8_t data[8];
    uint64_t sent_ms;
    int active;
} speer_path_chal_t;

typedef struct {
    speer_path_chal_t challenges[SPEER_MIG_MAX_OUTSTANDING];
    uint64_t timeout_ms;
    int validated;
    uint64_t validated_ms;
} speer_migration_t;

void speer_migration_init(speer_migration_t* m, uint64_t timeout_ms);
int  speer_migration_emit_challenge(speer_migration_t* m, uint64_t now_ms, uint8_t out_data[8]);
int  speer_migration_on_response(speer_migration_t* m, const uint8_t data[8], uint64_t now_ms);
int  speer_migration_is_validated(const speer_migration_t* m);
int  speer_migration_check_timeouts(speer_migration_t* m, uint64_t now_ms);

#endif
