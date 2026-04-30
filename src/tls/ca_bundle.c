#include "speer_internal.h"
#include "ca_bundle.h"

#if defined(SPEER_CA_BUNDLE_GENERATED)
#include "ca_bundle_generated.inc"
#else
static const speer_ca_entry_t empty_entries[] = {{0}};
static const speer_ca_store_t empty_store = { empty_entries, 0 };
#endif

const speer_ca_store_t* speer_ca_bundle_default(void) {
#if defined(SPEER_CA_BUNDLE_GENERATED)
    return &generated_ca_store;
#else
    return &empty_store;
#endif
}
