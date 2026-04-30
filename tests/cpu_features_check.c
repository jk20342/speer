#include <stdio.h>

#include "cpu_features.h"

int main(void) {
    unsigned f = speer_cpu_features();
    printf("cpu features: 0x%08x\n", f);
    printf("  sse2:         %s\n", (f & SPEER_CPUF_SSE2) ? "yes" : "no");
    printf("  ssse3:        %s\n", (f & SPEER_CPUF_SSSE3) ? "yes" : "no");
    printf("  aes-ni:       %s\n", (f & SPEER_CPUF_AESNI) ? "yes" : "no");
    printf("  pclmulqdq:    %s\n", (f & SPEER_CPUF_PCLMUL) ? "yes" : "no");
    printf("  avx:          %s\n", (f & SPEER_CPUF_AVX) ? "yes" : "no");
    printf("  armv8 aes:    %s\n", (f & SPEER_CPUF_ARMV8_AES) ? "yes" : "no");
    printf("  armv8 pmull:  %s\n", (f & SPEER_CPUF_ARMV8_PMULL) ? "yes" : "no");
    printf("aead path:      %s\n", speer_cpu_has_aes_clmul() ? "AES-NI/PCLMUL" : "software");
    return 0;
}
