#ifndef SPEER_CPU_FEATURES_H
#define SPEER_CPU_FEATURES_H

#define SPEER_CPUF_SSE2        (1u << 0)
#define SPEER_CPUF_SSSE3       (1u << 1)
#define SPEER_CPUF_AESNI       (1u << 2)
#define SPEER_CPUF_PCLMUL      (1u << 3)
#define SPEER_CPUF_AVX         (1u << 4)
#define SPEER_CPUF_AVX2        (1u << 5)
#define SPEER_CPUF_BMI2        (1u << 6)
#define SPEER_CPUF_SHA         (1u << 7)
#define SPEER_CPUF_SSE41       (1u << 8)
#define SPEER_CPUF_ARMV8_AES   (1u << 9)
#define SPEER_CPUF_ARMV8_PMULL (1u << 10)

unsigned speer_cpu_features(void);

int speer_cpu_has_aes_clmul(void);
int speer_cpu_has_avx2(void);
int speer_cpu_has_sha(void);

#endif
