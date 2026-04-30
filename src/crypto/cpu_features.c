#include "cpu_features.h"

#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <cpuid.h>
#define SPEER_HAVE_X86 1
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#define SPEER_HAVE_X86 1
#endif

#if defined(__aarch64__)
#if defined(__linux__)
#include <sys/auxv.h>
#ifndef HWCAP_AES
#define HWCAP_AES (1 << 3)
#endif
#ifndef HWCAP_PMULL
#define HWCAP_PMULL (1 << 4)
#endif
#endif
#define SPEER_HAVE_ARM 1
#endif

static unsigned g_cached_features = 0;
static int g_cached_init = 0;

#if defined(SPEER_HAVE_X86)
static void cpuid_leaf(unsigned leaf, unsigned subleaf, unsigned *eax, unsigned *ebx, unsigned *ecx,
                       unsigned *edx) {
#if defined(_MSC_VER) && !defined(__clang__)
    int regs[4];
    __cpuidex(regs, (int)leaf, (int)subleaf);
    *eax = (unsigned)regs[0];
    *ebx = (unsigned)regs[1];
    *ecx = (unsigned)regs[2];
    *edx = (unsigned)regs[3];
#else
    unsigned a = 0, b = 0, c = 0, d = 0;
    __cpuid_count(leaf, subleaf, a, b, c, d);
    *eax = a;
    *ebx = b;
    *ecx = c;
    *edx = d;
#endif
}
#endif

static unsigned detect_features(void) {
    unsigned f = 0;
#if defined(SPEER_HAVE_X86)
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    cpuid_leaf(1, 0, &eax, &ebx, &ecx, &edx);
    if (edx & (1u << 26)) f |= SPEER_CPUF_SSE2;
    if (ecx & (1u << 9)) f |= SPEER_CPUF_SSSE3;
    if (ecx & (1u << 19)) f |= SPEER_CPUF_SSE41;
    if (ecx & (1u << 25)) f |= SPEER_CPUF_AESNI;
    if (ecx & (1u << 1)) f |= SPEER_CPUF_PCLMUL;
    if (ecx & (1u << 28)) f |= SPEER_CPUF_AVX;

    cpuid_leaf(7, 0, &eax, &ebx, &ecx, &edx);
    if (ebx & (1u << 5)) f |= SPEER_CPUF_AVX2;
    if (ebx & (1u << 8)) f |= SPEER_CPUF_BMI2;
    if (ebx & (1u << 29)) f |= SPEER_CPUF_SHA;
#elif defined(SPEER_HAVE_ARM) && defined(__linux__)
    unsigned long hw = getauxval(AT_HWCAP);
    if (hw & HWCAP_AES) f |= SPEER_CPUF_ARMV8_AES;
    if (hw & HWCAP_PMULL) f |= SPEER_CPUF_ARMV8_PMULL;
#endif
    return f;
}

unsigned speer_cpu_features(void) {
    if (!g_cached_init) {
        g_cached_features = detect_features();
        g_cached_init = 1;
    }
    return g_cached_features;
}

int speer_cpu_has_aes_clmul(void) {
    unsigned f = speer_cpu_features();
    return (f & (SPEER_CPUF_AESNI | SPEER_CPUF_PCLMUL | SPEER_CPUF_SSE2)) ==
           (SPEER_CPUF_AESNI | SPEER_CPUF_PCLMUL | SPEER_CPUF_SSE2);
}

int speer_cpu_has_avx2(void) {
    return (speer_cpu_features() & SPEER_CPUF_AVX2) != 0;
}

int speer_cpu_has_sha(void) {
    return (speer_cpu_features() & (SPEER_CPUF_SHA | SPEER_CPUF_SSSE3 | SPEER_CPUF_SSE41)) ==
           (SPEER_CPUF_SHA | SPEER_CPUF_SSSE3 | SPEER_CPUF_SSE41);
}
