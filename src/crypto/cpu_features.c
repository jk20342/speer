#include "cpu_features.h"

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#define SPEER_HAVE_X86 1
#elif (defined(__x86_64__) || defined(__i386__))
#include <cpuid.h>
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

static unsigned detect_features(void) {
    unsigned f = 0;
#if defined(SPEER_HAVE_X86)
    unsigned ecx = 0, edx = 0;
#if defined(_MSC_VER)
    int regs[4];
    __cpuid(regs, 1);
    ecx = (unsigned)regs[2];
    edx = (unsigned)regs[3];
#else
    unsigned eax = 0, ebx = 0;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return 0;
    (void)eax;
    (void)ebx;
#endif
    if (edx & (1u << 26)) f |= SPEER_CPUF_SSE2;
    if (ecx & (1u << 9)) f |= SPEER_CPUF_SSSE3;
    if (ecx & (1u << 25)) f |= SPEER_CPUF_AESNI;
    if (ecx & (1u << 1)) f |= SPEER_CPUF_PCLMUL;
    if (ecx & (1u << 28)) f |= SPEER_CPUF_AVX;
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
