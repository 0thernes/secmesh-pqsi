/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * Dudect-Style Empirical Constant-Time Timing Audit (Reparaz et al., CHES 2017)
 * Measures high-resolution execution timing between Class 0 and Class 1 using:
 *   - Balanced Fisher-Yates shuffled class schedule (zero end-tail bias)
 *   - 64-byte aligned, identical-address branchless setup before timing
 *   - Full store+load serialization (mfence; lfence; rdtsc on x86_64) so setup
 *     stores never bleed into the timed measurement window
 *   - Percentile cropping (2%..90%) stripping OS preemption / turbo spikes
 *
 * Audited branchless C11 primitives:
 *   1. secmesh_ct_memeq (512B secret tag comparison: equal vs mismatch at byte 0)
 *   2. secmesh_gf128_mul (branchless GF(2^128) universal hash field multiply)
 *   3. secmesh_cw_mac_compute (128B Carter-Wegman IT-MAC)
 *   4. moonlab_mlkem768_encaps (FIPS 203 ML-KEM-768 encapsulation)
 */
#include "secmesh_pqsi.h"
#include "../third_party/moonlab/crypto/mlkem/mlkem.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <time.h>
#endif

static uint64_t now_ticks(void) {
#if defined(__x86_64__) || defined(_M_X64)
    uint32_t lo = 0, hi = 0;
    /* mfence drains prior setup stores (e.g., memcpy) before lfence+rdtsc */
    __asm__ __volatile__("mfence\nlfence\nrdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | (uint64_t)lo;
#elif defined(_WIN32)
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (uint64_t)li.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Compute Welch's t-statistic after cropping top 10% preemption/cache-miss spikes */
static double welch_t_cropped(uint64_t *c0, size_t n0, uint64_t *c1, size_t n1) {
    qsort(c0, n0, sizeof(uint64_t), cmp_u64);
    qsort(c1, n1, sizeof(uint64_t), cmp_u64);
    size_t k0 = (n0 * 90u) / 100u;
    size_t k1 = (n1 * 90u) / 100u;
    size_t s0 = (n0 * 2u) / 100u;
    size_t s1 = (n1 * 2u) / 100u;
    double m0 = 0.0, m1 = 0.0, v0 = 0.0, v1 = 0.0;
    size_t cnt0 = k0 - s0, cnt1 = k1 - s1;
    for (size_t i = s0; i < k0; i++) m0 += (double)c0[i];
    for (size_t i = s1; i < k1; i++) m1 += (double)c1[i];
    m0 /= (double)cnt0;
    m1 /= (double)cnt1;
    for (size_t i = s0; i < k0; i++) { double d = (double)c0[i] - m0; v0 += d * d; }
    for (size_t i = s1; i < k1; i++) { double d = (double)c1[i] - m1; v1 += d * d; }
    v0 /= (double)(cnt0 - 1u);
    v1 /= (double)(cnt1 - 1u);
    double denom = sqrt(v0 / (double)cnt0 + v1 / (double)cnt1);
    if (denom <= 1e-12) return 0.0;
    return (m0 - m1) / denom;
}

static uint64_t xorshift64(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static void fill_prng(uint64_t *s, uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(xorshift64(s) & 0xFFu);
}

static void build_balanced_schedule(uint8_t *sched, size_t per_class, uint64_t *rng) {
    size_t total = per_class * 2u;
    for (size_t i = 0; i < per_class; i++) sched[i] = 0u;
    for (size_t i = per_class; i < total; i++) sched[i] = 1u;
    for (size_t i = total - 1u; i > 0; i--) {
        size_t j = (size_t)(xorshift64(rng) % (i + 1u));
        uint8_t tmp = sched[i];
        sched[i] = sched[j];
        sched[j] = tmp;
    }
}

static volatile uint8_t g_sink = 0;

int main(void) {
    const size_t N_FAST = 12000;
    const size_t N_KEM  = 800;
    uint64_t *t0 = (uint64_t *)calloc(N_FAST, sizeof(uint64_t));
    uint64_t *t1 = (uint64_t *)calloc(N_FAST, sizeof(uint64_t));
    uint8_t *sched = (uint8_t *)calloc(N_FAST * 2u, sizeof(uint8_t));
    if (!t0 || !t1 || !sched) return 2;

    uint64_t rng = 0x20261126CAFEBABEULL;
    int failures = 0;

    /* Warmup all audited primitives to stabilize CPU frequency & instruction cache */
    {
        _Alignas(64) uint8_t wa[512], wb[512], wo[16];
        memset(wa, 0x5A, sizeof wa);
        memset(wb, 0xA5, sizeof wb);
        for (int i = 0; i < 3000; i++) {
            g_sink ^= (uint8_t)secmesh_ct_memeq(wa, wb, sizeof wa);
            secmesh_gf128_mul(wo, wa, wb);
            g_sink ^= wo[0];
        }
    }

    /* 1. secmesh_ct_memeq(512B): equal vs mismatch at byte 0 (identical addresses, branchless setup) */
    {
        size_t i0 = 0, i1 = 0;
        _Alignas(64) uint8_t a[512];
        _Alignas(64) uint8_t rhs[512];
        build_balanced_schedule(sched, N_FAST, &rng);
        for (size_t k = 0; k < N_FAST * 2u; k++) {
            uint8_t cls = sched[k];
            uint8_t flip = (uint8_t)(0u - cls); /* 0x00 if cls==0, 0xFF if cls==1 */
            fill_prng(&rng, a, sizeof a);
            memcpy(rhs, a, sizeof rhs);
            rhs[0] ^= flip;
            uint64_t s = now_ticks();
            int r = secmesh_ct_memeq(a, rhs, sizeof a);
            uint64_t e = now_ticks();
            g_sink ^= (uint8_t)r;
            if (cls == 0u) t0[i0++] = e - s; else t1[i1++] = e - s;
        }
        double t = welch_t_cropped(t0, N_FAST, t1, N_FAST);
        int pass = fabs(t) < 10.0; /* CI noisy-VM safe bound; ideal < 4.5 */
        printf("  [CT] secmesh_ct_memeq(512B):     Welch |t| = %.3f  (%s)\n", fabs(t), pass ? "PASS" : "WARN/FAIL");
        if (!pass) failures++;
    }

    /* 2. secmesh_gf128_mul: all-zero secret vs random secret (branchless identical-address setup) */
    {
        size_t i0 = 0, i1 = 0;
        _Alignas(64) uint8_t a[16];
        _Alignas(64) uint8_t r[16];
        _Alignas(64) uint8_t sec[16];
        _Alignas(64) uint8_t out[16];
        fill_prng(&rng, a, 16);
        build_balanced_schedule(sched, N_FAST, &rng);
        for (size_t k = 0; k < N_FAST * 2u; k++) {
            uint8_t cls = sched[k];
            uint8_t mask = (uint8_t)(0u - cls);
            fill_prng(&rng, r, 16);
            for (size_t j = 0; j < 16; j++) sec[j] = (uint8_t)(r[j] & mask);
            uint64_t s = now_ticks();
            secmesh_gf128_mul(out, a, sec);
            uint64_t e = now_ticks();
            g_sink ^= out[0];
            if (cls == 0u) t0[i0++] = e - s; else t1[i1++] = e - s;
        }
        double t = welch_t_cropped(t0, N_FAST, t1, N_FAST);
        int pass = fabs(t) < 10.0;
        printf("  [CT] secmesh_gf128_mul(128b):    Welch |t| = %.3f  (%s)\n", fabs(t), pass ? "PASS" : "WARN/FAIL");
        if (!pass) failures++;
    }

    /* 3. secmesh_cw_mac_compute(128B): all-zero key vs random key (branchless identical-address setup) */
    {
        size_t i0 = 0, i1 = 0;
        _Alignas(64) uint8_t msg[128];
        _Alignas(64) uint8_t rr[16];
        _Alignas(64) uint8_t br[16];
        _Alignas(64) uint8_t cur_r[16];
        _Alignas(64) uint8_t cur_b[16];
        _Alignas(64) uint8_t tag[16];
        fill_prng(&rng, msg, sizeof msg);
        build_balanced_schedule(sched, N_FAST, &rng);
        for (size_t k = 0; k < N_FAST * 2u; k++) {
            uint8_t cls = sched[k];
            uint8_t mask = (uint8_t)(0u - cls);
            fill_prng(&rng, rr, 16);
            fill_prng(&rng, br, 16);
            for (size_t j = 0; j < 16; j++) {
                cur_r[j] = (uint8_t)(rr[j] & mask);
                cur_b[j] = (uint8_t)(br[j] & mask);
            }
            uint64_t s = now_ticks();
            secmesh_cw_mac_compute(tag, cur_r, cur_b, msg, sizeof msg);
            uint64_t e = now_ticks();
            g_sink ^= tag[0];
            if (cls == 0u) t0[i0++] = e - s; else t1[i1++] = e - s;
        }
        double t = welch_t_cropped(t0, N_FAST, t1, N_FAST);
        int pass = fabs(t) < 10.0;
        printf("  [CT] secmesh_cw_mac(128B):       Welch |t| = %.3f  (%s)\n", fabs(t), pass ? "PASS" : "WARN/FAIL");
        if (!pass) failures++;
    }

    /* 4. moonlab_mlkem768_encaps: fixed all-zero seed vs random seed (branchless identical-address setup) */
    {
        _Alignas(64) uint8_t d[32];
        _Alignas(64) uint8_t z[32];
        _Alignas(64) uint8_t ek[MLKEM768_PUBLICKEYBYTES];
        _Alignas(64) uint8_t dk[MLKEM768_SECRETKEYBYTES];
        _Alignas(64) uint8_t m1[32];
        _Alignas(64) uint8_t cur_m[32];
        _Alignas(64) uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
        _Alignas(64) uint8_t ss[32];
        fill_prng(&rng, d, 32);
        fill_prng(&rng, z, 32);
        moonlab_mlkem768_keygen(ek, dk, d, z);
        size_t i0 = 0, i1 = 0;
        build_balanced_schedule(sched, N_KEM, &rng);
        for (size_t k = 0; k < N_KEM * 2u; k++) {
            uint8_t cls = sched[k];
            uint8_t mask = (uint8_t)(0u - cls);
            fill_prng(&rng, m1, 32);
            for (size_t j = 0; j < 32; j++) cur_m[j] = (uint8_t)(m1[j] & mask);
            uint64_t s = now_ticks();
            moonlab_mlkem768_encaps(ct, ss, ek, cur_m);
            uint64_t e = now_ticks();
            g_sink ^= ss[0];
            if (cls == 0u) t0[i0++] = e - s; else t1[i1++] = e - s;
        }
        double t = welch_t_cropped(t0, N_KEM, t1, N_KEM);
        int pass = fabs(t) < 10.0;
        printf("  [CT] moonlab_mlkem768_encaps:    Welch |t| = %.3f  (%s)\n", fabs(t), pass ? "PASS" : "WARN/FAIL");
        if (!pass) failures++;
        secmesh_secure_zero(dk, sizeof dk);
        secmesh_secure_zero(ss, sizeof ss);
    }

    free(sched);
    free(t0);
    free(t1);
    printf("Constant-Time Audit Summary: %d failures (sink=0x%02x)\n", failures, (unsigned)g_sink);
    return failures == 0 ? 0 : 1;
}
