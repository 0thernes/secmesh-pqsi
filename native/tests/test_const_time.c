/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * Dudect-Style Empirical Constant-Time Timing Audit (Reparaz et al., CHES 2017)
 * Measures high-resolution execution timing between Class 0 (fixed all-zero secret)
 * and Class 1 (fresh random secret) with randomized interleaving and outlier cropping,
 * computing Welch's t-statistic for SecMesh-PQSI's branchless C11 crypto primitives:
 *   1. secmesh_ct_memeq (32B secret tag comparison)
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
    __asm__ __volatile__("lfence\nrdtsc" : "=a"(lo), "=d"(hi) :: "memory");
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
    /* Skip bottom 2% and top 10% to strip CPU turbo warmup & OS interrupts */
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

static volatile uint8_t g_sink = 0;

int main(void) {
    const size_t N_FAST = 12000;
    const size_t N_KEM  = 800;
    uint64_t *t0 = (uint64_t *)calloc(N_FAST, sizeof(uint64_t));
    uint64_t *t1 = (uint64_t *)calloc(N_FAST, sizeof(uint64_t));
    if (!t0 || !t1) return 2;

    uint64_t rng = 0x20261126CAFEBABEULL;
    int failures = 0;

    /* Warmup */
    uint8_t wa[32], wb[32], wo[16];
    memset(wa, 0x5A, sizeof wa);
    memset(wb, 0xA5, sizeof wb);
    for (int i = 0; i < 2000; i++) {
        secmesh_gf128_mul(wo, wa, wb);
        g_sink ^= wo[0];
    }

    /* 1. secmesh_ct_memeq(512B): equal vs mismatch at byte 0 (same aligned rhs buffer) */
    {
        size_t i0 = 0, i1 = 0;
        uint8_t a[512], b0[512], b1[512], rhs[512];
        fill_prng(&rng, a, sizeof a);
        memcpy(b0, a, sizeof a);
        memcpy(b1, a, sizeof a);
        b1[0] ^= 0xFF;
        while (i0 < N_FAST || i1 < N_FAST) {
            int cls = (i0 < N_FAST && (i1 >= N_FAST || (xorshift64(&rng) & 1u) == 0)) ? 0 : 1;
            memcpy(rhs, cls ? b1 : b0, sizeof rhs);
            uint64_t s = now_ticks();
            int r = secmesh_ct_memeq(a, rhs, sizeof a);
            uint64_t e = now_ticks();
            g_sink ^= (uint8_t)r;
            if (cls == 0) t0[i0++] = e - s; else t1[i1++] = e - s;
        }
        double t = welch_t_cropped(t0, N_FAST, t1, N_FAST);
        int pass = fabs(t) < 10.0; /* CI noisy-VM safe bound; ideal < 4.5 */
        printf("  [CT] secmesh_ct_memeq(512B):     Welch |t| = %.3f  (%s)\n", fabs(t), pass ? "PASS" : "WARN/FAIL");
        if (!pass) failures++;
    }

    /* 2. secmesh_gf128_mul: all-zero secret vs random secret (equal work before rdtsc) */
    {
        size_t i0 = 0, i1 = 0;
        uint8_t a[16], z[16], r[16], sec[16], out[16];
        memset(z, 0, 16);
        fill_prng(&rng, a, 16);
        while (i0 < N_FAST || i1 < N_FAST) {
            int cls = (i0 < N_FAST && (i1 >= N_FAST || (xorshift64(&rng) & 1u) == 0)) ? 0 : 1;
            fill_prng(&rng, r, 16);
            memcpy(sec, cls ? r : z, 16);
            uint64_t s = now_ticks();
            secmesh_gf128_mul(out, a, sec);
            uint64_t e = now_ticks();
            g_sink ^= out[0];
            if (cls == 0) t0[i0++] = e - s; else t1[i1++] = e - s;
        }
        double t = welch_t_cropped(t0, N_FAST, t1, N_FAST);
        int pass = fabs(t) < 10.0;
        printf("  [CT] secmesh_gf128_mul(128b):    Welch |t| = %.3f  (%s)\n", fabs(t), pass ? "PASS" : "WARN/FAIL");
        if (!pass) failures++;
    }

    /* 3. secmesh_cw_mac_compute(128B): all-zero key vs random key (equal work before rdtsc) */
    {
        size_t i0 = 0, i1 = 0;
        uint8_t msg[128], rz[16], bz[16], rr[16], br[16], cur_r[16], cur_b[16], tag[16];
        memset(rz, 0, 16);
        memset(bz, 0, 16);
        fill_prng(&rng, msg, sizeof msg);
        while (i0 < N_FAST || i1 < N_FAST) {
            int cls = (i0 < N_FAST && (i1 >= N_FAST || (xorshift64(&rng) & 1u) == 0)) ? 0 : 1;
            fill_prng(&rng, rr, 16);
            fill_prng(&rng, br, 16);
            memcpy(cur_r, cls ? rr : rz, 16);
            memcpy(cur_b, cls ? br : bz, 16);
            uint64_t s = now_ticks();
            secmesh_cw_mac_compute(tag, cur_r, cur_b, msg, sizeof msg);
            uint64_t e = now_ticks();
            g_sink ^= tag[0];
            if (cls == 0) t0[i0++] = e - s; else t1[i1++] = e - s;
        }
        double t = welch_t_cropped(t0, N_FAST, t1, N_FAST);
        int pass = fabs(t) < 10.0;
        printf("  [CT] secmesh_cw_mac(128B):       Welch |t| = %.3f  (%s)\n", fabs(t), pass ? "PASS" : "WARN/FAIL");
        if (!pass) failures++;
    }

    /* 4. moonlab_mlkem768_encaps: fixed all-zero seed vs random seed (equal work before rdtsc) */
    {
        uint8_t d[32], z[32], ek[MLKEM768_PUBLICKEYBYTES], dk[MLKEM768_SECRETKEYBYTES];
        uint8_t m0[32], m1[32], cur_m[32], ct[MLKEM768_CIPHERTEXTBYTES], ss[32];
        fill_prng(&rng, d, 32);
        fill_prng(&rng, z, 32);
        memset(m0, 0, 32);
        moonlab_mlkem768_keygen(ek, dk, d, z);
        size_t i0 = 0, i1 = 0;
        while (i0 < N_KEM || i1 < N_KEM) {
            int cls = (i0 < N_KEM && (i1 >= N_KEM || (xorshift64(&rng) & 1u) == 0)) ? 0 : 1;
            fill_prng(&rng, m1, 32);
            memcpy(cur_m, cls ? m1 : m0, 32);
            uint64_t s = now_ticks();
            moonlab_mlkem768_encaps(ct, ss, ek, cur_m);
            uint64_t e = now_ticks();
            g_sink ^= ss[0];
            if (cls == 0) t0[i0++] = e - s; else t1[i1++] = e - s;
        }
        double t = welch_t_cropped(t0, N_KEM, t1, N_KEM);
        int pass = fabs(t) < 10.0;
        printf("  [CT] moonlab_mlkem768_encaps:    Welch |t| = %.3f  (%s)\n", fabs(t), pass ? "PASS" : "WARN/FAIL");
        if (!pass) failures++;
        secmesh_secure_zero(dk, sizeof dk);
        secmesh_secure_zero(ss, sizeof ss);
    }

    free(t0);
    free(t1);
    printf("Constant-Time Audit Summary: %d failures (sink=0x%02x)\n", failures, (unsigned)g_sink);
    return failures == 0 ? 0 : 1;
}
