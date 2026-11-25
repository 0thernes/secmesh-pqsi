/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * Information-Theoretic (Post-Super-Intelligence) Cryptography Core:
 *   1. Constant-time GF(2^128) Carter-Wegman Polynomial MAC
 *   2. Universal Dual-Survivability Hybrid PQ + IT Key Combiner
 *   3. Shamir (t, n) Threshold Secret Sharing over Mersenne Prime F_{2^61 - 1}
 *      with Byzantine Error Detection & Unique Recovery (n >= t + 2b)
 */
#include "secmesh_pqsi.h"
#include "../third_party/moonlab/crypto/sha3/sha3.h"
#include "../third_party/moonlab/applications/moonlab_export.h"

#include <stdint.h>
#include <string.h>

/* =========================================================================
 * 1. Constant-Time GF(2^128) Multiplication (GHASH / NIST SP 800-38D poly)
 *    Irreducible polynomial: x^128 + x^7 + x^2 + x + 1
 *    Bit-serial branchless implementation (zero lookup tables, zero cache timing).
 * ========================================================================= */
static uint64_t load_be64(const uint8_t p[8]) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static void store_be64(uint8_t p[8], uint64_t v) {
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)(v);
}

void secmesh_gf128_mul(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    if (!out || !a || !b) return;
    /* GHASH bit convention: MSB of byte 0 is x^0, LSB of byte 15 is x^127.
     * Reduction constant R = 0xE1 << 56 (representing 1 + x + x^2 + x^7). */
    uint64_t vh = load_be64(a);
    uint64_t vl = load_be64(a + 8);
    uint64_t zh = 0, zl = 0;

    for (int i = 0; i < 16; i++) {
        uint8_t bi = b[i];
        for (int bit = 7; bit >= 0; bit--) {
            uint64_t mask = (uint64_t)0 - (uint64_t)((bi >> bit) & 1u);
            zh ^= vh & mask;
            zl ^= vl & mask;
            uint64_t lsb = vl & 1ULL;
            uint64_t rmask = (uint64_t)0 - lsb;
            vl = (vl >> 1) | (vh << 63);
            vh = (vh >> 1) ^ (0xE100000000000000ULL & rmask);
        }
    }
    store_be64(out, zh);
    store_be64(out + 8, zl);
}

/* Carter-Wegman polynomial universal hash + OTP mask:
 *   Split message into 16-byte blocks M_1..M_d (zero-padded final block)
 *   plus final length block L = (0 || bitlen_be64) to prevent length-extension!
 *   Eval Horner: H = (((M_1 * r + M_2) * r + ... + M_d) * r + L) * r
 *   Tag = H XOR pad_b.
 *   Theorem T2d: Forgery probability <= (d + 1) / 2^128 against ANY unbounded adversary. */
void secmesh_cw_mac_compute(uint8_t tag[16],
                            const uint8_t r[16],
                            const uint8_t pad_b[16],
                            const uint8_t *msg,
                            size_t msg_len) {
    if (!tag || !r || !pad_b || (msg_len > 0 && !msg)) return;
    uint8_t acc[16];
    uint8_t blk[16];
    memset(acc, 0, 16);

    size_t off = 0;
    while (off < msg_len) {
        size_t take = (msg_len - off >= 16) ? 16 : (msg_len - off);
        memset(blk, 0, 16);
        memcpy(blk, msg + off, take);
        for (int i = 0; i < 16; i++) acc[i] ^= blk[i];
        secmesh_gf128_mul(acc, acc, r);
        off += take;
    }

    /* Domain-separating exact length block (64-bit byte length + 64-bit bit length) */
    memset(blk, 0, 16);
    store_be64(blk, (uint64_t)msg_len);
    store_be64(blk + 8, (uint64_t)msg_len * 8ULL);
    for (int i = 0; i < 16; i++) acc[i] ^= blk[i];
    secmesh_gf128_mul(acc, acc, r);

    for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(acc[i] ^ pad_b[i]);
    secmesh_secure_zero(acc, sizeof acc);
    secmesh_secure_zero(blk, sizeof blk);
}

int secmesh_cw_mac_verify(const uint8_t tag[16],
                          const uint8_t r[16],
                          const uint8_t pad_b[16],
                          const uint8_t *msg,
                          size_t msg_len) {
    if (!tag || !r || !pad_b || (msg_len > 0 && !msg)) return 0;
    uint8_t expected[16];
    secmesh_cw_mac_compute(expected, r, pad_b, msg, msg_len);
    int eq = secmesh_ct_memeq(expected, tag, 16);
    secmesh_secure_zero(expected, sizeof expected);
    return eq;
}

/* =========================================================================
 * 2. Universal Dual-Survivability Hybrid PQ + IT Key Combiner
 * ========================================================================= */
int secmesh_hybrid_combine(uint8_t k_out[32],
                           const uint8_t *k_pq, size_t k_pq_len,
                           const uint8_t *k_it_opt, size_t k_it_len,
                           const uint8_t *transcript, size_t transcript_len) {
    if (!k_out || (!k_pq && !k_it_opt)) return -1;
    if (k_it_opt && k_it_len != 32) return -2;

    uint8_t k_pq_derived[32];
    memset(k_pq_derived, 0, 32);

    if (k_pq && k_pq_len > 0) {
        sha3_ctx_t ctx;
        shake256_init(&ctx);
        const char dom[] = "SecMesh-PQSI-v2.0|DualSurvivabilityCombiner|PQ";
        sha3_update(&ctx, (const uint8_t *)dom, sizeof(dom) - 1);
        uint64_t tlen = (uint64_t)transcript_len;
        sha3_update(&ctx, (const uint8_t *)&tlen, sizeof tlen);
        if (transcript && transcript_len > 0) {
            sha3_update(&ctx, transcript, transcript_len);
        }
        uint64_t klen = (uint64_t)k_pq_len;
        sha3_update(&ctx, (const uint8_t *)&klen, sizeof klen);
        sha3_update(&ctx, k_pq, k_pq_len);
        shake_squeeze(&ctx, k_pq_derived, 32);
        secmesh_secure_zero(&ctx, sizeof ctx);
    }

    /* Pure XOR composition with independent IT key K_it (Theorem T2b):
     *   - If K_it is IT-uniform (independent of transcript & K_pq), K_out is
     *     EXACTLY uniform even if an unbounded Super-Intelligence recovers K_pq_derived!
     *   - If K_it is absent/zero or fully known to Eve, K_out retains full IND-CCA2
     *     security of K_pq_derived! */
    for (int i = 0; i < 32; i++) {
        uint8_t it_byte = (k_it_opt && k_it_len == 32) ? k_it_opt[i] : 0;
        k_out[i] = (uint8_t)(k_pq_derived[i] ^ it_byte);
    }
    secmesh_secure_zero(k_pq_derived, sizeof k_pq_derived);
    return 0;
}

/* =========================================================================
 * 3. Shamir (t, n) Threshold Secret Sharing over F_p (p = 2^61 - 1)
 *    Exact modular arithmetic using unsigned 128-bit products (__uint128_t).
 * ========================================================================= */
static inline uint64_t fp_add(uint64_t a, uint64_t b) {
    uint64_t s = a + b;
    if (s >= SECMESH_SHAMIR_PRIME) s -= SECMESH_SHAMIR_PRIME;
    return s;
}

static inline uint64_t fp_sub(uint64_t a, uint64_t b) {
    return (a >= b) ? (a - b) : (SECMESH_SHAMIR_PRIME - (b - a));
}

static inline uint64_t fp_mul(uint64_t a, uint64_t b) {
    __uint128_t prod = (__uint128_t)a * (__uint128_t)b;
    /* Fast exact Mersenne reduction for p = 2^61 - 1 */
    uint64_t lo = (uint64_t)(prod & SECMESH_SHAMIR_PRIME);
    uint64_t hi = (uint64_t)(prod >> 61);
    uint64_t s = lo + hi;
    if (s >= SECMESH_SHAMIR_PRIME) s -= SECMESH_SHAMIR_PRIME;
    if (s >= SECMESH_SHAMIR_PRIME) s -= SECMESH_SHAMIR_PRIME;
    return s;
}

static uint64_t fp_pow(uint64_t base, uint64_t exp) {
    uint64_t res = 1;
    base %= SECMESH_SHAMIR_PRIME;
    while (exp > 0) {
        if (exp & 1ULL) res = fp_mul(res, base);
        base = fp_mul(base, base);
        exp >>= 1;
    }
    return res;
}

static uint64_t fp_inv(uint64_t a) {
    /* Fermat's Little Theorem: a^(p-2) mod p (exact for prime p = 2^61 - 1) */
    return fp_pow(a, SECMESH_SHAMIR_PRIME - 2ULL);
}

static uint64_t poly_eval_fp(const uint64_t *coeffs, uint32_t deg_plus_1, uint64_t x) {
    uint64_t acc = 0;
    for (int32_t i = (int32_t)deg_plus_1 - 1; i >= 0; i--) {
        acc = fp_add(fp_mul(acc, x), coeffs[i]);
    }
    return acc;
}

int secmesh_shamir_split(uint64_t secret, uint32_t threshold, uint32_t num_shares,
                         secmesh_share_t *shares_out, const uint64_t *coeffs_opt) {
    if (!shares_out || threshold < 1 || num_shares < threshold || num_shares > 256) return -1;
    if (secret >= SECMESH_SHAMIR_PRIME) return -2;

    uint64_t coeffs[256];
    coeffs[0] = secret;
    if (coeffs_opt) {
        for (uint32_t i = 1; i < threshold; i++) {
            coeffs[i] = coeffs_opt[i - 1] % SECMESH_SHAMIR_PRIME;
        }
    } else {
        for (uint32_t i = 1; i < threshold; i++) {
            /* Rejection sampling for exact uniform elements in [0, p-1] */
            uint64_t v = SECMESH_SHAMIR_PRIME;
            while (v >= SECMESH_SHAMIR_PRIME) {
                uint8_t raw[8];
                if (moonlab_qrng_bytes(raw, 8) != 0) {
                    secmesh_secure_zero(coeffs, sizeof coeffs);
                    return -3;
                }
                v = load_be64(raw) & SECMESH_SHAMIR_PRIME;
                secmesh_secure_zero(raw, 8);
            }
            coeffs[i] = v;
        }
    }

    for (uint32_t j = 0; j < num_shares; j++) {
        uint64_t x = (uint64_t)(j + 1);
        shares_out[j].x = x;
        shares_out[j].y = poly_eval_fp(coeffs, threshold, x);
    }
    secmesh_secure_zero(coeffs, sizeof coeffs);
    return 0;
}

static int lagrange_eval_at(const secmesh_share_t *shares, uint32_t t,
                            uint64_t x_eval, uint64_t *out_y) {
    uint64_t acc = 0;
    for (uint32_t i = 0; i < t; i++) {
        if (shares[i].x == 0 || shares[i].x >= SECMESH_SHAMIR_PRIME ||
            shares[i].y >= SECMESH_SHAMIR_PRIME) return -1;
        uint64_t num = 1, den = 1;
        for (uint32_t j = 0; j < t; j++) {
            if (i == j) continue;
            if (shares[i].x == shares[j].x) return -2; /* duplicate x */
            num = fp_mul(num, fp_sub(x_eval, shares[j].x));
            den = fp_mul(den, fp_sub(shares[i].x, shares[j].x));
        }
        uint64_t li = fp_mul(num, fp_inv(den));
        acc = fp_add(acc, fp_mul(shares[i].y, li));
    }
    *out_y = acc;
    return 0;
}

int secmesh_shamir_reconstruct(const secmesh_share_t *shares, uint32_t threshold,
                               uint64_t *secret_out) {
    if (!shares || !secret_out || threshold < 1 || threshold > 256) return -1;
    return lagrange_eval_at(shares, threshold, 0, secret_out);
}

/* Recursive subset search over size-t subsets of n shares (exact Reed-Solomon
 * consensus decoder for small/medium mesh thresholds where n >= t + 2b).
 * Theorem T3b guarantees: if <= b shares are corrupted and n >= t + 2b, then
 * ANY candidate polynomial agreeing with >= n - b >= t + b shares MUST be the
 * unique true polynomial! */
typedef struct {
    const secmesh_share_t *all;
    uint32_t n;
    uint32_t t;
    uint32_t min_agree;
    secmesh_share_t pick[64];
    int found;
    uint64_t secret;
    uint32_t corrupted;
} byz_search_t;

static void byz_dfs(byz_search_t *st, uint32_t start, uint32_t depth) {
    if (st->found) return;
    if (depth == st->t) {
        uint32_t agree = 0;
        for (uint32_t k = 0; k < st->n; k++) {
            uint64_t y_pred = 0;
            if (lagrange_eval_at(st->pick, st->t, st->all[k].x, &y_pred) != 0) return;
            if (y_pred == st->all[k].y) agree++;
        }
        if (agree >= st->min_agree) {
            uint64_t s0 = 0;
            if (lagrange_eval_at(st->pick, st->t, 0, &s0) == 0) {
                st->found = 1;
                st->secret = s0;
                st->corrupted = st->n - agree;
            }
        }
        return;
    }
    for (uint32_t i = start; i + (st->t - depth) <= st->n; i++) {
        st->pick[depth] = st->all[i];
        byz_dfs(st, i + 1, depth + 1);
        if (st->found) return;
    }
}

int secmesh_shamir_reconstruct_byzantine(const secmesh_share_t *shares,
                                         uint32_t num_shares,
                                         uint32_t threshold,
                                         uint32_t max_byzantine,
                                         uint64_t *secret_out,
                                         uint32_t *corrupted_detected_out) {
    if (!shares || !secret_out || threshold < 1 || threshold > 64 ||
        num_shares > 256 || max_byzantine > 128) return -1;
    /* Enforce Theorem T3b Singleton-Byzantine condition (overflow-safe uint64_t): n >= t + 2b */
    if ((uint64_t)num_shares < (uint64_t)threshold + 2ULL * (uint64_t)max_byzantine) return -2;

    byz_search_t st;
    memset(&st, 0, sizeof st);
    st.all = shares;
    st.n = num_shares;
    st.t = threshold;
    st.min_agree = num_shares - max_byzantine;
    byz_dfs(&st, 0, 0);
    if (!st.found) return -3; /* More than max_byzantine corruptions! */
    *secret_out = st.secret;
    if (corrupted_detected_out) *corrupted_detected_out = st.corrupted;
    return 0;
}
