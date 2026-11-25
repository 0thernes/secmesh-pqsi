/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * SecMesh-PQSI Native C11 Core API
 * Integrates Tsotchke's Moonlab FIPS 202/203, SP 800-90B health tests,
 * Pironio DI-QRNG Toeplitz extractor, QGTL geometric tensor invariants,
 * libirrep-inspired Bivariate-Bicycle qLDPC CSS checks, and unconditional
 * Information-Theoretic (Post-Super-Intelligence) primitives.
 */
#ifndef SECMESH_PQSI_H
#define SECMESH_PQSI_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * 1. Constant-Time & Memory Hygiene Primitives
 * ========================================================================= */
void secmesh_secure_zero(void *ptr, size_t len);
int  secmesh_ct_memeq(const uint8_t *a, const uint8_t *b, size_t len);

/* =========================================================================
 * 2. Health-Tested, Bell-Gated Conditioned Entropy Engine
 *    (Moonlab SP 800-90B RCT/APT + Exact Singlet CHSH + SHAKE256 + Toeplitz)
 * ========================================================================= */
typedef struct {
    uint64_t requests_served;
    uint64_t bytes_served;
    uint64_t bell_epochs_passed;
    uint64_t health_failures;
    double   last_chsh_s;
    double   last_pironio_hmin;
    int      has_physical_qkd_hardware; /* ALWAYS 0 unless real hardware attached */
    int      fips_validated_module;     /* ALWAYS 0 (honest posture) */
} secmesh_entropy_status_t;

int  secmesh_os_csprng(uint8_t *out, size_t len);
int  secmesh_entropy_get_status(secmesh_entropy_status_t *out_status);
int  secmesh_entropy_self_test(void);

/* =========================================================================
 * 3. Information-Theoretic (Post-Super-Intelligence) Primitives
 * ========================================================================= */

/* GF(2^128) Carter-Wegman Polynomial MAC (modulo x^128 + x^7 + x^2 + x + 1).
 * Unconditionally secure against computationally unbounded adversaries:
 * forgery probability <= ceil(msg_len / 16) / 2^128 for fresh one-time pad b. */
void secmesh_gf128_mul(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);
void secmesh_cw_mac_compute(uint8_t tag[16],
                            const uint8_t r[16],
                            const uint8_t pad_b[16],
                            const uint8_t *msg,
                            size_t msg_len);
int  secmesh_cw_mac_verify(const uint8_t tag[16],
                           const uint8_t r[16],
                           const uint8_t pad_b[16],
                           const uint8_t *msg,
                           size_t msg_len);

/* Universal Dual-Survivability Hybrid Key Combiner:
 *   K_hyb = SHAKE256("SecMesh-PQSI-v2-Hybrid" || transcript_hash || K_pq) XOR K_it_extracted
 * Proved in Lean 4 (Theorem T2b):
 *   - Survives complete break of ML-KEM/X25519/SHA-3 if K_it_extracted is IT-uniform;
 *   - Survives complete compromise/absence of K_it if K_pq is IND-CCA2 secure. */
int secmesh_hybrid_combine(uint8_t k_out[32],
                           const uint8_t *k_pq, size_t k_pq_len,
                           const uint8_t *k_it_opt, size_t k_it_len,
                           const uint8_t *transcript, size_t transcript_len);

/* Shamir (t, n) Threshold Secret Sharing over Prime Field F_p (p = 2^61 - 1).
 * Unconditional zero mutual information for any <= t - 1 colluding unbounded
 * adversaries; exact Byzantine verification when n >= t + 2b. */
#define SECMESH_SHAMIR_PRIME ((uint64_t)((1ULL << 61) - 1ULL))

typedef struct {
    uint64_t x; /* Evaluation point in 1 .. p-1 */
    uint64_t y; /* Share value in 0 .. p-1 */
} secmesh_share_t;

int secmesh_shamir_split(uint64_t secret, uint32_t threshold, uint32_t num_shares,
                         secmesh_share_t *shares_out, const uint64_t *coeffs_opt);
int secmesh_shamir_reconstruct(const secmesh_share_t *shares, uint32_t threshold,
                               uint64_t *secret_out);
/* Byzantine-verified reconstruction across n >= t + 2b shares: checks consistency
 * of candidate polynomial against all n shares; returns 0 iff >= t + b agree
 * (unique recovery guaranteed when errors <= b and n >= t + 2b). */
int secmesh_shamir_reconstruct_byzantine(const secmesh_share_t *shares,
                                         uint32_t num_shares,
                                         uint32_t threshold,
                                         uint32_t max_byzantine,
                                         uint64_t *secret_out,
                                         uint32_t *corrupted_detected_out);

/* =========================================================================
 * 4. Composable Finite-Key E91 / DI-QKD Gate v2 (Fixes all SecMesh v1 bugs)
 * ========================================================================= */
typedef struct {
    double   chsh_s;           /* Observed |S| */
    uint64_t cnts[4];          /* Per-cell CHSH sample counts */
    uint64_t n_key;            /* Number of aligned sifting rounds */
    uint64_t qber_errors;      /* Number of errors observed in sifting test sample */
    uint64_t qber_sample;      /* Number of sifting rounds tested for QBER */
    double   eps_total;        /* Total composable security parameter (default 1e-6) */
    double   ec_efficiency;    /* Error-correction inefficiency f_EC >= 1.0 (default 1.16) */
    int      use_di_min_ent;   /* 1 = strict Pironio H_min (default), 0 = collective H_vN */
} secmesh_fk_input_t;

typedef struct {
    double   s_lb;             /* Corrected Hoeffding lower bound (range-2: sqrt(2 ln(8/eps_PE)/n_c)) */
    double   qber_hat;         /* Point estimate of QBER */
    double   qber_ub;          /* Exact Chernoff-KL upper confidence bound on QBER */
    double   h_min_di;         /* Strict Pironio DI min-entropy at s_lb */
    double   h_vn_di;          /* Collective Acin-Pironio von Neumann entropy at s_lb */
    double   leak_ec;          /* Error-correction syndrome leakage bits */
    double   aep_penalty;      /* Finite-block AEP smoothing penalty bits */
    double   pa_penalty;       /* Renner Leftover Hash 2*log2(1/(2*eps_PA)) bits */
    double   cor_penalty;      /* Error verification log2(1/eps_cor) bits */
    int64_t  cert_bits;        /* Certified extractable secret key length (>= 0) */
    int      admitted;         /* 1 iff cert_bits >= 256 (usable 256-bit key) */
} secmesh_fk_result_t;

double secmesh_bin_entropy(double p);
double secmesh_h_vn_from_chsh(double chsh);
double secmesh_h_min_from_chsh(double chsh);
void   secmesh_finite_key_eval(const secmesh_fk_input_t *in, secmesh_fk_result_t *out);

/* =========================================================================
 * 5. Quantum Geometric Tensor (QGTL) & Bivariate-Bicycle qLDPC (libirrep)
 * ========================================================================= */
typedef struct {
    double g_tt;               /* Fubini-Study metric g_{theta,theta} */
    double g_tp;               /* Fubini-Study metric g_{theta,phi} */
    double g_pp;               /* Fubini-Study metric g_{phi,phi} */
    double omega_tp;           /* Berry curvature Omega_{theta,phi} */
    double det_g;              /* det(g) */
    double qgt_rhs;            /* (1/4) * Omega^2 */
    double surplus;            /* det(g) - (1/4) * Omega^2 == (C^2 / 4) * sin^2(theta/2) */
    double concurrence;        /* Wootters concurrence C = |sin(2*alpha)| */
    double horodecki_s_max;    /* Maximal CHSH violation 2 * sqrt(1 + C^2) */
    double trace_g;            /* tr(g) */
    double qfi_trace;          /* Quantum Fisher Information tr(F_Q) = 4 * tr(g) */
    int    inequality_holds;   /* 1 iff det(g) + 1e-12 >= qgt_rhs && tr(g) + 1e-12 >= |Omega| */
} secmesh_qgt_result_t;

/* Exact QGT evaluation on the local-SU(2)-rotated two-qubit entangled manifold
 * |psi(theta, phi; alpha)> = (U(theta, phi) x I) (cos(alpha)|01> - sin(alpha)|10>).
 * Theorem T4a proves: det(g) - (1/4)*Omega^2 == (sin^2(2*alpha) / 4) * sin^2(theta/2),
 * linking QGTL determinant surplus directly to Wootters concurrence C and Horodecki S_max! */
void secmesh_qgt_entangled_manifold(double theta, double phi, double alpha,
                                    secmesh_qgt_result_t *out);
void secmesh_qgt_singlet_manifold(double theta, double phi, secmesh_qgt_result_t *out);

/* Bravyi et al. (Nature 2024) [[144, 12, 12]] Bivariate-Bicycle qLDPC code:
 * ell = 12, m = 6, A = x^3 + y + y^2, B = y^3 + x + x^2 over F_2[Z_12 x Z_6].
 * Builds H_X = [A | B] (72 x 144) and H_Z = [B^T | A^T] (72 x 144) and checks
 * H_X * H_Z^T == 0 (mod 2) across all 72*72 = 5,184 entries and row weight == 6. */
typedef struct {
    uint32_t n_qubits;         /* 144 */
    uint32_t num_checks_x;     /* 72 */
    uint32_t num_checks_z;     /* 72 */
    uint32_t row_weight_min;   /* 6 */
    uint32_t row_weight_max;   /* 6 */
    uint32_t nonzeros_hx_hzt;  /* 0 iff exact CSS commutation holds */
    uint32_t rank_hx;          /* 66 */
    uint32_t rank_hz;          /* 66 */
    uint32_t logical_k;        /* 144 - 66 - 66 = 12 */
} secmesh_bb144_audit_t;

void secmesh_bb144_verify_css(secmesh_bb144_audit_t *out);

/* =========================================================================
 * 6. Complete-Graph K_N PQ/PSI Mesh Wire-Bandwidth Model
 * ========================================================================= */
typedef struct {
    const char *profile_name;
    uint32_t    kem_ek_bytes;
    uint32_t    kem_ct_bytes;
    uint32_t    sig_pk_bytes;
    uint32_t    sig_bytes;
    uint32_t    it_mac_bytes;
    uint32_t    framing_bytes;
    uint32_t    one_way_bytes;
    uint32_t    round_trip_bytes;
} secmesh_bw_profile_t;

uint32_t secmesh_bw_profile_count(void);
const secmesh_bw_profile_t *secmesh_bw_get_profile(uint32_t idx);
uint64_t secmesh_bw_mesh_ceiling(uint64_t link_bps, double round_seconds,
                                 uint32_t one_way_bytes);

#ifdef __cplusplus
}
#endif

#endif /* SECMESH_PQSI_H */
