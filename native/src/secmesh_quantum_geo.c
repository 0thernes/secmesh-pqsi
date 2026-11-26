/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * Composable Finite-Key E91 Gate v2, Quantum Geometric Tensor (QGTL),
 * Bravyi-Nature 2024 [[144, 12, 12]] Bivariate-Bicycle qLDPC CSS Verifier,
 * and Complete-Graph K_N PQ/PSI Mesh Wire-Bandwidth Model.
 */
#include "secmesh_pqsi.h"
#include "../third_party/moonlab/applications/qrng_di.h"

#include <complex.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

/* =========================================================================
 * 1. Composable Finite-Key E91 / DI-QKD Gate v2
 *    Fixes ALL 6 analytic bugs found in BoogerCheeseOnRye/SecMesh v1:
 *      (1) Range-2 Hoeffding radius t_c = sqrt(2 * ln(8 / eps_PE) / n_c)
 *      (2) Strict Pironio DI min-entropy H_min(S_LB) vs collective H_vN(S_LB)
 *      (3) Statistical QBER upper confidence bound qber_ub via exact Bernoulli Chernoff-KL inversion
 *      (4) Explicit error-correction syndrome leakage f_EC * n_key * h(qber_ub)
 *      (5) Correct Renner Leftover Hash penalty 2 * log2(1 / (2 * eps_PA))
 *      (6) Disjoint union-bound epsilon budget:
 *            eps_PE + eps_QBER + eps_s + eps_PA + eps_cor = eps_total
 * ========================================================================= */
double secmesh_bin_entropy(double p) {
    if (!isfinite(p) || p <= 0.0 || p >= 1.0) return 0.0;
    return -(p * log2(p) + (1.0 - p) * log2(1.0 - p));
}

double secmesh_h_vn_from_chsh(double chsh) {
    const double tsirelson = 2.0 * 1.41421356237309504880;
    if (!isfinite(chsh) || chsh <= 2.0) return 0.0;
    if (chsh >= tsirelson) return 1.0;
    double inner = (chsh * 0.5) * (chsh * 0.5) - 1.0;
    if (inner < 0.0) inner = 0.0;
    double p = 0.5 * (1.0 + sqrt(inner));
    double val = 1.0 - secmesh_bin_entropy(p);
    return val < 0.0 ? 0.0 : (val > 1.0 ? 1.0 : val);
}

double secmesh_h_min_from_chsh(double chsh) {
    /* Directly delegates to Moonlab's verified qrng_di_min_entropy_from_chsh */
    return qrng_di_min_entropy_from_chsh(chsh);
}

/* Exact Kullback-Leibler divergence D_KL(p || q) in nats for Bernoulli(p), Bernoulli(q). */
static double bernoulli_kl_nats(double p, double q) {
    if (q <= 0.0 || q >= 1.0) return 1e300;
    double v = 0.0;
    if (p > 0.0) v += p * log(p / q);
    if (p < 1.0) v += (1.0 - p) * log((1.0 - p) / (1.0 - q));
    return v;
}

/* Exact Chernoff-KL upper confidence bound for Binomial(m, q) errors <= k:
 *   P(Bin(m, q) <= m * p_hat) <= exp(-m * D_KL(p_hat || q)) <= eps_qber
 * Tight for low QBER (O(ln(1/eps)/m) at 0 errors instead of Hoeffding's O(sqrt(ln(1/eps)/m))). */
static double qber_kl_upper_bound(double p_hat, uint64_t m, double eps_qber) {
    if (m == 0) return 0.5;
    if (p_hat >= 0.5) return 0.5;
    double rhs = log(1.0 / eps_qber) / (double)m;
    if (p_hat <= 0.0) {
        double q0 = 1.0 - exp(-rhs);
        return q0 > 0.5 ? 0.5 : q0;
    }
    if (bernoulli_kl_nats(p_hat, 0.5) <= rhs) return 0.5;
    double lo = p_hat, hi = 0.5;
    for (int iter = 0; iter < 64; iter++) {
        double mid = 0.5 * (lo + hi);
        if (bernoulli_kl_nats(p_hat, mid) < rhs) lo = mid;
        else hi = mid;
    }
    return hi;
}

void secmesh_finite_key_eval(const secmesh_fk_input_t *in, secmesh_fk_result_t *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!in || in->n_key == 0 ||
        !isfinite(in->eps_total) || !(in->eps_total > 0.0 && in->eps_total < 1.0) ||
        !isfinite(in->chsh_s) || !isfinite(in->ec_efficiency) ||
        in->qber_sample > in->n_key || in->qber_errors > in->qber_sample) return;

    /* Disjoint composable epsilon budget: 5 equal disjoint lanes summing to eps_total */
    const double eps_pe   = in->eps_total * 0.2;
    const double eps_qber = in->eps_total * 0.2;
    const double eps_s    = in->eps_total * 0.2;
    const double eps_pa   = in->eps_total * 0.2;
    const double eps_cor  = in->eps_total * 0.2;

    /* Corrected Hoeffding lower bound on CHSH for ±1 variables (range width b - a = 2):
     *   P(|E_c - mu_c| >= t_c) <= 2 * exp(-n_c * t_c^2 / 2) <= eps_pe / 4
     *   => t_c = sqrt(2 * ln(8 / eps_pe) / n_c). */
    double s_err = 0.0;
    int missing_cell = 0;
    for (int c = 0; c < 4; c++) {
        if (in->cnts[c] == 0) { missing_cell = 1; break; }
        s_err += sqrt((2.0 * log(8.0 / eps_pe)) / (double)in->cnts[c]);
    }
    double s_lb = (missing_cell || in->chsh_s <= 2.0) ? 2.0 : (in->chsh_s - s_err);
    if (s_lb < 2.0) s_lb = 2.0;

    /* Exact Chernoff-KL upper confidence bound on Bernoulli QBER */
    double qber_hat = 1.0;
    double qber_ub  = 0.5;
    if (in->qber_sample > 0) {
        qber_hat = (double)in->qber_errors / (double)in->qber_sample;
        qber_ub  = qber_kl_upper_bound(qber_hat, in->qber_sample, eps_qber);
    }

    double h_min = secmesh_h_min_from_chsh(s_lb);
    double h_vn  = secmesh_h_vn_from_chsh(s_lb);
    double h_per = in->use_di_min_ent ? h_min : h_vn;

    /* Remaining raw key bits after sacrificing qber_sample bits for parameter estimation */
    uint64_t n_rem = (in->n_key > in->qber_sample) ? (in->n_key - in->qber_sample) : 0;
    double f_ec = (in->ec_efficiency >= 1.0) ? in->ec_efficiency : 1.16;

    double leak_ec = (double)n_rem * f_ec * secmesh_bin_entropy(qber_ub);
    /* Tomamichel-Colbeck-Renner (2009) Quantum AEP smoothing term:
     *   Delta_AEP = 4 * log2(2 + sqrt(2)) * sqrt(n_rem * log2(2 / eps_s^2))
     * For single-round H_min (min-entropy already, not von Neumann), only the
     * composable smoothing cost applies; we include the conservative TCR bound
     * in collective mode and exact Renner smoothing in DI min-entropy mode. */
    double aep_pen = 0.0;
    if (n_rem > 0) {
        double log_term = log2(2.0 / (eps_s * eps_s));
        if (in->use_di_min_ent) {
            /* Strict Pironio H_min lower bound + finite-block Azuma/EAT smoothing */
            aep_pen = sqrt(2.0 * (double)n_rem * log(1.0 / eps_s)) / log(2.0);
        } else {
            /* Collective von Neumann requires full Tomamichel-Colbeck-Renner AEP */
            double c_tcr = 4.0 * log2(2.0 + 1.41421356237309504880);
            aep_pen = c_tcr * sqrt((double)n_rem * log_term);
        }
    }

    /* Renner Quantum Leftover Hash Lemma (Theorem T2c): 2 * log2(1 / (2 * eps_PA)) */
    double pa_pen  = 2.0 * log2(1.0 / (2.0 * eps_pa));
    /* Carter-Wegman universal-hash error-verification tag: ceil(log2(1 / eps_cor)) */
    double cor_pen = ceil(log2(1.0 / eps_cor));

    double raw_ell = (double)n_rem * h_per - leak_ec - aep_pen - pa_pen - cor_pen;
    int64_t ell = (raw_ell >= 1.0) ? (int64_t)floor(raw_ell) : 0;

    out->s_lb        = s_lb;
    out->qber_hat    = qber_hat;
    out->qber_ub     = qber_ub;
    out->h_min_di    = h_min;
    out->h_vn_di     = h_vn;
    out->leak_ec     = leak_ec;
    out->aep_penalty = aep_pen;
    out->pa_penalty  = pa_pen;
    out->cor_penalty = cor_pen;
    out->cert_bits   = ell;
    out->admitted    = (ell >= 256) ? 1 : 0;
}

/* =========================================================================
 * 2. Quantum Geometric Tensor (QGTL) on Parameterized Singlet Manifold
 *    |psi(theta, phi)> = (U(theta, phi) x I) |Psi->
 *    where U(theta, phi) = [[cos(t/2), -e^{-i*phi} sin(t/2)],
 *                           [e^{i*phi} sin(t/2), cos(t/2)]]
 *    Exact QGT: Q_uv = <d_u psi | d_v psi> - <d_u psi | psi><psi | d_v psi>
 * ========================================================================= */
static void entangled_state_and_derivs(double t, double p, double alpha,
                                       double complex psi[4],
                                       double complex dt[4],
                                       double complex dp[4]) {
    double ca = cos(alpha), sa = sin(alpha);
    double ct = cos(0.5 * t), st = sin(0.5 * t);
    double complex eip  = cexp( I * p);
    double complex emip = cexp(-I * p);

    /* |Psi_alpha> = cos(alpha)|01> - sin(alpha)|10>, Wootters concurrence C = |sin(2*alpha)|.
     * (U(t,p) x I) |Psi_alpha> =
     *   [ sa * e^{-ip} sin(t/2),  ca * cos(t/2),  -sa * cos(t/2),  ca * e^{ip} sin(t/2) ]^T */
    psi[0] =  sa * emip * st;
    psi[1] =  ca * ct;
    psi[2] = -sa * ct;
    psi[3] =  ca * eip  * st;

    dt[0] =  0.5 * sa * emip * ct;
    dt[1] = -0.5 * ca * st;
    dt[2] =  0.5 * sa * st;
    dt[3] =  0.5 * ca * eip  * ct;

    dp[0] = -I * sa * emip * st;
    dp[1] =  0.0;
    dp[2] =  0.0;
    dp[3] =  I * ca * eip  * st;
}

static double complex cvec_dot(const double complex a[4], const double complex b[4]) {
    double complex s = 0.0;
    for (int i = 0; i < 4; i++) s += conj(a[i]) * b[i];
    return s;
}

void secmesh_qgt_entangled_manifold(double theta, double phi, double alpha,
                                    secmesh_qgt_result_t *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!isfinite(theta) || !isfinite(phi) || !isfinite(alpha)) return;

    double complex psi[4], dt[4], dp[4];
    entangled_state_and_derivs(theta, phi, alpha, psi, dt, dp);

    double complex dt_psi = cvec_dot(dt, psi);
    double complex dp_psi = cvec_dot(dp, psi);

    double complex Q_tt = cvec_dot(dt, dt) - dt_psi * conj(dt_psi);
    double complex Q_pp = cvec_dot(dp, dp) - dp_psi * conj(dp_psi);
    double complex Q_tp = cvec_dot(dt, dp) - dt_psi * conj(dp_psi);

    out->g_tt            = creal(Q_tt);
    out->g_pp            = creal(Q_pp);
    out->g_tp            = creal(Q_tp);
    out->omega_tp        = -2.0 * cimag(Q_tp);
    out->det_g           = out->g_tt * out->g_pp - out->g_tp * out->g_tp;
    out->qgt_rhs         = 0.25 * out->omega_tp * out->omega_tp;
    out->surplus         = out->det_g - out->qgt_rhs;
    out->concurrence     = fabs(sin(2.0 * alpha));
    out->horodecki_s_max = 2.0 * sqrt(1.0 + out->concurrence * out->concurrence);
    out->trace_g         = out->g_tt + out->g_pp;
    out->qfi_trace       = 4.0 * out->trace_g;
    out->inequality_holds = (out->det_g + 1e-12 >= out->qgt_rhs &&
                             out->trace_g + 1e-12 >= fabs(out->omega_tp)) ? 1 : 0;
}

void secmesh_qgt_singlet_manifold(double theta, double phi, secmesh_qgt_result_t *out) {
    secmesh_qgt_entangled_manifold(theta, phi, 0.78539816339744830962, out); /* alpha = pi/4 */
}

void secmesh_chern_concurrence_ghz(double alpha, uint32_t n_qubits,
                                   secmesh_chern_ghz_result_t *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!isfinite(alpha)) return;
    if (n_qubits < 1) n_qubits = 1;
    double c_eff = -cos(2.0 * alpha);
    double conc  = fabs(sin(2.0 * alpha));
    double s_max = 2.0 * sqrt(1.0 + conc * conc);
    double h_min_c = 1.0 - log2(1.0 + fabs(c_eff));
    if (h_min_c < 0.0) h_min_c = 0.0;
    if (h_min_c > 1.0) h_min_c = 1.0;
    double h_min_s = secmesh_h_min_from_chsh(s_max);
    double h_vn_c  = 1.0 - secmesh_bin_entropy(0.5 * (1.0 + conc));
    double tau_n   = conc * conc;
    double nd      = (double)n_qubits;

    out->alpha            = alpha;
    out->n_qubits         = n_qubits;
    out->c_eff            = c_eff;
    out->concurrence      = conc;
    out->conservation_err = fabs(c_eff * c_eff + conc * conc - 1.0);
    out->horodecki_s_max  = s_max;
    out->h_min_from_chern = h_min_c;
    out->h_min_from_chsh  = h_min_s;
    out->h_vn_from_conc   = h_vn_c;
    out->tau_n            = tau_n;
    out->qfi_ghz          = nd * nd * tau_n;
    out->qfi_sql          = nd;
    out->casimir_4j_jp1   = (uint64_t)n_qubits * ((uint64_t)n_qubits + 2ULL);
    out->beats_sql        = (nd * tau_n > 1.0) ? 1 : 0;
}

int secmesh_ising_graph_energy(uint32_t n, const int64_t *J_flat, const int64_t *h_vec,
                               const int8_t *sig, int64_t *dirichlet_out,
                               int64_t *laplacian_quad_out, int64_t *ising_cut_out) {
    if (!J_flat || !h_vec || !sig || !dirichlet_out || !laplacian_quad_out || !ising_cut_out) {
        return -1;
    }
    if (n == 0 || n > 1024) return -2;
    for (uint32_t i = 0; i < n; i++) {
        if (sig[i] != 1 && sig[i] != -1) return -3;
        if (h_vec[i] < 0) return -4;
        for (uint32_t j = 0; j < n; j++) {
            int64_t wij = J_flat[(size_t)i * n + j];
            int64_t wji = J_flat[(size_t)j * n + i];
            if (wij < 0 || wij != wji) return -4;
        }
    }
    __int128 dir = 0, lap = 0, cut_pair = 0, field = 0;
    for (uint32_t i = 0; i < n; i++) {
        __int128 si = (__int128)sig[i];
        field += (__int128)h_vec[i] * (1 - si);
        for (uint32_t j = 0; j < n; j++) {
            __int128 sj = (__int128)sig[j];
            __int128 w  = (__int128)J_flat[(size_t)i * n + j];
            __int128 d  = si - sj;
            dir += w * d * d;
            lap += w * si * d;
            cut_pair += w * (1 - si * sj);
        }
    }
    __int128 cut_tot = cut_pair + 2 * field;
    if (dir < (__int128)INT64_MIN || dir > (__int128)INT64_MAX ||
        lap < (__int128)INT64_MIN || lap > (__int128)INT64_MAX ||
        cut_tot < (__int128)INT64_MIN || cut_tot > (__int128)INT64_MAX) {
        return -5; /* Overflow guard (zero signed UB) */
    }
    *dirichlet_out      = (int64_t)dir;
    *laplacian_quad_out = (int64_t)lap;
    *ising_cut_out      = (int64_t)cut_tot;
    return 0;
}

void secmesh_ising_eval_expander_barrier(uint32_t n_nodes, uint32_t compromised_k,
                                         double coupling_j, double edge_expansion_phi,
                                         double firewall_h, secmesh_ising_barrier_t *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!isfinite(coupling_j) || !isfinite(edge_expansion_phi) || !isfinite(firewall_h)) return;
    if (compromised_k > n_nodes / 2u) compromised_k = n_nodes / 2u;
    if (coupling_j < 0.0) coupling_j = 0.0;
    if (edge_expansion_phi < 0.0) edge_expansion_phi = 0.0;
    if (firewall_h < 0.0) firewall_h = 0.0;
    out->n_nodes            = n_nodes;
    out->compromised_k      = compromised_k;
    out->coupling_j         = coupling_j;
    out->edge_expansion_phi = edge_expansion_phi;
    out->firewall_h         = firewall_h;
    out->min_work_barrier   = 2.0 * (double)compromised_k * (coupling_j * edge_expansion_phi + firewall_h);
}

/* =========================================================================
 * 3. Bravyi et al. (Nature 2024) [[144, 12, 12]] Bivariate-Bicycle qLDPC Code
 *    Group algebra F_2[Z_12 x Z_6], M = 72, N = 144:
 *      A = x^3 + y + y^2
 *      B = y^3 + x + x^2
 *      H_X = [A | B], H_Z = [B^T | A^T]
 * ========================================================================= */
static uint32_t gf2_rank_72x144(uint8_t mat[72][144]) {
    uint32_t row = 0;
    for (uint32_t col = 0; col < 144 && row < 72; col++) {
        uint32_t piv = row;
        while (piv < 72 && mat[piv][col] == 0) piv++;
        if (piv == 72) continue;
        if (piv != row) {
            for (uint32_t c = col; c < 144; c++) {
                uint8_t tmp = mat[row][c];
                mat[row][c] = mat[piv][c];
                mat[piv][c] = tmp;
            }
        }
        for (uint32_t r = 0; r < 72; r++) {
            if (r != row && mat[r][col]) {
                for (uint32_t c = col; c < 144; c++) {
                    mat[r][c] ^= mat[row][c];
                }
            }
        }
        row++;
    }
    return row;
}

void secmesh_bb144_verify_css(secmesh_bb144_audit_t *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);

    enum { ELL = 12, M = 6, HALF = 72, NQ = 144 };
    /* Stack-allocated (31 KiB) for full thread safety & reentrancy */
    uint8_t A[HALF][HALF];
    uint8_t B[HALF][HALF];
    uint8_t HX[HALF][NQ];
    uint8_t HZ[HALF][NQ];
    memset(A, 0, sizeof A);
    memset(B, 0, sizeof B);
    memset(HX, 0, sizeof HX);
    memset(HZ, 0, sizeof HZ);

    /* Index (i, j) -> i * M + j for i in 0..11, j in 0..5.
     * Shift by (dx, dy): (i, j) -> ((i + dx) % ELL, (j + dy) % M). */
    for (int i = 0; i < ELL; i++) {
        for (int j = 0; j < M; j++) {
            int r = i * M + j;
            /* A = x^3 + y + y^2 */
            A[r][((i + 3) % ELL) * M + j] ^= 1;
            A[r][i * M + ((j + 1) % M)]   ^= 1;
            A[r][i * M + ((j + 2) % M)]   ^= 1;
            /* B = y^3 + x + x^2 */
            B[r][i * M + ((j + 3) % M)]   ^= 1;
            B[r][((i + 1) % ELL) * M + j] ^= 1;
            B[r][((i + 2) % ELL) * M + j] ^= 1;
        }
    }

    for (int r = 0; r < HALF; r++) {
        for (int c = 0; c < HALF; c++) {
            HX[r][c]        = A[r][c];
            HX[r][HALF + c] = B[r][c];
            HZ[r][c]        = B[c][r]; /* B^T */
            HZ[r][HALF + c] = A[c][r]; /* A^T */
        }
    }

    uint32_t wmin = NQ, wmax = 0;
    for (int r = 0; r < HALF; r++) {
        uint32_t wx = 0, wz = 0;
        for (int c = 0; c < NQ; c++) {
            wx += HX[r][c];
            wz += HZ[r][c];
        }
        if (wx < wmin) wmin = wx;
        if (wz < wmin) wmin = wz;
        if (wx > wmax) wmax = wx;
        if (wz > wmax) wmax = wz;
    }

    /* Check exact CSS orthogonality H_X * H_Z^T == 0 (mod 2) */
    uint32_t nonzeros = 0;
    for (int rx = 0; rx < HALF; rx++) {
        for (int rz = 0; rz < HALF; rz++) {
            uint8_t dot = 0;
            for (int c = 0; c < NQ; c++) dot ^= (uint8_t)(HX[rx][c] & HZ[rz][c]);
            if (dot) nonzeros++;
        }
    }

    uint8_t hx_copy[HALF][NQ], hz_copy[HALF][NQ];
    memcpy(hx_copy, HX, sizeof HX);
    memcpy(hz_copy, HZ, sizeof HZ);
    uint32_t rx = gf2_rank_72x144(hx_copy);
    uint32_t rz = gf2_rank_72x144(hz_copy);

    out->n_qubits        = NQ;
    out->num_checks_x    = HALF;
    out->num_checks_z    = HALF;
    out->row_weight_min  = wmin;
    out->row_weight_max  = wmax;
    out->nonzeros_hx_hzt = nonzeros;
    out->rank_hx         = rx;
    out->rank_hz         = rz;
    out->logical_k       = (NQ >= rx + rz) ? (NQ - rx - rz) : 0;
}

/* =========================================================================
 * 4. Complete-Graph K_N PQ/PSI Mesh Wire-Bandwidth Profiles
 *    Exact NIST FIPS 203 / 204 / 205 + RFC 7748 / 8032 + Carter-Wegman constants
 * ========================================================================= */
static const secmesh_bw_profile_t g_bw_profiles[] = {
    {
        "classical-x25519-ed25519",
        32, 32, 32, 64, 0, 64,
        32 + 32 + 64 + 64,
        (32 + 32 + 64 + 64) + (32 + 32 + 64 + 64)
    },
    {
        "pq-auth-only-x25519-mldsa65",
        32, 32, 1952, 3309, 0, 64,
        32 + 1952 + 3309 + 64,
        (32 + 1952 + 3309 + 64) + (32 + 1952 + 3309 + 64)
    },
    {
        "hybrid-pq-x25519-mlkem768-ed25519-mldsa65",
        32 + 1184, 32 + 1088, 32 + 1952, 64 + 3309, 0, 96,
        (32 + 1184) + (32 + 1952) + (64 + 3309) + 96,
        ((32 + 1184) + (32 + 1952) + (64 + 3309) + 96) +
        ((32 + 1088) + (32 + 1952) + (64 + 3309) + 96)
    },
    {
        "secmesh-pqsi-hybrid-cw128-xwing-mldsa65",
        32 + 1184, 32 + 1088, 32 + 1952, 64 + 3309, 16, 96,
        (32 + 1184) + (32 + 1952) + (64 + 3309) + 16 + 96,
        ((32 + 1184) + (32 + 1952) + (64 + 3309) + 16 + 96) +
        ((32 + 1088) + (32 + 1952) + (64 + 3309) + 16 + 96)
    },
    {
        "secmesh-pqsi-lattice-hedged-mlkem1024-slhdsa128s-cw128",
        32 + 1568, 32 + 1568, 32 + 1952 + 32, 64 + 3309 + 7856, 16, 128,
        (32 + 1568) + (32 + 1952 + 32) + (64 + 3309 + 7856) + 16 + 128,
        2u * ((32 + 1568) + (32 + 1952 + 32) + (64 + 3309 + 7856) + 16 + 128)
    }
};

uint32_t secmesh_bw_profile_count(void) {
    return (uint32_t)(sizeof(g_bw_profiles) / sizeof(g_bw_profiles[0]));
}

const secmesh_bw_profile_t *secmesh_bw_get_profile(uint32_t idx) {
    if (idx >= secmesh_bw_profile_count()) return NULL;
    return &g_bw_profiles[idx];
}

uint64_t secmesh_bw_mesh_ceiling(uint64_t link_bps, double round_seconds,
                                 uint32_t one_way_bytes) {
    if (one_way_bytes == 0 || !isfinite(round_seconds) || round_seconds <= 0.0) return 0;
    double budget_bytes = ((double)link_bps / 8.0) * round_seconds;
    if (!isfinite(budget_bytes) || budget_bytes < 0.0) return 0;
    double peers_d = floor(budget_bytes / (double)one_way_bytes);
    if (!isfinite(peers_d) || peers_d >= 18446744073709551615.0) return UINT64_MAX;
    uint64_t max_peers = (uint64_t)peers_d;
    return (max_peers == UINT64_MAX) ? UINT64_MAX : (max_peers + 1ULL);
}
