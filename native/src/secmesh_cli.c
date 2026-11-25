/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * SecMesh-PQSI Native C11 CLI (JSON interface for Node/Python/Rosette-Wire interop)
 */
#include "secmesh_pqsi.h"
#include "../third_party/moonlab/crypto/mlkem/mlkem.h"
#include "../third_party/moonlab/crypto/sha3/sha3.h"
#include "../third_party/moonlab/applications/qrng_di.h"
#include "../third_party/moonlab/applications/moonlab_export.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t hlen = strlen(hex);
    if ((hlen & 1u) || (hlen / 2u) > max_len) return -1;
    for (size_t i = 0; i < hlen / 2u; i++) {
        unsigned int v = 0;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)(hlen / 2u);
}

static int cmd_mlkem_kat(void) {
    /* Deterministic FIPS 203 ML-KEM-768 roundtrip with explicit test seeds (d, z, m) */
    uint8_t d[32], z[32], m[32];
    for (int i = 0; i < 32; i++) {
        d[i] = (uint8_t)(0x10 + i);
        z[i] = (uint8_t)(0x40 + i);
        m[i] = (uint8_t)(0x80 + i);
    }
    uint8_t ek[MLKEM768_PUBLICKEYBYTES], dk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES], k_enc[32], k_dec[32], k_bad[32];
    moonlab_mlkem768_keygen(ek, dk, d, z);
    int ek_ok = moonlab_mlkem768_check_ek(ek);
    int dk_ok = moonlab_mlkem768_check_dk(dk);
    moonlab_mlkem768_encaps(ct, k_enc, ek, m);
    moonlab_mlkem768_decaps(k_dec, ct, dk);
    int match = secmesh_ct_memeq(k_enc, k_dec, 32);

    /* Tamper ciphertext to verify Fujisaki-Okamoto implicit rejection */
    ct[0] ^= 0x01;
    moonlab_mlkem768_decaps(k_bad, ct, dk);
    int fo_reject = !secmesh_ct_memeq(k_enc, k_bad, 32);

    uint8_t ek_h[32], ct_h[32];
    ct[0] ^= 0x01; /* restore before hashing */
    sha3_256(ek, sizeof ek, ek_h);
    sha3_256(ct, sizeof ct, ct_h);

    printf("{\"op\":\"mlkem768_kat\",\"ek_valid\":%s,\"dk_valid\":%s,\"match\":%s,\"fo_implicit_reject\":%s,"
           "\"ek_sha3_256\":\"", ek_ok ? "true" : "false", dk_ok ? "true" : "false",
           match ? "true" : "false", fo_reject ? "true" : "false");
    print_hex(ek_h, 32);
    printf("\",\"ct_sha3_256\":\"");
    print_hex(ct_h, 32);
    printf("\",\"ss_hex\":\"");
    print_hex(k_enc, 32);
    printf("\"}\n");

    secmesh_secure_zero(dk, sizeof dk);
    secmesh_secure_zero(k_enc, sizeof k_enc);
    secmesh_secure_zero(k_dec, sizeof k_dec);
    secmesh_secure_zero(k_bad, sizeof k_bad);
    return (ek_ok && dk_ok && match && fo_reject) ? 0 : 1;
}

static int cmd_mlkem_decap_check(const char *ek_hex, const char *m_hex) {
    /* Interop oracle: given external ek (1184B) and m (32B), encapsulate and output ct + ss */
    uint8_t ek[MLKEM768_PUBLICKEYBYTES], m[32], ct[MLKEM768_CIPHERTEXTBYTES], ss[32];
    if (hex_to_bytes(ek_hex, ek, sizeof ek) != MLKEM768_PUBLICKEYBYTES) return 2;
    if (hex_to_bytes(m_hex, m, sizeof m) != 32) return 2;
    if (!moonlab_mlkem768_check_ek(ek)) {
        printf("{\"ok\":false,\"error\":\"invalid_ek\"}\n");
        return 3;
    }
    moonlab_mlkem768_encaps(ct, ss, ek, m);
    printf("{\"ok\":true,\"ct_hex\":\"");
    print_hex(ct, sizeof ct);
    printf("\",\"ss_hex\":\"");
    print_hex(ss, 32);
    printf("\"}\n");
    secmesh_secure_zero(ss, sizeof ss);
    return 0;
}

static int cmd_finite_key(int argc, char **argv) {
    secmesh_fk_input_t in;
    memset(&in, 0, sizeof in);
    in.chsh_s = (argc > 2) ? atof(argv[2]) : 2.82842712474619;
    uint64_t n_total = (argc > 3) ? (uint64_t)strtoull(argv[3], NULL, 10) : 50000ULL;
    double qber_in   = (argc > 4) ? atof(argv[4]) : 0.0;
    in.eps_total     = (argc > 5) ? atof(argv[5]) : 1e-6;
    in.use_di_min_ent = (argc > 6) ? atoi(argv[6]) : 1;
    in.ec_efficiency  = 1.16;

    /* Balanced 3-basis E91 split: 4/9 in CHSH cells (1/9 each), 1/9 in (0,0) key cell */
    uint64_t per_cell = n_total / 9ULL;
    for (int c = 0; c < 4; c++) in.cnts[c] = per_cell;
    in.n_key = per_cell;
    in.qber_sample = per_cell / 5ULL; /* 20% sifting sample for QBER estimation */
    if (in.qber_sample == 0 && in.n_key > 0) in.qber_sample = 1;
    in.qber_errors = (uint64_t)llround(qber_in * (double)in.qber_sample);

    secmesh_fk_result_t res;
    secmesh_finite_key_eval(&in, &res);
    printf("{\"op\":\"finite_key_v2\",\"n_total\":%llu,\"n_key\":%llu,\"qber_sample\":%llu,"
           "\"chsh_s\":%.12f,\"s_lb\":%.12f,\"qber_hat\":%.12f,\"qber_ub\":%.12f,"
           "\"h_min_di\":%.12f,\"h_vn_di\":%.12f,\"leak_ec\":%.4f,\"aep_penalty\":%.4f,"
           "\"pa_penalty\":%.4f,\"cor_penalty\":%.4f,\"cert_bits\":%lld,\"admitted\":%s}\n",
           (unsigned long long)n_total, (unsigned long long)in.n_key,
           (unsigned long long)in.qber_sample, in.chsh_s, res.s_lb,
           res.qber_hat, res.qber_ub, res.h_min_di, res.h_vn_di,
           res.leak_ec, res.aep_penalty, res.pa_penalty, res.cor_penalty,
           (long long)res.cert_bits, res.admitted ? "true" : "false");
    return 0;
}

static int cmd_qgt(int argc, char **argv) {
    double theta = (argc > 2) ? atof(argv[2]) : 1.0471975511965976; /* pi/3 */
    double phi   = (argc > 3) ? atof(argv[3]) : 0.7853981633974483; /* pi/4 */
    double alpha = (argc > 4) ? atof(argv[4]) : 0.7853981633974483; /* pi/4 = singlet */
    secmesh_qgt_result_t r;
    secmesh_qgt_entangled_manifold(theta, phi, alpha, &r);
    printf("{\"op\":\"qgt_entangled\",\"theta\":%.12f,\"phi\":%.12f,\"alpha\":%.12f,"
           "\"concurrence\":%.12f,\"horodecki_s_max\":%.12f,"
           "\"g_tt\":%.12f,\"g_tp\":%.12f,\"g_pp\":%.12f,\"omega_tp\":%.12f,"
           "\"det_g\":%.12f,\"qgt_rhs\":%.12f,\"surplus\":%.12f,"
           "\"trace_g\":%.12f,\"qfi_trace\":%.12f,\"inequality_holds\":%s}\n",
           theta, phi, alpha, r.concurrence, r.horodecki_s_max,
           r.g_tt, r.g_tp, r.g_pp, r.omega_tp,
           r.det_g, r.qgt_rhs, r.surplus, r.trace_g, r.qfi_trace,
           r.inequality_holds ? "true" : "false");
    return r.inequality_holds ? 0 : 1;
}

static int cmd_bb144(void) {
    secmesh_bb144_audit_t a;
    secmesh_bb144_verify_css(&a);
    printf("{\"op\":\"bb144_css\",\"n\":%u,\"k\":%u,\"rank_hx\":%u,\"rank_hz\":%u,"
           "\"row_weight_min\":%u,\"row_weight_max\":%u,\"hx_hzt_nonzeros\":%u,"
           "\"css_orthogonal\":%s}\n",
           a.n_qubits, a.logical_k, a.rank_hx, a.rank_hz,
           a.row_weight_min, a.row_weight_max, a.nonzeros_hx_hzt,
           (a.nonzeros_hx_hzt == 0 && a.logical_k == 12) ? "true" : "false");
    return (a.nonzeros_hx_hzt == 0 && a.logical_k == 12) ? 0 : 1;
}

static int cmd_bandwidth(uint64_t bps, double round_s) {
    uint32_t cnt = secmesh_bw_profile_count();
    printf("{\"op\":\"mesh_bandwidth\",\"link_bps\":%llu,\"round_s\":%.3f,\"profiles\":[",
           (unsigned long long)bps, round_s);
    for (uint32_t i = 0; i < cnt; i++) {
        const secmesh_bw_profile_t *p = secmesh_bw_get_profile(i);
        uint64_t ceil_n = secmesh_bw_mesh_ceiling(bps, round_s, p->one_way_bytes);
        printf("%s{\"name\":\"%s\",\"one_way_bytes\":%u,\"round_trip_bytes\":%u,"
               "\"k_n_ceiling\":%llu}",
               i ? "," : "", p->profile_name, p->one_way_bytes,
               p->round_trip_bytes, (unsigned long long)ceil_n);
    }
    printf("]}\n");
    return 0;
}

static int cmd_entropy_status(void) {
    if (secmesh_entropy_self_test() != 0) {
        printf("{\"op\":\"entropy_status\",\"ok\":false}\n");
        return 1;
    }
    secmesh_entropy_status_t st;
    secmesh_entropy_get_status(&st);
    printf("{\"op\":\"entropy_status\",\"ok\":true,\"requests_served\":%llu,"
           "\"bytes_served\":%llu,\"bell_epochs_passed\":%llu,\"health_failures\":%llu,"
           "\"last_chsh_s\":%.6f,\"last_pironio_hmin\":%.6f,"
           "\"has_physical_qkd_hardware\":%s,\"fips_validated_module\":%s}\n",
           (unsigned long long)st.requests_served, (unsigned long long)st.bytes_served,
           (unsigned long long)st.bell_epochs_passed, (unsigned long long)st.health_failures,
           st.last_chsh_s, st.last_pironio_hmin,
           st.has_physical_qkd_hardware ? "true" : "false",
           st.fips_validated_module ? "true" : "false");
    return 0;
}

static int cmd_chern_law(int argc, char **argv) {
    double alpha = (argc > 2) ? atof(argv[2]) : 0.7853981633974483; /* pi/4 */
    uint32_t nq  = (argc > 3) ? (uint32_t)strtoul(argv[3], NULL, 10) : 8u;
    secmesh_chern_ghz_result_t r;
    secmesh_chern_concurrence_ghz(alpha, nq, &r);
    printf("{\"op\":\"chern_concurrence_ghz\",\"alpha\":%.12f,\"n_qubits\":%u,"
           "\"c_eff\":%.12f,\"concurrence\":%.12f,\"conservation_err\":%.3e,"
           "\"horodecki_s_max\":%.12f,\"h_min_from_chern\":%.12f,\"h_min_from_chsh\":%.12f,"
           "\"h_vn_from_conc\":%.12f,\"tau_n\":%.12f,\"qfi_ghz\":%.12f,\"qfi_sql\":%.12f,"
           "\"casimir_4j_jp1\":%llu,\"beats_sql\":%s}\n",
           r.alpha, r.n_qubits, r.c_eff, r.concurrence, r.conservation_err,
           r.horodecki_s_max, r.h_min_from_chern, r.h_min_from_chsh,
           r.h_vn_from_conc, r.tau_n, r.qfi_ghz, r.qfi_sql,
           (unsigned long long)r.casimir_4j_jp1, r.beats_sql ? "true" : "false");
    return (r.conservation_err < 1e-12) ? 0 : 1;
}

static int cmd_ising_barrier(int argc, char **argv) {
    uint32_t n  = (argc > 2) ? (uint32_t)strtoul(argv[2], NULL, 10) : 60u;
    uint32_t k  = (argc > 3) ? (uint32_t)strtoul(argv[3], NULL, 10) : 10u;
    double jv   = (argc > 4) ? atof(argv[4]) : 1.0;
    double phi  = (argc > 5) ? atof(argv[5]) : 2.0;
    double hv   = (argc > 6) ? atof(argv[6]) : 0.7;
    secmesh_ising_barrier_t b;
    secmesh_ising_eval_expander_barrier(n, k, jv, phi, hv, &b);
    printf("{\"op\":\"ising_expander_barrier\",\"n_nodes\":%u,\"compromised_k\":%u,"
           "\"coupling_j\":%.6f,\"edge_expansion_phi\":%.6f,\"firewall_h\":%.6f,"
           "\"min_work_barrier\":%.6f}\n",
           b.n_nodes, b.compromised_k, b.coupling_j, b.edge_expansion_phi,
           b.firewall_h, b.min_work_barrier);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: secmesh_core <mlkem-kat|mlkem-encaps <ek_hex> <m_hex>|finite-key [S N QBER eps di]|qgt [theta phi alpha]|chern-law [alpha N]|ising-barrier [N k J phi h]|bb144|bandwidth [bps sec]|entropy-status>\n");
        return 1;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "mlkem-kat") == 0) return cmd_mlkem_kat();
    if (strcmp(cmd, "mlkem-encaps") == 0 && argc >= 4) return cmd_mlkem_decap_check(argv[2], argv[3]);
    if (strcmp(cmd, "finite-key") == 0) return cmd_finite_key(argc, argv);
    if (strcmp(cmd, "qgt") == 0) return cmd_qgt(argc, argv);
    if (strcmp(cmd, "chern-law") == 0) return cmd_chern_law(argc, argv);
    if (strcmp(cmd, "ising-barrier") == 0) return cmd_ising_barrier(argc, argv);
    if (strcmp(cmd, "bb144") == 0) return cmd_bb144();
    if (strcmp(cmd, "bandwidth") == 0) {
        uint64_t bps = (argc > 2) ? (uint64_t)strtoull(argv[2], NULL, 10) : 100000000ULL;
        double sec = (argc > 3) ? atof(argv[3]) : 1.0;
        return cmd_bandwidth(bps, sec);
    }
    if (strcmp(cmd, "entropy-status") == 0) return cmd_entropy_status();
    fprintf(stderr, "Unknown command: %s\n", cmd);
    return 1;
}
