/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * Comprehensive C11 Unit, Negative, KAT, and Cryptographic Invariant Tests
 * covering Moonlab FIPS 202/203, SP 800-90B Health Tests, Toeplitz 2-Universal
 * Extraction, GF(2^128) Carter-Wegman IT-MAC, Dual-Survivability Combiner,
 * Shamir Byzantine Secret Sharing, Finite-Key E91 v2, QGTL, and BB [[144,12,12]].
 */
#include "secmesh_pqsi.h"
#include "../third_party/moonlab/crypto/sha3/sha3.h"
#include "../third_party/moonlab/crypto/aes/aes.h"
#include "../third_party/moonlab/crypto/mlkem/mlkem.h"
#include "../third_party/moonlab/applications/health_tests.h"
#include "../third_party/moonlab/applications/qrng_di.h"
#include "../third_party/moonlab/applications/moonlab_export.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; printf("  [PASS] %s\n", msg); } \
    else { g_fail++; printf("  [FAIL] %s (line %d)\n", msg, __LINE__); } \
} while (0)

static int hex_eq(const uint8_t *buf, size_t len, const char *hex) {
    char tmp[129];
    if (len * 2 >= sizeof tmp) return 0;
    for (size_t i = 0; i < len; i++) snprintf(tmp + 2 * i, 3, "%02x", buf[i]);
    tmp[len * 2] = '\0';
    return strcmp(tmp, hex) == 0;
}

static void test_fips202_and_fips197(void) {
    uint8_t out32[32], out16[16];
    sha3_256((const uint8_t *)"", 0, out32);
    CHECK(hex_eq(out32, 32, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
          "FIPS 202 SHA3-256('') KAT");
    sha3_256((const uint8_t *)"abc", 3, out32);
    CHECK(hex_eq(out32, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
          "FIPS 202 SHA3-256('abc') KAT");
    shake256((const uint8_t *)"", 0, out32, 32);
    CHECK(hex_eq(out32, 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
          "FIPS 202 SHAKE256('', 32) KAT");

    uint8_t k[32], pt[16];
    for (int i = 0; i < 32; i++) k[i] = (uint8_t)i;
    for (int i = 0; i < 16; i++) pt[i] = (uint8_t)((i << 4) | i);
    aes256_ctx_t actx;
    aes256_init(&actx, k);
    aes256_encrypt_block(&actx, pt, out16);
    CHECK(hex_eq(out16, 16, "8ea2b7ca516745bfeafc49904b496089"),
          "FIPS 197 AES-256 Appendix C.3 KAT");
}

static void test_mlkem_all_sets_and_negatives(void) {
    /* ML-KEM-512, ML-KEM-768, ML-KEM-1024 QRNG-seeded roundtrips + FO tamper rejection */
    uint8_t ek5[MLKEM512_PUBLICKEYBYTES], dk5[MLKEM512_SECRETKEYBYTES], ct5[MLKEM512_CIPHERTEXTBYTES];
    uint8_t k1[32], k2[32], kbad[32];
    CHECK(moonlab_mlkem512_keygen_qrng(ek5, dk5) == 0, "ML-KEM-512 QRNG keygen");
    CHECK(moonlab_mlkem512_check_ek(ek5) == 1 && moonlab_mlkem512_check_dk(dk5) == 1,
          "ML-KEM-512 FIPS 203 Sec 7.2/7.3 key checks");
    CHECK(moonlab_mlkem512_encaps_qrng(ct5, k1, ek5) == 0, "ML-KEM-512 QRNG encaps");
    moonlab_mlkem512_decaps(k2, ct5, dk5);
    CHECK(secmesh_ct_memeq(k1, k2, 32) == 1, "ML-KEM-512 shared secret agreement");
    ct5[17] ^= 0x80;
    moonlab_mlkem512_decaps(kbad, ct5, dk5);
    CHECK(secmesh_ct_memeq(k1, kbad, 32) == 0, "ML-KEM-512 negative: FO implicit reject on tampered ct");

    uint8_t ek7[MLKEM768_PUBLICKEYBYTES], dk7[MLKEM768_SECRETKEYBYTES], ct7[MLKEM768_CIPHERTEXTBYTES];
    CHECK(moonlab_mlkem768_keygen_qrng(ek7, dk7) == 0, "ML-KEM-768 QRNG keygen");
    CHECK(moonlab_mlkem768_encaps_qrng(ct7, k1, ek7) == 0, "ML-KEM-768 QRNG encaps");
    moonlab_mlkem768_decaps(k2, ct7, dk7);
    CHECK(secmesh_ct_memeq(k1, k2, 32) == 1, "ML-KEM-768 shared secret agreement");
    /* Negative test: corrupt ek modulus >= q = 3329 (0xFFF in 12-bit coeff) */
    uint8_t ek7_bad[MLKEM768_PUBLICKEYBYTES];
    memcpy(ek7_bad, ek7, sizeof ek7);
    ek7_bad[0] = 0xFF; ek7_bad[1] = 0xFF;
    CHECK(moonlab_mlkem768_check_ek(ek7_bad) == 0, "ML-KEM-768 negative: invalid modulus ek rejected");
    CHECK(moonlab_mlkem768_encaps_qrng(ct7, k2, ek7_bad) == -2, "ML-KEM-768 negative: encaps refuses invalid ek");

    uint8_t ek10[MLKEM1024_PUBLICKEYBYTES], dk10[MLKEM1024_SECRETKEYBYTES], ct10[MLKEM1024_CIPHERTEXTBYTES];
    CHECK(moonlab_mlkem1024_keygen_qrng(ek10, dk10) == 0, "ML-KEM-1024 QRNG keygen");
    CHECK(moonlab_mlkem1024_encaps_qrng(ct10, k1, ek10) == 0, "ML-KEM-1024 QRNG encaps");
    moonlab_mlkem1024_decaps(k2, ct10, dk10);
    CHECK(secmesh_ct_memeq(k1, k2, 32) == 1, "ML-KEM-1024 shared secret agreement");
    secmesh_secure_zero(dk5, sizeof dk5);
    secmesh_secure_zero(dk7, sizeof dk7);
    secmesh_secure_zero(dk10, sizeof dk10);
}

static void test_health_negative_and_toeplitz(void) {
    /* Negative test: stuck-at fault MUST trigger SP 800-90B RCT failure */
    health_test_ctx_t hctx;
    CHECK(health_tests_init(&hctx) == HEALTH_SUCCESS, "SP 800-90B health init");
    uint8_t stuck[128];
    memset(stuck, 0xAA, sizeof stuck);
    health_error_t err = health_tests_run_batch(&hctx, stuck, sizeof stuck);
    CHECK(err == HEALTH_ERROR_RCT_FAILURE, "SP 800-90B negative: stuck-at 0xAA triggers RCT failure");
    health_tests_free(&hctx);

    /* Toeplitz linearity over F_2: T_s(x XOR y) == T_s(x) XOR T_s(y) */
    uint8_t x[32], y[32], xy[32], seed[80], ox[16], oy[16], oxy[16];
    CHECK(moonlab_qrng_bytes(x, 32) == 0 && moonlab_qrng_bytes(y, 32) == 0 &&
          moonlab_qrng_bytes(seed, 80) == 0, "Entropy draw for Toeplitz test");
    for (int i = 0; i < 32; i++) xy[i] = (uint8_t)(x[i] ^ y[i]);
    CHECK(qrng_di_toeplitz_extract(x, 32, seed, 80, ox, 16) == 0 &&
          qrng_di_toeplitz_extract(y, 32, seed, 80, oy, 16) == 0 &&
          qrng_di_toeplitz_extract(xy, 32, seed, 80, oxy, 16) == 0,
          "Moonlab Toeplitz 2-universal extraction");
    uint8_t xor_check[16];
    for (int i = 0; i < 16; i++) xor_check[i] = (uint8_t)(ox[i] ^ oy[i]);
    CHECK(secmesh_ct_memeq(xor_check, oxy, 16) == 1,
          "Toeplitz F_2 linearity: T_s(x XOR y) == T_s(x) XOR T_s(y)");
    /* Negative test: seed too short */
    CHECK(qrng_di_toeplitz_extract(x, 32, seed, 10, ox, 16) == -2,
          "Toeplitz negative: short seed rejected (-2)");
}

static void test_carter_wegman_and_combiner(void) {
    uint8_t r[16], b[16], tag[16];
    moonlab_qrng_bytes(r, 16);
    moonlab_qrng_bytes(b, 16);
    const char *msg = "SecMesh-PQSI authenticated control frame #0001";
    size_t mlen = strlen(msg);
    secmesh_cw_mac_compute(tag, r, b, (const uint8_t *)msg, mlen);
    CHECK(secmesh_cw_mac_verify(tag, r, b, (const uint8_t *)msg, mlen) == 1,
          "Carter-Wegman GF(2^128) IT-MAC verifies authentic message");

    /* Negative tests: bit flip in message, bit flip in tag, length extension */
    uint8_t tampered[64];
    memcpy(tampered, msg, mlen);
    tampered[5] ^= 0x01;
    CHECK(secmesh_cw_mac_verify(tag, r, b, tampered, mlen) == 0,
          "Carter-Wegman negative: 1-bit message tamper rejected");
    tag[15] ^= 0x01;
    CHECK(secmesh_cw_mac_verify(tag, r, b, (const uint8_t *)msg, mlen) == 0,
          "Carter-Wegman negative: 1-bit tag tamper rejected");

    /* Dual-Survivability Combiner test */
    uint8_t k_pq[32], k_it[32], k_out1[32], k_out2[32];
    moonlab_qrng_bytes(k_pq, 32);
    moonlab_qrng_bytes(k_it, 32);
    const uint8_t tr[] = "transcript-v2";
    CHECK(secmesh_hybrid_combine(k_out1, k_pq, 32, k_it, 32, tr, sizeof tr - 1) == 0,
          "Dual-Survivability Combiner PQ+IT");
    /* Flip 1 bit of K_it => flips exact same bit of K_out1 (bijective OTP masking!) */
    k_it[0] ^= 0x80;
    CHECK(secmesh_hybrid_combine(k_out2, k_pq, 32, k_it, 32, tr, sizeof tr - 1) == 0,
          "Dual-Survivability Combiner with flipped K_it");
    CHECK((k_out1[0] ^ k_out2[0]) == 0x80 && secmesh_ct_memeq(k_out1 + 1, k_out2 + 1, 31) == 1,
          "Dual-Survivability exact OTP bijection verified");
}

static void test_shamir_byzantine(void) {
    /* (t=3, n=7, b=2): n = 7 >= t + 2b = 3 + 4 = 7 (Singleton-tight!) */
    uint64_t secret = 0x123456789ABCDEFULL; /* < 2^61 - 1 */
    secmesh_share_t shares[7];
    CHECK(secmesh_shamir_split(secret, 3, 7, shares, NULL) == 0,
          "Shamir (3, 7) split over Mersenne F_{2^61 - 1}");

    uint64_t rec = 0;
    CHECK(secmesh_shamir_reconstruct(shares, 3, &rec) == 0 && rec == secret,
          "Shamir exact Lagrange reconstruction from shares [0..2]");

    /* Corrupt 2 Byzantine shares arbitrarily! */
    shares[1].y ^= 0x555555555ULL;
    shares[5].y = (shares[5].y + 999999937ULL) % SECMESH_SHAMIR_PRIME;
    uint32_t detected = 0;
    rec = 0;
    CHECK(secmesh_shamir_reconstruct_byzantine(shares, 7, 3, 2, &rec, &detected) == 0 &&
          rec == secret && detected == 2,
          "Shamir Byzantine unique recovery with b=2 corruptions (n=t+2b=7)");

    /* Negative test: violate Singleton-Byzantine bound (n=6 < 3 + 2*2) */
    CHECK(secmesh_shamir_reconstruct_byzantine(shares, 6, 3, 2, &rec, &detected) == -2,
          "Shamir Byzantine negative: refuses n < t + 2b (-2)");
}

static void test_finite_key_qgt_bb144_bw(void) {
    /* Honest link at N = 450,000 (50,000 per cell, 40,000 remaining key bits) */
    secmesh_fk_input_t in;
    memset(&in, 0, sizeof in);
    in.chsh_s = 2.82842712474619;
    for (int c = 0; c < 4; c++) in.cnts[c] = 50000;
    in.n_key = 50000;
    in.qber_sample = 10000;
    in.qber_errors = 0;
    in.eps_total = 1e-6;
    in.ec_efficiency = 1.16;
    in.use_di_min_ent = 1;
    secmesh_fk_result_t out;
    secmesh_finite_key_eval(&in, &out);
    CHECK(out.admitted == 1 && out.cert_bits > 15000,
          "Finite-Key v2 (exact KL-Chernoff QBER) admits clean N=450k link with >15k certified bits");
    CHECK(out.h_min_di < out.h_vn_di,
          "Theorem T1c: strict gap H_min^DI(S_LB) < H_vN^DI(S_LB) verified");

    /* Negative test 1: Aligned-cell side-channel Eve (S = 2*sqrt(2), QBER = 15%) */
    in.qber_errors = 1500;
    secmesh_finite_key_eval(&in, &out);
    CHECK(out.admitted == 0 && out.cert_bits == 0,
          "Finite-Key v2 negative: Bell-blind Aligned Eve (15% QBER) rejected");

    /* Negative test 2: Noise-parked Eve (S = 2.15, QBER = 6%) */
    in.chsh_s = 2.15;
    in.qber_errors = 600;
    secmesh_finite_key_eval(&in, &out);
    CHECK(out.admitted == 0 && out.cert_bits == 0,
          "Finite-Key v2 negative: Noise-parked Eve rejected");

    /* QGTL Entanglement Surplus Identity (Theorem T4a):
     * det(g) - (1/4)*Omega^2 == (C^2 / 4) * sin^2(theta/2)
     * Case 1: Product state (alpha = 0, C = 0) => exact saturation (surplus == 0)
     * Case 2: Partially entangled (alpha = pi/8, C = 1/sqrt(2)) => surplus == (1/8)*sin^2(theta/2)
     * Case 3: Singlet (alpha = pi/4, C = 1) => Omega == 0, surplus == (1/4)*sin^2(theta/2) */
    const double th = 1.0471975511965976; /* pi/3 => sin^2(theta/2) = 0.25 */
    secmesh_qgt_result_t qgt_prod, qgt_part, qgt_sing;
    secmesh_qgt_entangled_manifold(th, 0.5, 0.0, &qgt_prod);
    secmesh_qgt_entangled_manifold(th, 0.5, 0.39269908169872414, &qgt_part);
    secmesh_qgt_singlet_manifold(th, 0.5, &qgt_sing);
    CHECK(qgt_prod.inequality_holds == 1 && fabs(qgt_prod.surplus) < 1e-12 &&
          qgt_part.inequality_holds == 1 && fabs(qgt_part.surplus - 0.03125) < 1e-12 &&
          qgt_sing.inequality_holds == 1 && fabs(qgt_sing.omega_tp) < 1e-12 &&
          fabs(qgt_sing.surplus - 0.0625) < 1e-12,
          "QGTL Theorem T4a: det(g)-(1/4)Omega^2 == (C^2/4)sin^2(theta/2) exact across C=0, 1/sqrt(2), 1");

    /* Bivariate-Bicycle [[144, 12, 12]] CSS orthogonality */
    secmesh_bb144_audit_t bb;
    secmesh_bb144_verify_css(&bb);
    CHECK(bb.n_qubits == 144 && bb.nonzeros_hx_hzt == 0 &&
          bb.row_weight_min == 6 && bb.row_weight_max == 6 && bb.logical_k == 12,
          "libirrep/Moonlab BB [[144, 12, 12]] CSS orthogonality H_X H_Z^T = 0 & k = 12");

    /* Bandwidth ceiling check */
    const secmesh_bw_profile_t *p = secmesh_bw_get_profile(3);
    CHECK(p != NULL && p->one_way_bytes == 6685 &&
          secmesh_bw_mesh_ceiling(100000000ULL, 1.0, p->one_way_bytes) == 1870,
          "PQSI K_N wire-bandwidth profile & ceiling exact");
}

int main(void) {
    printf("=== SecMesh-PQSI Native C11 Verification Suite ===\n");
    test_fips202_and_fips197();
    test_mlkem_all_sets_and_negatives();
    test_health_negative_and_toeplitz();
    test_carter_wegman_and_combiner();
    test_shamir_byzantine();
    test_finite_key_qgt_bb144_bw();
    printf("=== Summary: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
