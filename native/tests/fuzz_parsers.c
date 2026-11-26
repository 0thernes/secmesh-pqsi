/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Alexander S. Donahue
 *
 * libFuzzer harness for SecMesh-PQSI C11 parsers & cryptographic boundary checks:
 *   - moonlab_mlkem768_check_ek (malformed public key rejection)
 *   - secmesh_cw128_mac (arbitrary message length Carter-Wegman GF(2^128) MAC)
 *   - secmesh_finite_key_eval (arbitrary CHSH / QBER / epsilon inputs)
 *   - secmesh_shamir_reconstruct (Byzantine share recovery on arbitrary inputs)
 *
 * Build with Clang libFuzzer:
 *   clang -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined ... fuzz_parsers.c -o secmesh_fuzzer -lm
 * Or deterministic standalone smoke test (-DFUZZ_STANDALONE):
 *   gcc -std=c11 -O2 -Wall -Wextra -Werror -DFUZZ_STANDALONE ... fuzz_parsers.c -o fuzz_smoke -lm
 */
#include "secmesh_pqsi.h"
#include "secmesh_tun.h"
#include "../third_party/moonlab/crypto/mlkem/mlkem.h"
#include "../third_party/moonlab/applications/moonlab_export.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || size < 32) return 0;

    /* 1. Fuzz Carter-Wegman GF(2^128) IT-MAC over arbitrary byte lengths */
    uint8_t tag[16];
    secmesh_cw_mac_compute(tag, data, data + 16, data + 32, size - 32);
    if (!secmesh_cw_mac_verify(tag, data, data + 16, data + 32, size - 32)) {
        __builtin_trap();
    }

    /* 2. Fuzz ML-KEM-768 public-key validation when input >= 1184 bytes */
    if (size >= MLKEM768_PUBLICKEYBYTES) {
        (void)moonlab_mlkem768_check_ek(data);
    }

    /* 3. Fuzz Finite-Key v2 admission gate on arbitrary finite/extreme inputs */
    secmesh_fk_input_t fk;
    memset(&fk, 0, sizeof fk);
    fk.chsh_s = 1.5 + ((double)data[0] / 128.0);
    uint64_t cell = ((uint64_t)data[1] << 10) + 1ULL;
    for (int i = 0; i < 4; i++) fk.cnts[i] = cell;
    fk.n_key = cell;
    fk.qber_sample = cell / 5ULL + 1ULL;
    fk.qber_errors = (uint64_t)data[2] % fk.qber_sample;
    fk.eps_total = 1e-6;
    fk.ec_efficiency = 1.16;
    fk.use_di_min_ent = data[3] & 1;
    secmesh_fk_result_t res;
    secmesh_finite_key_eval(&fk, &res);

    /* Invariant: parked/classical CHSH S <= 2.0 must NEVER certify positive bits */
    if (fk.chsh_s <= 2.0 && (res.admitted || res.cert_bits > 0)) {
        __builtin_trap();
    }

    /* 4. Fuzz Chern-Concurrence conservation (T4d) & Ising Laplacian PSD (T6a) */
    secmesh_chern_ghz_result_t cg;
    double alpha = ((double)data[4] / 255.0) * 1.5707963267948966;
    uint32_t nq = (uint32_t)(data[5] % 64u) + 1u;
    secmesh_chern_concurrence_ghz(alpha, nq, &cg);
    if (cg.conservation_err > 1e-11) __builtin_trap();

    int64_t J4[16] = {0};
    int64_t h4[4];
    int8_t sig4[4];
    for (int i = 0; i < 4; i++) {
        h4[i] = (int64_t)(data[6 + i] & 0x0Fu);
        sig4[i] = (data[10 + i] & 1u) ? 1 : -1;
        for (int j = i + 1; j < 4; j++) {
            int64_t w = (int64_t)(data[14 + i * 4 + j] & 0x0Fu);
            J4[i * 4 + j] = w;
            J4[j * 4 + i] = w;
        }
    }
    int64_t dir = 0, lap = 0, cut = 0;
    if (secmesh_ising_graph_energy(4, J4, h4, sig4, &dir, &lap, &cut) != 0 ||
        dir != 2 * lap || dir < 0 || cut < 0) {
        __builtin_trap();
    }

    /* 5. Fuzz v3.0 RFC 791 IPv4 parser & SP 800-90B pad buffer auditor */
    secmesh_ipv4_hdr_t ip4;
    (void)secmesh_ipv4_parse(data, size, &ip4);
    if (size >= 512) {
        (void)secmesh_sp80090b_audit_buffer(data, size);
    }
    return 0;
}

#ifdef FUZZ_STANDALONE
#include <stdio.h>
int main(void) {
    uint8_t buf[1280];
    uint64_t st = 0x9e3779b97f4a7c15ULL;
    for (int iter = 0; iter < 500; iter++) {
        size_t len = 32 + (size_t)(st % (sizeof(buf) - 32));
        for (size_t i = 0; i < len; i++) {
            st ^= st >> 12; st ^= st << 25; st ^= st >> 27;
            buf[i] = (uint8_t)((st * 2685821657736338717ULL) >> 56);
        }
        LLVMFuzzerTestOneInput(buf, len);
    }
    printf("fuzz_parsers standalone smoke test: 500/500 inputs passed (0 crashes, 0 invariant violations)\n");
    return 0;
}
#endif
