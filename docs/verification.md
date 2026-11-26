# Multi-Kernel Formal & Differential Verification (`docs/verification.md`)

`secmesh-pqsi` enforces defense-in-depth across four independent verification pillars:

1. **Zero-Mathlib Lean 4.35.0 Multi-Kernel Audit (`lean/`, `results/six_kernel_audit.txt`, `app/blueprint.html`):**
   - 27 theorems (`T1a`–`T7b`) + concrete `SimpleField (Fin 5)` and finite-graph non-vacuity witnesses + 4 zero-axiom adversarial boundary counterexamples (`AdversarialTests.lean`) across 15 `.lean` files (`0` warnings, `0` proof `sorry`s, `0` `native_decide`).
   - Replayed through **all 6 distinct kernel implementations** in Linux CI (`lake comparator --config palomar_comparator.json --paranoid`: `Lean paranoid`, `lean4lean`, `nanoda`, `con-leche --verified`, `con-ron --verified`, `Lean default`) and 5 distinct local Windows kernels (`3,638` `Solution` / `3,701` `PalomarSolution` decls; `nanoda_bin` `4,073` checked decls).
   - Every one of the `60` audited declarations' axioms lies strictly in `[propext, Classical.choice, Quot.sound]` (`results/lean_axioms.txt`), enforced automatically by `scripts/check_readme_axioms.py`, alongside a live negative test confirming the Lean kernel rejects a deliberately false `Compress_1` theorem.
2. **Native C11 Moonlab Test Suite & Fuzz Harness (`native/tests/test_native_core.c`, `fuzz_parsers.c`):**
   - Compiled with `-std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Werror` (`0` warnings); **58/58 passed** (incl. Shamir duplicate-`x`/`x=0`/DFS-cap, LE64 portability, NULL/`NaN`/asymmetric-Ising fail-closed guards) + **500/500 standalone fuzz inputs passed**.
3. **Node.js 25 Differential, Anti-Replay & Live Eshkol AD Suite (`node/tests/test_secmesh_v2.mjs`):**
   - **17/17 passed**, including bit-exact C11 Moonlab ↔ OpenSSL 3.5.5 FIPS 203 ML-KEM-768 interop, live 25,007 B lattice-hedged PQSI handshake, Guardian v2 RFC-6479 bounded sliding-window anti-replay CW-128 & bounded IP rate-limit enforcement, strict CLI hex/`NaN` refusal, non-empty Rosette receipt validation, `T6b` threshold-hedged XOR nonce closure, live execution (with DoS caps) of all 4 Eshkol `.esk` forward-mode dual-number AD modules, and C11 `chern-law`/`ising-barrier` differential checks.
4. **Python Exact-Arithmetic, Pytest, Linters & Live Citation Audit (`python/`, `scripts/`):**
   - `exact_audit.py` (60-digit QGT residual `3.3e-60`, `T4d` Chern–Concurrence conservation `1.0e-59`, `T4e` exact `Fraction` GHZ threshold, `T6a` exhaustive 64-state Ising check, `T6b` exhaustive XOR closure, `T7a` 3,211-point Toner monogamy grid, `T7b` 81,796-pair commitment conservation check, pre-registered 30-seed paired test `p_Holm = 3.73e-9` with bounded 10,000-resample bootstrap 95% CIs).
   - `pytest python/tests/test_all.py`: **14/14 passed**; `scripts/check_readme_axioms.py`: **PASS**; `ruff check`: **0 errors**; `mypy`: **0 issues**; `check_citations.py --online`: **42/42 HTTP 200 (32/32 DOIs Crossref-verified not retracted)**.
