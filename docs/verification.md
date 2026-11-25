# Multi-Kernel Formal & Differential Verification (`docs/verification.md`)

`secmesh-pqsi` enforces defense-in-depth across four independent verification pillars:

1. **Zero-Mathlib Lean 4.35.0 Multi-Kernel Audit (`lean/`, `results/six_kernel_audit.txt`, `app/blueprint.html`):**
   - 25 theorems (`T1a`–`T6b`) + concrete `SimpleField (Fin 5)` and finite-graph non-vacuity witnesses across 13 `.lean` files (`0` warnings, `0` proof `sorry`s, `0` `native_decide`).
   - Replayed through **all 6 distinct kernel implementations** in Linux CI (`lake comparator --config palomar_comparator.json --paranoid`: `Lean paranoid`, `lean4lean`, `nanoda`, `con-leche --verified`, `con-ron --verified`, `Lean default`) and 5 distinct local Windows kernels (`3,587` `Solution` / `3,630` `PalomarSolution` decls).
   - Every one of the `52` audited declarations' axioms lies strictly in `[propext, Classical.choice, Quot.sound]` (`results/lean_axioms.txt`), enforced automatically by `scripts/check_readme_axioms.py`.
2. **Native C11 Moonlab Test Suite & Fuzz Harness (`native/tests/test_native_core.c`, `fuzz_parsers.c`):**
   - Compiled with `-std=c11 -O2 -Wall -Wextra -Werror` (`0` warnings); **52/52 passed** + **500/500 standalone fuzz inputs passed**.
3. **Node.js 25 Differential, Anti-Replay & Live Eshkol AD Suite (`node/tests/test_secmesh_v2.mjs`):**
   - **15/15 passed**, including bit-exact C11 Moonlab ↔ OpenSSL 3.5.5 FIPS 203 ML-KEM-768 interop, live 25,007 B lattice-hedged PQSI handshake, Guardian v2 anti-replay CW-128 enforcement, `T6b` threshold-hedged XOR nonce closure, live execution of all 4 Eshkol `.esk` forward-mode dual-number AD modules, and C11 `chern-law`/`ising-barrier` differential checks.
4. **Python Exact-Arithmetic, Pytest, Linters & Live Citation Audit (`python/`, `scripts/`):**
   - `exact_audit.py` (60-digit QGT residual `3.3e-60`, `T4d` Chern–Concurrence conservation `1.0e-59`, `T4e` exact `Fraction` GHZ threshold, `T6a` exhaustive 64-state Ising check, `T6b` exhaustive XOR closure, pre-registered 30-seed paired test `p_Holm = 3.73e-9`).
   - `pytest python/tests/test_all.py`: **12/12 passed**; `scripts/check_readme_axioms.py`: **PASS**; `ruff check`: **0 errors**; `mypy`: **0 issues**; `check_citations.py --online`: **39/39 HTTP 200**.
