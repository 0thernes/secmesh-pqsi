# Multi-Kernel Formal & Differential Verification (`docs/verification.md`)

`secmesh-pqsi` enforces defense-in-depth across four independent verification pillars:

1. **Zero-Mathlib Lean 4.35.0 Multi-Kernel Audit (`lean/`, `results/six_kernel_audit.txt`):**
   - 21 theorems (`T1a`–`T5d`) + concrete `SimpleField (Fin 5)` non-vacuity witnesses across 12 `.lean` files (`3,501` lines, `0` warnings, `0` proof `sorry`s, `0` `native_decide`).
   - Replayed through **5 distinct kernel implementations (6 runs)**: `lean v4.35.0`, `leanchecker`, `leanchecker-paranoid`, `con-leche --verified` (`3,505` / `3,545` decls), `con-ron --verified` (`3,505` / `3,545` decls), and `nanoda_bin 0.4.19` (`unpermitted_axiom_hard_error=true`).
   - Every exported declaration's axioms lie strictly in `[propext, Classical.choice, Quot.sound]` (`results/lean_axioms.txt`).
2. **Native C11 Moonlab Test Suite (`native/tests/test_native_core.c`):**
   - Compiled with `-std=c11 -O2 -Wall -Wextra -Werror` (`0` warnings); **40/40 passed**.
3. **Node.js 25 Differential & Security Suite (`node/tests/test_secmesh_v2.mjs`):**
   - **12/12 passed**, including bit-exact C11 Moonlab ↔ OpenSSL 3.5.5 FIPS 203 ML-KEM-768 interop, live 25,003 B lattice-hedged PQSI handshake (`391.0 ms`), Guardian v2 security enforcement, and Rosette-Wire verification.
4. **Python Exact-Arithmetic, Pytest, Linters & Live Citation Audit (`python/`, `scripts/check_citations.py`):**
   - `exact_audit.py` (60-digit QGT residual `3.3e-60`, pre-registered 30-seed paired test `p_Holm = 3.73e-9`).
   - `pytest python/tests/test_all.py`: **11/11 passed**; `ruff check`: **0 errors**; `mypy`: **0 issues**; `check_citations.py --online`: **32/32 HTTP 200**.
