# Clean-Room Replication Guide (`REPLICATION.md`)

Every theorem, differential test, benchmark number, Rosette-Wire receipt, vector figure, and compiled PDF in `secmesh-pqsi` can be reproduced deterministically from source.

## Prerequisites

| Toolchain | Tested Version | Purpose |
| --- | --- | --- |
| GCC / Clang (C11) | GCC 16.1.0 (WinLibs UCRT) / GCC 14 (Ubuntu) | Native Moonlab C11 core, 52-test suite & 500-input fuzz harness |
| Node.js (OpenSSL 3.5+) | Node.js v25.8.2 (OpenSSL 3.5.5) | Hybrid PQ+PSI transport, CLI, live Eshkol AD runtime, 15-test suite |
| Lean 4 + Lake + external kernels | `leanprover/lean4:v4.35.0` | Zero-Mathlib 25-theorem formalization & 6-kernel replay |
| Python + `uv` | Python 3.12.10 | Exact-arithmetic oracles, pytest, README axiom guard, figures, citation audit |
| Tectonic (XeTeX) | Tectonic 0.17.0 | Compiling both AMS-LaTeX white papers |

## Step-by-Step Verification

### 1. Native C11 Moonlab Core (52/52 Tests + 500 Fuzz Inputs)
```bash
make -C native clean all test
./native/build/secmesh_core mlkem-kat
./native/build/secmesh_core bb144
./native/build/secmesh_core chern-law 0.39269908169872414 8
./native/build/secmesh_core ising-barrier 60 10 1.0 2.0 0.7
./native/build/secmesh_core finite-key 2.82842712474619 450000 0.0 1e-6 1
```
Expected: `52 passed, 0 failed`, `cert_bits: 18838`, `admitted: true`, `css_orthogonal: true`, `k: 12`, `conservation_err < 1e-14`, `min_work_barrier: 54.0`.

### 2. Node.js 25 Interop, Anti-Replay Security, Live Eshkol AD & Rosette-Wire Audit (15/15 Tests)
```bash
node node/tests/test_secmesh_v2.mjs
node node/src/secmesh-cli.mjs audit
```
Expected: `Node.js Suite Summary: 15/15 passed`, bit-exact C11 Moonlab ↔ OpenSSL 3.5.5 ML-KEM-768 shared secret match, all 4 Eshkol `.esk` modules evaluated with `< 1e-12` analytic derivative agreement, and `rosette/latest-audit/bundle.json` verifying `VERIFIED (4/4)`.

### 3. Zero-Mathlib Lean 4.35.0 Build & Multi-Kernel Replay
```bash
cd lean
lake clean
lake build
lake env lean VerifyAxioms.lean
lake env leanchecker Solution
lake env leanchecker PalomarSolution
lake env leanchecker-paranoid Solution
lake env leanchecker-paranoid PalomarSolution
```
To replay exported proof terms through `con-leche --verified`, `con-ron --verified`, `nanoda_bin`, and `lean4lean`:
```bash
lake env leanexport Solution -- SecMeshPQSI.Solution.prove_all_secmesh_theorems SecMeshPQSI.NonVacuity.nonvac_all_hypotheses > /tmp/Solution.export
con-leche --verified /tmp/Solution.export
con-ron --verified /tmp/Solution.export
# On Linux with bwrap (all 6 distinct kernels):
lake comparator --config palomar_comparator.json --paranoid
```
Expected: `0` warnings, `0` proof `sorry`s, `52/52` exported declarations strictly within `[propext, Classical.choice, Quot.sound]`, `3,587` decls (`Solution`) and `3,630` decls (`PalomarSolution`) accepted by all 6 distinct kernel implementations in CI (5 distinct locally on Windows).

### 4. Python Exact-Arithmetic Audit, Pytest, Linters & Figures
```bash
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.lock.txt
.venv/bin/python python/secmesh_verify/exact_audit.py
.venv/bin/python python/secmesh_verify/make_figures.py
.venv/bin/pytest python/tests/test_all.py -v
.venv/bin/python scripts/check_readme_axioms.py
.venv/bin/ruff check python scripts/check_citations.py scripts/check_readme_axioms.py
.venv/bin/mypy python/secmesh_verify scripts/check_citations.py scripts/check_readme_axioms.py --ignore-missing-imports
.venv/bin/python scripts/check_citations.py --online
```
Expected: `12 passed`, `README axioms & allowlist check: PASS`, `All checks passed!`, `Success: no issues found`, `39/39` citations HTTP 200, and exact report SHA-256 matching `results/exact_verification_report.json`.

### 5. Compile Both White Papers & Verify `MANIFEST.sha256`
```bash
(cd paper && tectonic -X compile main.tex --outdir build)
(cd paper/engineering && tectonic -X compile secmesh_architecture.tex --outdir build)
sha256sum -c MANIFEST.sha256
```

## Replication Log

| Date | Environment | Scope Verified | Result |
| --- | --- | --- | --- |
| 2026-11-25 | Windows 11 (GCC 16.1.0, Node 25.8.2 / OpenSSL 3.5.5, Lean 4.35.0, Python 3.12.10, Tectonic 0.17.0) + Ubuntu Linux CI | `v2.0.0` clean-room self-replication: C11 (52/52 + 500 fuzz), Node (15/15 + 4 live Eshkol AD modules), Lean 6-kernel CI / 5-kernel Windows replay (25 theorems, 52 decls, 3,587/3,630 decls), Python exact + pytest (12/12), README axiom guard, live citations (39/39), WP1 + WP2 + 5 figures + arXiv tarball | PASS (independent external second-person replication open) |

