# Verified Execution Run Log (`docs/run-log.md`)

Verbatim summary of local build and verification runs for `secmesh-pqsi v2.5.0` (2026-11-25, Windows 11, GCC 16.1.0 WinLibs UCRT, Node.js v25.8.2 / OpenSSL 3.5.5, Lean 4.35.0, Python 3.12.10, Tectonic 0.17.0):

| Subsystem | Command | Observed Result |
| --- | --- | --- |
| Native C11 Moonlab Core | `make -C native test` (`-std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Werror`) | **61 passed, 0 failed**, 0 compiler warnings + **500/500** fuzz inputs passed + `__int128` Ising guard, Shamir stack zeroization, strict CLI hex/`NaN` guards |
| Node.js 25 Interop & Security | `node node/tests/test_secmesh_v2.mjs` | **18/18 passed** (C11 ↔ OpenSSL ML-KEM-768 bit-exact, canonical `u32be` CW-128 record MAC, RFC-6479 bounded sliding replay window + IP-map cap, non-empty Rosette checks, 5 live Eshkol AD modules covering `T1`–`T7`) |
| Rosette-Wire Receipt Audit | `node node/src/secmesh-cli.mjs audit` | `verdict: VERIFIED` (4/4 checks passed) |
| Lean 4.35.0 Build & Axioms | `cd lean && lake build && lake env lean VerifyAxioms.lean` | **18/18 jobs**, 0 warnings, **63/63** decls strictly in `[propext, Classical.choice, Quot.sound]` (`Palomar.t7b` zero `Classical.choice`, 5 zero-axiom `AdversarialTests`) |
| Lean Multi-Kernel Replay | `leanchecker`, `leanchecker-paranoid`, `con-leche --verified`, `con-ron --verified`, `nanoda_bin 0.4.19` (+ `lean4lean` in Ubuntu CI) | **PASS** on `Solution` (3,638 decls) & `PalomarSolution` (3,694 comparator decls); all 6 distinct kernels PASS via `lake comparator --paranoid` on Ubuntu CI |
| Python Exact Audit | `.venv/Scripts/python.exe python/secmesh_verify/exact_audit.py` | **PASS** (8/8 sections; 60-digit QGT resid `3.3e-60`; Chern resid `1e-59`; 3,211-pt Toner; 81,796-pair `T7b`; 30-seed `p_Holm = 3.73e-9`, bounded bootstrap CIs) |
| Python Pytest / Ruff / Mypy | `pytest`, `check_readme_axioms.py`, `ruff check`, `mypy` | **14/14 pytest passed** (incl. live Lean negative rejection & manifest/Atlas sync guard), **README axiom check PASS**, **0 ruff errors**, **0 mypy issues** |
| Live Bibliography & Retractions | `python scripts/check_citations.py --online` | **42/42 citations HTTP 200** and **32/32 DOIs Crossref-verified not retracted** |
| White Paper I & II + arXiv | `tectonic -X compile ...` + standalone tarball extract & compile | **WP1:** 18 pp. (`0` overfulls, Table 3 inside Sec. 10); **WP2:** 5 pp. (`0` overfulls); **arXiv tarball:** standalone compile PASS |
