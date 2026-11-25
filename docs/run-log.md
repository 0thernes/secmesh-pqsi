# Verified Execution Run Log (`docs/run-log.md`)

Verbatim summary of local build and verification runs for `secmesh-pqsi v1.0.0` (2026-11-25, Windows 11, GCC 14.2.0, Node.js v25.8.2 / OpenSSL 3.5.5, Lean 4.35.0, Python 3.12.10, Tectonic 0.17.0):

| Subsystem | Command | Observed Result |
| --- | --- | --- |
| Native C11 Moonlab Core | `make -C native test` (`-std=c11 -O2 -Wall -Wextra -Werror`) | **40 passed, 0 failed**, 0 compiler warnings |
| Node.js 25 Interop & Security | `node node/tests/test_secmesh_v2.mjs` | **12/12 passed** (C11 ↔ OpenSSL ML-KEM-768 bit-exact, live 25,003 B handshake in 391.0 ms) |
| Rosette-Wire Receipt Audit | `node node/src/secmesh-cli.mjs audit` | `verdict: VERIFIED` (4/4 checks passed) |
| Lean 4.35.0 Build & Axioms | `cd lean && lake build && lake env lean VerifyAxioms.lean` | **15/15 jobs**, 0 warnings, 44/44 decls strictly in `[propext, Classical.choice, Quot.sound]` |
| Lean 5-Kernel Replay | `leanchecker`, `leanchecker-paranoid`, `con-leche --verified`, `con-ron --verified`, `nanoda_bin 0.4.19` | **PASS** on `Solution` (3,505 decls) & `PalomarSolution` (3,545 decls); see `results/six_kernel_audit.txt` |
| Python Exact Audit | `.venv/Scripts/python.exe python/secmesh_verify/exact_audit.py` | **PASS** (6/6 sections; 60-digit QGT resid `3.3e-60`; 30-seed `p_Holm = 3.73e-9`) |
| Python Pytest / Ruff / Mypy | `pytest`, `ruff check`, `mypy` | **11/11 pytest passed**, **0 ruff errors**, **0 mypy issues** |
| Live Bibliography Audit | `python scripts/check_citations.py --online` | **32/32 citations HTTP 200** (0 broken DOIs/URLs) |
| White Paper I & II + arXiv | `tectonic -X compile ...` + standalone tarball extract & compile | **WP1:** 14 pp. (`391,060 B`); **WP2:** 5 pp. (`132,907 B`, 0 overfulls); **arXiv tarball:** standalone compile PASS |
