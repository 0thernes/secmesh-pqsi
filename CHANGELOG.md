# Changelog (`CHANGELOG.md`)

All notable changes to `secmesh-pqsi` follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [1.0.1] — 2026-11-25

### Fixed
- **Ubuntu glibc C11 portability (`native/Makefile`, `.github/workflows/ci.yml`):** Added `-D_DEFAULT_SOURCE` under `-std=c11` so vendored Moonlab `utils/secure_memory.h` resolves `explicit_bzero` cleanly on Ubuntu Linux GCC (0 warnings).
- **CI White Papers build directory (`.github/workflows/ci.yml`):** Created `paper/build` and `paper/engineering/build` prior to Tectonic compilation.
- **Ubuntu 6-Kernel Palomar Comparator Verification:** Confirmed all 6 independent Lean 4.35.0 kernels (`Lean paranoid`, `lean4lean` [3,549 decls], `nanoda`, `con-leche` [3,552 decls], `con-ron` [3,552 decls], and `Lean default`) pass `lake comparator --config palomar_comparator.json --paranoid` (`"Your solution is okay!"`) on Ubuntu CI and promoted comparator check to strict mode.

## [1.0.0] — 2026-11-25

### Added
- **Native C11 Moonlab Core (`native/`):** Vendored 18 MIT-licensed files from `tsotchke/moonlab@cd3b234` (FIPS 202 SHA3/SHAKE, FIPS 197 AES-256, FIPS 203 ML-KEM-512/768/1024, NIST SP 800-90B health tests, Toeplitz DI-QRNG) plus constant-time $\mathbb{F}_{2^{128}}$ Carter–Wegman IT-MAC, XOR dual-survivability combiner, Mersenne $\mathbb{F}_{2^{61}-1}$ Byzantine Shamir sharing, exact KL-Chernoff Finite-Key v2, QGTL entanglement surplus witness, Bravyi `[[144,12,12]]` Gross BB qLDPC verifier, and complete-graph $K_N$ bandwidth profiler (`40/40` tests passing under `-Wall -Wextra -Werror`).
- **Node.js 25 PQSI Transport & Hardened Guardian v2 (`node/`):** Bit-exact C11 Moonlab ↔ OpenSSL 3.5.5 FIPS 203 ML-KEM-768 interop, live 25,003 B lattice-hedged hybrid PQSI handshake (`X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + SLH-DSA-128s + CW-128 + OTP`), hardened control plane (no wildcard CORS, no UDP echo, no key leak, 64 KiB cap), Rosette-Wire SHA-256 verifiable receipt bundles, CLI (`secmesh-cli.mjs`), and `12/12` integration tests.
- **Zero-Mathlib Lean 4.35.0 Formalization (`lean/`):** 21 theorems (`T1a`–`T5d`) + concrete `SimpleField (Fin 5)` non-vacuity witnesses + standalone Palomar Registry contract (`PalomarChallenge.lean` / `PalomarSolution.lean`), independently replayed across 5 distinct kernel implementations (`lean`, `leanchecker`, `leanchecker-paranoid`, `con-leche --verified`, `con-ron --verified`, `nanoda_bin 0.4.19`).
- **Eshkol v1.3.6 AD Modules (`eshkol/`) & Interactive Console (`app/index.html`):** Finite-key, QGT geodesic, and $K_N$ optimization modules plus browser-side Defense Console.
- **Independent Python Exact Audit & Figures (`python/`):** Exact-arithmetic verification suite (`exact_audit.py`), pre-registered 30-seed statistical evaluation (`p_Holm = 3.73e-9`), 4 publication vector PDF figures (`paper/figures/`), `11/11` pytest suite, and live citation checker (`32/32` HTTP 200).
- **Two Companion AMS-LaTeX White Papers (`paper/`, `dist/`):** *Formal Algebraic and Information-Theoretic Foundations* (15 pp.) and *Cryptographic Systems Architecture & Threat Model* (6 pp.), plus verified standalone `dist/arxiv_submission.tar.gz`.
- **Repository Governance:** Full Build Standard v1.2.0 compliance (`repo.yaml`, `AGENTS.md`, `CLAIMS.md`, `LIMITATIONS.md`, `REPLICATION.md`, `HARDENING_LOG.md`, `REUSE.toml`, `CITATION.cff`, `MANIFEST.sha256`).
