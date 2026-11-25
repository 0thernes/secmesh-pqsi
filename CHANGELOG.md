# Changelog (`CHANGELOG.md`)

All notable changes to `secmesh-pqsi` follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [2.1.0] — 2026-11-25

### Added
- **Theorem Family `T7` (`lean/SecMeshPQSI/MonogamyCommitmentNoGo.lean`, 14th Lean module → 27 total zero-Mathlib Lean 4.35.0 theorems, 56 audited declarations across all 6 kernels):**
  - **`T7a` (`t7a_toner_chsh_monogamy_and_eve_isolation`, zero `Classical.choice`):** First-principles algebraic proof of Toner's quantum CHSH monogamy theorem ($S_{AB}^2 + S_{AE}^2 \le 8$) from anticommuting Jordan-block observables, together with CKW tripartite Berry-monopole conservation ($\mathcal{C}_{AB}^2 + \mathcal{C}_{AE}^2 + \tau_{ABE} + r_A^2 = 1$), trapping any computationally unbounded quantum eavesdropper strictly below $2$ whenever $S_{AB} > 2$ and forcing $S_{AE} = \mathcal{C}_{AE} = \tau_{ABE} = r_A = 0$ at Tsirelson saturation.
  - **`T7b` (`t7b_hiding_binding_conservation_nogo`):** Exact finite-support Hiding–Binding Conservation Law ($\mathrm{TV}(P_0, P_1) + \mathrm{Overlap}(P_0, P_1) = 1$), proving unconditional impossibility of simultaneous statistical hiding & binding for bit commitments and establishing the mathematical necessity of SecMesh-PQSI's hybrid PQ+PSI architecture.
- **Exact Python Verification & Citations:** Added `verify_t7()` (`3,211`-point Toner grid + `81,796`-pair exhaustive distribution conservation check), deterministic `10,000`-resample nonparametric percentile bootstrap 95% CIs & rank-biserial $r_{\mathrm{rb}}=1.000$ in `exact_audit.py`, and 3 verified DOIs (`toner2009`, `ckw2000`, `mayers1997` → **42/42 live HTTP-200 citations**).

### Fixed (Cycle 7 Visual PDF, Statistical, GitHub MathJax & Metadata Hardening)
- **GitHub Markdown Broken LaTeX Macros (`bug`):** Replaced undefined custom macros `\HvN`, `\Hmin`, `\QBER` with standard MathJax (`H_{\mathrm{vN}}^{\mathrm{DI}}`, `H_{\min}^{\mathrm{DI}}`, `\mathrm{QBER}`) across `README.md`, `CLAIMS.md`, `DEVIATIONS.md`, `HARDENING_LOG.md`, and `docs/reviews/01-10-pass-review.md`.
- **Bounded-Domain Statistical CI Precision (`concern`):** Replaced symmetric $t$-CI `[59.898, 60.035]` (which overshot the 60-node domain ceiling) in White Paper II Table 4 with exact nonparametric percentile bootstrap 95% CI `[59.900, 60.000]` + rank-biserial $r_{\mathrm{rb}} = 1.000$ and explicit discrete boundary footnote.
- **Full 24-Page Visual PDF Typesetting Audit (`issue`):** Fixed WP1 Page 1 blank-page abstract overflow so Title + Author + full Abstract + Section 1 sit cleanly on Page 1; fixed Table 2/3 headers & Section 4 title wrap; tightened WP2 into a balanced 5-page paper with 0 overfull hboxes.
- **Live GitHub Metadata, Social Preview & Secondary Docs (`error`):** Synced GitHub repository About description, `docs/media/social-preview.svg`, `.cursor/rules/build-standard.mdc`, `CONTRIBUTING.md`, `docs/adr/0002`, `app/blueprint.html`, and `repo.yaml` to `v2.1.0` (`27 theorems`, `6/6 kernels`, `52/52` C11, `15/15` Node, `12/12` pytest, `42/42` live citations).

## [2.0.0] — 2026-11-25

### Added
- **Four New Zero-Mathlib Lean 4.35.0 Theorems (`T4d`, `T4e`, `T6a`, `T6b` → 25 total theorems, 52 audited declarations):**
  - `T4d`: **Topological Chern–Concurrence–Entropy Conservation Law** ($c_{\mathrm{eff}}^2 + \mathcal{C}^2 = 1$, unifying `T1c` quarter-circle duality with `T4b` QGTL Berry curvature and proving $H_{\min}^{\mathrm{DI}}(S_{\max}) = 1 - \log_2(1 + |c_{\mathrm{eff}}|)$).
  - `T4e`: **`libirrep` $\mathrm{SU}(2)$ Spin-$j$ $N$-Qubit GHZ Heisenberg QFI Scaling** ($N^2\tau_N > N \iff N\tau_N > 1$ and $4j(j+1) - 4j^2 = 2N$).
  - `T6a`: **Discrete Laplacian PSD, Ising Ground-State Cut Bijection & Cheeger Expander Cyber-Contagion Barrier** ($W_{\min}(k) \ge 2k(J_{\min}\phi_0 + h_{\min})$, integrating `tsotchke/spin_based_neural_network`).
  - `T6b`: **Cryptosymbology — Simmons Subliminal Channel Zero-Capacity, $2^k$ Kleptographic Bijection & Threshold-Hedged XOR Dual Closure**.
- **Executable Eshkol v1.3.6 Forward-Mode Dual-Number AD Runtime (`node/src/eshkol-ad-runtime.mjs`)** + 4th Eshkol module (`eshkol/chern_ising_ad.esk`), executing all 4 `.esk` modules live and verifying analytical derivatives to `< 1e-12`.
- **Interactive Lean 4.35 Proof Blueprint & SVG Dependency DAG (`app/blueprint.html`)**, upgraded Defense Console (`app/index.html`) with live Chern–Concurrence Monopole meter, and 5th vector figure (`paper/figures/fig5_chern_concurrence_ising_barrier.pdf`).
- **Playbook v1.3 Governance Additions:** Automated README `#print axioms` drift auditor (`scripts/check_readme_axioms.py`), complete enumerated 27-repository Tsotchke stack map (`docs/tsotchke-stack-map.md`), prior-art literature search log (`docs/literature-search-log.md`), and export-control self-screen (`docs/export-control-self-screen.md`).
- **Expanded Verification Suites:** `52/52` C11 tests (`+12` new tests), `500/500` fuzz inputs covering `T4d`/`T6a`, `15/15` Node 25 tests, `12/12` pytest, `39/39` live HTTP-200 citations.

### Fixed (Critical Security, Memory Safety & Citation Integrity Bugs Found in Cycles 4–6)
- **White Paper I Table 2 Mega Atlas ID Fidelity (`error`):** Audited every cited ID against `MegaAtlas_Unsolved_Problems_V2.json` (1,855 entries) and corrected mismatched IDs (`CS-028/031/050/054/061`, `QC-034/042`) to exact verbatim Atlas entries (`QC-021`, `CS-002`, `CS-026`, `CS-028`, `CS-030`, `CS-053`, `CS-061`, `QC-004`, `QC-018`, `QC-030`, `QC-042`, `STAT-014`, `SYS-024`).
- **C11 Undefined Behavior & Thread-Safety (`bug`):** Moved `if (!out) return;` *before* `memset(out, 0, sizeof *out)` in `secmesh_qgt_entangled_manifold`, `secmesh_bb144_verify_css`, and `secmesh_finite_key_eval`; converted `static` BB144 arrays to thread-safe stack allocation; added NULL guards to `secmesh_cw_mac_*` & `secmesh_gf128_mul`; added `uint32_t` overflow/DoS guards to `secmesh_shamir_reconstruct_byzantine`; chunked Windows `BCryptGenRandom` to prevent 64-bit `ULONG` truncation.
- **Guardian v2 CW-128 Anti-Replay & Pad-Reuse Fix (`hole`/`bug`):** Replaced static one-time pad reuse with sequence-bound `[u64be(seq) || tag16 || payload]` framing (`sealCwFrame`/`verifyCwFrame`), rejecting replayed sequence numbers and enforcing per-frame fresh pads per Theorem `T2d`; length-prefixed `nodeId` in canonical handshake transcripts.
- **Tsotchke Repository Inventory Accuracy (`error`):** Corrected repo count from `30 (20+10)` to live-API-verified **`27 (17+10)`** with exact pinned SHAs and verdicts for all 27 repositories.
- **Test & Label Bugs (`bug`/`error`):** Fixed `abs(X) - 1.0 < 1e-15` assertion bug in `python/tests/test_all.py:67`, upgraded Lean forbidden-token regex to catch `private/protected/noncomputable axiom` + strict allowlist parsing, corrected `exact_audit.py` `Compress_1` sharpness check to `e=+832`, fixed `T4a`→`T4b` mislabels across `secmesh_pqsi.h`, `test_native_core.c`, `qgt_geodesic.esk`, and `app/index.html`, and fixed `package.json` `status` script & `repo.yaml` `bundle.json` path.

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
