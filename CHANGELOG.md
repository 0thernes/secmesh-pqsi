# Changelog (`CHANGELOG.md`)

All notable changes to `secmesh-pqsi` follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [2.3.0] — 2026-11-25

### Fixed (Cycle 9 Full-Page Visual PDF, CLI/Node Security, Web App Parity & Mega Atlas Hygiene)
- **Guardian v2 Unbounded Rate-Limiter IP Map DoS (`hole`, `H9.01`):** Capped `rates` Map in `node/src/mesh-guardian-v2.mjs` at `4,096` tracked source IPs with expired-window pruning and fail-closed flood refusal.
- **C11 CLI Strict Hex Decoding & Float/Unsigned Wrap Guards (`bug`, `H9.02`):** Replaced permissive `sscanf(..., "%2x", ...)` in `native/src/secmesh_cli.c:hex_to_bytes` (which accepted leading whitespace, signs, and trailing non-hex chars) with strict nibble parsing, and added `isfinite` / `[0,1]` QBER bounds checks preventing negative `llround` → `uint64_t` wrap-around and invalid JSON (`nan`/`inf`).
- **`LIMITATIONS.md` Stale Mega Atlas ID Fix (`error`, `H9.03`):** Corrected leftover `v1.0.0` Atlas IDs in `LIMITATIONS.md:30` (`CS-028` → `CS-030` for Fiat–Shamir, `QC-034` → `QC-004` for qLDPC decoding) and added an automated pytest guard (`test_version_sync_and_no_stale_mega_atlas_ids`, `14/14` pytest) preventing both stale Atlas IDs and cross-manifest version drift forever.
- **Live GitHub Pages `app/index.html` & `app/blueprint.html` Upgrade (`error`/`gap`, `H9.04`):** Updated both live pages from stale `v2.0` / `25 Theorems` to `v2.3.0` / `27 Theorems · 6 Kernels · 60 Decls`, wired `T7a`/`T7b` + `AdversarialTests (0 ax)` into the interactive SVG DAG in `app/blueprint.html`, and added an interactive **Theorem `T7a` Toner CHSH Monogamy & `T7b` Hiding–Binding Conservation Explorer** card to `app/index.html`.
- **White Paper I Page 1 & Page 3 Parity (`error`, `H9.05`):** Visual audit of all 18 WP1 pages caught `14 files` → `15 files` in the Page 1 Abstract and aligned Table 1 1-to-1 with `CLAIMS.md` (`C1`–`C14`).
- **Node Finite-Key `NaN`/Negative Guards, Rosette Empty-Check Refusal & Eshkol DoS Cap (`bug`/`hole`, `H9.06`–`H9.08`):** Hardened `finite-key-v2.mjs` against `NaN` / negative QBER inputs, fixed vacuous `[].every(...) === true` fail-open in `rosette-receipt.mjs`, added step (`100,000`) and depth (`256`) DoS budgets to `eshkol-ad-runtime.mjs`, synced `lean/lakefile.toml` to `2.3.0`, raised `check_readme_axioms.py` threshold to `>= 60`, and expanded Node suite to **`17/17`**.

## [2.2.0] — 2026-11-25

### Added (Playbook v1.3 Adversarial Counterexamples & Automated Retraction Audits)
- **Lean 4.35 Adversarial Definition & Counterexample Suite (`lean/SecMeshPQSI/AdversarialTests.lean`, Playbook v1.3 Item 12):** Added 4 zero-axiom machine-checked boundary counterexamples (`adv_compress1_fails_at_plus_832`, `adv_v1_chsh_refutes_tsirelson_bound`, `adv_commitment_disjoint_refutes_hiding`, `adv_toner_concrete_pythagorean_witness`) bringing the Lean formalization to **15 `.lean` files, 18 build jobs, and 60 audited declarations**, paired with automated negative kernel-rejection tests in `python/tests/test_all.py` (`13/13`) and `.github/workflows/ci.yml` confirming Lean rejects deliberately false `Compress_1` claims.
- **Automated Crossref Retraction Check (`scripts/check_citations.py`, Playbook v1.3 Item 16):** Extended `--online` citation verification to query Crossref `relation.is-retracted-by` and `update-to` retraction metadata on every DOI (**42/42 live HTTP 200, 32/32 DOIs verified not retracted**).
- **Expanded Security Regression Tests:** Native C11 suite expanded from `52/52` to **`58/58`** (duplicate-`x` & `x=0` Shamir refusal, NULL `secmesh_ct_memeq`, IEEE-754 `NaN` fail-closed finite-key & Ising expander, asymmetric/negative Ising graph validation); Node.js 25 suite expanded from `15/15` to **`16/16`** (RFC-6479 bounded sliding replay window).

### Fixed (Cycle 8 Deep Cryptographic, Memory-DoS, Endianness, Axiom-Parity & Typesetting Hardening)
- **C11 Byzantine Shamir Duplicate-`x` Forgery & Combinatorial DoS (`bug`/`hole`, `H8.02`):** `secmesh_shamir_reconstruct_byzantine` now enforces pairwise distinct evaluation points $x_i \in [1, p-1]$ (returning `-4`, closing a duplicate-`x` double-counting bypass of Theorem `T3b`) and caps DFS combinations at `200,000` steps (returning `-5`).
- **C11 Big-Endian Portability (`bug`, `H8.03`):** Replaced host-endian `uint64_t` byte-pointer hashing in `secmesh_it_crypto.c` and `secmesh_entropy.c` with explicit little-endian `store_le64` matching Node.js `writeBigUInt64LE`.
- **C11 NULL / `NaN` / Ising Symmetry Guards (`bug`, `H8.04`):** Added NULL guard to `secmesh_ct_memeq`, `isfinite(...)` fail-closed guards across `secmesh_finite_key_eval`, `secmesh_qgt_entangled_manifold`, `secmesh_chern_concurrence_ghz`, and `secmesh_ising_eval_expander_barrier`, and symmetric nonnegative validation (`-4`) to `secmesh_ising_graph_energy`.
- **Node 25 Guardian v2 Unbounded Replay Memory DoS (`hole`, `H8.05`):** Replaced unbounded `Set` in `mesh-guardian-v2.mjs` with RFC-6479-style `createReplayWindow(windowSize = 4096n)` in `pqsi-handshake.mjs` keeping $O(1)$ memory while rejecting both duplicates and stale below-window sequences.
- **Lean `Palomar.t7b` Axiom Parity (`concern`, `H8.06`):** Eliminated unnecessary `Classical.choice` from `SecMeshPQSI.Palomar.t7b_hiding_binding_conservation_nogo` (`[propext, Quot.sound]`), matching `Solution.t7b` identically.
- **White Paper I Page-Layout Float Fix (`issue`, `H8.01`):** Added `\usepackage{placeins}` + `\FloatBarrier` after Table 3 and shortened col 3 header to `Claim & Ref.`, preventing Table 3 from floating past References and Author Affiliation onto a trailing page.

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
