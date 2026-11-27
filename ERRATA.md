<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Errata (`ERRATA.md`)

Post-release findings discovered between `v1.0.0` / `v1.0.1` and `v2.5.0` (2026-11-25) are logged in items 1–9 below and were resolved in the releases named. The section "2026-11-26 statement audit" at the end lists later findings, some of which are not yet fixed.

1. **`v1.0.0` → `v1.0.1` (Ubuntu CI Portability):** Added `-D_DEFAULT_SOURCE` in `native/Makefile` and `.github/workflows/ci.yml` so `explicit_bzero` compiles cleanly under strict `-std=c11` on Ubuntu glibc, and created `paper/build` prior to Tectonic compilation.
2. **`v1.0.1` → `v2.0.0` (White Paper I Table 2 Mega Atlas ID Audit — `error`):** Direct verification against `MegaAtlas_Unsolved_Problems_V2.json` uncovered 6 mismatched problem descriptions (`CS-028`, `CS-031`, `CS-050`, `CS-054`, `CS-061`, `QC-034`, `QC-042`). All Mega Atlas citations in White Paper I Table 2 and `CLAIMS.md` are now 100% verbatim-verified against `MegaAtlas_Unsolved_Problems_V2.json`.
3. **`v1.0.1` → `v2.0.0` (Tsotchke Public Repository Count — `error`):** Corrected `30 (20 + 10)` to the live GitHub API count of **27 public repositories** (`17` under `tsotchke`, `10` under `Tsotchke-Corporation`) and enumerated all 27 with pinned SHAs in `docs/tsotchke-stack-map.md`.
4. **`v1.0.1` → `v2.0.0` (C11 & Guardian v2 Security Hardening — `bug`/`hole`):** Fixed NULL-pointer dereference before NULL check (`memset` before `if (!out)`) in `secmesh_quantum_geo.c`, stack-allocated BB144 arrays for thread safety, guarded `secmesh_shamir_reconstruct_byzantine` against `uint32_t` wrap-around, and upgraded Guardian v2 TCP framing from static CW-128 pad reuse to sequence-bound anti-replay per-frame pads (`verifyCwFrame`).
5. **`v1.0.1` → `v2.0.0` (Test Assertion & Theorem Label Fixes — `bug`/`error`):** Fixed `abs(X) - 1.0 < 1e-15` precedence bug in `python/tests/test_all.py:67`, updated `exact_audit.py` `Compress_1` tightness check to `e=+832`, and corrected `T4a`→`T4b` labels in `secmesh_pqsi.h`, `test_native_core.c`, `qgt_geodesic.esk`, and `app/index.html`.
6. **`v2.0.0` → `v2.1.0` (GitHub MathJax, Bounded CIs & Page-1 Layout — `bug`/`concern`/`issue`):** Replaced custom undefined MathJax macros (`\HvN`, `\Hmin`, `\QBER`) in `.md` files with standard LaTeX, upgraded White Paper II Table 4 CIs to bounded 10,000-resample nonparametric percentile bootstrap `[59.900, 60.000]` + rank-biserial $r_{\mathrm{rb}}=1.000$, fixed WP1 Page 1 abstract overflow, and added Theorem Family `T7` (`T7a` Toner monogamy & `T7b` commitment conservation no-go).
7. **`v2.1.0` → `v2.2.0` (Shamir Duplicate-`x`, Endianness, `NaN` Guards, Bounded Replay Window, `Palomar.t7b` Axiom Parity & WP1 Table 3 Float — `bug`/`hole`/`issue`):** Enforced distinct $x_i \in [1,p-1]$ & DFS step cap in Byzantine Shamir, replaced host-endian integer hashing with `store_le64`, added NULL/`NaN`/symmetric-Ising guards, replaced unbounded Guardian v2 replay `Set` with RFC-6479 bounded sliding window, removed spurious `Classical.choice` from `Palomar.t7b`, added `\FloatBarrier` keeping WP1 Table 3 inside Sec. 10, added `AdversarialTests.lean` + negative kernel-rejection tests, and added live Crossref retraction checks (`34/34` DOIs not retracted).
8. **`v2.2.0` → `v2.3.0` (Full 18-Page PDF Audit, CLI Hex/`NaN`, Guardian IP-Map Cap, Rosette Non-Empty Checks, Eshkol DoS Cap & Live Web Console/Blueprint Sync — `bug`/`hole`/`error`):** Fixed `LIMITATIONS.md:30` leftover stale Mega Atlas IDs (`CS-028`→`CS-030`, `QC-034`→`QC-004`), fixed WP1 Abstract `14→15 files` & Table 1 `C1`–`C14` alignment with `CLAIMS.md`, replaced permissive `sscanf("%2x")` in `secmesh_cli.c` with strict nibble parser + `isfinite`/`[0,1]` CLI guards, bounded Guardian v2 `rates` Map at 4,096 IPs, added `NaN`/negative fail-closed guards in `finite-key-v2.mjs`, closed vacuous `checks: []` fail-open in `rosette-receipt.mjs`, added step/depth DoS caps in `eshkol-ad-runtime.mjs`, synced `lean/lakefile.toml` & live GitHub Pages (`app/index.html` + `app/blueprint.html` with `T7a`/`T7b` interactive explorer & `AdversarialTests` DAG node), and added automated manifest-version + Mega Atlas regression pytest (`14/14`).
9. **`v2.3.0` → `v2.4.0` (C11 Stack Zeroization & Signed-Overflow UB, Canonical CW-128 Record Framing, POSIX `EINTR` & 5th Eshkol T7 AD Module — `bug`/`hole`/`gap`):** Zeroized Shamir stack state `st` on all exit paths, upgraded `secmesh_ising_graph_energy` to `__int128` overflow-checked accumulators (`-5`), guarded `secmesh_bw_mesh_ceiling`/`secmesh_bin_entropy`/`secmesh_h_vn_from_chsh`/`secmesh_finite_key_eval` against `NaN`/`Inf`/out-of-range QBER (`61/61` C11), added canonical `u32be` length-prefixed CW-128 record MAC framing + strict 32-byte `kItOpt` enforcement + handshake error-path zeroization, added `EINTR` retries to `/dev/urandom` fallback, and added 5th live Eshkol AD module `eshkol/monogamy_commitment_ad.esk` (`18/18` Node).

If you discover any mathematical, formalization, or security error in this repository, please open a GitHub issue with the `bug` or `error` label or email `0_0@0thernes.art`.

## 2026-11-26 statement audit

An independent statement audit checked commit `6c7f6421465c0018f2cfa385ede6f1041a62e543` (`v2.5.0`). Audit log: <https://github.com/0thernes/0thernes-research-archive/blob/main/docs/reviews/2026-11-26-statement-audit.md>. The central rebuild passed (`lake build`, 18 jobs, 0 warnings, 0 errors), and all 28 exported theorems use only `propext`, `Classical.choice` and `Quot.sound`. The audit found that the Lean statements are elementary integer, Boolean and polynomial facts behind known results, and that several descriptions claimed more than the Lean code states.

**Corrected in place in this pass:** `README.md`, `CLAIMS.md`, `LIMITATIONS.md`, `CITATION.cff` (abstract), `lean/formalization.yaml` (descriptive text) and the Markdown files under `docs/` that restate claims. The archive registry class of this entry is now `FORMAL_INVARIANT_SUITE` (previously `PARTIAL_BOUNDED_CASE`): no result is a bounded case of any linked Mega Atlas problem.

**Not changed in this pass:** the frozen white papers (`paper/*.tex`, `paper/refs.bib`, `dist/*.pdf`, `dist/arxiv_submission.tar.gz`), the Lean sources, the Python tests and the CI workflow. Their errors are listed below so that readers of those files can apply the corrections.

### Errors in the frozen White Paper I source and PDF

Line numbers refer to `paper/main.tex` and `paper/refs.bib` at the audited commit; the same text appears in `dist/Donahue_2026_secmesh_pqsi_formal_foundations.pdf`.

1. **Where:** `paper/main.tex` line 67 and lines 493–509 (T7a); `paper/refs.bib` lines 394–403 (`toner2009`).
   **What is wrong:** The quadratic CHSH monogamy bound $S_{AB}^2 + S_{AE}^2 \le 8$ is attributed to Toner (2009, Proc. R. Soc. A 465, 59, doi:10.1098/rspa.2008.0149), whose Theorem 4.1 is the linear bound $\lvert B_{AB}\rvert + \lvert B_{AC}\rvert \le 4$. The text also calls the Lean proof "first-principles" and says it proves Toner's quantum monogamy theorem.
   **Correction:** Cite B. Toner and F. Verstraete, "Monogamy of Bell correlations and Tsirelson's bound", arXiv:quant-ph/0611001 (2006), Theorem 1, for the quadratic bound, and call it Toner–Verstraete monogamy. Describe `T7a` as the kernel-checked final Cauchy–Schwarz step of that bound, with the qubit/anticommutation reduction assumed and the CKW-type relation taken as a hypothesis.
   **Affects a theorem statement:** No (the Lean statement is unchanged; its description and attribution are wrong).
2. **Where:** `paper/main.tex` line 434 (T5c tightness remark).
   **What is wrong:** "at $e = +832$, BOTH $b = 0$ … and $b = 1$ … fail decoding". This holds for the Lean model `mlkemCompress1` (offset 1665) but is false for FIPS 203 Compress_1 (offset 1664), under which only $b = 1$ fails at $+832$.
   **Correction:** State that the margin $|e| \le 831$ is tight at $e = +832$ for $b = 1$; note that the Lean model differs from FIPS 203 at $x = 832$.
   **Affects a theorem statement:** No for `T5c` (true for both definitions on its domain); yes for the adversarial companion (see the formal-code list below).
3. **Where:** `paper/main.tex` lines 375–392 (T4d); `paper/refs.bib` (missing entries).
   **What is wrong:** `T4d` is called a "Topological Chern–Concurrence–Entropy Conservation Law", and product states are said to carry a "unit quantized Dirac monopole charge", while $c_{\mathrm{eff}}(\alpha) = -\cos 2\alpha$ is a continuous value in $[-1,1]$. The Lean content is the double-angle identity in integer form. The relation is prior work and is not cited.
   **Correction:** Describe `T4d` as the polynomial identity $(c_a^2 - s_a^2)^2 + (2c_as_a)^2 = (c_a^2+s_a^2)^2$, read on paper as $c_{\mathrm{eff}}^2 + \mathcal{C}^2 = 1$; cite M. Jakob and J. A. Bergou, "Quantitative complementarity relations in bipartite systems", arXiv:quant-ph/0302075 (2003), Eq. (11) $C^2 + S_k^2 = 1$ and Eqs. (22)–(23), and E. Sjöqvist, Phys. Rev. A 62, 022109 (2000), for the geometric-phase reading. Drop "Topological", "Law" and "quantized"; mark the $H_{\min}$ corollary as paper-level and numerical.
   **Affects a theorem statement:** No.
4. **Where:** `paper/main.tex` lines 290–300 (T3c); `paper/refs.bib` (missing entry).
   **What is wrong:** `T3c` is presented as progress on Mega Atlas `CS-053`. The Lean statement contains no PIR object and fixes $K = 1$; the Byzantine star-product rate is due to Tajeddine et al., not the cited Freij-Hollanti et al. (2017).
   **Correction:** Describe `T3c` as an arithmetic comparison of two published $K = 1$ rate formulas (numerator gap $T^2 > 0$); cite R. Tajeddine, O. W. Gnilke, D. Karpuk, R. Freij-Hollanti and C. Hollanti, arXiv:1806.08006, for the Byzantine rate and the $K = 1$ asymptotic capacity remark.
   **Affects a theorem statement:** No.
5. **Where:** `paper/main.tex` lines 493 and 517 (T7b), and Table 2 line 552.
   **What is wrong:** `T7b` is presented as proving unconditional bit-commitment impossibility and that the PQ+PSI architecture is "mathematically unavoidable". The Lean statement is the identity TV + overlap = 1 for two finite distributions; no protocol, opening phase or adversary is modelled. Mayers (1997), a quantum result, is cited for the classical item, and no source is given for "commitments require one-way functions".
   **Correction:** State the identity; move the commitment and architecture readings to an informal discussion citing Mayers (1997) and H.-K. Lo and H. F. Chau (1997) for the quantum no-go, with a source for the one-way-function claim.
   **Affects a theorem statement:** No.
6. **Where:** `paper/main.tex` lines 67, 116 and 524–526 (T7c).
   **What is wrong:** `T7c` is called a "Quantum Microcrypt EFI" ceiling. Lean covers only classical square-integer weights; the pure-state relation $D_{\mathrm{tr}}^2 + F = 1$ holds by definition; no EFI pair is defined.
   **Correction:** Call it classical Fuchs–van de Graaf bounds for square-integer weights.
   **Affects a theorem statement:** No.
7. **Where:** `paper/refs.bib` line 428 and other `.tex` files (19 lines across `.tex`/`.md`/`.lean`/`.bib` at the audited commit).
   **What is wrong:** Author name spelled "van de Graaff".
   **Correction:** "Jeroen van de Graaf". (Corrected in the Markdown files in this pass; Lean identifiers such as `t7c_fuchs_vandegraaff_microcrypt_efi` keep their names.)
   **Affects a theorem statement:** No.
8. **Where:** `paper/refs.bib` (missing entries).
   **What is wrong:** Earlier machine-checked work on the Kyber/ML-KEM correctness condition is not cited.
   **Correction:** Cite K. Kreuzer, "Verification of Correctness and Security Properties for CRYSTALS-KYBER", IACR ePrint 2023/087 (Isabelle), and Almeida et al., "Formally verifying Kyber".
   **Affects a theorem statement:** No.

### Known issues in the formal code (not yet fixed)

1. **Compress_1 model off by one at $x = 832$.**
   **Where:** `lean/SecMeshPQSI/LatticeBandwidth.lean` lines 197–199 (`mlkemCompress1`, docstring "FIPS 203 Compress_1"); `lean/SecMeshPQSI/AdversarialTests.lean` lines 14–16 and 34–36 (`adv_compress1_fails_at_plus_832`); `.github/workflows/ci.yml` lines 128–129 (negative test rejecting `mlkemCompress1 832 = 0`); `python/tests/test_all.py` lines 125–127 and the negative test near line 270.
   **What is wrong:** The definition uses `(2 * ym + 1665) / 3329`, while FIPS 203 rounding and the vendored `mlkem.c` (`MLKEM_Q / 2 = 1664`) use 1664. They differ only at $x = 832$, where the Lean model returns 1 and FIPS 203 returns 0. So `adv_compress1_fails_at_plus_832` (the $b = 0$ part), the CI negative test and the pytest mirror assert facts that are false, or reject a statement that is true, for FIPS 203.
   **Correction:** Use offset 1664 in Lean and in the Python mirror; restate the adversarial test as `mlkemCompress1 (1*1665+832) ≠ 1` and `mlkemCompress1 832 = 0`; replace the CI negative claim by one that is false for FIPS 203, for example `mlkemCompress1 (1665+832) = 1`; add a lemma tying the definition to round-half-up.
   **Affects a theorem statement:** Yes for `adv_compress1_fails_at_plus_832`; no for `t5c_mlkem_compress1_margin`, which is true for both definitions on its domain.
2. **`T4c1` assumes its conclusion.**
   **Where:** `lean/Challenge.lean` lines 150–153 (`t4c1_general_bb_commutation`).
   **What is wrong:** The hypothesis is the commutation statement itself, so the theorem says nothing about bivariate-bicycle codes. The general lemma `circEntry_comm` (`lean/SecMeshPQSI/QuantumGeometry.lean` line 474) is proved but not exported.
   **Correction:** Export `circEntry_comm`, or its $H_X H_Z^{\mathsf T} = 0$ corollary for all $\ell, m > 0$, as `T4c1`.
   **Affects a theorem statement:** Yes.
3. **`T3b` "tightness" is only arithmetic.**
   **Where:** `lean/Challenge.lean` lines 118–121; module header `lean/SecMeshPQSI/ThresholdPIR.lean` lines 16–21.
   **What is wrong:** The second conjunct is `d = 2 * b ∧ b + b = d` for $n = t + 2b - 1$; no pair of polynomials or received word is constructed, although the header promises an explicit construction.
   **Correction:** Construct the counterexample in Lean, or rename the theorem to "unique decoding for $n \ge t + 2b$".
   **Affects a theorem statement:** Yes (name and scope).
4. **`T1e` first conjunct is the tautology $P \to P$.**
   **Where:** `lean/Challenge.lean` lines 49–52.
   **What is wrong:** `ePE + eQ + eS + ePA + eC ≤ eTot → ePE + eQ + eS + ePA + eC ≤ eTot`.
   **Correction:** Remove the conjunct or replace it by a statement with content; describe `T1e` as budget arithmetic.
   **Affects a theorem statement:** Yes.
5. **Wrong axiom claim in a docstring.**
   **Where:** `lean/SecMeshPQSI/MonogamyCommitmentNoGo.lean` line 582.
   **What is wrong:** The docstring says `T7c` is proved "without `Classical.choice`"; `#print axioms t7c_fuchs_vandegraaff_microcrypt_efi` prints `[propext, Classical.choice, Quot.sound]`.
   **Correction:** Fix the docstring.
   **Affects a theorem statement:** No.
6. **"First-principles" docstring for `T7a`.**
   **Where:** `lean/SecMeshPQSI/MonogamyCommitmentNoGo.lean` line 10.
   **What is wrong:** "First-principles algebraic proof of Toner's quantum CHSH monogamy theorem"; the quantum reduction is assumed.
   **Correction:** "Final algebraic step of the Toner–Verstraete CHSH monogamy bound (quantum reduction assumed)".
   **Affects a theorem statement:** No.
7. **Stale theorem counts in the Lean tree.**
   **Where:** `lean/PalomarChallenge.lean` lines 10 and 197 ("27 theorems", "25 Compared Theorem Statements"); `lean/PalomarSolution.lean` line 11.
   **What is wrong:** The counts are 27 or 25; the exported set is 28 (`T1a`–`T7c`). (`lean/formalization.yaml` was corrected in this pass.)
   **Correction:** Regenerate the counts to 28.
   **Affects a theorem statement:** No.
8. **`SimpleField` docstring claims instances that do not exist.**
   **Where:** `lean/SecMeshPQSI/InfoTheoretic.lean` line 481.
   **What is wrong:** The docstring says the class is "instantiated on `F_p` and `GF(2^128)`"; the only instance in the repository is `SimpleField (Fin 5)` (`NonVacuity.lean` line 41). (Reported by the first audit stage; not re-checked by the final reviewer.)
   **Correction:** Fix the docstring, or add the instances.
   **Affects a theorem statement:** No.

### Tooling (not yet fixed)

1. **Where:** `.github/workflows/ci.yml` lines 87–88.
   **What is wrong:** `ruff` and `mypy` run with `|| true`, so they never fail the build, while the workflow and docs present them as checks. (Reported by the first audit stage; not re-checked by the final reviewer.)
   **Correction:** Make them blocking, or label them informational.
2. **Where:** `docs/literature-search-log.md`.
   **What is wrong:** The log lists sources but records no search queries, databases per query or dates, and it missed Toner–Verstraete (2006), Jakob–Bergou (2003), Tajeddine et al. (2018) and Kreuzer (2023).
   **Correction:** The missed works are now named in the log; future searches should record queries, databases and dates.
