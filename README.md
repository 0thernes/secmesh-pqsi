<!-- SPDX-License-Identifier: CC-BY-4.0 -->
![SecMesh-PQSI — Post-Quantum & Post-Super-Intelligence Mesh Cryptography](docs/media/social-preview.svg)

# SecMesh-PQSI

<p align="center">
  <strong>Post-Quantum (PQ) &amp; Post-Super-Intelligence (Information-Theoretic PSI) Cryptographic Mesh Defense Engine</strong><br/>
  <em>28 Zero-Mathlib Lean 4.35.0 Theorem Statements · 6 Kernel Runs (5 Distinct Implementations) · C11 Moonlab ↔ OpenSSL 3.5.5 FIPS 203 Interop · 5 Eshkol AD Modules · 2 AMS-LaTeX White Papers</em>
</p>

<p align="center">
  <a href="https://github.com/0thernes/secmesh-pqsi/actions/workflows/ci.yml"><img src="https://github.com/0thernes/secmesh-pqsi/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/code-Apache--2.0-blue.svg" alt="Code License: Apache-2.0" /></a>
  <a href="LICENSE-DOCS"><img src="https://img.shields.io/badge/docs%20%26%20papers-CC--BY--4.0-lightgrey.svg" alt="Docs License: CC-BY-4.0" /></a>
  <a href="lean/lean-toolchain"><img src="https://img.shields.io/badge/Lean-4.35.0%20(zero--Mathlib)-purple.svg" alt="Lean 4.35.0" /></a>
  <a href="results/six_kernel_audit.txt"><img src="https://img.shields.io/badge/proof%20kernels-6%20%2F%206%20Palomar-brightgreen.svg" alt="6 kernel runs (5 distinct implementations)" /></a>
  <a href="https://0thernes.github.io/secmesh-pqsi/"><img src="https://img.shields.io/badge/console-GitHub%20Pages-teal.svg" alt="Interactive Defense Console" /></a>
  <a href="https://0thernes.github.io/secmesh-pqsi/blueprint.html"><img src="https://img.shields.io/badge/blueprint-Lean%20DAG-indigo.svg" alt="Interactive Proof Blueprint" /></a>
</p>

---

**SecMesh-PQSI** (`v2.5.0`) is a clean-room cryptographic refactoring of [`BoogerCheeseOnRye/SecMesh@aff7dc6`](https://github.com/BoogerCheeseOnRye/SecMesh) rebuilt atop Tsotchke's MIT/Apache-2.0 cryptographic, representation-theoretic, and quantum-geometry stack (`moonlab`, `quantum_geometric_tensor`, `libirrep`, `spin_based_neural_network`, `eshkol`, `rosette-wire`, `pq-consensus-bandwidth`, `quantum_rng`, `classical_rng`; complete live-verified 27-repo audit in [`docs/tsotchke-stack-map.md`](docs/tsotchke-stack-map.md)) into a **Post-Quantum + Post-Super-Intelligence (information-theoretic)** defense architecture. It is a research reference implementation.

**What the Lean code proves, in one sentence.** The 28 Lean statements are elementary integer, Boolean and polynomial identities and inequalities that sit behind known cryptographic and quantum-information results; the physical, probabilistic and protocol readings in the theorem names (quantum states, entropy, Chern numbers, PIR schemes, commitments, EFI pairs) are not defined in Lean and are paper-level. See [`CLAIMS.md`](CLAIMS.md) for the per-family split and the [2026-11-26 statement audit](https://github.com/0thernes/0thernes-research-archive/blob/main/docs/reviews/2026-11-26-statement-audit.md) for the evidence.

- **Author:** Alexander S. Donahue ([ORCID `0009-0006-8168-9648`](https://orcid.org/0009-0006-8168-9648), Independent Researcher, Spokane, WA, USA)
- **White Paper I (Formal Foundations):** [PDF (`dist/Donahue_2026_secmesh_pqsi_formal_foundations.pdf`)](dist/Donahue_2026_secmesh_pqsi_formal_foundations.pdf) · [LaTeX](paper/main.tex) · [arXiv Tarball](dist/arxiv_submission.tar.gz)
- **White Paper II (Systems Architecture & Threat Model):** [PDF (`dist/Donahue_2026_secmesh_pqsi_architecture.pdf`)](dist/Donahue_2026_secmesh_pqsi_architecture.pdf) · [LaTeX](paper/engineering/secmesh_architecture.tex)
- **Interactive Defense Console & Proof Blueprint:** [`app/index.html`](app/index.html) · [`app/blueprint.html`](app/blueprint.html) (live on GitHub Pages)

---

## 5-Second Verbatim Kernel Proof (`#print axioms`)

Each of the **28 theorem statements (`T1a`–`T7c`)** in both `SecMeshPQSI.Solution.*` and standalone Palomar `SecMeshPQSI.Palomar.*` compiles in **zero-Mathlib Lean 4.35.0** with **0 warnings**, **0 `sorry` outside the 28 comparator challenge stubs in `PalomarChallenge.lean`** (which is not a default build target), **0 `native_decide`**, and **0 custom axioms**. The Palomar targets passed **6 kernel runs (5 distinct implementations)** (`Lean paranoid`, `lean4lean`, `nanoda`, `con-leche --verified`, `con-ron --verified`, `Lean default`; the first and last are one kernel in two modes) via `lake comparator --config palomar_comparator.json --paranoid` on Ubuntu CI run 45745957907, with automated drift checks via [`scripts/check_readme_axioms.py`](scripts/check_readme_axioms.py):

```text
$ cd lean && lake build && lake env lean VerifyAxioms.lean
'SecMeshPQSI.Solution.t1a_v1_tsirelson_violation' does not depend on any axioms
'SecMeshPQSI.Solution.t1d_denoise_majority_bias_and_fragility' does not depend on any axioms
'SecMeshPQSI.Solution.t4c1_general_bb_commutation' does not depend on any axioms
'SecMeshPQSI.Solution.t2a_shannon_otp_perfect_secrecy' depends on axioms: [Quot.sound]
'SecMeshPQSI.Solution.t2b_hybrid_dual_survivability' depends on axioms: [propext, Quot.sound]
'SecMeshPQSI.Solution.t4b_qgt_concurrence_surplus_identity' depends on axioms: [propext, Classical.choice, Quot.sound]
'SecMeshPQSI.Solution.t4c2_bravyi_gross_bb144_certified' depends on axioms: [propext, Classical.choice, Quot.sound]
'SecMeshPQSI.Solution.t4d_chern_concurrence_entropy_conservation' depends on axioms: [propext, Classical.choice, Quot.sound]
'SecMeshPQSI.Solution.t4e_libirrep_ghz_heisenberg_qfi_scaling' depends on axioms: [propext, Classical.choice, Quot.sound]
'SecMeshPQSI.Solution.t6a_ising_laplacian_psd_and_cheeger_barrier' depends on axioms: [propext, Classical.choice, Quot.sound]
'SecMeshPQSI.Solution.t6b_cryptosymbology_subliminal_and_threshold_closure' depends on axioms: [propext, Quot.sound]
'SecMeshPQSI.Solution.t7a_toner_chsh_monogamy_and_eve_isolation' depends on axioms: [propext, Quot.sound]
'SecMeshPQSI.Solution.t7b_hiding_binding_conservation_nogo' depends on axioms: [propext, Quot.sound]
'SecMeshPQSI.Solution.t7c_fuchs_vandegraaff_microcrypt_efi' depends on axioms: [propext, Classical.choice, Quot.sound]
'SecMeshPQSI.Solution.prove_all_secmesh_theorems' depends on axioms: [propext, Classical.choice, Quot.sound]
'SecMeshPQSI.NonVacuity.nonvac_all_hypotheses' depends on axioms: [propext, Quot.sound]
```
*(All 63 exported lines in [`results/lean_axioms.txt`](results/lean_axioms.txt) — 28 `Solution` + master conjunction + `NonVacuity` + 28 `Palomar` + 5 zero-axiom `AdversarialTests` — lie strictly within `[propext, Classical.choice, Quot.sound]`.)*

---

## Core Results at a Glance

All T-rows are classed `FORMAL_INVARIANT_SUITE` in the archive registry: kernel-checked formalizations of known results and engineering arithmetic. None is new mathematics, and none is a bounded case of any Mega Atlas problem.

| Family | What Lean checks (kernel-checked) | What is paper-level, numerical or cited, not formalized | Lean module |
| --- | --- | --- | --- |
| **T1 — Arithmetic on the legacy SecMesh v1 prototype** | Fixed-number facts: $4(1-2\cdot 0.146) = 354/125$ with $354^2 - 8\cdot 125^2 = 316 > 0$; among 8-bit words, 93 have popcount $\ge 5$, 163 have popcount $< 5$ and 70 have popcount 4; cleared-denominator integer forms of the range-2 Hoeffding factor and of $u^2+v^2=1$; budget arithmetic for five $\varepsilon$-lanes. | The values $0.02857$ vs $2.5{\times}10^{-7}$ and the $H_{\mathrm{vN}}^{\mathrm{DI}} - H_{\min}^{\mathrm{DI}}$ peak $+0.2357$ bit at $S \approx 2.6990$ are Python computations. That the legacy code uses `CELL_P = [0.146, 0.854]` is an input. The first conjunct of `t1e` is the tautology $P \to P$. | [`lean/SecMeshPQSI/FiniteKey.lean`](lean/SecMeshPQSI/FiniteKey.lean) |
| **T2 — Combinatorial cores of OTP, XOR combining, Toeplitz hashing and polynomial MACs** | Over Boolean vectors: one-time-pad key uniqueness, XOR-combiner factor uniqueness, a Toeplitz pivot-window bijection; an integer Cauchy–Schwarz inequality; over any `SimpleField`, a nonzero polynomial with at most $d+1$ coefficients has at most $d$ distinct roots. | Perfect secrecy, 2-universality as a collision probability, the leftover hash lemma and the $d/2^{128}$ forgery bound are not formalized. Textbook sources: Shannon (1949), Wegman and Carter (1981). The only `SimpleField` instance in the repository is `Fin 5`. | [`lean/SecMeshPQSI/InfoTheoretic.lean`](lean/SecMeshPQSI/InfoTheoretic.lean) |
| **T3 — Shamir sharing, Reed–Solomon decoding, PIR rate arithmetic** | Over any `SimpleField`: $t$ points determine $f(0)$; $t-1$ shares are consistent with every secret; $f(0)$ is uniquely decodable when $n \ge t + 2b$; the arithmetic $d = 2b$ at $n = t+2b-1$; $K+T+2B \le N \iff 0 < N-(K+T+2B-1)$ and $E^2 = (E-T)(E+T) + T^2$. | No counterexample is built for "tightness". No PIR scheme is formalized: the $T^2 > 0$ numerator gap compares two published $K = 1$ rate formulas (Banawan and Ulukus 2019; Tajeddine et al., arXiv:1806.08006, who already note that their $K=1$ scheme is asymptotically capacity-achieving). This is not progress on Mega Atlas `CS-053`. | [`lean/SecMeshPQSI/ThresholdPIR.lean`](lean/SecMeshPQSI/ThresholdPIR.lean) |
| **T4 — Polynomial identities for a two-qubit family; gross-code checks** | Cauchy–Schwarz-type bounds for sums over Gaussian-integer vectors (`t4a`); a scaled polynomial identity (`t4b`); for the two explicit $72\times 144$ Boolean matrices in the repository, all $5{,}184$ entries of $H_X H_Z^{\mathsf T}$ over GF(2) are 0 and every row has weight 6 (`t4c2`); $(c_a^2-s_a^2)^2 + (2c_as_a)^2 = (c_a^2+s_a^2)^2$ (`t4d`); an integer threshold equivalence (`t4e`). | The quantum geometric tensor, Berry curvature, concurrence, min-entropy and QFI readings are paper-level. `t4d`, read as $c_{\mathrm{eff}}^2 + \mathcal{C}^2 = 1$, coincides with the complementarity relation $C^2 + S_k^2 = 1$ of Jakob and Bergou (arXiv:quant-ph/0302075, Eq. 11); the geometric-phase reading relates to Sjöqvist (Phys. Rev. A 62, 022109, 2000). $c_{\mathrm{eff}} = -\cos 2\alpha$ is continuous, so it is not topological or quantized. $H_{\min}^{\mathrm{DI}}(S_{\max}) = 1 - \log_2(1 + \lvert c_{\mathrm{eff}}\rvert)$ is paper-level and numerical. Novelty of the `t4b` identity was not searched. $k = 12$ comes from GF(2) rank in C11/Python, and distance 12 is quoted from Bravyi et al. (2024). The exported `t4c1` assumes its conclusion. | [`lean/SecMeshPQSI/QuantumGeometry.lean`](lean/SecMeshPQSI/QuantumGeometry.lean) |
| **T5 — ML-KEM parameter arithmetic and a Compress_1 margin; $K_N$ arithmetic** | 3329 is prime and 17 has multiplicative order 256 modulo 3329; signed Montgomery reduction is exact for $\lvert a\rvert < 2^{15}\cdot 3329$; for $b \in \{0,1\}$ and $\lvert e\rvert \le 831$ the Lean function `mlkemCompress1` maps $b\cdot 1665 + e$ to $b$; complete-graph edge count, a floor-division node ceiling, and hedge-overhead arithmetic (`+112 B`, `< 1.75%`). | `mlkemCompress1` uses offset 1665, while FIPS 203 rounding and the vendored C (`MLKEM_Q/2 = 1664`) use 1664; they differ only at $x = 832$. The margin statement never reaches 832 and also holds for FIPS 203. The companion claim that $b = 0$ also fails at $e = +832$ is false for FIPS 203 (see [`ERRATA.md`](ERRATA.md)). The margin is the standard Kyber/ML-KEM correctness condition; earlier machine-checked work includes Kreuzer (IACR ePrint 2023/087, Isabelle) and Almeida et al. ("Formally verifying Kyber"). | [`lean/SecMeshPQSI/LatticeBandwidth.lean`](lean/SecMeshPQSI/LatticeBandwidth.lean) |
| **T6 — Laplacian/Ising quadratic forms; Boolean facts for cryptosymbology** | A discrete Laplacian quadratic form is nonnegative and equals the Ising cut energy; a contagion work bound $W_{\min}(k) \ge 2k(J_{\min}\phi_0 + h_{\min})$ obtained by adding two assumed bounds; Boolean/XOR counting facts (`t6b`). | No Cheeger inequality is proved. The Simmons subliminal-channel and kleptography readings are paper-level. | [`lean/SecMeshPQSI/SpinDefenseCryptosymbology.lean`](lean/SecMeshPQSI/SpinDefenseCryptosymbology.lean) |
| **T7 — Cauchy–Schwarz step, TV/overlap identity, classical Fuchs–van de Graaf bounds** | `t7a`: for integers with $c^2+s^2=R^2$, $x_1^2+y_1^2 \le R^2$, $x_2^2+y_2^2 \le R^2$: $(2(cx_1+sx_2))^2 + (2(cy_2+sy_1))^2 \le 8R^4$, plus rearrangements of an assumed relation $c_{AB}^2 + c_{AE}^2 + \tau + r_A^2 = R^2$. `t7b`: for finite distributions with equal totals $D$, $\sum\lvert P_0-P_1\rvert + 2\sum\min(P_0,P_1) = 2D$ (TV + overlap = 1) with three corollaries. `t7c`: for square-integer weights, overlap $\le B \le M$, $2M \le \mathrm{TV}_2 + 2B$, $\mathrm{TV}_2^2 + 4B^2 \le 4M^2$, and $\lvert\langle u,v\rangle\rvert^2 \le M^2$ for complex integer vectors. | `t7a` is only the final Cauchy–Schwarz step of the CHSH monogamy bound $S_{AB}^2 + S_{AE}^2 \le 8$ of Toner and Verstraete (arXiv:quant-ph/0611001, Theorem 1); the qubit/anticommutation reduction is assumed and the CKW-type relation is a hypothesis. Toner (2009, Proc. R. Soc. A 465, 59) proves the linear bound $\lvert B_{AB}\rvert + \lvert B_{AC}\rvert \le 4$. `t7b`: no commitment protocol is formalized; the bit-commitment no-go (Mayers 1997; Lo and Chau 1997) is cited, not proved. `t7c` is the classical case of Fuchs and van de Graaf (1999); the pure-state relation $D_{\mathrm{tr}}^2 + F = 1$ holds by the Lean definition of $D_{\mathrm{tr}}^2$; no EFI pair or computational indistinguishability is formalized. | [`lean/SecMeshPQSI/MonogamyCommitmentNoGo.lean`](lean/SecMeshPQSI/MonogamyCommitmentNoGo.lean) |
| **C11 + Node 25 + Eshkol AD Engine** | **64/64** C11 Moonlab tests (`-Wall -Wextra -Werror`, ASan/UBSan + 500/500 fuzz, `__int128` Ising overflow guard, Shamir stack zeroization, strict CLI parser), **19/19** Node 25 tests (bit-exact C11 ↔ OpenSSL 3.5.5 ML-KEM-768, strict 16-byte AES-256-GCM tag guard, canonical CW-128, Guardian v2 RFC-6479 + HTTP 405/CSP, parse/eval-depth-capped execution of all **5** Eshkol v1.3.6 AD modules to `<1e-12`, schema-verified Rosette-Wire receipts, deterministic seeded Toeplitz), **15/15** pytest (incl. a negative Lean test on the `mlkemCompress1` model, placeholder & manifest/Atlas sync guards), **44/44** HTTP-200 citations (**33/33** Crossref non-retracted DOIs + **1** DataCite DOI), pre-registered 30-seed paired benchmark (`p_Holm = 3.73e-9`). | `differential-tested` and `numerical` (see [`CLAIMS.md`](CLAIMS.md)). The negative Lean test rejects `mlkemCompress1 832 = 0`, which is false for the Lean model but true for FIPS 203 Compress_1. | [`native/`](native/), [`node/`](node/), [`eshkol/`](eshkol/), [`python/`](python/) |

---

## Quickstart

```bash
# 1. Build & test the native C11 Moonlab cryptographic core (64/64 tests)
make -C native test

# 2. Run Node.js 25 differential, ML-KEM interop, anti-replay CW-128 & live Eshkol AD suite (19/19 tests)
node node/tests/test_secmesh_v2.mjs

# 3. Run the interactive quickstart demo & emit a Rosette-Wire audit bundle
node examples/quickstart_demo.mjs
node node/src/secmesh-cli.mjs audit

# 4. Verify all 28 Lean 4.35.0 theorems & strict axiom allowlist + README drift check
cd lean && lake build && lake env lean VerifyAxioms.lean
cd .. && python scripts/check_readme_axioms.py

# 5. Run exact Python verification, pytest (15/15), ruff, mypy & citation+retraction check (44/44)
python python/secmesh_verify/exact_audit.py
pytest python/tests/test_all.py -v
python scripts/check_citations.py
```

Full step-by-step replication instructions live in [`REPLICATION.md`](REPLICATION.md).

---

## Usage & Examples

```bash
# Run live lattice-hedged PQSI handshake + C11 QGTL/BB144/ML-KEM demo
node examples/quickstart_demo.mjs

# Invoke the native C11 Moonlab JSON CLI directly
./native/build/secmesh_core mlkem-kat
./native/build/secmesh_core finite-key 2.82842712474619 450000 0.0 1e-6 1
./native/build/secmesh_core qgt 1.0471975511965976 0.7853981633974483 0.7853981633974483
./native/build/secmesh_core chern-law 0.39269908169872414 8
./native/build/secmesh_core ising-barrier 60 10 1.0 2.0 0.7
./native/build/secmesh_core bb144
./native/build/secmesh_core bandwidth 100000000 1.0
```

See [`examples/README.md`](examples/README.md), [`app/index.html`](app/index.html), and [`app/blueprint.html`](app/blueprint.html) for interactive usage.

---

## Honest Scope & Non-Claims

Read [`LIMITATIONS.md`](LIMITATIONS.md) and [`CLAIMS.md`](CLAIMS.md) in full before citing or deploying:
- **Software E91 is a mathematical finite-key simulator, NOT physical photonic QKD.** Physical device-independent randomness requires loophole-free Bell-test hardware.
- **Unconditional PSI confidentiality requires an independent physical QRNG or pre-shared OTP pad.** Without one (`SECMESH_IT_PAD_FILE`), confidentiality relies on hybrid `X25519 + ML-KEM-768`.
- **Open hardness conjectures remain open.** We do not claim to solve $\mathrm{P}\neq\mathrm{NP}$ (`CS-002`), MLWE reduction tightness (`CS-026`), or general coded/Byzantine PIR capacity (`CS-053`). The 15 Mega Atlas problems listed in `CLAIMS.md` (C14) are topically related only; no result here is a bounded case of any of them.
- **Physical and protocol readings are not formalized.** Lean defines no quantum state, operator, entropy, Fisher information, Chern number, probability distribution type, PIR scheme, commitment scheme or EFI pair. Theorem names such as "Toner CHSH monogamy", "Chern–Concurrence–Entropy Conservation", "Hiding–Binding Conservation No-Go" and "Microcrypt EFI" describe the paper-level reading, not the Lean statement.
- **The Lean `Compress_1` model differs from FIPS 203 at $x = 832$.** See [`ERRATA.md`](ERRATA.md) (2026-11-26 statement audit) for this and the other known issues in the frozen paper and the formal code.
- **Preprint & research status:** Both white papers are self-assessed research preprints with machine-checked Lean statements; neither has undergone external journal peer review, and `secmesh-pqsi` is not a FIPS 140-3 certified HSM.
- **Windows `lean4lean.exe` & local `eshkol-run.exe` notes:** On Windows, bundled `lean4lean.exe` emits an `.olean` `incompatible header` error, while Ubuntu Linux CI runs the 6 comparator kernel runs (5 distinct implementations, including `lean4lean`) via `lake comparator --paranoid`. All **5** Eshkol `.esk` modules are executed by our portable forward-mode dual-number AD runtime (`node/src/eshkol-ad-runtime.mjs`), not by the native Eshkol compiler.

---

## Documentation & Governance

- **Tsotchke Complete 27-Repo Audit:** [`docs/tsotchke-stack-map.md`](docs/tsotchke-stack-map.md) · **Third-Party Notices:** [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
- **Threat Model:** [`docs/threat-model.md`](docs/threat-model.md) · **Literature Log:** [`docs/literature-search-log.md`](docs/literature-search-log.md) · **Export Self-Screen:** [`docs/export-control-self-screen.md`](docs/export-control-self-screen.md)
- **Architecture:** [`docs/architecture.md`](docs/architecture.md) · **ADRs:** [`docs/adr/README.md`](docs/adr/README.md) · **Errata:** [`ERRATA.md`](ERRATA.md) · **Statement audit (2026-11-26):** [audit log](https://github.com/0thernes/0thernes-research-archive/blob/main/docs/reviews/2026-11-26-statement-audit.md)
- **Hardening Log (11 Cycles):** [`HARDENING_LOG.md`](HARDENING_LOG.md) · **Complete Repo Index:** [`INDEX.md`](INDEX.md)
- **Checksums:** [`MANIFEST.sha256`](MANIFEST.sha256) · **Citation:** [`CITATION.cff`](CITATION.cff) · **Licensing:** [`LICENSE`](LICENSE) (Apache-2.0), [`LICENSE-DOCS`](LICENSE-DOCS) (CC-BY-4.0), [`REUSE.toml`](REUSE.toml)
