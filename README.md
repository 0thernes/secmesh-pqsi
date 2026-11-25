<!-- SPDX-License-Identifier: CC-BY-4.0 -->
![SecMesh-PQSI — Post-Quantum & Post-Super-Intelligence Mesh Cryptography](docs/media/social-preview.svg)

# SecMesh-PQSI

<p align="center">
  <strong>Post-Quantum (PQ) &amp; Post-Super-Intelligence (Information-Theoretic PSI) Cryptographic Mesh Defense Engine</strong><br/>
  <em>27 Zero-Mathlib Lean 4.35.0 Theorems · All 6 Independent Proof Kernels · C11 Moonlab ↔ OpenSSL 3.5.5 FIPS 203 Interop · Live Eshkol AD · 2 AMS-LaTeX White Papers</em>
</p>

<p align="center">
  <a href="https://github.com/0thernes/secmesh-pqsi/actions/workflows/ci.yml"><img src="https://github.com/0thernes/secmesh-pqsi/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/code-Apache--2.0-blue.svg" alt="Code License: Apache-2.0" /></a>
  <a href="LICENSE-DOCS"><img src="https://img.shields.io/badge/docs%20%26%20papers-CC--BY--4.0-lightgrey.svg" alt="Docs License: CC-BY-4.0" /></a>
  <a href="lean/lean-toolchain"><img src="https://img.shields.io/badge/Lean-4.35.0%20(zero--Mathlib)-purple.svg" alt="Lean 4.35.0" /></a>
  <a href="results/six_kernel_audit.txt"><img src="https://img.shields.io/badge/proof%20kernels-6%20%2F%206%20Palomar-brightgreen.svg" alt="All 6 Distinct Proof Kernels" /></a>
  <a href="https://0thernes.github.io/secmesh-pqsi/"><img src="https://img.shields.io/badge/console-GitHub%20Pages-teal.svg" alt="Interactive Defense Console" /></a>
  <a href="https://0thernes.github.io/secmesh-pqsi/blueprint.html"><img src="https://img.shields.io/badge/blueprint-Lean%20DAG-indigo.svg" alt="Interactive Proof Blueprint" /></a>
</p>

---

**SecMesh-PQSI** (`v2.2.0`) is a clean-room cryptographic refactoring of [`BoogerCheeseOnRye/SecMesh@aff7dc6`](https://github.com/BoogerCheeseOnRye/SecMesh) rebuilt atop Tsotchke's MIT/Apache-2.0 cryptographic, representation-theoretic, and quantum-geometry stack (`moonlab`, `quantum_geometric_tensor`, `libirrep`, `spin_based_neural_network`, `eshkol`, `rosette-wire`, `pq-consensus-bandwidth`, `quantum_rng`, `classical_rng`; complete live-verified 27-repo audit in [`docs/tsotchke-stack-map.md`](docs/tsotchke-stack-map.md)) into a rigorously audited **Post-Quantum + Post-Super-Intelligence (information-theoretic)** defense architecture.

- **Author:** Alexander S. Donahue ([ORCID `0009-0006-8168-9648`](https://orcid.org/0009-0006-8168-9648), Independent Researcher, Spokane, WA, USA)
- **White Paper I (Formal Foundations):** [PDF (`dist/Donahue_2026_secmesh_pqsi_formal_foundations.pdf`)](dist/Donahue_2026_secmesh_pqsi_formal_foundations.pdf) · [LaTeX](paper/main.tex) · [arXiv Tarball](dist/arxiv_submission.tar.gz)
- **White Paper II (Systems Architecture & Threat Model):** [PDF (`dist/Donahue_2026_secmesh_pqsi_architecture.pdf`)](dist/Donahue_2026_secmesh_pqsi_architecture.pdf) · [LaTeX](paper/engineering/secmesh_architecture.tex)
- **Interactive Defense Console & Proof Blueprint:** [`app/index.html`](app/index.html) · [`app/blueprint.html`](app/blueprint.html) (live on GitHub Pages)

---

## 5-Second Verbatim Kernel Proof (`#print axioms`)

Every one of the **27 formal theorems (`T1a`–`T7b`)** across both `SecMeshPQSI.Solution.*` and standalone Palomar `SecMeshPQSI.Palomar.*` compiles in **zero-Mathlib Lean 4.35.0** with **0 warnings**, **0 proof `sorry`s**, **0 `native_decide`**, and **0 custom axioms**, passing **all 6 distinct Lean 4.35 kernels** (`Lean paranoid`, `lean4lean`, `nanoda`, `con-leche --verified`, `con-ron --verified`, `Lean default`) via `lake comparator --config palomar_comparator.json --paranoid` (verified in CI with automated drift checks via [`scripts/check_readme_axioms.py`](scripts/check_readme_axioms.py)):

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
'SecMeshPQSI.Solution.prove_all_secmesh_theorems' depends on axioms: [propext, Classical.choice, Quot.sound]
'SecMeshPQSI.NonVacuity.nonvac_all_hypotheses' depends on axioms: [propext, Quot.sound]
```
*(All 60 exported lines in [`results/lean_axioms.txt`](results/lean_axioms.txt) — 27 `Solution` + master conjunction + `NonVacuity` + 27 `Palomar` + 4 zero-axiom `AdversarialTests` — lie strictly within `[propext, Classical.choice, Quot.sound]`.)*

---

## Core Results at a Glance

| Pillar | What Is Proved / Verified | Key Artifact |
| --- | --- | --- |
| **T1 — Forensic Audit of Legacy SecMesh v1** | Resolves 10 real defects in `SecMesh@aff7dc6`: super-quantum $S = 354/125 > 2\sqrt{2}$ (`+316`), $4\times$ range-2 Hoeffding error ($0.02857$ vs $2.5{\times}10^{-7}$), quarter-circle duality $u^2+v^2=1$ ($H_{\mathrm{vN}}^{\mathrm{DI}} - H_{\min}^{\mathrm{DI}}$ peak $+0.2357$ bit at $S \approx 2.6992$), $93/256$ biased `deNoise`, and 5-lane composable $\varepsilon$-conservation. | [`lean/SecMeshPQSI/FiniteKey.lean`](lean/SecMeshPQSI/FiniteKey.lean) |
| **T2 — Unconditional PSI Triad** | Shannon OTP bijection, $k$-factor XOR dual-survivability, constructive back-substitution Toeplitz $2$-universality (mirroring Moonlab), integer Cauchy–Schwarz LHL core, and general-field Carter–Wegman degree-$d$ bound ($\le d/2^{128}$ forgery). | [`lean/SecMeshPQSI/InfoTheoretic.lean`](lean/SecMeshPQSI/InfoTheoretic.lean) |
| **T3 — Shamir, Byzantine & CS-053 PIR** | Exact Shamir $(t,n)$ threshold secrecy over any field, Byzantine Singleton tightness $n \ge t + 2b$, and exact $T^2 > 0$ strict gap between Banawan–Ulukus $M=2$ PIR capacity and star-product rates (Mega Atlas `CS-053`). | [`lean/SecMeshPQSI/ThresholdPIR.lean`](lean/SecMeshPQSI/ThresholdPIR.lean) |
| **T4 — QGTL Surplus, Chern–Concurrence Law, GHZ QFI & BB144** | $D$-dim QGT PSD; exact QGT Concurrence Surplus $\det(g) - \frac{1}{4}\Omega^2 = \frac{1}{4}\mathcal{C}^2 \sin^2(\theta/2)$ ($3.3{\times}10^{-60}$ residual); **Topological Chern–Concurrence–Entropy Conservation Law** $c_{\mathrm{eff}}^2 + \mathcal{C}^2 = 1$ ($H_{\min}^{\mathrm{DI}}(S_{\max}) = 1 - \log_2(1 + |c_{\mathrm{eff}}|)$); `libirrep` spin-$j$ GHZ Heisenberg QFI ($N^2\tau_N > N \iff N\tau_N > 1$); Bravyi `[[144,12,12]]` Gross BB qLDPC certification ($5{,}184$ CSS checks, weight 6, $k=12$). | [`lean/SecMeshPQSI/QuantumGeometry.lean`](lean/SecMeshPQSI/QuantumGeometry.lean) |
| **T5 — FIPS 203 ML-KEM & $K_N$ Ceilings** | $q = 3329$ prime & $\zeta = 17$ primitive 256-th NTT root, zero-overflow Montgomery reduction across $|a| < 2^{15}\cdot 3329$, sharp `Compress_1` margin $|e|\le 831$ (tight at $+832$), complete-graph $K_N$ ceiling optimality & `< 1.75%` IT-hedge overhead (`+112 B`). | [`lean/SecMeshPQSI/LatticeBandwidth.lean`](lean/SecMeshPQSI/LatticeBandwidth.lean) |
| **T6 — Ising Expander Barrier & Cryptosymbology** | Discrete Laplacian PSD, exact Ising spin-flip cut bijection, Cheeger expander contagion work barrier $W_{\min}(k) \ge 2k(J_{\min}\phi_0 + h_{\min})$; Simmons deterministic zero-capacity, $2^k$ kleptographic bijection & threshold-hedged XOR dual-closure. | [`lean/SecMeshPQSI/SpinDefenseCryptosymbology.lean`](lean/SecMeshPQSI/SpinDefenseCryptosymbology.lean) |
| **T7 — Toner CHSH Monogamy & Commitment No-Go** | First-principles Toner quantum CHSH monogamy $S_{AB}^2 + S_{AE}^2 \le 8$ (trapping any unbounded eavesdropper below $2$ whenever $S_{AB} > 2$) + CKW Berry-monopole isolation; exact Hiding–Binding Conservation Law $\mathrm{TV}(P_0,P_1)+\mathrm{Overlap}(P_0,P_1)=1$ proving unconditional commitment impossibility and hybrid PQ+PSI necessity. | [`lean/SecMeshPQSI/MonogamyCommitmentNoGo.lean`](lean/SecMeshPQSI/MonogamyCommitmentNoGo.lean) |
| **C11 + Node 25 + Eshkol AD Engine** | **58/58** C11 Moonlab tests (`-Wall -Wextra -Werror`, ASan/UBSan + 500/500 fuzz, Shamir duplicate-$x$/`NaN`/LE64 hardening), **16/16** Node 25 tests (bit-exact C11 ↔ OpenSSL 3.5.5 ML-KEM-768 interop, RFC-6479 bounded sliding-window anti-replay CW-128 Guardian v2, live execution of all 4 Eshkol v1.3.6 AD modules to `<1e-12`, Rosette-Wire receipts), **13/13** pytest (incl. negative Lean kernel rejection), **42/42** HTTP-200 citations (**32/32** DOIs Crossref-verified not retracted), pre-registered 30-seed paired benchmark (`p_Holm = 3.73e-9`, bounded bootstrap 95% CIs). | [`native/`](native/), [`node/`](node/), [`eshkol/`](eshkol/), [`python/`](python/) |

---

## Quickstart

```bash
# 1. Build & test the native C11 Moonlab cryptographic core (58/58 tests)
make -C native test

# 2. Run Node.js 25 differential, ML-KEM interop, anti-replay CW-128 & live Eshkol AD suite (16/16 tests)
node node/tests/test_secmesh_v2.mjs

# 3. Run the interactive quickstart demo & emit a Rosette-Wire audit bundle
node examples/quickstart_demo.mjs
node node/src/secmesh-cli.mjs audit

# 4. Verify all 27 Lean 4.35.0 theorems & strict axiom allowlist + README drift check
cd lean && lake build && lake env lean VerifyAxioms.lean
cd .. && python scripts/check_readme_axioms.py

# 5. Run exact Python verification, pytest (13/13), ruff, mypy & citation+retraction check (42/42)
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
- **Open hardness conjectures remain open.** We do not claim to solve $\mathrm{P}\neq\mathrm{NP}$ (`CS-002`), MLWE reduction tightness (`CS-026`), or general coded/Byzantine PIR capacity (`CS-053`).
- **Preprint & research status:** Both white papers are self-assessed research preprints backed by six-kernel machine-checked proofs; neither has undergone external journal peer review, and `secmesh-pqsi` is not a FIPS 140-3 certified HSM.
- **Windows `lean4lean.exe` & local `eshkol-run.exe` notes:** On Windows, bundled `lean4lean.exe` emits an `.olean` `incompatible header` error while Ubuntu Linux CI verifies **all 6 kernels** via `lake comparator --paranoid`. All 4 Eshkol `.esk` modules are executed live by our portable forward-mode dual-number AD runtime (`node/src/eshkol-ad-runtime.mjs`).

---

## Documentation & Governance

- **Tsotchke Complete 27-Repo Audit:** [`docs/tsotchke-stack-map.md`](docs/tsotchke-stack-map.md) · **Third-Party Notices:** [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
- **Threat Model:** [`docs/threat-model.md`](docs/threat-model.md) · **Literature Log:** [`docs/literature-search-log.md`](docs/literature-search-log.md) · **Export Self-Screen:** [`docs/export-control-self-screen.md`](docs/export-control-self-screen.md)
- **Architecture:** [`docs/architecture.md`](docs/architecture.md) · **ADRs:** [`docs/adr/README.md`](docs/adr/README.md) · **Errata:** [`ERRATA.md`](ERRATA.md)
- **Hardening Log (6 Full Cycles):** [`HARDENING_LOG.md`](HARDENING_LOG.md) · **Complete Repo Index:** [`INDEX.md`](INDEX.md)
- **Checksums:** [`MANIFEST.sha256`](MANIFEST.sha256) · **Citation:** [`CITATION.cff`](CITATION.cff) · **Licensing:** [`LICENSE`](LICENSE) (Apache-2.0), [`LICENSE-DOCS`](LICENSE-DOCS) (CC-BY-4.0), [`REUSE.toml`](REUSE.toml)
