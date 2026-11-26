# Limitations, Threats to Validity, and Honest Boundaries (`LIMITATIONS.md`)

This document states explicitly what `secmesh-pqsi` does **not** prove, claim, or guarantee.

## 1. Cryptographic & Physical Security Boundaries

1. **Software E91 is a mathematical simulator, NOT physical photonic QKD:**
   Simulating CHSH correlations over classical TCP/localhost validates finite-key admission formulas, adversarial rejection paths (Classical, Aligned, Parked Eve), and key-rate accounting. It does **not** generate physically certified device-independent randomness; physical DI-QKD/QRNG requires loophole-free photonic/atomic Bell-test hardware closing detection, locality, and freedom-of-choice loopholes.
2. **Post-Super-Intelligence (PSI) secrecy requires an independent physical or pre-shared pad:**
   Theorems `T2a` and `T2b` prove unconditional secrecy against computationally unbounded adversaries **if and only if** the information-theoretic key factor $K_{\mathrm{IT}}$ is statistically uniform and independent of adversary knowledge (e.g., from a certified physical QRNG or physically distributed one-time pad). When operated without an external pad, confidentiality rests strictly on the strongest surviving computational primitive (`ML-KEM-768` or `X25519`), and the system never misrepresents computational keys as information-theoretic.
3. **One-time pad discipline for Carter–Wegman $\mathbb{F}_{2^{128}}$ IT-MAC:**
   Theorem `T2d` ($\le d/2^{128}$ forgery bound) assumes a fresh one-time pad mask $s$ per authenticated frame. `secmesh-pqsi v2.4.0` enforces monotonic 64-bit sequence numbers and an RFC-6479-style bounded sliding replay window (`createReplayWindow` / `verifyCwFrame`) across all Guardian v2 frames; when operated with a pre-shared pad pool (`padPool`), each frame consumes a single-use IT pad (unconditional PSI mode), whereas `padSeed` mode derives per-frame pads via `SHAKE256` (computational Wegman–Carter mode, explicitly distinguished from unconditional PSI).
4. **No hardware side-channel or FIPS 140-3 certification:**
   While constant-time comparison (`secmesh_ct_memeq`) and zeroization (`secmesh_secure_zero`) are implemented in C11, Lean 4 verifies mathematical specifications rather than compiled assembly timing, cache, power, or EM leakage on specific microarchitectures. `secmesh-pqsi` is a research reference implementation, not a FIPS 140-3 validated module.
5. **Simulated mesh defense telemetry vs. live network pentesting:**
   The pre-registered 30-seed paired benchmark (`results/exact_verification_report.json`) evaluates deterministic health-field controller dynamics under synthetic intrusion injection. It is **not** a substitute for live adversarial penetration testing on production network infrastructure.

## 2. Formal Verification & Tooling Boundaries

1. **Zero-Mathlib algebraic boundary:**
   To eliminate Mathlib from the Lean 4.35.0 trusted computing base, transcendental curves (Hoeffding exponential, binary entropy $h(p)$, Bernoulli KL inversion, and trigonometric $\cos/\sin$) are formalized via cleared-denominator integer/rational identities (`T1a`, `T1b`, `T1c`, `T4b`) and cross-verified to 60-digit `Decimal` precision in Python and differentially against C11 and Node.js 25 (`< 1e-11`).
2. **Platform split for Lean 4.35 `lean4lean` & `lake comparator` (`problem`):**
   On Windows hosts, the bundled `lean4lean.exe` in `leanprover--lean4---v4.35.0` fails with `incompatible header` and `lake comparator` requires Linux `bwrap` namespaces. Accordingly, Windows local verification runs **5 distinct kernel implementations** (`lean`, `leanchecker`, `leanchecker-paranoid`, `con-leche --verified`, `con-ron --verified`, `nanoda_bin 0.4.19`), while Ubuntu Linux GitHub Actions CI executes `lake comparator --config palomar_comparator.json --paranoid` verifying **all 6 distinct kernels** (including `lean4lean`).
3. **Eshkol v1.3.6 native LLVM binary vs. portable dual-number AD runtime (`problem`):**
   While a Windows `eshkol-run.exe` binary exists on this workstation (`Z:\Tools\eshkol\current\bin`), it exited with `0xC0000135` (`STATUS_DLL_NOT_FOUND`) due to missing runtime DLLs. Rather than leaving the 5 Eshkol modules unexecuted, `secmesh-pqsi v2.4.0` ships a portable, zero-dependency forward-mode dual-number AD & OALR `(with-region ...)` evaluator (`node/src/eshkol-ad-runtime.mjs`) with step/recursion-depth DoS caps that parses and executes all five `eshkol/*.esk` modules live and verifies every AD derivative to `< 1e-12` against closed-form calculus. This portable evaluator is transparently labeled as a reference AD interpreter rather than Tsotchke's native LLVM AOT compiler.

## 3. Open Conjectures & Peer Review Status

1. **No false claims on open hardness problems:**
   We do not solve `P != NP` / one-way function existence (`CS-002`), worst-to-average MLWE reduction tightness (`CS-026`), long-term non-lattice PQ hardness (`CS-028`), standard-model Fiat–Shamir soundness (`CS-030`), general coded/Byzantine PIR capacity (`CS-053`), or real-time full-distance fault-tolerant qLDPC decoding (`QC-004`).
2. **Peer review status:**
   Both companion white papers are self-assessed research preprints backed by multi-kernel machine-checked proofs and open code. They have **not** undergone external journal or conference peer review, and no external DOI or arXiv identifier is claimed prior to confirmed external assignment.

## 4. Resolved Affiliation & Entity Naming Conflict (`conflict`)

An early prompt and personal workspace note referenced `0thernes LLC`. Following the Defensible Independent AI Research Playbook v1.3 (Nov 2026) and confirming that no legal LLC entity has been formally incorporated, all manuscripts, `CITATION.cff`, `formalization.yaml`, `LICENSE`, `REUSE.toml`, and archive records in this repository accurately attribute sole authorship and copyright to **Alexander S. Donahue** (`Independent Researcher, Spokane, WA, USA`, ORCID `0009-0006-8168-9648`, GitHub account `https://github.com/0thernes`). This resolution is recorded transparently in `HARDENING_LOG.md`.
