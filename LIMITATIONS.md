# Limitations, Threats to Validity, and Honest Boundaries (`LIMITATIONS.md`)

This document states explicitly what `secmesh-pqsi` does **not** prove, claim, or guarantee.

## 1. Cryptographic & Physical Security Boundaries

1. **Software E91 is a mathematical simulator, NOT physical photonic QKD:**
   Simulating CHSH correlations over classical TCP/localhost validates finite-key admission formulas, adversarial rejection paths (Classical, Aligned, Parked Eve), and key-rate accounting. It does **not** generate physically certified device-independent randomness; physical DI-QKD/QRNG requires loophole-free photonic/atomic Bell-test hardware closing detection, locality, and freedom-of-choice loopholes.
2. **Post-Super-Intelligence (PSI) secrecy requires an independent physical or pre-shared pad:**
   Theorems `T2a` and `T2b` prove unconditional secrecy against computationally unbounded adversaries **if and only if** the information-theoretic key factor $K_{\mathrm{IT}}$ is statistically uniform and independent of adversary knowledge (e.g., from a certified physical QRNG or physically distributed one-time pad). When operated without an external pad, confidentiality rests strictly on the strongest surviving computational primitive (`ML-KEM-768` or `X25519`), and the system never misrepresents computational keys as information-theoretic.
3. **One-time pad discipline for Carter–Wegman $\mathbb{F}_{2^{128}}$ IT-MAC:**
   Theorem `T2d` ($\le d/2^{128}$ forgery bound) assumes a fresh one-time pad mask $s$ per authenticated frame. Reusing $(r, s)$ across two distinct frames allows an adversary to recover $r$ algebraically.
4. **No hardware side-channel or FIPS 140-3 certification:**
   While constant-time comparison (`secmesh_ct_memeq`) and zeroization (`secmesh_secure_zero`) are implemented in C11, Lean 4 verifies mathematical specifications rather than compiled assembly timing, cache, power, or EM leakage on specific microarchitectures. `secmesh-pqsi` is a research reference implementation, not a FIPS 140-3 validated module.
5. **Simulated mesh defense telemetry vs. live network pentesting:**
   The pre-registered 30-seed paired benchmark (`results/exact_verification_report.json`) evaluates deterministic health-field controller dynamics under synthetic intrusion injection. It is **not** a substitute for live adversarial penetration testing on production network infrastructure.

## 2. Formal Verification & Tooling Boundaries

1. **Zero-Mathlib algebraic boundary:**
   To eliminate Mathlib from the Lean 4.35.0 trusted computing base, transcendental curves (Hoeffding exponential, binary entropy $h(p)$, Bernoulli KL inversion, and trigonometric $\cos/\sin$) are formalized via cleared-denominator integer/rational identities (`T1a`, `T1b`, `T1c`, `T4b`) and cross-verified to 60-digit `Decimal` precision in Python and differentially against C11 and Node.js 25 (`< 1e-11`).
2. **Upstream Windows `lean4lean.exe` limitation (`problem`):**
   The bundled `lean4lean.exe` in the Windows `leanprover--lean4---v4.35.0` toolchain failed locally with `incompatible header` when reading valid `.olean` files. Accordingly, `lean4lean` is **excluded** from our reported count of 5 completed local kernel implementations (`lean`, `leanchecker`, `leanchecker-paranoid`, `con-leche --verified`, `con-ron --verified`, `nanoda_bin 0.4.19`).
3. **Linux namespace requirement for `lake comparator` (`problem`):**
   Lean 4.35's `lake comparator --config palomar_comparator.json --paranoid` requires POSIX `bwrap` namespaces unavailable natively on Windows and is executed in Linux (`ubuntu-latest`) CI (`.github/workflows/ci.yml`).
4. **Eshkol v1.3.6 compiler availability:**
   The three Eshkol AD modules (`eshkol/*.esk`) are verified for balanced S-expression syntax and cross-checked mathematically against Python/C11 gradients, as the native LLVM `eshkol` compiler binary is not pre-installed on this Windows host.

## 3. Open Conjectures & Peer Review Status

1. **No false claims on open hardness problems:**
   We do not solve `P != NP`, worst-to-average MLWE reduction tightness (`CS-026`), QROM Fiat–Shamir tightness (`CS-028`), general coded/Byzantine PIR capacity (`CS-053`), or linear-time full-distance qLDPC decoding (`QC-034`).
2. **Peer review status:**
   Both companion white papers are self-assessed research preprints backed by multi-kernel machine-checked proofs and open code. They have **not** undergone external journal or conference peer review, and no external DOI or arXiv identifier is claimed prior to confirmed external assignment.

## 4. Resolved Affiliation & Entity Naming Conflict (`conflict`)

An early prompt and personal workspace note referenced `0thernes LLC`. Following the Defensible Independent AI Research Playbook v1.3 (Nov 2026) and confirming that no legal LLC entity has been formally incorporated, all manuscripts, `CITATION.cff`, `formalization.yaml`, `LICENSE`, `REUSE.toml`, and archive records in this repository accurately attribute sole authorship and copyright to **Alexander S. Donahue** (`Independent Researcher, Spokane, WA, USA`, ORCID `0009-0006-8168-9648`, GitHub account `https://github.com/0thernes`). This resolution is recorded transparently in `HARDENING_LOG.md`.
