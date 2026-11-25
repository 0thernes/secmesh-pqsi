<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Roadmap (`ROADMAP.md`)

## Released (`v1.0.0` – `v2.0.0`)
- **`v1.0.0` / `v1.0.1`:** Clean-room C11 + Node.js 25 + Eshkol + Lean 4.35.0 rebuild resolving all 10 legacy SecMesh defects, 21 zero-Mathlib theorems passing all 6 kernels under `lake comparator --paranoid` on Ubuntu CI, two AMS-LaTeX white papers, standalone arXiv tarball, and full Build Standard v1.2.0 packaging.
- **`v2.0.0`:** Expanded to **25 zero-Mathlib Lean 4.35.0 theorems (`T1a`–`T6b`)** adding Topological Chern–Concurrence–Entropy Conservation (`T4d`), `libirrep` Spin-$j$ GHZ Heisenberg QFI (`T4e`), Ising Laplacian PSD & Cheeger Expander Barrier (`T6a`), and Simmons Cryptosymbology / Threshold-Hedged Dual Closure (`T6b`); built live executable forward-mode dual-number Eshkol AD runtime; fixed C11 NULL/thread-safety/overflow hardening and Guardian v2 CW-128 per-frame anti-replay; launched Interactive Lean Proof Blueprint DAG (`app/blueprint.html`); completed verbatim Mega Atlas v2 ID audit and full 27-repo Tsotchke audit.

## Planned Future Milestones (`v2.1.x`+)
1. **Real-Analytic EAT/GEAT Formalization (`QC-021`):** Explore finite-key Entropy Accumulation Theorem (EAT) and Generalized EAT bounds for non-i.i.d. coherent attacks below $N < 10^5$ rounds.
2. **Hardware QRNG Driver Integration:** Add optional pluggable adapter for physical certified QRNG endpoints (e.g., `Tsotchke-Corporation/Quantum-RNG-API` or local USB QRNG hardware) feeding the `SECMESH_IT_PAD_FILE` PSI lane.
3. **Native Eshkol LLVM Linux CI Target:** Compile and benchmark `eshkol/*.esk` natively in CI alongside our portable `eshkol-ad-runtime.mjs` once prebuilt Linux Eshkol packages ship.
4. **Mixed-State Multipartite QGT Monotones (`QC-018` / `QC-030`):** Extend Theorems `T4b`, `T4d`, and `T4e` to noisy/mixed Werner and dephased GHZ states using Bures metric and quantum Fisher information bounds.
5. **External Archival & Registry Deposits:** Submit frozen `v2.0.0` release to Palomar Registry (`submit.palomar-registry.org`), Software Heritage Save Code Now, and arXiv (`cs.CR` / `quant-ph`) upon endorsement.
