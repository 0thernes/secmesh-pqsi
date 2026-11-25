# Roadmap (`ROADMAP.md`)

## Released (`v1.0.0`)
- Clean-room C11 + Node.js 25 + Eshkol + Lean 4.35.0 rebuild resolving all 10 legacy SecMesh defects.
- 21 zero-Mathlib Lean 4.35 theorems replayed across 5 distinct kernel implementations.
- Two compiled AMS-LaTeX white papers, standalone arXiv tarball, and full Build Standard v1.2.0 repository packaging.

## Planned Next Milestones (`v1.1.x` – `v2.0.0`)
1. **Linux CI `lake comparator --paranoid` + `lean4lean` verification:** Confirm full sandboxed Palomar comparator and Linux `lean4lean` replay in GitHub Actions Ubuntu runners.
2. **Real-Analytic EAT/GEAT Formalization (`QC-021`):** Explore finite-key Entropy Accumulation Theorem (EAT) and Generalized EAT bounds for non-i.i.d. coherent attacks below $N < 10^5$ rounds.
3. **Hardware QRNG Driver Integration:** Add optional pluggable adapter for physical certified QRNG endpoints (e.g., `Tsotchke-Corporation/Quantum-RNG-API` or local USB QRNG hardware) feeding the `SECMESH_IT_PAD_FILE` PSI lane.
4. **Native Eshkol LLVM Execution Target:** Compile and benchmark `eshkol/*.esk` natively in CI once prebuilt Eshkol v1.3.6 Linux releases are packaged.
5. **Multipartite QGT Entanglement Witness (`QC-042`):** Extend Theorem `T4b` ($\det(g) - \frac{1}{4}\Omega^2 = \frac{1}{4}\mathcal{C}^2 \sin^2(\theta/2)$) toward 3-qubit GHZ/W tangle and mixed-state Bures/QFI bounds.
6. **External Archival Deposits:** Submit frozen `v1.0.0` release to Zenodo, arXiv (`cs.CR` / `quant-ph`), and Palomar Registry after external endorsement/review.
