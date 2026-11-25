<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AGENTS.md — Canonical Agent Instructions for `secmesh-pqsi`

This file is the single canonical instruction set for all coding and research agents working on `secmesh-pqsi`. `CLAUDE.md`, `GEMINI.md`, and `.cursor/rules/build-standard.mdc` delegate here.

## 1. Repository Purpose & Integrity Rules

`secmesh-pqsi` is a clean-room cryptographic refactoring of `BoogerCheeseOnRye/SecMesh@aff7dc6` rebuilt atop Tsotchke's MIT/Apache-2.0 stack (`moonlab`, `quantum_geometric_tensor`, `eshkol`, `rosette-wire`, `pq-consensus-bandwidth`) into a Post-Quantum (PQ) and Post-Super-Intelligence (PSI = information-theoretic) mesh defense engine, backed by **21 zero-Mathlib Lean 4.35.0 theorems** verified across **5 distinct kernel implementations** (6 runs) and **two companion AMS-LaTeX white papers**.

### Non-Negotiable Integrity Boundaries
- **Zero fabrication / zero sycophancy:** Every reported theorem, test count, byte count, latency, and hash MUST come from an actual run of current files in this repo.
- **Honest cryptographic scope:** Software E91/CHSH over TCP is a mathematical simulator — NEVER claim physical photonic loophole-free QKD. Unconditional PSI confidentiality requires an independent physical/pre-shared pad; without one, confidentiality reduces to the strongest surviving computational primitive (`ML-KEM-768` / `X25519`).
- **Lean 4.35.0 TCB:** Zero Mathlib, zero `sorry` (except standalone `lean/PalomarChallenge.lean` contract stubs, never imported by proofs), zero `admit`, zero `native_decide`, zero custom `axiom`, zero `implemented_by`, zero `@[extern`. Every theorem's `#print axioms` must lie strictly inside `[propext, Classical.choice, Quot.sound]`.
- **Author & Licensing:** Author `Alexander S. Donahue` (`Independent Researcher, Spokane, WA, USA`, ORCID `0009-0006-8168-9648`, `0_0@0thernes.art`). Code is `Apache-2.0`, vendored Moonlab C11 is `MIT`, manuscripts and docs are `CC-BY-4.0`. Never list an AI as an author.

## 2. Build Standard v1.2.0 Hard Rules (`R1–R8`)

- **R1:** No gating/blocking git hooks; all local checks are opt-in.
- **R2:** Work, commit, and push straight to `main` (no PR ceremony, no branch protection).
- **R3:** CI workflows are informational (report-only, never blocking pushes).
- **R4:** Never add banned files or bots (no Dependabot, Renovate, PR templates, CodeRabbit, `.github/copilot-instructions.md`, `FUNDING.yml`).
- **R5:** Unsigned plain commits and annotated tags (`vX.Y.Z`).
- **R6:** Classify every audit finding into exactly one of the 10 classes: `bug`, `error`, `issue`, `problem`, `concern`, `dilemma`, `conflict`, `gap`, `hole`, `blindspot`.
- **R7:** On Windows paths containing `[...]`, ALWAYS pass `-LiteralPath` in PowerShell file cmdlets.
- **R8:** Keep `repo.yaml` honest and synced with `scripts/Audit-Repo.ps1` / `scripts/audit-repo.sh`.

## 3. Repository Layout

- `native/`: C11 Moonlab cryptographic core (`third_party/moonlab/`, `include/`, `src/`, `tests/test_native_core.c`, `Makefile`).
- `node/`: Node.js 25 / OpenSSL 3.5.5 hybrid PQ+PSI handshake, Finite-Key v2, Hardened Guardian v2, Rosette-Wire receipts, CLI, and 12-test differential suite.
- `eshkol/`: Three Eshkol v1.3.6 automatic differentiation modules (`finite_key_ad.esk`, `qgt_geodesic.esk`, `bandwidth_opt.esk`).
- `lean/`: Zero-Mathlib Lean 4.35.0 proofs (`SecMeshPQSI/*.lean`, `Challenge.lean`, `Solution.lean`, `PalomarChallenge.lean`, `PalomarSolution.lean`, `VerifyAxioms.lean`, `formalization.yaml`, `palomar_comparator.json`).
- `python/`: Exact-arithmetic audit (`secmesh_verify/exact_audit.py`), vector figure generator (`make_figures.py`), and `tests/test_all.py`.
- `paper/`: AMS-LaTeX White Paper I (`main.tex`), White Paper II (`engineering/secmesh_architecture.tex`), verified bibliography (`refs.bib`), and vector figures (`figures/*.pdf`).
- `dist/`: Frozen release PDFs (`Donahue_2026_secmesh_pqsi_formal_foundations.pdf`, `Donahue_2026_secmesh_pqsi_architecture.pdf`) and standalone `arxiv_submission.tar.gz`.
- `app/`: Interactive client-side SecMesh-PQSI Defense Console (`index.html`, deployed to GitHub Pages).
- `results/`, `rosette/`: Verbatim Lean axiom log, multi-kernel audit transcript, exact Python report, and Rosette-Wire audit receipt bundle.

## 4. Essential Commands

```bash
# Native C11 core (40/40 tests, -Wall -Wextra -Werror)
make -C native test

# Node.js 25 differential, interop & security suite (12/12 tests)
node node/tests/test_secmesh_v2.mjs

# Zero-Mathlib Lean 4.35.0 full build & strict axiom allowlist audit
cd lean && lake build && lake env lean VerifyAxioms.lean

# Python exact-arithmetic suite, pytest, ruff, mypy & citation audit
python python/secmesh_verify/exact_audit.py
pytest python/tests/test_all.py -v
ruff check python scripts/check_citations.py
mypy python/secmesh_verify scripts/check_citations.py --ignore-missing-imports
python scripts/check_citations.py

# Compile both white papers (Tectonic 0.17+)
(cd paper && tectonic -X compile main.tex --outdir build)
(cd paper/engineering && tectonic -X compile secmesh_architecture.tex --outdir build)

# Build Standard v1.2.0 self-audit
pwsh -File scripts/Audit-Repo.ps1   # or: bash scripts/audit-repo.sh
```
