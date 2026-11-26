# ADR 0002: Zero-Mathlib Lean 4.35.0 Proofs with Standalone Palomar Comparator Contract

- **Status:** Accepted (2026-11-25)
- **Context:** Formalizing 27 cryptographic, quantum-geometry, and information-theoretic theorems with Mathlib pulls in >1.5M lines of external dependencies and slows multi-kernel replay.
- **Decision:** Write all 27 proofs (`T1a`–`T7b`) strictly in zero-Mathlib Lean 4.35.0 core (`module` header, zero `sorry`, zero `native_decide`, zero custom axioms) alongside a standalone zero-import `PalomarChallenge.lean` (<460 lines, <19 KiB) + `PalomarSolution.lean` so every proof term replays in 6 kernel runs with 5 distinct implementations (`Lean paranoid`, `lean4lean`, `nanoda_bin`, `con-leche --verified`, `con-ron --verified`, `Lean default`; the first and last are one kernel in two modes). The exported set later grew to 28 theorems (`T1a`–`T7c`).
- **Consequences:** Transcendental real-number inequalities are proved via exact cleared-denominator integer/rational algebraic identities in Lean and cross-checked to 60-digit `Decimal` precision in Python (`LIMITATIONS.md`).
