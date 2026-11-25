# ADR 0002: Zero-Mathlib Lean 4.35.0 Proofs with Standalone Palomar Comparator Contract

- **Status:** Accepted (2026-11-25)
- **Context:** Formalizing 21 cryptographic and quantum-geometry theorems with Mathlib pulls in >1.5M lines of external dependencies and slows multi-kernel replay.
- **Decision:** Write all 21 proofs strictly in zero-Mathlib Lean 4.35.0 core (`module` header, zero `sorry`, zero `native_decide`, zero custom axioms) alongside a standalone zero-import `PalomarChallenge.lean` (343 lines, 13.3 KiB) + `PalomarSolution.lean` so every proof term replays independently across `lean`, `leanchecker`, `leanchecker-paranoid`, `con-leche`, `con-ron`, and `nanoda_bin`.
- **Consequences:** Transcendental real-number inequalities are proved via exact cleared-denominator integer/rational algebraic identities in Lean and cross-checked to 60-digit `Decimal` precision in Python (`LIMITATIONS.md`).
