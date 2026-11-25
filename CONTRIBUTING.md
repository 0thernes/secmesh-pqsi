# Contributing to `secmesh-pqsi` (`CONTRIBUTING.md`)

Contributions that strengthen mathematical rigor, cryptographic verification, C11/Node/Python differential testing, or documentation clarity are welcome.

## Standards for Every Contribution
1. **Honest verification:** Never claim a test, benchmark, or theorem passes unless you actually ran it.
2. **Lean 4.35.0 proofs (`lean/`):**
   - Zero Mathlib dependencies.
   - Zero `sorry`, `admit`, `native_decide`, custom `axiom`, `implemented_by`, or `@[extern` in proof/solution modules.
   - Run `lake build && lake env lean VerifyAxioms.lean` and confirm strict membership in `[propext, Classical.choice, Quot.sound]`.
3. **Native C11 (`native/`):** Must compile with `-std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra -Werror` (0 warnings) and pass `make -C native test` (58/58).
4. **Node.js & Python:** Must pass `node node/tests/test_secmesh_v2.mjs` (16/16), `pytest python/tests/test_all.py` (13/13), `python scripts/check_readme_axioms.py`, `ruff check`, and `mypy`.
5. **Licensing & SPDX:** Code contributions are licensed under `Apache-2.0`; documentation and manuscripts under `CC-BY-4.0`. Include SPDX headers on new files and respect `CODE_OF_CONDUCT.md`.
6. **Workflow:** Commits are plain unsigned commits targeting `main` (see `AGENTS.md`). Classify bug/audit reports using the 10-class finding taxonomy.
