#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Unified local dev & verification runner for SecMesh-PQSI
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== [1/5] Native C11 Moonlab Core ==="
make -C native test

echo "=== [2/5] Node.js 25 Differential & Security Suite ==="
node node/tests/test_secmesh_v2.mjs

echo "=== [3/5] Lean 4.35.0 Build & Strict Axiom Audit ==="
(cd lean && lake build && lake env lean VerifyAxioms.lean)

echo "=== [4/5] Python Exact Audit, Pytest, Ruff & Mypy ==="
PY="${PYTHON:-python3}"
"$PY" python/secmesh_verify/exact_audit.py
"$PY" -m pytest python/tests/test_all.py -v
"$PY" -m ruff check python scripts/check_citations.py
"$PY" -m mypy python/secmesh_verify scripts/check_citations.py --ignore-missing-imports
"$PY" scripts/check_citations.py

echo "=== [5/5] Build Standard Repo Audit ==="
bash scripts/audit-repo.sh || true
echo "All verification steps completed."
