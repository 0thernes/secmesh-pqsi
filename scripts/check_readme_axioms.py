#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Alexander S. Donahue
"""
CI & Local Drift Auditor for README.md 5-Second Verbatim `#print axioms` Block
(Defensible Independent AI Research Playbook v1.3, Checklist Item 4).

1. Parses every `#print axioms` declaration in `results/lean_axioms.txt` and asserts
   that every axiom lies strictly inside {"propext", "Classical.choice", "Quot.sound"}
   (rejecting sorryAx, Lean 4.29+ ._native.* axioms, or any custom axiom).
2. Extracts every quoted declaration line from README.md's 5-second proof block and
   verifies it matches `results/lean_axioms.txt` verbatim (zero drift).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AXIOMS_FILE = REPO_ROOT / "results" / "lean_axioms.txt"
README_FILE = REPO_ROOT / "README.md"
ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


def normalize_axioms(text: str) -> dict[str, str]:
    collapsed = re.sub(r",\s*\n\s*", ", ", text)
    entries: dict[str, str] = {}
    for raw in collapsed.splitlines():
        line = raw.strip()
        if not line.startswith("'SecMeshPQSI."):
            continue
        m_name = re.match(r"^'([^']+)'\s+(.*)$", line)
        if not m_name:
            continue
        entries[m_name.group(1)] = m_name.group(2).strip()
    return entries


def validate_entries(entries: dict[str, str], readme_entries: dict[str, str]) -> list[str]:
    errors: list[str] = []
    if len(entries) < 56:
        errors.append(f"expected >= 56 declarations in {AXIOMS_FILE}, got {len(entries)}")
    for decl, rest in entries.items():
        if rest == "does not depend on any axioms":
            continue
        m_ax = re.match(r"^depends on axioms:\s*\[([^\]]*)\]$", rest)
        if not m_ax:
            errors.append(f"unparseable axiom line for {decl}: {rest}")
            continue
        used = {a.strip() for a in m_ax.group(1).split(",") if a.strip()}
        bad = used - ALLOWED_AXIOMS
        if bad:
            errors.append(f"disallowed axioms {sorted(bad)} in {decl}")
    if len(readme_entries) < 10:
        errors.append(f"README.md 5-second proof block has only {len(readme_entries)} verbatim lines")
    for decl, rest in readme_entries.items():
        if decl not in entries:
            errors.append(f"README decl missing in lean_axioms.txt: {decl}")
        elif entries[decl] != rest:
            errors.append(f"README mismatch for {decl}: {rest!r} vs {entries[decl]!r}")
    return errors


def main() -> int:
    if not AXIOMS_FILE.exists() or not README_FILE.exists():
        print("ERROR: missing results/lean_axioms.txt or README.md", file=sys.stderr)
        return 1
    entries = normalize_axioms(AXIOMS_FILE.read_text(encoding="utf-8"))
    readme_entries = normalize_axioms(README_FILE.read_text(encoding="utf-8"))
    errors = validate_entries(entries, readme_entries)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1
    print(
        f"README axiom check PASS: {len(entries)} declarations strictly within "
        f"{sorted(ALLOWED_AXIOMS)}; {len(readme_entries)} README verbatim lines match 100%."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
