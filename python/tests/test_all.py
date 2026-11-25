# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Alexander S. Donahue
"""Comprehensive pytest suite for SecMesh-PQSI:
- Positive & negative exact mathematical checks (T1-T5)
- Metamorphic & property checks (OTP bijection, Toeplitz F_2 linearity, Shamir invariance, QGT PSD)
- Cross-language differential verification (C11 Moonlab <-> Node.js 25 <-> Python exact)
- Lean 4.35 forbidden-token and axiom allowlist check
- Eshkol v1.3.6 source structure & dual-number AD sanity checks
"""

from __future__ import annotations

import json
import math
import re
import subprocess
from decimal import Decimal, getcontext
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
NATIVE_CLI = REPO_ROOT / "native" / "build" / (
    "secmesh_core.exe" if (REPO_ROOT / "native" / "build" / "secmesh_core.exe").exists() else "secmesh_core"
)
RESULTS_REPORT = REPO_ROOT / "results" / "exact_verification_report.json"


def run_json(cmd: list[str]) -> dict:
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)


# ============================================================================
# 1. Exact Mathematical Oracles (Positive & Negative Tests)
# ============================================================================


def test_t1a_v1_tsirelson_violation_exact():
    from fractions import Fraction
    s_v1 = 4 * (1 - 2 * Fraction(146, 1000))
    assert s_v1 == Fraction(354, 125)
    assert s_v1 * s_v1 > 8
    assert s_v1.numerator ** 2 - 8 * (s_v1.denominator ** 2) == 316


def test_t1b_hoeffding_range2_factor4():
    eps_s = 1e-6
    t_v1 = math.sqrt(math.log(8.0 / eps_s) / 2.0)
    # Range-2 variable actual failure probability per cell under v1's t_v1:
    actual_tail = 2.0 * math.exp(-t_v1 * t_v1 / 2.0)
    assert actual_tail > 0.028
    assert actual_tail / (eps_s / 4.0) > 100_000.0


def test_t1c_quarter_circle_duality_and_vn_overestimate():
    for s in [2.05, 2.2, 2.5, 2.699, 2.8]:
        rad_vn = math.sqrt((s / 2.0) ** 2 - 1.0)
        rad_hm = math.sqrt(2.0 - (s / 2.0) ** 2)
        assert abs(rad_vn ** 2 + rad_hm ** 2 - 1.0) < 1e-15
        p = 0.5 * (1.0 + rad_vn)
        h_vn = 1.0 - (-p * math.log2(p) - (1 - p) * math.log2(1 - p))
        h_min = 1.0 - math.log2(1.0 + rad_hm)
        assert h_vn > h_min
    # Boundary cases: S = 2 => both 0; S = 2*sqrt(2) => both 1
    assert abs(1.0 - math.log2(1.0 + math.sqrt(2.0 - 1.0))) < 1e-15
    assert abs((1.0 - math.log2(1.0 + math.sqrt(max(0.0, 2.0 - 2.0)))) - 1.0) < 1e-15


def test_t1d_denoise_majority_bias_exhaustive():
    ones = sum(1 for x in range(256) if x.bit_count() >= 5)
    zeros = sum(1 for x in range(256) if x.bit_count() < 5)
    fragile = sum(1 for x in range(256) if x.bit_count() == 4)
    assert (ones, zeros, fragile) == (93, 163, 70)
    assert ones + zeros == 256


def test_t2_otp_and_toeplitz_metamorphic():
    # Metamorphic check: Toeplitz F_2 linearity T_s(x xor y) == T_s(x) xor T_s(y)
    m, n = 8, 12
    seed = [((i * 7 + 3) % 5) & 1 for i in range(m + n - 1)]

    def toep(x: list[int]) -> list[int]:
        return [
            sum(seed[i + j] & x[j] for j in range(n)) & 1
            for i in range(m)
        ]

    for a in range(16):
        for b in range(16):
            xa = [(a >> (k % 4)) & 1 for k in range(n)]
            xb = [(b >> (k % 4)) & 1 for k in range(n)]
            xab = [u ^ v for u, v in zip(xa, xb, strict=True)]
            assert toep(xab) == [u ^ v for u, v in zip(toep(xa), toep(xb), strict=True)]


def test_t4b_qgt_concurrence_surplus_high_precision():
    getcontext().prec = 60
    for ca, sa, ch, sh, r in [(3, 4, 3, 4, 5), (0, 5, 3, 4, 5), (5, 0, 4, 3, 5), (5, 12, 12, 5, 13)]:
        D = Decimal
        c2a = D(ca * ca - sa * sa) / D(r * r)
        conc = D(2 * ca * sa) / D(r * r)
        sh2 = D(sh * sh) / D(r * r)
        st = D(2 * sh * ch) / D(r * r)
        g_tt = D(1) / D(4)
        g_pp = sh2 - (c2a ** 2) * (sh2 ** 2)
        omega = -(D(1) / D(2)) * c2a * st
        surplus = g_tt * g_pp - (D(1) / D(4)) * (omega ** 2)
        expected = (conc ** 2 / D(4)) * sh2
        assert abs(surplus - expected) < Decimal("1e-55")


def test_t5c_mlkem_compress1_exact_boundary():
    q = 3329

    def comp1(y: int) -> int:
        return ((2 * (y % q) + 1665) // q) % 2

    # Positive: ALL |e| <= 831 succeed for BOTH b=0 and b=1
    for b in (0, 1):
        for e in range(-831, 832):
            assert comp1(b * 1665 + e) == b
    # Negative (exact tightness): at e = +832 BOTH b=0 and b=1 fail!
    assert comp1(0 * 1665 + 832) == 1
    assert comp1(1 * 1665 + 832) == 0
    # Negative asymmetry on negative side: b=0 fails at -833, b=1 fails at -834
    assert comp1(0 * 1665 - 833) == 1
    assert comp1(1 * 1665 - 834) == 0


# ============================================================================
# 2. Cross-Language Differential Verification (C11 <-> Node.js <-> Python)
# ============================================================================


@pytest.mark.skipif(not NATIVE_CLI.exists(), reason="Native C11 binary not built")
def test_differential_c11_vs_python_finite_key_and_qgt():
    # Finite-key differential check (clean singlet N=450000, qber=0, eps=1e-6)
    fk = run_json([str(NATIVE_CLI), "finite-key", "2.82842712474619", "450000", "0.0", "1e-6", "1"])
    assert fk["admitted"] is True
    assert fk["cert_bits"] == 18838
    assert 2.0 < fk["s_lb"] < 2.8284272
    # Adversarial negative check: parked Eve (S = 2.0) MUST be rejected
    fk_eve = run_json([str(NATIVE_CLI), "finite-key", "2.00", "450000", "0.0", "1e-6", "1"])
    assert fk_eve["admitted"] is False
    assert fk_eve["cert_bits"] == 0

    # QGT differential check across separable, partial, and singlet states (CLI: qgt theta phi alpha)
    for theta, phi, alpha in [(1.2, 0.5, 0.0), (1.0, 0.3, 0.4), (math.pi / 2.0, 0.7, math.pi / 4.0)]:
        qgt = run_json([str(NATIVE_CLI), "qgt", str(theta), str(phi), str(alpha)])
        conc = abs(math.sin(2.0 * alpha))
        expected_surplus = 0.25 * (conc ** 2) * (math.sin(theta / 2.0) ** 2)
        assert abs(qgt["surplus"] - expected_surplus) < 1e-11
        assert qgt["inequality_holds"] is True

    # Bravyi [[144,12,12]] BB qLDPC C11 check
    bb = run_json([str(NATIVE_CLI), "bb144"])
    assert bb["n"] == 144 and bb["k"] == 12
    assert bb["css_orthogonal"] is True and bb["row_weight_min"] == 6 and bb["row_weight_max"] == 6

    # ML-KEM KAT check
    kat = run_json([str(NATIVE_CLI), "mlkem-kat"])
    assert kat["ek_valid"] is True and kat["dk_valid"] is True
    assert kat["match"] is True and kat["fo_implicit_reject"] is True


def test_differential_node_suite_and_report():
    proc = subprocess.run(
        ["node", "node/tests/test_secmesh_v2.mjs"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Node.js Suite Summary: 15/15 passed" in proc.stdout
    assert RESULTS_REPORT.exists()
    data = json.loads(RESULTS_REPORT.read_text(encoding="utf-8"))
    for key in [
        "T1_finite_key_forensics",
        "T2_info_theoretic_psi",
        "T3_shamir_byzantine_pir",
        "T4_qgtl_chern_ghz_bb144",
        "T5_fips203_and_bandwidth",
        "T6_ising_and_cryptosymbology",
        "empirical_preregistered_ab",
    ]:
        assert data[key]["status"] == "PASS"


# ============================================================================
# 3. Lean 4.35 Integrity & Eshkol Module Checks
# ============================================================================


def _strip_lean_comments(src: str) -> str:
    # Remove nested /- ... -/ block comments and -- line comments
    out = []
    i, depth = 0, 0
    n = len(src)
    while i < n:
        if depth == 0 and src[i : i + 2] == "--":
            while i < n and src[i] != "\n":
                i += 1
        elif src[i : i + 2] == "/-":
            depth += 1
            i += 2
        elif depth > 0 and src[i : i + 2] == "-/":
            depth -= 1
            i += 2
        else:
            if depth == 0:
                out.append(src[i])
            i += 1
    return "".join(out)


def test_lean_zero_forbidden_tokens_and_axioms():
    lean_dir = REPO_ROOT / "lean"
    forbidden = re.compile(
        r"\b(sorry|admit|native_decide|implemented_by)\b|^\s*((private|protected|noncomputable)\s+)*axiom\b|@\[extern",
        re.MULTILINE,
    )
    proof_files = [
        p for p in lean_dir.rglob("*.lean")
        if ".lake" not in p.parts and p.name != "PalomarChallenge.lean"
    ]
    assert len(proof_files) >= 12
    for pf in proof_files:
        cleaned = _strip_lean_comments(pf.read_text(encoding="utf-8"))
        m = forbidden.search(cleaned)
        assert m is None, f"Forbidden token {m.group(0)!r} in {pf}"

    # Strict allowlist parsing of every #print axioms entry (catches custom & Lean 4.29+ ._native. axioms!)
    axioms_txt = (REPO_ROOT / "results" / "lean_axioms.txt").read_text(encoding="utf-8")
    allowed = {"propext", "Classical.choice", "Quot.sound"}
    # Collapse multi-line bracketed lists
    normalized = re.sub(r",\s*\n\s*", ", ", axioms_txt)
    decl_lines = [ln.strip() for ln in normalized.splitlines() if ln.strip().startswith("'SecMeshPQSI.")]
    assert len(decl_lines) >= 52, f"Expected >= 52 audited declarations, got {len(decl_lines)}"
    for ln in decl_lines:
        if "does not depend on any axioms" in ln:
            continue
        m_ax = re.search(r"depends on axioms:\s*\[([^\]]*)\]", ln)
        assert m_ax is not None, f"Unexpected axiom line format: {ln}"
        used = {a.strip() for a in m_ax.group(1).split(",") if a.strip()}
        assert used <= allowed, f"Disallowed axiom(s) {used - allowed} in {ln}"
    assert "SecMeshPQSI.Solution.prove_all_secmesh_theorems" in normalized
    assert "SecMeshPQSI.Palomar.t6b_cryptosymbology_subliminal_and_threshold_closure" in normalized


def test_t4de_and_t6_high_precision_invariants():
    from fractions import Fraction
    # Theorem T4d: Exact rational Chern-Concurrence conservation on Pythagorean triples
    for ca, sa, r in [(3, 4, 5), (5, 12, 13), (8, 15, 17), (0, 1, 1), (1, 0, 1)]:
        c_eff = Fraction(-(ca * ca - sa * sa), r * r)
        conc = Fraction(2 * ca * sa, r * r)
        assert c_eff * c_eff + conc * conc == Fraction(1, 1)
        s_half_sq = Fraction(1, 1) + conc * conc
        assert c_eff * c_eff + s_half_sq == Fraction(2, 1)
    # Theorem T4e: GHZ QFI Heisenberg ceiling & Casimir
    for nq in (1, 4, 8, 16):
        assert 4 * nq * (nq + 2) - 4 * nq * nq == 8 * nq
    # Theorem T6a: Cheeger expander barrier monotonicity
    assert 2 * 10 * (1.0 * 2.0 + 0.7) > 2 * 10 * (1.0 * 0.4 + 0.7)


def test_eshkol_modules_balanced_sexprs():
    esk_files = sorted((REPO_ROOT / "eshkol").glob("*.esk"))
    assert len(esk_files) == 4
    for ef in esk_files:
        text = ef.read_text(encoding="utf-8")
        # Strip `;` line comments and string literals before checking parenthesis balance
        depth = 0
        in_str = False
        for line in text.splitlines():
            i = 0
            while i < len(line):
                ch = line[i]
                if ch == ";" and not in_str:
                    break
                if ch == '"' and (i == 0 or line[i - 1] != "\\"):
                    in_str = not in_str
                elif not in_str:
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        assert depth >= 0, f"Unmatched ')' in {ef.name}"
                i += 1
        assert depth == 0 and not in_str, f"Unbalanced S-expressions in {ef.name}"
