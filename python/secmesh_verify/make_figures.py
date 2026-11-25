#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Alexander S. Donahue
"""
Generate publication-grade vector PDF figures for both AMS-LaTeX white papers.
"""
from __future__ import annotations

import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
FIG_DIR = REPO_ROOT / "paper" / "figures"

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 9.5,
    "axes.labelsize": 10,
    "axes.titlesize": 10.5,
    "legend.fontsize": 8.5,
    "xtick.labelsize": 8.5,
    "ytick.labelsize": 8.5,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linestyle": "--",
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})

TSIRELSON = 2.0 * math.sqrt(2.0)


def h_bin(p: float) -> float:
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))


def h_min_di(s: float) -> float:
    if s <= 2.0:
        return 0.0
    if s >= TSIRELSON:
        return 1.0
    return max(0.0, 1.0 - math.log2(1.0 + math.sqrt(max(0.0, 2.0 - s * s / 4.0))))


def h_vn_di(s: float) -> float:
    if s <= 2.0:
        return 0.0
    if s >= TSIRELSON:
        return 1.0
    p = 0.5 * (1.0 + math.sqrt(max(0.0, (s / 2.0) ** 2 - 1.0)))
    return max(0.0, 1.0 - h_bin(p))


def qber_kl_ub(q_hat: float, m: int, eps: float) -> float:
    if m <= 0 or q_hat >= 0.5:
        return 0.5
    rhs = math.log(1.0 / eps) / m
    if q_hat <= 0.0:
        return min(0.5, 1.0 - math.exp(-rhs))
    def kl(p: float, q: float) -> float:
        v = 0.0
        if p > 0:
            v += p * math.log(p / q)
        if p < 1:
            v += (1 - p) * math.log((1 - p) / (1 - q))
        return v
    if kl(q_hat, 0.5) <= rhs:
        return 0.5
    lo, hi = q_hat, 0.5
    for _ in range(64):
        mid = 0.5 * (lo + hi)
        if kl(q_hat, mid) < rhs:
            lo = mid
        else:
            hi = mid
    return hi


def fk_v2_bits(n_total: int, s: float = TSIRELSON, qber: float = 0.0, eps: float = 1e-6) -> int:
    cell = n_total // 9
    if cell <= 0:
        return 0
    q_samp = max(1, cell // 5)
    n_rem = cell - q_samp
    eps_lane = eps / 5.0
    s_lb = max(2.0, s - 4.0 * math.sqrt((2.0 * math.log(8.0 / eps_lane)) / cell))
    q_ub = qber_kl_ub(qber, q_samp, eps_lane)
    ell = (
        n_rem * h_min_di(s_lb)
        - n_rem * 1.16 * h_bin(q_ub)
        - math.sqrt(2.0 * n_rem * math.log(1.0 / eps_lane)) / math.log(2.0)
        - 2.0 * math.log2(1.0 / (2.0 * eps_lane))
        - math.ceil(math.log2(1.0 / eps_lane))
    )
    return max(0, math.floor(ell))


def fk_v1_broken_bits(n_total: int, s: float = 2.832, qber: float = 0.0, eps: float = 1e-6) -> int:
    cell = n_total // 9
    if cell <= 0:
        return 0
    eps_s = eps / 3.0
    s_lb = max(2.0, s - 4.0 * math.sqrt(math.log(8.0 / eps_s) / (2.0 * cell)))
    per = max(0.0, h_vn_di(s_lb) - h_bin(qber))
    if per <= 0:
        return 0
    aep = math.sqrt(2.0 * cell * math.log(1.0 / eps_s)) / math.log(2.0)
    hcost = math.log2(3.0 / eps) + 3.0
    return max(0, math.floor(cell * per - aep - hcost))


def fig1_finite_key_contrast() -> None:
    ns = np.linspace(10_000, 600_000, 120, dtype=int)
    v1_hon = [fk_v1_broken_bits(int(n), s=2.832, qber=0.0) for n in ns]
    v2_hon = [fk_v2_bits(int(n), s=TSIRELSON, qber=0.0) for n in ns]
    v2_q1 = [fk_v2_bits(int(n), s=TSIRELSON, qber=0.01) for n in ns]

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    ax.plot(ns / 1000.0, v1_hon, "--", color="#d97706", lw=2.0, label="Legacy SecMesh v1 (defective: $S=2.832$, wrong Hoeffding & $H_{\\mathrm{vN}}$)")
    ax.plot(ns / 1000.0, v2_hon, "-", color="#059669", lw=2.2, label="SecMesh-PQSI v2 (composable DI $H_{\\min}$, exact KL-QBER, $\\mathrm{QBER}=0\\%$)")
    ax.plot(ns / 1000.0, v2_q1, "-.", color="#2563eb", lw=1.8, label="SecMesh-PQSI v2 ($\\mathrm{QBER}=1\\%$, $f_{\\mathrm{EC}}=1.16$)")
    ax.fill_between(ns / 1000.0, v2_hon, v1_hon, color="#ef4444", alpha=0.12, label="Unjustified overclaim region (legacy v1)")
    ax.axhline(256, color="#64748b", ls=":", lw=1.2, label="256-bit key admission threshold")
    ax.set_xlabel("Total E91 Rounds $N$ (thousands)")
    ax.set_ylabel("Certified Secret Key Length $\\ell$ (bits, $\\varepsilon = 10^{-6}$)")
    ax.set_title("Finite-Key Admission: SecMesh-PQSI v2 vs. Defective Legacy v1")
    ax.legend(loc="upper left", frameon=True, framealpha=0.92)
    fig.tight_layout(pad=0.6)
    fig.savefig(FIG_DIR / "fig1_finite_key_contrast.pdf", bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)


def fig2_di_entropy_duality() -> None:
    s_grid = np.linspace(2.0, TSIRELSON, 400)
    y_min = [h_min_di(float(s)) for s in s_grid]
    y_vn = [h_vn_di(float(s)) for s in s_grid]
    gap = [a - b for a, b in zip(y_vn, y_min, strict=True)]
    idx_max = int(np.argmax(gap))

    fig, ax = plt.subplots(figsize=(6.4, 3.5))
    ax.plot(s_grid, y_vn, "--", color="#d97706", lw=2.0, label="Collective von Neumann $H_{\\mathrm{vN}}^{\\mathrm{DI}}(S)$ (Acín\u2013Pironio)")
    ax.plot(s_grid, y_min, "-", color="#059669", lw=2.2, label="Strict DI Min-Entropy $H_{\\min}^{\\mathrm{DI}}(S)$ (Pironio 2010 / Moonlab)")
    ax.fill_between(s_grid, y_min, y_vn, color="#ef4444", alpha=0.14, label="Strict overestimation gap $\\Delta(S) > 0$")
    ax.annotate(
        f"Max gap $+{gap[idx_max]:.3f}$ bit\nat $S={s_grid[idx_max]:.3f}$",
        xy=(s_grid[idx_max], 0.5 * (y_min[idx_max] + y_vn[idx_max])),
        xytext=(2.20, 0.54),
        arrowprops={"arrowstyle": "->", "color": "#991b1b", "lw": 1.15},
        fontsize=8.5,
        color="#7f1d1d",
        bbox={"boxstyle": "round,pad=0.25", "fc": "#fff5f5", "ec": "#fca5a5", "lw": 0.7},
    )
    ax.axvline(TSIRELSON, color="#334155", ls=":", lw=1.1)
    ax.text(TSIRELSON - 0.015, 0.06, "$2\\sqrt{2}$", ha="right", fontsize=8.5, color="#334155")
    ax.set_xlabel("Observed CHSH Parameter $S \\in [2, 2\\sqrt{2}]$")
    ax.set_ylabel("Certified Entropy Rate (bits / round)")
    ax.set_title("Theorem T1c: Quarter-Circle Duality ($u^2 + v^2 = 1$) & Entropy Gap")
    ax.legend(loc="upper left", frameon=True, framealpha=0.92)
    fig.tight_layout(pad=0.6)
    fig.savefig(FIG_DIR / "fig2_di_entropy_duality.pdf", bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)


def fig3_qgt_concurrence_surplus() -> None:
    alphas = np.linspace(0.0, math.pi / 4.0, 200)
    conc = np.sin(2.0 * alphas)
    fig, ax = plt.subplots(figsize=(6.4, 3.5))
    for theta, lbl, col, ls in [
        (math.pi / 3.0, "$\\theta = \\pi/3$", "#2563eb", "-"),
        (math.pi / 2.0, "$\\theta = \\pi/2$", "#7c3aed", "--"),
        (2.0 * math.pi / 3.0, "$\\theta = 2\\pi/3$", "#059669", "-."),
        (math.pi, "$\\theta = \\pi$ (max surplus $C^2/4$)", "#dc2626", ":"),
    ]:
        sh2 = math.sin(theta / 2.0) ** 2
        surp = 0.25 * (conc**2) * sh2
        ax.plot(conc, surp, ls=ls, color=col, lw=2.0, label=lbl)
    ax.set_xlabel("Wootters Concurrence $\\mathcal{C} = \\sin(2\\alpha)$ (0 = separable, 1 = singlet)")
    ax.set_ylabel("QGT Surplus $\\det(g) - \\frac{1}{4}\\Omega_{\\theta\\phi}^2$")
    ax.set_title("Theorem T4b: QGTL Determinant Surplus as an Entanglement Witness")
    ax.legend(loc="upper left", frameon=True, framealpha=0.92)
    fig.tight_layout(pad=0.6)
    fig.savefig(FIG_DIR / "fig3_qgt_concurrence_surplus.pdf", bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)


def fig4_kn_pq_bandwidth_ceilings() -> None:
    profiles = [
        ("Classical\nX25519+Ed25519", 192, "#94a3b8"),
        ("PQ-Auth Only\n(SNDL Broken)", 5357, "#f59e0b"),
        ("Hybrid PQ\nML-KEM-768+ML-DSA-65", 6669, "#3b82f6"),
        ("SecMesh-PQSI\nHybrid + CW-128", 6685, "#10b981"),
        ("SecMesh-PQSI\nLattice-Hedged (SLH-DSA)", 14989, "#7c3aed"),
    ]
    names = [p[0] for p in profiles]
    sizes = [p[1] for p in profiles]
    cols = [p[2] for p in profiles]
    ceilings = [math.floor((100_000_000 / 8.0) / s) + 1 for s in sizes]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 3.35), gridspec_kw={"wspace": 0.22})
    y = np.arange(len(names))
    ax1.barh(y, sizes, color=cols, edgecolor="#1e293b", linewidth=0.6)
    ax1.set_yticks(y)
    ax1.set_yticklabels(names, fontsize=7.8)
    ax1.invert_yaxis()
    ax1.set_xlabel("One-Way Size (bytes)")
    ax1.set_title("Exact Handshake Wire Cost")
    for idx, val in enumerate(sizes):
        ax1.text(val + 300, idx, f"{val:,} B", va="center", fontsize=7.5)
    ax1.set_xlim(0, 21500)

    ax2.barh(y, ceilings, color=cols, edgecolor="#1e293b", linewidth=0.6)
    ax2.set_yticks(y)
    ax2.set_yticklabels([""] * len(names))
    ax2.invert_yaxis()
    ax2.set_xscale("log")
    ax2.set_xlabel("$K_N$ Ceiling (100 Mbps, 1 s, log)")
    ax2.set_title("Complete-Graph $K_N$ Ceiling")
    for idx, val in enumerate(ceilings):
        ax2.text(val * 1.18, idx, f"{val:,}", va="center", fontsize=7.5)
    ax2.set_xlim(100, 450000)

    fig.savefig(FIG_DIR / "fig4_kn_pq_bandwidth_ceilings.pdf", bbox_inches="tight", pad_inches=0.06)
    plt.close(fig)


def main() -> int:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    fig1_finite_key_contrast()
    fig2_di_entropy_duality()
    fig3_qgt_concurrence_surplus()
    fig4_kn_pq_bandwidth_ceilings()
    print(f"Generated 4 vector PDF figures in {FIG_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
