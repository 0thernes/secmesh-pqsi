# Glossary (`docs/glossary.md`)

- **BB qLDPC (Bivariate-Bicycle Quantum LDPC):** Calderbank–Shor–Steane (CSS) quantum error-correcting codes built from commuting polynomials $A, B \in \mathbb{F}_2[\mathbb{Z}_\ell \times \mathbb{Z}_m]$, exemplified by Bravyi et al.'s `[[144,12,12]]` Gross code (`T4c`).
- **Carter–Wegman IT-MAC:** Unconditional polynomial authentication over $\mathbb{F}_{2^{128}}$ with forgery probability $\le d/2^{128}$ under one-time pad masking (`T2d`).
- **CHSH Inequality / Tsirelson Bound:** Classical local hidden-variable bound $S \le 2$ vs. quantum Tsirelson ceiling $S \le 2\sqrt{2} \approx 2.828427$ (`T1a`).
- **Dual-Survivability Combiner:** XOR key combiner $K_{\mathrm{eff}} = K_{\mathrm{PQ}} \oplus K_{\mathrm{IT}}$ remaining unconditionally uniform if at least one independent factor survives (`T2b`).
- **ML-KEM-768 / ML-DSA-65 / SLH-DSA-128s:** NIST Post-Quantum standards FIPS 203 (module-lattice KEM), FIPS 204 (module-lattice signature), and FIPS 205 (stateless hash-based signature hedging against lattice collapse).
- **Palomar Comparator:** Lean 4.35 protocol verifying that a zero-`sorry` solution module proves the exact literal propositions declared in a standalone zero-import challenge contract (`PalomarChallenge.lean` vs. `PalomarSolution.lean`).
- **PSI (Post-Super-Intelligence):** Security against computationally unbounded adversaries via information-theoretic primitives (`T2a`–`T2d`, `T3a`–`T3b`).
- **QGT / QGTL (Quantum Geometric Tensor):** Complex Hermitian tensor $Q_{\mu\nu} = g_{\mu\nu} - \frac{i}{2}\Omega_{\mu\nu}$ uniting Fubini–Study metric $g$ and Berry curvature $\Omega$; Theorem `T4b` kernel-checks a polynomial identity that the paper reads as $\det(g) - \frac{1}{4}\Omega_{\theta\phi}^2 = \frac{1}{4}\mathcal{C}^2 \sin^2(\theta/2)$; no quantum geometric tensor is defined in Lean.
- **Rosette-Wire Receipt:** Deterministic canonical JSON + SHA-256 Merkle bundle enabling offline third-party audit replay (`rosette/latest-audit/`).
