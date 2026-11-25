# Numbered Claims Ledger (`CLAIMS.md`)

Every technical and mathematical claim in `secmesh-pqsi` is tagged by its exact verification status:
- `kernel-checked` — Proved in zero-Mathlib Lean 4.35.0 and independently replayed across 5 distinct kernel implementations (`results/six_kernel_audit.txt`).
- `differential-tested` — Verified across independent C11, Node.js 25/OpenSSL 3.5.5, and Python implementations.
- `numerical` — Verified via arbitrary-precision (60-digit `Decimal`) or seeded exact-arithmetic Python simulation.
- `open-problem` — Explicitly documented as an unresolved conjecture (not claimed solved).

| ID | Claim | Primary Artifact | Status |
| --- | --- | --- | --- |
| C1 | Legacy `BoogerCheeseOnRye/SecMesh@aff7dc6` `CELL_P=[0.146, 0.854]` gives expected $S = 354/125 = 2.832 > 2\sqrt{2}$ ($354^2 - 8 \cdot 125^2 = 316 > 0$). | `lean/SecMeshPQSI/FiniteKey.lean` (`t1a`) | `kernel-checked` |
| C2 | Legacy v1 Hoeffding bound omits range-2 factor 4, inflating per-cell failure at $\varepsilon_s = 10^{-6}$ from $2.5 \times 10^{-7}$ to $0.0285744 > 1/50$. | `lean/SecMeshPQSI/FiniteKey.lean` (`t1b`) | `kernel-checked` |
| C3 | Exact quarter-circle duality $u^2 + v^2 = 1$ separates Acín–Pironio $\HvN(S)$ from Pironio $\Hmin(S)$; $\Hmin(2.5) < \HvN(2.5)$ with numerical max gap $+0.235703$ bit/round at $S \approx 2.699192$. | `lean/SecMeshPQSI/FiniteKey.lean` (`t1c`), `exact_audit.py` | `kernel-checked`, `numerical` |
| C4 | Legacy 8-bit majority `deNoise` biases uniform bytes to $93/256$ ones ($163/256$ zeros) and is single-flip fragile on $70/256$ weight-4 blocks. | `lean/SecMeshPQSI/FiniteKey.lean` (`t1d`) | `kernel-checked` |
| C5 | Five-lane composable $\varepsilon$-conservation holds additively; legacy v1 double-spends $\varepsilon_s$ and leaves zero budget for $\varepsilon_Q, \varepsilon_{\mathrm{cor}}$. | `lean/SecMeshPQSI/FiniteKey.lean` (`t1e`) | `kernel-checked` |
| C6 | Unconditional PSI triad: Shannon OTP bijection, $k$-factor XOR dual-survivability, constructive general-dimension Toeplitz 2-universality, integer Cauchy–Schwarz LHL, general-field Carter–Wegman degree-$d$ bound. | `lean/SecMeshPQSI/InfoTheoretic.lean` (`t2a`–`t2d`) | `kernel-checked` |
| C7 | Shamir $(t,n)$ exact reconstruction & $(t-1)$-collusion zero-leakage; Byzantine Singleton bound $n \ge t + 2b$ & tightness $d = 2b$ at $n = t + 2b - 1$; Mega Atlas `CS-053` PIR threshold $N \ge K + T + 2B$ & strict $T^2 > 0$ gap at $M=2$. | `lean/SecMeshPQSI/ThresholdPIR.lean` (`t3a`–`t3c`) | `kernel-checked` |
| C8 | $D$-dim QGT Hermitian PSD Lagrange/trace bounds; exact new QGT Concurrence Surplus identity $\det(g) - \frac{1}{4}\Omega_{\theta\phi}^2 = \frac{1}{4}\mathcal{C}^2\sin^2(\theta/2)$ (60-digit residual $3.3 \times 10^{-60}$); general $\mathbb{Z}_\ell \times \mathbb{Z}_m$ involution proof + Bravyi `[[144,12,12]]` Gross BB qLDPC CSS & weight-6 certification ($k=12$ via $\mathbb{F}_2$ rank $66$). | `lean/SecMeshPQSI/QuantumGeometry.lean` (`t4a`–`t4c2`), `exact_audit.py` | `kernel-checked`, `numerical` |
| C9 | FIPS 203 $q = 3329$ prime & $\zeta = 17$ primitive 256-th root; exact zero-overflow Montgomery reduction; sharp `Compress_1` error margin $|e| \le 831$ (tight at $e=+832$); $K_N$ ceiling optimality & $<1.75\%$ IT-hedge overhead ($+112\text{ B}$). | `lean/SecMeshPQSI/LatticeBandwidth.lean` (`t5a`–`t5d`) | `kernel-checked` |
| C10 | Bit-exact FIPS 203 ML-KEM-768 cross-implementation interop between C11 Moonlab and Node.js 25 OpenSSL 3.5.5; live $25{,}003\text{ B}$ ($391.0\text{ ms}$) lattice-hedged PQSI handshake; C11 $\leftrightarrow$ Node $\leftrightarrow$ Python differential agreement ($<10^{-11}$). | `native/tests/test_native_core.c`, `node/tests/test_secmesh_v2.mjs`, `python/tests/test_all.py` | `differential-tested` |
| C11 | Pre-registered 30-seed paired simulation (`20260001..20260030`) of hardened health-field controller yields Holm–Bonferroni $p_{\mathrm{Holm}} = 3.73 \times 10^{-9}$ for intrusion suppression ($60.0 \to 0.033$) and peak stress ($1.0425 \to 0.4431$). | `python/secmesh_verify/exact_audit.py`, `results/exact_verification_report.json` | `numerical` |
| C12 | Open conjectures in `unsolved-problems-mega-atlas` (`QC-021`, `CS-026`, `CS-028`, `CS-031`, `CS-050`, `CS-053`, `CS-054`, `CS-061`, `QC-034`, `QC-042`) remain open beyond our proved structural theorems. | `paper/main.tex` Table 2 | `open-problem` |

## What Would Prove Us Wrong (Explicit Falsification Criteria — B42)

1. **Lean 4.35 Proof Soundness (`C1`–`C9`):** Any counterexample accepted by `lean v4.35.0`, `leanchecker`, `con-leche`, `con-ron`, or `nanoda_bin`, OR any unpermitted axiom (`sorryAx`, `Lean.ofReduceBool`, `Lean.trustCompiler`, or custom `axiom`) appearing in `lake env lean VerifyAxioms.lean`, OR any vacuous hypothesis uninstantiable by `NonVacuity.lean`.
2. **FIPS 203 ML-KEM-768 Interop (`C10`):** Any valid NIST FIPS 203 public key `ek` and seed `m` where Moonlab C11 `moonlab_mlkem768_encaps` produces a shared secret differing from OpenSSL 3.5.5 `ml-kem-768` decapsulation, or where single-bit ciphertext tampering fails Fujisaki–Okamoto implicit rejection.
3. **Finite-Key v2 & QGTL Differential Agreement (`C3`, `C8`, `C10`):** Any parameter tuple where C11, Node.js 25, and 60-digit Python `Decimal` disagree beyond `1e-11`, or where an adversary with $S \le 2.0$ (Classical/Aligned/Parked Eve) receives `admitted = true` or `cert_bits > 0`.
4. **Hardened Guardian v2 Security (`C10`):** Any unauthenticated frame accepted on the CW-128 control plane, any wildcard `CORS: *` header, any UDP echo amplification response, or any raw key bytes leaked via `/status`.
5. **Pre-Registered 30-Seed Benchmark (`C11`):** Failure to reproduce identical control/treatment means and Holm–Bonferroni $p_{\mathrm{Holm}} = 3.73 \times 10^{-9}$ from seeds `20260001..20260030` in `exact_audit.py`.

