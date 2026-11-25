# Deviations from Standards & Upstream Prototypes (`DEVIATIONS.md`)

All deliberate deviations from upstream prototypes (`BoogerCheeseOnRye/SecMesh@aff7dc6`), third-party specs, or Build Standard v1.2.0 defaults are recorded explicitly below.

1. **Deviation from Legacy `BoogerCheeseOnRye/SecMesh@aff7dc6` (Intentional Security Fixes):**
   - Replaced super-quantum `CELL_P = [0.146, 0.854]` ($S = 2.832$) with exact $\sin^2(\pi/8)$ singlet correlators ($S \le 2\sqrt{2}$).
   - Replaced range-1 Hoeffding with range-2 Hoeffding ($4\times$ sample correction) and replaced collective von Neumann $H_{\mathrm{vN}}^{\mathrm{DI}}(S)$ with strict Pironio $H_{\min}^{\mathrm{DI}}(S)$.
   - Replaced point QBER with exact Bernoulli Chernoff–KL upper confidence bound and realistic $f_{\mathrm{EC}} = 1.16$.
   - Removed biased 8-bit majority `deNoise`, cleartext `bitA`/`bitB` JSON transmission, unauthenticated `0.0.0.0` binding, wildcard `CORS: *`, `/e91` raw key leak, and open UDP amplification echo.
2. **Deviation in Lean 4.35.0 Local Multi-Kernel Audit:**
   - `lean4lean.exe` in the Windows `v4.35.0` bundle fails with an upstream `.olean` `incompatible header` error; excluded from local count (`LIMITATIONS.md`).
   - `lake comparator --paranoid` requires Linux `bwrap` and runs in Ubuntu CI rather than native Windows.
3. **Deviation in Build Standard v1.2.0 Optional Items (`repo.yaml`):**
   - Items marked `N/A` in `repo.yaml` (e.g., container image publishing, mobile binary signing, public SaaS telemetry, or enterprise SLA tiers) are explicitly justified with concrete N/A rationales per Build Standard v1.2.0.
4. **Affiliation Clarification (`conflict` resolution):**
   - Uses `Independent Researcher, Spokane, WA, USA` rather than `0thernes LLC` since no legal LLC entity is formed (`LIMITATIONS.md`, `HARDENING_LOG.md`).
