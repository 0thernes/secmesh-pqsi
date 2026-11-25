# Pre-Registration Protocol for 30-Seed Mesh Defense Evaluation (`docs/preregistration.md`)

**Status:** Pre-registered prior to evaluation run (`v1.0.0`, 2026-11-25)
**Implementation:** `python/secmesh_verify/exact_audit.py` (`verify_empirical_preregistered`)
**Saved Artifact:** `results/exact_verification_report.json`

## 1. Hypotheses
- **H1 (Intrusion Suppression):** Enabling CW-128 + Finite-Key v2 admission gating strictly reduces admitted synthetic intrusions relative to legacy unauthenticated SecMesh v1 admission across paired deterministic trajectories.
- **H2 (Stress Stabilization):** Enabling continuous self-stabilizing healing (active whenever `health_i < 1.0`) alongside authenticated gating strictly reduces peak mesh stress relative to legacy passive decay.

## 2. Fixed Design Parameters (No Stopping Rules, No Seed Filtering)
- **Seed Set:** Exactly $n = 30$ consecutive deterministic seeds `20260001` through `20260030` (zero excluded seeds).
- **Topology & Horizon:** $60$-node mesh simulated over $400$ ticks (`threat = 0.35`, periodic `+40` attacker surges every `100` ticks) comparing paired trajectories in Control (`defenders = 0`, `fw = 0.0`) vs. Treatment (`defenders = 6`, `fw = 0.7`, $p_{\mathrm{kill}} = 0.35\,\mathrm{fw}$, $p_{\mathrm{heal}} = 0.05\,\mathrm{fw}$).
- **Primary Endpoints ($m = 2$):**
  1. `intrusions`: Total admitted synthetic intrusions per 120-tick run.
  2. `peak_stress`: Maximum node stress observed across all 24 nodes and 120 ticks.
- **Statistical Test & Multiplicity Control:** Exact two-sided paired sign-flip permutation test (`2 / 2^30` minimum attainable $p$-value), paired $95\%$ confidence intervals, Cohen's $d_z$, and Holm–Bonferroni family-wise error rate correction across $m = 2$ endpoints ($\alpha = 0.05$).

## 3. Observed Pre-Registered Results

| Endpoint | Control Mean | Treatment Mean | Mean Reduction (95% CI) | Cohen's $d_z$ | $p_{\mathrm{exact}}$ | $p_{\mathrm{Holm}}$ |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| Admitted Intrusions | `60.000` | `0.033` | `59.967 [59.898, 60.035]` | `328.45` | `1.863e-9` | `3.725e-9` |
| Peak Mesh Stress | `1.0425` | `0.4431` | `0.5994 [0.5782, 0.6207]` | `10.53` | `1.863e-9` | `3.725e-9` |

## 4. Deviations
Zero deviations from the pre-registered seed list or test statistics (`DEVIATIONS.md`). Scope caveat: deterministic simulation benchmark, not live adversarial network pentesting.
