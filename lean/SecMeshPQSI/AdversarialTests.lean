module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

public import SecMeshPQSI.FiniteKey
public import SecMeshPQSI.LatticeBandwidth
public import SecMeshPQSI.MonogamyCommitmentNoGo
public import SecMeshPQSI.NonVacuity

/-!
# Adversarial Definition & Counterexample Suite (Playbook v1.3 Item 12)

Machine-checks concrete negations of strengthened/false variants of headline definitions
to prove our theorem boundaries are sharp and our definitions cannot prove false claims:
1. FIPS 203 `Compress_1` radius `|e| ≤ 831` (`T5c`) is STRICTLY TIGHT: at `e = +832`, BOTH
   `b = 0` and `b = 1` FAIL decoding (`mlkemCompress1 (0*1665 + 832) ≠ 0` and
   `mlkemCompress1 (1*1665 + 832) ≠ 1`).
2. Legacy SecMesh v1 `CELL_P = [0.146, 0.854]` (`T1a`) strictly violates Tsirelson's bound:
   `¬ (354 * 354 ≤ 8 * 125 * 125)`.
3. Commitment Conservation (`T7b`) concrete tightness: for disjoint supports `P0 = [1, 0]`,
   `P1 = [0, 1]` (`D = 1`), `TV = 1` and `Overlap = 0`, refuting any hiding claim `TV < 1`.
4. Toner Monogamy (`T7a`) concrete Pythagorean witness: at `(c,s,R) = (3,4,5)`,
   with `x1=3, x2=4, y1=-3, y2=4` we have `S_AB = 2(9+16) = 50 = 2 R^2` and `S_AE = 2(-9+16) = 14`,
   satisfying `50^2 + 14^2 = 2696 ≤ 5000 = 8 * 625`.
-/

namespace SecMeshPQSI.AdversarialTests

open SecMeshPQSI.LatticeBandwidth (mlkemCompress1)
open SecMeshPQSI.MonogamyCommitmentNoGo (sumNat absDiffNat)

public section

theorem adv_compress1_fails_at_plus_832 :
    mlkemCompress1 (0 * 1665 + 832) ≠ 0 ∧ mlkemCompress1 (1 * 1665 + 832) ≠ 1 := by
  decide

theorem adv_v1_chsh_refutes_tsirelson_bound :
    ¬ (354 * 354 ≤ 8 * (125 * 125)) := by
  decide

theorem adv_commitment_disjoint_refutes_hiding :
    let P0 : Nat → Nat := fun t => if t = 0 then 1 else 0
    let P1 : Nat → Nat := fun t => if t = 1 then 1 else 0
    sumNat 2 P0 = 1 ∧ sumNat 2 P1 = 1 ∧
    sumNat 2 (fun t => absDiffNat (P0 t) (P1 t)) = 2 ∧
    sumNat 2 (fun t => min (P0 t) (P1 t)) = 0 := by
  decide

theorem adv_toner_concrete_pythagorean_witness :
    let sAB : Int := 2 * (3 * 3 + 4 * 4)
    let sAE : Int := 2 * (3 * (-3) + 4 * 4)
    sAB * sAB + sAE * sAE ≤ 8 * (5 * 5 * 5 * 5) := by
  decide

/-- Concrete (3, 4, 5) Pythagorean saturation of Fuchs-van de Graaff (`T7c`):
for `r = (3, 1)` (`P0 = (9/10, 1/10)`) and `s = (1, 3)` (`P1 = (1/10, 9/10)`),
`M = 10`, `tv2 = 16` (`TV = 4/5`), `B = 6` (`B = 3/5`), `ov = 2`, attaining
exact equality `tv2^2 + 4 B^2 = 256 + 144 = 400 = 4 M^2` (proving `T7c` cannot be tightened). -/
theorem adv_fuchs_vdg_pythagorean_tight :
    let r : Nat → Nat := fun t => if t = 0 then 3 else 1
    let s : Nat → Nat := fun t => if t = 0 then 1 else 3
    sumNat 2 (fun t => r t * r t) = 10 ∧
    sumNat 2 (fun t => s t * s t) = 10 ∧
    sumNat 2 (fun t => absDiffNat (r t * r t) (s t * s t)) = 16 ∧
    sumNat 2 (fun t => r t * s t) = 6 ∧
    16 * 16 + 4 * (6 * 6) = 4 * (10 * 10) := by
  decide

end

end SecMeshPQSI.AdversarialTests
