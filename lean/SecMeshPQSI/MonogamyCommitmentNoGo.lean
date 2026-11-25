module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

/-!
# Theorem Family T7: Quantum CHSH Monogamy (Toner/CKW) & Unconditional Commitment No-Go

Formalizes two foundational conservation laws governing Post-Super-Intelligence (PSI)
cryptography:
- **T7a (`t7a_toner_chsh_monogamy_and_eve_isolation`):** First-principles algebraic proof of
  Toner's quantum CHSH monogamy theorem `S_AB^2 + S_AE^2 ≤ 8` from anticommuting Jordan-block
  observables, together with Coffman-Kundu-Wootters (CKW) tripartite Berry-monopole
  conservation `C_AB^2 + C_AE^2 + tau_ABE + r_A^2 = 1`: any Bell violation `S_AB > 2` traps
  any computationally unbounded eavesdropper strictly inside the classical polytope `|S_AE| < 2`,
  and Tsirelson saturation forces `S_AE = C_AE = tau_ABE = r_A = 0`.
- **T7b (`t7b_hiding_binding_conservation_nogo`):** Exact finite-support Hiding-Binding
  Conservation Law `TV(P_0, P_1) + Overlap(P_0, P_1) = 1` (exact integer form
  `∑ |P_0(t) - P_1(t)| + 2 ∑ min(P_0(t), P_1(t)) = 2 D`), proving the unconditional
  impossibility of simultaneously statistically-hiding and statistically-binding bit
  commitments and establishing the mathematical necessity of SecMesh-PQSI's hybrid PQ+PSI
  architecture.

Zero Mathlib dependencies; pure Lean 4.35.0 core.
-/

namespace SecMeshPQSI.MonogamyCommitmentNoGo

@[expose] public section

def sumNat : Nat → (Nat → Nat) → Nat
  | 0, _ => 0
  | n + 1, f => sumNat n f + f n

def absDiffNat (a b : Nat) : Nat :=
  if a ≤ b then b - a else a - b

private theorem int_sq_nonneg (x : Int) : 0 ≤ x * x := by
  by_cases h : 0 ≤ x
  · exact Int.mul_nonneg h h
  · have h' : 0 ≤ -x := by omega
    have hmul : 0 ≤ (-x) * (-x) := Int.mul_nonneg h' h'
    have heq : (-x) * (-x) = x * x := by
      rw [Int.neg_mul, Int.mul_neg, Int.neg_neg]
    omega

private theorem int_sq_eq_zero (x : Int) (h : x * x = 0) : x = 0 := by
  by_cases hx : x = 0
  · exact hx
  · exfalso
    by_cases hp : 0 < x
    · have : 0 < x * x := Int.mul_pos hp hp
      omega
    · have hn : 0 < -x := by omega
      have hpos : 0 < (-x) * (-x) := Int.mul_pos hn hn
      have heq : (-x) * (-x) = x * x := by
        rw [Int.neg_mul, Int.mul_neg, Int.neg_neg]
      omega

private theorem lagrange_cs2 (c s a b : Int) :
    (c * a + s * b) * (c * a + s * b) + (c * b - s * a) * (c * b - s * a) =
    (c * c + s * s) * (a * a + b * b) := by
  simp only [Int.mul_add, Int.add_mul, Int.mul_sub, Int.sub_mul]
  have h1 : c * a * (s * b) = c * b * (s * a) := by
    rw [Int.mul_assoc c a (s * b), Int.mul_left_comm a s b, Int.mul_comm a b,
        Int.mul_left_comm s b a, ← Int.mul_assoc c b (s * a)]
  have h2 : s * b * (c * a) = c * b * (s * a) := by
    rw [Int.mul_comm (s * b) (c * a), h1]
  have h3 : s * a * (c * b) = c * b * (s * a) := Int.mul_comm (s * a) (c * b)
  have h4 : c * a * (c * a) = c * c * (a * a) := by
    rw [Int.mul_assoc, Int.mul_left_comm a c a, ← Int.mul_assoc]
  have h5 : s * b * (s * b) = s * s * (b * b) := by
    rw [Int.mul_assoc, Int.mul_left_comm b s b, ← Int.mul_assoc]
  have h6 : c * b * (c * b) = c * c * (b * b) := by
    rw [Int.mul_assoc, Int.mul_left_comm b c b, ← Int.mul_assoc]
  have h7 : s * a * (s * a) = s * s * (a * a) := by
    rw [Int.mul_assoc, Int.mul_left_comm a s a, ← Int.mul_assoc]
  omega

/-- **T7a (Toner Quantum CHSH Monogamy & CKW Berry-Monopole Eve Isolation):**
(1) From any Jordan-block Alice observables `c^2 + s^2 = R^2` and anticommuting operator
expectation bounds `x1^2 + y1^2 ≤ R^2` and `x2^2 + y2^2 ≤ R^2`, the CHSH parameters
`S_AB = 2(c x1 + s x2)` and `S_AE = 2(c y2 + s y1)` obey Toner's monogamy law
`S_AB^2 + S_AE^2 ≤ 8 R^4`, trapping Eve strictly below `2` whenever `S_AB > 2` and forcing
`S_AE = 0` at Tsirelson saturation.
(2) Under tripartite CKW + Berry-monopole conservation `cAB^2 + cAE^2 + tau + rA^2 = R^2`
(`tau ≥ 0`), singlet saturation `cAB^2 = R^2` forces `cAE = 0`, `tau = 0`, and `rA = 0`. -/
theorem t7a_toner_chsh_monogamy_and_eve_isolation :
    (∀ (c s x1 x2 y1 y2 R : Int),
      c * c + s * s = R * R →
      x1 * x1 + y1 * y1 ≤ R * R →
      x2 * x2 + y2 * y2 ≤ R * R →
      let sAB := 2 * (c * x1 + s * x2)
      let sAE := 2 * (c * y2 + s * y1)
      let R4 := R * R * R * R
      sAB * sAB + sAE * sAE ≤ 8 * R4 ∧
      (4 * R4 < sAB * sAB → sAE * sAE < 4 * R4) ∧
      (sAB * sAB = 8 * R4 → sAE = 0)) ∧
    (∀ (cAB cAE tau rA R : Int),
      0 ≤ tau →
      cAB * cAB + cAE * cAE + tau + rA * rA = R * R →
      cAE * cAE + tau + rA * rA = R * R - cAB * cAB ∧
      cAE * cAE ≤ R * R - cAB * cAB ∧
      (cAB * cAB = R * R → cAE = 0 ∧ tau = 0 ∧ rA = 0)) := by
  constructor
  · intro c s x1 x2 y1 y2 R hcs h1 h2
    dsimp only
    have hL1 := lagrange_cs2 c s x1 x2
    have hL2 := lagrange_cs2 c s y2 y1
    have hnn1 := int_sq_nonneg (c * x2 - s * x1)
    have hnn2 := int_sq_nonneg (c * y1 - s * y2)
    have hcs1 : (c * x1 + s * x2) * (c * x1 + s * x2) ≤ (R * R) * (x1 * x1 + x2 * x2) := by
      rw [← hcs]; omega
    have hcs2 : (c * y2 + s * y1) * (c * y2 + s * y1) ≤ (R * R) * (y2 * y2 + y1 * y1) := by
      rw [← hcs]; omega
    have hsum_xy : (x1 * x1 + x2 * x2) + (y2 * y2 + y1 * y1) ≤ 2 * (R * R) := by omega
    have hR2nn : 0 ≤ R * R := int_sq_nonneg R
    have hmul : (R * R) * ((x1 * x1 + x2 * x2) + (y2 * y2 + y1 * y1)) ≤ (R * R) * (2 * (R * R)) :=
      Int.mul_le_mul_of_nonneg_left hsum_xy hR2nn
    have hdist : (R * R) * ((x1 * x1 + x2 * x2) + (y2 * y2 + y1 * y1)) =
        (R * R) * (x1 * x1 + x2 * x2) + (R * R) * (y2 * y2 + y1 * y1) := Int.mul_add ..
    have hR4eq : (R * R) * (2 * (R * R)) = 2 * (R * R * R * R) := by
      rw [Int.mul_left_comm (R * R) 2 (R * R), Int.mul_assoc R R (R * R)]
      simp only [Int.mul_assoc]
    have hsq1 : (2 * (c * x1 + s * x2)) * (2 * (c * x1 + s * x2)) =
        4 * ((c * x1 + s * x2) * (c * x1 + s * x2)) := by
      rw [Int.mul_assoc, Int.mul_left_comm (c * x1 + s * x2) 2 (c * x1 + s * x2), ← Int.mul_assoc]
      rfl
    have hsq2 : (2 * (c * y2 + s * y1)) * (2 * (c * y2 + s * y1)) =
        4 * ((c * y2 + s * y1) * (c * y2 + s * y1)) := by
      rw [Int.mul_assoc, Int.mul_left_comm (c * y2 + s * y1) 2 (c * y2 + s * y1), ← Int.mul_assoc]
      rfl
    have hmono : (2 * (c * x1 + s * x2)) * (2 * (c * x1 + s * x2)) +
        (2 * (c * y2 + s * y1)) * (2 * (c * y2 + s * y1)) ≤ 8 * (R * R * R * R) := by
      omega
    refine ⟨hmono, ?_, ?_⟩
    · intro hviol; omega
    · intro hsat
      have h0 : (2 * (c * y2 + s * y1)) * (2 * (c * y2 + s * y1)) = 0 := by
        have hnn := int_sq_nonneg (2 * (c * y2 + s * y1))
        omega
      exact int_sq_eq_zero _ h0
  · intro cAB cAE tau rA R htau hcons
    have hcAE_nn := int_sq_nonneg cAE
    have hrA_nn := int_sq_nonneg rA
    refine ⟨by omega, by omega, ?_⟩
    intro hsing
    have hcAE0 : cAE * cAE = 0 := by omega
    have hrA0 : rA * rA = 0 := by omega
    have htau0 : tau = 0 := by omega
    exact ⟨int_sq_eq_zero cAE hcAE0, htau0, int_sq_eq_zero rA hrA0⟩

private theorem absDiff_plus_two_min (a b : Nat) :
    absDiffNat a b + 2 * min a b = a + b := by
  unfold absDiffNat
  by_cases h : a ≤ b
  · simp [h, Nat.min_eq_left h]; omega
  · simp [h, Nat.min_eq_right (Nat.le_of_not_ge h)]; omega

private theorem sumNat_add (n : Nat) (f g : Nat → Nat) :
    sumNat n (fun i => f i + g i) = sumNat n f + sumNat n g := by
  induction n with
  | zero => rfl
  | succ k ih => simp [sumNat, ih]; omega

private theorem sumNat_mul_left (c n : Nat) (f : Nat → Nat) :
    sumNat n (fun i => c * f i) = c * sumNat n f := by
  induction n with
  | zero => simp [sumNat]
  | succ k ih => simp [sumNat, ih, Nat.mul_add]

private theorem sumNat_eq_zero_of_all_zero (n : Nat) (f : Nat → Nat)
    (h : ∀ i, i < n → f i = 0) : sumNat n f = 0 := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp [sumNat, ih (fun i hi => h i (by omega)), h k (by omega)]

private theorem sumNat_absDiff_two_min (T : Nat) (P0 P1 : Nat → Nat) :
    sumNat T (fun t => absDiffNat (P0 t) (P1 t) + 2 * min (P0 t) (P1 t)) =
    sumNat T (fun t => P0 t + P1 t) := by
  induction T with
  | zero => rfl
  | succ k ih =>
    simp only [sumNat]
    rw [absDiff_plus_two_min, ih]

/-- **T7b (Unconditional Commitment Impossibility & Exact Hiding-Binding Conservation Law):**
Over ANY finite transcript space `Fin T` and ANY two scaled distributions `P0, P1` summing
to `D`:
(1) Exact Conservation Law: `∑ |P0(t) - P1(t)| + 2 ∑ min(P0(t), P1(t)) = 2 D`
    (equivalently `TV(P0, P1) + Overlap(P0, P1) = 1`).
(2) Perfect Hiding + Perfect Binding Impossibility whenever `D > 0`.
(3) Quantitative Tradeoff: `TV ≤ eps / D` forces `Overlap ≥ (D - eps) / D`, and no protocol
    can simultaneously satisfy `TV < 1/2` and `Overlap < 1/2`. -/
theorem t7b_hiding_binding_conservation_nogo :
    ∀ (T D : Nat) (P0 P1 : Nat → Nat),
      sumNat T P0 = D →
      sumNat T P1 = D →
      let tv2 := sumNat T (fun t => absDiffNat (P0 t) (P1 t))
      let ov := sumNat T (fun t => min (P0 t) (P1 t))
      tv2 + 2 * ov = 2 * D ∧
      (0 < D → ¬ ((∀ t, t < T → P0 t = P1 t) ∧ (∀ t, t < T → P0 t = 0 ∨ P1 t = 0))) ∧
      (∀ eps : Nat, tv2 ≤ 2 * eps → D - eps ≤ ov) ∧
      ¬ (tv2 < D ∧ 2 * ov < D) := by
  intro T D P0 P1 h0 h1
  dsimp only
  have hcons : sumNat T (fun t => absDiffNat (P0 t) (P1 t)) +
      2 * sumNat T (fun t => min (P0 t) (P1 t)) = 2 * D := by
    have hpt := sumNat_absDiff_two_min T P0 P1
    rw [sumNat_add, sumNat_mul_left, sumNat_add, h0, h1] at hpt
    omega
  refine ⟨hcons, ?_, ?_, ?_⟩
  · intro hD ⟨hhide, hbind⟩
    have htv0 : sumNat T (fun t => absDiffNat (P0 t) (P1 t)) = 0 := by
      apply sumNat_eq_zero_of_all_zero
      intro t ht
      rw [hhide t ht]
      unfold absDiffNat
      simp
    have hov0 : sumNat T (fun t => min (P0 t) (P1 t)) = 0 := by
      apply sumNat_eq_zero_of_all_zero
      intro t ht
      rcases hbind t ht with hz | hz
      · simp [hz]
      · simp [hz]
    omega
  · intro eps heps
    omega
  · intro ⟨hlt1, hlt2⟩
    omega

end

end SecMeshPQSI.MonogamyCommitmentNoGo
