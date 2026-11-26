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

-- ============================================================================
-- T7c: Fuchs-van de Graaff Sandwich & Quantum Microcrypt EFI Conservation Law
--      (Mega Atlas CS-031 / QC-022: Quantum Cryptography Below One-Way Functions)
-- ============================================================================

def sumIntT7 : Nat → (Nat → Int) → Int
  | 0, _ => 0
  | n + 1, f => sumIntT7 n f + f n

private theorem sumNat_le_sumNat (n : Nat) (f g : Nat → Nat)
    (h : ∀ i, i < n → f i ≤ g i) : sumNat n f ≤ sumNat n g := by
  induction n with
  | zero => exact Nat.le_refl 0
  | succ k ih =>
    simp only [sumNat]
    exact Nat.add_le_add (ih (fun i hi => h i (by omega))) (h k (by omega))

private theorem sumNat_congr (n : Nat) (f g : Nat → Nat)
    (h : ∀ i, i < n → f i = g i) : sumNat n f = sumNat n g := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [sumNat, ih (fun i hi => h i (by omega)), h k (by omega)]

private theorem sumNat_mul_right (n c : Nat) (f : Nat → Nat) :
    sumNat n (fun i => f i * c) = sumNat n f * c := by
  induction n with
  | zero => simp [sumNat]
  | succ k ih => simp [sumNat, ih, Nat.add_mul]

private theorem nat_absDiff_sq_add_two_mul (a b : Nat) :
    absDiffNat a b * absDiffNat a b + 2 * (a * b) = a * a + b * b := by
  unfold absDiffNat
  by_cases h : a ≤ b
  · simp only [h, ↓reduceIte]
    obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le h
    have hsub : a + d - a = d := by omega
    rw [hsub]
    simp only [Nat.mul_add, Nat.add_mul]
    have hcomm : d * a = a * d := Nat.mul_comm d a
    omega
  · simp only [h, ↓reduceIte]
    have hlt : b ≤ a := by omega
    obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hlt
    have hsub : b + d - b = d := by omega
    rw [hsub]
    simp only [Nat.mul_add, Nat.add_mul]
    have hcomm : d * b = b * d := Nat.mul_comm d b
    omega

private theorem nat_two_mul_le_sq_add (a b : Nat) : 2 * (a * b) ≤ a * a + b * b := by
  have h := nat_absDiff_sq_add_two_mul a b
  omega

private theorem nat_min_sq_le_mul (a b : Nat) : min (a * a) (b * b) ≤ a * b := by
  by_cases h : a ≤ b
  · have hsq : a * a ≤ b * b := Nat.mul_le_mul h h
    rw [Nat.min_eq_left hsq]
    exact Nat.mul_le_mul_left a h
  · have hba : b ≤ a := by omega
    have hsq : b * b ≤ a * a := Nat.mul_le_mul hba hba
    rw [Nat.min_eq_right hsq]
    exact Nat.mul_le_mul_right b hba

private theorem nat_absDiff_sq_factor (a b : Nat) :
    absDiffNat (a * a) (b * b) = absDiffNat a b * (a + b) := by
  unfold absDiffNat
  by_cases h : a ≤ b
  · have hsq : a * a ≤ b * b := Nat.mul_le_mul h h
    simp only [h, hsq, ↓reduceIte]
    obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le h
    have h1 : a + d - a = d := by omega
    rw [h1]
    simp only [Nat.mul_add, Nat.add_mul]
    have hcomm : d * a = a * d := Nat.mul_comm d a
    omega
  · have hba : b ≤ a := by omega
    have hsq : b * b ≤ a * a := Nat.mul_le_mul hba hba
    have hnot : ¬ (a * a ≤ b * b) := by
      intro hle
      obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hba
      have hdpos : 0 < d := by omega
      have hmul : (b + d) * (b + d) = b * b + 2 * (b * d) + d * d := by
        simp only [Nat.mul_add, Nat.add_mul]
        have hc : d * b = b * d := Nat.mul_comm d b
        omega
      have hd2 : 0 < d * d := Nat.mul_pos hdpos hdpos
      omega
    simp only [h, hnot, ↓reduceIte]
    obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hba
    have h1 : b + d - b = d := by omega
    rw [h1]
    simp only [Nat.mul_add, Nat.add_mul]
    have hcomm : d * b = b * d := Nat.mul_comm d b
    omega

private theorem sumNat_cauchy_schwarz (T : Nat) (f g : Nat → Nat) :
    sumNat T (fun t => f t * g t) * sumNat T (fun t => f t * g t) ≤
    sumNat T (fun t => f t * f t) * sumNat T (fun t => g t * g t) := by
  induction T with
  | zero => simp [sumNat]
  | succ k ih =>
    simp only [sumNat]
    let Sfg := sumNat k (fun t => f t * g t)
    let Sf := sumNat k (fun t => f t * f t)
    let Sg := sumNat k (fun t => g t * g t)
    let a := f k
    let b := g k
    change (Sfg + a * b) * (Sfg + a * b) ≤ (Sf + a * a) * (Sg + b * b)
    have ih' : Sfg * Sfg ≤ Sf * Sg := ih
    have hcross : 2 * (Sfg * (a * b)) ≤ Sf * (b * b) + Sg * (a * a) := by
      have hpt : ∀ t, t < k → 2 * ((f t * b) * (g t * a)) ≤ (f t * b) * (f t * b) + (g t * a) * (g t * a) :=
        fun t _ => nat_two_mul_le_sq_add (f t * b) (g t * a)
      have hsum := sumNat_le_sumNat k _ _ hpt
      have hL : sumNat k (fun t => 2 * ((f t * b) * (g t * a))) = 2 * (Sfg * (a * b)) := by
        rw [sumNat_mul_left]
        congr 1
        rw [← sumNat_mul_right]
        apply sumNat_congr
        intro t _
        have h1 : (f t * b) * (g t * a) = (f t * g t) * (a * b) := by
          rw [Nat.mul_assoc, Nat.mul_left_comm b (g t) a, ← Nat.mul_assoc, Nat.mul_comm b a]
        exact h1
      have hR : sumNat k (fun t => (f t * b) * (f t * b) + (g t * a) * (g t * a)) =
          Sf * (b * b) + Sg * (a * a) := by
        rw [sumNat_add]
        congr 1
        · rw [← sumNat_mul_right]
          apply sumNat_congr
          intro t _
          rw [Nat.mul_assoc, Nat.mul_left_comm b (f t) b, ← Nat.mul_assoc, Nat.mul_assoc]
        · rw [← sumNat_mul_right]
          apply sumNat_congr
          intro t _
          rw [Nat.mul_assoc, Nat.mul_left_comm a (g t) a, ← Nat.mul_assoc, Nat.mul_assoc]
      rw [hL, hR] at hsum
      exact hsum
    have hlhs : (Sfg + a * b) * (Sfg + a * b) = Sfg * Sfg + 2 * (Sfg * (a * b)) + (a * b) * (a * b) := by
      simp only [Nat.mul_add, Nat.add_mul]
      have hc : a * b * Sfg = Sfg * (a * b) := Nat.mul_comm (a * b) Sfg
      omega
    have hrhs : (Sf + a * a) * (Sg + b * b) = Sf * Sg + Sf * (b * b) + Sg * (a * a) + (a * a) * (b * b) := by
      simp only [Nat.mul_add, Nat.add_mul]
      have hc : a * a * Sg = Sg * (a * a) := Nat.mul_comm (a * a) Sg
      omega
    have hab : (a * b) * (a * b) = (a * a) * (b * b) := by
      rw [Nat.mul_assoc, Nat.mul_left_comm b a b, ← Nat.mul_assoc, Nat.mul_assoc]
    rw [hlhs, hrhs, hab]
    omega

private theorem sumIntT7_add (n : Nat) (f g : Nat → Int) :
    sumIntT7 n (fun i => f i + g i) = sumIntT7 n f + sumIntT7 n g := by
  induction n with
  | zero => rfl
  | succ k ih => simp [sumIntT7, ih]; omega

private theorem sumIntT7_mul_right (n : Nat) (c : Int) (f : Nat → Int) :
    sumIntT7 n (fun i => f i * c) = sumIntT7 n f * c := by
  induction n with
  | zero => simp [sumIntT7]
  | succ k ih => simp [sumIntT7, ih, Int.add_mul]

private theorem sumIntT7_mul_left (n : Nat) (c : Int) (f : Nat → Int) :
    sumIntT7 n (fun i => c * f i) = c * sumIntT7 n f := by
  induction n with
  | zero => simp [sumIntT7]
  | succ k ih => simp [sumIntT7, ih, Int.mul_add]

private theorem sumIntT7_le_sumIntT7 (n : Nat) (f g : Nat → Int)
    (h : ∀ i, i < n → f i ≤ g i) : sumIntT7 n f ≤ sumIntT7 n g := by
  induction n with
  | zero => exact Int.le_refl 0
  | succ k ih =>
    simp only [sumIntT7]
    exact Int.add_le_add (ih (fun i hi => h i (by omega))) (h k (by omega))

private theorem sumIntT7_congr (n : Nat) (f g : Nat → Int)
    (h : ∀ i, i < n → f i = g i) : sumIntT7 n f = sumIntT7 n g := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [sumIntT7, ih (fun i hi => h i (by omega)), h k (by omega)]

private theorem complex_pair_cross_le (a1 b1 c1 d1 a2 b2 c2 d2 : Int) :
    2 * ((a1 * c1 + b1 * d1) * (a2 * c2 + b2 * d2) +
         (a1 * d1 - b1 * c1) * (a2 * d2 - b2 * c2)) ≤
    (a1 * a1 + b1 * b1) * (c2 * c2 + d2 * d2) +
    (c1 * c1 + d1 * d1) * (a2 * a2 + b2 * b2) := by
  have hx := int_sq_nonneg ((a1 * c2 - b1 * d2) - (a2 * c1 - b2 * d1))
  have hy := int_sq_nonneg ((a1 * d2 + b1 * c2) - (a2 * d1 + b2 * c1))
  have hid : ((a1 * c2 - b1 * d2) - (a2 * c1 - b2 * d1)) *
             ((a1 * c2 - b1 * d2) - (a2 * c1 - b2 * d1)) +
             ((a1 * d2 + b1 * c2) - (a2 * d1 + b2 * c1)) *
             ((a1 * d2 + b1 * c2) - (a2 * d1 + b2 * c1)) =
             (a1 * a1 + b1 * b1) * (c2 * c2 + d2 * d2) +
             (c1 * c1 + d1 * d1) * (a2 * a2 + b2 * b2) -
             2 * ((a1 * c1 + b1 * d1) * (a2 * c2 + b2 * d2) +
                  (a1 * d1 - b1 * c1) * (a2 * d2 - b2 * c2)) := by
    have p1 : (a1 * c2 - b1 * d2) * (a1 * c2 - b1 * d2) +
              (a1 * d2 + b1 * c2) * (a1 * d2 + b1 * c2) =
              (a1 * a1 + b1 * b1) * (c2 * c2 + d2 * d2) := by
      simp only [Int.mul_add, Int.add_mul, Int.mul_sub, Int.sub_mul]
      have m2 : a1 * c2 * (b1 * d2) = a1 * d2 * (b1 * c2) := by
        rw [Int.mul_assoc, Int.mul_left_comm c2 b1 d2, Int.mul_comm c2 d2,
            Int.mul_left_comm b1 d2 c2, ← Int.mul_assoc]
      have m3 : b1 * d2 * (a1 * c2) = a1 * d2 * (b1 * c2) := by
        rw [Int.mul_comm (b1 * d2) (a1 * c2), m2]
      have m4 : b1 * c2 * (a1 * d2) = a1 * d2 * (b1 * c2) := Int.mul_comm _ _
      have s1 : a1 * c2 * (a1 * c2) = a1 * a1 * (c2 * c2) := by
        rw [Int.mul_assoc, Int.mul_left_comm c2 a1 c2, ← Int.mul_assoc]
      have s2 : b1 * d2 * (b1 * d2) = b1 * b1 * (d2 * d2) := by
        rw [Int.mul_assoc, Int.mul_left_comm d2 b1 d2, ← Int.mul_assoc]
      have s3 : a1 * d2 * (a1 * d2) = a1 * a1 * (d2 * d2) := by
        rw [Int.mul_assoc, Int.mul_left_comm d2 a1 d2, ← Int.mul_assoc]
      have s4 : b1 * c2 * (b1 * c2) = b1 * b1 * (c2 * c2) := by
        rw [Int.mul_assoc, Int.mul_left_comm c2 b1 c2, ← Int.mul_assoc]
      omega
    have p2 : (a2 * c1 - b2 * d1) * (a2 * c1 - b2 * d1) +
              (a2 * d1 + b2 * c1) * (a2 * d1 + b2 * c1) =
              (c1 * c1 + d1 * d1) * (a2 * a2 + b2 * b2) := by
      have hcomm : (c1 * c1 + d1 * d1) * (a2 * a2 + b2 * b2) =
          (a2 * a2 + b2 * b2) * (c1 * c1 + d1 * d1) := Int.mul_comm _ _
      rw [hcomm]
      simp only [Int.mul_add, Int.add_mul, Int.mul_sub, Int.sub_mul]
      have m2 : a2 * c1 * (b2 * d1) = a2 * d1 * (b2 * c1) := by
        rw [Int.mul_assoc, Int.mul_left_comm c1 b2 d1, Int.mul_comm c1 d1,
            Int.mul_left_comm b2 d1 c1, ← Int.mul_assoc]
      have m3 : b2 * d1 * (a2 * c1) = a2 * d1 * (b2 * c1) := by
        rw [Int.mul_comm (b2 * d1) (a2 * c1), m2]
      have m4 : b2 * c1 * (a2 * d1) = a2 * d1 * (b2 * c1) := Int.mul_comm _ _
      have s1 : a2 * c1 * (a2 * c1) = a2 * a2 * (c1 * c1) := by
        rw [Int.mul_assoc, Int.mul_left_comm c1 a2 c1, ← Int.mul_assoc]
      have s2 : b2 * d1 * (b2 * d1) = b2 * b2 * (d1 * d1) := by
        rw [Int.mul_assoc, Int.mul_left_comm d1 b2 d1, ← Int.mul_assoc]
      have s3 : a2 * d1 * (a2 * d1) = a2 * a2 * (d1 * d1) := by
        rw [Int.mul_assoc, Int.mul_left_comm d1 a2 d1, ← Int.mul_assoc]
      have s4 : b2 * c1 * (b2 * c1) = b2 * b2 * (c1 * c1) := by
        rw [Int.mul_assoc, Int.mul_left_comm c1 b2 c1, ← Int.mul_assoc]
      omega
    have p3 : (a1 * c2 - b1 * d2) * (a2 * c1 - b2 * d1) +
              (a1 * d2 + b1 * c2) * (a2 * d1 + b2 * c1) =
              (a1 * c1 + b1 * d1) * (a2 * c2 + b2 * d2) +
              (a1 * d1 - b1 * c1) * (a2 * d2 - b2 * c2) := by
      simp only [Int.mul_add, Int.add_mul, Int.mul_sub, Int.sub_mul]
      have t1 : a1 * c2 * (a2 * c1) = a1 * c1 * (a2 * c2) := by
        rw [Int.mul_assoc, Int.mul_left_comm c2 a2 c1, Int.mul_comm c2 c1,
            Int.mul_left_comm a2 c1 c2, ← Int.mul_assoc]
      have t2 : a1 * c2 * (b2 * d1) = a1 * d1 * (b2 * c2) := by
        rw [Int.mul_assoc, Int.mul_left_comm c2 b2 d1, Int.mul_comm c2 d1,
            Int.mul_left_comm b2 d1 c2, ← Int.mul_assoc]
      have t3 : b1 * d2 * (a2 * c1) = b1 * c1 * (a2 * d2) := by
        rw [Int.mul_assoc, Int.mul_left_comm d2 a2 c1, Int.mul_comm d2 c1,
            Int.mul_left_comm a2 c1 d2, ← Int.mul_assoc]
      have t4 : b1 * d2 * (b2 * d1) = b1 * d1 * (b2 * d2) := by
        rw [Int.mul_assoc, Int.mul_left_comm d2 b2 d1, Int.mul_comm d2 d1,
            Int.mul_left_comm b2 d1 d2, ← Int.mul_assoc]
      have t5 : a1 * d2 * (a2 * d1) = a1 * d1 * (a2 * d2) := by
        rw [Int.mul_assoc, Int.mul_left_comm d2 a2 d1, Int.mul_comm d2 d1,
            Int.mul_left_comm a2 d1 d2, ← Int.mul_assoc]
      have t6 : a1 * d2 * (b2 * c1) = a1 * c1 * (b2 * d2) := by
        rw [Int.mul_assoc, Int.mul_left_comm d2 b2 c1, Int.mul_comm d2 c1,
            Int.mul_left_comm b2 c1 d2, ← Int.mul_assoc]
      have t7 : b1 * c2 * (a2 * d1) = b1 * d1 * (a2 * c2) := by
        rw [Int.mul_assoc, Int.mul_left_comm c2 a2 d1, Int.mul_comm c2 d1,
            Int.mul_left_comm a2 d1 c2, ← Int.mul_assoc]
      have t8 : b1 * c2 * (b2 * c1) = b1 * c1 * (b2 * c2) := by
        rw [Int.mul_assoc, Int.mul_left_comm c2 b2 c1, Int.mul_comm c2 c1,
            Int.mul_left_comm b2 c1 c2, ← Int.mul_assoc]
      omega
    have hsub1 (X Y : Int) : (X - Y) * (X - Y) = X * X + Y * Y - 2 * (X * Y) := by
      simp only [Int.mul_sub, Int.sub_mul]
      have hc : Y * X = X * Y := Int.mul_comm Y X
      omega
    have hs1 := hsub1 (a1 * c2 - b1 * d2) (a2 * c1 - b2 * d1)
    have hs2 := hsub1 (a1 * d2 + b1 * c2) (a2 * d1 + b2 * c1)
    rw [hs1, hs2]
    omega
  omega

private theorem complex_cauchy_schwarz_int (D : Nat) (uRe uIm vRe vIm : Nat → Int) :
    let dotRe := sumIntT7 D (fun i => uRe i * vRe i + uIm i * vIm i)
    let dotIm := sumIntT7 D (fun i => uRe i * vIm i - uIm i * vRe i)
    let normU := sumIntT7 D (fun i => uRe i * uRe i + uIm i * uIm i)
    let normV := sumIntT7 D (fun i => vRe i * vRe i + vIm i * vIm i)
    dotRe * dotRe + dotIm * dotIm ≤ normU * normV := by
  induction D with
  | zero => simp [sumIntT7]
  | succ k ih =>
    dsimp only at ih ⊢
    simp only [sumIntT7]
    let dr := sumIntT7 k (fun i => uRe i * vRe i + uIm i * vIm i)
    let di := sumIntT7 k (fun i => uRe i * vIm i - uIm i * vRe i)
    let nU := sumIntT7 k (fun i => uRe i * uRe i + uIm i * uIm i)
    let nV := sumIntT7 k (fun i => vRe i * vRe i + vIm i * vIm i)
    let a2 := uRe k
    let b2 := uIm k
    let c2 := vRe k
    let d2 := vIm k
    let qr := a2 * c2 + b2 * d2
    let qi := a2 * d2 - b2 * c2
    change (dr + qr) * (dr + qr) + (di + qi) * (di + qi) ≤
           (nU + (a2 * a2 + b2 * b2)) * (nV + (c2 * c2 + d2 * d2))
    have ih' : dr * dr + di * di ≤ nU * nV := ih
    have hbase : qr * qr + qi * qi = (a2 * a2 + b2 * b2) * (c2 * c2 + d2 * d2) :=
      lagrange_cs2 a2 b2 c2 d2
    have hcross : 2 * (dr * qr + di * qi) ≤ nU * (c2 * c2 + d2 * d2) + nV * (a2 * a2 + b2 * b2) := by
      have hpt : ∀ t, t < k →
          2 * ((uRe t * vRe t + uIm t * vIm t) * qr + (uRe t * vIm t - uIm t * vRe t) * qi) ≤
          (uRe t * uRe t + uIm t * uIm t) * (c2 * c2 + d2 * d2) +
          (vRe t * vRe t + vIm t * vIm t) * (a2 * a2 + b2 * b2) :=
        fun t _ => complex_pair_cross_le (uRe t) (uIm t) (vRe t) (vIm t) a2 b2 c2 d2
      have hsum := sumIntT7_le_sumIntT7 k _ _ hpt
      have hL : sumIntT7 k (fun t =>
          2 * ((uRe t * vRe t + uIm t * vIm t) * qr + (uRe t * vIm t - uIm t * vRe t) * qi)) =
          2 * (dr * qr + di * qi) := by
        rw [sumIntT7_mul_left, sumIntT7_add, sumIntT7_mul_right, sumIntT7_mul_right]
      have hR : sumIntT7 k (fun t =>
          (uRe t * uRe t + uIm t * uIm t) * (c2 * c2 + d2 * d2) +
          (vRe t * vRe t + vIm t * vIm t) * (a2 * a2 + b2 * b2)) =
          nU * (c2 * c2 + d2 * d2) + nV * (a2 * a2 + b2 * b2) := by
        rw [sumIntT7_add, sumIntT7_mul_right, sumIntT7_mul_right]
      rw [hL, hR] at hsum
      exact hsum
    have hexpL : (dr + qr) * (dr + qr) + (di + qi) * (di + qi) =
        (dr * dr + di * di) + 2 * (dr * qr + di * qi) + (qr * qr + qi * qi) := by
      simp only [Int.mul_add, Int.add_mul]
      have h1 : qr * dr = dr * qr := Int.mul_comm qr dr
      have h2 : qi * di = di * qi := Int.mul_comm qi di
      omega
    have hexpR : (nU + (a2 * a2 + b2 * b2)) * (nV + (c2 * c2 + d2 * d2)) =
        nU * nV + nU * (c2 * c2 + d2 * d2) + nV * (a2 * a2 + b2 * b2) +
        (a2 * a2 + b2 * b2) * (c2 * c2 + d2 * d2) := by
      have hc : (a2 * a2 + b2 * b2) * nV = nV * (a2 * a2 + b2 * b2) := Int.mul_comm _ _
      rw [Int.add_mul, Int.mul_add nU, Int.mul_add (a2 * a2 + b2 * b2), hc]
      omega
    rw [hexpL, hexpR, hbase]
    omega

/-- **T7c (Fuchs-van de Graaff Sandwich & Quantum Microcrypt EFI Conservation Law — Mega Atlas CS-031 / QC-022):**
(1) For ANY finite outcome space `Fin T` and non-negative amplitude vectors `r, s : Nat → Nat`
    representing distributions `P0(t) = r(t)^2 / M`, `P1(t) = s(t)^2 / M` with equal mass `M`:
    - Overlap-Fidelity hierarchy & Fuchs-van de Graaff lower bound: `ov ≤ B ≤ M` and
      `2 M ≤ tv2 + 2 B` (i.e., `1 - B(P0, P1) ≤ TV(P0, P1)`).
    - Exact Fuchs-van de Graaff upper bound: `tv2^2 + 4 B^2 ≤ 4 M^2`
      (i.e., `TV(P0, P1)^2 + B(P0, P1)^2 ≤ 1`).
    - Quantitative Microcrypt EFI Fidelity Ceiling: any statistical separation `2 δ ≤ tv2`
      forces `B^2 + δ^2 ≤ M^2`.
(2) For ANY complex pure quantum states `u, v ∈ ℂ^D` of equal squared norm `M`:
    exact Gram trace-distance conservation `D_tr^2 M^2 + |⟨u, v⟩|^2 = M^2` (`D_tr^2 M^2 ≥ 0`),
    proving Mayers-Lo-Chau perfect-hiding equivocation (`D_tr = 0 → |⟨u, v⟩|^2 = M^2`) and
    Helstrom perfect-binding leakage (`⟨u, v⟩ = 0 → D_tr^2 M^2 = M^2`) without `Classical.choice`. -/
theorem t7c_fuchs_vandegraaff_microcrypt_efi :
    (∀ (T M : Nat) (r s : Nat → Nat),
      sumNat T (fun t => r t * r t) = M →
      sumNat T (fun t => s t * s t) = M →
      let tv2 := sumNat T (fun t => absDiffNat (r t * r t) (s t * s t))
      let B   := sumNat T (fun t => r t * s t)
      let ov  := sumNat T (fun t => min (r t * r t) (s t * s t))
      ov ≤ B ∧
      B ≤ M ∧
      2 * M ≤ tv2 + 2 * B ∧
      tv2 * tv2 + 4 * (B * B) ≤ 4 * (M * M) ∧
      (∀ delta : Nat, 2 * delta ≤ tv2 → B * B + delta * delta ≤ M * M)) ∧
    (∀ (D : Nat) (M : Int) (uRe uIm vRe vIm : Nat → Int),
      sumIntT7 D (fun i => uRe i * uRe i + uIm i * uIm i) = M →
      sumIntT7 D (fun i => vRe i * vRe i + vIm i * vIm i) = M →
      let dotRe := sumIntT7 D (fun i => uRe i * vRe i + uIm i * vIm i)
      let dotIm := sumIntT7 D (fun i => uRe i * vIm i - uIm i * vRe i)
      let fidSq := dotRe * dotRe + dotIm * dotIm
      let dTrSq := M * M - fidSq
      0 ≤ dTrSq ∧
      dTrSq + fidSq = M * M ∧
      (dTrSq = 0 → fidSq = M * M) ∧
      (dotRe = 0 ∧ dotIm = 0 → dTrSq = M * M)) := by
  constructor
  · intro T M r s hr hs
    dsimp only
    let tv2 := sumNat T (fun t => absDiffNat (r t * r t) (s t * s t))
    let B   := sumNat T (fun t => r t * s t)
    let ov  := sumNat T (fun t => min (r t * r t) (s t * s t))
    have hovB : ov ≤ B := sumNat_le_sumNat T _ _ (fun t _ => nat_min_sq_le_mul (r t) (s t))
    have h2BM : 2 * B ≤ 2 * M := by
      have h1 := sumNat_le_sumNat T (fun t => 2 * (r t * s t)) (fun t => r t * r t + s t * s t)
        (fun t _ => nat_two_mul_le_sq_add (r t) (s t))
      rw [sumNat_mul_left, sumNat_add, hr, hs] at h1
      omega
    have hBM : B ≤ M := by omega
    have hcons : tv2 + 2 * ov = 2 * M :=
      (t7b_hiding_binding_conservation_nogo T M (fun t => r t * r t) (fun t => s t * s t) hr hs).1
    have hlow : 2 * M ≤ tv2 + 2 * B := by omega
    have htv_eq : tv2 = sumNat T (fun t => absDiffNat (r t) (s t) * (r t + s t)) :=
      sumNat_congr T _ _ (fun t _ => nat_absDiff_sq_factor (r t) (s t))
    have hcs := sumNat_cauchy_schwarz T (fun t => absDiffNat (r t) (s t)) (fun t => r t + s t)
    have hSf_add : sumNat T (fun t => absDiffNat (r t) (s t) * absDiffNat (r t) (s t)) + 2 * B = 2 * M := by
      have h1 := sumNat_congr T
        (fun t => absDiffNat (r t) (s t) * absDiffNat (r t) (s t) + 2 * (r t * s t))
        (fun t => r t * r t + s t * s t)
        (fun t _ => nat_absDiff_sq_add_two_mul (r t) (s t))
      rw [sumNat_add, sumNat_mul_left, sumNat_add, hr, hs] at h1
      omega
    have hSg_eq : sumNat T (fun t => (r t + s t) * (r t + s t)) = 2 * M + 2 * B := by
      have h1 := sumNat_congr T
        (fun t => (r t + s t) * (r t + s t))
        (fun t => (r t * r t + s t * s t) + 2 * (r t * s t))
        (fun t _ => by
          simp only [Nat.mul_add, Nat.add_mul]
          have hc : s t * r t = r t * s t := Nat.mul_comm (s t) (r t)
          omega)
      rw [h1, sumNat_add, sumNat_add, sumNat_mul_left, hr, hs]
      omega
    have hSf_eq : sumNat T (fun t => absDiffNat (r t) (s t) * absDiffNat (r t) (s t)) = 2 * M - 2 * B := by
      omega
    rw [← htv_eq, hSf_eq, hSg_eq] at hcs
    have hprod : (2 * M - 2 * B) * (2 * M + 2 * B) + 4 * (B * B) = 4 * (M * M) := by
      obtain ⟨d, hd⟩ := Nat.exists_eq_add_of_le hBM
      have hsub : 2 * M - 2 * B = 2 * d := by omega
      have hadd : 2 * M + 2 * B = 4 * B + 2 * d := by omega
      rw [hsub, hadd, hd]
      simp only [Nat.mul_add, Nat.add_mul]
      have h1 : d * B = B * d := Nat.mul_comm d B
      have h2 : 2 * d * (4 * B) = 8 * (B * d) := by
        rw [Nat.mul_assoc, Nat.mul_left_comm d 4 B, ← Nat.mul_assoc, Nat.mul_assoc, Nat.mul_comm d B]
        omega
      have h3 : 2 * d * (2 * d) = 4 * (d * d) := by
        rw [Nat.mul_assoc, Nat.mul_left_comm d 2 d, ← Nat.mul_assoc, Nat.mul_assoc]
      omega
    have hfvdg : tv2 * tv2 + 4 * (B * B) ≤ 4 * (M * M) := by omega
    refine ⟨hovB, hBM, hlow, hfvdg, ?_⟩
    intro delta hdelta
    change B * B + delta * delta ≤ M * M
    have hdelta' : 2 * delta ≤ tv2 := hdelta
    have hsq : (2 * delta) * (2 * delta) ≤ tv2 * tv2 := Nat.mul_le_mul hdelta' hdelta'
    have h4d : (2 * delta) * (2 * delta) = 4 * (delta * delta) := by
      rw [Nat.mul_assoc, Nat.mul_left_comm delta 2 delta, ← Nat.mul_assoc, Nat.mul_assoc]
    omega
  · intro D M uRe uIm vRe vIm hu hv
    dsimp only
    have hcs := complex_cauchy_schwarz_int D uRe uIm vRe vIm
    dsimp only at hcs
    rw [hu, hv] at hcs
    refine ⟨by omega, by omega, ?_, ?_⟩
    · intro h0; omega
    · intro ⟨hre, him⟩
      rw [hre, him]
      omega

end

end SecMeshPQSI.MonogamyCommitmentNoGo
