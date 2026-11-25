module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

public import SecMeshPQSI
public import Solution

/-!
# Palomar Comparator Solution (`secmesh-pqsi`)

Complete zero-`sorry` implementation of all 21 Palomar Registry Comparator theorems (`T1a`–`T5d`),
discharged directly from the verified `SecMeshPQSI.*` proof library.
The definition block matches `PalomarChallenge.lean` verbatim.
-/

namespace SecMeshPQSI.Palomar

@[expose] public section

-- ============================================================================
-- Verbatim Definition Block Matching PalomarChallenge.lean
-- ============================================================================

def v1ExpectedChshNum : Nat := 354
def v1ExpectedChshDen : Nat := 125

def popcount8 (x : Nat) : Nat :=
  (x % 2) + ((x / 2) % 2) + ((x / 4) % 2) + ((x / 8) % 2) +
  ((x / 16) % 2) + ((x / 32) % 2) + ((x / 64) % 2) + ((x / 128) % 2)

def countBelow (p : Nat → Bool) : Nat → Nat
  | 0 => 0
  | n + 1 => countBelow p n + (if p n then 1 else 0)

def bxor {n : Nat} (a b : Fin n → Bool) : Fin n → Bool :=
  fun i => xor (a i) (b i)

def xorList {n : Nat} : List (Fin n → Bool) → (Fin n → Bool)
  | [] => fun _ => false
  | k :: ks => bxor k (xorList ks)

def xorB : Nat → (Nat → Bool) → Bool
  | 0, _ => false
  | k + 1, f => xor (xorB k f) (f k)

def toeplitzMul (m n : Nat) (seed x : Nat → Bool) (i : Nat) : Bool :=
  if i < m then xorB n (fun j => seed (i + j) && x j) else false

def sumInt : Nat → (Nat → Int) → Int
  | 0, _ => 0
  | k + 1, f => sumInt k f + f k

class SimpleField (F : Type) extends Add F, Sub F, Mul F, Neg F, Zero F, One F where
  inv : F → F
  add_assoc : ∀ a b c : F, (a + b) + c = a + (b + c)
  add_comm : ∀ a b : F, a + b = b + a
  zero_add : ∀ a : F, 0 + a = a
  add_neg : ∀ a : F, a + (-a) = 0
  sub_eq : ∀ a b : F, a - b = a + (-b)
  mul_assoc : ∀ a b c : F, (a * b) * c = a * (b * c)
  mul_comm : ∀ a b : F, a * b = b * a
  one_mul : ∀ a : F, 1 * a = a
  left_distrib : ∀ a b c : F, a * (b + c) = a * b + a * c
  zero_ne_one : (0 : F) ≠ (1 : F)
  mul_inv_cancel : ∀ a : F, a ≠ 0 → a * inv a = 1

def evalPoly {F : Type} [SimpleField F] : List F → F → F
  | [], _ => 0
  | c :: cs, x => c + x * evalPoly cs x

def PolyNonzero {F : Type} [SimpleField F] : List F → Prop
  | [] => False
  | c :: cs => c ≠ 0 ∨ PolyNonzero cs

def PairwiseNeq {α : Type} : List α → Prop
  | [] => True
  | x :: xs => (∀ y ∈ xs, x ≠ y) ∧ PairwiseNeq xs

def hammingDist {F : Type} (dec : ∀ a b : F, Decidable (a = b)) : List F → List F → Nat
  | [], _ => 0
  | _, [] => 0
  | a :: as, b :: bs => (if @decide (a = b) (dec a b) then 0 else 1) + hammingDist dec as bs

abbrev CInt := Int × Int

def cNormSq (z : CInt) : Int := z.1 * z.1 + z.2 * z.2
def cDotRe (u v : CInt) : Int := u.1 * v.1 + u.2 * v.2
def cDotIm (u v : CInt) : Int := u.1 * v.2 - u.2 * v.1

def sumCNormSq : Nat → (Nat → CInt) → Int
  | 0, _ => 0
  | k + 1, f => sumCNormSq k f + cNormSq (f k)

def sumCDotRe : Nat → (Nat → CInt) → (Nat → CInt) → Int
  | 0, _, _ => 0
  | k + 1, u, v => sumCDotRe k u v + cDotRe (u k) (v k)

def sumCDotIm : Nat → (Nat → CInt) → (Nat → CInt) → Int
  | 0, _, _ => 0
  | k + 1, u, v => sumCDotIm k u v + cDotIm (u k) (v k)

def xorN : Nat → (Nat → Bool) → Bool
  | 0, _ => false
  | k + 1, f => xor (xorN k f) (f k)

def circEntry (ell m : Nat) (poly : Nat → Nat → Bool) (r c : Nat) : Bool :=
  let i1 := r / m; let j1 := r % m
  let i2 := c / m; let j2 := c % m
  poly ((i2 + ell - i1) % ell) ((j2 + m - j1) % m)

def matMulT (N : Nat) (M1 M2 : Nat → Nat → Bool) (r s : Nat) : Bool :=
  xorN N (fun c => M1 r c && M2 s c)

def grossA (dx dy : Nat) : Bool :=
  (dx == 3 && dy == 0) || (dx == 0 && dy == 1) || (dx == 0 && dy == 2)

def grossB (dx dy : Nat) : Bool :=
  (dx == 0 && dy == 3) || (dx == 1 && dy == 0) || (dx == 2 && dy == 0)

def grossHX (r c : Nat) : Bool :=
  if c < 72 then circEntry 12 6 grossA r c else circEntry 12 6 grossB r (c - 72)

def grossHZ (r c : Nat) : Bool :=
  if c < 72 then circEntry 12 6 grossB c r else circEntry 12 6 grossA (c - 72) r

def rowWeight (N : Nat) (M : Nat → Nat → Bool) (r : Nat) : Nat :=
  match N with
  | 0 => 0
  | k + 1 => rowWeight k M r + (if M r k then 1 else 0)

def allBelow (n : Nat) (p : Nat → Bool) : Bool :=
  match n with
  | 0 => true
  | k + 1 => allBelow k p && p k

def IsPrime (p : Nat) : Prop :=
  2 ≤ p ∧ ∀ d : Nat, d ∣ p → d = 1 ∨ d = p

def powMod (base exp mod : Nat) : Nat :=
  match exp with
  | 0 => 1 % mod
  | e + 1 => (powMod base e mod * base) % mod

def toInt16 (x : Int) : Int :=
  let r := x % 65536
  if r < 32768 then r else r - 65536

def montgomeryReduce (a : Int) : Int :=
  let t := toInt16 (a * (-3327))
  (a - t * 3329) / 65536

def mlkemCompress1 (y : Int) : Int :=
  let ym := y % 3329
  ((2 * ym + 1665) / 3329) % 2

def completeEdges (N : Nat) : Nat := N * (N - 1) / 2
def meshCeiling (B S : Nat) : Nat := B / S + 1

-- ============================================================================
-- Private Structural Bridges to SecMeshPQSI.*
-- ============================================================================

@[instance_reducible]
private def toCoreField {F : Type} (inst : SimpleField F) : SecMeshPQSI.InfoTheoretic.SimpleField F where
  add := inst.add
  sub := inst.sub
  mul := inst.mul
  neg := inst.neg
  zero := inst.zero
  one := inst.one
  inv := inst.inv
  add_assoc := inst.add_assoc
  add_comm := inst.add_comm
  zero_add := inst.zero_add
  add_neg := inst.add_neg
  sub_eq := inst.sub_eq
  mul_assoc := inst.mul_assoc
  mul_comm := inst.mul_comm
  one_mul := inst.one_mul
  left_distrib := inst.left_distrib
  zero_ne_one := inst.zero_ne_one
  mul_inv_cancel := inst.mul_inv_cancel

private theorem countBelow_eq (p : Nat → Bool) (n : Nat) :
    countBelow p n = SecMeshPQSI.FiniteKey.countBelow p n := by
  induction n with
  | zero => rfl
  | succ k ih => simp [countBelow, SecMeshPQSI.FiniteKey.countBelow, ih]

private theorem xorList_eq {n : Nat} (ks : List (Fin n → Bool)) :
    xorList ks = SecMeshPQSI.InfoTheoretic.xorList ks := by
  induction ks with
  | nil => rfl
  | cons k rest ih =>
    simp only [xorList, SecMeshPQSI.InfoTheoretic.xorList, ih]
    rfl

private theorem xorB_eq (k : Nat) (f : Nat → Bool) :
    xorB k f = SecMeshPQSI.InfoTheoretic.xorRange k f := by
  induction k with
  | zero => rfl
  | succ k ih => simp [xorB, SecMeshPQSI.InfoTheoretic.xorRange, ih]

private theorem toeplitzMul_eq (m n : Nat) (s x : Nat → Bool) (i : Nat) :
    toeplitzMul m n s x i = SecMeshPQSI.InfoTheoretic.toeplitzMul m n s x i := by
  simp only [toeplitzMul, SecMeshPQSI.InfoTheoretic.toeplitzMul, xorB_eq]

private theorem sumInt_eq (k : Nat) (f : Nat → Int) :
    sumInt k f = SecMeshPQSI.InfoTheoretic.sumInt k f := by
  induction k with
  | zero => rfl
  | succ k ih => simp [sumInt, SecMeshPQSI.InfoTheoretic.sumInt, ih]

private theorem evalPoly_eq {F : Type} (inst : SimpleField F) (p : List F) (x : F) :
    @evalPoly F inst p x = @SecMeshPQSI.InfoTheoretic.evalPoly F (toCoreField inst) p x := by
  induction p with
  | nil => rfl
  | cons c cs ih =>
    simp only [evalPoly, SecMeshPQSI.InfoTheoretic.evalPoly, ih]

private theorem polyNonzero_iff {F : Type} (inst : SimpleField F) (p : List F) :
    @PolyNonzero F inst p ↔ @SecMeshPQSI.InfoTheoretic.PolyNonzero F (toCoreField inst) p := by
  induction p with
  | nil => exact Iff.rfl
  | cons c cs ih =>
    simp only [PolyNonzero, SecMeshPQSI.InfoTheoretic.PolyNonzero, ih]

private theorem pairwiseNeq_iff {α : Type} (xs : List α) :
    PairwiseNeq xs ↔ SecMeshPQSI.InfoTheoretic.PairwiseNeq xs := by
  induction xs with
  | nil => exact Iff.rfl
  | cons x rest ih =>
    simp only [PairwiseNeq, SecMeshPQSI.InfoTheoretic.PairwiseNeq, ih]

private theorem hammingDist_eq {F : Type} (dec : ∀ a b : F, Decidable (a = b)) (u v : List F) :
    hammingDist dec u v = SecMeshPQSI.ThresholdPIR.hammingDist dec u v := by
  induction u generalizing v with
  | nil => rfl
  | cons a as ih =>
    cases v with
    | nil => rfl
    | cons b bs => simp [hammingDist, SecMeshPQSI.ThresholdPIR.hammingDist, ih]

private theorem sumCNormSq_eq (D : Nat) (u : Nat → CInt) :
    sumCNormSq D u = SecMeshPQSI.QuantumGeometry.sumCNormSq D u := by
  induction D with
  | zero => rfl
  | succ k ih => simp [sumCNormSq, SecMeshPQSI.QuantumGeometry.sumCNormSq, ih]; rfl

private theorem sumCDotRe_eq (D : Nat) (u v : Nat → CInt) :
    sumCDotRe D u v = SecMeshPQSI.QuantumGeometry.sumCDotRe D u v := by
  induction D with
  | zero => rfl
  | succ k ih => simp [sumCDotRe, SecMeshPQSI.QuantumGeometry.sumCDotRe, ih]; rfl

private theorem sumCDotIm_eq (D : Nat) (u v : Nat → CInt) :
    sumCDotIm D u v = SecMeshPQSI.QuantumGeometry.sumCDotIm D u v := by
  induction D with
  | zero => rfl
  | succ k ih => simp [sumCDotIm, SecMeshPQSI.QuantumGeometry.sumCDotIm, ih]; rfl

private theorem xorN_eq (k : Nat) (f : Nat → Bool) :
    xorN k f = SecMeshPQSI.QuantumGeometry.xorN k f := by
  induction k with
  | zero => rfl
  | succ k ih => simp [xorN, SecMeshPQSI.QuantumGeometry.xorN, ih]

private theorem allBelow_eq (n : Nat) (p q : Nat → Bool) (h : ∀ i, i < n → p i = q i) :
    allBelow n p = SecMeshPQSI.QuantumGeometry.allBelow n q := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [allBelow, SecMeshPQSI.QuantumGeometry.allBelow,
      ih (fun i hi => h i (by omega)), h k (by omega)]

private theorem powMod_eq (b e m : Nat) :
    powMod b e m = SecMeshPQSI.LatticeBandwidth.powMod b e m := by
  induction e with
  | zero => rfl
  | succ k ih => simp [powMod, SecMeshPQSI.LatticeBandwidth.powMod, ih]

-- ============================================================================
-- 21 Zero-Sorry Theorem Proofs
-- ============================================================================

theorem t1a_v1_tsirelson_violation :
    4 * (1000 - 2 * 146) * v1ExpectedChshDen = 1000 * v1ExpectedChshNum ∧
    v1ExpectedChshNum * v1ExpectedChshNum > 8 * (v1ExpectedChshDen * v1ExpectedChshDen) ∧
    v1ExpectedChshNum * v1ExpectedChshNum - 8 * (v1ExpectedChshDen * v1ExpectedChshDen) = 316 :=
  SecMeshPQSI.FiniteKey.t1a_v1_tsirelson_violation

theorem t1b_hoeffding_range2_factor4 :
    (∀ (n t : Nat), 2 * n * ((2 * t) * (2 * t)) = 4 * (2 * n * (t * t))) ∧
    (∀ (n t : Nat), (2 * n * ((2 * t) * (2 * t))) / (2 * 2) = 2 * n * (t * t)) ∧
    (16 * (50 ^ 4) > 24000000) :=
  SecMeshPQSI.FiniteKey.t1b_hoeffding_range2_factor4

theorem t1c_di_quarter_circle_duality :
    (∀ (a b : Int), (a * a - b * b) + (2 * b * b - a * a) = b * b) ∧
    (3 * 3 = 5 * 5 - 4 * 4 ∧ 2 * (4 * 4) - 5 * 5 = 7) ∧
    (33 * 33 * 16 < 7 * (50 * 50)) ∧
    ((83 : Nat) ^ 10 > 128 * ((50 : Nat) ^ 10)) ∧
    ((7 : Nat) ^ 5 > (2 : Nat) ^ 14) :=
  SecMeshPQSI.FiniteKey.t1c_di_quarter_circle_duality

theorem t1d_denoise_majority_bias_and_fragility :
    countBelow (fun x => decide (5 ≤ popcount8 x)) 256 = 93 ∧
    countBelow (fun x => decide (popcount8 x < 5)) 256 = 163 ∧
    countBelow (fun x => decide (popcount8 x == 4)) 256 = 70 ∧
    (93 + 163 = 256 ∧ 128 - 93 = 35) := by
  have h := SecMeshPQSI.FiniteKey.t1d_denoise_majority_bias_and_fragility
  rw [countBelow_eq, countBelow_eq, countBelow_eq]
  exact h

theorem t1e_composable_epsilon_conservation :
    (∀ (ePE eQ eS ePA eC eTot : Nat),
      ePE + eQ + eS + ePA + eC ≤ eTot →
      ePE + eQ + eS + ePA + eC ≤ eTot) ∧
    (∀ (eUnit : Nat), 0 < eUnit →
      let epsTot := 3 * eUnit
      let epsS := eUnit
      let epsH := eUnit
      epsS + epsS + epsH = epsTot ∧
      ∀ (eQ eC : Nat), 0 < eQ + eC → epsS + epsS + epsH + eQ + eC > epsTot) :=
  SecMeshPQSI.FiniteKey.t1e_composable_epsilon_conservation

theorem t2a_shannon_otp_perfect_secrecy (n : Nat) :
    ∀ (m c : Fin n → Bool),
      ∃ k : Fin n → Bool, bxor m k = c ∧ ∀ k' : Fin n → Bool, bxor m k' = c → k' = k :=
  SecMeshPQSI.InfoTheoretic.t2a_shannon_otp_perfect_secrecy n

theorem t2b_hybrid_dual_survivability (n : Nat) :
    (∀ (k_pq y : Fin n → Bool),
      ∃ k_it : Fin n → Bool, bxor k_pq k_it = y ∧ ∀ k', bxor k_pq k' = y → k' = k_it) ∧
    (∀ (k_it y : Fin n → Bool),
      ∃ k_pq : Fin n → Bool, bxor k_pq k_it = y ∧ ∀ k', bxor k' k_it = y → k' = k_pq) ∧
    (∀ (pre suf : List (Fin n → Bool)) (y : Fin n → Bool),
      ∃ k_good : Fin n → Bool,
        xorList (pre ++ k_good :: suf) = y ∧
        ∀ k', xorList (pre ++ k' :: suf) = y → k' = k_good) := by
  have h := SecMeshPQSI.InfoTheoretic.t2b_hybrid_dual_survivability n
  refine ⟨h.1, h.2.1, ?_⟩
  intro pre suf y
  obtain ⟨kg, h1, h2⟩ := h.2.2 pre suf y
  exact ⟨kg, by rw [xorList_eq]; exact h1, fun k' hk' => h2 k' (by rw [← xorList_eq]; exact hk')⟩

theorem t2c1_toeplitz_exact_2_universal (m n : Nat) (x y z sFree : Nat → Bool)
    (hdiff : ∃ j, j < n ∧ x j ≠ y j) :
    ∃ j0, j0 < n ∧
      (∃ s : Nat → Bool,
        (∀ k, (k < j0 ∨ j0 + m ≤ k) → s k = sFree k) ∧
        (∀ i, i < m → xor (toeplitzMul m n s x i) (toeplitzMul m n s y i) = z i) ∧
        (∀ s' : Nat → Bool,
          (∀ k, (k < j0 ∨ j0 + m ≤ k) → s' k = sFree k) →
          (∀ i, i < m → xor (toeplitzMul m n s' x i) (toeplitzMul m n s' y i) = z i) →
          ∀ k, s' k = s k)) := by
  obtain ⟨j0, hj0, s, h1, h2, h3⟩ :=
    SecMeshPQSI.InfoTheoretic.t2c_toeplitz_exact_2_universal m n x y z sFree hdiff
  refine ⟨j0, hj0, s, h1, fun i hi => ?_, fun s' hs1 hs2 => h3 s' hs1 (fun i hi => ?_)⟩
  · rw [toeplitzMul_eq, toeplitzMul_eq]; exact h2 i hi
  · rw [← toeplitzMul_eq, ← toeplitzMul_eq]; exact hs2 i hi

theorem t2c2_cauchy_schwarz_lhl (N : Nat) (a : Nat → Int) :
    (sumInt N a) * (sumInt N a) ≤ (N : Int) * sumInt N (fun i => a i * a i) := by
  rw [sumInt_eq, sumInt_eq]
  exact SecMeshPQSI.InfoTheoretic.t2c_cauchy_schwarz_lhl N a

theorem t2d_carter_wegman_poly_bound {F : Type} [inst : SimpleField F] (d : Nat) (p roots : List F)
    (hdeg : p.length ≤ d + 1) (hnz : PolyNonzero p)
    (hpw : PairwiseNeq roots) (hroots : ∀ r ∈ roots, evalPoly p r = 0) :
    roots.length ≤ d := by
  letI := toCoreField inst
  exact SecMeshPQSI.InfoTheoretic.t2d_carter_wegman_poly_bound d p roots hdeg
    ((polyNonzero_iff inst p).mp hnz)
    ((pairwiseNeq_iff roots).mp hpw)
    (fun r hr => by rw [← evalPoly_eq inst p r]; exact hroots r hr)

theorem t3a_shamir_threshold_and_secrecy {F : Type} [inst : SimpleField F] (t : Nat) :
    (∀ (f g : List F) (xs : List F),
      f.length ≤ t → g.length ≤ t → xs.length = t → PairwiseNeq xs →
      (∀ x ∈ xs, evalPoly f x = evalPoly g x) → evalPoly f 0 = evalPoly g 0) ∧
    (∀ (pts : List (F × F)) (s : F),
      pts.length + 1 = t →
      PairwiseNeq (0 :: pts.map Prod.fst) →
      ∃ f : List F, f.length ≤ t ∧ evalPoly f 0 = s ∧ (∀ p ∈ pts, evalPoly f p.1 = p.2) ∧
        ∀ g : List F, g.length ≤ t → evalPoly g 0 = s → (∀ p ∈ pts, evalPoly g p.1 = p.2) →
          ∀ x : F, evalPoly g x = evalPoly f x) := by
  letI := toCoreField inst
  have h := @SecMeshPQSI.ThresholdPIR.t3a_shamir_exact_threshold_and_secrecy F (toCoreField inst) t
  refine ⟨?_, ?_⟩
  · intro f g xs hf hg hxs hpw ha
    rw [evalPoly_eq inst f, evalPoly_eq inst g]
    exact h.1 f g xs hf hg hxs ((pairwiseNeq_iff xs).mp hpw)
      (fun x hx => by rw [← evalPoly_eq inst f x, ← evalPoly_eq inst g x]; exact ha x hx)
  · intro pts s hlen hpw
    obtain ⟨f, hfl, hf0, hfpts, huniq⟩ := h.2 pts s hlen ((pairwiseNeq_iff _).mp hpw)
    refine ⟨f, hfl, by rw [evalPoly_eq inst f]; exact hf0,
      fun p hp => by rw [evalPoly_eq inst f]; exact hfpts p hp, ?_⟩
    intro g hgl hg0 hgpts x
    rw [evalPoly_eq inst g x, evalPoly_eq inst f x]
    exact huniq g hgl
      (by rw [← evalPoly_eq inst g]; exact hg0)
      (fun p hp => by rw [← evalPoly_eq inst g]; exact hgpts p hp) x

theorem t3b_byzantine_singleton_tightness {F : Type} [inst : SimpleField F]
    (dec : ∀ a b : F, Decidable (a = b)) :
    (∀ (t b : Nat) (xs r f g : List F),
      t + 2 * b ≤ xs.length →
      r.length = xs.length →
      f.length ≤ t → g.length ≤ t →
      PairwiseNeq xs →
      hammingDist dec (xs.map (evalPoly f)) r ≤ b →
      hammingDist dec (xs.map (evalPoly g)) r ≤ b →
      evalPoly f 0 = evalPoly g 0) ∧
    (∀ (t b : Nat), 1 ≤ t → 1 ≤ b →
      let n := t + 2 * b - 1
      let d := n - t + 1
      d = 2 * b ∧ b + b = d) := by
  letI := toCoreField inst
  have h := @SecMeshPQSI.ThresholdPIR.t3b_byzantine_singleton_tightness F (toCoreField inst) dec
  refine ⟨?_, h.2⟩
  intro t b xs r f g hnb hr hf hg hpw hfr hgr
  have hmf : xs.map (@evalPoly F inst f) =
      xs.map (@SecMeshPQSI.InfoTheoretic.evalPoly F (toCoreField inst) f) :=
    List.map_congr_left (fun x _ => evalPoly_eq inst f x)
  have hmg : xs.map (@evalPoly F inst g) =
      xs.map (@SecMeshPQSI.InfoTheoretic.evalPoly F (toCoreField inst) g) :=
    List.map_congr_left (fun x _ => evalPoly_eq inst g x)
  rw [evalPoly_eq inst f, evalPoly_eq inst g]
  exact h.1 t b xs r f g hnb hr hf hg ((pairwiseNeq_iff xs).mp hpw)
    (by rw [← hammingDist_eq dec, ← hmf]; exact hfr)
    (by rw [← hammingDist_eq dec, ← hmg]; exact hgr)

theorem t3c_pir_byzantine_capacity_gap :
    (∀ (N K T B : Nat), 1 ≤ K →
      (K + T + 2 * B ≤ N ↔ 0 < N - (K + T + 2 * B - 1))) ∧
    (∀ (N T B : Nat), 1 ≤ T → T + 2 * B < N →
      let eff := N - 2 * B
      (eff * eff) = (eff - T) * (eff + T) + T * T ∧
      (eff - T) * (eff + T) < eff * eff) :=
  SecMeshPQSI.ThresholdPIR.t3c_pir_byzantine_capacity_gap

theorem t4a_qgt_psd_lagrange_and_trace (D : Nat) (u v : Nat → CInt) :
    let g11 := sumCNormSq D u
    let g22 := sumCNormSq D v
    let g12 := sumCDotRe D u v
    let omega := -2 * sumCDotIm D u v
    4 * (g11 * g22 - g12 * g12) ≥ omega * omega ∧
    (g11 + g22) * (g11 + g22) ≥ omega * omega := by
  dsimp only
  rw [sumCNormSq_eq, sumCNormSq_eq, sumCDotRe_eq, sumCDotIm_eq]
  exact SecMeshPQSI.QuantumGeometry.t4a_qgt_psd_lagrange_and_trace D u v

theorem t4b_qgt_concurrence_surplus_identity (ca sa ch sh R : Int)
    (ha : ca * ca + sa * sa = R * R) (ht : ch * ch + sh * sh = R * R) :
    let c2a := ca * ca - sa * sa
    let C := 2 * ca * sa
    let st := 2 * sh * ch
    let det_scaled := 4 * (R * R * R * R * R * R * (sh * sh) - (c2a * c2a) * (sh * sh * (sh * sh)))
    let rhs_scaled := (c2a * c2a) * (st * st)
    det_scaled - rhs_scaled = 4 * (C * C) * (R * R) * (sh * sh) :=
  SecMeshPQSI.QuantumGeometry.t4b_qgt_concurrence_surplus_identity ca sa ch sh R ha ht

theorem t4c1_general_bb_commutation (M : Nat) (A B : Nat → Nat → Bool)
    (hcomm : ∀ r s, xorN M (fun c => A r c && B c s) = xorN M (fun c => B r c && A c s)) :
    ∀ r s, xor (xorN M (fun c => A r c && B c s)) (xorN M (fun c => B r c && A c s)) = false := by
  intro r s
  rw [xorN_eq, xorN_eq]
  exact SecMeshPQSI.QuantumGeometry.t4c_general_bb_css_commutation M A B
    (fun r' s' => by rw [← xorN_eq, ← xorN_eq]; exact hcomm r' s') r s

theorem t4c2_bravyi_gross_bb144_certified :
    allBelow 72 (fun r => allBelow 72 (fun s => !matMulT 144 grossHX grossHZ r s)) = true ∧
    allBelow 72 (fun r => rowWeight 144 grossHX r == 6 && rowWeight 144 grossHZ r == 6) = true := by
  have h := SecMeshPQSI.QuantumGeometry.t4c_bravyi_gross_bb144_certified
  refine ⟨?_, by decide +kernel⟩
  rw [allBelow_eq 72 _ (fun r => SecMeshPQSI.QuantumGeometry.allBelow 72
        (fun s => !SecMeshPQSI.QuantumGeometry.matMulT 144
          SecMeshPQSI.QuantumGeometry.grossHX SecMeshPQSI.QuantumGeometry.grossHZ r s))]
  · exact h.1
  · intro r _
    apply allBelow_eq 72
    intro s _
    simp only [matMulT, SecMeshPQSI.QuantumGeometry.matMulT, xorN_eq]
    rfl

theorem t5a_fips203_ntt_prime_and_root :
    IsPrime 3329 ∧ 3329 = 13 * 256 + 1 ∧ powMod 17 128 3329 = 3328 ∧ powMod 17 256 3329 = 1 := by
  have h := SecMeshPQSI.LatticeBandwidth.t5a_fips203_ntt_prime_and_root
  rw [powMod_eq, powMod_eq]
  exact h

theorem t5b_montgomery_reduction_exact (a : Int)
    (hlo : -32768 * 3329 < a) (hhi : a < 32768 * 3329) :
    let t := toInt16 (a * (-3327))
    let r := montgomeryReduce a
    (a - t * 3329) % 65536 = 0 ∧ (r * 65536 - a) % 3329 = 0 ∧ -3329 < r ∧ r < 3329 :=
  SecMeshPQSI.LatticeBandwidth.t5b_montgomery_reduction_exact a hlo hhi

theorem t5c_mlkem_compress1_margin (b e : Int)
    (hb : b = 0 ∨ b = 1) (hlo : -831 ≤ e) (hhi : e ≤ 831) :
    mlkemCompress1 (b * 1665 + e) = b :=
  SecMeshPQSI.LatticeBandwidth.t5c_mlkem_compress1_margin b e hb hlo hhi

theorem t5d_kn_mesh_bandwidth_and_hedge_overhead :
    (∀ N : Nat, 2 * completeEdges N = N * (N - 1)) ∧
    (∀ B S : Nat, 0 < S → (meshCeiling B S - 1) * S ≤ B ∧ B < meshCeiling B S * S) ∧
    (6573 + 96 + 16 = 6685 ∧ (96 + 16) * 400 < 7 * 6573) :=
  SecMeshPQSI.LatticeBandwidth.t5d_kn_mesh_bandwidth_and_hedge_overhead

end
end SecMeshPQSI.Palomar
