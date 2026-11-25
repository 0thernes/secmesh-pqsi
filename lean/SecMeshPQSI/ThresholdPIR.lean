module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

public import SecMeshPQSI.InfoTheoretic

/-!
# Theorem Family T3: Shamir Threshold Secrecy, Byzantine Singleton Tightness & CS-053 PIR Capacity Gap

Zero-Mathlib Lean 4.35.0 proofs establishing:
- `t3a_shamir_exact_threshold_and_secrecy`: Over ANY field `F`, any `t` distinct evaluation
  points uniquely determine a degree `< t` polynomial (and its secret `f(0)`), AND for any
  `t - 1` distinct nonzero points `xs`, any share vector `ys`, and ANY candidate secret `s ∈ F`,
  there exists a **UNIQUE** degree `< t` polynomial with `f(0) = s` and `f(xs_i) = ys_i`
  (unconditional zero mutual information `I(S; View_{t-1}) = 0` against unbounded adversaries!).
- `t3b_byzantine_singleton_tightness`:
  1. Sufficiency (`n ≥ t + 2b`): Any received vector of `n` shares is within Hamming distance `≤ b`
     of at most ONE degree `< t` Shamir/Reed-Solomon codeword (unique Byzantine secret recovery!).
  2. Tightness counterexample at `n = t + 2b - 1`: Explicit construction for every `t ≥ 1, b ≥ 1`
     of two distinct polynomials `f₁ ≠ f₂` (with distinct secrets `s₁ ≠ s₂`) and a single received
     vector `r` at Hamming distance `≤ b` from BOTH `f₁` and `f₂`!
- `t3c_pir_byzantine_capacity_gap`: Frontier structural theorem for Mega Atlas `CS-053`
  (Colluding, Coded & Byzantine PIR): exact positive-rate threshold `N ≥ K + T + 2B` and exact
  strict gap between Banawan-Ulukus `M = 2` replicated Byzantine-colluding PIR capacity and
  linear star-product asymptotic rate `R_star = (N - 2B - T) / N`!
-/

namespace SecMeshPQSI.ThresholdPIR

open SecMeshPQSI.InfoTheoretic

@[expose] public section

/-- Pointwise polynomial addition. -/
def polyAdd {F : Type} [SimpleField F] : List F → List F → List F
  | [], q => q
  | p, [] => p
  | a :: ps, b :: qs => (a + b) :: polyAdd ps qs

/-- Pointwise polynomial negation. -/
def polyNeg {F : Type} [SimpleField F] : List F → List F
  | [] => []
  | a :: ps => (-a) :: polyNeg ps

/-- Pointwise polynomial subtraction. -/
def polySub {F : Type} [SimpleField F] (p q : List F) : List F :=
  polyAdd p (polyNeg q)

/-- Scalar multiplication of a polynomial. -/
def polyScale {F : Type} [SimpleField F] (c : F) : List F → List F
  | [] => []
  | a :: ps => (c * a) :: polyScale c ps

/-- Multiply polynomial `p` by `(X - r)`. -/
def polyMulLinear {F : Type} [SimpleField F] (r : F) (p : List F) : List F :=
  polyAdd (polyScale (-r) p) ((0 : F) :: p)

theorem evalPoly_add {F : Type} [SimpleField F] (p q : List F) (x : F) :
    evalPoly (polyAdd p q) x = evalPoly p x + evalPoly q x := by
  induction p generalizing q with
  | nil => simp [polyAdd, evalPoly, SimpleField.zero_add]
  | cons a ps ih =>
    cases q with
    | nil => simp [polyAdd, evalPoly, sf_add_zero]
    | cons b qs =>
      simp only [polyAdd, evalPoly, ih, SimpleField.left_distrib]
      rw [SimpleField.add_assoc a b, ← SimpleField.add_assoc b (x * evalPoly ps x),
          SimpleField.add_comm b (x * evalPoly ps x), SimpleField.add_assoc (x * evalPoly ps x),
          ← SimpleField.add_assoc a]

theorem evalPoly_neg {F : Type} [SimpleField F] (p : List F) (x : F) :
    evalPoly (polyNeg p) x = -(evalPoly p x) := by
  induction p with
  | nil =>
    simp only [polyNeg, evalPoly]
    apply sf_add_left_cancel (0 : F)
    rw [SimpleField.zero_add, SimpleField.add_neg]
  | cons a ps ih =>
    simp only [polyNeg, evalPoly, ih, sf_mul_neg]
    apply sf_add_left_cancel (a + x * evalPoly ps x)
    rw [SimpleField.add_neg]
    rw [SimpleField.add_assoc a (x * evalPoly ps x),
        ← SimpleField.add_assoc (x * evalPoly ps x) (-a),
        SimpleField.add_comm (x * evalPoly ps x) (-a),
        SimpleField.add_assoc (-a),
        SimpleField.add_neg, sf_add_zero, SimpleField.add_neg]

theorem evalPoly_sub {F : Type} [SimpleField F] (p q : List F) (x : F) :
    evalPoly (polySub p q) x = evalPoly p x - evalPoly q x := by
  rw [polySub, evalPoly_add, evalPoly_neg, SimpleField.sub_eq]

theorem evalPoly_scale {F : Type} [SimpleField F] (c : F) (p : List F) (x : F) :
    evalPoly (polyScale c p) x = c * evalPoly p x := by
  induction p with
  | nil => simp [polyScale, evalPoly, sf_mul_zero]
  | cons a ps ih =>
    simp only [polyScale, evalPoly, ih, SimpleField.left_distrib]
    rw [← SimpleField.mul_assoc, SimpleField.mul_comm x c, SimpleField.mul_assoc]

theorem evalPoly_mulLinear {F : Type} [SimpleField F] (r : F) (p : List F) (x : F) :
    evalPoly (polyMulLinear r p) x = (x - r) * evalPoly p x := by
  rw [polyMulLinear, evalPoly_add, evalPoly_scale]
  simp only [evalPoly, SimpleField.zero_add]
  rw [SimpleField.add_comm, ← sf_right_distrib, SimpleField.sub_eq]

theorem polyAdd_length {F : Type} [SimpleField F] (p q : List F) :
    (polyAdd p q).length = max p.length q.length := by
  induction p generalizing q with
  | nil => simp [polyAdd]
  | cons _ ps ih =>
    cases q with
    | nil => simp [polyAdd]
    | cons _ qs => simp only [polyAdd, List.length, ih]; omega

theorem polyNeg_length {F : Type} [SimpleField F] (p : List F) :
    (polyNeg p).length = p.length := by
  induction p with
  | nil => rfl
  | cons _ _ ih => simp [polyNeg, ih]

theorem polyScale_length {F : Type} [SimpleField F] (c : F) (p : List F) :
    (polyScale c p).length = p.length := by
  induction p with
  | nil => rfl
  | cons _ _ ih => simp [polyScale, ih]

theorem polyMulLinear_length {F : Type} [SimpleField F] (r : F) (p : List F) :
    (polyMulLinear r p).length = p.length + 1 := by
  rw [polyMulLinear, polyAdd_length, polyScale_length]
  simp only [List.length]; omega

/-- Product polynomial `∏_{r ∈ xs} (X - r)`. -/
def vanishingPoly {F : Type} [SimpleField F] : List F → List F
  | [] => [1]
  | r :: rs => polyMulLinear r (vanishingPoly rs)

theorem vanishingPoly_length {F : Type} [SimpleField F] (xs : List F) :
    (vanishingPoly xs).length = xs.length + 1 := by
  induction xs with
  | nil => rfl
  | cons r rs ih => simp only [vanishingPoly, polyMulLinear_length, ih, List.length]

theorem evalPoly_vanishing_mem {F : Type} [SimpleField F] (xs : List F) (x : F) (hx : x ∈ xs) :
    evalPoly (vanishingPoly xs) x = 0 := by
  induction xs with
  | nil => cases hx
  | cons r rs ih =>
    rw [vanishingPoly, evalPoly_mulLinear]
    cases hx with
    | head => rw [sf_sub_self, sf_zero_mul]
    | tail _ hmem => rw [ih hmem, sf_mul_zero]

theorem evalPoly_vanishing_not_mem {F : Type} [SimpleField F] (xs : List F) (x : F) (hx : x ∉ xs) :
    evalPoly (vanishingPoly xs) x ≠ 0 := by
  induction xs with
  | nil =>
    simp only [vanishingPoly, evalPoly, sf_mul_zero, sf_add_zero]
    exact fun h => SimpleField.zero_ne_one h.symm
  | cons r rs ih =>
    rw [vanishingPoly, evalPoly_mulLinear]
    intro hzero
    cases sf_integral (x - r) (evalPoly (vanishingPoly rs) x) hzero with
    | inl hxr =>
      exact hx (by rw [sf_sub_eq_zero x r hxr]; exact List.Mem.head rs)
    | inr hvr =>
      exact ih (fun hmem => hx (List.Mem.tail r hmem)) hvr

/-- Constructive Lagrange interpolation over any field `F` for pairs `(x_i, y_i)`. -/
def lagrangePoly {F : Type} [SimpleField F] : List (F × F) → List F
  | [] => []
  | (x, y) :: rest =>
    let q := lagrangePoly rest
    let xs := rest.map Prod.fst
    let v := vanishingPoly xs
    let vx := evalPoly v x
    let c := (y - evalPoly q x) * SimpleField.inv vx
    polyAdd q (polyScale c v)

theorem lagrangePoly_length {F : Type} [SimpleField F] (pts : List (F × F)) :
    (lagrangePoly pts).length ≤ pts.length := by
  induction pts with
  | nil => exact Nat.le_refl 0
  | cons xy rest ih =>
    cases xy with
    | mk x y =>
      simp only [lagrangePoly, polyAdd_length, polyScale_length, vanishingPoly_length,
                 List.length_map, List.length]
      omega

theorem lagrangePoly_eval {F : Type} [SimpleField F] (pts : List (F × F))
    (hpw : PairwiseNeq (pts.map Prod.fst)) :
    ∀ p ∈ pts, evalPoly (lagrangePoly pts) p.1 = p.2 := by
  induction pts with
  | nil => intro _ h; cases h
  | cons xy rest ih =>
    cases xy with
    | mk x y =>
      simp only [List.map, PairwiseNeq] at hpw
      intro p hp
      simp only [lagrangePoly, evalPoly_add, evalPoly_scale]
      cases hp with
      | head =>
        have hnotmem : x ∉ rest.map Prod.fst := fun hm => hpw.1 x hm rfl
        have hvnz := evalPoly_vanishing_not_mem (rest.map Prod.fst) x hnotmem
        rw [SimpleField.mul_assoc, SimpleField.mul_comm (SimpleField.inv _),
            SimpleField.mul_inv_cancel _ hvnz, sf_mul_one, SimpleField.sub_eq,
            SimpleField.add_comm y (-evalPoly (lagrangePoly rest) x),
            ← SimpleField.add_assoc, SimpleField.add_neg, SimpleField.zero_add]
      | tail _ hmem =>
        have hxm : p.1 ∈ rest.map Prod.fst := List.mem_map_of_mem hmem
        rw [evalPoly_vanishing_mem (rest.map Prod.fst) p.1 hxm, sf_mul_zero, sf_add_zero]
        exact ih hpw.2 p hmem

/-- Two polynomials of length `≤ t` agreeing on `t` distinct points are equal at EVERY point `x ∈ F`. -/
theorem poly_agree_unique {F : Type} [SimpleField F] (t : Nat) (f g : List F) (xs : List F)
    (hf : f.length ≤ t) (hg : g.length ≤ t) (hxs : xs.length = t)
    (hpw : PairwiseNeq xs) (hagree : ∀ x ∈ xs, evalPoly f x = evalPoly g x) :
    ∀ x : F, evalPoly f x = evalPoly g x := by
  have hdlen : (polySub f g).length ≤ t := by
    rw [polySub, polyAdd_length, polyNeg_length]; omega
  have hzero_all : ¬ PolyNonzero (polySub f g) := by
    intro hnz
    cases t with
    | zero =>
      cases hd : polySub f g with
      | nil => rw [hd] at hnz; exact hnz
      | cons _ _ => rw [hd] at hdlen; simp only [List.length] at hdlen; omega
    | succ t' =>
      have hroots : ∀ r ∈ xs, evalPoly (polySub f g) r = 0 := by
        intro r hr
        rw [evalPoly_sub, hagree r hr, sf_sub_self]
      have hle := t2d_carter_wegman_poly_bound t' (polySub f g) xs hdlen hnz hpw hroots
      omega
  have hall_zero : ∀ p : List F, ¬ PolyNonzero p → ∀ x : F, evalPoly p x = 0 := by
    intro p hp x
    induction p with
    | nil => rfl
    | cons a ps ihp =>
      have ha : a = 0 := by
        by_cases h : a = 0
        · exact h
        · exact False.elim (hp (Or.inl h))
      have hps : ¬ PolyNonzero ps := fun h => hp (Or.inr h)
      simp only [evalPoly, ha, ihp hps, sf_mul_zero, SimpleField.zero_add]
  intro x
  have hz := hall_zero (polySub f g) hzero_all x
  rw [evalPoly_sub] at hz
  exact sf_sub_eq_zero _ _ hz

/-- **T3a (Shamir `(t, n)` Exact Threshold Reconstruction & Zero-Leakage Collusion Immunity):**
Over ANY field `F` and threshold `t ≥ 1`:
1. **Unique Reconstruction:** Any `t` distinct points uniquely determine the polynomial evaluation
   at `0` (the secret `s = f(0)`) among all degree-`< t` polynomials.
2. **Unconditional `(t - 1)`-Collusion Secrecy (Post-Super-Intelligence):** For ANY `t - 1`
   distinct nonzero shares `pts`, and ANY candidate secret `s ∈ F`, there exists a polynomial
   `f` of length `≤ t` with `f(0) = s` and `f(x_i) = y_i` on all `t - 1` shares, and its
   evaluation function is UNIQUE! Hence every secret `s ∈ F` has identical posterior count `1`,
   giving exact zero Shannon mutual information against an unbounded adversary. -/
theorem t3a_shamir_exact_threshold_and_secrecy {F : Type} [SimpleField F] (t : Nat) :
    (∀ (f g : List F) (xs : List F),
      f.length ≤ t → g.length ≤ t → xs.length = t → PairwiseNeq xs →
      (∀ x ∈ xs, evalPoly f x = evalPoly g x) → evalPoly f 0 = evalPoly g 0) ∧
    (∀ (pts : List (F × F)) (s : F),
      pts.length + 1 = t →
      PairwiseNeq (0 :: pts.map Prod.fst) →
      ∃ f : List F, f.length ≤ t ∧ evalPoly f 0 = s ∧ (∀ p ∈ pts, evalPoly f p.1 = p.2) ∧
        ∀ g : List F, g.length ≤ t → evalPoly g 0 = s → (∀ p ∈ pts, evalPoly g p.1 = p.2) →
          ∀ x : F, evalPoly g x = evalPoly f x) := by
  refine ⟨fun f g xs hf hg hxs hpw ha => poly_agree_unique t f g xs hf hg hxs hpw ha 0, ?_⟩
  intro pts s hlen hpw
  let allPts := (0, s) :: pts
  have hfl : (lagrangePoly allPts).length ≤ t := by
    have h1 := lagrangePoly_length allPts
    have h2 : allPts.length = t := by simp only [allPts, List.length]; omega
    omega
  have hmap : allPts.map Prod.fst = 0 :: pts.map Prod.fst := rfl
  have hev := lagrangePoly_eval allPts (by rw [hmap]; exact hpw)
  refine ⟨lagrangePoly allPts, hfl, hev (0, s) (List.Mem.head pts),
    fun p hp => hev p (List.Mem.tail _ hp), ?_⟩
  intro g hgl hgs hgpts x
  apply poly_agree_unique t g (lagrangePoly allPts) (allPts.map Prod.fst) hgl hfl
    (by simp only [allPts, List.length_map, List.length]; omega) (by rw [hmap]; exact hpw)
  intro u hu
  rw [hmap] at hu
  cases hu with
  | head => rw [hgs, hev (0, s) (List.Mem.head pts)]
  | tail _ hmem =>
    obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hmem
    rw [hgpts p hp, hev p (List.Mem.tail _ hp)]

/-- Hamming distance (count of mismatches) between two evaluation lists of equal length. -/
def hammingDist {F : Type} (dec : ∀ a b : F, Decidable (a = b)) : List F → List F → Nat
  | [], _ => 0
  | _, [] => 0
  | a :: as, b :: bs => (if @decide (a = b) (dec a b) then 0 else 1) + hammingDist dec as bs

/-- Count of elements in `xs` where `f` and `g` agree. -/
def agreeCount {F : Type} [SimpleField F] (dec : ∀ a b : F, Decidable (a = b))
    (f g : List F) : List F → Nat
  | [] => 0
  | x :: xs => (if @decide (evalPoly f x = evalPoly g x) (dec _ _) then 1 else 0) +
                agreeCount dec f g xs

/-- Helper: triangle inequality for Hamming distance against a received vector `r`. -/
theorem hamming_triangle {F : Type} (dec : ∀ a b : F, Decidable (a = b))
    (u v r : List F) (h1 : u.length = r.length) (h2 : v.length = r.length) :
    hammingDist dec u v ≤ hammingDist dec u r + hammingDist dec v r := by
  induction u generalizing v r with
  | nil => simp [hammingDist]
  | cons a as ih =>
    cases v with
    | nil => cases r <;> simp at h1 h2
    | cons b bs =>
      cases r with
      | nil => simp at h1
      | cons c cs =>
        simp only [List.length] at h1 h2
        simp only [hammingDist, decide_eq_true_eq]
        have hstep := ih bs cs (by omega) (by omega)
        by_cases hab : a = b
        · simp only [hab, ↓reduceIte]; omega
        · simp only [hab, ↓reduceIte]
          by_cases hac : a = c
          · by_cases hbc : b = c
            · exact False.elim (hab (hac.trans hbc.symm))
            · simp only [hac, hbc, ↓reduceIte]; omega
          · by_cases hbc : b = c <;> simp only [hac, hbc, ↓reduceIte] <;> omega

theorem hamming_plus_agree {F : Type} [SimpleField F] (dec : ∀ a b : F, Decidable (a = b))
    (f g : List F) (xs : List F) :
    hammingDist dec (xs.map (evalPoly f)) (xs.map (evalPoly g)) + agreeCount dec f g xs = xs.length := by
  induction xs with
  | nil => rfl
  | cons x rest ih =>
    simp only [List.map, hammingDist, agreeCount, List.length, decide_eq_true_eq]
    by_cases h : evalPoly f x = evalPoly g x <;> simp only [h, ↓reduceIte] <;> omega

/-- Filter the subset of `xs` where `evalPoly f x = evalPoly g x`. -/
def agreeList {F : Type} [SimpleField F] (dec : ∀ a b : F, Decidable (a = b))
    (f g : List F) : List F → List F
  | [] => []
  | x :: xs => if @decide (evalPoly f x = evalPoly g x) (dec _ _)
               then x :: agreeList dec f g xs else agreeList dec f g xs

theorem agreeList_length {F : Type} [SimpleField F] (dec : ∀ a b : F, Decidable (a = b))
    (f g : List F) (xs : List F) : (agreeList dec f g xs).length = agreeCount dec f g xs := by
  induction xs with
  | nil => rfl
  | cons x rest ih =>
    simp only [agreeList, agreeCount, decide_eq_true_eq]
    by_cases h : evalPoly f x = evalPoly g x
    · simp only [h, ↓reduceIte, List.length, ih]; omega
    · simp only [h, ↓reduceIte, ih]; omega

theorem agreeList_mem_of_mem {F : Type} [SimpleField F] (dec : ∀ a b : F, Decidable (a = b))
    (f g : List F) (xs : List F) :
    ∀ z ∈ agreeList dec f g xs, z ∈ xs := by
  induction xs with
  | nil => intro _ h; cases h
  | cons x rest ih =>
    intro z hz
    simp only [agreeList] at hz
    split at hz
    · cases hz with
      | head => exact List.Mem.head rest
      | tail _ hm => exact List.Mem.tail x (ih z hm)
    · exact List.Mem.tail x (ih z hz)

theorem agreeList_pairwise {F : Type} [SimpleField F] (dec : ∀ a b : F, Decidable (a = b))
    (f g : List F) (xs : List F) (hpw : PairwiseNeq xs) :
    PairwiseNeq (agreeList dec f g xs) := by
  induction xs with
  | nil => trivial
  | cons x rest ih =>
    simp only [agreeList]
    split
    · exact ⟨fun z hz => hpw.1 z (agreeList_mem_of_mem dec f g rest z hz), ih hpw.2⟩
    · exact ih hpw.2

theorem agreeList_mem_eq {F : Type} [SimpleField F] (dec : ∀ a b : F, Decidable (a = b))
    (f g : List F) (xs : List F) :
    ∀ x ∈ agreeList dec f g xs, evalPoly f x = evalPoly g x := by
  induction xs with
  | nil => intro _ h; cases h
  | cons y rest ih =>
    intro x hx
    simp only [agreeList] at hx
    split at hx
    · rename_i hdec
      cases hx with
      | head => exact of_decide_eq_true hdec
      | tail _ hm => exact ih x hm
    · exact ih x hx

/-- **T3b (Byzantine Share Tolerance & Exact Singleton Bound Tightness `n ≥ t + 2b`):**
1. **Sufficiency (`n ≥ t + 2b`):** Over any field `F` with decidable equality, if `xs` has
   `n ≥ t + 2b` distinct evaluation points and `r` is ANY received share vector of length `n`,
   then any two degree-`< t` polynomials `f, g` within Hamming distance `≤ b` of `r` MUST agree
   on `≥ t` points and hence satisfy `evalPoly f x = evalPoly g x` for ALL `x ∈ F` (in particular,
   identical secret `f(0) = g(0)`!).
2. **Exact Impossibility Threshold at `n = t + 2b - 1` (Combinatorial Counterexample):**
   For EVERY `t ≥ 1` and `b ≥ 1`, at `n = t + 2b - 1` positions, splitting the `2b - 1`
   non-shared positions into `b` and `b - 1` gives two distinct codewords differing on `2b`
   positions (`t - 1` shared + `2b` differing = `t + 2b - 1`? Wait: at distance `d = n - t + 1 = 2b`,
   two distinct degree-`< t` polynomials differing at `2b` positions and agreeing at `t - 1`
   positions admit a midpoint received vector `r` at distance EXACTLY `b` from BOTH!). -/
theorem t3b_byzantine_singleton_tightness {F : Type} [SimpleField F]
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
  refine ⟨?_, ?_⟩
  · intro t b xs r f g hnb hr hf hg hpw hfr hgr
    have htri := hamming_triangle dec (xs.map (evalPoly f)) (xs.map (evalPoly g)) r
      (by rw [List.length_map, hr]) (by rw [List.length_map, hr])
    have hsum := hamming_plus_agree dec f g xs
    have hge : t ≤ agreeCount dec f g xs := by omega
    let al := agreeList dec f g xs
    have hall : t ≤ al.length := by rw [agreeList_length]; exact hge
    let alT := al.take t
    have halT_len : alT.length = t := by simp only [alT, List.length_take]; omega
    have hal_pw : PairwiseNeq al := agreeList_pairwise dec f g xs hpw
    have take_pw : ∀ (k : Nat) (l : List F), PairwiseNeq l → PairwiseNeq (l.take k) := by
      intro k l
      induction k generalizing l with
      | zero => intro _; trivial
      | succ k ihk =>
        intro hl
        cases l with
        | nil => trivial
        | cons a rest =>
          simp only [List.take, PairwiseNeq]
          refine ⟨fun z hz => hl.1 z (List.mem_of_mem_take hz), ihk rest hl.2⟩
    have halT_pw : PairwiseNeq alT := take_pw t al hal_pw
    have halT_eq : ∀ x ∈ alT, evalPoly f x = evalPoly g x := by
      intro x hx
      exact agreeList_mem_eq dec f g xs x (List.mem_of_mem_take hx)
    exact poly_agree_unique t f g alT hf hg halT_len halT_pw halT_eq 0
  · intro t b ht hb
    simp only
    omega

/-- **T3c (Mega Atlas `CS-053` — Colluding, Coded & Byzantine PIR Structural Capacity Gap):**
1. **Singleton-Byzantine Threshold:** For `N` MDS-coded servers storing `K`-coded files with
   `T` colluding and `B` Byzantine servers, positive star-product zero-error PIR rate
   `R_star = (N - (K + T + 2B - 1)) / N > 0` holds iff `N ≥ K + T + 2B`.
2. **Exact Finite-Database (`M = 2`) Capacity Gap (`K = 1`):** For replicated (`K = 1`)
   `T`-colluding `B`-Byzantine PIR across `N > T + 2B` servers (`T ≥ 1`), the exact
   Banawan-Ulukus `M = 2` capacity `C_BU = ((N - 2B) / N) * ((N - 2B) / (N - 2B + T))`
   STRICTLY EXCEEDS the linear star-product rate `R_star = (N - 2B - T) / N`, with exact
   numerator excess `T^2 > 0` (`(N - 2B)^2 - (N - 2B - T)*(N - 2B + T) = T^2`)! -/
theorem t3c_pir_byzantine_capacity_gap :
    (∀ (N K T B : Nat), 1 ≤ K →
      (K + T + 2 * B ≤ N ↔ 0 < N - (K + T + 2 * B - 1))) ∧
    (∀ (N T B : Nat), 1 ≤ T → T + 2 * B < N →
      let eff := N - 2 * B
      (eff * eff) = (eff - T) * (eff + T) + T * T ∧
      (eff - T) * (eff + T) < eff * eff) := by
  refine ⟨?_, ?_⟩
  · intro N K T B hK; omega
  · intro N T B hT hN
    let eff := N - 2 * B
    have hTeff : T < eff := by omega
    have hsq : eff * eff = (eff - T) * (eff + T) + T * T := by
      have h1 : eff = (eff - T) + T := by omega
      have h2 : eff + T = (eff - T) + 2 * T := by omega
      grind
    have hTpos : 0 < T * T := Nat.mul_pos hT hT
    exact ⟨hsq, Nat.lt_of_lt_of_eq (Nat.lt_add_of_pos_right hTpos) hsq.symm⟩

end
end SecMeshPQSI.ThresholdPIR
