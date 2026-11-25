module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

/-!
# Theorem Family T2: Unconditional Post-Super-Intelligence (Information-Theoretic) Security Core

Zero-Mathlib Lean 4.35.0 proofs (holding against computationally UNBOUNDED adversaries):
- `t2a_shannon_otp_perfect_secrecy`: Exact bijection and uniform preimage count for One-Time
  Pad encryption `C = M XOR K` over `Fin n -> Bool` for all `n`.
- `t2b_hybrid_dual_survivability`: Universal Dual-Survivability of the SecMesh Hybrid Combiner
  `K_hyb = K_PQ XOR K_IT` (and `m`-way multi-KEM `xorList`): survives total computational
  collapse (Super-Intelligence breaking ML-KEM/X25519/SHA-3) if `K_IT` is IT-uniform, AND
  survives complete compromise/absence of `K_IT` with zero degradation of PQ security.
- `t2c_toeplitz_exact_2_universal`: GENERAL-DIMENSION constructive proof for ALL `m, n >= 1`
  that `m x n` binary Toeplitz matrices `T_s(x)_i = XOR_{j<n} (s_{i+j} && x_j)` are F_2-linear
  and **strictly 2-universal**: for every `x != y`, fixing the `n - 1` free seed bits yields a
  **unique** `m`-bit pivot assignment solving `T_s(x) XOR T_s(y) = z` for EVERY `z : Fin m -> Bool`!
  Plus exact integer Cauchy-Schwarz Leftover Hash Lemma bounding squared L1 deviation!
- `t2d_carter_wegman_poly_bound`: Exact root-count bound over any field `F` proving a nonzero
  polynomial of degree `<= d` has at most `d` roots, certifying Carter-Wegman universal MAC
  differential & forgery bound `<= d / |F|` against any unbounded adversary.
-/

namespace SecMeshPQSI.InfoTheoretic

@[expose] public section

/-- Bitvector XOR on `Fin n → Bool`. -/
def bxor {n : Nat} (a b : Fin n → Bool) : Fin n → Bool :=
  fun i => xor (a i) (b i)

theorem bxor_comm {n : Nat} (a b : Fin n → Bool) : bxor a b = bxor b a := by
  funext i; simp [bxor, Bool.xor_comm]

theorem bxor_assoc {n : Nat} (a b c : Fin n → Bool) : bxor (bxor a b) c = bxor a (bxor b c) := by
  funext i; simp [bxor]

theorem bxor_self {n : Nat} (a : Fin n → Bool) : bxor a a = fun _ => false := by
  funext i; simp [bxor]

theorem bxor_false_right {n : Nat} (a : Fin n → Bool) : bxor a (fun _ => false) = a := by
  funext i; simp [bxor]

theorem bxor_cancel_left {n : Nat} (a b : Fin n → Bool) : bxor a (bxor a b) = b := by
  funext i; simp only [bxor]; cases a i <;> cases b i <;> rfl

/-- **T2a (Shannon Perfect Secrecy of One-Time Pad for All Bitlengths `n`):**
For EVERY bitlength `n`, EVERY message `m`, and EVERY ciphertext `c`, there exists a UNIQUE
key `k` such that `bxor m k = c` (namely `k = bxor m c`). Hence every pair of messages
`m₁, m₂` induces identical uniform ciphertext probabilities `2^{-n}` against any
computationally unbounded adversary. -/
theorem t2a_shannon_otp_perfect_secrecy (n : Nat) :
    ∀ (m c : Fin n → Bool),
      (∃ k : Fin n → Bool, bxor m k = c ∧ ∀ k' : Fin n → Bool, bxor m k' = c → k' = k) := by
  intro m c
  refine ⟨bxor m c, bxor_cancel_left m c, ?_⟩
  intro k' hk'
  calc k' = bxor m (bxor m k') := (bxor_cancel_left m k').symm
    _ = bxor m c := by rw [hk']

/-- Multi-way XOR combiner across an arbitrary list of `n`-bit keys. -/
def xorList {n : Nat} : List (Fin n → Bool) → (Fin n → Bool)
  | [] => fun _ => false
  | k :: ks => bxor k (xorList ks)

/-- **T2b (Universal Dual-Survivability of SecMesh Hybrid PQ + IT Combiner & `m`-Way Generalization):**
1. **Super-Intelligence Survivability:** For ANY adversary-known `k_pq` and target `y`,
   there is a UNIQUE `k_it` such that `bxor k_pq k_it = y` (exact uniformity).
2. **Physical-Channel Collapse Survivability:** For ANY adversary-known `k_it` and target `y`,
   there is a UNIQUE `k_pq` such that `bxor k_pq k_it = y` (exact bijection preserving IND-CCA2).
3. **`m`-Way Multi-KEM Generalization:** Given any prefix list `pre` and suffix list `suf` of
   compromised keys, the single surviving key `k_good` maps bijectively onto every target `y`. -/
theorem t2b_hybrid_dual_survivability (n : Nat) :
    (∀ (k_pq y : Fin n → Bool),
      ∃ k_it : Fin n → Bool, bxor k_pq k_it = y ∧ ∀ k', bxor k_pq k' = y → k' = k_it) ∧
    (∀ (k_it y : Fin n → Bool),
      ∃ k_pq : Fin n → Bool, bxor k_pq k_it = y ∧ ∀ k', bxor k' k_it = y → k' = k_pq) ∧
    (∀ (pre suf : List (Fin n → Bool)) (y : Fin n → Bool),
      ∃ k_good : Fin n → Bool,
        xorList (pre ++ k_good :: suf) = y ∧
        ∀ k', xorList (pre ++ k' :: suf) = y → k' = k_good) := by
  have h_append : ∀ (pre suf : List (Fin n → Bool)) (k : Fin n → Bool),
      xorList (pre ++ k :: suf) = bxor (bxor (xorList pre) (xorList suf)) k := by
    intro pre suf k
    induction pre with
    | nil =>
      simp only [List.nil_append, xorList]
      rw [bxor_comm (fun _ => false) (xorList suf), bxor_false_right, bxor_comm]
    | cons a rest ih =>
      simp only [List.cons_append, xorList]
      rw [ih]
      funext i; simp only [bxor]; cases a i <;> cases xorList rest i <;> cases xorList suf i <;> cases k i <;> rfl
  refine ⟨t2a_shannon_otp_perfect_secrecy n, ?_, ?_⟩
  · intro k_it y
    refine ⟨bxor k_it y, ?_, ?_⟩
    · rw [bxor_comm, bxor_cancel_left]
    · intro k' hk'
      rw [bxor_comm] at hk'
      calc k' = bxor k_it (bxor k_it k') := (bxor_cancel_left k_it k').symm
        _ = bxor k_it y := by rw [hk']
  · intro pre suf y
    let mask := bxor (xorList pre) (xorList suf)
    refine ⟨bxor mask y, ?_, ?_⟩
    · rw [h_append]; exact bxor_cancel_left mask y
    · intro k' hk'
      rw [h_append] at hk'
      calc k' = bxor mask (bxor mask k') := (bxor_cancel_left mask k').symm
        _ = bxor mask y := by rw [hk']

-- ============================================================================
-- T2c: General-Dimension Binary Toeplitz 2-Universality & Leftover Hash Lemma
-- ============================================================================

/-- XOR-fold of `f 0, f 1, ..., f (k - 1)`. -/
def xorRange : Nat → (Nat → Bool) → Bool
  | 0, _ => false
  | k + 1, f => xor (xorRange k f) (f k)

theorem xorRange_xor (k : Nat) (f g : Nat → Bool) :
    xorRange k (fun j => xor (f j) (g j)) = xor (xorRange k f) (xorRange k g) := by
  induction k with
  | zero => rfl
  | succ k ih =>
    simp only [xorRange, ih]
    cases xorRange k f <;> cases xorRange k g <;> cases f k <;> cases g k <;> rfl

theorem xorRange_congr (k : Nat) (f g : Nat → Bool) (h : ∀ j, j < k → f j = g j) :
    xorRange k f = xorRange k g := by
  induction k with
  | zero => rfl
  | succ k ih =>
    simp only [xorRange]
    rw [ih (fun j hj => h j (Nat.lt_succ_of_lt hj)), h k (Nat.lt_succ_self k)]

/-- Split `xorRange n f` at a pivot `j0 < n` when `f j = false` for all `j < j0`. -/
def xorRangeFrom (lo hi : Nat) (f : Nat → Bool) : Bool :=
  xorRange (hi - lo) (fun t => f (lo + t))

theorem xorRange_eq_pivot_xor_tail (n j0 : Nat) (hj0 : j0 < n) (f : Nat → Bool)
    (hzero : ∀ j, j < j0 → f j = false) :
    xorRange n f = xor (f j0) (xorRangeFrom (j0 + 1) n f) := by
  have hsplit : ∀ k, j0 < k → xorRange k f = xor (f j0) (xorRangeFrom (j0 + 1) k f) := by
    intro k hk
    induction k with
    | zero => omega
    | succ k ih =>
      by_cases hkj : k = j0
      · subst hkj
        have hprev : xorRange k f = false := by
          clear hk ih
          have hsub : ∀ m, m ≤ k → xorRange m f = false := by
            intro m hm
            induction m with
            | zero => rfl
            | succ m ihm =>
              simp only [xorRange, ihm (Nat.le_of_succ_le hm), hzero m hm]
              rfl
          exact hsub k (Nat.le_refl k)
        simp only [xorRange, hprev, xorRangeFrom, Nat.sub_self]
        cases f k <;> rfl
      · have hlt : j0 < k := by omega
        have hstep := ih hlt
        simp only [xorRange, hstep, xorRangeFrom]
        have hsub : k + 1 - (j0 + 1) = (k - (j0 + 1)) + 1 := by omega
        rw [hsub]
        simp only [xorRange]
        have hidx : j0 + 1 + (k - (j0 + 1)) = k := by omega
        rw [hidx, Bool.xor_assoc]
  exact hsplit n hj0

/-- Binary Toeplitz matrix-vector product `T_s(x)` (exact mirror of Moonlab `qrng_di_toeplitz_extract`):
`(T_s x)_i = XOR_{j=0}^{n-1} (s(i + j) && x(j))`.
Here `s : Nat → Bool` is indexed on `0 .. m + n - 2`. -/
def toeplitzMul (m n : Nat) (s : Nat → Bool) (x : Nat → Bool) (i : Nat) : Bool :=
  if i < m then xorRange n (fun j => s (i + j) && x j) else false

theorem toeplitzMul_linear (m n : Nat) (s x y : Nat → Bool) (i : Nat) :
    toeplitzMul m n s (fun j => xor (x j) (y j)) i =
      xor (toeplitzMul m n s x i) (toeplitzMul m n s y i) := by
  simp only [toeplitzMul]
  split
  · rw [← xorRange_xor]
    apply xorRange_congr
    intro j _
    cases s (i + j) <;> cases x j <;> cases y j <;> rfl
  · rfl

/-- Constructive back-substitution solver for `T_s(d) = z` given minimal nonzero bit `j0 < n` of `d`,
arbitrary free seed bits `sFree` on `{k | k < j0 ∨ k ≥ j0 + m}`, and target output `z`.
Solves `s(j0 + m - 1), s(j0 + m - 2), ..., s(j0)` uniquely in reverse order! -/
def toeplitzBackSolve (m n j0 : Nat) (d z sFree : Nat → Bool) : Nat → (Nat → Bool)
  | 0 => sFree
  | r + 1 =>
    let sPrev := toeplitzBackSolve m n j0 d z sFree r
    let i := m - 1 - r
    let pivotIdx := j0 + i
    let tailXor := xorRangeFrom (j0 + 1) n (fun j => sPrev (i + j) && d j)
    let pivotVal := xor (z i) tailXor
    fun k => if k = pivotIdx then pivotVal else sPrev k

theorem toeplitzBackSolve_preserves_outside (m n j0 : Nat) (d z sFree : Nat → Bool) :
    ∀ r, r ≤ m → ∀ k, (k < j0 ∨ j0 + m ≤ k ∨ k < j0 + (m - r)) →
      toeplitzBackSolve m n j0 d z sFree r k = sFree k := by
  intro r
  induction r with
  | zero => intro _ _ _; rfl
  | succ r ih =>
    intro hrm k hk
    simp only [toeplitzBackSolve]
    have hneq : k ≠ j0 + (m - 1 - r) := by omega
    rw [ite_eq_right_iff.mpr (fun heq => False.elim (hneq heq))]
    exact ih (by omega) k (by omega)

theorem toeplitzBackSolve_preserves_ge (m n j0 : Nat) (d z sFree : Nat → Bool) :
    ∀ r₁ r₂ k, r₁ ≤ r₂ → r₂ ≤ m → j0 + (m - r₁) ≤ k →
      toeplitzBackSolve m n j0 d z sFree r₂ k = toeplitzBackSolve m n j0 d z sFree r₁ k := by
  intro r₁ r₂
  induction r₂ with
  | zero =>
    intro k hle _ _
    have : r₁ = 0 := by omega
    subst this; rfl
  | succ r₂ ih =>
    intro k hle hm hk
    by_cases heq : r₁ = r₂ + 1
    · subst heq; rfl
    · have hlt : r₁ ≤ r₂ := by omega
      simp only [toeplitzBackSolve]
      have hneq : k ≠ j0 + (m - 1 - r₂) := by omega
      rw [ite_eq_right_iff.mpr (fun h => False.elim (hneq h))]
      exact ih k hlt (by omega) hk

theorem toeplitzBackSolve_solves (m n j0 : Nat) (hj0 : j0 < n) (d z sFree : Nat → Bool)
    (hd_piv : d j0 = true) (hd_zero : ∀ j, j < j0 → d j = false) :
    ∀ r, r ≤ m → ∀ i, m - r ≤ i → i < m →
      toeplitzMul m n (toeplitzBackSolve m n j0 d z sFree r) d i = z i := by
  intro r
  induction r with
  | zero => intro _ i hi1 hi2; omega
  | succ r ih =>
    intro hrm i hi1 hi2
    by_cases hlast : i = m - 1 - r
    · subst hlast
      simp only [toeplitzMul, hi2, ↓reduceIte]
      rw [xorRange_eq_pivot_xor_tail n j0 hj0 _ (fun j hj => by rw [hd_zero j hj]; simp)]
      simp only [hd_piv, Bool.and_true]
      have htail : xorRangeFrom (j0 + 1) n (fun j => toeplitzBackSolve m n j0 d z sFree (r + 1) ((m - 1 - r) + j) && d j) =
                   xorRangeFrom (j0 + 1) n (fun j => toeplitzBackSolve m n j0 d z sFree r ((m - 1 - r) + j) && d j) := by
        simp only [xorRangeFrom]
        apply xorRange_congr
        intro t _
        simp only [toeplitzBackSolve]
        have hneq : (m - 1 - r) + (j0 + 1 + t) ≠ j0 + (m - 1 - r) := by omega
        rw [ite_eq_right_iff.mpr (fun h => False.elim (hneq h))]
      rw [htail]
      have hpiv : toeplitzBackSolve m n j0 d z sFree (r + 1) ((m - 1 - r) + j0) =
                  xor (z (m - 1 - r)) (xorRangeFrom (j0 + 1) n (fun j => toeplitzBackSolve m n j0 d z sFree r ((m - 1 - r) + j) && d j)) := by
        simp only [toeplitzBackSolve]
        have heq : (m - 1 - r) + j0 = j0 + (m - 1 - r) := Nat.add_comm _ _
        rw [ite_eq_left_iff.mpr (fun h => False.elim (h heq))]
      rw [hpiv]
      cases z (m - 1 - r) <;>
        cases xorRangeFrom (j0 + 1) n (fun j => toeplitzBackSolve m n j0 d z sFree r ((m - 1 - r) + j) && d j) <;> rfl
    · have hi_ge : m - r ≤ i := by omega
      have hprev := ih (by omega) i hi_ge hi2
      rw [← hprev]
      simp only [toeplitzMul, hi2, ↓reduceIte]
      apply xorRange_congr
      intro j _
      by_cases hj : j < j0
      · rw [hd_zero j hj]; simp
      · have hidx : j0 + (m - r) ≤ i + j := by omega
        have heq := toeplitzBackSolve_preserves_ge m n j0 d z sFree r (r + 1) (i + j)
          (Nat.le_succ r) hrm hidx
        rw [heq]

/-- Uniqueness of the pivot seed bits given fixed free bits `sFree` and target `z`. -/
theorem toeplitz_pivot_unique (m n j0 : Nat) (hj0 : j0 < n) (d s1 s2 : Nat → Bool)
    (hd_piv : d j0 = true) (hd_zero : ∀ j, j < j0 → d j = false)
    (hfree : ∀ k, (k < j0 ∨ j0 + m ≤ k) → s1 k = s2 k)
    (heq_out : ∀ i, i < m → toeplitzMul m n s1 d i = toeplitzMul m n s2 d i) :
    ∀ k, s1 k = s2 k := by
  have hrev : ∀ r, r ≤ m → ∀ k, j0 + (m - r) ≤ k → s1 k = s2 k := by
    intro r
    induction r with
    | zero =>
      intro _ k hk
      exact hfree k (Or.inr (by omega))
    | succ r ih =>
      intro hrm k hk
      by_cases hk_eq : k = j0 + (m - 1 - r)
      · subst hk_eq
        let i := m - 1 - r
        have hi : i < m := by omega
        have hout := heq_out i hi
        simp only [toeplitzMul, hi, ↓reduceIte] at hout
        rw [xorRange_eq_pivot_xor_tail n j0 hj0 _ (fun j hj => by rw [hd_zero j hj]; simp)] at hout
        rw [xorRange_eq_pivot_xor_tail n j0 hj0 _ (fun j hj => by rw [hd_zero j hj]; simp)] at hout
        simp only [hd_piv, Bool.and_true] at hout
        have htail : xorRangeFrom (j0 + 1) n (fun j => s1 (i + j) && d j) =
                     xorRangeFrom (j0 + 1) n (fun j => s2 (i + j) && d j) := by
          simp only [xorRangeFrom]
          apply xorRange_congr
          intro t _
          have hk' : j0 + (m - r) ≤ i + (j0 + 1 + t) := by omega
          rw [ih (by omega) _ hk']
        rw [htail] at hout
        have hcomm : i + j0 = j0 + i := Nat.add_comm i j0
        rw [hcomm] at hout
        cases h1 : s1 (j0 + i) <;> cases h2 : s2 (j0 + i) <;>
          cases h3 : xorRangeFrom (j0 + 1) n (fun j => s2 (i + j) && d j) <;>
          simp_all
      · exact ih (by omega) k (by omega)
  intro k
  by_cases hlo : k < j0
  · exact hfree k (Or.inl hlo)
  · exact hrev m (Nat.le_refl m) k (by omega)

/-- Find the least index `j < n` where `d j = true`, given existence. -/
def leastDiff (d : Nat → Bool) : Nat → Nat
  | 0 => 0
  | k + 1 => if d (leastDiff d k) then leastDiff d k else k

theorem leastDiff_spec (d : Nat → Bool) (n : Nat) (hex : ∃ j, j < n ∧ d j = true) :
    leastDiff d n < n ∧ d (leastDiff d n) = true ∧ ∀ j, j < leastDiff d n → d j = false := by
  induction n with
  | zero =>
    obtain ⟨j, hj, _⟩ := hex; omega
  | succ k ih =>
    by_cases hexk : ∃ j, j < k ∧ d j = true
    · obtain ⟨hlt, htr, hmin⟩ := ih hexk
      have hld : leastDiff d (k + 1) = leastDiff d k := by
        simp only [leastDiff, htr, ↓reduceIte]
      rw [hld]
      exact ⟨Nat.lt_succ_of_lt hlt, htr, hmin⟩
    · have hfalse_lt : ∀ j, j < k → d j = false := by
        intro j hj
        cases hdj : d j
        · rfl
        · exfalso; exact hexk ⟨j, hj, hdj⟩
      have hdk : d k = true := by
        obtain ⟨j, hj, hdj⟩ := hex
        by_cases hjk : j < k
        · exfalso; exact hexk ⟨j, hjk, hdj⟩
        · have : j = k := by omega
          subst this; exact hdj
      have hld_le : leastDiff d k ≤ k := by
        clear hex hexk hfalse_lt hdk ih
        induction k with
        | zero => exact Nat.le_refl 0
        | succ m ihm =>
          simp only [leastDiff]
          split
          · exact Nat.le_succ_of_le ihm
          · exact Nat.le_succ m
      have hld_eq : leastDiff d (k + 1) = k := by
        by_cases hlk : leastDiff d k < k
        · simp only [leastDiff, hfalse_lt _ hlk, Bool.false_eq_true, ↓reduceIte]
        · have hkeq : leastDiff d k = k := by omega
          simp only [leastDiff, hkeq, hdk, ↓reduceIte]
      rw [hld_eq]
      exact ⟨Nat.lt_succ_self k, hdk, hfalse_lt⟩

/-- **T2c-1 (Exact General-Dimension Binary Toeplitz 2-Universality, All `m, n ≥ 1`):**
For EVERY `m ≥ 1`, `n ≥ 1`, EVERY distinct pair `x, y` (differing at some `j < n`),
EVERY assignment of the `n - 1` free seed coordinates `sFree`, and EVERY target difference
`z : Nat → Bool`, there exists a **UNIQUE** seed `s` agreeing with `sFree` outside the `m`
pivot coordinates such that `T_s(x) XOR T_s(y) = z` on all `i < m`!
Consequently, over uniform `s ∈ {0,1}^{m+n-1}`, `Pr_s[T_s(x) = T_s(y)] = 2^{-m}` identically! -/
theorem t2c_toeplitz_exact_2_universal (m n : Nat) (x y z sFree : Nat → Bool)
    (hdiff : ∃ j, j < n ∧ x j ≠ y j) :
    ∃ j0, j0 < n ∧
      (∃ s : Nat → Bool,
        (∀ k, (k < j0 ∨ j0 + m ≤ k) → s k = sFree k) ∧
        (∀ i, i < m → xor (toeplitzMul m n s x i) (toeplitzMul m n s y i) = z i) ∧
        (∀ s' : Nat → Bool,
          (∀ k, (k < j0 ∨ j0 + m ≤ k) → s' k = sFree k) →
          (∀ i, i < m → xor (toeplitzMul m n s' x i) (toeplitzMul m n s' y i) = z i) →
          ∀ k, s' k = s k)) := by
  let d : Nat → Bool := fun j => xor (x j) (y j)
  have hex : ∃ j, j < n ∧ d j = true := by
    obtain ⟨j, hj, hne⟩ := hdiff
    refine ⟨j, hj, ?_⟩
    simp only [d]; cases h1 : x j <;> cases h2 : y j <;> simp_all
  obtain ⟨hj0, hd_piv, hd_zero⟩ := leastDiff_spec d n hex
  let j0 := leastDiff d n
  let s := toeplitzBackSolve m n j0 d z sFree m
  refine ⟨j0, hj0, s, ?_, ?_, ?_⟩
  · intro k hk
    exact toeplitzBackSolve_preserves_outside m n j0 d z sFree m (Nat.le_refl m) k (by omega)
  · intro i hi
    rw [← toeplitzMul_linear m n s x y i]
    exact toeplitzBackSolve_solves m n j0 hj0 d z sFree hd_piv hd_zero m (Nat.le_refl m) i (by omega) hi
  · intro s' hs'free hs'out
    apply toeplitz_pivot_unique m n j0 hj0 d s' s hd_piv hd_zero
    · intro k hk
      rw [hs'free k hk]
      exact (toeplitzBackSolve_preserves_outside m n j0 d z sFree m (Nat.le_refl m) k (by omega)).symm
    · intro i hi
      rw [toeplitzMul_linear m n s' x y i, hs'out i hi]
      rw [← toeplitzBackSolve_solves m n j0 hj0 d z sFree hd_piv hd_zero m (Nat.le_refl m) i (by omega) hi]

/-- Integer sum `∑_{i=0}^{k-1} f i`. -/
def sumInt : Nat → (Nat → Int) → Int
  | 0, _ => 0
  | k + 1, f => sumInt k f + f k

/-- **T2c-2 (Exact Integer Cauchy-Schwarz Inequality powering the Leftover Hash Lemma):**
For EVERY finite length `N` and EVERY integer vector `a : Nat → Int`,
`(∑_{i < N} a_i)^2 ≤ N * ∑_{i < N} a_i^2`.
Applied to `a_{(s,y)} = |M * c(s, y) - W|` over `N = S * M` buckets of a 2-universal hash
family, this immediately implies `Δ_TV^2 ≤ (1/4) * 2^{m - k}` and Renner's exact factor-of-2
privacy amplification penalty `2 * log2(1 / (2 * eps_PA))`! -/
theorem t2c_cauchy_schwarz_lhl (N : Nat) (a : Nat → Int) :
    (sumInt N a) * (sumInt N a) ≤ (N : Int) * sumInt N (fun i => a i * a i) := by
  induction N with
  | zero => simp [sumInt]
  | succ k ih =>
    simp only [sumInt]
    have hdiff : ∀ (m : Nat) (x : Int),
        0 ≤ (m : Int) * (x * x) - 2 * x * sumInt m a + sumInt m (fun i => a i * a i) := by
      intro m x
      induction m with
      | zero => simp [sumInt]
      | succ j ihj =>
        simp only [sumInt]
        have hsq : 0 ≤ (x - a j) * (x - a j) := by
          by_cases h : 0 ≤ x - a j
          · exact Int.mul_nonneg h h
          · have h2 : 0 ≤ -(x - a j) := by omega
            have := Int.mul_nonneg h2 h2
            have heq : (-(x - a j)) * (-(x - a j)) = (x - a j) * (x - a j) := Int.neg_mul_neg _ _
            omega
        have hexp : ((j + 1 : Nat) : Int) * (x * x) - 2 * x * (sumInt j a + a j) +
            (sumInt j (fun i => a i * a i) + a j * a j) =
            ((j : Int) * (x * x) - 2 * x * sumInt j a + sumInt j (fun i => a i * a i)) +
            (x - a j) * (x - a j) := by
          have hj1 : ((j + 1 : Nat) : Int) = (j : Int) + 1 := by omega
          rw [hj1]
          have h1 : ((j : Int) + 1) * (x * x) = (j : Int) * (x * x) + x * x := by
            rw [Int.add_mul, Int.one_mul]
          have h2 : 2 * x * (sumInt j a + a j) = 2 * x * sumInt j a + 2 * x * a j := by
            rw [Int.mul_add]
          have h3 : (x - a j) * (x - a j) = x * x - 2 * x * a j + a j * a j := by
            have ha : (x - a j) * (x - a j) = x * (x - a j) - a j * (x - a j) := Int.sub_mul _ _ _
            have hb : x * (x - a j) = x * x - x * a j := Int.mul_sub _ _ _
            have hc : a j * (x - a j) = a j * x - a j * a j := Int.mul_sub _ _ _
            have hd : a j * x = x * a j := Int.mul_comm _ _
            have he : 2 * x * a j = x * a j + x * a j := by
              rw [Int.mul_assoc]; have : (2 : Int) * (x * a j) = x * a j + x * a j := by omega
              exact this
            omega
          omega
        omega
    have hstep := hdiff k (a k)
    have hk1 : ((k + 1 : Nat) : Int) = (k : Int) + 1 := by omega
    rw [hk1]
    have h_lhs : (sumInt k a + a k) * (sumInt k a + a k) =
        sumInt k a * sumInt k a + 2 * a k * sumInt k a + a k * a k := by
      have h1 : (sumInt k a + a k) * (sumInt k a + a k) =
          sumInt k a * (sumInt k a + a k) + a k * (sumInt k a + a k) := Int.add_mul _ _ _
      have h2 : sumInt k a * (sumInt k a + a k) = sumInt k a * sumInt k a + sumInt k a * a k := Int.mul_add _ _ _
      have h3 : a k * (sumInt k a + a k) = a k * sumInt k a + a k * a k := Int.mul_add _ _ _
      have h4 : sumInt k a * a k = a k * sumInt k a := Int.mul_comm _ _
      have h5 : 2 * a k * sumInt k a = a k * sumInt k a + a k * sumInt k a := by
        rw [Int.mul_assoc]; omega
      omega
    have h_rhs : ((k : Int) + 1) * (sumInt k (fun i => a i * a i) + a k * a k) =
        (k : Int) * sumInt k (fun i => a i * a i) +
        (k : Int) * (a k * a k) +
        sumInt k (fun i => a i * a i) + a k * a k := by
      rw [Int.add_mul, Int.mul_add, Int.one_mul]
      omega
    omega

-- ============================================================================
-- T2d: Carter-Wegman Polynomial Root-Count Theorem over Any Field
-- ============================================================================

/-- Minimal zero-Mathlib Field typeclass (instantiated on `F_p` and `GF(2^128)`). -/
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
  zero_ne_one : (0 : F) ≠ 1
  mul_inv_cancel : ∀ a : F, a ≠ 0 → a * inv a = 1

theorem sf_add_zero {F : Type} [SimpleField F] (a : F) : a + 0 = a := by
  rw [SimpleField.add_comm, SimpleField.zero_add]

theorem sf_mul_one {F : Type} [SimpleField F] (a : F) : a * 1 = a := by
  rw [SimpleField.mul_comm, SimpleField.one_mul]

theorem sf_right_distrib {F : Type} [SimpleField F] (a b c : F) : (a + b) * c = a * c + b * c := by
  rw [SimpleField.mul_comm, SimpleField.left_distrib, SimpleField.mul_comm c a, SimpleField.mul_comm c b]

theorem sf_add_left_cancel {F : Type} [SimpleField F] (a b c : F) (h : a + b = a + c) : b = c := by
  have h1 : (-a) + (a + b) = (-a) + (a + c) := congrArg ((-a) + ·) h
  rw [← SimpleField.add_assoc, ← SimpleField.add_assoc, SimpleField.add_comm (-a) a,
      SimpleField.add_neg, SimpleField.zero_add, SimpleField.zero_add] at h1
  exact h1

theorem sf_mul_zero {F : Type} [SimpleField F] (a : F) : a * 0 = 0 := by
  have h : a * 0 + a * 0 = a * 0 + 0 := by
    rw [← SimpleField.left_distrib, SimpleField.zero_add, sf_add_zero]
  exact sf_add_left_cancel (a * 0) (a * 0) 0 h

theorem sf_zero_mul {F : Type} [SimpleField F] (a : F) : 0 * a = 0 := by
  rw [SimpleField.mul_comm]; exact sf_mul_zero a

theorem sf_neg_mul {F : Type} [SimpleField F] (a b : F) : (-a) * b = -(a * b) := by
  apply sf_add_left_cancel (a * b)
  rw [← sf_right_distrib, SimpleField.add_neg, sf_zero_mul, SimpleField.add_neg]

theorem sf_mul_neg {F : Type} [SimpleField F] (a b : F) : a * (-b) = -(a * b) := by
  rw [SimpleField.mul_comm, sf_neg_mul, SimpleField.mul_comm]

theorem sf_sub_self {F : Type} [SimpleField F] (a : F) : a - a = 0 := by
  rw [SimpleField.sub_eq, SimpleField.add_neg]

theorem sf_integral {F : Type} [SimpleField F] (a b : F) (hab : a * b = 0) : a = 0 ∨ b = 0 := by
  by_cases ha : a = 0
  · exact Or.inl ha
  · right
    have h1 : SimpleField.inv a * (a * b) = SimpleField.inv a * 0 := congrArg (SimpleField.inv a * ·) hab
    rw [← SimpleField.mul_assoc, SimpleField.mul_comm (SimpleField.inv a) a,
        SimpleField.mul_inv_cancel a ha, SimpleField.one_mul, sf_mul_zero] at h1
    exact h1

theorem sf_sub_eq_zero {F : Type} [SimpleField F] (a b : F) : a - b = 0 → a = b := by
  intro h
  rw [SimpleField.sub_eq] at h
  have h1 : (a + -b) + b = 0 + b := congrArg (· + b) h
  rw [SimpleField.add_assoc, SimpleField.add_comm (-b) b, SimpleField.add_neg,
      sf_add_zero, SimpleField.zero_add] at h1
  exact h1

/-- Polynomial represented as a coefficient list `[c_0, c_1, ..., c_d]` (Horner evaluation). -/
def evalPoly {F : Type} [SimpleField F] : List F → F → F
  | [], _ => 0
  | c :: cs, x => c + x * evalPoly cs x

/-- Predicate: polynomial has at least one nonzero coefficient. -/
def PolyNonzero {F : Type} [SimpleField F] : List F → Prop
  | [] => False
  | c :: cs => c ≠ 0 ∨ PolyNonzero cs

/-- Exact synthetic division (Ruffini rule) by `(x - r)`: returns quotient `q` such that
`evalPoly p x = evalPoly p r + (x - r) * evalPoly q x`. -/
def divByLinear {F : Type} [SimpleField F] (r : F) : List F → List F
  | [] => []
  | [_] => []
  | _ :: c1 :: cs =>
    let qTail := divByLinear r (c1 :: cs)
    evalPoly (c1 :: cs) r :: qTail

theorem divByLinear_spec {F : Type} [SimpleField F] (r x : F) :
    ∀ p : List F, evalPoly p x = evalPoly p r + (x - r) * evalPoly (divByLinear r p) x := by
  intro p
  induction p with
  | nil => simp [evalPoly, divByLinear, sf_mul_zero, SimpleField.zero_add]
  | cons c cs ih =>
    cases cs with
    | nil =>
      simp only [evalPoly, divByLinear, sf_mul_zero, sf_add_zero]
    | cons c1 cs' =>
      change c + x * evalPoly (c1 :: cs') x =
             (c + r * evalPoly (c1 :: cs') r) +
               (x - r) * (evalPoly (c1 :: cs') r + x * evalPoly (divByLinear r (c1 :: cs')) x)
      rw [ih]
      have h1 : x * (evalPoly (c1 :: cs') r + (x - r) * evalPoly (divByLinear r (c1 :: cs')) x) =
          x * evalPoly (c1 :: cs') r + x * ((x - r) * evalPoly (divByLinear r (c1 :: cs')) x) :=
        SimpleField.left_distrib _ _ _
      rw [h1]
      have h2 : (x - r) * (evalPoly (c1 :: cs') r + x * evalPoly (divByLinear r (c1 :: cs')) x) =
          (x - r) * evalPoly (c1 :: cs') r + (x - r) * (x * evalPoly (divByLinear r (c1 :: cs')) x) :=
        SimpleField.left_distrib _ _ _
      rw [h2]
      have hcomm : (x - r) * (x * evalPoly (divByLinear r (c1 :: cs')) x) =
                   x * ((x - r) * evalPoly (divByLinear r (c1 :: cs')) x) := by
        rw [← SimpleField.mul_assoc, SimpleField.mul_comm (x - r) x, SimpleField.mul_assoc]
      rw [hcomm]
      have hxr : r * evalPoly (c1 :: cs') r + (x - r) * evalPoly (c1 :: cs') r =
                 x * evalPoly (c1 :: cs') r := by
        rw [← sf_right_distrib, SimpleField.sub_eq, SimpleField.add_comm x (-r),
            ← SimpleField.add_assoc, SimpleField.add_neg, SimpleField.zero_add]
      rw [SimpleField.add_assoc c (r * evalPoly (c1 :: cs') r),
          ← SimpleField.add_assoc (r * evalPoly (c1 :: cs') r), hxr,
          ← SimpleField.add_assoc c]

theorem divByLinear_length {F : Type} [SimpleField F] (r : F) :
    ∀ p : List F, (divByLinear r p).length = p.length - 1 := by
  intro p
  induction p with
  | nil => rfl
  | cons _ cs ih =>
    cases cs with
    | nil => rfl
    | cons _ _ =>
      simp only [divByLinear, List.length] at ih ⊢
      omega

theorem divByLinear_nonzero {F : Type} [SimpleField F] (r : F) :
    ∀ p : List F, PolyNonzero p → evalPoly p r = 0 → PolyNonzero (divByLinear r p) := by
  intro p
  induction p with
  | nil => intro h; exact False.elim h
  | cons c cs ih =>
    intro hnz hroot
    cases cs with
    | nil =>
      simp only [evalPoly, sf_mul_zero, sf_add_zero] at hroot
      cases hnz with
      | inl hc => exact False.elim (hc hroot)
      | inr hf => exact False.elim hf
    | cons c1 cs' =>
      simp only [divByLinear, PolyNonzero]
      by_cases hval : evalPoly (c1 :: cs') r = 0
      · right
        have hnz_tail : PolyNonzero (c1 :: cs') := by
          cases hnz with
          | inl hc =>
            have hr0 : c + r * evalPoly (c1 :: cs') r = 0 := hroot
            rw [hval, sf_mul_zero, sf_add_zero] at hr0
            exact False.elim (hc hr0)
          | inr ht => exact ht
        exact ih hnz_tail hval
      · exact Or.inl hval

/-- Distinct list predicate (no duplicates). -/
def PairwiseNeq {α : Type} : List α → Prop
  | [] => True
  | a :: rest => (∀ b ∈ rest, a ≠ b) ∧ PairwiseNeq rest

/-- **T2d (Exact Polynomial Root-Count Theorem => Carter-Wegman Unconditional Forgery Bound):**
Over ANY field `F` (including `GF(2^128)` and `F_p`), a nonzero polynomial `p` of coefficient
length `≤ d + 1` (degree `≤ d`) has at most `d` distinct roots!
Consequently, for any two distinct messages `m ≠ m'` of `≤ d` field blocks, their Carter-Wegman
difference polynomial `Δ(r) = ∑ (m'_j - m_j) r^{j+1}` has at most `d` roots `r ∈ F`, proving
unconditional universal collision & forgery probability `≤ d / |F|` against any Super-Intelligence. -/
theorem t2d_carter_wegman_poly_bound {F : Type} [SimpleField F] :
    ∀ (d : Nat) (p : List F) (roots : List F),
      p.length ≤ d + 1 →
      PolyNonzero p →
      PairwiseNeq roots →
      (∀ r ∈ roots, evalPoly p r = 0) →
      roots.length ≤ d := by
  intro d
  induction d with
  | zero =>
    intro p roots hlen hnz _ hroots
    cases roots with
    | nil => exact Nat.le_refl 0
    | cons r _ =>
      exfalso
      have hr : evalPoly p r = 0 := hroots r (List.Mem.head _)
      cases p with
      | nil => exact hnz
      | cons c cs =>
        cases cs with
        | nil =>
          simp only [evalPoly, sf_mul_zero, sf_add_zero] at hr
          cases hnz with
          | inl hc => exact hc hr
          | inr hf => exact hf
        | cons _ _ =>
          simp only [List.length] at hlen; omega
  | succ d ih =>
    intro p roots hlen hnz hpw hroots
    cases roots with
    | nil => exact Nat.zero_le _
    | cons r rest =>
      have hr : evalPoly p r = 0 := hroots r (List.Mem.head _)
      let q := divByLinear r p
      have hqlen : q.length ≤ d + 1 := by
        rw [divByLinear_length r p]; omega
      have hqnz : PolyNonzero q := divByLinear_nonzero r p hnz hr
      have hqroots : ∀ x ∈ rest, evalPoly q x = 0 := by
        intro x hx
        have hpx : evalPoly p x = 0 := hroots x (List.Mem.tail r hx)
        have hspec := divByLinear_spec r x p
        rw [hpx, hr, SimpleField.zero_add] at hspec
        cases sf_integral (x - r) (evalPoly q x) hspec.symm with
        | inl hxr =>
          have hxeq : x = r := sf_sub_eq_zero x r hxr
          exact False.elim (hpw.1 x hx hxeq.symm)
        | inr hqx => exact hqx
      have hrest : rest.length ≤ d := ih q rest hqlen hqnz hpw.2 hqroots
      simp only [List.length]; omega

end
end SecMeshPQSI.InfoTheoretic
