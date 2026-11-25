module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

/-!
# Theorem Family T5: FIPS 203 ML-KEM Algebraic Invariants & Complete-Graph `K_N` PQ Wire-Bandwidth Law

Zero-Mathlib Lean 4.35.0 proofs certifying Moonlab's C11 FIPS 203 ML-KEM arithmetic and
extending `Tsotchke-Corporation/pq-consensus-bandwidth` to complete-graph `K_N` SecMesh:
- `t5a_fips203_ntt_prime_and_root`: Exact proof that `q = 3329` is prime, `3329 = 13 * 256 + 1`,
  and `zeta = 17` is an exact primitive 256-th root of unity mod `3329`
  (`17^128 ≡ 3328 ≡ -1 (mod 3329)` and `17^256 ≡ 1 (mod 3329)`).
- `t5b_montgomery_reduction_exact`: Exact proof for EVERY integer `a` with `|a| < 2^15 * 3329`
  that Moonlab `poly.c`'s Montgomery reduction (`q = 3329`, `QINV = -3327`, `R = 2^16`) is
  EXACTLY divisible by `2^16`, satisfies `r * 2^16 ≡ a (mod 3329)`, and stays strictly within
  `-3329 < r < 3329` (zero silent overflow!).
- `t5c_mlkem_compress1_margin`: Exact FIPS 203 `Compress_1` / `Decompress_1` error-free
  decryption theorem: for EVERY message bit `b ∈ {0, 1}` and EVERY noise `|e| ≤ 831`,
  rounding decoding recovers `b` with 100% deterministic exactness.
- `t5d_kn_mesh_bandwidth_and_hedge_overhead`: Complete-graph `K_N` edge scaling
  `2 * E(N) = N * (N - 1)`, exact node-count ceiling optimality `N_max = B / S + 1`, and
  exact proof that classical+IT hedging (`+112 B` Ed25519 + CW-128 IT-MAC) adds `< 1.75%`
  wire overhead atop pure PQ (`6573 B` -> `6685 B`).
-/

namespace SecMeshPQSI.LatticeBandwidth

@[expose] public section

def IsPrime (p : Nat) : Prop :=
  2 ≤ p ∧ ∀ d : Nat, d ∣ p → d = 1 ∨ d = p

def noDivisorBelow (p : Nat) : Nat → Bool
  | 0 => true
  | 1 => true
  | 2 => true
  | k + 1 => (p % k != 0) && noDivisorBelow p k

private theorem noDivisorBelow_sound (p n : Nat) (h : noDivisorBelow p n = true) :
    ∀ d, 2 ≤ d → d < n → p % d ≠ 0 := by
  induction n with
  | zero => intro d _ hd; omega
  | succ k ih =>
    cases k with
    | zero => intro d hd1 hd2; omega
    | succ k' =>
      cases k' with
      | zero => intro d hd1 hd2; omega
      | succ k'' =>
        simp only [noDivisorBelow, Bool.and_eq_true, bne_iff_ne, ne_eq] at h
        intro d hd1 hd2
        by_cases hdk : d = k'' + 2
        · subst hdk; exact h.1
        · exact ih h.2 d hd1 (by omega)

def powMod (base exp mod : Nat) : Nat :=
  match exp with
  | 0 => 1 % mod
  | e + 1 => (powMod base e mod * base) % mod

private theorem powMod_add (b e1 e2 m : Nat) (hm : 1 < m) :
    powMod b (e1 + e2) m = (powMod b e1 m * powMod b e2 m) % m := by
  induction e2 with
  | zero =>
    simp only [Nat.add_zero, powMod]
    have h1 : 1 % m = 1 := Nat.mod_eq_of_lt hm
    rw [h1, Nat.mul_one]
    cases e1 with
    | zero => simp [powMod, h1]
    | succ k => simp [powMod]
  | succ k ih =>
    rw [← Nat.add_assoc]
    simp only [powMod, ih]
    rw [Nat.mod_mul_mod, Nat.mul_mod_mod, Nat.mul_assoc]

/-- **T5a (FIPS 203 ML-KEM Prime `q = 3329` & Primitive 256-th NTT Root `zeta = 17`):**
1. `3329` is prime (`IsPrime 3329`),
2. `3329 = 13 * 256 + 1`,
3. `17^128 % 3329 = 3328` (i.e., `17^128 ≡ -1 (mod 3329)`) and `17^256 % 3329 = 1`,
   certifying the negacyclic NTT factorization `Z_3329[X]/(X^256 + 1) ≅ ∏ Z_3329[X]/(X^2 - zeta^{2*br(i)+1})`! -/
theorem t5a_fips203_ntt_prime_and_root :
    IsPrime 3329 ∧
    3329 = 13 * 256 + 1 ∧
    powMod 17 128 3329 = 3328 ∧
    powMod 17 256 3329 = 1 := by
  have hp16 : powMod 17 16 3329 = 2642 := by decide
  have hp32 : powMod 17 32 3329 = 2580 := by
    have h := powMod_add 17 16 16 3329 (by decide)
    rw [hp16] at h
    exact h
  have hp64 : powMod 17 64 3329 = 1729 := by
    have h := powMod_add 17 32 32 3329 (by decide)
    rw [hp32] at h
    exact h
  have hp128 : powMod 17 128 3329 = 3328 := by
    have h := powMod_add 17 64 64 3329 (by decide)
    rw [hp64] at h
    exact h
  have hp256 : powMod 17 256 3329 = 1 := by
    have h := powMod_add 17 128 128 3329 (by decide)
    rw [hp128] at h
    exact h
  refine ⟨⟨by decide, ?_⟩, by decide, hp128, hp256⟩
  intro d hd
  have hnd : noDivisorBelow 3329 59 = true := by decide
  have hnd_s := noDivisorBelow_sound 3329 59 hnd
  rcases hd with ⟨k, hk⟩
  have hd_pos : 0 < d := by
    by_cases h0 : d = 0
    · subst h0; simp at hk
    · omega
  have hk_pos : 0 < k := by
    by_cases h0 : k = 0
    · subst h0; simp at hk
    · omega
  by_cases hd1 : d = 1
  · exact Or.inl hd1
  · by_cases hk1 : k = 1
    · right; subst hk1; omega
    · exfalso
      have hmin : d < 59 ∨ k < 59 := by
        by_cases h1 : d < 59
        · exact Or.inl h1
        · by_cases h2 : k < 59
          · exact Or.inr h2
          · exfalso
            have hm : 59 * 59 ≤ d * k := Nat.mul_le_mul (by omega) (by omega)
            omega
      cases hmin with
      | inl hdl =>
        have hmod : 3329 % d = 0 := by rw [hk]; exact Nat.mul_mod_right d k
        exact hnd_s d (by omega) hdl hmod
      | inr hkl =>
        have hmod : 3329 % k = 0 := by rw [hk]; exact Nat.mul_mod_left d k
        exact hnd_s k (by omega) hkl hmod

/-- Signed 16-bit wrap `toInt16(x) ∈ [-32768, 32767]` congruent to `x (mod 65536)`. -/
def toInt16 (x : Int) : Int :=
  let r := x % 65536
  if r < 32768 then r else r - 65536

/-- Moonlab `poly.c` Montgomery reduction `montgomery_reduce(a)` for `q = 3329`, `QINV = -3327`. -/
def montgomeryReduce (a : Int) : Int :=
  let t := toInt16 (a * (-3327))
  (a - t * 3329) / 65536

/-- **T5b (Exact FIPS 203 / Moonlab Montgomery Reduction Soundness & Zero-Overflow Bound):**
For EVERY integer `a` with `-32768 * 3329 < a < 32768 * 3329`:
1. `65536 ∣ (a - t * 3329)` (exact zero remainder),
2. `montgomeryReduce a * 65536 ≡ a (mod 3329)`,
3. `-3329 < montgomeryReduce a < 3329` (strictly bounded, zero silent int16 overflow!). -/
theorem t5b_montgomery_reduction_exact (a : Int)
    (hlo : -32768 * 3329 < a) (hhi : a < 32768 * 3329) :
    let t := toInt16 (a * (-3327))
    let r := montgomeryReduce a
    (a - t * 3329) % 65536 = 0 ∧
    (r * 65536 - a) % 3329 = 0 ∧
    -3329 < r ∧ r < 3329 := by
  dsimp only [montgomeryReduce, toInt16]
  let m := (a * (-3327)) % 65536
  have hm_lo : 0 ≤ m := Int.emod_nonneg _ (by decide)
  have hm_hi : m < 65536 := Int.emod_lt_of_pos _ (by decide)
  have hinv : (-3327 : Int) * 3329 = 1 - 169 * 65536 := by decide
  have hm_eq : ∃ qm : Int, a * (-3327) = 65536 * qm + m :=
    ⟨(a * (-3327)) / 65536, by omega⟩
  obtain ⟨qm, hqm⟩ := hm_eq
  have hdiv_m : (a - m * 3329) % 65536 = 0 := by
    have hmul : a - m * 3329 = 65536 * (qm * 3329 + 169 * a) := by grind
    rw [hmul, Int.mul_emod_right]
  change (a - (if m < 32768 then m else m - 65536) * 3329) % 65536 = 0 ∧
         ((a - (if m < 32768 then m else m - 65536) * 3329) / 65536 * 65536 - a) % 3329 = 0 ∧
         -3329 < (a - (if m < 32768 then m else m - 65536) * 3329) / 65536 ∧
         (a - (if m < 32768 then m else m - 65536) * 3329) / 65536 < 3329
  by_cases hlt : m < 32768
  · simp only [hlt, ↓reduceIte]
    have hq_exact : (a - m * 3329) / 65536 * 65536 = a - m * 3329 := by omega
    refine ⟨hdiv_m, ?_, ?_, ?_⟩
    · rw [hq_exact]
      have h1 : a - m * 3329 - a = (-m) * 3329 := by grind
      rw [h1, Int.mul_emod_left]
    · omega
    · omega
  · simp only [hlt, ↓reduceIte]
    have hdiv2 : (a - (m - 65536) * 3329) % 65536 = 0 := by
      have h1 : a - (m - 65536) * 3329 = (a - m * 3329) + 65536 * 3329 := by grind
      rw [h1, Int.add_emod, hdiv_m, Int.mul_emod_right]
      rfl
    have hq_exact : (a - (m - 65536) * 3329) / 65536 * 65536 = a - (m - 65536) * 3329 := by omega
    refine ⟨hdiv2, ?_, ?_, ?_⟩
    · rw [hq_exact]
      have h1 : a - (m - 65536) * 3329 - a = (-(m - 65536)) * 3329 := by grind
      rw [h1, Int.mul_emod_left]
    · omega
    · omega

/-- FIPS 203 `Compress_1` decryption decoder on `Z_3329`. -/
def mlkemCompress1 (y : Int) : Int :=
  let ym := y % 3329
  ((2 * ym + 1665) / 3329) % 2

/-- **T5c (Exact FIPS 203 `Compress_1` / `Decompress_1` Zero-Error Decoding Margin):**
For EVERY message bit `b ∈ {0, 1}` encoded as `b * 1665` (`⌊(q+1)/2⌋ = 1665`) and EVERY
decryption noise integer `e` with `|e| ≤ 831` (`< q / 4 = 832.25`), FIPS 203 rounding
decodes `b` with **100% deterministic exactness**! -/
theorem t5c_mlkem_compress1_margin (b e : Int)
    (hb : b = 0 ∨ b = 1) (hlo : -831 ≤ e) (hhi : e ≤ 831) :
    mlkemCompress1 (b * 1665 + e) = b := by
  unfold mlkemCompress1
  cases hb with
  | inl hb0 =>
    subst hb0
    simp only [Int.zero_mul, Int.zero_add]
    by_cases hneg : 0 ≤ e
    · have hm : e % 3329 = e := Int.emod_eq_of_lt hneg (by omega)
      rw [hm]; omega
    · have hm : e % 3329 = e + 3329 := by
        have h1 : e + 3329 = (e + 3329) % 3329 := (Int.emod_eq_of_lt (by omega) (by omega)).symm
        rw [Int.add_emod_right] at h1
        exact h1.symm
      rw [hm]; omega
  | inr hb1 =>
    subst hb1
    simp only [Int.one_mul]
    have hm : (1665 + e) % 3329 = 1665 + e := Int.emod_eq_of_lt (by omega) (by omega)
    rw [hm]; omega

/-- Complete-graph `K_N` pairwise link count `N * (N - 1) / 2`. -/
def completeEdges (N : Nat) : Nat := N * (N - 1) / 2

/-- Complete-graph `K_N` node-count ceiling under per-node byte budget `B` and handshake size `S`. -/
def meshCeiling (B S : Nat) : Nat := B / S + 1

/-- **T5d (Complete-Graph `K_N` Wire-Scaling & Composite Hedge Overhead Law):**
1. Exact complete-graph edge identity: `2 * completeEdges N = N * (N - 1)` for all `N`.
2. Exact ceiling optimality: for any positive wire cost `S > 0` and per-node budget `B`,
   `N_max = meshCeiling B S` satisfies `(N_max - 1) * S ≤ B` (feasible!) and
   `N_max * S > B` (strictly tight: adding one more node exceeds budget!).
3. Exact SecMesh-PQSI hedge overhead bound: adding Ed25519 (`32 + 64 = 96 B`) plus
   Carter-Wegman `GF(2^128)` IT-MAC (`16 B`) onto pure PQ ML-KEM-768 + ML-DSA-65 (`6573 B`
   one-way) yields `6685 B`, which is strictly less than `1.75%` overhead (`112 * 400 < 7 * 6573`)! -/
theorem t5d_kn_mesh_bandwidth_and_hedge_overhead :
    (∀ N : Nat, 2 * completeEdges N = N * (N - 1)) ∧
    (∀ B S : Nat, 0 < S →
      (meshCeiling B S - 1) * S ≤ B ∧ B < meshCeiling B S * S) ∧
    (6573 + 96 + 16 = 6685 ∧ (96 + 16) * 400 < 7 * 6573) := by
  refine ⟨?_, ?_, by decide⟩
  · intro N
    unfold completeEdges
    have heven : N * (N - 1) % 2 = 0 := by
      cases N with
      | zero => rfl
      | succ k =>
        simp only [Nat.add_sub_cancel]
        have hcases : k % 2 = 0 ∨ k % 2 = 1 := by omega
        cases hcases with
        | inl h0 =>
          have h1 : (k + 1) * k % 2 = ((k + 1) % 2 * (k % 2)) % 2 := Nat.mul_mod _ _ 2
          rw [h1, h0]; rfl
        | inr h1 =>
          have h2 : (k + 1) % 2 = 0 := by omega
          have h3 : (k + 1) * k % 2 = ((k + 1) % 2 * (k % 2)) % 2 := Nat.mul_mod _ _ 2
          rw [h3, h2]; simp
    have hdm := Nat.div_add_mod (N * (N - 1)) 2
    rw [heven, Nat.add_zero] at hdm
    exact hdm
  · intro B S hS
    unfold meshCeiling
    simp only [Nat.add_sub_cancel]
    have hdm := Nat.div_add_mod B S
    have hlt := Nat.mod_lt B hS
    have hmul : (B / S + 1) * S = S * (B / S) + S := by
      rw [Nat.add_mul, Nat.one_mul, Nat.mul_comm (B / S) S]
    have hmul0 : (B / S) * S = S * (B / S) := Nat.mul_comm _ _
    omega

end
end SecMeshPQSI.LatticeBandwidth
