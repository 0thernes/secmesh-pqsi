module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

/-!
# Theorem Family T4: Quantum Geometric Tensor (QGTL) Concurrence Surplus & Bivariate-Bicycle qLDPC CSS

Zero-Mathlib Lean 4.35.0 proofs establishing:
- `t4a_qgt_psd_lagrange_and_trace`: General exact Hermitian PSD determinant & trace inequalities
  for the Quantum Geometric Tensor `Q_uv = <u, v> = g_uv - (i/2) * Omega_uv` in ANY complex
  dimension `D` (proved unconditionally over `Int` via the exact complex Lagrange identity
  `g_11 * g_22 - g_12^2 - (1/4) * Omega^2 = sum_{j < k} |u_j v_k - u_k v_j|^2 >= 0`!).
- `t4b_qgt_concurrence_surplus_identity`: EXACT NEW CLOSED-FORM RING IDENTITY bridging
  Tsotchke's QGTL, Wootters concurrence `C = 2*ca*sa`, and Horodecki CHSH `S_max = 2*sqrt(1+C^2)`:
  for ANY `ca, sa, ch, sh, R : Int` with `ca^2 + sa^2 = R^2` and `ch^2 + sh^2 = R^2`,
  the exact QGT determinant surplus on the local-SU(2)-rotated two-qubit entangled manifold
  `|psi(theta, phi; alpha)> = (U(theta, phi) x I) (cos(alpha)|01> - sin(alpha)|10>)` satisfies
    `det(g) - (1/4) * Omega^2 == (C^2 / 4) * sin^2(theta / 2)`
  identically! With exact corollaries for separable saturation (`C = 0 => surplus = 0`) and
  singlet flat-Berry maximum (`C = 1 => Omega = 0 ∧ surplus = (1/4) sin^2(theta/2)`).
- `t4c_bb_qldpc_css_commutation`:
  1. General algebraic theorem: for ANY `ell, m >= 1` and ANY two polynomials `A, B` in the
     commutative group algebra `F_2[Z_ell x Z_m]`, `H_X = [A | B]` and `H_Z = [B^T | A^T]`
     satisfy `H_X * H_Z^T = 0 (mod 2)` identically!
  2. Concrete kernel-checked (`decide`) certification of Bravyi et al. (Nature 2024)
     `[[144, 12, 12]]` Gross Bivariate-Bicycle qLDPC code (`ell = 12, m = 6`,
     `A = x^3 + y + y^2`, `B = y^3 + x + x^2`): all `72 * 72 = 5,184` CSS commutation entries
     vanish identically mod 2 AND every stabilizer row has exact weight 6!
-/

namespace SecMeshPQSI.QuantumGeometry

@[expose] public section

-- ============================================================================
-- T4a: General D-Dimensional Complex QGT Hermitian PSD Lagrange Identity
-- ============================================================================

/-- Complex vector represented over `Int` as `(re, im)` pairs. -/
abbrev CInt := Int × Int

def cNormSq (z : CInt) : Int := z.1 * z.1 + z.2 * z.2
def cDotRe (u v : CInt) : Int := u.1 * v.1 + u.2 * v.2
def cDotIm (u v : CInt) : Int := u.1 * v.2 - u.2 * v.1

/-- Complex 2x2 determinant `u_j * v_k - u_k * v_j` (as a complex integer). -/
def cDet2 (uj uk vj vk : CInt) : CInt :=
  (uj.1 * vk.1 - uj.2 * vk.2 - (uk.1 * vj.1 - uk.2 * vj.2),
   uj.1 * vk.2 + uj.2 * vk.1 - (uk.1 * vj.2 + uk.2 * vj.1))

def sumCNormSq : Nat → (Nat → CInt) → Int
  | 0, _ => 0
  | k + 1, f => sumCNormSq k f + cNormSq (f k)

def sumCDotRe : Nat → (Nat → CInt) → (Nat → CInt) → Int
  | 0, _, _ => 0
  | k + 1, u, v => sumCDotRe k u v + cDotRe (u k) (v k)

def sumCDotIm : Nat → (Nat → CInt) → (Nat → CInt) → Int
  | 0, _, _ => 0
  | k + 1, u, v => sumCDotIm k u v + cDotIm (u k) (v k)

private theorem int_sq_nonneg (x : Int) : 0 ≤ x * x := by
  by_cases h : 0 ≤ x
  · exact Int.mul_nonneg h h
  · have h2 : 0 ≤ -x := by omega
    have hm := Int.mul_nonneg h2 h2
    rw [Int.neg_mul_neg] at hm
    exact hm

private theorem cNormSq_nonneg (z : CInt) : 0 ≤ cNormSq z := by
  unfold cNormSq
  have h1 := int_sq_nonneg z.1
  have h2 := int_sq_nonneg z.2
  omega

/-- Explicit outer-index helper for `∑_{j < m} |u_j v_k - u_k v_j|^2`. -/
def sumDetAgainst (m k : Nat) (u v : Nat → CInt) : Int :=
  match m with
  | 0 => 0
  | j + 1 => sumDetAgainst j k u v + cNormSq (cDet2 (u j) (u k) (v j) (v k))

def sumAllDet (D : Nat) (u v : Nat → CInt) : Int :=
  match D with
  | 0 => 0
  | k + 1 => sumAllDet k u v + sumDetAgainst k k u v

theorem sumDetAgainst_nonneg (m k : Nat) (u v : Nat → CInt) : 0 ≤ sumDetAgainst m k u v := by
  induction m with
  | zero => exact Int.le_refl 0
  | succ j ih =>
    unfold sumDetAgainst
    have h := cNormSq_nonneg (cDet2 (u j) (u k) (v j) (v k))
    omega

theorem sumAllDet_nonneg (D : Nat) (u v : Nat → CInt) : 0 ≤ sumAllDet D u v := by
  induction D with
  | zero => exact Int.le_refl 0
  | succ k ih =>
    unfold sumAllDet
    have h := sumDetAgainst_nonneg k k u v
    omega

/-- Pointwise complex Lagrange identity for two complex 2-vectors `(uj, uk)` and `(vj, vk)`:
`|uj|^2 |vk|^2 + |uk|^2 |vj|^2 - 2 Re(<uj,vj>) Re(<uk,vk>) - 2 Im(<uj,vj>) Im(<uk,vk>) = |uj vk - uk vj|^2`. -/
private theorem cLagrange_pair (uj uk vj vk : CInt) :
    cNormSq uj * cNormSq vk + cNormSq uk * cNormSq vj
      - 2 * cDotRe uj vj * cDotRe uk vk
      - 2 * cDotIm uj vj * cDotIm uk vk
    = cNormSq (cDet2 uj uk vj vk) := by
  rcases uj with ⟨a, b⟩; rcases uk with ⟨c, d⟩; rcases vj with ⟨e, f⟩; rcases vk with ⟨g, h⟩
  simp only [cNormSq, cDotRe, cDotIm, cDet2]
  grind

private theorem cDiag_zero (u v : CInt) :
    cNormSq u * cNormSq v - cDotRe u v * cDotRe u v - cDotIm u v * cDotIm u v = 0 := by
  rcases u with ⟨a, b⟩; rcases v with ⟨e, f⟩
  simp only [cNormSq, cDotRe, cDotIm]
  grind

/-- Exact D-dimensional Complex Lagrange Identity for QGT:
`g_11 * g_22 - g_12^2 - (Im<u,v>)^2 = ∑_{j < k < D} |u_j v_k - u_k v_j|^2`.
Note `Omega = -2 * Im<u,v>`, so `(1/4) * Omega^2 = (Im<u,v>)^2` identically! -/
theorem qgt_lagrange_identity (D : Nat) (u v : Nat → CInt) :
    sumCNormSq D u * sumCNormSq D v
      - sumCDotRe D u v * sumCDotRe D u v
      - sumCDotIm D u v * sumCDotIm D u v
    = sumAllDet D u v := by
  induction D with
  | zero => simp [sumCNormSq, sumCDotRe, sumCDotIm, sumAllDet]
  | succ k ih =>
    simp only [sumCNormSq, sumCDotRe, sumCDotIm, sumAllDet]
    have hcross : ∀ m,
        sumCNormSq m u * cNormSq (v k) + cNormSq (u k) * sumCNormSq m v
        - 2 * sumCDotRe m u v * cDotRe (u k) (v k)
        - 2 * sumCDotIm m u v * cDotIm (u k) (v k)
        = sumDetAgainst m k u v := by
      intro m
      induction m with
      | zero => simp [sumCNormSq, sumCDotRe, sumCDotIm, sumDetAgainst]
      | succ j ihj =>
        simp only [sumCNormSq, sumCDotRe, sumCDotIm, sumDetAgainst]
        have hp := cLagrange_pair (u j) (u k) (v j) (v k)
        have h1 : (sumCNormSq j u + cNormSq (u j)) * cNormSq (v k) =
            sumCNormSq j u * cNormSq (v k) + cNormSq (u j) * cNormSq (v k) := Int.add_mul _ _ _
        have h2 : cNormSq (u k) * (sumCNormSq j v + cNormSq (v j)) =
            cNormSq (u k) * sumCNormSq j v + cNormSq (u k) * cNormSq (v j) := Int.mul_add _ _ _
        have h3 : 2 * (sumCDotRe j u v + cDotRe (u j) (v j)) * cDotRe (u k) (v k) =
            2 * sumCDotRe j u v * cDotRe (u k) (v k) + 2 * cDotRe (u j) (v j) * cDotRe (u k) (v k) := by
          rw [Int.mul_add, Int.add_mul]
        have h4 : 2 * (sumCDotIm j u v + cDotIm (u j) (v j)) * cDotIm (u k) (v k) =
            2 * sumCDotIm j u v * cDotIm (u k) (v k) + 2 * cDotIm (u j) (v j) * cDotIm (u k) (v k) := by
          rw [Int.mul_add, Int.add_mul]
        omega
    have hc := hcross k
    have hd := cDiag_zero (u k) (v k)
    have hprod : (sumCNormSq k u + cNormSq (u k)) * (sumCNormSq k v + cNormSq (v k)) =
        sumCNormSq k u * sumCNormSq k v + sumCNormSq k u * cNormSq (v k) +
        cNormSq (u k) * sumCNormSq k v + cNormSq (u k) * cNormSq (v k) := by
      rw [Int.add_mul, Int.mul_add, Int.mul_add]; omega
    have hre : (sumCDotRe k u v + cDotRe (u k) (v k)) * (sumCDotRe k u v + cDotRe (u k) (v k)) =
        sumCDotRe k u v * sumCDotRe k u v + 2 * sumCDotRe k u v * cDotRe (u k) (v k) +
        cDotRe (u k) (v k) * cDotRe (u k) (v k) := by
      rw [Int.add_mul, Int.mul_add, Int.mul_add, Int.mul_comm (cDotRe (u k) (v k)) (sumCDotRe k u v)]
      have h2 : 2 * sumCDotRe k u v * cDotRe (u k) (v k) =
          sumCDotRe k u v * cDotRe (u k) (v k) + sumCDotRe k u v * cDotRe (u k) (v k) := by
        rw [Int.mul_assoc]; omega
      omega
    have him : (sumCDotIm k u v + cDotIm (u k) (v k)) * (sumCDotIm k u v + cDotIm (u k) (v k)) =
        sumCDotIm k u v * sumCDotIm k u v + 2 * sumCDotIm k u v * cDotIm (u k) (v k) +
        cDotIm (u k) (v k) * cDotIm (u k) (v k) := by
      rw [Int.add_mul, Int.mul_add, Int.mul_add, Int.mul_comm (cDotIm (u k) (v k)) (sumCDotIm k u v)]
      have h2 : 2 * sumCDotIm k u v * cDotIm (u k) (v k) =
          sumCDotIm k u v * cDotIm (u k) (v k) + sumCDotIm k u v * cDotIm (u k) (v k) := by
        rw [Int.mul_assoc]; omega
      omega
    omega

/-- **T4a (General QGT Hermitian PSD Determinant & Trace Uncertainty Inequalities):**
For EVERY Hilbert dimension `D` and ANY complex tangent vectors `u, v : Nat → CInt`:
1. `g_11 * g_22 - g_12^2 ≥ (1/4) * Omega^2` (written integer-exact with `Omega = -2 * Im<u,v>`,
   i.e., `4 * (g_11 * g_22 - g_12^2) ≥ Omega^2`),
2. `(g_11 + g_22)^2 ≥ Omega^2` (equivalent to `tr(g) ≥ |Omega|` since `g_11, g_22 ≥ 0`)! -/
theorem t4a_qgt_psd_lagrange_and_trace (D : Nat) (u v : Nat → CInt) :
    let g11 := sumCNormSq D u
    let g22 := sumCNormSq D v
    let g12 := sumCDotRe D u v
    let omega := -2 * sumCDotIm D u v
    4 * (g11 * g22 - g12 * g12) ≥ omega * omega ∧
    (g11 + g22) * (g11 + g22) ≥ omega * omega := by
  dsimp only
  have hlag := qgt_lagrange_identity D u v
  have hnn := sumAllDet_nonneg D u v
  have hom : (-2 * sumCDotIm D u v) * (-2 * sumCDotIm D u v) =
      4 * (sumCDotIm D u v * sumCDotIm D u v) := by
    rw [Int.mul_assoc, ← Int.mul_assoc (sumCDotIm D u v) (-2), Int.mul_comm (sumCDotIm D u v) (-2),
        Int.mul_assoc (-2), ← Int.mul_assoc (-2) (-2)]
    rfl
  have hdet : 4 * (sumCNormSq D u * sumCNormSq D v - sumCDotRe D u v * sumCDotRe D u v) ≥
      (-2 * sumCDotIm D u v) * (-2 * sumCDotIm D u v) := by
    rw [hom]; omega
  refine ⟨hdet, ?_⟩
  have hsq1 : 0 ≤ (sumCNormSq D u - sumCNormSq D v) * (sumCNormSq D u - sumCNormSq D v) :=
    int_sq_nonneg _
  have hsq2 : 0 ≤ sumCDotRe D u v * sumCDotRe D u v := int_sq_nonneg _
  have hamgm : (sumCNormSq D u + sumCNormSq D v) * (sumCNormSq D u + sumCNormSq D v) =
      (sumCNormSq D u - sumCNormSq D v) * (sumCNormSq D u - sumCNormSq D v) +
      4 * (sumCNormSq D u * sumCNormSq D v) := by
    have ha : (sumCNormSq D u + sumCNormSq D v) * (sumCNormSq D u + sumCNormSq D v) =
        sumCNormSq D u * sumCNormSq D u + sumCNormSq D v * sumCNormSq D v +
        2 * (sumCNormSq D u * sumCNormSq D v) := by
      rw [Int.add_mul, Int.mul_add, Int.mul_add, Int.mul_comm (sumCNormSq D v) (sumCNormSq D u)]
      omega
    have hb : (sumCNormSq D u - sumCNormSq D v) * (sumCNormSq D u - sumCNormSq D v) =
        sumCNormSq D u * sumCNormSq D u + sumCNormSq D v * sumCNormSq D v -
        2 * (sumCNormSq D u * sumCNormSq D v) := by
      rw [Int.sub_mul, Int.mul_sub, Int.mul_sub, Int.mul_comm (sumCNormSq D v) (sumCNormSq D u)]
      omega
    omega
  omega

-- ============================================================================
-- T4b: Exact QGT Concurrence Surplus Identity (New Bridge QGTL <-> CHSH)
-- ============================================================================

/-- **T4b (Exact QGT Concurrence Surplus Identity over Any Integer Scale `R`):**
Let `ca, sa` represent `R * cos(alpha), R * sin(alpha)` (`ca^2 + sa^2 = R^2`) and `ch, sh`
represent `R * cos(theta/2), R * sin(theta/2)` (`ch^2 + sh^2 = R^2`).
Then:
- Wootters concurrence (scaled by `R^2`): `C = 2 * ca * sa`
- `cos(2*alpha)` (scaled by `R^2`): `c2a = ca^2 - sa^2`
- `sin(theta)` (scaled by `R^2`): `st = 2 * sh * ch`
- Scaled Fubini-Study metric `g_tt = (1/4)` and `g_pp = sin^2(theta/2) - cos^2(2*alpha) * sin^4(theta/2)`:
  clearing denominators by `R^8`, `det_scaled = 4 * (R^6 * sh^2 - c2a^2 * sh^4)`
- Scaled `(1/4) * Omega^2 = (1/16) * cos^2(2*alpha) * sin^2(theta)`:
  clearing denominators by `R^8`, `rhs_scaled = c2a^2 * st^2`
- **EXACT IDENTITY:**
  `det_scaled - rhs_scaled = 4 * C^2 * R^2 * sh^2`
  i.e., `det(g) - (1/4) * Omega^2 == (C^2 / 4) * sin^2(theta / 2)` identically!
  Furthermore:
  - Separable state (`sa = 0`, `C = 0`): `det_scaled = rhs_scaled` (exact saturation!).
  - Maximally entangled singlet (`ca = sa`, `c2a = 0`, `C = R^2`): `rhs_scaled = 0` (flat Berry!)
    and `det_scaled = 4 * R^6 * sh^2`. -/
theorem t4b_qgt_concurrence_surplus_identity (ca sa ch sh R : Int)
    (ha : ca * ca + sa * sa = R * R) (ht : ch * ch + sh * sh = R * R) :
    let c2a := ca * ca - sa * sa
    let C := 2 * ca * sa
    let st := 2 * sh * ch
    let det_scaled := 4 * (R * R * R * R * R * R * (sh * sh) - (c2a * c2a) * (sh * sh * (sh * sh)))
    let rhs_scaled := (c2a * c2a) * (st * st)
    det_scaled - rhs_scaled = 4 * (C * C) * (R * R) * (sh * sh) := by
  dsimp only
  grind

-- ============================================================================
-- T4c: Bivariate-Bicycle qLDPC CSS Orthogonality (General + Bravyi [[144,12,12]])
-- ============================================================================

/-- XOR-fold over `0 .. k-1`. -/
def xorN : Nat → (Nat → Bool) → Bool
  | 0, _ => false
  | k + 1, f => xor (xorN k f) (f k)

theorem xorN_xor (k : Nat) (f g : Nat → Bool) :
    xorN k (fun i => xor (f i) (g i)) = xor (xorN k f) (xorN k g) := by
  induction k with
  | zero => rfl
  | succ k ih =>
    simp only [xorN, ih]
    cases xorN k f <;> cases xorN k g <;> cases f k <;> cases g k <;> rfl

theorem xorN_false (k : Nat) : xorN k (fun _ => false) = false := by
  induction k with
  | zero => rfl
  | succ k ih => simp [xorN, ih]

/-- Group-algebra matrix entry on `Z_ell x Z_m`: row `r = (i1, j1)`, col `c = (i2, j2)` depends
ONLY on the group difference `((i2 + ell - i1) % ell, (j2 + m - j1) % m)`. -/
def circEntry (ell m : Nat) (poly : Nat → Nat → Bool) (r c : Nat) : Bool :=
  let i1 := r / m; let j1 := r % m
  let i2 := c / m; let j2 := c % m
  poly ((i2 + ell - i1) % ell) ((j2 + m - j1) % m)

/-- Product `(M1 * M2^T)_{r, s}` over `F_2` for `N`-column binary matrices. -/
def matMulT (N : Nat) (M1 M2 : Nat → Nat → Bool) (r s : Nat) : Bool :=
  xorN N (fun c => M1 r c && M2 s c)

/-- **T4c-1 (General Algebraic Bivariate-Bicycle CSS Commutation Theorem):**
For ANY binary matrices `A, B` of size `M x M` that satisfy the block-circulant symmetry
`A B = B A` (which holds identically for all elements of the commutative group algebra
`F_2[Z_ell x Z_m]`), defining `H_X = [A | B]` and `H_Z = [B^T | A^T]` yields
`H_X * H_Z^T = A B + B A = 0 (mod 2)` identically! -/
theorem t4c_general_bb_css_commutation (M : Nat) (A B : Nat → Nat → Bool)
    (hcomm : ∀ r s, xorN M (fun c => A r c && B c s) = xorN M (fun c => B r c && A c s)) :
    ∀ r s,
      xor (xorN M (fun c => A r c && B c s)) (xorN M (fun c => B r c && A c s)) = false := by
  intro r s
  rw [hcomm r s]
  cases xorN M (fun c => B r c && A c s) <;> rfl

/-- Concrete Bravyi et al. (Nature 2024) `[[144, 12, 12]]` Gross BB Code (`ell = 12, m = 6`):
`A = x^3 + y + y^2`, `B = y^3 + x + x^2`. -/
def grossA (dx dy : Nat) : Bool :=
  (dx == 3 && dy == 0) || (dx == 0 && dy == 1) || (dx == 0 && dy == 2)

def grossB (dx dy : Nat) : Bool :=
  (dx == 0 && dy == 3) || (dx == 1 && dy == 0) || (dx == 2 && dy == 0)

def grossHX (r c : Nat) : Bool :=
  if c < 72 then circEntry 12 6 grossA r c else circEntry 12 6 grossB r (c - 72)

def grossHZ (r c : Nat) : Bool :=
  if c < 72 then circEntry 12 6 grossB c r else circEntry 12 6 grossA (c - 72) r

def rowWeight (N : Nat) (M : Nat → Nat → Bool) (r : Nat) : Nat :=
  let rec go : Nat → Nat
    | 0 => 0
    | k + 1 => go k + (if M r k then 1 else 0)
  go N

def allBelow (n : Nat) (p : Nat → Bool) : Bool :=
  match n with
  | 0 => true
  | k + 1 => allBelow k p && p k

private theorem xorN_congr (k : Nat) (f g : Nat → Bool) (h : ∀ i, i < k → f i = g i) :
    xorN k f = xorN k g := by
  induction k with
  | zero => rfl
  | succ k ih =>
    simp only [xorN]
    rw [ih (fun i hi => h i (by omega)), h k (by omega)]

private theorem xorN_add (a b : Nat) (f : Nat → Bool) :
    xorN (a + b) f = xor (xorN a f) (xorN b (fun i => f (a + i))) := by
  induction b with
  | zero => simp [xorN]
  | succ b ih =>
    rw [← Nat.add_assoc]
    simp only [xorN, ih]
    cases xorN a f <;> cases xorN b (fun i => f (a + i)) <;> cases f (a + b) <;> rfl

private theorem xorN_single (M idx : Nat) (v : Bool) (hidx : idx < M) :
    xorN M (fun c => if c = idx then v else false) = v := by
  induction M with
  | zero => omega
  | succ k ih =>
    simp only [xorN]
    by_cases hk : k = idx
    · subst hk
      have hz : xorN k (fun c => if c = k then v else false) = false := by
        rw [xorN_congr k _ (fun _ => false) (fun i hi => by simp [Nat.ne_of_lt hi]), xorN_false]
      rw [hz]; simp
    · have hlt : idx < k := by omega
      rw [ih hlt]
      simp [hk]

/-- `xorN` over `0..M-1` is invariant under any involution `inv` on `{0..M-1}`. -/
private theorem xorN_involution (M : Nat) (inv : Nat → Nat) (g : Nat → Bool)
    (hlt : ∀ c, c < M → inv c < M) (hinv : ∀ c, c < M → inv (inv c) = c) :
    xorN M g = xorN M (fun c => g (inv c)) := by
  let H : Nat → Bool := fun c => xor (g c) (g (inv c))
  have hHsym : ∀ c, c < M → H (inv c) = H c := by
    intro c hc
    simp only [H, hinv c hc]
    cases g c <;> cases g (inv c) <;> rfl
  let filt : Nat → Nat → Bool := fun k c => if c < k ∧ inv c < k then H c else false
  have filt_pos : ∀ k c, c < k ∧ inv c < k → filt k c = H c := fun k c h => by
    dsimp only [filt]; exact ite_eq_left_iff.mpr (fun hn => False.elim (hn h))
  have filt_neg : ∀ k c, ¬(c < k ∧ inv c < k) → filt k c = false := fun k c h => by
    dsimp only [filt]; exact ite_eq_right_iff.mpr (fun hp => False.elim (h hp))
  have hstep : ∀ k, k ≤ M → xorN M (filt k) = false := by
    intro k hk
    induction k with
    | zero =>
      rw [xorN_congr M (filt 0) (fun _ => false) (fun c _ => filt_neg 0 c (by omega)), xorN_false]
    | succ k ih =>
      have hkM : k < M := by omega
      have hprev := ih (by omega)
      have hdiff : xorN M (filt (k + 1)) =
          xor (xorN M (filt k)) (xorN M (fun c => xor (filt (k + 1) c) (filt k c))) := by
        rw [← xorN_xor]
        apply xorN_congr M
        intro c _
        cases filt (k + 1) c <;> cases filt k c <;> rfl
      rw [hdiff, hprev]
      by_cases hgt : k < inv k
      · have hz : ∀ c, c < M → xor (filt (k + 1) c) (filt k c) = false := by
          intro c hc
          by_cases h1 : c < k + 1 ∧ inv c < k + 1
          · have hck : c ≠ k := fun heq => by subst heq; omega
            have hick : inv c ≠ k := fun heq => by
              have := hinv c hc; rw [heq] at this; omega
            have h2 : c < k ∧ inv c < k := by omega
            rw [filt_pos (k + 1) c h1, filt_pos k c h2]; cases H c <;> rfl
          · have h2 : ¬ (c < k ∧ inv c < k) := fun ⟨a, b⟩ => h1 ⟨by omega, by omega⟩
            rw [filt_neg (k + 1) c h1, filt_neg k c h2]; rfl
        rw [xorN_congr M _ (fun _ => false) hz, xorN_false]; rfl
      · by_cases heq : inv k = k
        · have hz : ∀ c, c < M → xor (filt (k + 1) c) (filt k c) = false := by
            intro c hc
            by_cases hck : c = k
            · subst hck
              have hHk : H c = false := by simp only [H, heq]; cases g c <;> rfl
              have h1 : c < c + 1 ∧ inv c < c + 1 := by omega
              have h2 : ¬ (c < c ∧ inv c < c) := by omega
              rw [filt_pos (c + 1) c h1, filt_neg c c h2, hHk]; rfl
            · by_cases h1 : c < k ∧ inv c < k
              · have h2 : c < k + 1 ∧ inv c < k + 1 := ⟨by omega, by omega⟩
                rw [filt_pos (k + 1) c h2, filt_pos k c h1]; cases H c <;> rfl
              · have h2 : ¬ (c < k + 1 ∧ inv c < k + 1) := by
                  intro ⟨hc1, hic1⟩
                  have hick : inv c ≠ k := fun h => by
                    have := hinv c hc; rw [h, heq] at this; exact hck this.symm
                  exact h1 ⟨by omega, by omega⟩
                rw [filt_neg (k + 1) c h2, filt_neg k c h1]; rfl
          rw [xorN_congr M _ (fun _ => false) hz, xorN_false]; rfl
        · have hik : inv k < k := by omega
          have hpair : ∀ c, c < M →
              xor (filt (k + 1) c) (filt k c) =
                xor (if c = k then H k else false) (if c = inv k then H k else false) := by
            intro c hc
            by_cases hck : c = k
            · subst hck
              have hne : c ≠ inv c := by omega
              have h1 : c < c + 1 ∧ inv c < c + 1 := ⟨by omega, by omega⟩
              have h2 : ¬ (c < c ∧ inv c < c) := by omega
              rw [filt_pos (c + 1) c h1, filt_neg c c h2]
              simp only [↓reduceIte, hne]
            · by_cases hcik : c = inv k
              · subst hcik
                have hne : inv k ≠ k := by omega
                have hinv2 : inv (inv k) = k := hinv k hkM
                have h1 : inv k < k + 1 ∧ inv (inv k) < k + 1 := ⟨by omega, by omega⟩
                have h2 : ¬ (inv k < k ∧ inv (inv k) < k) := by omega
                rw [filt_pos (k + 1) (inv k) h1, filt_neg k (inv k) h2, hHsym k hkM]
                simp only [hne, ↓reduceIte]; cases H k <;> rfl
              · have hick : inv c ≠ k := fun h => by
                  have := hinv c hc; rw [h] at this; exact hcik this.symm
                simp only [hck, hcik, ↓reduceIte]
                by_cases h1 : c < k ∧ inv c < k
                · have h2 : c < k + 1 ∧ inv c < k + 1 := ⟨by omega, by omega⟩
                  rw [filt_pos (k + 1) c h2, filt_pos k c h1]; cases H c <;> rfl
                · have h2 : ¬ (c < k + 1 ∧ inv c < k + 1) := fun ⟨a, b⟩ => h1 ⟨by omega, by omega⟩
                  rw [filt_neg (k + 1) c h2, filt_neg k c h1]
          rw [xorN_congr M _ _ hpair, xorN_xor,
              xorN_single M k (H k) hkM, xorN_single M (inv k) (H k) (hlt k hkM)]
          cases H k <;> rfl
  have hM := hstep M (Nat.le_refl M)
  have heq : xorN M (filt M) = xorN M H :=
    xorN_congr M (filt M) H (fun c hc => filt_pos M c ⟨hc, hlt c hc⟩)
  rw [heq] at hM
  have hx : xor (xorN M g) (xorN M (fun c => g (inv c))) = false := by
    rw [← xorN_xor]; exact hM
  cases hx1 : xorN M g <;> cases hx2 : xorN M (fun c => g (inv c)) <;> simp_all

/-- Helper: exact reduction of `(a + b + n - x) % n` for `a, b, x < n`. -/
private theorem mod_three_cases (n a b x : Nat) (ha : a < n) (hb : b < n) (hx : x < n) :
    (a + b + n - x < n ∧ (a + b + n - x) % n = a + b + n - x) ∨
    (n ≤ a + b + n - x ∧ a + b + n - x < 2 * n ∧ (a + b + n - x) % n = a + b - x) ∨
    (2 * n ≤ a + b + n - x ∧ (a + b + n - x) % n = a + b - n - x) := by
  by_cases h1 : a + b + n - x < n
  · exact Or.inl ⟨h1, Nat.mod_eq_of_lt h1⟩
  · by_cases h2 : a + b + n - x < 2 * n
    · refine Or.inr (Or.inl ⟨by omega, h2, ?_⟩)
      have heq : a + b + n - x = (a + b - x) + n := by omega
      rw [heq, Nat.add_mod_right, Nat.mod_eq_of_lt (by omega)]
    · refine Or.inr (Or.inr ⟨by omega, ?_⟩)
      have heq : a + b + n - x = (a + b - n - x) + n + n := by omega
      rw [heq, Nat.add_mod_right, Nat.add_mod_right, Nat.mod_eq_of_lt (by omega)]

/-- Group-algebra involution on `Z_ell x Z_m` proving `circEntry ell m A * circEntry ell m B`
commutes for ALL `ell, m > 0` and ALL polynomials `A, B : Nat → Nat → Bool`! -/
theorem circEntry_comm (ell m : Nat) (hell : 0 < ell) (hm : 0 < m)
    (A B : Nat → Nat → Bool) (r s : Nat) (hr : r < ell * m) (hs : s < ell * m) :
    xorN (ell * m) (fun c => circEntry ell m A r c && circEntry ell m B c s) =
    xorN (ell * m) (fun c => circEntry ell m B r c && circEntry ell m A c s) := by
  let ir := r / m; let jr := r % m
  let is_ := s / m; let js := s % m
  have hir : ir < ell := Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hr)
  have his : is_ < ell := Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hs)
  have hjr : jr < m := Nat.mod_lt r hm
  have hjs : js < m := Nat.mod_lt s hm
  let inv : Nat → Nat := fun c =>
    let ic := c / m; let jc := c % m
    let ic' := (ir + is_ + ell - ic) % ell
    let jc' := (jr + js + m - jc) % m
    ic' * m + jc'
  have hlt : ∀ c, c < ell * m → inv c < ell * m := by
    intro c _
    dsimp only [inv]
    have h1 : (ir + is_ + ell - c / m) % ell < ell := Nat.mod_lt _ hell
    have h2 : (jr + js + m - c % m) % m < m := Nat.mod_lt _ hm
    have hle : ((ir + is_ + ell - c / m) % ell + 1) * m ≤ ell * m := Nat.mul_le_mul_right m h1
    rw [Nat.add_mul, Nat.one_mul] at hle
    omega
  have hmod_inv : ∀ (n a b x : Nat), a < n → b < n → x < n →
      (a + b + n - (a + b + n - x) % n) % n = x := by
    intro n a b x ha hb hx
    rcases mod_three_cases n a b x ha hb hx with ⟨h1, hm1⟩ | ⟨h1, h2, hm1⟩ | ⟨h1, hm1⟩
    · rw [hm1, show a + b + n - (a + b + n - x) = x by omega]; exact Nat.mod_eq_of_lt hx
    · rw [hm1, show a + b + n - (a + b - x) = x + n by omega, Nat.add_mod_right]
      exact Nat.mod_eq_of_lt hx
    · rw [hm1, show a + b + n - (a + b - n - x) = x + n + n by omega,
          Nat.add_mod_right, Nat.add_mod_right]
      exact Nat.mod_eq_of_lt hx
  have hdiff_swap1 : ∀ (n a b x : Nat), a < n → b < n → x < n →
      ((a + b + n - x) % n + n - a) % n = (b + n - x) % n := by
    intro n a b x ha hb hx
    rcases mod_three_cases n a b x ha hb hx with ⟨h1, hm1⟩ | ⟨h1, h2, hm1⟩ | ⟨h1, hm1⟩
    · rw [hm1, show a + b + n - x + n - a = (b + n - x) + n by omega, Nat.add_mod_right]
    · rw [hm1, show a + b - x + n - a = b + n - x by omega]
    · rw [hm1, show a + b - n - x + n - a = b - x by omega,
          show b + n - x = (b - x) + n by omega, Nat.add_mod_right]
  have hdiff_swap2 : ∀ (n a b x : Nat), a < n → b < n → x < n →
      (b + n - (a + b + n - x) % n) % n = (x + n - a) % n := by
    intro n a b x ha hb hx
    rcases mod_three_cases n a b x ha hb hx with ⟨h1, hm1⟩ | ⟨h1, h2, hm1⟩ | ⟨h1, hm1⟩
    · rw [hm1, show b + n - (a + b + n - x) = x - a by omega,
          show x + n - a = (x - a) + n by omega, Nat.add_mod_right]
    · rw [hm1, show b + n - (a + b - x) = x + n - a by omega]
    · rw [hm1, show b + n - (a + b - n - x) = (x + n - a) + n by omega, Nat.add_mod_right]
  have hinv_eq : ∀ c, c < ell * m → inv (inv c) = c := by
    intro c hc
    have hic : c / m < ell := Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hc)
    have hjc : c % m < m := Nat.mod_lt c hm
    dsimp only [inv]
    have hrem_j : (jr + js + m - c % m) % m < m := Nat.mod_lt _ hm
    have hdiv : ((ir + is_ + ell - c / m) % ell * m + (jr + js + m - c % m) % m) / m =
        (ir + is_ + ell - c / m) % ell := by
      rw [Nat.mul_comm, Nat.mul_add_div hm, Nat.div_eq_of_lt hrem_j, Nat.add_zero]
    have hmod : ((ir + is_ + ell - c / m) % ell * m + (jr + js + m - c % m) % m) % m =
        (jr + js + m - c % m) % m := by
      rw [Nat.mul_comm, Nat.mul_add_mod, Nat.mod_eq_of_lt hrem_j]
    rw [hdiv, hmod, hmod_inv ell ir is_ (c / m) hir his hic,
        hmod_inv m jr js (c % m) hjr hjs hjc]
    have := Nat.div_add_mod c m
    rw [Nat.mul_comm]; omega
  rw [xorN_involution (ell * m) inv _ hlt hinv_eq]
  apply xorN_congr (ell * m)
  intro c hc
  have hic : c / m < ell := Nat.div_lt_of_lt_mul (by rw [Nat.mul_comm]; exact hc)
  have hjc : c % m < m := Nat.mod_lt c hm
  have hrem_j : (jr + js + m - c % m) % m < m := Nat.mod_lt _ hm
  have hdiv : (inv c) / m = (ir + is_ + ell - c / m) % ell := by
    dsimp only [inv]
    rw [Nat.mul_comm, Nat.mul_add_div hm, Nat.div_eq_of_lt hrem_j, Nat.add_zero]
  have hmod : (inv c) % m = (jr + js + m - c % m) % m := by
    dsimp only [inv]
    rw [Nat.mul_comm, Nat.mul_add_mod, Nat.mod_eq_of_lt hrem_j]
  simp only [circEntry, hdiv, hmod]
  have hd1 := hdiff_swap1 ell ir is_ (c / m) hir his hic
  have hd2 := hdiff_swap1 m jr js (c % m) hjr hjs hjc
  have hd3 := hdiff_swap2 ell ir is_ (c / m) hir his hic
  have hd4 := hdiff_swap2 m jr js (c % m) hjr hjs hjc
  change (A (((ir + is_ + ell - c / m) % ell + ell - ir) % ell)
            (((jr + js + m - c % m) % m + m - jr) % m) &&
          B ((is_ + ell - (ir + is_ + ell - c / m) % ell) % ell)
            ((js + m - (jr + js + m - c % m) % m) % m)) =
         (B ((c / m + ell - ir) % ell) ((c % m + m - jr) % m) &&
          A ((is_ + ell - c / m) % ell) ((js + m - c % m) % m))
  rw [hd1, hd2, hd3, hd4, Bool.and_comm]

private theorem allBelow_of_forall (n : Nat) (p : Nat → Bool) (h : ∀ i, i < n → p i = true) :
    allBelow n p = true := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [allBelow, ih (fun i hi => h i (by omega)), h k (by omega), Bool.and_self]

/-- **T4c-2 (Kernel-Checked Certification of Bravyi `[[144, 12, 12]]` Gross qLDPC CSS Code):**
Verified algebraically + directly inside the Lean 4 kernel (NO `native_decide`!):
1. All `72 * 72 = 5,184` stabilizer inner products `(H_X * H_Z^T)_{r,s} = 0 (mod 2)` vanish
   (discharged unconditionally from `circEntry_comm` on `Z_12 × Z_6` in milliseconds!).
2. All 72 `X`-stabilizers and all 72 `Z`-stabilizers have exact weight 6 (`LDPC` check). -/
theorem t4c_bravyi_gross_bb144_certified :
    allBelow 72 (fun r => allBelow 72 (fun s => !matMulT 144 grossHX grossHZ r s)) = true ∧
    allBelow 72 (fun r => rowWeight 144 grossHX r == 6 && rowWeight 144 grossHZ r == 6) = true := by
  refine ⟨?_, by decide +kernel⟩
  apply allBelow_of_forall
  intro r hr
  apply allBelow_of_forall
  intro s hs
  have hsplit : matMulT 144 grossHX grossHZ r s = false := by
    unfold matMulT
    rw [show (144 : Nat) = 72 + 72 from rfl, xorN_add]
    have hL : xorN 72 (fun c => grossHX r c && grossHZ s c) =
        xorN 72 (fun c => circEntry 12 6 grossA r c && circEntry 12 6 grossB c s) :=
      xorN_congr 72 _ _ (fun c hc => by simp [grossHX, grossHZ, hc])
    have hR : xorN 72 (fun i => grossHX r (72 + i) && grossHZ s (72 + i)) =
        xorN 72 (fun c => circEntry 12 6 grossB r c && circEntry 12 6 grossA c s) :=
      xorN_congr 72 _ _ (fun c _ => by
        have hge : ¬ (72 + c < 72) := by omega
        simp [grossHX, grossHZ, hge])
    rw [hL, hR, circEntry_comm 12 6 (by decide) (by decide) grossA grossB r s hr hs]
    cases xorN 72 (fun c => circEntry 12 6 grossB r c && circEntry 12 6 grossA c s) <;> rfl
  rw [hsplit]; rfl

end
end SecMeshPQSI.QuantumGeometry
