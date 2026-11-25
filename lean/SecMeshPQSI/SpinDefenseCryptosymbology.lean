module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

public import SecMeshPQSI.InfoTheoretic

/-!
# Theorem Family T6: Spin-Glass / Ising Expander Cyber-Contagion Barriers & Cryptosymbology

Zero-Mathlib Lean 4.35.0 proofs uniting:
- `t6a_ising_laplacian_psd_and_cheeger_barrier`:
  Bridges Tsotchke's `spin_based_neural_network` & `PIMC` with SecMesh cyber-defense topology
  and Mega Atlas `STAT-014` / `STAT-027` / `SYS-024` / `QC-045`:
  1. Exact Discrete Laplacian Quadratic Form identity & Positive Semi-Definiteness for ANY
     symmetric nonnegative weighted graph `(V, w)`:
     `sum_{i,j} w_{ij} (x_i - x_j)^2 = 2 * sum_{i,j} w_{ij} x_i (x_i - x_j) >= 0`.
  2. Exact Ising Spin-Flip Cut-Energy Identity (`2 * ΔH(σ) = Dirichlet(J, σ) + 4 * Field(h, σ)`),
     proving all-healthy `σ ≡ +1` is the exact global ground state (`ΔH(σ) ≥ 0`).
  3. Exact Cheeger Expander Contagion Barrier: if edge expansion satisfies `cutW ≥ Jmin * (phi0 * k)`
     and firewall field satisfies `fieldW ≥ hmin * k`, compromising `k` nodes requires energy barrier
     `2 * cutW + 2 * fieldW ≥ 2 * k * (Jmin * phi0 + hmin)`.
- `t6b_cryptosymbology_subliminal_and_threshold_closure`:
  Formalizes Simmons (1983) subliminal channels & Young–Yung kleptography (Mega Atlas `CS-030`):
  1. Deterministic signature uniqueness implies STRICTLY ZERO subliminal channel capacity.
  2. Randomized `k`-bit nonce injection yields an exact `2^k`-message covert bijection channel.
  3. Split-trust threshold-hedged randomness `r_eff = r_signer XOR r_auditor` simultaneously closes
     kleptographic covert bias (when `r_auditor` is independent) and differential fault attacks
     (when `r_signer` is independent).
-/

namespace SecMeshPQSI.SpinDefenseCryptosymbology

open SecMeshPQSI.InfoTheoretic

@[expose] public section

-- ============================================================================
-- T6a: Discrete Laplacian PSD, Ising Spin-Glass Cut Energy & Cheeger Barrier
-- ============================================================================

/-- Double finite integer sum `∑_{i=0}^{n-1} ∑_{j=0}^{n-1} f i j`. -/
def sumInt2 (n : Nat) (f : Nat → Nat → Int) : Int :=
  sumInt n (fun i => sumInt n (fun j => f i j))

/-- Discrete graph Dirichlet energy `∑_{i,j} w(i,j) * (x i - x j)^2`. -/
def dirichletEnergy (n : Nat) (w : Nat → Nat → Int) (x : Nat → Int) : Int :=
  sumInt2 n (fun i j => w i j * ((x i - x j) * (x i - x j)))

/-- Discrete graph Laplacian quadratic form `∑_{i,j} w(i,j) * x i * (x i - x j)`. -/
def laplacianQuad (n : Nat) (w : Nat → Nat → Int) (x : Nat → Int) : Int :=
  sumInt2 n (fun i j => w i j * x i * (x i - x j))

/-- Scaled Ising spin-flip excitation energy `2 * (H(sig) - H(+1))` on `{0..n-1}`. -/
def isingCutEnergy (n : Nat) (J : Nat → Nat → Int) (h : Nat → Int) (sig : Nat → Int) : Int :=
  sumInt2 n (fun i j => J i j * (1 - sig i * sig j)) + 2 * sumInt n (fun i => h i * (1 - sig i))

private theorem sumInt_congr (n : Nat) (f g : Nat → Int) (h : ∀ i, i < n → f i = g i) :
    sumInt n f = sumInt n g := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [sumInt]
    rw [ih (fun i hi => h i (by omega)), h k (by omega)]

private theorem sumInt_add (n : Nat) (f g : Nat → Int) :
    sumInt n (fun i => f i + g i) = sumInt n f + sumInt n g := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [sumInt, ih]
    omega

private theorem sumInt_mul_left (n : Nat) (c : Int) (f : Nat → Int) :
    sumInt n (fun i => c * f i) = c * sumInt n f := by
  induction n with
  | zero => simp [sumInt]
  | succ k ih =>
    simp only [sumInt, ih, Int.mul_add]

private theorem sumInt_nonneg (n : Nat) (f : Nat → Int) (h : ∀ i, i < n → 0 ≤ f i) :
    0 ≤ sumInt n f := by
  induction n with
  | zero => exact Int.le_refl 0
  | succ k ih =>
    simp only [sumInt]
    have h1 := ih (fun i hi => h i (by omega))
    have h2 := h k (by omega)
    omega

private theorem sumInt_swap (m n : Nat) (f : Nat → Nat → Int) :
    sumInt m (fun i => sumInt n (fun j => f i j)) =
    sumInt n (fun j => sumInt m (fun i => f i j)) := by
  induction m with
  | zero =>
    simp only [sumInt]
    induction n with
    | zero => rfl
    | succ k ihk => simp [sumInt, ← ihk]
  | succ a iha =>
    simp only [sumInt, iha]
    rw [← sumInt_add]

private theorem int_sq_nonneg' (x : Int) : 0 ≤ x * x := by
  by_cases h : 0 ≤ x
  · exact Int.mul_nonneg h h
  · have h2 : 0 ≤ -x := by omega
    have hm := Int.mul_nonneg h2 h2
    rw [Int.neg_mul_neg] at hm
    exact hm

/-- **T6a (Discrete Laplacian PSD, Ising Ground-State Cut Bijection & Cheeger Contagion Barrier):**
For EVERY mesh size `n`, EVERY symmetric nonnegative coupling matrix `w`/`J`, EVERY firewall field `h ≥ 0`,
EVERY potential `x : Nat → Int`, and EVERY Ising spin configuration `sig` (`sig i ∈ {-1, +1}`):
1. Exact Laplacian identity & PSD: `dirichletEnergy n w x = 2 * laplacianQuad n w x ∧ 0 ≤ dirichletEnergy n w x`.
2. Exact Ising spin-flip cut identity & ground-state optimality:
   `2 * sumInt2 n (fun i j => J i j * (1 - sig i * sig j)) = dirichletEnergy n J sig`
   and `0 ≤ isingCutEnergy n J h sig`.
3. Exact Cheeger Expander Contagion Barrier:
   if `cutW ≥ Jmin * (phi0 * k)` and `fieldW ≥ hmin * k`, then
   `2 * cutW + 2 * fieldW ≥ 2 * k * (Jmin * phi0 + hmin)`. -/
theorem t6a_ising_laplacian_psd_and_cheeger_barrier :
    (∀ (n : Nat) (w : Nat → Nat → Int) (x : Nat → Int),
      (∀ i j, i < n → j < n → w i j = w j i) →
      (∀ i j, i < n → j < n → 0 ≤ w i j) →
      dirichletEnergy n w x = 2 * laplacianQuad n w x ∧ 0 ≤ dirichletEnergy n w x) ∧
    (∀ (n : Nat) (J : Nat → Nat → Int) (h sig : Nat → Int),
      (∀ i j, i < n → j < n → 0 ≤ J i j) →
      (∀ i, i < n → 0 ≤ h i) →
      (∀ i, i < n → sig i = 1 ∨ sig i = -1) →
      2 * sumInt2 n (fun i j => J i j * (1 - sig i * sig j)) = dirichletEnergy n J sig ∧
      0 ≤ isingCutEnergy n J h sig) ∧
    (∀ (k phi0 Jmin hmin cutW fieldW : Int),
      0 ≤ k → 0 ≤ phi0 → 0 ≤ Jmin → 0 ≤ hmin →
      Jmin * (phi0 * k) ≤ cutW → hmin * k ≤ fieldW →
      2 * k * (Jmin * phi0 + hmin) ≤ 2 * cutW + 2 * fieldW) := by
  refine ⟨?_, ?_, ?_⟩
  · intro n w x hsym hnn
    have hterm : ∀ i j, i < n → j < n →
        w i j * ((x i - x j) * (x i - x j)) =
          w i j * x i * (x i - x j) + w j i * x j * (x j - x i) := by
      intro i j hi hj
      rw [hsym i j hi hj]
      grind
    have hdir : dirichletEnergy n w x =
        laplacianQuad n w x + sumInt2 n (fun i j => w j i * x j * (x j - x i)) := by
      unfold dirichletEnergy laplacianQuad sumInt2
      have h1 : sumInt n (fun i => sumInt n (fun j => w i j * ((x i - x j) * (x i - x j)))) =
          sumInt n (fun i => sumInt n (fun j =>
            w i j * x i * (x i - x j) + w j i * x j * (x j - x i))) :=
        sumInt_congr n _ _ (fun i hi => sumInt_congr n _ _ (fun j hj => hterm i j hi hj))
      rw [h1]
      have h2 : sumInt n (fun i => sumInt n (fun j =>
            w i j * x i * (x i - x j) + w j i * x j * (x j - x i))) =
          sumInt n (fun i => sumInt n (fun j => w i j * x i * (x i - x j)) +
                             sumInt n (fun j => w j i * x j * (x j - x i))) :=
        sumInt_congr n _ _ (fun i _ => sumInt_add n _ _)
      rw [h2, sumInt_add]
    have hsw : sumInt2 n (fun i j => w j i * x j * (x j - x i)) = laplacianQuad n w x := by
      unfold sumInt2 laplacianQuad
      exact sumInt_swap n n (fun i j => w j i * x j * (x j - x i))
    have hge : 0 ≤ dirichletEnergy n w x := by
      unfold dirichletEnergy sumInt2
      exact sumInt_nonneg n _ (fun i hi =>
        sumInt_nonneg n _ (fun j hj =>
          Int.mul_nonneg (hnn i j hi hj) (int_sq_nonneg' (x i - x j))))
    refine ⟨?_, hge⟩
    rw [hdir, hsw]
    omega
  · intro n J h sig hJnn hhnn hsig
    have hpt : ∀ i j, i < n → j < n →
        2 * (J i j * (1 - sig i * sig j)) = J i j * ((sig i - sig j) * (sig i - sig j)) := by
      intro i j hi hj
      rcases hsig i hi with h1 | h1 <;> rcases hsig j hj with h2 | h2 <;> simp [h1, h2] <;> grind
    have hid : 2 * sumInt2 n (fun i j => J i j * (1 - sig i * sig j)) = dirichletEnergy n J sig := by
      unfold dirichletEnergy sumInt2
      rw [← sumInt_mul_left]
      apply sumInt_congr n
      intro i hi
      rw [← sumInt_mul_left]
      exact sumInt_congr n _ _ (fun j hj => hpt i j hi hj)
    have hcut_nn : 0 ≤ sumInt2 n (fun i j => J i j * (1 - sig i * sig j)) := by
      unfold sumInt2
      refine sumInt_nonneg n _ (fun i hi => sumInt_nonneg n _ (fun j hj => ?_))
      have h1 : 0 ≤ 1 - sig i * sig j := by
        rcases hsig i hi with h1 | h1 <;> rcases hsig j hj with h2 | h2 <;> simp [h1, h2]
      exact Int.mul_nonneg (hJnn i j hi hj) h1
    have hfield_nn : 0 ≤ sumInt n (fun i => h i * (1 - sig i)) := by
      refine sumInt_nonneg n _ (fun i hi => ?_)
      have h1 : 0 ≤ 1 - sig i := by
        rcases hsig i hi with h1 | h1 <;> simp [h1]
      exact Int.mul_nonneg (hhnn i hi) h1
    refine ⟨hid, ?_⟩
    unfold isingCutEnergy
    omega
  · intro k phi0 Jmin hmin cutW fieldW _ _ _ _ hcut hfield
    have hlhs : 2 * k * (Jmin * phi0 + hmin) = 2 * (Jmin * (phi0 * k)) + 2 * (hmin * k) := by
      grind
    omega

-- ============================================================================
-- T6b: Cryptosymbology — Simmons Subliminal Channels & Threshold-Hedged Closure
-- ============================================================================

/-- **T6b (Cryptosymbology: Deterministic Zero-Capacity, Kleptographic Bijection, & Threshold Closure):**
1. **Deterministic zero-capacity:** If a signature verifier accepts at most one valid signature per
   `(sk, m)` (deterministic Ed25519 / FIPS 204 ML-DSA), ANY valid subliminal encoder `enc` maps all
   covert payloads `c1, c2` to the identical signature (`0` bits of subliminal capacity).
2. **Randomized kleptographic bijection:** Conversely, if `signWithNonce` is injective over `k`-bit
   nonces `{0,1}^k`, a malicious signer embeds all `k` covert bits injectively via `c ↦ signWithNonce (r0 ⊕ c)`.
3. **Threshold-hedged dual closure:** Split-trust hedging `r_eff = r_signer ⊕ r_auditor` simultaneously
   destroys arbitrary signer subliminal bias (for uniform `r_auditor`, unique bijection onto every target)
   and preserves fault-injection resistance (for uniform `r_signer`, unique bijection onto every target). -/
theorem t6b_cryptosymbology_subliminal_and_threshold_closure :
    (∀ (SK M Sig C : Type) (Valid : SK → M → Sig → Prop) (enc : SK → M → C → Sig),
      (∀ sk m s1 s2, Valid sk m s1 → Valid sk m s2 → s1 = s2) →
      (∀ sk m c, Valid sk m (enc sk m c)) →
      ∀ sk m c1 c2, enc sk m c1 = enc sk m c2) ∧
    (∀ (k : Nat) (Sig : Type) (signWithNonce : (Fin k → Bool) → Sig) (r0 : Fin k → Bool),
      (∀ r1 r2, signWithNonce r1 = signWithNonce r2 → r1 = r2) →
      ∀ c1 c2 : Fin k → Bool,
        signWithNonce (bxor r0 c1) = signWithNonce (bxor r0 c2) → c1 = c2) ∧
    (∀ (k : Nat),
      (∀ (r_signer target : Fin k → Bool),
        ∃ r_auditor : Fin k → Bool,
          bxor r_signer r_auditor = target ∧
          ∀ r', bxor r_signer r' = target → r' = r_auditor) ∧
      (∀ (r_auditor target : Fin k → Bool),
        ∃ r_signer : Fin k → Bool,
          bxor r_signer r_auditor = target ∧
          ∀ r', bxor r' r_auditor = target → r' = r_signer)) := by
  refine ⟨?_, ?_, ?_⟩
  · intro SK M Sig C Valid enc huniq hval sk m c1 c2
    exact huniq sk m (enc sk m c1) (enc sk m c2) (hval sk m c1) (hval sk m c2)
  · intro k Sig signWithNonce r0 hinj c1 c2 heq
    have hbx : bxor r0 c1 = bxor r0 c2 := hinj _ _ heq
    have h := (t2a_shannon_otp_perfect_secrecy k r0 (bxor r0 c2))
    obtain ⟨u, _, hu⟩ := h
    have h1 : c1 = u := hu c1 hbx
    have h2 : c2 = u := hu c2 rfl
    rw [h1, h2]
  · intro k
    have h := t2b_hybrid_dual_survivability k
    exact ⟨h.1, h.2.1⟩

end
end SecMeshPQSI.SpinDefenseCryptosymbology
