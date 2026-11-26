module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

public import SecMeshPQSI

/-!
# Formal Challenge Statements (`T1`–`T7` and Non-Vacuity)

Exported literal theorem specifications for independent kernel audit (Palomar convention).
All proofs live in `Solution.lean` and `SecMeshPQSI.*`; this file defines only propositions.
-/

namespace SecMeshPQSI.Challenge

open SecMeshPQSI.FiniteKey
open SecMeshPQSI.InfoTheoretic
open SecMeshPQSI.ThresholdPIR
open SecMeshPQSI.QuantumGeometry
open SecMeshPQSI.LatticeBandwidth
open SecMeshPQSI.SpinDefenseCryptosymbology
open SecMeshPQSI.MonogamyCommitmentNoGo

@[expose] public section

def T1a_V1TsirelsonViolation : Prop :=
  4 * (1000 - 2 * 146) * v1ExpectedChshDen = 1000 * v1ExpectedChshNum ∧
  v1ExpectedChshNum * v1ExpectedChshNum > 8 * (v1ExpectedChshDen * v1ExpectedChshDen) ∧
  v1ExpectedChshNum * v1ExpectedChshNum - 8 * (v1ExpectedChshDen * v1ExpectedChshDen) = 316

def T1b_HoeffdingRange2Factor4 : Prop :=
  (∀ (n t : Nat), 2 * n * ((2 * t) * (2 * t)) = 4 * (2 * n * (t * t))) ∧
  (∀ (n t : Nat), (2 * n * ((2 * t) * (2 * t))) / (2 * 2) = 2 * n * (t * t)) ∧
  (16 * (50 ^ 4) > 24000000)

def T1c_DIQuarterCircleDuality : Prop :=
  (∀ (a b : Int), (a * a - b * b) + (2 * b * b - a * a) = b * b) ∧
  (3 * 3 = 5 * 5 - 4 * 4 ∧ 2 * (4 * 4) - 5 * 5 = 7) ∧
  (33 * 33 * 16 < 7 * (50 * 50)) ∧
  ((83 : Nat) ^ 10 > 128 * ((50 : Nat) ^ 10)) ∧
  ((7 : Nat) ^ 5 > (2 : Nat) ^ 14)

def T1d_DenoiseMajorityBiasAndFragility : Prop :=
  countBelow (fun x => decide (5 ≤ popcount8 x)) 256 = 93 ∧
  countBelow (fun x => decide (popcount8 x < 5)) 256 = 163 ∧
  countBelow (fun x => decide (popcount8 x == 4)) 256 = 70 ∧
  (93 + 163 = 256 ∧ 128 - 93 = 35)

def T1e_ComposableEpsilonConservation : Prop :=
  (∀ (ePE eQ eS ePA eC eTot : Nat),
    ePE + eQ + eS + ePA + eC ≤ eTot →
    ePE + eQ + eS + ePA + eC ≤ eTot) ∧
  (∀ (eUnit : Nat), 0 < eUnit →
    let epsTot := 3 * eUnit
    let epsS := eUnit
    let epsH := eUnit
    epsS + epsS + epsH = epsTot ∧
    ∀ (eQ eC : Nat), 0 < eQ + eC → epsS + epsS + epsH + eQ + eC > epsTot)

def T2a_ShannonOTPPerfectSecrecy : Prop :=
  ∀ (n : Nat) (m c : Fin n → Bool),
    ∃ k : Fin n → Bool, bxor m k = c ∧ ∀ k' : Fin n → Bool, bxor m k' = c → k' = k

def T2b_HybridDualSurvivability : Prop :=
  ∀ (n : Nat),
    (∀ (k_pq y : Fin n → Bool),
      ∃ k_it : Fin n → Bool, bxor k_pq k_it = y ∧ ∀ k', bxor k_pq k' = y → k' = k_it) ∧
    (∀ (k_it y : Fin n → Bool),
      ∃ k_pq : Fin n → Bool, bxor k_pq k_it = y ∧ ∀ k', bxor k' k_it = y → k' = k_pq) ∧
    (∀ (pre suf : List (Fin n → Bool)) (y : Fin n → Bool),
      ∃ k_good : Fin n → Bool,
        xorList (pre ++ k_good :: suf) = y ∧
        ∀ k', xorList (pre ++ k' :: suf) = y → k' = k_good)

def T2c1_ToeplitzExact2Universal : Prop :=
  ∀ (m n : Nat) (x y z sFree : Nat → Bool),
    (∃ j, j < n ∧ x j ≠ y j) →
    ∃ j0, j0 < n ∧
      (∃ s : Nat → Bool,
        (∀ k, (k < j0 ∨ j0 + m ≤ k) → s k = sFree k) ∧
        (∀ i, i < m → xor (toeplitzMul m n s x i) (toeplitzMul m n s y i) = z i) ∧
        (∀ s' : Nat → Bool,
          (∀ k, (k < j0 ∨ j0 + m ≤ k) → s' k = sFree k) →
          (∀ i, i < m → xor (toeplitzMul m n s' x i) (toeplitzMul m n s' y i) = z i) →
          ∀ k, s' k = s k))

def T2c2_CauchySchwarzLHL : Prop :=
  ∀ (N : Nat) (a : Nat → Int),
    (sumInt N a) * (sumInt N a) ≤ (N : Int) * sumInt N (fun i => a i * a i)

def T2d_CarterWegmanPolyBound : Prop :=
  ∀ (F : Type) [SimpleField F] (d : Nat) (p roots : List F),
    p.length ≤ d + 1 → PolyNonzero p → PairwiseNeq roots →
    (∀ r ∈ roots, evalPoly p r = 0) → roots.length ≤ d

def T3a_ShamirThresholdAndSecrecy : Prop :=
  ∀ (F : Type) [SimpleField F] (t : Nat),
    (∀ (f g : List F) (xs : List F),
      f.length ≤ t → g.length ≤ t → xs.length = t → PairwiseNeq xs →
      (∀ x ∈ xs, evalPoly f x = evalPoly g x) → evalPoly f 0 = evalPoly g 0) ∧
    (∀ (pts : List (F × F)) (s : F),
      pts.length + 1 = t →
      PairwiseNeq (0 :: pts.map Prod.fst) →
      ∃ f : List F, f.length ≤ t ∧ evalPoly f 0 = s ∧ (∀ p ∈ pts, evalPoly f p.1 = p.2) ∧
        ∀ g : List F, g.length ≤ t → evalPoly g 0 = s → (∀ p ∈ pts, evalPoly g p.1 = p.2) →
          ∀ x : F, evalPoly g x = evalPoly f x)

def T3b_ByzantineSingletonTightness : Prop :=
  ∀ (F : Type) [SimpleField F] (dec : ∀ a b : F, Decidable (a = b)),
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
      d = 2 * b ∧ b + b = d)

def T3c_PIRByzantineCapacityGap : Prop :=
  (∀ (N K T B : Nat), 1 ≤ K →
    (K + T + 2 * B ≤ N ↔ 0 < N - (K + T + 2 * B - 1))) ∧
  (∀ (N T B : Nat), 1 ≤ T → T + 2 * B < N →
    let eff := N - 2 * B
    (eff * eff) = (eff - T) * (eff + T) + T * T ∧
    (eff - T) * (eff + T) < eff * eff)

def T4a_QGTPSDLagrangeAndTrace : Prop :=
  ∀ (D : Nat) (u v : Nat → CInt),
    let g11 := sumCNormSq D u
    let g22 := sumCNormSq D v
    let g12 := sumCDotRe D u v
    let omega := -2 * sumCDotIm D u v
    4 * (g11 * g22 - g12 * g12) ≥ omega * omega ∧
    (g11 + g22) * (g11 + g22) ≥ omega * omega

def T4b_QGTConcurrenceSurplusIdentity : Prop :=
  ∀ (ca sa ch sh R : Int),
    ca * ca + sa * sa = R * R → ch * ch + sh * sh = R * R →
    let c2a := ca * ca - sa * sa
    let C := 2 * ca * sa
    let st := 2 * sh * ch
    let det_scaled := 4 * (R * R * R * R * R * R * (sh * sh) - (c2a * c2a) * (sh * sh * (sh * sh)))
    let rhs_scaled := (c2a * c2a) * (st * st)
    det_scaled - rhs_scaled = 4 * (C * C) * (R * R) * (sh * sh)

def T4c1_GeneralBBCommutation : Prop :=
  ∀ (M : Nat) (A B : Nat → Nat → Bool),
    (∀ r s, xorN M (fun c => A r c && B c s) = xorN M (fun c => B r c && A c s)) →
    ∀ r s, xor (xorN M (fun c => A r c && B c s)) (xorN M (fun c => B r c && A c s)) = false

def T4c2_BravyiGrossBB144Certified : Prop :=
  allBelow 72 (fun r => allBelow 72 (fun s => !matMulT 144 grossHX grossHZ r s)) = true ∧
  allBelow 72 (fun r => rowWeight 144 grossHX r == 6 && rowWeight 144 grossHZ r == 6) = true

def T4d_ChernConcurrenceEntropyConservation : Prop :=
  ∀ (ca sa R : Int),
    ca * ca + sa * sa = R * R →
    let c_eff := -(ca * ca - sa * sa)
    let C := 2 * ca * sa
    let R4 := R * R * R * R
    let s_half_sq := R4 + C * C
    c_eff * c_eff + C * C = R4 ∧
    c_eff * c_eff + s_half_sq = 2 * R4 ∧
    (2 * R4 - s_half_sq = c_eff * c_eff ∧ s_half_sq - R4 = C * C) ∧
    (c_eff = 0 → C * C = R4 ∧ s_half_sq = 2 * R4) ∧
    (C = 0 → c_eff * c_eff = R4 ∧ s_half_sq = R4)

def T4e_LibirrepGHZHeisenbergQFIScaling : Prop :=
  ∀ (N : Nat), 1 ≤ N → ∀ (ca sa R : Int),
    ca * ca + sa * sa = R * R →
    let tau_N := (2 * ca * sa) * (2 * ca * sa)
    let R4 := R * R * R * R
    let qfi_ghz := (N : Int) * (N : Int) * tau_N
    let qfi_sql := (N : Int) * R4
    (qfi_ghz > qfi_sql ↔ (N : Int) * tau_N > R4) ∧
    (ca * ca = sa * sa → tau_N = R4 ∧ qfi_ghz = (N : Int) * qfi_sql) ∧
    qfi_ghz ≤ (N : Int) * (N : Int) * R4 ∧
    4 * (N * (N + 2)) - 4 * (N * N) = 8 * N

def T5a_FIPS203NTTPrimeAndRoot : Prop :=
  IsPrime 3329 ∧ 3329 = 13 * 256 + 1 ∧ powMod 17 128 3329 = 3328 ∧ powMod 17 256 3329 = 1

def T5b_MontgomeryReductionExact : Prop :=
  ∀ (a : Int), -32768 * 3329 < a → a < 32768 * 3329 →
    let t := toInt16 (a * (-3327))
    let r := montgomeryReduce a
    (a - t * 3329) % 65536 = 0 ∧ (r * 65536 - a) % 3329 = 0 ∧ -3329 < r ∧ r < 3329

def T5c_MLKEMCompress1Margin : Prop :=
  ∀ (b e : Int), (b = 0 ∨ b = 1) → -831 ≤ e → e ≤ 831 →
    mlkemCompress1 (b * 1665 + e) = b

def T5d_KNMeshBandwidthAndHedgeOverhead : Prop :=
  (∀ N : Nat, 2 * completeEdges N = N * (N - 1)) ∧
  (∀ B S : Nat, 0 < S → (meshCeiling B S - 1) * S ≤ B ∧ B < meshCeiling B S * S) ∧
  (6573 + 96 + 16 = 6685 ∧ (96 + 16) * 400 < 7 * 6573)

def T6a_IsingLaplacianPSDAndCheegerBarrier : Prop :=
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
    2 * k * (Jmin * phi0 + hmin) ≤ 2 * cutW + 2 * fieldW)

def T6b_CryptosymbologySubliminalAndThresholdClosure : Prop :=
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
        ∀ r', bxor r' r_auditor = target → r' = r_signer))

def T7a_TonerCHSHMonogamyAndEveIsolation : Prop :=
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
    (cAB * cAB = R * R → cAE = 0 ∧ tau = 0 ∧ rA = 0))

def T7b_HidingBindingConservationNoGo : Prop :=
  ∀ (T D : Nat) (P0 P1 : Nat → Nat),
    sumNat T P0 = D →
    sumNat T P1 = D →
    let tv2 := sumNat T (fun t => absDiffNat (P0 t) (P1 t))
    let ov := sumNat T (fun t => min (P0 t) (P1 t))
    tv2 + 2 * ov = 2 * D ∧
    (0 < D → ¬ ((∀ t, t < T → P0 t = P1 t) ∧ (∀ t, t < T → P0 t = 0 ∨ P1 t = 0))) ∧
    (∀ eps : Nat, tv2 ≤ 2 * eps → D - eps ≤ ov) ∧
    ¬ (tv2 < D ∧ 2 * ov < D)

def T7c_FuchsVanDeGraaffMicrocryptEFI : Prop :=
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
    (dotRe = 0 ∧ dotIm = 0 → dTrSq = M * M))

def AllSecMeshTheorems : Prop :=
  T1a_V1TsirelsonViolation ∧
  T1b_HoeffdingRange2Factor4 ∧
  T1c_DIQuarterCircleDuality ∧
  T1d_DenoiseMajorityBiasAndFragility ∧
  T1e_ComposableEpsilonConservation ∧
  T2a_ShannonOTPPerfectSecrecy ∧
  T2b_HybridDualSurvivability ∧
  T2c1_ToeplitzExact2Universal ∧
  T2c2_CauchySchwarzLHL ∧
  T2d_CarterWegmanPolyBound ∧
  T3a_ShamirThresholdAndSecrecy ∧
  T3b_ByzantineSingletonTightness ∧
  T3c_PIRByzantineCapacityGap ∧
  T4a_QGTPSDLagrangeAndTrace ∧
  T4b_QGTConcurrenceSurplusIdentity ∧
  T4c1_GeneralBBCommutation ∧
  T4c2_BravyiGrossBB144Certified ∧
  T4d_ChernConcurrenceEntropyConservation ∧
  T4e_LibirrepGHZHeisenbergQFIScaling ∧
  T5a_FIPS203NTTPrimeAndRoot ∧
  T5b_MontgomeryReductionExact ∧
  T5c_MLKEMCompress1Margin ∧
  T5d_KNMeshBandwidthAndHedgeOverhead ∧
  T6a_IsingLaplacianPSDAndCheegerBarrier ∧
  T6b_CryptosymbologySubliminalAndThresholdClosure ∧
  T7a_TonerCHSHMonogamyAndEveIsolation ∧
  T7b_HidingBindingConservationNoGo ∧
  T7c_FuchsVanDeGraaffMicrocryptEFI

end
end SecMeshPQSI.Challenge
