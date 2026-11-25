module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

public import Challenge
public import SecMeshPQSI

/-!
# Verified Solutions to All 25 Formalized Theorems (`T1`–`T6`)

Zero-Mathlib Lean 4.35.0 proofs depending strictly on a subset of
`[propext, Classical.choice, Quot.sound]`, zero `sorry`, zero `native_decide`, zero custom axioms.
-/

namespace SecMeshPQSI.Solution

open SecMeshPQSI.Challenge
open SecMeshPQSI.FiniteKey
open SecMeshPQSI.InfoTheoretic
open SecMeshPQSI.ThresholdPIR
open SecMeshPQSI.QuantumGeometry
open SecMeshPQSI.LatticeBandwidth
open SecMeshPQSI.SpinDefenseCryptosymbology

public theorem t1a_v1_tsirelson_violation : T1a_V1TsirelsonViolation :=
  FiniteKey.t1a_v1_tsirelson_violation

public theorem t1b_hoeffding_range2_factor4 : T1b_HoeffdingRange2Factor4 :=
  FiniteKey.t1b_hoeffding_range2_factor4

public theorem t1c_di_quarter_circle_duality : T1c_DIQuarterCircleDuality :=
  FiniteKey.t1c_di_quarter_circle_duality

public theorem t1d_denoise_majority_bias_and_fragility : T1d_DenoiseMajorityBiasAndFragility :=
  FiniteKey.t1d_denoise_majority_bias_and_fragility

public theorem t1e_composable_epsilon_conservation : T1e_ComposableEpsilonConservation :=
  FiniteKey.t1e_composable_epsilon_conservation

public theorem t2a_shannon_otp_perfect_secrecy : T2a_ShannonOTPPerfectSecrecy :=
  fun n => InfoTheoretic.t2a_shannon_otp_perfect_secrecy n

public theorem t2b_hybrid_dual_survivability : T2b_HybridDualSurvivability :=
  fun n => InfoTheoretic.t2b_hybrid_dual_survivability n

public theorem t2c1_toeplitz_exact_2_universal : T2c1_ToeplitzExact2Universal :=
  fun m n x y z sFree h => InfoTheoretic.t2c_toeplitz_exact_2_universal m n x y z sFree h

public theorem t2c2_cauchy_schwarz_lhl : T2c2_CauchySchwarzLHL :=
  fun N a => InfoTheoretic.t2c_cauchy_schwarz_lhl N a

public theorem t2d_carter_wegman_poly_bound : T2d_CarterWegmanPolyBound :=
  fun _ _ d p roots h1 h2 h3 h4 => InfoTheoretic.t2d_carter_wegman_poly_bound d p roots h1 h2 h3 h4

public theorem t3a_shamir_threshold_and_secrecy : T3a_ShamirThresholdAndSecrecy :=
  fun _ _ t => ThresholdPIR.t3a_shamir_exact_threshold_and_secrecy t

public theorem t3b_byzantine_singleton_tightness : T3b_ByzantineSingletonTightness :=
  fun _ _ dec => ThresholdPIR.t3b_byzantine_singleton_tightness dec

public theorem t3c_pir_byzantine_capacity_gap : T3c_PIRByzantineCapacityGap :=
  ThresholdPIR.t3c_pir_byzantine_capacity_gap

public theorem t4a_qgt_psd_lagrange_and_trace : T4a_QGTPSDLagrangeAndTrace :=
  fun D u v => QuantumGeometry.t4a_qgt_psd_lagrange_and_trace D u v

public theorem t4b_qgt_concurrence_surplus_identity : T4b_QGTConcurrenceSurplusIdentity :=
  fun ca sa ch sh R ha ht => QuantumGeometry.t4b_qgt_concurrence_surplus_identity ca sa ch sh R ha ht

public theorem t4c1_general_bb_commutation : T4c1_GeneralBBCommutation :=
  fun M A B h => QuantumGeometry.t4c_general_bb_css_commutation M A B h

public theorem t4c2_bravyi_gross_bb144_certified : T4c2_BravyiGrossBB144Certified :=
  QuantumGeometry.t4c_bravyi_gross_bb144_certified

public theorem t4d_chern_concurrence_entropy_conservation : T4d_ChernConcurrenceEntropyConservation :=
  fun ca sa R ha => QuantumGeometry.t4d_chern_concurrence_entropy_conservation ca sa R ha

public theorem t4e_libirrep_ghz_heisenberg_qfi_scaling : T4e_LibirrepGHZHeisenbergQFIScaling :=
  fun N hN ca sa R ha => QuantumGeometry.t4e_libirrep_ghz_heisenberg_qfi_scaling N hN ca sa R ha

public theorem t5a_fips203_ntt_prime_and_root : T5a_FIPS203NTTPrimeAndRoot :=
  LatticeBandwidth.t5a_fips203_ntt_prime_and_root

public theorem t5b_montgomery_reduction_exact : T5b_MontgomeryReductionExact :=
  fun a hlo hhi => LatticeBandwidth.t5b_montgomery_reduction_exact a hlo hhi

public theorem t5c_mlkem_compress1_margin : T5c_MLKEMCompress1Margin :=
  fun b e hb hlo hhi => LatticeBandwidth.t5c_mlkem_compress1_margin b e hb hlo hhi

public theorem t5d_kn_mesh_bandwidth_and_hedge_overhead : T5d_KNMeshBandwidthAndHedgeOverhead :=
  LatticeBandwidth.t5d_kn_mesh_bandwidth_and_hedge_overhead

public theorem t6a_ising_laplacian_psd_and_cheeger_barrier : T6a_IsingLaplacianPSDAndCheegerBarrier :=
  SpinDefenseCryptosymbology.t6a_ising_laplacian_psd_and_cheeger_barrier

public theorem t6b_cryptosymbology_subliminal_and_threshold_closure : T6b_CryptosymbologySubliminalAndThresholdClosure :=
  SpinDefenseCryptosymbology.t6b_cryptosymbology_subliminal_and_threshold_closure

public theorem prove_all_secmesh_theorems : AllSecMeshTheorems :=
  ⟨t1a_v1_tsirelson_violation,
   t1b_hoeffding_range2_factor4,
   t1c_di_quarter_circle_duality,
   t1d_denoise_majority_bias_and_fragility,
   t1e_composable_epsilon_conservation,
   t2a_shannon_otp_perfect_secrecy,
   t2b_hybrid_dual_survivability,
   t2c1_toeplitz_exact_2_universal,
   t2c2_cauchy_schwarz_lhl,
   t2d_carter_wegman_poly_bound,
   t3a_shamir_threshold_and_secrecy,
   t3b_byzantine_singleton_tightness,
   t3c_pir_byzantine_capacity_gap,
   t4a_qgt_psd_lagrange_and_trace,
   t4b_qgt_concurrence_surplus_identity,
   t4c1_general_bb_commutation,
   t4c2_bravyi_gross_bb144_certified,
   t4d_chern_concurrence_entropy_conservation,
   t4e_libirrep_ghz_heisenberg_qfi_scaling,
   t5a_fips203_ntt_prime_and_root,
   t5b_montgomery_reduction_exact,
   t5c_mlkem_compress1_margin,
   t5d_kn_mesh_bandwidth_and_hedge_overhead,
   t6a_ising_laplacian_psd_and_cheeger_barrier,
   t6b_cryptosymbology_subliminal_and_threshold_closure⟩

end SecMeshPQSI.Solution
