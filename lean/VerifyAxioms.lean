module
-- SPDX-License-Identifier: Apache-2.0
-- Copyright (c) 2026 Alexander S. Donahue

import Solution
import PalomarSolution
import SecMeshPQSI.AdversarialTests

/-!
# Strict Axiom Allowlist Audit

Every exported theorem in `SecMeshPQSI.Solution` AND `SecMeshPQSI.Palomar` (28 individual
theorems + master conjunction), the non-vacuity witness
`SecMeshPQSI.NonVacuity.nonvac_all_hypotheses`, and the 5 adversarial boundary counterexamples
in `SecMeshPQSI.AdversarialTests` (63 audited declarations total) must depend strictly on a
subset of the three standard Lean 4 axioms `[propext, Classical.choice, Quot.sound]`.
-/

#print axioms SecMeshPQSI.Solution.t1a_v1_tsirelson_violation
#print axioms SecMeshPQSI.Solution.t1b_hoeffding_range2_factor4
#print axioms SecMeshPQSI.Solution.t1c_di_quarter_circle_duality
#print axioms SecMeshPQSI.Solution.t1d_denoise_majority_bias_and_fragility
#print axioms SecMeshPQSI.Solution.t1e_composable_epsilon_conservation
#print axioms SecMeshPQSI.Solution.t2a_shannon_otp_perfect_secrecy
#print axioms SecMeshPQSI.Solution.t2b_hybrid_dual_survivability
#print axioms SecMeshPQSI.Solution.t2c1_toeplitz_exact_2_universal
#print axioms SecMeshPQSI.Solution.t2c2_cauchy_schwarz_lhl
#print axioms SecMeshPQSI.Solution.t2d_carter_wegman_poly_bound
#print axioms SecMeshPQSI.Solution.t3a_shamir_threshold_and_secrecy
#print axioms SecMeshPQSI.Solution.t3b_byzantine_singleton_tightness
#print axioms SecMeshPQSI.Solution.t3c_pir_byzantine_capacity_gap
#print axioms SecMeshPQSI.Solution.t4a_qgt_psd_lagrange_and_trace
#print axioms SecMeshPQSI.Solution.t4b_qgt_concurrence_surplus_identity
#print axioms SecMeshPQSI.Solution.t4c1_general_bb_commutation
#print axioms SecMeshPQSI.Solution.t4c2_bravyi_gross_bb144_certified
#print axioms SecMeshPQSI.Solution.t4d_chern_concurrence_entropy_conservation
#print axioms SecMeshPQSI.Solution.t4e_libirrep_ghz_heisenberg_qfi_scaling
#print axioms SecMeshPQSI.Solution.t5a_fips203_ntt_prime_and_root
#print axioms SecMeshPQSI.Solution.t5b_montgomery_reduction_exact
#print axioms SecMeshPQSI.Solution.t5c_mlkem_compress1_margin
#print axioms SecMeshPQSI.Solution.t5d_kn_mesh_bandwidth_and_hedge_overhead
#print axioms SecMeshPQSI.Solution.t6a_ising_laplacian_psd_and_cheeger_barrier
#print axioms SecMeshPQSI.Solution.t6b_cryptosymbology_subliminal_and_threshold_closure
#print axioms SecMeshPQSI.Solution.t7a_toner_chsh_monogamy_and_eve_isolation
#print axioms SecMeshPQSI.Solution.t7b_hiding_binding_conservation_nogo
#print axioms SecMeshPQSI.Solution.t7c_fuchs_vandegraaff_microcrypt_efi
#print axioms SecMeshPQSI.Solution.prove_all_secmesh_theorems
#print axioms SecMeshPQSI.NonVacuity.nonvac_all_hypotheses
#print axioms SecMeshPQSI.Palomar.t1a_v1_tsirelson_violation
#print axioms SecMeshPQSI.Palomar.t1b_hoeffding_range2_factor4
#print axioms SecMeshPQSI.Palomar.t1c_di_quarter_circle_duality
#print axioms SecMeshPQSI.Palomar.t1d_denoise_majority_bias_and_fragility
#print axioms SecMeshPQSI.Palomar.t1e_composable_epsilon_conservation
#print axioms SecMeshPQSI.Palomar.t2a_shannon_otp_perfect_secrecy
#print axioms SecMeshPQSI.Palomar.t2b_hybrid_dual_survivability
#print axioms SecMeshPQSI.Palomar.t2c1_toeplitz_exact_2_universal
#print axioms SecMeshPQSI.Palomar.t2c2_cauchy_schwarz_lhl
#print axioms SecMeshPQSI.Palomar.t2d_carter_wegman_poly_bound
#print axioms SecMeshPQSI.Palomar.t3a_shamir_threshold_and_secrecy
#print axioms SecMeshPQSI.Palomar.t3b_byzantine_singleton_tightness
#print axioms SecMeshPQSI.Palomar.t3c_pir_byzantine_capacity_gap
#print axioms SecMeshPQSI.Palomar.t4a_qgt_psd_lagrange_and_trace
#print axioms SecMeshPQSI.Palomar.t4b_qgt_concurrence_surplus_identity
#print axioms SecMeshPQSI.Palomar.t4c1_general_bb_commutation
#print axioms SecMeshPQSI.Palomar.t4c2_bravyi_gross_bb144_certified
#print axioms SecMeshPQSI.Palomar.t4d_chern_concurrence_entropy_conservation
#print axioms SecMeshPQSI.Palomar.t4e_libirrep_ghz_heisenberg_qfi_scaling
#print axioms SecMeshPQSI.Palomar.t5a_fips203_ntt_prime_and_root
#print axioms SecMeshPQSI.Palomar.t5b_montgomery_reduction_exact
#print axioms SecMeshPQSI.Palomar.t5c_mlkem_compress1_margin
#print axioms SecMeshPQSI.Palomar.t5d_kn_mesh_bandwidth_and_hedge_overhead
#print axioms SecMeshPQSI.Palomar.t6a_ising_laplacian_psd_and_cheeger_barrier
#print axioms SecMeshPQSI.Palomar.t6b_cryptosymbology_subliminal_and_threshold_closure
#print axioms SecMeshPQSI.Palomar.t7a_toner_chsh_monogamy_and_eve_isolation
#print axioms SecMeshPQSI.Palomar.t7b_hiding_binding_conservation_nogo
#print axioms SecMeshPQSI.Palomar.t7c_fuchs_vandegraaff_microcrypt_efi
#print axioms SecMeshPQSI.AdversarialTests.adv_compress1_fails_at_plus_832
#print axioms SecMeshPQSI.AdversarialTests.adv_v1_chsh_refutes_tsirelson_bound
#print axioms SecMeshPQSI.AdversarialTests.adv_commitment_disjoint_refutes_hiding
#print axioms SecMeshPQSI.AdversarialTests.adv_toner_concrete_pythagorean_witness
#print axioms SecMeshPQSI.AdversarialTests.adv_fuchs_vdg_pythagorean_tight
