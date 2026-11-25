# Tsotchke Ecosystem 30-Repository Integration & Audit Map (`docs/tsotchke-stack-map.md`)

During the clean-room rebuild of `BoogerCheeseOnRye/SecMesh@aff7dc6`, we surveyed all **30 public repositories** across `github.com/tsotchke` (20 repos) and `github.com/Tsotchke-Corporation` (10 repos). To prevent security theater or false dependency claims, every repository is honestly classified as **Vendored**, **Adapted / Extended**, **Target Language / Schema**, or **Audited & Out-of-Scope**.

## 1. Directly Integrated, Adapted, or Extended (8 Repositories)

| Repository | Pinned Commit SHA | License | Integration Mode | Exact Role in `secmesh-pqsi` |
| --- | --- | --- | --- | --- |
| `tsotchke/moonlab` | `cd3b2347e3739327548708073d7e4ac710cc6a6c` | MIT | **Vendored C11 (18 files)** | Compiled directly into `secmesh_core`: FIPS 202 SHA3/SHAKE, FIPS 197 AES-256, SP 800-90A CTR_DRBG, FIPS 203 ML-KEM-512/768/1024, SP 800-90B health tests, Toeplitz DI-QRNG |
| `tsotchke/quantum_geometric_tensor` | `770994aa8ddd858e6bb16eebb25250a7b9f67c96` | MIT | **Adapted C11 + Lean** | Provost–Vallee QGT metric & Berry curvature (`secmesh_quantum_geo.c`) + new exact QGT Concurrence Surplus Theorem (`T4a`–`T4b`) |
| `tsotchke/eshkol` | `eb224260b4814baf3ad260744c8dcdd05fb84898` | MIT | **Source AD Modules** | Three Eshkol v1.3.6 S-expression AD modules (`eshkol/finite_key_ad.esk`, `qgt_geodesic.esk`, `bandwidth_opt.esk`) |
| `tsotchke/rosette-wire` | `bb34bbe7536f2ea9829dc302c6a578e9fdd877a0` | Apache-2.0 | **Protocol Schema** | Canonical SHA-256 verifiable audit receipt bundles (`node/src/rosette-receipt.mjs`, `rosette/latest-audit/`) |
| `Tsotchke-Corporation/pq-consensus-bandwidth` | `245c3be58edfe600ccfe799619a7939039039617` | Apache-2.0 | **Extended Law** | Generalized to complete-graph $K_N$ ceilings + CW-128/SLH-DSA profiles (`T5d`, `secmesh_quantum_geo.c`) |
| `tsotchke/libirrep` | `6c6acab7960bd747d32bc841c9d1f61a0051f1b7` | MIT | **Algebraic Core** | Group-algebra representation context for $\mathbb{F}_2[\mathbb{Z}_{12} \times \mathbb{Z}_6]$ Bravyi `[[144,12,12]]` BB qLDPC (`T4c`) |
| `tsotchke/quantum_rng` | `1a77e77f803c63883349b658361c06401cd8ceb7` | MIT | **Entropy Spec** | DI-QRNG Toeplitz extraction & CHSH min-entropy reference |
| `tsotchke/classical_rng` | `b9c2a109401bb58b1658035e51475062c65ecc1e` | MIT | **Entropy Spec** | Classical SP 800-90B RCT/APT entropy testing reference |

## 2. Optional Future Connectors (1 Repository)

| Repository | Pinned Commit SHA | License | Notes |
| --- | --- | --- | --- |
| `Tsotchke-Corporation/Quantum-RNG-API` | `b02c7039ca40f5975cafb0c147beb4bdbc9202bc` | MIT | Candidate external physical QRNG HTTP provider for `SECMESH_IT_PAD_FILE` (not invoked in offline test suite) |

## 3. Audited & Explicitly Excluded from Cryptographic TCB (21 Repositories)

The remaining 21 repositories across `tsotchke` and `Tsotchke-Corporation` (including `Tsotchke-Corporation/GeoRefine@a7f1f70`, `tsotchke/spin_based_neural_network@9e8f2d0`, ML/LLM inference tools, UI/web templates, and domain utilities unrelated to post-quantum cryptography, information theory, or quantum geometry) were inspected and **deliberately excluded** from `secmesh-pqsi` to keep the cryptographic Trusted Computing Base minimal, auditable, and free of bloat.
