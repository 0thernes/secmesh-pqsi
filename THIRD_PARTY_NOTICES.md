# Third-Party Notices & Upstream Commit Attributions

This repository (`secmesh-pqsi`, Copyright 2026 Alexander S. Donahue) is dual-licensed under **Apache-2.0** (code) and **CC-BY-4.0** (manuscripts and documentation). All upstream third-party code, specifications, and reference prototypes used or audited are attributed below with pinned commit SHAs and preserved licenses.

## 1. Vendored Third-Party Source Code (`native/third_party/moonlab/`)

- **Upstream Repository:** `https://github.com/tsotchke/moonlab`
- **Pinned Commit SHA:** `cd3b2347e3739327548708073d7e4ac710cc6a6c`
- **License:** MIT License (full upstream license preserved verbatim at `native/third_party/moonlab/LICENSE-MOONLAB`)
- **Vendored Files (18 files):**
  - `crypto/sha3/{sha3.h, sha3.c}` (FIPS 202 SHA3-256/512, SHAKE128/256)
  - `crypto/aes/{aes.h, aes.c}` (FIPS 197 AES-256)
  - `crypto/drbg/{ctr_drbg.h, ctr_drbg.c}` (NIST SP 800-90A CTR_DRBG)
  - `crypto/mlkem/{mlkem.h, mlkem.c, poly.h, poly.c}` (FIPS 203 ML-KEM-512/768/1024 + NTT)
  - `applications/{qrng_di.h, qrng_di.c, health_tests.h, health_tests.c, moonlab_api.h}` (SP 800-90B RCT/APT + Toeplitz DI-QRNG)
  - `utils/secure_memory.h` (secure zeroization helpers)
- **Local Modifications:** Added `native/third_party/moonlab/applications/moonlab_export.h` (Apache-2.0 wrapper header exposing clean symbol bindings for `secmesh_core`). No upstream MIT license headers were removed or altered.

## 2. Audited & Refactored Prototype Attribution

- **Upstream Repository:** `https://github.com/BoogerCheeseOnRye/SecMesh`
- **Pinned Commit SHA:** `aff7dc6eea1f6ad93bda2e1de31c96f662408d04`
- **Role:** Original conceptual prototype audited forensically (10 mathematical and network defects documented in White Papers I & II and `CLAIMS.md`); `secmesh-pqsi` is a clean-room architectural rebuild.

## 3. Referenced & Adapted Open-Source Ecosystem (`tsotchke` & `Tsotchke-Corporation`)

All upstream commits inspected and pinned (detailed 30-repository audit in `docs/tsotchke-stack-map.md`):

| Repository | Pinned Commit SHA | Upstream License | Usage Mode |
| --- | --- | --- | --- |
| `tsotchke/quantum_geometric_tensor` | `770994aa8ddd858e6bb16eebb25250a7b9f67c96` | MIT | Mathematical reference for QGT metric/Berry curvature & T4a–T4b proofs |
| `tsotchke/eshkol` | `eb224260b4814baf3ad260744c8dcdd05fb84898` | MIT | Target language for `eshkol/*.esk` AD optimization modules |
| `tsotchke/rosette-wire` | `bb34bbe7536f2ea9829dc302c6a578e9fdd877a0` | Apache-2.0 | Verifiable receipt bundle architecture (`node/src/rosette-receipt.mjs`) |
| `Tsotchke-Corporation/pq-consensus-bandwidth` | `245c3be58edfe600ccfe799619a7939039039617` | Apache-2.0 | Extended to complete-graph $K_N$ ceilings & IT-MAC hedge law (T5d) |
| `tsotchke/libirrep` | `6c6acab7960bd747d32bc841c9d1f61a0051f1b7` | MIT | Group-algebra representation context for Bravyi `[[144,12,12]]` BB code |
| `tsotchke/quantum_rng` | `1a77e77f803c63883349b658361c06401cd8ceb7` | MIT | DI-QRNG entropy pipeline reference |
| `tsotchke/classical_rng` | `b9c2a109401bb58b1658035e51475062c65ecc1e` | MIT | Classical entropy health-test cross-reference |
| `tsotchke/spin_based_neural_network` | `9e8f2d0cd5ee6eab5e297ad626e1f60aed6b0fef` | MIT | Audited; classified out-of-scope for cryptographic TCB |
| `Tsotchke-Corporation/Quantum-RNG-API` | `b02c7039ca40f5975cafb0c147beb4bdbc9202bc` | MIT | Optional external QRNG provider interface reference |
| `Tsotchke-Corporation/GeoRefine` | `a7f1f701e4a24916aa5e15e21739562ed0835b0d` | Apache-2.0 | Audited; classified out-of-scope for cryptographic TCB |

## 4. Build Standard & Tooling Attribution

- Repository audit checklists (`scripts/Audit-Repo.ps1`, `scripts/audit-repo.sh`, `scripts/audit-checks.tsv`, `scripts/repo-standard.schema.json`, `docs/build-standard.md`) follow the Build Standard for LLMs v1.2.0.
- Cryptographic primitives in Node.js 25 execute through Node's bundled OpenSSL 3.5.5 library (Apache-2.0).
