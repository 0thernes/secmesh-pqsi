<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Tsotchke Ecosystem 27-Repository Complete Audit & Integration Map (`docs/tsotchke-stack-map.md`)

During the clean-room rebuild of `BoogerCheeseOnRye/SecMesh@aff7dc6`, we queried the GitHub API across both public namespaces (`github.com/tsotchke`: **17 public repositories**; `github.com/Tsotchke-Corporation`: **10 public repositories**; **27 total public repositories** verified live on 2026-11-25).

> **Correction logged in `HARDENING_LOG.md` (`H4.01`):** An earlier `v1.0.0` draft stated "30 public repositories (20 + 10)" before running an exact enumerated API audit. The complete 27-repository inventory below lists every single public repository verbatim with its exact HEAD commit SHA, SPDX license, language, and integration/exclusion verdict.

---

## 1. Directly Integrated, Adapted, or Extended (10 Repositories)

| # | Repository | Pinned Commit SHA | License | Language | Mode | Exact Role in `secmesh-pqsi v2.2.0` |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `tsotchke/moonlab` | `cd3b2347e3` | MIT | C | **Vendored C11 (18 files)** | Compiled directly into `secmesh_core`: FIPS 202 SHA3/SHAKE, FIPS 197 AES-256, SP 800-90A CTR_DRBG, FIPS 203 ML-KEM-512/768/1024, SP 800-90B health tests, Toeplitz DI-QRNG |
| 2 | `tsotchke/quantum_geometric_tensor` | `770994aa8d` | MIT | C | **Adapted C11 + Lean** | Provost–Vallée QGT metric & Berry curvature (`secmesh_quantum_geo.c`), QGT Concurrence Surplus (`T4a`–`T4b`), and Topological Chern–Concurrence–Entropy Conservation Law (`T4d`) |
| 3 | `tsotchke/eshkol` | `eb224260b4` | MIT | C++ | **Executable AD Modules** | 4 Eshkol v1.3.6 S-expression AD modules (`eshkol/{finite_key_ad,qgt_geodesic,bandwidth_opt,chern_ising_ad}.esk`) executed live by our forward-mode dual-number AD evaluator (`node/src/eshkol-ad-runtime.mjs`) |
| 4 | `tsotchke/rosette-wire` | `bb34bbe753` | Apache-2.0 | Spec | **Protocol Schema** | Canonical SHA-256 verifiable execution receipt bundles (`node/src/rosette-receipt.mjs`, `rosette/latest-audit/`) |
| 5 | `Tsotchke-Corporation/pq-consensus-bandwidth` | `245c3be58e` | Apache-2.0 | Go | **Extended Law** | Generalized from CometBFT consensus to complete-graph $K_N$ ceilings + CW-128 & SLH-DSA profiles (`T5d`, `secmesh_quantum_geo.c`) |
| 6 | `tsotchke/libirrep` | `6c6acab796` | MIT | C | **Algebraic + SU(2) Core** | Group-algebra $\mathbb{F}_2[\mathbb{Z}_{12} \times \mathbb{Z}_6]$ Bravyi `[[144,12,12]]` BB qLDPC (`T4c`) + collective $\mathrm{SU}(2)$ spin-$j$ ($j=N/2$) GHZ Heisenberg QFI & Casimir scaling (`T4e`) |
| 7 | `tsotchke/spin_based_neural_network` | `9e8f2d0cd5` | MIT | C | **Hamiltonian Model** | Ising spin-glass Hamiltonian cyber-contagion barrier & discrete Laplacian PSD (`T6a`, `secmesh_ising_graph_energy`) |
| 8 | `tsotchke/PIMC` | `39222e8695` | None (cited only) | Java | **Conceptual Reference** | Path-integral / frustration energy landscape context for `T6a` ground-state optimality (zero code copied due to unspecified upstream license) |
| 9 | `tsotchke/quantum_rng` | `1a77e77f80` | MIT | C | **Entropy Spec** | DI-QRNG Toeplitz extraction & Pironio CHSH min-entropy cross-verification |
| 10 | `tsotchke/classical_rng` | `b9c2a10940` | MIT | C | **Entropy Spec** | Classical SP 800-90B RCT/APT entropy health-test cross-verification |

---

## 2. Optional Future External Connectors (1 Repository)

| # | Repository | Pinned Commit SHA | License | Language | Role / Exclusion Boundary |
| --- | --- | --- | --- | --- | --- |
| 11 | `Tsotchke-Corporation/Quantum-RNG-API` | `b02c7039ca` | MIT | JavaScript | Candidate external HTTP QRNG entropy endpoint for `SECMESH_IT_PAD_FILE`; not invoked in offline reproducible CI |

---

## 3. Audited & Explicitly Excluded from Cryptographic TCB (16 Repositories)

Every remaining public repository across `tsotchke` and `Tsotchke-Corporation` was inspected via GitHub API and deliberately excluded from the `secmesh-pqsi` cryptographic Trusted Computing Base to maintain minimal audit surface, clean license compatibility (Apache-2.0 / MIT), and zero unrelated bloat:

| # | Repository | Pinned Commit SHA | License | Language | Technical Reason for Exclusion from Cryptographic TCB |
| --- | --- | --- | --- | --- | --- |
| 12 | `tsotchke/asteroids` | `a84fa1602f` | MIT | C | Arcade game demo; non-cryptographic |
| 13 | `tsotchke/gpt2-basic` | `f1d51a48c3` | MIT | Python | DOS/486 BASIC fixed-point LLM runtime; non-cryptographic |
| 14 | `tsotchke/homebrew-eshkol` | `7cc5d130f2` | None | Ruby | macOS Homebrew packaging tap formula |
| 15 | `tsotchke/homebrew-moonlab` | `96506422cb` | None | Ruby | macOS Homebrew packaging tap formula |
| 16 | `tsotchke/llm-arbitrator` | `5672fbdae8` | MIT | TypeScript | Multi-LLM MCP orchestrator; excluded per Build Standard A40/R5 (no runtime LLM inside crypto core) |
| 17 | `tsotchke/PINN` | `8ec293633e` | None | C | Physics-informed neural PDE solver; unspecified license & outside crypto TCB |
| 18 | `tsotchke/simple_mnist` | `19824248ae` | MIT | C | Minimalist 2-layer MNIST classifier; non-cryptographic |
| 19 | `tsotchke/tensorcore` | `553823c7c5` | MIT | Python | Apple Silicon Metal GEMM/FlashAttention kernel library; macOS/ML-specific |
| 20 | `Tsotchke-Corporation/.github` | `ea3554d93f` | None | None | GitHub organization profile README |
| 21 | `Tsotchke-Corporation/SolanaQuantumFlux` | `7c951ef066` | NOASSERTION | TypeScript | Solana blockchain randomness SDK; chain-specific & non-OSI license metadata |
| 22 | `Tsotchke-Corporation/quantum-quake` | `904094a9c3` | None | C | QuakeSpasm fork for quantum visualization; game engine runtime |
| 23 | `Tsotchke-Corporation/logo-lab` | `19ff17fa68` | None | JavaScript | Browser Möbius visual identity renderer; non-cryptographic |
| 24 | `Tsotchke-Corporation/ulg` | `842d852cf2` | None | JavaScript | Browser WebGPU simulation runtime; unspecified license |
| 25 | `Tsotchke-Corporation/OBLITERATUS` | `a5a1ffa584` | AGPL-3.0 | Fork | Refusal-geometry interpretability fork; AGPL-3.0 copyleft incompatible with Apache-2.0 crypto core |
| 26 | `Tsotchke-Corporation/GeoRefine` | `a7f1f701e4` | Apache-2.0 | Python | Neural model codec & quantization loader; ML inference outside crypto TCB |
| 27 | `Tsotchke-Corporation/bonsai-fidelity-study` | `09f59af208` | Apache-2.0 | Python | Prism ML Bonsai 27B fidelity study; empirical LLM study outside crypto TCB |
