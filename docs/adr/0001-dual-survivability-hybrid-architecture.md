# ADR 0001: Dual-Survivability Hybrid PQ + PSI Cryptographic Architecture

- **Status:** Accepted (2026-11-25)
- **Context:** Single-family cryptography fails catastrophically if its underlying hardness assumption breaks (e.g., Shor's algorithm breaking X25519/Ed25519, or a future breakthrough against Module-LWE breaking ML-KEM/ML-DSA).
- **Decision:** Combine classical (`X25519`, `Ed25519`), module-lattice PQ (`ML-KEM-768`, `ML-DSA-65`), hash-based PQ (`SLH-DSA-128s`), and information-theoretic PSI primitives (XOR OTP combiner, Toeplitz extraction, $\mathbb{F}_{2^{128}}$ Carter–Wegman MAC, Byzantine Shamir sharing) so security survives collapse of any proper subset of assumptions (`T2b`, `T5d`).
- **Consequences:** One-way wire cost increases from 192 B (classical) to 6,685 B (Hybrid+CW-128, `+1.704%` over pure PQ) or 14,989 B (SLH-DSA lattice-hedged), setting exact complete-graph $K_N$ ceilings of 1,870 and 834 nodes at 100 Mbps / 1 s (`T5d`).
