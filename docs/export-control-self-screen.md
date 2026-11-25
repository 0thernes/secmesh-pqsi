<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Export-Control Self-Screening Note (`docs/export-control-self-screen.md`)

Per **Defensible Independent AI Research Playbook v1.3 (Checklist Item 37 & Section 10)**, this document records an informal, non-legal export-control self-screen for `secmesh-pqsi` (cryptographic software and fundamental research). **This note is not legal advice; consult qualified trade-compliance counsel before commercial distribution.**

1. **Publicly Available Open-Source Cryptographic Software (EAR 15 CFR § 742.15(b) / § 734.3(b)(3)):**
   - `secmesh-pqsi` implements standard, publicly published NIST post-quantum algorithms (`FIPS 202` SHA-3/SHAKE, `FIPS 197` AES-256, `FIPS 203` ML-KEM, `FIPS 204` ML-DSA, `FIPS 205` SLH-DSA) and classical academic primitives (X25519, Ed25519, Shamir secret sharing, Carter–Wegman MAC) under OSI-approved open-source licenses (`Apache-2.0` / `MIT` for vendored `moonlab`).
   - All source code, Lean 4 formal proofs, and companion white papers are publicly available without fee or access restriction on GitHub (`https://github.com/0thernes/secmesh-pqsi`).
   - **Action item for author before distributing pre-compiled binaries commercially or outside public source repos:** Under 15 CFR § 742.15(b), publicly available encryption source code released in the U.S. generally requires a one-time public-availability email notification to BIS (`crypt@bis.doc.gov`) and the ENC Encryption Request Coordinator (`enc@nsa.gov`) providing the public repository URL so the code exits EAR jurisdiction.

2. **Fundamental Research Carve-Out (15 CFR § 734.8 & ITAR 22 CFR § 120.34):**
   - The mathematical theorems (`lean/`), white papers (`paper/`), and open educational simulations are published fundamental scientific research with no proprietary, classified, military, or offensive-cyber (exploitation/weaponization) functionality.
   - `secmesh-pqsi` contains strictly **defensive** cryptographic verification and mathematical modeling tools; it contains zero offensive exploits, zero network scanning/attack payloads, and zero physical weapon/sensor hardware designs.
