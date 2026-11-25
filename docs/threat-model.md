# STRIDE + Post-Quantum + Post-Super-Intelligence Threat Model (`docs/threat-model.md`)

## Adversary Classes
1. **Dolev–Yao Network Attacker:** Full control over TCP/UDP packets (eavesdrop, replay, drop, inject, spoof source IP).
2. **Store-Now, Decrypt-Later (SNDL) Quantum Adversary:** Records classical handshakes today and breaks X25519/Ed25519 with a future fault-tolerant quantum computer running Shor's algorithm.
3. **Lattice-Collapse Adversary:** Breaks Module-LWE/Module-SIS (ML-KEM / ML-DSA) via unforeseen algorithmic or quantum breakthroughs.
4. **Post-Super-Intelligence (PSI) Computationally Unbounded Adversary:** Unlimited classical and quantum compute; defeated strictly by information-theoretic primitives (`T2a`–`T2d`, `T3a`–`T3b`) when supplied with independent physical or pre-shared randomness.
5. **Byzantine Mesh Minority ($b$ corrupted guardians):** Up to $b$ malicious nodes returning forged Shamir shares; tolerated uniquely iff $n \ge t + 2b$ (`T3b`).

## Control Matrix

| Threat | Legacy SecMesh v1 Flaw | SecMesh-PQSI v2 Control | Residual Risk |
| --- | --- | --- | --- |
| **Spoofing** | Unauthenticated TCP/UDP | Ed25519 + ML-DSA-65 + SLH-DSA-128s + CW-128 MAC | Endpoint private-key compromise |
| **Tampering** | No per-frame MAC | Constant-time $\mathbb{F}_{2^{128}}$ Carter–Wegman MAC ($\le d/2^{128}$) | Mask reuse across frames breaks CW-128 |
| **Repudiation** | Plain console prints | Canonical Rosette-Wire SHA-256 receipt bundles | Requires external TSA / SWH anchoring |
| **Info Disclosure** | Cleartext `bitA`/`bitB` JSON, `/e91` key leak, `CORS: *` | Zero key output on `/status`, loopback CORS, X25519+ML-KEM-768 $\oplus$ OTP | PSI secrecy requires physical/pre-shared pad |
| **Denial of Service** | Unbounded line buffer, UDP amplification echo | 64 KiB hard frame cap, UDP echo removed, $K_N$ admission ceiling | Upstream volumetric L3/L4 flood |
| **Elevation / Replay** | `Math.random()`, double-spent $\varepsilon_s$ | OS CSPRNG + SP 800-90B health gate + 5-lane $\varepsilon$-conservation | Host CPU microarchitectural side-channels |
