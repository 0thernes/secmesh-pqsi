# Operations & Incident Playbook (`docs/operations.md`)

## Pre-Flight Health Checks
1. Run `native/build/secmesh_core entropy-status` — confirms SP 800-90B RCT/APT health tests pass. Any non-zero exit indicates an entropy source fault and MUST halt key generation (fail-closed).
2. Run `node node/src/secmesh-cli.mjs audit` — emits a signed Rosette-Wire receipt bundle under `rosette/latest-audit/` confirming C11 ↔ Node finite-key, ML-KEM, QGTL, and BB144 integrity.

## Incident Response Rules
- **SP 800-90B Health Fault:** Halt immediately, zeroize in-memory session keys, inspect OS CSPRNG / hardware QRNG driver.
- **CW-128 MAC Verification Failure:** Drop connection immediately, log peer ID and frame digest, rotate ephemeral one-time pad mask before retrying.
- **Suspected Pre-Shared Pad Compromise:** Revoke affected pad segment; dual-survivability (`T2b`) guarantees session confidentiality still holds under hybrid X25519 + ML-KEM-768 until fresh physical entropy is provisioned.
- **Suspected Lattice Break (`CS-026`):** Switch policy profile to `Lattice-Hedged (SLH-DSA)` (`14,989 B` one-way) and require physical/pre-shared OTP pad for PSI confidentiality.
