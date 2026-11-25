# Examples (`examples/`)

Runnable end-to-end demonstrations of `secmesh-pqsi`:

- **`examples/quickstart_demo.mjs`:** Executes a live lattice-hedged PQSI handshake (`X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + SLH-DSA-128s + CW-128 IT-MAC + OTP`), runs Finite-Key v2 admission vs. Parked-Eve rejection, computes the exact QGT Concurrence Surplus witness (`T4b`), and inspects Bravyi `[[144,12,12]]` BB qLDPC orthogonality via the native C11 Moonlab binary.

```bash
node examples/quickstart_demo.mjs
```
