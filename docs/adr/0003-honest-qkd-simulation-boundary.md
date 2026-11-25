# ADR 0003: Explicit Software E91 Simulator vs. Physical Photonic QKD Boundary

- **Status:** Accepted (2026-11-25)
- **Context:** Legacy `BoogerCheeseOnRye/SecMesh@aff7dc6` simulated E91 rounds over TCP while using broken super-quantum probabilities (`S = 2.832 > 2*sqrt(2)`) and mislabeled entropy bounds, blurring the distinction between software simulation and physical Bell-test cryptography.
- **Decision:** Repair every finite-key formula (`T1a`–`T1e`) and explicitly label all software E91 execution as a *mathematical finite-key simulator* across README, white papers, CLI output, and `LIMITATIONS.md`, while providing a clean `SECMESH_IT_PAD_FILE` hook for external physical QRNG / pre-shared OTP pads.
- **Consequences:** Zero risk of misrepresenting software simulation as physical loophole-free photonic QKD.
