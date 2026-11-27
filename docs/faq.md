# Frequently Asked Questions (`docs/faq.md`)

**Q: Does `secmesh-pqsi` perform physical photonic Quantum Key Distribution over the internet?**
**No.** Software E91/CHSH rounds over TCP are a mathematical simulator for auditing finite-key bounds and protocol logic. Physical DI-QKD requires loophole-free optical/atomic Bell-test hardware (`LIMITATIONS.md`).

**Q: What does "Post-Super-Intelligence (PSI)" actually mean mathematically?**
It means **information-theoretic security** against computationally unbounded adversaries (Shannon OTP `T2a`, $2$-universal Toeplitz extraction `T2c`, Carter–Wegman $\mathbb{F}_{2^{128}}$ authentication `T2d`, and Shamir/Byzantine threshold sharing `T3a`–`T3b`), which holds unconditionally whenever an independent physical or pre-shared entropy source supplies the IT key factor.

**Q: Why zero-Mathlib Lean 4.35.0 instead of importing Mathlib?**
Eliminating Mathlib shrinks the Trusted Computing Base from millions of lines to pure Lean 4 core (15 self-contained `.lean` files), enabling fast clean-room builds (~15 s) and proof-term replay in **6 kernel runs with 5 distinct implementations** (Lean kernel in paranoid and default mode, `lean4lean`, `nanoda`, `con-leche --verified`, `con-ron --verified`) via `lake comparator --paranoid`.

**Q: Did you solve `P != NP`, LWE hardness, or general Byzantine PIR capacity?**
**No.** White Paper I Section 9 and `CLAIMS.md` explicitly distinguish our 28 kernel-checked theorem statements (`T1a`–`T7c`) from the verbatim-verified open conjectures in the *Unsolved Problems Mega Atlas*. The listed Atlas problems are topically related only; no result here is a bounded case of any of them.
