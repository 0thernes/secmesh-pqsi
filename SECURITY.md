# Security Policy (`SECURITY.md`)

## Supported Versions

| Version | Status |
| --- | --- |
| `1.0.x` | Supported (active research reference release) |

## Reporting a Vulnerability

Please report security vulnerabilities, cryptographic flaws, or Lean 4 formalization soundness holes **privately first** via email to:
- **Contact:** Alexander S. Donahue (`0_0@0thernes.art`)
- **ORCID:** `0009-0006-8168-9648`

Please include:
1. Affected component (`native/`, `node/`, `lean/`, `python/`, or `app/`).
2. Minimal reproducible proof-of-concept or counterexample.
3. Suggested finding class from the 10-class taxonomy (`bug`, `error`, `hole`, `concern`, etc.).

We aim to acknowledge reports within 72 hours and publish a transparent fix plus an entry in `ERRATA.md` and `HARDENING_LOG.md` once verified.

## Scope & Operational Warnings
- `secmesh-pqsi` is a research reference engine, **not** a FIPS 140-3 certified HSM.
- Never reuse a Carter–Wegman $\mathbb{F}_{2^{128}}$ one-time pad mask across two frames.
- Never bind the control plane to `0.0.0.0` without external mutual-TLS / authenticated tunneling, and never commit pre-shared OTP pads to git.
