# Benchmarks & Wire-Cost Measurements (`docs/benchmarks.md`)

All wire sizes, complete-graph $K_N$ ceilings, live handshake latencies, and statistical mesh-defense measurements below were directly measured on this repository's current code (`v1.0.0`, Windows 11, GCC 14.2.0, Node.js v25.8.2 / OpenSSL 3.5.5, Python 3.12.10).

## 1. Exact Handshake Wire Costs & Complete-Graph $K_N$ Ceilings (Theorem T5d)

Reproduced by `./native/build/secmesh_core bandwidth 100000000 1.0` and `node examples/quickstart_demo.mjs`:

| Profile | One-Way Size (B) | $K_N$ Ceiling (100 Mbps, 1 s) | Live Measured RTT & Latency |
| --- | ---: | ---: | --- |
| Classical `X25519 + Ed25519` | `192` | `65,105` | *(baseline; broken by Shor/SNDL)* |
| PQ-Auth Only (no PQ KEM) | `5,357` | `2,334` | *(broken by SNDL harvesting)* |
| Pure PQ (`ML-KEM-768 + ML-DSA-65`) | `6,573` | `1,902` | *(single-family lattice)* |
| Hybrid PQ (`X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65`) | `6,669` | `1,875` | *(hybrid lattice)* |
| **SecMesh-PQSI Hybrid + CW-128 IT-MAC** | **`6,685`** | **`1,870`** | `+112 B` (`+1.704% < 1.75%`) over pure PQ |
| **SecMesh-PQSI Lattice-Hedged (`+ SLH-DSA-128s`)** | **`14,989`** | **`834`** | **`25,003 B` RTT** (`12,561 B` C→S, `12,442 B` S→C) in **`391.0 ms`** |

## 2. Verification Runtime Budgets (Local Reference Host)

| Suite | Observed Wall Time | Pass Count |
| --- | ---: | --- |
| Native C11 (`make -C native test`) | `< 0.5 s` | `40/40` |
| Native C11 Fuzz Smoke (`fuzz_parsers -DFUZZ_STANDALONE`, 500 inputs) | `< 0.5 s` | `500/500` |
| Node.js 25 Differential + Interop + Security (`test_secmesh_v2.mjs`) | `~1.1 s` | `12/12` |
| Python Exact Audit + Pytest (`exact_audit.py` + `pytest`) | `~1.6 s` | `11/11` |
| Zero-Mathlib Lean 4.35.0 Clean Build (`lake build`, 15 jobs) | `~18 s` | `21/21` theorems |
| 5-Kernel External Replay (`leanchecker`, `con-leche`, `con-ron`, `nanoda_bin`) | `~45 s` | `3,505 / 3,545` decls |

## 3. Pre-Registered 30-Seed Simulated Mesh Defense Summary

See [`docs/preregistration.md`](preregistration.md) and [`results/exact_verification_report.json`](../results/exact_verification_report.json). Scope note: measures deterministic simulated health-field controller trajectories, **not** physical network penetration testing.
