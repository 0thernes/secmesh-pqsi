<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Errata (`ERRATA.md`)

All post-release findings discovered between `v1.0.0` / `v1.0.1` and `v2.0.0` (2026-11-25) are transparently logged below and resolved in `v2.0.0`:

1. **`v1.0.0` → `v1.0.1` (Ubuntu CI Portability):** Added `-D_DEFAULT_SOURCE` in `native/Makefile` and `.github/workflows/ci.yml` so `explicit_bzero` compiles cleanly under strict `-std=c11` on Ubuntu glibc, and created `paper/build` prior to Tectonic compilation.
2. **`v1.0.1` → `v2.0.0` (White Paper I Table 2 Mega Atlas ID Audit — `error`):** Direct verification against `MegaAtlas_Unsolved_Problems_V2.json` uncovered 6 mismatched problem descriptions (`CS-028`, `CS-031`, `CS-050`, `CS-054`, `CS-061`, `QC-034`, `QC-042`). All Mega Atlas citations in White Paper I Table 2 and `CLAIMS.md` are now 100% verbatim-verified against `MegaAtlas_Unsolved_Problems_V2.json`.
3. **`v1.0.1` → `v2.0.0` (Tsotchke Public Repository Count — `error`):** Corrected `30 (20 + 10)` to the live GitHub API count of **27 public repositories** (`17` under `tsotchke`, `10` under `Tsotchke-Corporation`) and enumerated all 27 with pinned SHAs in `docs/tsotchke-stack-map.md`.
4. **`v1.0.1` → `v2.0.0` (C11 & Guardian v2 Security Hardening — `bug`/`hole`):** Fixed NULL-pointer dereference before NULL check (`memset` before `if (!out)`) in `secmesh_quantum_geo.c`, stack-allocated BB144 arrays for thread safety, guarded `secmesh_shamir_reconstruct_byzantine` against `uint32_t` wrap-around, and upgraded Guardian v2 TCP framing from static CW-128 pad reuse to sequence-bound anti-replay per-frame pads (`verifyCwFrame`).
5. **`v1.0.1` → `v2.0.0` (Test Assertion & Theorem Label Fixes — `bug`/`error`):** Fixed `abs(X) - 1.0 < 1e-15` precedence bug in `python/tests/test_all.py:67`, updated `exact_audit.py` `Compress_1` tightness check to `e=+832`, and corrected `T4a`→`T4b` labels in `secmesh_pqsi.h`, `test_native_core.c`, `qgt_geodesic.esk`, and `app/index.html`.

If you discover any mathematical, formalization, or security error in `v2.0.0`, please open a GitHub issue with the `bug` or `error` label or email `0_0@0thernes.art`.
