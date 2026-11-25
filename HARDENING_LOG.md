# Three-Cycle Deep-Dive Hardening Log (`HARDENING_LOG.md`)

**Repository:** `secmesh-pqsi v1.0.0`
**Methodology:** Three complete exhaustive hardening cycles across every directory, file, theorem, kernel, test harness, vector figure, LaTeX manuscript, and Build Standard v1.2.0 item, classifying every finding strictly into one of the **10 finding classes** (`bug`, `error`, `issue`, `problem`, `concern`, `dilemma`, `conflict`, `gap`, `hole`, `blindspot`).

---

## Baseline Audit — Upstream `BoogerCheeseOnRye/SecMesh@aff7dc6` (10 Findings)

| ID | Class | Location (Upstream) | Finding & Resolution in `secmesh-pqsi v1.0.0` |
| --- | --- | --- | --- |
| U01 | `bug` | `node-tests/entangle-qkd.mjs` | `CELL_P = [0.146, 0.854]` yields expected $S = 354/125 = 2.832 > 2\sqrt{2}$, violating Tsirelson's bound (`+316`). **Fixed** with exact $\sin^2(\pi/8)$ probabilities; proved in Lean `T1a`. |
| U02 | `bug` | `entangle-qkd.mjs:151`, `finite-key-e91.tex:526` | Range-1 Hoeffding formula applied to $\pm 1$ range-2 variables ($4\times$ exponent error; true per-cell tail `0.02857 > 1/50` vs. claimed `2.5e-7`). **Fixed** with $t_c = \sqrt{2\ln(8/\varepsilon_{\mathrm{PE}})/n_c}$; proved in Lean `T1b`. |
| U03 | `error` | `entangle-qkd.mjs` (`minEntropyFromChsh`) | Computes Acín–Pironio collective $\HvN(S)$ instead of Pironio strict $\Hmin(S)$, overestimating by up to `+0.235703` bits/round at $S \approx 2.6992$. **Fixed** with exact Pironio $\Hmin(S)$; quarter-circle duality proved in Lean `T1c`. |
| U04 | `bug` | `entangle-qkd.mjs` | Point $\widehat{\QBER}$ and $h(\QBER)$ without upper confidence bound or syndrome inefficiency. **Fixed** with exact Bernoulli Chernoff–KL inversion $\QBER_{\mathrm{UB}}$ and $f_{\mathrm{EC}} = 1.16$. |
| U05 | `bug` | `entangle-qkd.mjs` (`deNoise`) | 8-bit majority vote (`ones >= 5`) biases uniform bytes to `93/256` ones and fails single flips on `70/256` weight-4 blocks. **Removed**; proved in Lean `T1d`. |
| U06 | `hole` | `entangle-qkd.mjs:280` (`runLink`) | Transmitted cleartext `bitA`/`bitB` sifted key rounds over raw TCP JSON. **Eliminated**; zero secret bits ever leave key isolation. |
| U07 | `bug` | `entangle-qkd.mjs` | Double-spent $\varepsilon_s$, omitted $\varepsilon_Q$ & $\varepsilon_{\mathrm{cor}}$, dropped factor of 2 in Renner LHL, used SHA-256 instead of 2-universal hashing. **Fixed** with 5-lane composable budget + Toeplitz extraction (`T1e`, `T2c1`, `T2c2`). |
| U08 | `hole` | `entangle-peer.mjs`, `mesh-guardian.mjs` | Unauthenticated `0.0.0.0` control plane, raw key leak on `/e91` with `CORS: *`, unbounded line buffer (OOM DoS), open UDP echo amplification. **Eliminated** in Hardened Guardian v2 (CW-128 MAC, loopback CORS, 64 KiB cap, zero UDP echo, zero key leak). |
| U09 | `bug` | `entangle-qkd.mjs`, `secsim-e91.mjs` | Non-cryptographic `Math.random()` for protocol choices and stale $S > 2$ console gate. **Fixed** with OS CSPRNG (`BCryptGenRandom`/OpenSSL) + SP 800-90B health tests + composable gate. |
| U10 | `error` | `finite-key-e91.tex:402` | Parked-Eve threshold miscomputed as `0.058` instead of $(1 - 1/\sqrt{2})/2 \approx 0.146447$. **Corrected** and documented in White Paper I. |

---

## Hardening Cycle 1 — Core Math, C11, Node.js, Lean 4.35 & Adversarial Audit

| ID | Class | Location | Finding & Verified Resolution |
| --- | --- | --- | --- |
| H1.01 | `bug` | `native/tests/test_native_core.c` | Moonlab `aes256_encrypt_block` takes `(ctx, in, out)` (input before output); initial KAT reversed args. **Fixed**; 40/40 C11 tests pass under `-Wall -Wextra -Werror`. |
| H1.02 | `gap` | `native/src/secmesh_quantum_geo.c`, `node/src/finite-key-v2.mjs` | Initial Hoeffding QBER bound was overly conservative ($O(1/\sqrt{m})$); upgraded to exact 64-step Bernoulli Chernoff–KL inversion matching C11↔Node↔Python to `< 1e-11`, lifting clean $N=450\text{k}$ certified bits from `11,115` to `18,838`. |
| H1.03 | `bug` | `node/src/mesh-guardian-v2.mjs` | `HealthFieldEngine.step` only healed nodes marked `compromised == true` rather than any `health < 1.0`. **Fixed**; verified deterministic replay and 30-seed paired stats. |
| H1.04 | `error` | `app/index.html`, early draft notes | Stale lattice-hedged wire size (`14,957 B` vs. exact `14,989 B`) and rough early `0.207` entropy gap estimate (exact maximum is `+0.235703` at $S = 2.699192$). **Synced** across C11, Node, Python, HTML, figures, and both white papers. |
| H1.05 | `problem` | `lean/SecMeshPQSI/QuantumGeometry.lean` | Brute-force `decide +kernel` over $72 \times 72 \times 144 = 746{,}496$ BB144 CSS steps exceeded default heartbeats. **Upgraded** to a completely general group-algebra involution proof (`circEntry_comm` on $\mathbb{Z}_\ell \times \mathbb{Z}_m$), proving CSS orthogonality for ALL BB codes in milliseconds across all 5 kernels! |
| H1.06 | `bug` | `lean/SecMeshPQSI/LatticeBandwidth.lean` | Linear `powMod 17 256 3329` hit `maxRecDepth` under `decide`. **Fixed** via proved `powMod_add` repeated squaring (`17^16=2642, 17^32=2580, 17^64=1729, 17^128=3328, 17^256=1`), shrinking proof term and clearing all 5 kernels. |
| H1.07 | `blindspot` | `python/tests/test_all.py` | Discovered exact asymmetric boundary of FIPS 203 `Compress_1` for odd $q=3329$: symmetric radius is $|e| \le 831$, strictly tight at $e = +832$ (where **both** $b=0$ and $b=1$ fail), while negative failures occur at $-833$ ($b=0$) and $-834$ ($b=1$). **Verified** in pytest and stated explicitly in Theorem `T5c`. |
| H1.08 | `problem` | `lean/` (Windows toolchain) | Bundled Windows `lean4lean.exe` failed with `.olean` `incompatible header`, and `lake comparator` requires Linux `bwrap`. **Honest disclosure** in `LIMITATIONS.md`, `results/six_kernel_audit.txt`, and White Paper I; excluded `lean4lean` from local count (`5 distinct kernels / 6 runs`) and enabled Ubuntu `bwrap` in CI. |
| H1.09 | `bug` | `.github/workflows/ci.yml`, `justfile`, `THIRD_PARTY_NOTICES.md` | Referenced nonexistent `nist_drbg.c` and `ntt.c` (actual Moonlab filenames are `ctr_drbg.c` with NTT inside `poly.c`) — caught immediately by compiling `native/tests/fuzz_parsers.c`! **Fixed** across all 3 files + verified `500/500` standalone fuzz smoke pass. |
| H1.10 | `bug` | `examples/quickstart_demo.mjs` | Initial script used mismatched export/field names (`finiteKeyV2`, `hs.wire`). **Fixed** to exact `evaluateFiniteKeyV2`, `evaluateLegacyV1BrokenGate`, `generatePeerIdentity`, `hs.wireBytes`; verified clean execution. |
| H1.11 | `conflict` | Repository-wide attribution | Early prompt mentioned `0thernes LLC`, whereas Playbook v1.3 and actual legal status confirm no LLC entity is formed yet. **Resolved** cleanly to `Alexander S. Donahue` (`Independent Researcher, Spokane, WA, USA`, ORCID `0009-0006-8168-9648`, GitHub `0thernes`); documented in `LIMITATIONS.md` and `DEVIATIONS.md`. |
| H1.12 | `concern` | `native/include/secmesh_pqsi.h:116` | Stale inline comment still said `Hoeffding upper confidence bound on QBER` after Chernoff–KL upgrade. **Updated** to `Exact Chernoff-KL upper confidence bound on QBER`. |
| H1.13 | `dilemma` | `lean/` (zero-Mathlib vs. Mathlib) | Balancing real-analytic transcendental proofs against small multi-kernel TCB. **Resolved** (ADR 0002): cleared-denominator integer/rational algebraic theorems in zero-Mathlib Lean 4.35 + 60-digit Decimal Python differential verification (`LIMITATIONS.md`). |

---

## Hardening Cycle 2 — Visual Figures, AMS-LaTeX Manuscripts, Citations & Build Standard

| ID | Class | Location | Finding & Verified Resolution |
| --- | --- | --- | --- |
| H2.01 | `issue` | `paper/figures/fig2_di_entropy_duality.pdf`, `fig4_kn_pq_bandwidth_ceilings.pdf` | Visual PNG inspection caught double-hyphen `Acin--Pironio`, annotation-curve overlap in Fig 2, and subplot x-axis collision + bar label clipping in Fig 4. **Fixed** (`make_figures.py`), re-rendered, and visually confirmed clean! |
| H2.02 | `bug` | `paper/main.tex:358,437,508`, `paper/engineering/secmesh_architecture.tex` | Unbraced `[[144,12,12]]` inside `\begin{theorem}[...]`, two unescaped `&` in `main.tex`, missing `\Z` macro in `secmesh_architecture.tex`. **Fixed** immediately. |
| H2.03 | `issue` | `paper/engineering/secmesh_architecture.tex` (Tables 1, 2, 4), `paper/main.tex` (Tables 2, 3) | Visual PDF inspection caught column-1 text overlapping column-2 in WP2 Table 1 and skinny column-5 wrapping in WP2 Table 2. **Fixed** with `ragged2e` `Y` columns, wrapped monospace SHAs, and tuned column widths — visually confirmed museum-grade layout with **0 overfull hboxes** on WP2! |
| H2.04 | `issue` | `CODE_OF_CONDUCT.md`, `.github/ISSUE_TEMPLATE/config.yml` | Copied Build Standard templates retained `{{OWNER}}` and `{{PROJECT_NAME}}` placeholders — caught by `Audit-Repo.ps1`. **Replaced** with `0thernes` and `secmesh-pqsi` (0 remaining placeholders). |
| H2.05 | `gap` | Build Standard v1.2.0 (`A04`, `A05`, `A36`, `B01`, `B15`, `B26`, `B32`, `B37`, `B44`) | Added `Usage & Examples` + markdown image in `README.md`, `reproduce`/`rollback`/`fuzz` recipes in `justfile`, real C11 `libFuzzer` harness (`native/tests/fuzz_parsers.c`), `docs/benchmarks.md`, `docs/preregistration.md`, `SHA256SUMS` in `release.yml`, and dated replication log in `REPLICATION.md`. |
| H2.06 | `issue` | `python/` (`ruff check`) | Cleaned 18 minor `ruff` lint notices (`bit_count()`, `next(...)`, `re.MULTILINE`, import ordering, narrow exception handling). **Verified:** `ruff check` = 0 errors, `mypy` = 0 issues, `pytest` = 11/11 passed. |
| H2.07 | `concern` | `paper/refs.bib` | Verified all 32 BibTeX references via live HTTP audit (`scripts/check_citations.py --online`): **32/32 HTTP 200** (zero fabricated or dead DOIs/URLs). |

---

## Hardening Cycle 3 — Clean-Room Final Confirmation & Cryptographic Provenance

| ID | Class | Location | Finding & Verified Resolution |
| --- | --- | --- | --- |
| H3.01 | `blindspot` | `paper/engineering/secmesh_architecture.tex`, `docs/preregistration.md` | Prose described the 30-seed simulation as "24-node mesh over 120 ticks", whereas `python/secmesh_verify/exact_audit.py:356` actually ran `nodes = 60`, `steps = 400`, `threat = 0.35`, Control `(defenders=0, fw=0.0)` vs. Treatment `(defenders=6, fw=0.7)`. **Synced** verbatim to match exact code parameters and recompiled WP2 (`0` overfulls). |
| H3.02 | `issue` | `python/secmesh_verify/{exact_audit,make_figures}.py`, `python/tests/test_all.py` | Newly enabled `pyproject.toml` ruff rules (`B905` `zip(..., strict=True)`, `PLR0917`, `RUF001`) flagged 9 style notices. **Fixed** (`ruff check`: `All checks passed!`). |
| H3.03 | `issue` | `paper/main.tex:126` | Last 6.6pt overfull hbox on Theorem 2.1 title. **Shortened** title cleanly (`WP1=0, WP2=0` overfull hboxes across all 19 pages!). |

- **Clean-room Lean 4.35 rebuild:** `lake clean && lake build && lake env lean VerifyAxioms.lean` confirmed 15/15 jobs, 0 warnings, 0 forbidden tokens, 44/44 axioms strictly inside `[propext, Classical.choice, Quot.sound]`, and 5-kernel independent replay verified (`results/six_kernel_audit.txt`).
- **Adversarial Lean soundness check:** Confirmed Lean 4 rejects false mutants (`bad_tsirelson`, `bad_compress1`, `bad_denoise`, exit code 1).
- **Standalone arXiv submission check:** Extracted `dist/arxiv_submission.tar.gz` to a clean temporary directory and compiled `main.tex` cleanly via Tectonic with zero missing assets.
- **Full-repo hygiene & Build Standard v1.2.0 audit:** Verified 0 secrets, 0 banned files (R4), 0 broken relative markdown links, 0 files > 5 MiB, frozen `MANIFEST.sha256`, and **76/76 (100.0%) PASS** on `scripts/Audit-Repo.ps1` after committing to `main`.
