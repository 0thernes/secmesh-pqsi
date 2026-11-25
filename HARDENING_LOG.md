# Seven-Cycle Deep-Dive Hardening Log (`HARDENING_LOG.md`)

**Repository:** `secmesh-pqsi v2.1.0`
**Methodology:** Seven complete exhaustive hardening cycles (Cycles 1–3 for `v1.0.0`/`v1.0.1`; Cycles 4–6 for `v2.0.0`; Cycle 7 for `v2.1.0`) across every directory, file, line, theorem, kernel, test harness, vector figure, rendered PDF page, live GitHub metadata field, Playbook v1.3 item, and Build Standard v1.2.0 item, classifying every finding strictly into one of the **10 finding classes** (`bug`, `error`, `issue`, `problem`, `concern`, `dilemma`, `conflict`, `gap`, `hole`, `blindspot`).

---

## Baseline Audit — Upstream `BoogerCheeseOnRye/SecMesh@aff7dc6` (10 Findings)

| ID | Class | Location (Upstream) | Finding & Resolution in `secmesh-pqsi v1.0.0` |
| --- | --- | --- | --- |
| U01 | `bug` | `node-tests/entangle-qkd.mjs` | `CELL_P = [0.146, 0.854]` yields expected $S = 354/125 = 2.832 > 2\sqrt{2}$, violating Tsirelson's bound (`+316`). **Fixed** with exact $\sin^2(\pi/8)$ probabilities; proved in Lean `T1a`. |
| U02 | `bug` | `entangle-qkd.mjs:151`, `finite-key-e91.tex:526` | Range-1 Hoeffding formula applied to $\pm 1$ range-2 variables ($4\times$ exponent error; true per-cell tail `0.02857 > 1/50` vs. claimed `2.5e-7`). **Fixed** with $t_c = \sqrt{2\ln(8/\varepsilon_{\mathrm{PE}})/n_c}$; proved in Lean `T1b`. |
| U03 | `error` | `entangle-qkd.mjs` (`minEntropyFromChsh`) | Computes Acín–Pironio collective $H_{\mathrm{vN}}^{\mathrm{DI}}(S)$ instead of Pironio strict $H_{\min}^{\mathrm{DI}}(S)$, overestimating by up to `+0.235703` bits/round at $S \approx 2.6992$. **Fixed** with exact Pironio $H_{\min}^{\mathrm{DI}}(S)$; quarter-circle duality proved in Lean `T1c`. |
| U04 | `bug` | `entangle-qkd.mjs` | Point $\widehat{\mathrm{QBER}}$ and $h(\mathrm{QBER})$ without upper confidence bound or syndrome inefficiency. **Fixed** with exact Bernoulli Chernoff–KL inversion $\mathrm{QBER}_{\mathrm{UB}}$ and $f_{\mathrm{EC}} = 1.16$. |
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

---

## Hardening Cycle 4 (`v1.0.1` → `v2.0.0`) — Ruthless Source, Security & Citation Fidelity Audit

| ID | Class | Location | Finding & Verified Resolution |
| --- | --- | --- | --- |
| H4.01 | `error` | `docs/tsotchke-stack-map.md`, `paper/engineering/secmesh_architecture.tex`, `README.md` | Claimed 30 Tsotchke repos (`20 + 10`, remaining `22`), whereas live `gh api` query proved **27 public repositories** (`17` under `tsotchke` + `10` under `Tsotchke-Corporation`). **Fixed** with full 27-repo table pinning every commit SHA, license, language, and audit verdict. |
| H4.02 | `error` | `paper/main.tex` Table 2 (`tab:frontier`), `CLAIMS.md` | Direct audit against `MegaAtlas_Unsolved_Problems_V2.json` (1,855 entries) exposed 6 mismatched problem descriptions (`CS-028`, `CS-031`, `CS-050`, `CS-054`, `CS-061`, `QC-034`, `QC-042`). **Rebuilt Table 2 100% verbatim** from the live Atlas JSON (`QC-021`, `CS-002`, `CS-026`, `CS-028`, `CS-030`, `CS-053`, `CS-061`, `QC-004`, `QC-018`, `QC-030`, `QC-042`, `STAT-014`, `SYS-024`). |
| H4.03 | `bug` | `native/src/secmesh_quantum_geo.c:200,265` | `memset(out, 0, sizeof *out)` executed *before* `if (!out) return;` (immediate NULL dereference UB + GCC dead-code removal of NULL check), plus non-reentrant `static` BB144 arrays. **Fixed** NULL checks before `memset` (also in `secmesh_finite_key_eval`), moved BB144 matrices to stack (31 KiB), added regression NULL tests. |
| H4.04 | `hole` | `native/src/secmesh_it_crypto.c:311`, `secmesh_entropy.c:61` | Missing `num_shares <= 256` / `max_byzantine <= 128` guards allowed `uint32_t` wrap-around in `threshold + 2u * max_byzantine`; missing NULL guards in `secmesh_cw_mac_*`; Windows `BCryptGenRandom` cast `(ULONG)len` truncated >4 GiB. **Fixed** with `uint64_t` check, strict caps, NULL guards, and chunked `BCryptGenRandom` loop. |
| H4.05 | `bug` | `node/src/mesh-guardian-v2.mjs:182`, `pqsi-handshake.mjs:170` | Guardian v2 reused static Carter–Wegman pad `cwControlKey.b` across TCP frames (violating Theorem `T2d` one-time pad uniqueness!) and handshake omitted length prefix on `nodeId`. **Fixed** with sequence-bound `[u64be(seq) \|\| tag16 \|\| payload]` anti-replay framing (`sealCwFrame`/`verifyCwFrame`, rejecting duplicate `seq`) and `u16be` length-prefixed `nodeId`. |
| H4.06 | `bug` | `python/tests/test_all.py:67,218` | Precedence bug `abs(X) - 1.0 < 1e-15` (would falsely pass if `X = 0`) and `^\s*axiom\b` missed `private/protected/noncomputable axiom` and Lean 4.29+ `._native.*` axioms. **Fixed** to `abs(X - 1.0) < 1e-15`, full modifier regex, and strict allowlist parsing of all 52 `#print axioms` entries. |
| H4.07 | `error` | `native/include/secmesh_pqsi.h:152`, `test_native_core.c:229`, `eshkol/qgt_geodesic.esk:5,26`, `app/index.html:61,90,103` | Mislabelled QGT Concurrence Surplus as `Theorem T4a` (actually `T4b`), raw `$K_N$` LaTeX in HTML, `package.json` broken `status` script, `repo.yaml` nonexistent `bundle.json`, and `exact_audit.py` checked `Compress_1` failure at `833` instead of sharpest `832`. **Fixed all 7 locations.** |
| H4.08 | `problem` | `native/Makefile`, `.github/workflows/ci.yml` (`v1.0.1` CI) | Ubuntu glibc omitted `explicit_bzero` under strict `-std=c11` without `-D_DEFAULT_SOURCE`, and Tectonic needed `mkdir -p paper/build`. **Fixed** in `v1.0.1` and confirmed 6/6 CI jobs green. |

---

## Hardening Cycle 5 (`v2.0.0`) — Mathematical Frontier Expansion, Live Eshkol AD & Playbook v1.3

| ID | Class | Location | Finding & Verified Resolution |
| --- | --- | --- | --- |
| H5.01 | `gap` | `lean/SecMeshPQSI/{QuantumGeometry,SpinDefenseCryptosymbology}.lean` | Added 4 novel zero-Mathlib Lean 4.35 theorems (`T4d` Chern–Concurrence–Entropy Conservation Law, `T4e` `libirrep` spin-$j$ GHZ Heisenberg QFI scaling, `T6a` Discrete Laplacian PSD + Ising cut bijection + Cheeger contagion barrier, `T6b` Simmons subliminal zero-capacity + $2^k$ kleptography + XOR dual-closure) + concrete non-vacuity witnesses (`25/25` theorems, `52/52` audited declarations, 0 warnings, all local kernels PASS). |
| H5.02 | `gap` | `node/src/eshkol-ad-runtime.mjs`, `eshkol/chern_ising_ad.esk` | Native Windows `Z:\Tools\eshkol\current\bin\eshkol-run.exe` exited `0xC0000135` (`STATUS_DLL_NOT_FOUND`, `problem`). Built portable forward-mode dual-number AD + OALR `(with-region ...)` evaluator executing all 4 `.esk` modules live with `< 1e-12` analytical verification in `test_secmesh_v2.mjs` (`15/15` pass). |
| H5.03 | `gap` | `scripts/check_readme_axioms.py`, `app/blueprint.html`, `docs/{literature-search-log,export-control-self-screen}.md` | Closed remaining Playbook v1.3 Gold-Standard Checklist items (`#4` automated README verbatim `#print axioms` drift auditor, `#11` interactive Lean Blueprint SVG DAG on GitHub Pages, `#15` literature prior-art log, `#37` export-control self-screen). |
| H5.04 | `issue` | `paper/figures/fig5_chern_concurrence_ising_barrier.pdf` | Initial PNG visual inspection caught legend-annotation overlap in Panel (a) and `\le` mathtext parse error. **Fixed** (`\leq`, compact legend labels, `ylim=(-0.04, 1.36)`), re-rendered, and visually confirmed zero overlap! |

---

## Hardening Cycle 6 (`v2.0.0`) — Clean-Room Final Confirmation, Concurrency Catch, All-6-Kernel Sync & Provenance

| ID | Class | Location | Finding & Verified Resolution |
| --- | --- | --- | --- |
| H6.01 | `bug` | `node/src/mesh-guardian-v2.mjs:206,247,258` | Caught real concurrency/port-collision deadlock during final `v2.0.0` verification run: when `listenPort === 0`, `udpServer.bind(tcpAddr.port)` forced UDP onto the ephemeral TCP port, and `udpServer.on('error', () => {})` silently swallowed `EADDRINUSE` so `start()` hung indefinitely; additionally `stop()` lacked active TCP socket destruction and `statusServer.closeAllConnections()`. **Fixed** by binding ephemeral UDP independently (`listenPort === 0 ? 0 : tcpAddr.port`), forwarding startup errors to `reject`, returning `{ tcpPort, statusPort, udpPort }`, tracking/destroying `activeTcpSockets`, and calling `statusServer.closeAllConnections?.()` in `stop()`. |
| H6.02 | `issue` | `docs/{architecture,faq,verification}.md`, `llms-full.txt`, `REPLICATION.md`, `justfile`, `examples/quickstart_demo.mjs`, `lean/formalization.yaml` | Full-repo regex sweep caught residual `v1.0.0` / `21 theorems` / `5 distinct` count strings in secondary reference files. **Synchronized 100%** to `v2.0.0` (`25 theorems`, `6 distinct kernels`, `52` C11 tests, `15` Node tests, `12` pytest, `39` live citations). |

- **Zero-overfull AMS-LaTeX white papers:** Both White Paper I (`paper/main.tex`, 25 theorems, 5 vector figures, verbatim Mega Atlas Table 2) and White Paper II (`paper/engineering/secmesh_architecture.tex`, 27-repo audit, v2.0.0 controls) compiled with **0 overfull hboxes**, **0 undefined refs/citations**, and **39/39 live HTTP-200 bibliography citations**.
- **Full verification battery:** `52/52` C11 tests (`-Wall -Wextra -Werror`, GCC 16.1.0), `500/500` fuzz inputs, `15/15` Node 25 tests (bit-exact ML-KEM-768 interop + CW-128 anti-replay + collision-free UDP guardian + 4 live Eshkol AD modules), `12/12` pytest, `0` ruff errors, `0` mypy issues, `scripts/check_readme_axioms.py` PASS (`52` decls, `13` verbatim README lines), `lake build` + 5 local Lean kernels (`3,587` / `3,630` decls) + Ubuntu CI 6-kernel `lake comparator --paranoid`, and Build Standard v1.2.0 `scripts/Audit-Repo.ps1` **100.0% PASS**.

---

## Hardening Cycle 7 (`v2.1.0`) — Full 24-Page Visual PDF Audit, Statistics-God-Emperor CI Rigor, GitHub MathJax/Metadata Sweep & Theorem Family `T7`

| ID | Class | Location | Finding & Verified Resolution |
| --- | --- | --- | --- |
| H7.01 | `bug` | `README.md:60,63`, `CLAIMS.md:14,19`, `DEVIATIONS.md:7`, `HARDENING_LOG.md:14,15`, `docs/reviews/01-10-pass-review.md:10` | Custom LaTeX macros `\HvN`, `\Hmin`, `\QBER` are undefined in GitHub MathJax and rendered as red error text on the live repo page! **Replaced** everywhere with standard MathJax `H_{\mathrm{vN}}^{\mathrm{DI}}`, `H_{\min}^{\mathrm{DI}}`, `\mathrm{QBER}`. |
| H7.02 | `concern` | `paper/engineering/secmesh_architecture.tex` Table 4, `python/secmesh_verify/exact_audit.py` | Parametric Student-$t$ 95% CI `[59.898, 60.035]` on bounded discrete `Admitted Intrusions` ($\in [0, 60]$) overshot the 60-node domain ceiling! **Upgraded** `exact_audit.py` and WP2 Table 4 with deterministic 10,000-resample nonparametric percentile bootstrap 95% CI `[59.900, 60.000]`, exact rank-biserial $r_{\mathrm{rb}} = 1.000$, and explicit discrete boundary footnote. |
| H7.03 | `issue` | `paper/main.tex` (Page 1, Sec. 4, Tables 2–3), `paper/engineering/secmesh_architecture.tex` (Title, Page 6 stub) | Full 24-page `pypdfium2` PNG visual audit caught WP1 Page 1 blank-page abstract overflow, Table 2 `Verbatim Open Prob-lem` hyphenation, Table 3 header wrap, WP2 title orphan word, and WP2 3-reference stub Page 6. **Fixed all five** and visually re-verified every updated page (**0 overfull hboxes** on both papers; WP2 now 5 crisp pages). |
| H7.04 | `error` | Live GitHub repo About description, `docs/media/social-preview.svg`, `.cursor/rules/build-standard.mdc`, `CONTRIBUTING.md`, `docs/adr/0002`, `repo.yaml` | Secondary files and live GitHub repo metadata still displayed `21 theorems`, `40/40 C11`, `12/12 Node`, `5 kernels`, `25,003 B`. **Synced 100%** across all files and live `gh repo edit`. |
| H7.05 | `gap` | `lean/SecMeshPQSI/MonogamyCommitmentNoGo.lean`, `exact_audit.py`, `paper/main.tex` Sec. 8, `app/blueprint.html`, `paper/refs.bib` | Added Theorem Family **`T7`** (`T7a` Toner quantum CHSH monogamy $S_{AB}^2 + S_{AE}^2 \le 8$ + CKW Berry-monopole Eve isolation, zero `Classical.choice`; `T7b` exact Hiding–Binding Conservation Law $\mathrm{TV}(P_0, P_1) + \mathrm{Overlap}(P_0, P_1) = 1$ proving unconditional commitment no-go & hybrid PQ+PSI architectural necessity), bringing the formalization to **27 zero-Mathlib Lean 4.35 theorems (`56` audited declarations, `14` `.lean` files)** across all 6 independent kernels + **42/42 live HTTP-200 citations**. |

## Cycle 8 — Deep C11/Node Security, Axiom Parity, Playbook v1.3 Adversarial/Retraction Audits & WP1 Float Fix (`v2.2.0`)

| Finding ID | Class | Location | Root Cause & Verified Fix |
| --- | --- | --- | --- |
| H8.01 | `issue` | `paper/main.tex` Table 3 & Sec. 11 | Visual inspection of rendered WP1 pages 14–18 caught Table 3 floating past References and Author Affiliation onto Page 18 alone with hyphenated header `Refer-ence`. Added `\usepackage{placeins}`, `\FloatBarrier` before Sec. 11, and header `Claim & Ref.`; visually verified Table 3 now sits cleanly on Page 15 before Sec. 11 (Page 16) and References + Author Affiliation (Pages 16–18) with 0 overfull hboxes. |
| H8.02 | `bug` / `hole` | `native/src/secmesh_it_crypto.c`, `native/tests/test_native_core.c` | `secmesh_shamir_reconstruct_byzantine` did not check pairwise distinctness or $x_i \in [1, p-1]$, allowing duplicate-$x$ forged shares to double-count in `agree++` and bypass Theorem `T3b`, nor did it bound DFS step count. Added strict domain + distinctness validation (`-4`) and `max_steps = 200000` combinatorial DoS cap (`-5`) with unit tests (`58/58` C11 tests pass). |
| H8.03 | `bug` | `native/src/secmesh_it_crypto.c`, `native/src/secmesh_entropy.c` | Host-endian `(const uint8_t *)&tlen` / `&klen` / `&ctr` hashing would diverge from Node `writeBigUInt64LE` on big-endian CPUs. Replaced with explicit little-endian `store_le64`. |
| H8.04 | `bug` | `native/src/secmesh_entropy.c`, `native/src/secmesh_quantum_geo.c`, `native/tests/test_native_core.c` | Added NULL guard to `secmesh_ct_memeq`, `isfinite(...)` fail-closed guards on `secmesh_finite_key_eval`, `secmesh_qgt_entangled_manifold`, `secmesh_chern_concurrence_ghz`, and `secmesh_ising_eval_expander_barrier` (preventing IEEE-754 `NaN`/`Inf` bypass), and symmetric nonnegative check (`-4`) in `secmesh_ising_graph_energy`. |
| H8.05 | `hole` | `node/src/pqsi-handshake.mjs`, `node/src/mesh-guardian-v2.mjs`, `node/tests/test_secmesh_v2.mjs` | Unbounded `seenCwSeqs = new Set()` allowed memory-exhaustion DoS on long-lived Guardian v2 sessions. Replaced with RFC-6479-style `createReplayWindow(windowSize = 4096n)` maintaining $O(1)$ bounded memory while rejecting both in-window duplicates and stale sequences below `maxSeq - windowSize` (`16/16` Node tests pass). |
| H8.06 | `concern` | `lean/PalomarSolution.lean`, `lean/formalization.yaml` | `Palomar.t7b_hiding_binding_conservation_nogo` unnecessarily pulled `Classical.choice` via `simpa` whereas `Solution.t7b` used `[propext, Quot.sound]`. Replaced with direct `sumNat_absDiff_eq` rewrite; `Palomar.t7b` now matches `Solution.t7b` identically with zero `Classical.choice`. |
| H8.07 | `gap` | `lean/SecMeshPQSI/AdversarialTests.lean`, `lean/VerifyAxioms.lean`, `python/tests/test_all.py`, `.github/workflows/ci.yml` | Closed Playbook v1.3 Item 12 by adding 4 zero-axiom Lean 4.35 adversarial boundary counterexamples (`60/60` audited declarations across `15` `.lean` files) plus live negative kernel-rejection tests in both `pytest` (`13/13`) and CI confirming Lean rejects a deliberately false `Compress_1` claim. |
| H8.08 | `gap` | `scripts/check_citations.py` | Closed Playbook v1.3 Item 16 by adding live Crossref retraction checks (`relation.is-retracted-by` and `update-to` `type == "retraction"`) under `--online`: **42/42 HTTP 200, 32/32 DOIs verified not retracted**. |
