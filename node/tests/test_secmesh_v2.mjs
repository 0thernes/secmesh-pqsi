// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v2 Node.js Test Suite:
//   - Positive, Negative, Differential (Moonlab C11 <-> OpenSSL 3.5.5),
//     Regression (SecMesh v1 10 defects), Hardened Guardian network security,
//     and Rosette-Wire verifiable receipt replay.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import dgram from 'node:dgram';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import fs from 'node:fs';
import os from 'node:os';
import {
  gf128Mul,
  carterWegmanMac,
  carterWegmanVerify,
  sealCwFrame,
  verifyCwFrame,
  createReplayWindow,
  thresholdHedgedNonce,
  dualSurvivabilityCombine,
  generatePeerIdentity,
  runPQSIHandshake,
  sealRecord,
  openRecord,
} from '../src/pqsi-handshake.mjs';
import { evaluateEshkolFile, evaluateEshkolSource } from '../src/eshkol-ad-runtime.mjs';
import {
  TSIRELSON,
  P_ANTI_EXACT,
  P_CORR_EXACT,
  binEntropy,
  chshLowerBoundV2,
  minEntropyDI,
  vonNeumannEntropyDI,
  evaluateFiniteKeyV2,
  evaluateLegacyV1BrokenGate,
  toeplitzExtract,
  simulateE91Session,
} from '../src/finite-key-v2.mjs';
import { createHardenedGuardian, HealthFieldEngine } from '../src/mesh-guardian-v2.mjs';
import { canonicalJson, createRosetteBundle, verifyRosetteBundleDir } from '../src/rosette-receipt.mjs';
import { runCrossImplMlkem768Check } from '../src/secmesh-cli.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const NATIVE_BIN = path.join(REPO_ROOT, 'native', 'build', process.platform === 'win32' ? 'secmesh_core.exe' : 'secmesh_core');

let passed = 0;
async function test(name, fn) {
  await fn();
  passed++;
  console.log(`  [PASS] ${name}`);
}

console.log('=== SecMesh-PQSI v2 Node.js Differential, Security & Regression Suite ===');

await test('Regression T1a: SecMesh v1 0.146/0.854 exceeds Tsirelson (2.832 > 2*sqrt(2)); v2 exact', () => {
  const sV1 = 4 * (1 - 2 * 0.146);
  const sV2 = 4 * (1 - 2 * P_ANTI_EXACT);
  assert.ok(sV1 > TSIRELSON, 'v1 must exceed Tsirelson');
  assert.ok(Math.abs(sV2 - TSIRELSON) < 1e-15, 'v2 equals exact 2*sqrt(2)');
  assert.ok(Math.abs(P_ANTI_EXACT + P_CORR_EXACT - 1) < 1e-15);
});

await test('Regression T1c: Strict gap H_min^DI(S) < H_vN^DI(S) on interior (2, 2*sqrt(2))', () => {
  for (const s of [2.1, 2.25, 2.4, 2.5, 2.65, 2.75, 2.8]) {
    assert.ok(minEntropyDI(s) < vonNeumannEntropyDI(s), `strict gap at S=${s}`);
  }
  assert.equal(minEntropyDI(2.0), 0);
  assert.equal(minEntropyDI(TSIRELSON), 1);
});

await test('Differential: Node Finite-Key v2 matches Moonlab C11 secmesh_core bit-for-bit', () => {
  const cJson = JSON.parse(execFileSync(NATIVE_BIN, ['finite-key', '2.82842712474619', '450000', '0.0', '1e-6', '1'], { encoding: 'utf8' }));
  const jsRes = evaluateFiniteKeyV2({
    S: 2.82842712474619,
    cnts: [50000, 50000, 50000, 50000],
    nKey: 50000,
    qberErrors: 0,
    qberSample: 10000,
    epsTotal: 1e-6,
  });
  assert.equal(jsRes.certBits, cJson.cert_bits);
  assert.ok(Math.abs(jsRes.sLB - cJson.s_lb) < 1e-9);
  assert.ok(Math.abs(jsRes.qberUB - cJson.qber_ub) < 1e-9);
  assert.ok(jsRes.admitted && jsRes.certBits > 15000);
});

await test('Regression T1b: Legacy v1 falsely over-certifies at N=20k/50k where corrected v2 refuses admission', () => {
  const v1_20k = evaluateLegacyV1BrokenGate({ S: 2.832, sift: 2222, QBER: 0, cnts: [2222, 2222, 2222, 2222], eps: 1e-6 });
  const v2_20k = evaluateFiniteKeyV2({ S: TSIRELSON, cnts: [2222, 2222, 2222, 2222], nKey: 2222, qberErrors: 0, qberSample: 444, epsTotal: 1e-6 });
  assert.ok(v1_20k.certBits > 800, `v1 falsely claimed ${v1_20k.certBits} bits at N=20k`);
  assert.equal(v2_20k.certBits, 0, 'corrected v2 certifies 0 bits at N=20k');

  const v1_50k = evaluateLegacyV1BrokenGate({ S: 2.832, sift: 5555, QBER: 0, cnts: [5555, 5555, 5555, 5555], eps: 1e-6 });
  const v2_50k = evaluateFiniteKeyV2({ S: TSIRELSON, cnts: [5555, 5555, 5555, 5555], nKey: 5555, qberErrors: 0, qberSample: 1111, epsTotal: 1e-6 });
  assert.ok(v1_50k.certBits > 3000, `v1 falsely claimed ${v1_50k.certBits} bits at N=50k`);
  assert.equal(v2_50k.admitted, false, 'corrected v2 refuses 256-bit key admission at N=50k');
  assert.ok(v2_50k.certBits < 256, `corrected v2 yields ${v2_50k.certBits} < 256 bits at N=50k`);
});

await test('Differential Cross-Implementation: Moonlab C11 ML-KEM-768 <-> OpenSSL 3.5.5 ML-KEM-768', () => {
  const r = runCrossImplMlkem768Check();
  assert.equal(r.ok, true);
  assert.equal(r.ekBytes, 1184);
  assert.equal(r.ctBytes, 1088);
});

await test('PQSI Handshake (X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65 + SLH-DSA-128s + CW-128 + OTP)', () => {
  const a = generatePeerIdentity('alpha', { latticeHedged: true });
  const b = generatePeerIdentity('beta', { latticeHedged: true });
  const itKey = crypto.randomBytes(32);
  const cwKey = { r: crypto.randomBytes(16), bClient: crypto.randomBytes(16), bServer: crypto.randomBytes(16) };
  const hs = runPQSIHandshake(a, b, { preSharedItKey: itKey, preSharedCwKey: cwKey });
  assert.equal(hs.ok, true);
  assert.equal(hs.securityTier, 'HYBRID_PQ_IT_OTP');
  assert.equal(hs.latticeHedged, true);

  const otpPad = crypto.randomBytes(64);
  const recCw = { r: crypto.randomBytes(16), b: crypto.randomBytes(16) };
  const pt = Buffer.from('Top-secret post-super-intelligence mesh command');
  const aad = Buffer.from('hdr:v2:seq=1');
  const rec = sealRecord(hs.sessionKey, pt, aad, { otpPadOpt: otpPad, cwKeyOpt: recCw });
  const dec = openRecord(hs.sessionKeyResponder, rec, aad, { otpPadOpt: otpPad, cwKeyOpt: recCw });
  assert.ok(dec.equals(pt));

  // Negative: 1-bit tamper MUST fail Carter-Wegman IT-MAC before decryption!
  rec.ciphertext[0] ^= 0x01;
  assert.throws(() => openRecord(hs.sessionKeyResponder, rec, aad, { otpPadOpt: otpPad, cwKeyOpt: recCw }),
    /Carter-Wegman IT-MAC verification failed/);
  hs.sessionKey.fill(0);
  hs.sessionKeyResponder.fill(0);
});

await test('Negative: Carter-Wegman GF(2^128) IT-MAC rejects length extension and bit flips', () => {
  const r = crypto.randomBytes(16);
  const b = crypto.randomBytes(16);
  const m1 = Buffer.from('hello');
  const m2 = Buffer.from('hello\x00'); // zero-padded extension must NOT collide!
  const t1 = carterWegmanMac(r, b, m1);
  assert.equal(carterWegmanVerify(t1, r, b, m1), true);
  assert.equal(carterWegmanVerify(t1, r, b, m2), false);
});

await test('Theorem T2b: Dual-Survivability Combiner exact OTP bijection & Toeplitz linearity', () => {
  const k1 = crypto.randomBytes(32);
  const k2 = crypto.randomBytes(32);
  const it = crypto.randomBytes(32);
  const tr = Buffer.from('transcript');
  const outA = dualSurvivabilityCombine({ kX25519: k1, kMlKem: k2, kItOpt: it, transcriptBuf: tr });
  const itFlip = Buffer.from(it);
  itFlip[7] ^= 0x20;
  const outB = dualSurvivabilityCombine({ kX25519: k1, kMlKem: k2, kItOpt: itFlip, transcriptBuf: tr });
  assert.equal(outA[7] ^ outB[7], 0x20);

  const x = crypto.randomBytes(16), y = crypto.randomBytes(16);
  const xy = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) xy[i] = x[i] ^ y[i];
  const seed = crypto.randomBytes(40);
  const tx = toeplitzExtract(x, seed, 8);
  const ty = toeplitzExtract(y, seed, 8);
  const txy = toeplitzExtract(xy, seed, 8);
  for (let i = 0; i < 8; i++) assert.equal(tx[i] ^ ty[i], txy[i]);
});

await test('Seeded E91 Simulation: honest admits, Classical/Aligned/Parked Eve all rejected', () => {
  const hon = simulateE91Session({ nRounds: 450000, eveRate: 0, seed: 42 });
  const cls = simulateE91Session({ nRounds: 450000, eveRate: 0.4, eveMode: 'flip', seed: 42 });
  const aln = simulateE91Session({ nRounds: 450000, eveRate: 0.2, eveMode: 'aligned', seed: 42 });
  const prk = simulateE91Session({ nRounds: 450000, eveRate: 0.088, eveMode: 'parked', seed: 42 });
  assert.equal(hon.verdict, 'KEY');
  assert.equal(hon.physicalQkdHardware, false);
  assert.equal(cls.verdict, 'ABORT');
  assert.equal(aln.verdict, 'ABORT');
  assert.equal(prk.verdict, 'ABORT');
});

await test('Hardened Mesh Guardian v2: CW-128 anti-replay & per-frame pad enforcement, no wildcard CORS, no UDP amp, no key leak', async () => {
  const cwKey = { r: crypto.randomBytes(16), padSeed: crypto.randomBytes(32) };
  const guard = createHardenedGuardian({
    host: '127.0.0.1',
    listenPort: 0,
    statusPort: 0,
    udpEnabled: true,
    rateLimitPerSec: 10,
    cwControlKey: cwKey,
    allowedOrigin: 'http://127.0.0.1:8080',
  });
  const { tcpPort, statusPort, udpPort } = await guard.start();
  try {
    // 1. Send valid sequence-bound CW-128 authenticated frame (seq = 1)
    const payload = Buffer.from('PING-AUTH');
    const frame1 = sealCwFrame(cwKey.r, cwKey.padSeed, 1n, payload);
    const ack = await new Promise((resolve, reject) => {
      const s = net.connect(tcpPort, '127.0.0.1', () => s.write(frame1));
      s.once('data', d => { s.end(); resolve(d.toString()); });
      s.once('error', reject);
    });
    assert.equal(JSON.parse(ack).ok, true);

    // 1b. Negative (Theorem T2d anti-replay / pad-reuse defense): replaying seq = 1 MUST be rejected!
    await new Promise((resolve) => {
      const s = net.connect(tcpPort, '127.0.0.1', () => s.write(frame1));
      s.on('close', resolve);
      s.on('error', () => {});
    });
    assert.ok((guard.state.byVector['cw-replay-reject'] || 0) >= 1, 'replayed seq=1 must be rejected');

    // 1c. Fresh seq = 2 frame with distinct per-frame pad succeeds cleanly
    const frame2 = sealCwFrame(cwKey.r, cwKey.padSeed, 2n, Buffer.from('PING-AUTH-2'));
    const ack2 = await new Promise((resolve, reject) => {
      const s = net.connect(tcpPort, '127.0.0.1', () => s.write(frame2));
      s.once('data', d => { s.end(); resolve(d.toString()); });
      s.once('error', reject);
    });
    assert.equal(JSON.parse(ack2).ok, true);

    // 2. Negative: Unauthenticated frame MUST be rejected & tallied
    await new Promise((resolve) => {
      const s = net.connect(tcpPort, '127.0.0.1', () => s.write(Buffer.from('FORGED-FRAME-WITHOUT-MAC-12345-PAD')));
      s.on('close', resolve);
      s.on('error', () => {});
    });
    assert.ok((guard.state.byVector['cw-mac-reject'] || 0) >= 1);

    // 3. Negative: UDP packet must NOT trigger reflection echo
    const udpCli = dgram.createSocket('udp4');
    let echoed = false;
    udpCli.on('message', () => { echoed = true; });
    await new Promise(r => udpCli.send(Buffer.from('UDP-AMP-PROBE'), udpPort, '127.0.0.1', r));
    await new Promise(r => setTimeout(r, 80));
    udpCli.close();
    assert.equal(echoed, false, 'UDP must NOT echo/amplify');

    // 4. Negative: Evil Origin must NOT get CORS header, and /status leaks no secret key
    const resp = await fetch(`http://127.0.0.1:${statusPort}/status`, {
      headers: { Origin: 'https://evil.example' },
    });
    assert.equal(resp.headers.get('access-control-allow-origin'), null);
    const body = await resp.json();
    assert.equal(body.ok, true);
    assert.equal('key' in body, false);
  } finally {
    await guard.stop();
  }
});

await test('Self-Stabilizing Health Field: deterministic seeded replay matches bit-for-bit', () => {
  const mkRng = (seed) => {
    let s = seed >>> 0;
    return () => { s = (Math.imul(1664525, s) + 1013904223) >>> 0; return s / 4294967296; };
  };
  const h1 = new HealthFieldEngine({ nodeCount: 60, defenderCount: 6, firewall: 0.7, threat: 0.35 });
  const h2 = new HealthFieldEngine({ nodeCount: 60, defenderCount: 6, firewall: 0.7, threat: 0.35 });
  const r1 = mkRng(1337), r2 = mkRng(1337);
  let last1, last2;
  for (let i = 0; i < 300; i++) { last1 = h1.step(r1); last2 = h2.step(r2); }
  assert.deepEqual(last1, last2);
  assert.equal(last1.intrusions, 0);
});

await test('Rosette-Wire Verifiable Receipt Bundle: create & independent replay verify', () => {
  const dir = path.join(REPO_ROOT, 'rosette', 'test-receipt');
  createRosetteBundle({
    compositionId: 'unit-test-v2',
    components: ['pqsi-handshake', 'finite-key-v2'],
    inputs: { seed: 7 },
    outputs: { status: 'ok' },
    checks: [{ name: 'deterministic_check', passed: true }],
    outDir: dir,
  });
  const ver = verifyRosetteBundleDir(dir);
  assert.equal(ver.ok, true);
  assert.equal(ver.verdict, 'VERIFIED');
});

await test('Theorem T6b: Cryptosymbology threshold-hedged nonce XOR dual-closure', () => {
  const rSignerMalicious = Buffer.alloc(32, 0x5A); // adversarial subliminal payload
  const rAuditor = crypto.randomBytes(32);
  const rEff = thresholdHedgedNonce(rSignerMalicious, rAuditor);
  // Exact inverse recovery verifies bijection on {0,1}^256
  assert.ok(thresholdHedgedNonce(rEff, rSignerMalicious).equals(rAuditor));
  assert.ok(thresholdHedgedNonce(rEff, rAuditor).equals(rSignerMalicious));
  assert.throws(() => thresholdHedgedNonce(Buffer.alloc(16), Buffer.alloc(32)));
});

await test('Eshkol v1.3.6 Forward-Mode Dual-Number AD Execution across 4 core .esk modules', () => {
  const eskDir = path.join(REPO_ROOT, 'eshkol');
  const rFk = evaluateEshkolFile(path.join(eskDir, 'finite_key_ad.esk'));
  assert.ok(rFk.regions.includes('secmesh-finite-key-ad'));
  // Analytical check of dH_min^DI/dS at S=2.5: S / (4 * ln(2) * sqrt(2 - S^2/4) * (1 + sqrt(2 - S^2/4)))
  const s0 = 2.5;
  const v = Math.sqrt(2 - 0.25 * s0 * s0);
  const expectedDHmin = s0 / (4 * Math.LN2 * v * (1 + v));
  const mFk = rFk.lines.find(l => l.includes('dH_min^DI / dS = '));
  assert.ok(Math.abs(parseFloat(mFk.split('= ')[1]) - expectedDHmin) < 1e-12);

  const rQgt = evaluateEshkolFile(path.join(eskDir, 'qgt_geodesic.esk'));
  assert.ok(rQgt.regions.includes('secmesh-qgt-entanglement-ad'));
  const mResid = rQgt.lines.find(l => l.includes('Identity residual'));
  assert.ok(Math.abs(parseFloat(mResid.split('= ')[1])) < 1e-15);
  const mDsurpDt = rQgt.lines.find(l => l.includes('d(surplus)/d(theta)'));
  // At singlet (C=1), d/dtheta [(1/4) sin^2(theta/2)] = (1/8) sin(theta)
  assert.ok(Math.abs(parseFloat(mDsurpDt.split('= ')[1]) - Math.sin(Math.PI / 3) / 8) < 1e-12);

  const rBw = evaluateEshkolFile(path.join(eskDir, 'bandwidth_opt.esk'));
  assert.ok(rBw.regions.includes('secmesh-bandwidth-ad'));
  const mDbw = rBw.lines.find(l => l.includes('d(total bytes)/dN'));
  // d/dN [0.5*N*(N-1)*13274] at N=32 = 31.5 * 13274 = 418131
  assert.ok(Math.abs(parseFloat(mDbw.split('= ')[1]) - 31.5 * 13274) < 1e-9);

  const rCi = evaluateEshkolFile(path.join(eskDir, 'chern_ising_ad.esk'));
  assert.ok(rCi.regions.includes('secmesh-chern-ising-ad'));
  const mCons = rCi.lines.find(l => l.includes('conservation err'));
  assert.ok(Math.abs(parseFloat(mCons.split('= ')[1])) < 1e-15);
  const mDbar = rCi.lines.find(l => l.includes('d(IsingBarrier)/d(phi0)'));
  assert.ok(Math.abs(parseFloat(mDbar.split('= ')[1]) - 20.0) < 1e-12);
});

await test('Differential C11: Chern-Concurrence-GHZ (T4d/T4e) & Ising Expander Barrier (T6a)', () => {
  const cg = JSON.parse(execFileSync(NATIVE_BIN, ['chern-law', String(Math.PI / 8), '8'], { encoding: 'utf8' }));
  assert.ok(cg.conservation_err < 1e-14);
  assert.ok(Math.abs(cg.h_min_from_chern - cg.h_min_from_chsh) < 1e-12);
  assert.equal(cg.beats_sql, true);
  assert.equal(cg.casimir_4j_jp1, 80);

  const bar = JSON.parse(execFileSync(NATIVE_BIN, ['ising-barrier', '60', '10', '1.0', '2.0', '0.7'], { encoding: 'utf8' }));
  assert.ok(Math.abs(bar.min_work_barrier - 54.0) < 1e-12);
});

await test('Security: Bounded RFC-6479 CW-128 Sliding Replay Window rejects stale & bounds memory O(1)', () => {
  const r = crypto.randomBytes(16);
  const padSeed = crypto.randomBytes(32);
  const win = createReplayWindow(8n);
  // Accept 20 monotonically increasing frames; window must stay <= 8 entries!
  for (let i = 1n; i <= 20n; i++) {
    const f = sealCwFrame(r, padSeed, i, Buffer.from(`MSG-${i}`));
    const v = verifyCwFrame(f, r, padSeed, win);
    assert.equal(v.ok, true);
  }
  assert.ok(win.size <= 8, `replay window grew unbounded: ${win.size}`);
  // Exact in-window duplicate (seq=19) rejected
  const dup = sealCwFrame(r, padSeed, 19n, Buffer.from('MSG-19'));
  assert.equal(verifyCwFrame(dup, r, padSeed, win).reason, 'cw-replay-reject');
  // Stale below-window sequence (seq=5 <= 20 - 8 = 12) MUST be rejected even after eviction!
  const stale = sealCwFrame(r, padSeed, 5n, Buffer.from('MSG-5'));
  assert.equal(verifyCwFrame(stale, r, padSeed, win).reason, 'cw-replay-reject');
});

await test('Security Cycle 9: Strict CLI hex/NaN guards, fail-closed finite-key, Rosette non-empty checks & Eshkol DoS cap', () => {
  // 1. Native C11 CLI must reject non-hex / whitespace-padded hex in mlkem-encaps (H9.02)
  assert.throws(() => {
    execFileSync(NATIVE_BIN, ['mlkem-encaps', ' 0'.repeat(1184), '00'.repeat(32)], { stdio: 'pipe' });
  });
  assert.throws(() => {
    execFileSync(NATIVE_BIN, ['mlkem-encaps', 'aZ'.repeat(1184), '00'.repeat(32)], { stdio: 'pipe' });
  });
  // 2. Native C11 CLI must reject negative or NaN QBER (H9.02)
  assert.throws(() => {
    execFileSync(NATIVE_BIN, ['finite-key', '2.828', '450000', '-0.5', '1e-6', '1'], { stdio: 'pipe' });
  });
  // 3. Node finite-key fails closed on NaN CHSH and negative qberErrors (H9.06)
  assert.equal(minEntropyDI(Number.NaN), 0);
  assert.equal(vonNeumannEntropyDI(Number.NaN), 0);
  const badFk = evaluateFiniteKeyV2({
    S: 2.828,
    cnts: [50000, 50000, 50000, 50000],
    nKey: 50000,
    qberErrors: -1,
    qberSample: 10000,
    epsTotal: 1e-6,
  });
  assert.equal(badFk.admitted, false);
  assert.equal(badFk.certBits, 0);
  // 4. Rosette-Wire bundle refuses empty checks[] array (H9.07)
  const emptyBundle = createRosetteBundle({
    compositionId: 'empty-check-reject-test',
    components: ['test'],
    inputs: {},
    outputs: {},
    checks: [],
    outDir: null,
  });
  assert.equal(emptyBundle.verification.verdict, 'REFUSED');
  // 5. Eshkol AD runtime enforces recursion depth / step budget DoS cap (H9.08)
  assert.throws(() => {
    evaluateEshkolSource('(define (loop x) (loop (+ x 1))) (loop 0)');
  }, /budget|depth/);
});

await test('Security & AD Cycle 10: Canonical CW-128 record framing, kItOpt length guard & Eshkol T7 AD module', () => {
  // 1. dualSurvivabilityCombine must refuse non-32-byte kItOpt (H10.04)
  assert.throws(() => {
    dualSurvivabilityCombine({
      kX25519: crypto.randomBytes(32),
      kMlKem: crypto.randomBytes(32),
      kItOpt: crypto.randomBytes(16),
      transcriptBuf: Buffer.from('tx'),
    });
  }, /32-byte/);
  // 2. Canonical length-prefixed CW-128 record framing rejects shifted AAD/ct boundaries (H10.04)
  const sk = crypto.randomBytes(32);
  const cw = { r: crypto.randomBytes(16), b: crypto.randomBytes(16) };
  const otp = crypto.randomBytes(64);
  const rec = sealRecord(sk, Buffer.from('secret-payload'), Buffer.from('aad-part'), { otpPadOpt: otp, cwKeyOpt: cw });
  assert.equal(openRecord(sk, rec, Buffer.from('aad-part'), { otpPadOpt: otp, cwKeyOpt: cw }).toString(), 'secret-payload');
  assert.throws(() => {
    openRecord(sk, rec, Buffer.from('aad-par'), { otpPadOpt: otp, cwKeyOpt: cw });
  }, /Carter-Wegman/);
  // 3. 5th Eshkol v1.3.6 AD module covering T7a Toner Monogamy & T7b Commitment Conservation (H10.06)
  const eskT7 = path.join(REPO_ROOT, 'eshkol', 'monogamy_commitment_ad.esk');
  const rT7 = evaluateEshkolFile(eskT7);
  assert.ok(rT7.regions.includes('secmesh-monogamy-commitment-ad'));
  const mDsae = rT7.lines.find(l => l.includes('d(S_AE)/d(S_AB)'));
  const exactDsae = -2.4 / Math.sqrt(8.0 - 2.4 * 2.4);
  assert.ok(Math.abs(parseFloat(mDsae.split('= ')[1]) - exactDsae) < 1e-12);
  const mDrdc = rT7.lines.find(l => l.includes('d(r_A)/d(C_AB)'));
  assert.ok(Math.abs(parseFloat(mDrdc.split('= ')[1]) - (-0.6 / 0.8)) < 1e-12);
  const mDov = rT7.lines.find(l => l.includes('d(Overlap)/d(TV)'));
  assert.ok(Math.abs(parseFloat(mDov.split('= ')[1]) - (-1.0)) < 1e-12);
  const mBceil = rT7.lines.find(l => l.includes('T7c B_max(0.8)'));
  assert.ok(Math.abs(parseFloat(mBceil.split('= ')[1]) - 0.6) < 1e-12);
  const mDbdtv = rT7.lines.find(l => l.includes('d(B_max)/d(TV)'));
  assert.ok(Math.abs(parseFloat(mDbdtv.split('= ')[1]) - (-0.8 / 0.6)) < 1e-12);
});

await test('Security Cycle 11: GCM tag-truncation refusal, CW-128 length guards, HTTP 405, Eshkol parse-depth, Rosette schema & seeded Toeplitz determinism', async () => {
  // 1. H11.01: AES-256-GCM tag-truncation (CWE-347) & key/IV/CW-128 length refusal
  const sk = crypto.randomBytes(32);
  const rec = sealRecord(sk, Buffer.from('hello-pqsi'), Buffer.from('aad'));
  const truncRec = { ...rec, gcmTag: rec.gcmTag.subarray(0, 4) };
  assert.throws(() => openRecord(sk, truncRec, Buffer.from('aad')), /Malformed record|16-byte/);
  assert.throws(() => openRecord(crypto.randomBytes(16), rec, Buffer.from('aad')), /32-byte/);
  assert.throws(() => gf128Mul(Buffer.alloc(15), Buffer.alloc(16)), /16-byte/);
  assert.throws(() => carterWegmanMac(Buffer.alloc(16), Buffer.alloc(15), Buffer.from('x')), /16-byte/);

  // 2. H11.02: HealthFieldEngine invalid parameter refusal & Guardian HTTP 405 + hardening headers
  assert.throws(() => new HealthFieldEngine({ nodeCount: 0 }), /nodeCount/);
  assert.throws(() => new HealthFieldEngine({ firewall: 1.5 }), /firewall/);
  const g = createHardenedGuardian({ host: '127.0.0.1', listenPort: 0, statusPort: 0 });
  const ports = await g.start();
  try {
    const rPost = await fetch(`http://127.0.0.1:${ports.statusPort}/status`, { method: 'POST' });
    assert.equal(rPost.status, 405);
    const rGet = await fetch(`http://127.0.0.1:${ports.statusPort}/status?ignored=1`);
    assert.equal(rGet.status, 200);
    assert.equal(rGet.headers.get('cache-control'), 'no-store');
    assert.equal(rGet.headers.get('content-security-policy'), "default-src 'none'");
  } finally {
    await g.stop();
  }

  // 3. H11.03: Eshkol parser recursion-depth DoS cap & malformed special forms
  assert.throws(() => evaluateEshkolSource('('.repeat(300) + '1' + ')'.repeat(300)), /nesting depth/);
  assert.throws(() => evaluateEshkolSource('(lambda 42 x)'), /Malformed lambda/);

  // 4. H11.04: Rosette canonicalJson undefined/NaN handling & schema/compositionId verification
  assert.equal(canonicalJson({ b: 2, a: undefined, c: [1, undefined] }), '{"b":2,"c":[1,null]}');
  assert.throws(() => canonicalJson({ x: Number.NaN }), /non-finite/);
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secmesh-rosette-c11-'));
  try {
    createRosetteBundle({
      compositionId: 'c11-schema-test',
      components: ['test'],
      inputs: { k: 1, ignored: undefined },
      outputs: { ok: true },
      checks: [{ name: 'c1', passed: true }],
      outDir: tmpDir,
    });
    assert.equal(verifyRosetteBundleDir(tmpDir).ok, true);
    const vPath = path.join(tmpDir, 'verification.json');
    const vObj = JSON.parse(fs.readFileSync(vPath, 'utf8'));
    vObj.compositionId = 'forged-id';
    fs.writeFileSync(vPath, JSON.stringify(vObj, null, 2) + '\n');
    assert.equal(verifyRosetteBundleDir(tmpDir).ok, false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // 5. H11.05: Native C11 CLI strict parser refuses NaN/negative bandwidth & garbage tokens
  assert.throws(() => execFileSync(NATIVE_BIN, ['bandwidth', '100000000', 'NaN'], { stdio: 'pipe' }));
  assert.throws(() => execFileSync(NATIVE_BIN, ['bandwidth', '100000000', '-1'], { stdio: 'pipe' }));
  assert.throws(() => execFileSync(NATIVE_BIN, ['finite-key', 'garbage'], { stdio: 'pipe' }));

  // 6. H11.06: Node finite-key NaN guards & deterministic seeded Toeplitz keyFingerprint
  assert.equal(binEntropy(Number.NaN), 0);
  assert.equal(chshLowerBoundV2(2.8, [50000, 50000, 50000, 50000], 0), 2);
  const sim1 = simulateE91Session({ nRounds: 450000, eveRate: 0, seed: 20261125 });
  const sim2 = simulateE91Session({ nRounds: 450000, eveRate: 0, seed: 20261125 });
  assert.ok(sim1.keyFingerprint && sim1.keyFingerprint.length === 32);
  assert.equal(sim1.keyFingerprint, sim2.keyFingerprint);
});

console.log(`=== Node.js Suite Summary: ${passed}/${passed} passed ===`);
