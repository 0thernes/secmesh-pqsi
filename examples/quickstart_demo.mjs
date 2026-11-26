#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
// Runnable end-to-end demonstration of SecMesh-PQSI v2.3.0

import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generatePeerIdentity, runPQSIHandshake } from '../node/src/pqsi-handshake.mjs';
import { evaluateFiniteKeyV2, evaluateLegacyV1BrokenGate, TSIRELSON } from '../node/src/finite-key-v2.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');
const nativeBin = existsSync(resolve(root, 'native/build/secmesh_core.exe'))
  ? resolve(root, 'native/build/secmesh_core.exe')
  : resolve(root, 'native/build/secmesh_core');

console.log('=== SecMesh-PQSI v2.3.0 Quickstart Demo ===\n');

// 1. Live Lattice-Hedged PQSI Handshake
const alpha = generatePeerIdentity('alpha-demo', { latticeHedged: true });
const beta = generatePeerIdentity('beta-demo', { latticeHedged: true });
const itKey = crypto.randomBytes(32);
const cwKey = { r: crypto.randomBytes(16), bClient: crypto.randomBytes(16), bServer: crypto.randomBytes(16) };
const hs = runPQSIHandshake(alpha, beta, { preSharedItKey: itKey, preSharedCwKey: cwKey });
console.log('[1] Live Lattice-Hedged PQSI Handshake (X25519+ML-KEM-768+Ed25519+ML-DSA-65+SLH-DSA-128s+CW-128+OTP):');
console.log(`    ok=${hs.ok}, tier=${hs.securityTier}, C->S=${hs.wireBytes.clientToServer} B, S->C=${hs.wireBytes.serverToClient} B, RTT=${hs.wireBytes.totalRoundTrip} B (${hs.elapsedMs.toFixed(1)} ms)\n`);
hs.sessionKey.fill(0);
hs.sessionKeyResponder.fill(0);

// 2. Composable Finite-Key v2 vs Defective Legacy v1
const cell450 = 50000;
const fkClean = evaluateFiniteKeyV2({ S: TSIRELSON, cnts: [cell450, cell450, cell450, cell450], nKey: cell450, qberErrors: 0, qberSample: 10000, epsTotal: 1e-6 });
const fkEve = evaluateFiniteKeyV2({ S: 2.0, cnts: [cell450, cell450, cell450, cell450], nKey: cell450, qberErrors: 0, qberSample: 10000, epsTotal: 1e-6 });
const cell50 = Math.floor(50000 / 9);
const fkV1 = evaluateLegacyV1BrokenGate({ S: 2.832, sift: cell50, QBER: 0.0, cnts: [cell50, cell50, cell50, cell50], eps: 1e-6 });
const fkV2Small = evaluateFiniteKeyV2({ S: TSIRELSON, cnts: [cell50, cell50, cell50, cell50], nKey: cell50, qberErrors: 0, qberSample: Math.floor(cell50 / 5), epsTotal: 1e-6 });
console.log('[2] Finite-Key Admission Contrast (eps=1e-6):');
console.log(`    Clean Singlet N=450k (v2): admitted=${fkClean.admitted}, cert_bits=${fkClean.certBits}, s_lb=${fkClean.sLB.toFixed(6)}`);
console.log(`    Parked Eve    N=450k (v2): admitted=${fkEve.admitted}, cert_bits=${fkEve.certBits}`);
console.log(`    Small Block   N=50k  (v1 broken vs v2): v1=${fkV1.certBits} bits (FALSE OVERCLAIM) vs v2=${fkV2Small.certBits} bits (admitted=${fkV2Small.admitted})\n`);

// 3. Native C11 Moonlab Core (QGTL + Bravyi BB144 + ML-KEM-768 KAT)
if (existsSync(nativeBin)) {
  const qgt = JSON.parse(execFileSync(nativeBin, ['qgt', String(Math.PI / 2), '0.785398163', String(Math.PI / 4)], { encoding: 'utf8' }));
  const bb = JSON.parse(execFileSync(nativeBin, ['bb144'], { encoding: 'utf8' }));
  const kat = JSON.parse(execFileSync(nativeBin, ['mlkem-kat'], { encoding: 'utf8' }));
  console.log('[3] Native C11 Moonlab Core Verification:');
  console.log(`    ML-KEM-768 KAT: ek_valid=${kat.ek_valid}, match=${kat.match}, fo_implicit_reject=${kat.fo_implicit_reject}`);
  console.log(`    QGTL Singlet (theta=pi/2, C=1): omega=${qgt.omega_tp.toFixed(12)}, surplus=${qgt.surplus.toFixed(12)} (exact 0.125)`);
  console.log(`    Bravyi [[${bb.n},${bb.k},12]] BB qLDPC: rank_hx=${bb.rank_hx}, rank_hz=${bb.rank_hz}, css_orthogonal=${bb.css_orthogonal}\n`);
} else {
  console.log('[3] Native C11 binary not yet compiled (run `make -C native all` first).\n');
}
console.log('Demo complete.');
