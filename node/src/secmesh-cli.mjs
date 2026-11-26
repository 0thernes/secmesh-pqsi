#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v2 CLI — Real Post-Quantum + Post-Super-Intelligence Cyber-Defense Engine

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  generatePeerIdentity,
  runPQSIHandshake,
  sealRecord,
  openRecord,
} from './pqsi-handshake.mjs';
import {
  evaluateFiniteKeyV2,
  evaluateLegacyV1BrokenGate,
  simulateE91Session,
} from './finite-key-v2.mjs';
import { createRosetteBundle } from './rosette-receipt.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

function nativeBinaryPath() {
  const exe = process.platform === 'win32' ? 'secmesh_core.exe' : 'secmesh_core';
  return path.join(REPO_ROOT, 'native', 'build', exe);
}

/**
 * Cross-implementation differential verification:
 *   Node.js 25 OpenSSL 3.5.5 generates ML-KEM-768 keypair (SPKI DER),
 *   extracts raw 1184-byte FIPS 203 ek, passes ek + fresh 32B seed m to
 *   Tsotchke Moonlab's C11 binary `secmesh_core mlkem-encaps`, and Node.js 25
 *   OpenSSL 3.5.5 decapsulates Moonlab's ciphertext ct and verifies bit-exact
 *   32-byte shared secret equality!
 */
export function runCrossImplMlkem768Check() {
  const bin = nativeBinaryPath();
  if (!fs.existsSync(bin)) {
    throw new Error(`Native binary missing: ${bin}`);
  }
  const kp = crypto.generateKeyPairSync('ml-kem-768');
  const spki = kp.publicKey.export({ type: 'spki', format: 'der' });
  // FIPS 203 ML-KEM-768 raw encapsulation key is the trailing 1184 bytes of SPKI BIT STRING
  const rawEk = spki.subarray(spki.length - 1184);
  const m = crypto.randomBytes(32);

  const stdout = execFileSync(bin, ['mlkem-encaps', rawEk.toString('hex'), m.toString('hex')], {
    encoding: 'utf8',
  });
  const cRes = JSON.parse(stdout.trim());
  if (!cRes.ok) throw new Error(`Moonlab C11 ML-KEM-768 encaps refused: ${cRes.error}`);

  const ct = Buffer.from(cRes.ct_hex, 'hex');
  const ssMoonlab = Buffer.from(cRes.ss_hex, 'hex');
  const ssOpenSsl = crypto.decapsulate(kp.privateKey, ct);
  const exactMatch = crypto.timingSafeEqual(ssMoonlab, ssOpenSsl);

  const ssFp = crypto.createHash('sha3-256').update(ssOpenSsl).digest('hex').slice(0, 32);
  ssMoonlab.fill(0);
  ssOpenSsl.fill(0);
  return {
    ok: exactMatch,
    ekBytes: rawEk.length,
    ctBytes: ct.length,
    sharedSecretSha3Prefix: ssFp,
    implementations: ['Moonlab-C11-FIPS203', `OpenSSL-${process.versions.openssl}-FIPS203`],
  };
}

function main() {
  const cmd = process.argv[2] || 'audit';
  if (cmd === 'handshake') {
    const hedged = process.argv.includes('--hedged');
    const withIt = !process.argv.includes('--pq-only');
    const a = generatePeerIdentity('mesh-node-alpha', { latticeHedged: hedged });
    const b = generatePeerIdentity('mesh-node-beta', { latticeHedged: hedged });
    const itKey = withIt ? crypto.randomBytes(32) : null;
    const cwKey = withIt
      ? { r: crypto.randomBytes(16), bClient: crypto.randomBytes(16), bServer: crypto.randomBytes(16) }
      : null;
    const hs = runPQSIHandshake(a, b, { preSharedItKey: itKey, preSharedCwKey: cwKey });
    const otpPad = withIt ? crypto.randomBytes(64) : null;
    const recCw = withIt ? { r: crypto.randomBytes(16), b: crypto.randomBytes(16) } : null;
    const msg = Buffer.from('SecMesh-PQSI v2 authenticated payload');
    const rec = sealRecord(hs.sessionKey, msg, Buffer.from('frame-0'), { otpPadOpt: otpPad, cwKeyOpt: recCw });
    const opened = openRecord(hs.sessionKeyResponder, rec, Buffer.from('frame-0'), { otpPadOpt: otpPad, cwKeyOpt: recCw });
    const roundtripOk = opened.equals(msg);
    hs.sessionKey.fill(0);
    hs.sessionKeyResponder.fill(0);
    console.log(JSON.stringify({
      ok: hs.ok && roundtripOk,
      securityTier: hs.securityTier,
      latticeHedged: hs.latticeHedged,
      sessionFingerprint: hs.sessionFingerprint,
      transcriptSha3: hs.transcriptSha3,
      wireBytes: hs.wireBytes,
      elapsedMs: Number(hs.elapsedMs.toFixed(3)),
    }, null, 2));
    process.exit(hs.ok && roundtripOk ? 0 : 1);
  }

  if (cmd === 'interop') {
    const res = runCrossImplMlkem768Check();
    console.log(JSON.stringify(res, null, 2));
    process.exit(res.ok ? 0 : 1);
  }

  if (cmd === 'audit') {
    const interop = runCrossImplMlkem768Check();
    const a = generatePeerIdentity('node-0', { latticeHedged: true });
    const b = generatePeerIdentity('node-1', { latticeHedged: true });
    const hs = runPQSIHandshake(a, b, {
      preSharedItKey: crypto.randomBytes(32),
      preSharedCwKey: { r: crypto.randomBytes(16), bClient: crypto.randomBytes(16), bServer: crypto.randomBytes(16) },
    });
    hs.sessionKey.fill(0);
    hs.sessionKeyResponder.fill(0);

    const honestSim = simulateE91Session({ nRounds: 450000, eveRate: 0, seed: 20261125 });
    const alignedSim = simulateE91Session({ nRounds: 450000, eveRate: 0.2, eveMode: 'aligned', seed: 20261125 });
    const v1Broken = evaluateLegacyV1BrokenGate({ S: 2.832, sift: 5555, QBER: 0, cnts: [5555, 5555, 5555, 5555], eps: 1e-6 });
    const v2Honest = evaluateFiniteKeyV2({ S: 2 * Math.SQRT2, cnts: [5555, 5555, 5555, 5555], nKey: 5555, qberErrors: 0, qberSample: 1111, epsTotal: 1e-6 });

    const outDir = path.join(REPO_ROOT, 'rosette', 'latest-audit');
    const bundle = createRosetteBundle({
      compositionId: 'secmesh-pqsi-full-audit-v2',
      components: ['moonlab-c11-fips203', 'openssl-3.5-fips203-204-205', 'secmesh-finite-key-v2', 'carter-wegman-gf128'],
      inputs: { nRounds: 450000, seed: 20261125, epsTotal: 1e-6 },
      outputs: {
        interop,
        handshakeTier: hs.securityTier,
        handshakeWireBytes: hs.wireBytes,
        honestCertBits: honestSim.cert.certBits,
        alignedEveCertBits: alignedSim.cert.certBits,
        v1BrokenAt50k: v1Broken.certBits,
        v2CorrectedAt50k: v2Honest.certBits,
      },
      checks: [
        { name: 'moonlab_c11_vs_openssl35_mlkem768_interop', passed: interop.ok },
        { name: 'pqsi_lattice_hedged_handshake', passed: hs.ok && hs.securityTier === 'HYBRID_PQ_IT_OTP' },
        { name: 'finite_key_v2_admits_honest_450k', passed: honestSim.verdict === 'KEY' && honestSim.cert.certBits > 10000 },
        { name: 'finite_key_v2_rejects_aligned_eve', passed: alignedSim.verdict === 'ABORT' && alignedSim.cert.certBits === 0 },
      ],
      outDir,
    });
    console.log(JSON.stringify(bundle.verification, null, 2));
    process.exit(bundle.verification.verdict === 'VERIFIED' ? 0 : 1);
  }

  console.error('Usage: node secmesh-cli.mjs <audit|handshake [--hedged] [--pq-only]|interop>');
  process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
