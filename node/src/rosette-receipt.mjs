// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// Rosette-Wire-compatible verifiable execution receipts (inspired by tsotchke/rosette-wire)
// Emits composition.json, receipt.json, and verification.json with canonical SHA-256 hashes.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export function canonicalJson(obj) {
  if (typeof obj === 'number' && !Number.isFinite(obj)) {
    throw new Error('canonicalJson rejects non-finite IEEE-754 numbers (NaN/Infinity)');
  }
  if (obj === undefined) return 'null';
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map((v) => (v === undefined ? 'null' : canonicalJson(v))).join(',') + ']';
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

export function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

export function createRosetteBundle({
  compositionId,
  components,
  inputs,
  outputs,
  checks,
  outDir = null,
}) {
  const composition = {
    schema: 'rosette-wire/composition/v1',
    id: compositionId,
    components,
    inputs,
    declaredBounds: { deterministicReplay: true, failClosed: true },
  };
  const compositionHash = sha256Hex(canonicalJson(composition));

  const receipt = {
    schema: 'rosette-wire/receipt/v1',
    compositionId,
    compositionSha256: compositionHash,
    timestampUtc: new Date().toISOString(),
    runtime: { node: process.version, openssl: process.versions.openssl, platform: process.platform },
    outputs,
  };
  const receiptHash = sha256Hex(canonicalJson(receipt));

  const allPassed =
    Array.isArray(checks) && checks.length > 0 && checks.every(c => c && c.passed === true);
  const verification = {
    schema: 'rosette-wire/verification/v1',
    compositionId,
    compositionSha256: compositionHash,
    receiptSha256: receiptHash,
    verdict: allPassed ? 'VERIFIED' : 'REFUSED',
    checks,
  };

  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, 'composition.json'), JSON.stringify(composition, null, 2) + '\n');
    fs.writeFileSync(path.join(outDir, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
    fs.writeFileSync(path.join(outDir, 'verification.json'), JSON.stringify(verification, null, 2) + '\n');
  }
  return { composition, receipt, verification };
}

export function verifyRosetteBundleDir(dir) {
  const composition = JSON.parse(fs.readFileSync(path.join(dir, 'composition.json'), 'utf8'));
  const receipt = JSON.parse(fs.readFileSync(path.join(dir, 'receipt.json'), 'utf8'));
  const verification = JSON.parse(fs.readFileSync(path.join(dir, 'verification.json'), 'utf8'));
  const cHash = sha256Hex(canonicalJson(composition));
  const rHash = sha256Hex(canonicalJson(receipt));
  const ok =
    composition.schema === 'rosette-wire/composition/v1' &&
    receipt.schema === 'rosette-wire/receipt/v1' &&
    verification.schema === 'rosette-wire/verification/v1' &&
    typeof composition.id === 'string' &&
    composition.id.length > 0 &&
    receipt.compositionId === composition.id &&
    verification.compositionId === composition.id &&
    receipt.compositionSha256 === cHash &&
    verification.compositionSha256 === cHash &&
    verification.receiptSha256 === rHash &&
    verification.verdict === 'VERIFIED' &&
    Array.isArray(verification.checks) &&
    verification.checks.length > 0 &&
    verification.checks.every(c => c && c.passed === true);
  return { ok, cHash, rHash, verdict: verification.verdict };
}
