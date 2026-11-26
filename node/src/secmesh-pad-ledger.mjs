// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — Crash-Safe Atomic One-Time Pad Ledger (`SECMESH_IT_PAD_FILE`)
// Enforces Theorem T2a & T2d unconditionally:
//   1. Exclusive OS lockfile (`O_CREAT | O_EXCL`) prevents multi-process offset races.
//   2. Write-ahead journal (`fsync` + atomic rename) advances consumedBytes BEFORE returning bytes.
//   3. Immediately overwrites consumed pad bytes on disk with zeros + `fsync` so a crash,
//      power loss, or SIGKILL can NEVER reuse a single One-Time Pad byte.
//   4. Gates newly ingested pad files through Moonlab C11 NIST SP 800-90B RCT+APT health tests.

import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { resolveNativeCoreBinary } from './native-ct-bridge.mjs';

const LEDGER_SCHEMA = 'secmesh-pqsi/pad-ledger/v3';

function ledgerPathFor(padPath) {
  return `${padPath}.ledger.json`;
}

function lockPathFor(padPath) {
  return `${padPath}.lock`;
}

function atomicWriteJson(filePath, obj) {
  const tmp = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  const data = Buffer.from(JSON.stringify(obj, null, 2) + '\n', 'utf8');
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeSync(fd, data, 0, data.length, 0);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, filePath);
}

function withExclusiveLock(padPath, fn) {
  const lockPath = lockPathFor(padPath);
  const deadline = Date.now() + 5000;
  let lockFd = -1;
  while (lockFd < 0) {
    try {
      lockFd = fs.openSync(lockPath, 'wx', 0o600);
      fs.writeSync(lockFd, `${process.pid}\n`);
      fs.fsyncSync(lockFd);
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      if (Date.now() > deadline) {
        throw new Error(`Pad ledger lock timeout (another process holds ${lockPath})`);
      }
      // Brief non-busy yield via Atomics.wait
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    }
  }
  try {
    return fn();
  } finally {
    try { fs.closeSync(lockFd); } catch { /* ignore */ }
    try { fs.unlinkSync(lockPath); } catch { /* ignore */ }
  }
}

export function auditPadFileSp80090b(padPath) {
  const bin = resolveNativeCoreBinary();
  if (!fs.existsSync(bin)) {
    throw new Error(`Native binary required for SP 800-90B pad audit: ${bin}`);
  }
  try {
    const out = execFileSync(bin, ['sp80090b-file', padPath], { encoding: 'utf8' });
    const res = JSON.parse(out.trim());
    return { ok: !!res.ok, bytesAudited: res.bytes_audited || 0 };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

/**
 * Initialize a new crash-safe One-Time Pad pool file on disk.
 * If `sourceBytes` is omitted, generates OS CSPRNG bytes (tagged as csprng_dev_pad;
 * supply physical QRNG bytes via `sourceBytes` for true physical PSI pad provenance).
 */
export function initPadPool(padPath, sizeBytes, { sourceBytes = null, runSp80090b = true, provenance = 'os-csprng-preshared' } = {}) {
  const abs = path.resolve(padPath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  const raw = sourceBytes ? Buffer.from(sourceBytes) : crypto.randomBytes(sizeBytes);
  if (raw.length < 512) {
    raw.fill(0);
    throw new Error('Pad pool must be at least 512 bytes (required for NIST SP 800-90B RCT/APT gate)');
  }
  const fd = fs.openSync(abs, 'w', 0o600);
  try {
    fs.writeSync(fd, raw, 0, raw.length, 0);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  try {
    if (runSp80090b) {
      const audit = auditPadFileSp80090b(abs);
      if (!audit.ok) {
        // Destroy rejected low-entropy pad file immediately
        fs.unlinkSync(abs);
        throw new Error('Pad file FAILED NIST SP 800-90B RCT/APT entropy health test — refused');
      }
    }
    const padId = crypto.createHash('sha3-256').update('SecMesh-PadId|').update(raw.subarray(0, 64)).digest('hex').slice(0, 32);
    const ledger = {
      schema: LEDGER_SCHEMA,
      padId,
      provenance,
      createdAt: new Date().toISOString(),
      totalBytes: raw.length,
      consumedBytes: 0,
      consumptionCount: 0,
      lastConsumedAt: null,
      sp80090bVerified: !!runSp80090b,
    };
    atomicWriteJson(ledgerPathFor(abs), ledger);
    return { padPath: abs, ledgerPath: ledgerPathFor(abs), ...ledger };
  } finally {
    raw.fill(0);
  }
}

export function inspectPadLedger(padPath) {
  const abs = path.resolve(padPath);
  const lp = ledgerPathFor(abs);
  if (!fs.existsSync(abs) || !fs.existsSync(lp)) {
    throw new Error(`Pad pool or ledger missing for ${abs}`);
  }
  const ledger = JSON.parse(fs.readFileSync(lp, 'utf8'));
  if (ledger.schema !== LEDGER_SCHEMA) {
    throw new Error(`Unsupported pad ledger schema: ${ledger.schema}`);
  }
  const st = fs.statSync(abs);
  if (st.size !== ledger.totalBytes) {
    throw new Error(`Pad file size drift detected (${st.size} != ${ledger.totalBytes}) — refusing tampered pad`);
  }
  const remainingBytes = ledger.totalBytes - ledger.consumedBytes;
  return {
    ...ledger,
    remainingBytes,
    pctRemaining: ledger.totalBytes > 0 ? Number(((remainingBytes / ledger.totalBytes) * 100).toFixed(2)) : 0,
  };
}

/**
 * Atomically consume `numBytes` of fresh One-Time Pad material at the current write-ahead offset.
 * Advances & fsyncs ledger BEFORE returning bytes AND shreds consumed slice on disk with zeros.
 */
export function consumePadSlice(padPath, numBytes, purpose = 'unspecified') {
  if (!Number.isInteger(numBytes) || numBytes <= 0 || numBytes > 16 * 1024 * 1024) {
    throw new Error(`Invalid pad slice size: ${numBytes}`);
  }
  const abs = path.resolve(padPath);
  return withExclusiveLock(abs, () => {
    const lp = ledgerPathFor(abs);
    if (!fs.existsSync(abs) || !fs.existsSync(lp)) {
      throw new Error(`Pad pool or ledger missing: ${abs}`);
    }
    const ledger = JSON.parse(fs.readFileSync(lp, 'utf8'));
    if (ledger.schema !== LEDGER_SCHEMA) throw new Error('Invalid pad ledger schema');
    const st = fs.statSync(abs);
    if (st.size !== ledger.totalBytes) {
      throw new Error(`Pad file size mismatch (${st.size} != ${ledger.totalBytes})`);
    }
    const offset = ledger.consumedBytes;
    if (!Number.isInteger(offset) || offset < 0 || offset + numBytes > ledger.totalBytes) {
      throw new Error(`One-Time Pad exhausted (requested=${numBytes}B, remaining=${ledger.totalBytes - offset}B)`);
    }

    const slice = Buffer.alloc(numBytes);
    const fd = fs.openSync(abs, 'r+');
    try {
      const nRead = fs.readSync(fd, slice, 0, numBytes, offset);
      if (nRead !== numBytes) throw new Error(`Short pad read (${nRead} != ${numBytes})`);

      // Refuse all-zero slice (defense against already-shredded / manually rolled-back ledger!)
      let orAll = 0;
      for (let i = 0; i < numBytes; i++) orAll |= slice[i];
      if (orAll === 0) {
        throw new Error(`PAD_REUSE_ALARM: slice at offset=${offset} is all-zero (ledger rollback or already shredded)!`);
      }

      // 1. WRITE-AHEAD COMMIT: persist incremented cursor BEFORE returning pad bytes
      ledger.consumedBytes = offset + numBytes;
      ledger.consumptionCount = (ledger.consumptionCount || 0) + 1;
      ledger.lastConsumedAt = new Date().toISOString();
      ledger.lastPurpose = String(purpose).slice(0, 64);
      atomicWriteJson(lp, ledger);

      // 2. IMMEDIATE PHYSICAL SHRED: overwrite consumed slice in pad file with zeros + fsync
      const zeros = Buffer.alloc(numBytes, 0);
      fs.writeSync(fd, zeros, 0, numBytes, offset);
      fs.fsyncSync(fd);
    } catch (err) {
      slice.fill(0);
      throw err;
    } finally {
      fs.closeSync(fd);
    }

    return {
      padId: ledger.padId,
      offset,
      length: numBytes,
      bytes: slice,
      remainingBytes: ledger.totalBytes - ledger.consumedBytes,
    };
  });
}

/**
 * Consume a specific (padId, offset, length) slice on the RECEIVER side for synchronized
 * pre-shared pad decryption (still shreds on-disk after reading and forbids double-consume
 * via an explicit consumed-ranges set in the receiver ledger!).
 */
export function consumePadAtOffset(padPath, expectedPadId, offset, numBytes) {
  if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(numBytes) || numBytes <= 0) {
    throw new Error('Invalid pad offset/length');
  }
  const abs = path.resolve(padPath);
  return withExclusiveLock(abs, () => {
    const lp = ledgerPathFor(abs);
    const ledger = JSON.parse(fs.readFileSync(lp, 'utf8'));
    if (ledger.schema !== LEDGER_SCHEMA) throw new Error('Invalid pad ledger schema');
    if (ledger.padId !== expectedPadId) {
      throw new Error(`Pad ID mismatch (expected=${expectedPadId}, local=${ledger.padId})`);
    }
    if (offset + numBytes > ledger.totalBytes) {
      throw new Error('Requested pad offset exceeds pool bounds');
    }
    const ranges = Array.isArray(ledger.consumedRanges) ? ledger.consumedRanges : [];
    for (const [a, b] of ranges) {
      if (offset < b && offset + numBytes > a) {
        throw new Error(`PAD_REUSE_ALARM: offset range [${offset}, ${offset + numBytes}) overlaps already-consumed [${a}, ${b})`);
      }
    }

    const slice = Buffer.alloc(numBytes);
    const fd = fs.openSync(abs, 'r+');
    try {
      const nRead = fs.readSync(fd, slice, 0, numBytes, offset);
      if (nRead !== numBytes) throw new Error('Short pad read');
      let orAll = 0;
      for (let i = 0; i < numBytes; i++) orAll |= slice[i];
      if (orAll === 0) {
        throw new Error(`PAD_REUSE_ALARM: receiver slice at offset=${offset} is already shredded!`);
      }
      ranges.push([offset, offset + numBytes]);
      ledger.consumedRanges = ranges;
      ledger.consumedBytes = Math.max(ledger.consumedBytes || 0, offset + numBytes);
      ledger.consumptionCount = (ledger.consumptionCount || 0) + 1;
      ledger.lastConsumedAt = new Date().toISOString();
      atomicWriteJson(lp, ledger);

      const zeros = Buffer.alloc(numBytes, 0);
      fs.writeSync(fd, zeros, 0, numBytes, offset);
      fs.fsyncSync(fd);
    } catch (err) {
      slice.fill(0);
      throw err;
    } finally {
      fs.closeSync(fd);
    }
    return slice;
  });
}
