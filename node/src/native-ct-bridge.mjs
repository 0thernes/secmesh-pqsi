// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — Persistent Constant-Time C11 Crypto Coprocessor Bridge
// Offloads GF(2^128), Carter-Wegman IT-MAC, Dual-Survivability Hybrid Combine,
// FIPS 203 ML-KEM-768 encaps, and SP 800-90B entropy audits into the compiled,
// branchless, VirtualLock/mlock-hardened C11 binary (`native/build/secmesh_core ct-worker`),
// eliminating JS BigInt timing side-channels and V8 heap retention.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

export function resolveNativeCoreBinary() {
  const exe = process.platform === 'win32' ? 'secmesh_core.exe' : 'secmesh_core';
  return path.join(REPO_ROOT, 'native', 'build', exe);
}

export class NativeCtCoprocessor {
  constructor(binaryPath = resolveNativeCoreBinary()) {
    this.binaryPath = binaryPath;
    this.proc = null;
    this.rl = null;
    this.queue = [];
    this.closed = false;
  }

  start() {
    if (this.proc) return this;
    if (!fs.existsSync(this.binaryPath)) {
      throw new Error(`Native C11 binary not found at ${this.binaryPath}; run 'make -C native all'`);
    }
    this.closed = false;
    this.proc = spawn(this.binaryPath, ['ct-worker'], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    this.rl = readline.createInterface({ input: this.proc.stdout, crlfDelay: Infinity });
    this.rl.on('line', (line) => {
      const next = this.queue.shift();
      if (!next) return;
      try {
        next.resolve(JSON.parse(line));
      } catch (err) {
        next.reject(new Error(`Malformed C11 ct-worker JSON: ${err.message}`));
      }
    });
    this.proc.on('exit', (code) => {
      this.proc = null;
      if (this.rl) { this.rl.close(); this.rl = null; }
      while (this.queue.length > 0) {
        this.queue.shift().reject(new Error(`C11 ct-worker exited unexpectedly (code=${code})`));
      }
    });
    this.proc.on('error', (err) => {
      while (this.queue.length > 0) this.queue.shift().reject(err);
    });
    return this;
  }

  _send(cmdLine) {
    if (this.closed) return Promise.reject(new Error('NativeCtCoprocessor is closed'));
    if (!this.proc) this.start();
    return new Promise((resolve, reject) => {
      this.queue.push({ resolve, reject });
      this.proc.stdin.write(cmdLine + '\n');
    });
  }

  async ping() {
    const res = await this._send('PING');
    if (!res.ok) throw new Error(`C11 ct-worker ping failed: ${res.error}`);
    return res;
  }

  async gf128Mul(aBuf, bBuf) {
    if (!Buffer.isBuffer(aBuf) || aBuf.length !== 16 || !Buffer.isBuffer(bBuf) || bBuf.length !== 16) {
      throw new Error('gf128Mul requires two 16-byte Buffers');
    }
    const res = await this._send(`GF128 ${aBuf.toString('hex')} ${bBuf.toString('hex')}`);
    if (!res.ok) throw new Error(`C11 GF128 failed: ${res.error}`);
    return Buffer.from(res.out_hex, 'hex');
  }

  async carterWegmanMac(rBuf, padBBuf, msgBuf) {
    if (!Buffer.isBuffer(rBuf) || rBuf.length !== 16 || !Buffer.isBuffer(padBBuf) || padBBuf.length !== 16) {
      throw new Error('carterWegmanMac requires 16-byte rBuf and padBBuf');
    }
    const msg = Buffer.isBuffer(msgBuf) ? msgBuf : Buffer.from(msgBuf);
    const mHex = msg.length === 0 ? '-' : msg.toString('hex');
    const res = await this._send(`CW_MAC ${rBuf.toString('hex')} ${padBBuf.toString('hex')} ${mHex}`);
    if (!res.ok) throw new Error(`C11 CW_MAC failed: ${res.error}`);
    return Buffer.from(res.tag_hex, 'hex');
  }

  async carterWegmanVerify(tagBuf, rBuf, padBBuf, msgBuf) {
    if (!Buffer.isBuffer(tagBuf) || tagBuf.length !== 16) return false;
    if (!Buffer.isBuffer(rBuf) || rBuf.length !== 16 || !Buffer.isBuffer(padBBuf) || padBBuf.length !== 16) {
      return false;
    }
    const msg = Buffer.isBuffer(msgBuf) ? msgBuf : Buffer.from(msgBuf);
    const mHex = msg.length === 0 ? '-' : msg.toString('hex');
    const res = await this._send(
      `CW_VERIFY ${tagBuf.toString('hex')} ${rBuf.toString('hex')} ${padBBuf.toString('hex')} ${mHex}`,
    );
    return !!(res.ok && res.valid === true);
  }

  async hybridCombine(kPqBuf, kItOptBuf, transcriptBuf) {
    if (!Buffer.isBuffer(kPqBuf) || kPqBuf.length === 0) throw new Error('kPqBuf required');
    if (kItOptBuf !== null && (!Buffer.isBuffer(kItOptBuf) || kItOptBuf.length !== 32)) {
      throw new Error('kItOptBuf must be null or 32-byte Buffer');
    }
    const itHex = kItOptBuf ? kItOptBuf.toString('hex') : '-';
    const trHex = transcriptBuf && transcriptBuf.length > 0 ? transcriptBuf.toString('hex') : '-';
    const res = await this._send(`HYBRID ${kPqBuf.toString('hex')} ${itHex} ${trHex}`);
    if (!res.ok) throw new Error(`C11 HYBRID failed: ${res.error}`);
    return Buffer.from(res.key_hex, 'hex');
  }

  async mlkem768Encaps(rawEkBuf, seedMBuf) {
    if (!Buffer.isBuffer(rawEkBuf) || rawEkBuf.length !== 1184) {
      throw new Error('ML-KEM-768 raw ek must be 1184 bytes');
    }
    if (!Buffer.isBuffer(seedMBuf) || seedMBuf.length !== 32) {
      throw new Error('ML-KEM-768 seed m must be 32 bytes');
    }
    const res = await this._send(`MLKEM_ENCAPS ${rawEkBuf.toString('hex')} ${seedMBuf.toString('hex')}`);
    if (!res.ok) throw new Error(`C11 MLKEM_ENCAPS failed: ${res.error}`);
    return {
      ciphertext: Buffer.from(res.ct_hex, 'hex'),
      sharedSecret: Buffer.from(res.ss_hex, 'hex'),
    };
  }

  async sp80090bAudit(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 512) {
      return { ok: false, passed: false, reason: 'need_512_bytes' };
    }
    const res = await this._send(`SP80090B ${buf.toString('hex')}`);
    return { ok: !!res.ok, passed: !!(res.ok && res.passed), bytes: res.bytes || 0 };
  }

  async close() {
    if (this.closed) return;
    if (this.proc) {
      try { await this._send('QUIT'); } catch { /* exiting */ }
    }
    this.closed = true;
    if (this.proc) {
      try { this.proc.kill(); } catch { /* already dead */ }
      this.proc = null;
    }
  }
}

export function createCtCoprocessor(binaryPath) {
  return new NativeCtCoprocessor(binaryPath).start();
}
