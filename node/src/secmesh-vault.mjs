// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — Level 1 Paranoid Vault:
//   1. 6-Algorithm Composite Identity (Ed25519 + ML-DSA-65 + SLH-DSA-128s + X25519 + ML-KEM-768 + ML-KEM-1024)
//   2. Argon2id Memory-Hard Encrypted Keystore + Dual-AEAD Cascade (AES-256-GCM inner + ChaCha20-Poly1305 outer)
//   3. Byzantine Shamir (t, n >= t + 2b) Backup & Recovery of 256-bit Master Keys over F_{2^61 - 1}
//   4. 5-Layer "Invincible Onion Artichoke" File & Buffer Encryptor:
//        Layer 1: Fixed-4096B Bucket Padded Plaintext (zero compression, blocks CRIME/size leaks)
//        Layer 2: Triple-KEM Hybrid Ephemeral Wrap (X25519 + ML-KEM-768 + ML-KEM-1024 + optional PSI Pad)
//        Layer 3: Dual-AEAD Independent Cascade (AES-256-GCM + ChaCha20-Poly1305)
//        Layer 4: Optional Unconditional OTP Mask + Constant-Time C11 GF(2^128) Carter-Wegman IT-MAC
//        Layer 5: Composite Sender Signature (Ed25519 + ML-DSA-65 + SLH-DSA-128s) pinned to TrustStore

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { carterWegmanMac, carterWegmanVerify, dualSurvivabilityCombine } from './pqsi-handshake.mjs';
import { consumePadSlice, consumePadAtOffset } from './secmesh-pad-ledger.mjs';
import {
  computePublicBundleFingerprint,
  serializePublicBundle,
  deserializePublicBundle,
  compositeSignV3,
  compositeVerifyV3,
} from './secmesh-trust.mjs';

const KEYSTORE_SCHEMA = 'secmesh-pqsi/keystore-argon2id-cascade/v3';
const VAULT_MAGIC = Buffer.from('SMPQSI3\0', 'ascii'); // 8 bytes
const PADDING_BUCKET = 4096;

function atomicWriteBuffer(filePath, buf) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeSync(fd, buf, 0, buf.length, 0);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, filePath);
}

// ============================================================================
// 1. Dual-AEAD Cascade (AES-256-GCM inner + ChaCha20-Poly1305 outer)
//    Independent subkeys & nonces derived via SHAKE-256; survives break of EITHER cipher!
// ============================================================================
export function deriveCascadeKeys(master32, domainLabel) {
  if (!Buffer.isBuffer(master32) || master32.length < 32) {
    throw new Error('deriveCascadeKeys requires >= 32B master key');
  }
  const mat = crypto
    .createHash('shake256', { outputLength: 64 })
    .update(`SecMesh-PQSI-v3|CascadeKeys|${domainLabel}|`)
    .update(master32)
    .digest();
  const kAes = Buffer.from(mat.subarray(0, 32));
  const kChaCha = Buffer.from(mat.subarray(32, 64));
  mat.fill(0);
  return { kAes, kChaCha };
}

export function doubleAeadSeal(master32, plaintextBuf, aadBuf, domainLabel = 'record') {
  const { kAes, kChaCha } = deriveCascadeKeys(master32, domainLabel);
  const ivAes = crypto.randomBytes(12);
  const ivChaCha = crypto.randomBytes(12);
  let innerCt = null;
  try {
    // Inner Layer: AES-256-GCM (NIST FIPS 197 + SP 800-38D, strict 16-byte tag)
    const c1 = crypto.createCipheriv('aes-256-gcm', kAes, ivAes, { authTagLength: 16 });
    c1.setAAD(aadBuf);
    innerCt = Buffer.concat([c1.update(plaintextBuf), c1.final()]);
    const tagAes = c1.getAuthTag();

    // Outer Layer: ChaCha20-Poly1305 (RFC 8439, independent ARX cipher + 16-byte Poly1305 tag)
    const outerAad = Buffer.concat([aadBuf, ivAes, tagAes]);
    const c2 = crypto.createCipheriv('chacha20-poly1305', kChaCha, ivChaCha, { authTagLength: 16 });
    c2.setAAD(outerAad);
    const outerCt = Buffer.concat([c2.update(innerCt), c2.final()]);
    const tagChaCha = c2.getAuthTag();

    return { ivAes, tagAes, ivChaCha, tagChaCha, ciphertext: outerCt };
  } finally {
    kAes.fill(0);
    kChaCha.fill(0);
    if (innerCt) innerCt.fill(0);
  }
}

export function doubleAeadOpen(master32, sealed, aadBuf, domainLabel = 'record') {
  if (
    !sealed ||
    !Buffer.isBuffer(sealed.ivAes) || sealed.ivAes.length !== 12 ||
    !Buffer.isBuffer(sealed.tagAes) || sealed.tagAes.length !== 16 ||
    !Buffer.isBuffer(sealed.ivChaCha) || sealed.ivChaCha.length !== 12 ||
    !Buffer.isBuffer(sealed.tagChaCha) || sealed.tagChaCha.length !== 16 ||
    !Buffer.isBuffer(sealed.ciphertext)
  ) {
    throw new Error('Malformed double-AEAD envelope');
  }
  const { kAes, kChaCha } = deriveCascadeKeys(master32, domainLabel);
  let innerCt = null;
  try {
    // Peel Outer Layer first (ChaCha20-Poly1305)
    const outerAad = Buffer.concat([aadBuf, sealed.ivAes, sealed.tagAes]);
    const d2 = crypto.createDecipheriv('chacha20-poly1305', kChaCha, sealed.ivChaCha, { authTagLength: 16 });
    d2.setAAD(outerAad);
    d2.setAuthTag(sealed.tagChaCha);
    innerCt = Buffer.concat([d2.update(sealed.ciphertext), d2.final()]);

    // Peel Inner Layer (AES-256-GCM, strict 16-byte tag closing CWE-347)
    const d1 = crypto.createDecipheriv('aes-256-gcm', kAes, sealed.ivAes, { authTagLength: 16 });
    d1.setAAD(aadBuf);
    d1.setAuthTag(sealed.tagAes);
    return Buffer.concat([d1.update(innerCt), d1.final()]);
  } finally {
    kAes.fill(0);
    kChaCha.fill(0);
    if (innerCt) innerCt.fill(0);
  }
}

// ============================================================================
// 2. 6-Algorithm Composite Identity & Argon2id Encrypted Keystore
// ============================================================================
export function generateCompositeIdentityV3(nodeId, { latticeHedged = true } = {}) {
  if (!nodeId || typeof nodeId !== 'string' || nodeId.length > 128) {
    throw new Error('nodeId must be a non-empty string <= 128 chars');
  }
  const ed = crypto.generateKeyPairSync('ed25519');
  const mldsa = crypto.generateKeyPairSync('ml-dsa-65');
  const slhdsa = latticeHedged ? crypto.generateKeyPairSync('slh-dsa-sha2-128s') : null;
  const x25519 = crypto.generateKeyPairSync('x25519');
  const mlkem768 = crypto.generateKeyPairSync('ml-kem-768');
  const mlkem1024 = crypto.generateKeyPairSync('ml-kem-1024');

  const pub = {
    nodeId,
    ed25519Pub: ed.publicKey.export({ type: 'spki', format: 'der' }),
    mldsa65Pub: mldsa.publicKey.export({ type: 'spki', format: 'der' }),
    slhdsa128sPub: slhdsa ? slhdsa.publicKey.export({ type: 'spki', format: 'der' }) : null,
    x25519Pub: x25519.publicKey.export({ type: 'spki', format: 'der' }),
    mlkem768Pub: mlkem768.publicKey.export({ type: 'spki', format: 'der' }),
    mlkem1024Pub: mlkem1024.publicKey.export({ type: 'spki', format: 'der' }),
  };
  const fingerprint = computePublicBundleFingerprint(pub);
  pub.fingerprint = fingerprint;

  return {
    nodeId,
    fingerprint,
    latticeHedged,
    pub,
    priv: {
      ed25519: ed.privateKey,
      mldsa65: mldsa.privateKey,
      slhdsa128s: slhdsa ? slhdsa.privateKey : null,
      x25519: x25519.privateKey,
      mlkem768: mlkem768.privateKey,
      mlkem1024: mlkem1024.privateKey,
    },
  };
}

function deriveArgon2idKey(passphrase, salt, kdfParams) {
  const pw = Buffer.isBuffer(passphrase) ? passphrase : Buffer.from(String(passphrase), 'utf8');
  if (pw.length < 12) {
    throw new Error('Passphrase must be at least 12 characters');
  }
  return crypto.argon2Sync('argon2id', {
    message: pw,
    nonce: salt,
    parallelism: kdfParams.parallelism,
    tagLength: 32,
    memory: kdfParams.memoryKiB,
    passes: kdfParams.passes,
  });
}

export function saveEncryptedKeystore(keystorePath, identity, passphrase, {
  memoryKiB = 65536, // 64 MiB default (OWASP Argon2id production strength)
  passes = 3,
  parallelism = 4,
} = {}) {
  const salt = crypto.randomBytes(32);
  const kdfParams = { algorithm: 'argon2id', memoryKiB, passes, parallelism };
  const wrapKey = deriveArgon2idKey(passphrase, salt, kdfParams);
  const privPayload = Buffer.from(JSON.stringify({
    ed25519: identity.priv.ed25519.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    mldsa65: identity.priv.mldsa65.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    slhdsa128s: identity.priv.slhdsa128s
      ? identity.priv.slhdsa128s.export({ type: 'pkcs8', format: 'der' }).toString('base64')
      : null,
    x25519: identity.priv.x25519.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    mlkem768: identity.priv.mlkem768.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    mlkem1024: identity.priv.mlkem1024.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  }), 'utf8');

  const pubSerialized = serializePublicBundle(identity.pub);
  const aad = Buffer.from(`${KEYSTORE_SCHEMA}|${identity.nodeId}|${pubSerialized.fingerprint}`, 'utf8');
  try {
    const sealed = doubleAeadSeal(wrapKey, privPayload, aad, 'keystore');
    const doc = {
      schema: KEYSTORE_SCHEMA,
      createdAt: new Date().toISOString(),
      nodeId: identity.nodeId,
      fingerprint: pubSerialized.fingerprint,
      latticeHedged: !!identity.latticeHedged,
      kdf: { ...kdfParams, saltB64: salt.toString('base64') },
      pub: pubSerialized,
      encryptedPrivate: {
        ivAesB64: sealed.ivAes.toString('base64'),
        tagAesB64: sealed.tagAes.toString('base64'),
        ivChaChaB64: sealed.ivChaCha.toString('base64'),
        tagChaChaB64: sealed.tagChaCha.toString('base64'),
        ciphertextB64: sealed.ciphertext.toString('base64'),
      },
    };
    atomicWriteBuffer(path.resolve(keystorePath), Buffer.from(JSON.stringify(doc, null, 2) + '\n', 'utf8'));
    return { keystorePath: path.resolve(keystorePath), fingerprint: pubSerialized.fingerprint, pub: pubSerialized };
  } finally {
    wrapKey.fill(0);
    privPayload.fill(0);
  }
}

export function loadEncryptedKeystore(keystorePath, passphrase) {
  const doc = JSON.parse(fs.readFileSync(path.resolve(keystorePath), 'utf8'));
  if (doc.schema !== KEYSTORE_SCHEMA) throw new Error(`Unsupported keystore schema: ${doc.schema}`);
  const pub = deserializePublicBundle(doc.pub);
  if (pub.fingerprint !== doc.fingerprint) {
    throw new Error('Keystore public bundle fingerprint integrity check FAILED');
  }
  const salt = Buffer.from(doc.kdf.saltB64, 'base64');
  const wrapKey = deriveArgon2idKey(passphrase, salt, doc.kdf);
  const aad = Buffer.from(`${KEYSTORE_SCHEMA}|${doc.nodeId}|${doc.fingerprint}`, 'utf8');
  let rawPriv = null;
  try {
    rawPriv = doubleAeadOpen(wrapKey, {
      ivAes: Buffer.from(doc.encryptedPrivate.ivAesB64, 'base64'),
      tagAes: Buffer.from(doc.encryptedPrivate.tagAesB64, 'base64'),
      ivChaCha: Buffer.from(doc.encryptedPrivate.ivChaChaB64, 'base64'),
      tagChaCha: Buffer.from(doc.encryptedPrivate.tagChaChaB64, 'base64'),
      ciphertext: Buffer.from(doc.encryptedPrivate.ciphertextB64, 'base64'),
    }, aad, 'keystore');
    const p = JSON.parse(rawPriv.toString('utf8'));
    const mk = (b64) => (b64 ? crypto.createPrivateKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'pkcs8' }) : null);
    return {
      nodeId: doc.nodeId,
      fingerprint: doc.fingerprint,
      latticeHedged: !!doc.latticeHedged,
      pub,
      priv: {
        ed25519: mk(p.ed25519),
        mldsa65: mk(p.mldsa65),
        slhdsa128s: mk(p.slhdsa128s),
        x25519: mk(p.x25519),
        mlkem768: mk(p.mlkem768),
        mlkem1024: mk(p.mlkem1024),
      },
    };
  } finally {
    wrapKey.fill(0);
    if (rawPriv) rawPriv.fill(0);
  }
}

// ============================================================================
// 3. Byzantine Shamir (t, n >= t + 2b) Backup & Recovery of 256-bit Master Keys
//    Chunks 256 bits into five 52-bit limbs (< 2^61 - 1), enforcing Theorem T3a/T3b!
// ============================================================================
const SHAMIR_P = (1n << 61n) - 1n;

function fpMod(a) { return ((a % SHAMIR_P) + SHAMIR_P) % SHAMIR_P; }

function fpPow(base, exp) {
  let r = 1n, b = fpMod(base), e = exp;
  while (e > 0n) { if (e & 1n) r = fpMod(r * b); b = fpMod(b * b); e >>= 1n; }
  return r;
}

function randomFieldElem() {
  // Rejection sampling in [0, 2^61 - 2] (exact uniform over F_{2^61 - 1}, zero modulo bias)
  for (;;) {
    const raw = crypto.randomBytes(8).readBigUInt64BE(0) & SHAMIR_P;
    if (raw < SHAMIR_P) return raw;
  }
}

function shamirSplit(secret, threshold, numShares) {
  const coeffs = [fpMod(secret)];
  for (let i = 1; i < threshold; i++) coeffs.push(randomFieldElem());
  const out = [];
  for (let i = 1; i <= numShares; i++) {
    const x = BigInt(i);
    let y = 0n;
    for (let k = threshold - 1; k >= 0; k--) y = fpMod(y * x + coeffs[k]);
    out.push({ x, y });
  }
  return out;
}

function shamirEvalAt(pick, xTarget) {
  let sum = 0n;
  for (let i = 0; i < pick.length; i++) {
    let num = 1n, den = 1n;
    for (let j = 0; j < pick.length; j++) {
      if (i === j) continue;
      num = fpMod(num * fpMod(xTarget - pick[j].x));
      den = fpMod(den * fpMod(pick[i].x - pick[j].x));
    }
    sum = fpMod(sum + fpMod(pick[i].y * fpMod(num * fpPow(den, SHAMIR_P - 2n))));
  }
  return sum;
}

function splitBytes256ToLimbs52(buf32) {
  let acc = 0n;
  for (let i = 0; i < 32; i++) acc = (acc << 8n) | BigInt(buf32[i]);
  const limbs = [];
  const mask52 = (1n << 52n) - 1n;
  for (let i = 0; i < 5; i++) {
    limbs.push(acc & mask52);
    acc >>= 52n;
  }
  return limbs;
}

function limbs52ToBytes256(limbs) {
  let acc = 0n;
  for (let i = 4; i >= 0; i--) acc = (acc << 52n) | limbs[i];
  const out = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(acc & 0xFFn);
    acc >>= 8n;
  }
  return out;
}

export function splitKey256Byzantine(key32, { threshold = 3, numShares = 7, maxByzantine = 2 } = {}) {
  if (!Buffer.isBuffer(key32) || key32.length !== 32) throw new Error('key32 must be 32 bytes');
  if (numShares < threshold + 2 * maxByzantine) {
    throw new Error(`Theorem T3b violation: need n >= t + 2b (${numShares} < ${threshold + 2 * maxByzantine})`);
  }
  const limbs = splitBytes256ToLimbs52(key32);
  const perLimb = limbs.map((limb) => shamirSplit(limb, threshold, numShares));
  const shares = [];
  for (let s = 0; s < numShares; s++) {
    shares.push({
      schema: 'secmesh-pqsi/shamir-backup-share/v3',
      index: s + 1,
      threshold,
      numShares,
      maxByzantine,
      x: perLimb[0][s].x.toString(),
      limbsY: perLimb.map((arr) => arr[s].y.toString()),
    });
  }
  return shares;
}

function reconstructLimbByzantine(pts, t, b) {
  const n = pts.length;
  if (n < t + 2 * b) throw new Error('Insufficient shares for Byzantine recovery');
  // Combinatorial subset search over C(n, t) checking consistency with >= t + b shares (Theorem T3b)
  const pick = [];
  let recovered = null;
  let steps = 0;
  function dfs(start) {
    if (recovered !== null || ++steps > 100000) return;
    if (pick.length === t) {
      const badIndices = [];
      for (let k = 0; k < n; k++) {
        if (shamirEvalAt(pick, pts[k].x) !== pts[k].y) badIndices.push(k);
      }
      if (n - badIndices.length >= t + b) {
        recovered = { secret: shamirEvalAt(pick, 0n), badIndices };
      }
      return;
    }
    for (let i = start; i <= n - (t - pick.length); i++) {
      pick.push(pts[i]);
      dfs(i + 1);
      pick.pop();
      if (recovered !== null) return;
    }
  }
  dfs(0);
  if (recovered === null) throw new Error('Byzantine Shamir reconstruction failed (> b corrupted shares)');
  return recovered;
}

export function recoverKey256Byzantine(shares) {
  if (!Array.isArray(shares) || shares.length === 0) throw new Error('Shares array required');
  const { threshold: t, maxByzantine: b } = shares[0];
  const seenX = new Set();
  for (const sh of shares) {
    if (seenX.has(sh.x)) throw new Error(`Duplicate Shamir x=${sh.x} rejected (Theorem T3b guard)`);
    seenX.add(sh.x);
  }
  const limbs = [];
  const allBad = new Set();
  for (let l = 0; l < 5; l++) {
    const pts = shares.map((sh) => ({ x: BigInt(sh.x), y: BigInt(sh.limbsY[l]) }));
    const res = reconstructLimbByzantine(pts, t, b);
    limbs.push(res.secret);
    for (const idx of res.badIndices) allBad.add(idx);
  }
  return { key32: limbs52ToBytes256(limbs), corruptedDetected: allBad.size };
}

// ============================================================================
// 4. 5-Layer "Invincible Onion Artichoke" File & Buffer Encryptor
// ============================================================================
function padToBucket(plainBuf, bucket = PADDING_BUCKET) {
  const lenHdr = Buffer.alloc(4);
  lenHdr.writeUInt32BE(plainBuf.length, 0);
  const rawLen = 4 + plainBuf.length;
  const target = Math.max(bucket, Math.ceil(rawLen / bucket) * bucket);
  const pad = crypto.randomBytes(target - rawLen);
  return Buffer.concat([lenHdr, plainBuf, pad]);
}

function unpadFromBucket(paddedBuf) {
  if (!Buffer.isBuffer(paddedBuf) || paddedBuf.length < 4) throw new Error('Corrupt padded payload');
  const realLen = paddedBuf.readUInt32BE(0);
  if (realLen > paddedBuf.length - 4) throw new Error('Invalid padded length header');
  return Buffer.from(paddedBuf.subarray(4, 4 + realLen));
}

export async function encryptArtichokeBuffer(plaintextBuf, {
  senderIdentity,
  recipientPub,
  padPoolPath = null,
  ctCoprocessor = null,
}) {
  const plain = Buffer.isBuffer(plaintextBuf) ? plaintextBuf : Buffer.from(plaintextBuf);
  const recPub = deserializePublicBundle(recipientPub);

  // Layer 1: Fixed-4096B bucket padding (zero compression -> CRIME/length-leak resistant)
  const paddedPlain = padToBucket(plain);

  // Layer 2: Triple-KEM Ephemeral Hybrid Wrapping (X25519 + ML-KEM-768 + ML-KEM-1024)
  const ephX = crypto.generateKeyPairSync('x25519');
  const recXKey = crypto.createPublicKey({ key: recPub.x25519Pub, format: 'der', type: 'spki' });
  const recKem768Key = crypto.createPublicKey({ key: recPub.mlkem768Pub, format: 'der', type: 'spki' });
  const recKem1024Key = crypto.createPublicKey({ key: recPub.mlkem1024Pub, format: 'der', type: 'spki' });

  const ssX = crypto.diffieHellman({ privateKey: ephX.privateKey, publicKey: recXKey });
  const enc768 = crypto.encapsulate(recKem768Key);
  const enc1024 = crypto.encapsulate(recKem1024Key);
  const ephXPubDer = ephX.publicKey.export({ type: 'spki', format: 'der' });

  // Optional PSI Pad Consumption (write-ahead crash-safe + immediate on-disk shred!)
  // Consumes: 32B IT key combiner + 16B CW-r + 16B CW-padB + paddedPlain.length OTP bytes
  let padSlice = null;
  let psiMeta = null;
  if (padPoolPath) {
    const need = 32 + 16 + 16 + paddedPlain.length;
    padSlice = consumePadSlice(padPoolPath, need, `artichoke-encrypt:${recPub.nodeId}`);
    psiMeta = { padId: padSlice.padId, offset: padSlice.offset, length: padSlice.length };
  }

  const headerObj = {
    schema: 'secmesh-pqsi/artichoke-vault/v3',
    senderNodeId: senderIdentity.nodeId,
    senderFingerprint: computePublicBundleFingerprint(senderIdentity.pub),
    recipientNodeId: recPub.nodeId,
    recipientFingerprint: recPub.fingerprint,
    ephX25519PubB64: ephXPubDer.toString('base64'),
    ctMlKem768B64: enc768.ciphertext.toString('base64'),
    ctMlKem1024B64: enc1024.ciphertext.toString('base64'),
    psiPad: psiMeta,
    bucketBytes: paddedPlain.length,
  };
  const headerBytes = Buffer.from(JSON.stringify(headerObj), 'utf8');

  // Dual-Survivability Combiner (Theorem T2b): SHAKE256(Triple-KEM || header) XOR K_it_opt
  const kPqConcat = Buffer.concat([ssX, enc768.sharedKey, enc1024.sharedKey]);
  const kItOpt = padSlice ? padSlice.bytes.subarray(0, 32) : null;
  let masterKey = null;
  try {
    if (ctCoprocessor) {
      masterKey = await ctCoprocessor.hybridCombine(kPqConcat, kItOpt, headerBytes);
    } else {
      masterKey = dualSurvivabilityCombine({
        kX25519: ssX,
        kMlKem: Buffer.concat([enc768.sharedKey, enc1024.sharedKey]),
        kItOpt,
        transcriptBuf: headerBytes,
      });
    }

    // Layer 3: Dual-AEAD Independent Cascade (AES-256-GCM inner + ChaCha20-Poly1305 outer)
    const sealed = doubleAeadSeal(masterKey, paddedPlain, headerBytes, 'artichoke-body');

    // Layer 4: Optional Unconditional OTP Mask + Constant-Time C11 GF(2^128) Carter-Wegman IT-MAC
    let bodyBytes = sealed.ciphertext;
    let cwTag = Buffer.alloc(0);
    if (padSlice) {
      const cwR = padSlice.bytes.subarray(32, 48);
      const cwB = padSlice.bytes.subarray(48, 64);
      const otp = padSlice.bytes.subarray(64, 64 + paddedPlain.length);
      const masked = Buffer.alloc(bodyBytes.length);
      for (let i = 0; i < bodyBytes.length; i++) masked[i] = bodyBytes[i] ^ otp[i];
      bodyBytes = masked;
      const macInput = Buffer.concat([headerBytes, sealed.ivAes, sealed.tagAes, sealed.ivChaCha, sealed.tagChaCha, bodyBytes]);
      cwTag = ctCoprocessor
        ? await ctCoprocessor.carterWegmanMac(cwR, cwB, macInput)
        : carterWegmanMac(cwR, cwB, macInput);
    }

    // Layer 5: Full Composite Sender Signature (Ed25519 + ML-DSA-65 + SLH-DSA-128s)
    const envDigest = crypto
      .createHash('sha3-256')
      .update('SecMesh-PQSI-v3|ArtichokeSig|')
      .update(headerBytes)
      .update(sealed.ivAes).update(sealed.tagAes)
      .update(sealed.ivChaCha).update(sealed.tagChaCha)
      .update(cwTag).update(bodyBytes)
      .digest();
    const sigs = compositeSignV3(senderIdentity, envDigest);
    const metaJson = Buffer.from(JSON.stringify({
      header: headerObj,
      ivAesB64: sealed.ivAes.toString('base64'),
      tagAesB64: sealed.tagAes.toString('base64'),
      ivChaChaB64: sealed.ivChaCha.toString('base64'),
      tagChaChaB64: sealed.tagChaCha.toString('base64'),
      cwTagB64: cwTag.length ? cwTag.toString('base64') : null,
      sigs,
    }), 'utf8');

    const metaLen = Buffer.alloc(4);
    metaLen.writeUInt32BE(metaJson.length, 0);
    return {
      envelope: Buffer.concat([VAULT_MAGIC, metaLen, metaJson, bodyBytes]),
      securityTier: padSlice ? 'ARTICHOKE_5LAYER_TRIPLE_KEM_CASCADE_OTP_CW128' : 'ARTICHOKE_4LAYER_TRIPLE_KEM_CASCADE_PQ',
      bucketBytes: paddedPlain.length,
    };
  } finally {
    ssX.fill(0);
    enc768.sharedKey.fill(0);
    enc1024.sharedKey.fill(0);
    kPqConcat.fill(0);
    paddedPlain.fill(0);
    if (masterKey) masterKey.fill(0);
    if (padSlice) padSlice.bytes.fill(0);
  }
}

export async function decryptArtichokeBuffer(envelopeBuf, {
  recipientIdentity,
  trustStore,
  padPoolPath = null,
  ctCoprocessor = null,
}) {
  if (!Buffer.isBuffer(envelopeBuf) || envelopeBuf.length < 16 || !envelopeBuf.subarray(0, 8).equals(VAULT_MAGIC)) {
    throw new Error('Invalid SecMesh-PQSI v3 Artichoke magic header');
  }
  const metaLen = envelopeBuf.readUInt32BE(8);
  if (metaLen === 0 || 12 + metaLen > envelopeBuf.length) throw new Error('Corrupt envelope metadata length');
  const meta = JSON.parse(envelopeBuf.subarray(12, 12 + metaLen).toString('utf8'));
  const bodyBytes = envelopeBuf.subarray(12 + metaLen);
  const headerObj = meta.header;
  const headerBytes = Buffer.from(JSON.stringify(headerObj), 'utf8');

  // Verify recipient binding
  const myFp = computePublicBundleFingerprint(recipientIdentity.pub);
  if (headerObj.recipientFingerprint !== myFp) {
    throw new Error('Envelope was not encrypted for this recipient identity');
  }

  // Layer 5 Verification FIRST (fail-closed before decrypting): pinned TrustStore + Composite PQ Signature!
  const pinnedSender = trustStore.getPeer(headerObj.senderNodeId);
  if (!pinnedSender || pinnedSender.fingerprint !== headerObj.senderFingerprint) {
    throw new Error(`UNTRUSTED_OR_REVOKED_SENDER: ${headerObj.senderNodeId}`);
  }
  const ivAes = Buffer.from(meta.ivAesB64, 'base64');
  const tagAes = Buffer.from(meta.tagAesB64, 'base64');
  const ivChaCha = Buffer.from(meta.ivChaChaB64, 'base64');
  const tagChaCha = Buffer.from(meta.tagChaChaB64, 'base64');
  const cwTag = meta.cwTagB64 ? Buffer.from(meta.cwTagB64, 'base64') : Buffer.alloc(0);

  const envDigest = crypto
    .createHash('sha3-256')
    .update('SecMesh-PQSI-v3|ArtichokeSig|')
    .update(headerBytes)
    .update(ivAes).update(tagAes)
    .update(ivChaCha).update(tagChaCha)
    .update(cwTag).update(bodyBytes)
    .digest();
  if (!compositeVerifyV3(pinnedSender, envDigest, meta.sigs)) {
    throw new Error('COMPOSITE_SENDER_SIGNATURE_INVALID (Ed25519/ML-DSA-65/SLH-DSA-128s)');
  }

  // Layer 4: If PSI Pad used, atomically consume matching offset (and shred) + verify CW-128 IT-MAC BEFORE AEAD!
  let padBytes = null;
  let cipherBody = bodyBytes;
  if (headerObj.psiPad) {
    if (!padPoolPath) throw new Error('Envelope requires SECMESH_IT_PAD_FILE for PSI decryption');
    if (cwTag.length !== 16) throw new Error('Missing 16-byte Carter-Wegman IT-MAC');
    padBytes = consumePadAtOffset(padPoolPath, headerObj.psiPad.padId, headerObj.psiPad.offset, headerObj.psiPad.length);
  }

  let ssX = null, ss768 = null, ss1024 = null, kPqConcat = null, masterKey = null, paddedPlain = null;
  try {
    if (padBytes) {
      const cwR = padBytes.subarray(32, 48);
      const cwB = padBytes.subarray(48, 64);
      const otp = padBytes.subarray(64, 64 + bodyBytes.length);
      const macInput = Buffer.concat([headerBytes, ivAes, tagAes, ivChaCha, tagChaCha, bodyBytes]);
      const cwOk = ctCoprocessor
        ? await ctCoprocessor.carterWegmanVerify(cwTag, cwR, cwB, macInput)
        : carterWegmanVerify(cwTag, cwR, cwB, macInput);
      if (!cwOk) throw new Error('CARTER_WEGMAN_IT_MAC_REJECTED');
      const unmasked = Buffer.alloc(bodyBytes.length);
      for (let i = 0; i < bodyBytes.length; i++) unmasked[i] = bodyBytes[i] ^ otp[i];
      cipherBody = unmasked;
    }

    // Layer 2: Triple-KEM Decapsulation (X25519 + ML-KEM-768 + ML-KEM-1024)
    const ephXPub = crypto.createPublicKey({ key: Buffer.from(headerObj.ephX25519PubB64, 'base64'), format: 'der', type: 'spki' });
    ssX = crypto.diffieHellman({ privateKey: recipientIdentity.priv.x25519, publicKey: ephXPub });
    ss768 = crypto.decapsulate(recipientIdentity.priv.mlkem768, Buffer.from(headerObj.ctMlKem768B64, 'base64'));
    ss1024 = crypto.decapsulate(recipientIdentity.priv.mlkem1024, Buffer.from(headerObj.ctMlKem1024B64, 'base64'));

    kPqConcat = Buffer.concat([ssX, ss768, ss1024]);
    const kItOpt = padBytes ? padBytes.subarray(0, 32) : null;
    if (ctCoprocessor) {
      masterKey = await ctCoprocessor.hybridCombine(kPqConcat, kItOpt, headerBytes);
    } else {
      masterKey = dualSurvivabilityCombine({
        kX25519: ssX,
        kMlKem: Buffer.concat([ss768, ss1024]),
        kItOpt,
        transcriptBuf: headerBytes,
      });
    }

    // Layer 3: Peel Dual-AEAD Cascade (ChaCha20-Poly1305 outer -> AES-256-GCM inner)
    paddedPlain = doubleAeadOpen(masterKey, {
      ivAes, tagAes, ivChaCha, tagChaCha, ciphertext: cipherBody,
    }, headerBytes, 'artichoke-body');

    // Layer 1: Strip fixed-bucket padding
    return {
      plaintext: unpadFromBucket(paddedPlain),
      senderNodeId: headerObj.senderNodeId,
      senderFingerprint: headerObj.senderFingerprint,
      psiVerified: !!padBytes,
    };
  } finally {
    if (ssX) ssX.fill(0);
    if (ss768) ss768.fill(0);
    if (ss1024) ss1024.fill(0);
    if (kPqConcat) kPqConcat.fill(0);
    if (masterKey) masterKey.fill(0);
    if (paddedPlain) paddedPlain.fill(0);
    if (padBytes) padBytes.fill(0);
    if (cipherBody !== bodyBytes) cipherBody.fill(0);
  }
}

export async function encryptArtichokeFile(inPath, outPath, opts) {
  const plain = fs.readFileSync(path.resolve(inPath));
  try {
    const res = await encryptArtichokeBuffer(plain, opts);
    atomicWriteBuffer(path.resolve(outPath), res.envelope);
    return { outPath: path.resolve(outPath), bytes: res.envelope.length, securityTier: res.securityTier };
  } finally {
    plain.fill(0);
  }
}

export async function decryptArtichokeFile(inPath, outPath, opts) {
  const env = fs.readFileSync(path.resolve(inPath));
  const res = await decryptArtichokeBuffer(env, opts);
  try {
    atomicWriteBuffer(path.resolve(outPath), res.plaintext);
    return { outPath: path.resolve(outPath), bytes: res.plaintext.length, senderNodeId: res.senderNodeId, psiVerified: res.psiVerified };
  } finally {
    res.plaintext.fill(0);
  }
}
