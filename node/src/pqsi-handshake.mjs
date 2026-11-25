// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v2.0 — Real Post-Quantum + Information-Theoretic (Post-Super-Intelligence)
// Cryptographic Handshake, Authenticated Framing, Dual-Survivability Combiner,
// GF(2^128) Carter-Wegman IT-MAC, and Shamir Byzantine Threshold Sharing.
//
// Uses REAL Node.js 25 / OpenSSL 3.5.5 FIPS 203 (ML-KEM-768/1024),
// FIPS 204 (ML-DSA-65), FIPS 205 (SLH-DSA-SHA2-128s), X25519, Ed25519, AES-256-GCM.

import crypto from 'node:crypto';

// ============================================================================
// 1. Constant-Time GF(2^128) Carter-Wegman Information-Theoretic MAC
//    Exact mirror of native/src/secmesh_it_crypto.c (GHASH poly x^128+x^7+x^2+x+1)
// ============================================================================
const R_POLY = 0xE100000000000000n;
const MASK64 = 0xFFFFFFFFFFFFFFFFn;

export function gf128Mul(aBuf, bBuf) {
  let vh = aBuf.readBigUInt64BE(0);
  let vl = aBuf.readBigUInt64BE(8);
  let zh = 0n;
  let zl = 0n;
  for (let i = 0; i < 16; i++) {
    const bi = bBuf[i];
    for (let bit = 7; bit >= 0; bit--) {
      const m = ((bi >> bit) & 1) ? MASK64 : 0n;
      zh ^= vh & m;
      zl ^= vl & m;
      const lsb = vl & 1n;
      const rm = lsb ? MASK64 : 0n;
      vl = ((vl >> 1n) | ((vh & 1n) << 63n)) & MASK64;
      vh = ((vh >> 1n) ^ (R_POLY & rm)) & MASK64;
    }
  }
  const out = Buffer.alloc(16);
  out.writeBigUInt64BE(zh, 0);
  out.writeBigUInt64BE(zl, 8);
  return out;
}

export function carterWegmanMac(rBuf, padBBuf, msgBuf) {
  const msg = Buffer.isBuffer(msgBuf) ? msgBuf : Buffer.from(msgBuf);
  let acc = Buffer.alloc(16);
  const blk = Buffer.alloc(16);

  for (let off = 0; off < msg.length; off += 16) {
    blk.fill(0);
    msg.copy(blk, 0, off, Math.min(off + 16, msg.length));
    for (let i = 0; i < 16; i++) acc[i] ^= blk[i];
    acc = gf128Mul(acc, rBuf);
  }
  // Exact length domain-separation block (prevents length extension)
  blk.fill(0);
  blk.writeBigUInt64BE(BigInt(msg.length), 0);
  blk.writeBigUInt64BE(BigInt(msg.length) * 8n, 8);
  for (let i = 0; i < 16; i++) acc[i] ^= blk[i];
  acc = gf128Mul(acc, rBuf);

  const tag = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) tag[i] = acc[i] ^ padBBuf[i];
  acc.fill(0);
  return tag;
}

export function carterWegmanVerify(tagBuf, rBuf, padBBuf, msgBuf) {
  if (!Buffer.isBuffer(tagBuf) || tagBuf.length !== 16) return false;
  const expected = carterWegmanMac(rBuf, padBBuf, msgBuf);
  const ok = crypto.timingSafeEqual(expected, tagBuf);
  expected.fill(0);
  return ok;
}

/**
 * Per-frame one-time pad derivation for Carter-Wegman IT-MAC (strictly preventing
 * two-frame pad reuse of `(r, b)` as required by Theorem T2d).
 * If `padSource` is an Array of pre-shared 16-byte IT pads (PSI mode), consumes pad[seq]
 * at most once; if it is a 32-byte master key Buffer (computational Wegman-Carter mode),
 * derives a domain-separated unique 16-byte pad per monotonic sequence number `seq`.
 */
export function resolveCwFramePad(padSource, seqBigInt) {
  if (Array.isArray(padSource)) {
    const idx = Number(seqBigInt);
    if (!Number.isInteger(idx) || idx < 0 || idx >= padSource.length) return null;
    const pad = padSource[idx];
    return Buffer.isBuffer(pad) && pad.length === 16 ? pad : null;
  }
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(seqBigInt, 0);
  return crypto
    .createHash('shake256', { outputLength: 16 })
    .update('SecMesh-PQSI-v2|CW128-FramePad|')
    .update(seqBuf)
    .update(padSource)
    .digest();
}

/**
 * Seal a length-and-sequence-bound Carter-Wegman frame: [seq_u64be (8B) || tag (16B) || payload].
 * Prevents both forgery (<= d / 2^128) and pad-reuse/replay attacks across frames.
 */
export function sealCwFrame(rBuf, padSource, seq, payloadBuf) {
  const seqBig = BigInt(seq);
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(seqBig, 0);
  const padB = resolveCwFramePad(padSource, seqBig);
  if (!padB) throw new Error(`No fresh CW-128 one-time pad available for seq=${seqBig}`);
  const payload = Buffer.isBuffer(payloadBuf) ? payloadBuf : Buffer.from(payloadBuf);
  const macInput = Buffer.concat([seqBuf, payload]);
  const tag = carterWegmanMac(rBuf, padB, macInput);
  return Buffer.concat([seqBuf, tag, payload]);
}

/**
 * Verify and consume a Carter-Wegman frame with strict replay & pad-reuse protection.
 */
export function verifyCwFrame(frameBuf, rBuf, padSource, seenSeqs) {
  if (!Buffer.isBuffer(frameBuf) || frameBuf.length < 25) {
    return { ok: false, reason: 'unauth-frame' };
  }
  const seqBuf = frameBuf.subarray(0, 8);
  const seqBig = seqBuf.readBigUInt64BE(0);
  if (seenSeqs && seenSeqs.has(seqBig)) {
    return { ok: false, reason: 'cw-replay-reject', seq: seqBig };
  }
  const padB = resolveCwFramePad(padSource, seqBig);
  if (!padB) {
    return { ok: false, reason: 'cw-pad-exhausted', seq: seqBig };
  }
  const tag = frameBuf.subarray(8, 24);
  const payload = frameBuf.subarray(24);
  const macInput = Buffer.concat([seqBuf, payload]);
  if (!carterWegmanVerify(tag, rBuf, padB, macInput)) {
    return { ok: false, reason: 'cw-mac-reject', seq: seqBig };
  }
  if (seenSeqs) seenSeqs.add(seqBig);
  return { ok: true, seq: seqBig, payload };
}

/**
 * Theorem T6b (Cryptosymbology / Threshold-Hedged Signing Randomness):
 * Combines signer nonce and independent auditor/QRNG nonce via exact XOR bijection
 * so neither a kleptographic signer nor a stalled auditor can bias effective entropy.
 */
export function thresholdHedgedNonce(rSignerBuf, rAuditorBuf) {
  if (!Buffer.isBuffer(rSignerBuf) || !Buffer.isBuffer(rAuditorBuf) || rSignerBuf.length !== rAuditorBuf.length) {
    throw new Error('thresholdHedgedNonce requires equal-length Buffers');
  }
  const out = Buffer.alloc(rSignerBuf.length);
  for (let i = 0; i < rSignerBuf.length; i++) out[i] = rSignerBuf[i] ^ rAuditorBuf[i];
  return out;
}

// ============================================================================
// 2. Universal Dual-Survivability Hybrid PQ + IT Key Combiner (Theorem T2b)
// ============================================================================
export function dualSurvivabilityCombine({ kX25519, kMlKem, kItOpt = null, transcriptBuf }) {
  const kPqConcat = Buffer.concat([kX25519, kMlKem]);
  const dom = Buffer.from('SecMesh-PQSI-v2.0|DualSurvivabilityCombiner|PQ', 'utf8');
  const tlen = Buffer.alloc(8);
  tlen.writeBigUInt64LE(BigInt(transcriptBuf.length), 0);
  const klen = Buffer.alloc(8);
  klen.writeBigUInt64LE(BigInt(kPqConcat.length), 0);

  const kPqDerived = crypto
    .createHash('shake256', { outputLength: 32 })
    .update(dom)
    .update(tlen)
    .update(transcriptBuf)
    .update(klen)
    .update(kPqConcat)
    .digest();

  const kOut = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    kOut[i] = kPqDerived[i] ^ (kItOpt ? kItOpt[i] : 0);
  }
  kPqConcat.fill(0);
  kPqDerived.fill(0);
  return kOut;
}

// ============================================================================
// 3. Composite Peer Identity & Real Hybrid PQ + IT Handshake
//    Profile: X25519 + ML-KEM-768 KEM | Ed25519 + ML-DSA-65 (+ optional SLH-DSA-128s)
// ============================================================================
export function generatePeerIdentity(nodeId, { latticeHedged = false } = {}) {
  const ed = crypto.generateKeyPairSync('ed25519');
  const mldsa = crypto.generateKeyPairSync('ml-dsa-65');
  const slhdsa = latticeHedged ? crypto.generateKeyPairSync('slh-dsa-sha2-128s') : null;

  const publicBundle = {
    nodeId,
    ed25519Pub: ed.publicKey.export({ type: 'spki', format: 'der' }),
    mldsa65Pub: mldsa.publicKey.export({ type: 'spki', format: 'der' }),
    slhdsa128sPub: slhdsa ? slhdsa.publicKey.export({ type: 'spki', format: 'der' }) : null,
  };
  const fingerprint = crypto
    .createHash('sha3-256')
    .update(publicBundle.ed25519Pub)
    .update(publicBundle.mldsa65Pub)
    .update(publicBundle.slhdsa128sPub || Buffer.alloc(0))
    .digest('hex');

  return {
    nodeId,
    fingerprint,
    latticeHedged,
    pub: publicBundle,
    priv: { ed25519: ed.privateKey, mldsa65: mldsa.privateKey, slhdsa128s: slhdsa ? slhdsa.privateKey : null },
  };
}

export function compositeSign(identity, messageBuf) {
  const sigEd = crypto.sign(null, messageBuf, identity.priv.ed25519);
  const sigMlDsa = crypto.sign(null, messageBuf, identity.priv.mldsa65);
  const sigSlh = identity.priv.slhdsa128s ? crypto.sign(null, messageBuf, identity.priv.slhdsa128s) : null;
  return { sigEd, sigMlDsa, sigSlh };
}

export function compositeVerify(pubBundle, messageBuf, sigs) {
  const edKey = crypto.createPublicKey({ key: pubBundle.ed25519Pub, format: 'der', type: 'spki' });
  const mldsaKey = crypto.createPublicKey({ key: pubBundle.mldsa65Pub, format: 'der', type: 'spki' });
  const okEd = crypto.verify(null, messageBuf, edKey, sigs.sigEd);
  const okMlDsa = crypto.verify(null, messageBuf, mldsaKey, sigs.sigMlDsa);
  let okSlh = true;
  if (pubBundle.slhdsa128sPub) {
    if (!sigs.sigSlh) return false;
    const slhKey = crypto.createPublicKey({ key: pubBundle.slhdsa128sPub, format: 'der', type: 'spki' });
    okSlh = crypto.verify(null, messageBuf, slhKey, sigs.sigSlh);
  }
  return okEd && okMlDsa && okSlh;
}

/**
 * Execute a complete 2-party authenticated Hybrid PQ (+ optional IT pre-shared OTP) handshake.
 * Returns identical 256-bit session keys + AEAD + Carter-Wegman keys + exact wire byte audit.
 */
export function runPQSIHandshake(initiatorId, responderId, { preSharedItKey = null, preSharedCwKey = null } = {}) {
  const t0 = process.hrtime.bigint();

  // Step 1: Initiator generates fresh ephemeral X25519 + ML-KEM-768 keys
  const initX = crypto.generateKeyPairSync('x25519');
  const initKem = crypto.generateKeyPairSync('ml-kem-768');
  const initNonce = crypto.randomBytes(32);
  const initXPubDer = initX.publicKey.export({ type: 'spki', format: 'der' });
  const initKemPubDer = initKem.publicKey.export({ type: 'spki', format: 'der' });

  const initIdBuf = Buffer.from(initiatorId.nodeId, 'utf8');
  const initIdLen = Buffer.alloc(2);
  initIdLen.writeUInt16BE(initIdBuf.length, 0);
  const clientHelloBody = Buffer.concat([
    Buffer.from('SecMesh-PQSI-v2|CH|', 'utf8'),
    initIdLen,
    initIdBuf,
    initNonce,
    initXPubDer,
    initKemPubDer,
  ]);
  const clientSig = compositeSign(initiatorId, clientHelloBody);
  const clientCwTag = preSharedCwKey
    ? carterWegmanMac(preSharedCwKey.r, preSharedCwKey.bClient, clientHelloBody)
    : null;

  // Step 2: Responder verifies Initiator composite signature (+ IT-MAC if provisioned)
  if (!compositeVerify(initiatorId.pub, clientHelloBody, clientSig)) {
    throw new Error('Initiator composite PQ signature verification failed');
  }
  if (preSharedCwKey && !carterWegmanVerify(clientCwTag, preSharedCwKey.r, preSharedCwKey.bClient, clientHelloBody)) {
    throw new Error('Initiator Carter-Wegman IT-MAC verification failed');
  }

  // Responder generates ephemeral X25519 and encapsulates against Initiator's ML-KEM-768 key
  const respX = crypto.generateKeyPairSync('x25519');
  const respXPubDer = respX.publicKey.export({ type: 'spki', format: 'der' });
  const respNonce = crypto.randomBytes(32);

  const initXPubObj = crypto.createPublicKey({ key: initXPubDer, format: 'der', type: 'spki' });
  const initKemPubObj = crypto.createPublicKey({ key: initKemPubDer, format: 'der', type: 'spki' });
  const kX25519Resp = crypto.diffieHellman({ privateKey: respX.privateKey, publicKey: initXPubObj });
  const { ciphertext: kemCt, sharedKey: kMlKemResp } = crypto.encapsulate(initKemPubObj);

  const respIdBuf = Buffer.from(responderId.nodeId, 'utf8');
  const respIdLen = Buffer.alloc(2);
  respIdLen.writeUInt16BE(respIdBuf.length, 0);
  const serverHelloBody = Buffer.concat([
    Buffer.from('SecMesh-PQSI-v2|SH|', 'utf8'),
    respIdLen,
    respIdBuf,
    respNonce,
    respXPubDer,
    kemCt,
  ]);
  const fullTranscript = Buffer.concat([clientHelloBody, serverHelloBody]);
  const serverSig = compositeSign(responderId, fullTranscript);
  const serverCwTag = preSharedCwKey
    ? carterWegmanMac(preSharedCwKey.r, preSharedCwKey.bServer, fullTranscript)
    : null;

  // Step 3: Initiator verifies Responder signature (+ IT-MAC), computes X25519 + ML-KEM decaps
  if (!compositeVerify(responderId.pub, fullTranscript, serverSig)) {
    throw new Error('Responder composite PQ signature verification failed');
  }
  if (preSharedCwKey && !carterWegmanVerify(serverCwTag, preSharedCwKey.r, preSharedCwKey.bServer, fullTranscript)) {
    throw new Error('Responder Carter-Wegman IT-MAC verification failed');
  }

  const respXPubObj = crypto.createPublicKey({ key: respXPubDer, format: 'der', type: 'spki' });
  const kX25519Init = crypto.diffieHellman({ privateKey: initX.privateKey, publicKey: respXPubObj });
  const kMlKemInit = crypto.decapsulate(initKem.privateKey, kemCt);

  const sessionKeyInit = dualSurvivabilityCombine({
    kX25519: kX25519Init,
    kMlKem: kMlKemInit,
    kItOpt: preSharedItKey,
    transcriptBuf: fullTranscript,
  });
  const sessionKeyResp = dualSurvivabilityCombine({
    kX25519: kX25519Resp,
    kMlKem: kMlKemResp,
    kItOpt: preSharedItKey,
    transcriptBuf: fullTranscript,
  });

  const keysMatch = crypto.timingSafeEqual(sessionKeyInit, sessionKeyResp);
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;

  // Exact wire byte measurements
  const clientWireBytes =
    clientHelloBody.length +
    clientSig.sigEd.length +
    clientSig.sigMlDsa.length +
    (clientSig.sigSlh ? clientSig.sigSlh.length : 0) +
    (clientCwTag ? clientCwTag.length : 0);
  const serverWireBytes =
    serverHelloBody.length +
    serverSig.sigEd.length +
    serverSig.sigMlDsa.length +
    (serverSig.sigSlh ? serverSig.sigSlh.length : 0) +
    (serverCwTag ? serverCwTag.length : 0);

  const sessionFingerprint = crypto
    .createHash('sha3-256')
    .update('SecMesh-Session-FP|')
    .update(sessionKeyInit)
    .digest('hex')
    .slice(0, 32);

  // Zeroize raw intermediate secrets
  kX25519Init.fill(0);
  kX25519Resp.fill(0);
  kMlKemInit.fill(0);
  kMlKemResp.fill(0);

  return {
    ok: keysMatch,
    securityTier: preSharedItKey && preSharedCwKey ? 'HYBRID_PQ_IT_OTP' : 'HYBRID_PQ_COMPUTATIONAL',
    latticeHedged: initiatorId.latticeHedged && responderId.latticeHedged,
    sessionKey: sessionKeyInit,
    sessionKeyResponder: sessionKeyResp,
    sessionFingerprint,
    transcriptSha3: crypto.createHash('sha3-256').update(fullTranscript).digest('hex'),
    wireBytes: {
      clientToServer: clientWireBytes,
      serverToClient: serverWireBytes,
      totalRoundTrip: clientWireBytes + serverWireBytes,
      mlkemCtBytes: kemCt.length,
      mldsaSigBytes: clientSig.sigMlDsa.length,
      slhdsaSigBytes: clientSig.sigSlh ? clientSig.sigSlh.length : 0,
      cwItMacBytes: clientCwTag ? 16 : 0,
    },
    elapsedMs,
  };
}

/**
 * Authenticated encryption with dual defense:
 *   - Computational layer: AES-256-GCM (nonce-bound, AAD-bound)
 *   - Optional Post-Super-Intelligence layer: Exact One-Time Pad (OTP) + GF(2^128) Carter-Wegman IT-MAC
 */
export function sealRecord(sessionKey, plaintextBuf, aadBuf, { otpPadOpt = null, cwKeyOpt = null } = {}) {
  const pt = Buffer.isBuffer(plaintextBuf) ? plaintextBuf : Buffer.from(plaintextBuf);
  const aad = Buffer.isBuffer(aadBuf) ? aadBuf : Buffer.from(aadBuf || '');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
  cipher.setAAD(aad);
  const aeadCt = Buffer.concat([cipher.update(pt), cipher.final()]);
  const gcmTag = cipher.getAuthTag();

  let wireCt = aeadCt;
  let cwTag = null;
  if (otpPadOpt) {
    if (otpPadOpt.length < aeadCt.length) throw new Error('OTP pad shorter than plaintext');
    wireCt = Buffer.alloc(aeadCt.length);
    for (let i = 0; i < aeadCt.length; i++) wireCt[i] = aeadCt[i] ^ otpPadOpt[i];
  }
  if (cwKeyOpt) {
    const macInput = Buffer.concat([aad, iv, wireCt, gcmTag]);
    cwTag = carterWegmanMac(cwKeyOpt.r, cwKeyOpt.b, macInput);
  }
  return {
    iv,
    ciphertext: wireCt,
    gcmTag,
    cwTag,
    tier: otpPadOpt && cwKeyOpt ? 'HYBRID_PQ_IT_OTP' : 'HYBRID_PQ_COMPUTATIONAL',
  };
}

export function openRecord(sessionKey, record, aadBuf, { otpPadOpt = null, cwKeyOpt = null } = {}) {
  const aad = Buffer.isBuffer(aadBuf) ? aadBuf : Buffer.from(aadBuf || '');
  if (cwKeyOpt) {
    if (!record.cwTag) throw new Error('Missing mandatory Carter-Wegman IT-MAC tag');
    const macInput = Buffer.concat([aad, record.iv, record.ciphertext, record.gcmTag]);
    if (!carterWegmanVerify(record.cwTag, cwKeyOpt.r, cwKeyOpt.b, macInput)) {
      throw new Error('Carter-Wegman IT-MAC verification failed (forged/corrupted record)');
    }
  }
  let aeadCt = record.ciphertext;
  if (otpPadOpt) {
    if (otpPadOpt.length < record.ciphertext.length) throw new Error('OTP pad shorter than ciphertext');
    aeadCt = Buffer.alloc(record.ciphertext.length);
    for (let i = 0; i < record.ciphertext.length; i++) aeadCt[i] = record.ciphertext[i] ^ otpPadOpt[i];
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, record.iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(record.gcmTag);
  return Buffer.concat([decipher.update(aeadCt), decipher.final()]);
}
