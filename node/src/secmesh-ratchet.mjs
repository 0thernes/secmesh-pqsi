// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — Post-Quantum Double-Ratchet & Automatic Epoch Rekeying Engine
// Provides:
//   - Bidirectional directional isolation (initiator->responder != responder->initiator)
//   - Per-packet SHAKE-256 symmetric chain ratchet (immediate forward secrecy; old keys wiped)
//   - Double-AEAD cascade per packet (AES-256-GCM inner + ChaCha20-Poly1305 outer)
//   - Optional constant-time C11 GF(2^128) Carter-Wegman IT-MAC + PSI OTP masking per frame
//   - Bounded RFC-6479 sliding replay window + bounded out-of-order skipped-key cache (MAX_SKIP=64)
//   - Automatic Asymmetric PQ Epoch Rekeying (fresh X25519 + ML-KEM-768 -> Post-Compromise Security)

import crypto from 'node:crypto';
import { carterWegmanMac, carterWegmanVerify, createReplayWindow } from './pqsi-handshake.mjs';
import { doubleAeadSeal, doubleAeadOpen } from './secmesh-vault.mjs';

const MAX_SKIP = 64;
const RECORD_VERSION = 3;

function kdfLabel(key32, label, extraBuf = Buffer.alloc(0), outLen = 32) {
  return crypto
    .createHash('shake256', { outputLength: outLen })
    .update(`SecMesh-PQSI-v3|Ratchet|${label}|`)
    .update(key32)
    .update(extraBuf)
    .digest();
}

function advanceChain(chainKey32, seqBigInt, dirTag) {
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64BE(seqBigInt, 0);
  const mat = kdfLabel(chainKey32, `Step|${dirTag}`, seqBuf, 96);
  const nextChain = Buffer.from(mat.subarray(0, 32));
  const msgKey = Buffer.from(mat.subarray(32, 64));
  const cwR = Buffer.from(mat.subarray(64, 80));
  const cwB = Buffer.from(mat.subarray(80, 96));
  mat.fill(0);
  return { nextChain, msgKey, cwR, cwB };
}

export class PqDoubleRatchetSession {
  constructor({
    rootKey32,
    role, // 'initiator' | 'responder'
    transcriptHash32,
    rekeyAfterPackets = 1000,
    rekeyAfterMs = 120000,
    enableCwMac = true,
    ctCoprocessor = null,
  }) {
    if (!Buffer.isBuffer(rootKey32) || rootKey32.length !== 32) {
      throw new Error('rootKey32 must be a 32-byte Buffer');
    }
    if (role !== 'initiator' && role !== 'responder') {
      throw new Error('role must be initiator or responder');
    }
    this.role = role;
    this.epoch = 0;
    this.rootKey = Buffer.from(rootKey32);
    this.transcriptHash = Buffer.from(transcriptHash32 || Buffer.alloc(32));
    this.rekeyAfterPackets = rekeyAfterPackets;
    this.rekeyAfterMs = rekeyAfterMs;
    this.enableCwMac = !!enableCwMac;
    this.ctCoprocessor = ctCoprocessor;
    this.epochStartedAt = Date.now();
    this.packetsInEpoch = 0;
    this.totalSealed = 0;
    this.totalOpened = 0;
    this.rekeyCount = 0;
    this.pendingRekey = null;
    this._initEpochChains();
  }

  _initEpochChains() {
    const epBuf = Buffer.alloc(4);
    epBuf.writeUInt32BE(this.epoch, 0);
    const seed = Buffer.concat([epBuf, this.transcriptHash]);
    const c2s = kdfLabel(this.rootKey, 'Chain|C2S', seed, 32);
    const s2c = kdfLabel(this.rootKey, 'Chain|S2C', seed, 32);
    if (this.txChain) this.txChain.fill(0);
    if (this.rxChain) this.rxChain.fill(0);
    if (this.role === 'initiator') {
      this.txChain = c2s;
      this.rxChain = s2c;
      this.txDir = 'C2S';
      this.rxDir = 'S2C';
    } else {
      this.txChain = s2c;
      this.rxChain = c2s;
      this.txDir = 'S2C';
      this.rxDir = 'C2S';
    }
    this.txSeq = 0n;
    this.rxExpectedSeq = 0n;
    this.replayWindow = createReplayWindow(4096n);
    if (this.skippedKeys) {
      for (const k of this.skippedKeys.values()) {
        k.msgKey.fill(0); k.cwR.fill(0); k.cwB.fill(0);
      }
    }
    this.skippedKeys = new Map();
    this.packetsInEpoch = 0;
    this.epochStartedAt = Date.now();
  }

  needsRekey() {
    return (
      this.packetsInEpoch >= this.rekeyAfterPackets ||
      Date.now() - this.epochStartedAt >= this.rekeyAfterMs
    );
  }

  /**
   * Step 1 of Asymmetric PQ Epoch Rekey: generate fresh ephemeral X25519 + ML-KEM-768 keypairs.
   */
  beginPqRekey() {
    const ephX = crypto.generateKeyPairSync('x25519');
    const ephKem = crypto.generateKeyPairSync('ml-kem-768');
    const nextEpoch = this.epoch + 1;
    this.pendingRekey = { nextEpoch, ephX, ephKem };
    return {
      nextEpoch,
      x25519PubB64: ephX.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      mlkem768PubB64: ephKem.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    };
  }

  /**
   * Step 2 (Peer Responder): encapsulate fresh X25519 + ML-KEM-768 and immediately rotate epoch!
   */
  respondPqRekey(rekeyInit, extraPsiKey32 = null) {
    if (!rekeyInit || rekeyInit.nextEpoch !== this.epoch + 1) {
      throw new Error(`Invalid rekey epoch (got=${rekeyInit?.nextEpoch}, expected=${this.epoch + 1})`);
    }
    const peerX = crypto.createPublicKey({ key: Buffer.from(rekeyInit.x25519PubB64, 'base64'), format: 'der', type: 'spki' });
    const peerKem = crypto.createPublicKey({ key: Buffer.from(rekeyInit.mlkem768PubB64, 'base64'), format: 'der', type: 'spki' });
    const myX = crypto.generateKeyPairSync('x25519');
    const ssX = crypto.diffieHellman({ privateKey: myX.privateKey, publicKey: peerX });
    const enc = crypto.encapsulate(peerKem);
    try {
      this._mixEpochSecret(rekeyInit.nextEpoch, ssX, enc.sharedKey, extraPsiKey32);
      return {
        nextEpoch: rekeyInit.nextEpoch,
        x25519PubB64: myX.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        ctMlKem768B64: enc.ciphertext.toString('base64'),
      };
    } finally {
      ssX.fill(0);
      enc.sharedKey.fill(0);
    }
  }

  /**
   * Step 3 (Initiator): decapsulate responder's fresh PQ ratchet ciphertext and rotate epoch!
   */
  finishPqRekey(rekeyAck, extraPsiKey32 = null) {
    if (!this.pendingRekey || rekeyAck.nextEpoch !== this.pendingRekey.nextEpoch) {
      throw new Error('Unexpected or mismatched rekey ACK');
    }
    const { nextEpoch, ephX, ephKem } = this.pendingRekey;
    const peerX = crypto.createPublicKey({ key: Buffer.from(rekeyAck.x25519PubB64, 'base64'), format: 'der', type: 'spki' });
    const ssX = crypto.diffieHellman({ privateKey: ephX.privateKey, publicKey: peerX });
    const ssKem = crypto.decapsulate(ephKem.privateKey, Buffer.from(rekeyAck.ctMlKem768B64, 'base64'));
    try {
      this._mixEpochSecret(nextEpoch, ssX, ssKem, extraPsiKey32);
      this.pendingRekey = null;
      return { epoch: this.epoch, rekeyCount: this.rekeyCount };
    } finally {
      ssX.fill(0);
      ssKem.fill(0);
    }
  }

  _mixEpochSecret(nextEpoch, ssX, ssKem, extraPsiKey32) {
    const epBuf = Buffer.alloc(4);
    epBuf.writeUInt32BE(nextEpoch, 0);
    const derived = crypto
      .createHash('shake256', { outputLength: 32 })
      .update('SecMesh-PQSI-v3|EpochRekey|')
      .update(epBuf)
      .update(this.rootKey)
      .update(ssX)
      .update(ssKem)
      .digest();
    for (let i = 0; i < 32; i++) {
      this.rootKey[i] = derived[i] ^ (extraPsiKey32 ? extraPsiKey32[i] : 0);
    }
    derived.fill(0);
    this.epoch = nextEpoch;
    this.rekeyCount++;
    this._initEpochChains();
  }

  /**
   * Seal one packet with forward-secret ratcheted Double-AEAD + optional CW-128 IT-MAC + OTP.
   * Binary packet layout:
   *   [u8 ver=3 | u8 flags | u32be epoch | u64be seq | ivAes(12) | tagAes(16) | ivCha(12) | tagCha(16) | cwTag(0|16) | ct]
   */
  async sealPacket(plaintextBuf, { aadExtra = Buffer.alloc(0), otpPadOpt = null } = {}) {
    const plain = Buffer.isBuffer(plaintextBuf) ? plaintextBuf : Buffer.from(plaintextBuf);
    const seq = this.txSeq;
    const step = advanceChain(this.txChain, seq, this.txDir);
    this.txChain.fill(0);
    this.txChain = step.nextChain;
    this.txSeq = seq + 1n;
    this.packetsInEpoch++;
    this.totalSealed++;

    const flags = (this.enableCwMac ? 0x01 : 0x00) | (otpPadOpt ? 0x02 : 0x00);
    const hdr = Buffer.alloc(14);
    hdr[0] = RECORD_VERSION;
    hdr[1] = flags;
    hdr.writeUInt32BE(this.epoch, 2);
    hdr.writeBigUInt64BE(seq, 6);
    const aad = Buffer.concat([hdr, this.transcriptHash, aadExtra]);

    try {
      const sealed = doubleAeadSeal(step.msgKey, plain, aad, `pkt-${this.txDir}`);
      let body = sealed.ciphertext;
      if (otpPadOpt) {
        if (!Buffer.isBuffer(otpPadOpt) || otpPadOpt.length < body.length) {
          throw new Error(`Insufficient OTP pad (${otpPadOpt?.length} < ${body.length})`);
        }
        const masked = Buffer.alloc(body.length);
        for (let i = 0; i < body.length; i++) masked[i] = body[i] ^ otpPadOpt[i];
        body = masked;
      }

      let cwTag = Buffer.alloc(0);
      if (this.enableCwMac) {
        const macIn = Buffer.concat([hdr, sealed.ivAes, sealed.tagAes, sealed.ivChaCha, sealed.tagChaCha, body]);
        cwTag = this.ctCoprocessor
          ? await this.ctCoprocessor.carterWegmanMac(step.cwR, step.cwB, macIn)
          : carterWegmanMac(step.cwR, step.cwB, macIn);
      }

      return Buffer.concat([hdr, sealed.ivAes, sealed.tagAes, sealed.ivChaCha, sealed.tagChaCha, cwTag, body]);
    } finally {
      step.msgKey.fill(0);
      step.cwR.fill(0);
      step.cwB.fill(0);
    }
  }

  _consumeRxKey(seqBigInt) {
    if (this.replayWindow.has(seqBigInt)) {
      throw new Error(`RATCHET_REPLAY_REJECTED: seq=${seqBigInt}`);
    }
    const keyId = seqBigInt.toString();
    if (this.skippedKeys.has(keyId)) {
      const k = this.skippedKeys.get(keyId);
      this.skippedKeys.delete(keyId);
      return k;
    }
    if (seqBigInt < this.rxExpectedSeq) {
      throw new Error(`RATCHET_STALE_SEQ: seq=${seqBigInt} < expected=${this.rxExpectedSeq}`);
    }
    const skip = Number(seqBigInt - this.rxExpectedSeq);
    if (skip > MAX_SKIP || this.skippedKeys.size + skip > MAX_SKIP) {
      throw new Error(`RATCHET_SKIP_DOS_REFUSED: skip=${skip} > MAX_SKIP=${MAX_SKIP}`);
    }
    // Advance chain safely, caching skipped keys up to MAX_SKIP without mutating until verified
    let curChain = Buffer.from(this.rxChain);
    const newlySkipped = [];
    for (let s = this.rxExpectedSeq; s < seqBigInt; s += 1n) {
      const st = advanceChain(curChain, s, this.rxDir);
      curChain.fill(0);
      curChain = st.nextChain;
      newlySkipped.push([s.toString(), { msgKey: st.msgKey, cwR: st.cwR, cwB: st.cwB }]);
    }
    const target = advanceChain(curChain, seqBigInt, this.rxDir);
    curChain.fill(0);
    return {
      msgKey: target.msgKey,
      cwR: target.cwR,
      cwB: target.cwB,
      commit: () => {
        this.rxChain.fill(0);
        this.rxChain = target.nextChain;
        this.rxExpectedSeq = seqBigInt + 1n;
        for (const [k, v] of newlySkipped) this.skippedKeys.set(k, v);
      },
      rollback: () => {
        target.nextChain.fill(0);
        for (const [, v] of newlySkipped) {
          v.msgKey.fill(0); v.cwR.fill(0); v.cwB.fill(0);
        }
      },
    };
  }

  async openPacket(packetBuf, { aadExtra = Buffer.alloc(0), otpPadOpt = null } = {}) {
    if (!Buffer.isBuffer(packetBuf) || packetBuf.length < 70) {
      throw new Error('Malformed ratchet packet (< 70B)');
    }
    const ver = packetBuf[0];
    const flags = packetBuf[1];
    const epoch = packetBuf.readUInt32BE(2);
    const seq = packetBuf.readBigUInt64BE(6);
    if (ver !== RECORD_VERSION) throw new Error(`Unsupported ratchet packet version: ${ver}`);
    if (epoch !== this.epoch) throw new Error(`RATCHET_EPOCH_MISMATCH: got=${epoch}, expected=${this.epoch}`);

    const hasCw = (flags & 0x01) !== 0;
    const hasOtp = (flags & 0x02) !== 0;
    if (this.enableCwMac && !hasCw) throw new Error('CW-128 MAC stripped (downgrade refused)');
    if (hasOtp && !otpPadOpt) throw new Error('OTP pad required for PSI-masked packet');

    const minLen = 70 + (hasCw ? 16 : 0);
    if (packetBuf.length < minLen) throw new Error('Truncated ratchet packet');

    const hdr = packetBuf.subarray(0, 14);
    const ivAes = packetBuf.subarray(14, 26);
    const tagAes = packetBuf.subarray(26, 42);
    const ivChaCha = packetBuf.subarray(42, 54);
    const tagChaCha = packetBuf.subarray(54, 70);
    const cwTag = hasCw ? packetBuf.subarray(70, 86) : Buffer.alloc(0);
    const body = packetBuf.subarray(hasCw ? 86 : 70);

    const kEntry = this._consumeRxKey(seq);
    let committed = false;
    let unmasked = null;
    try {
      if (hasCw) {
        const macIn = Buffer.concat([hdr, ivAes, tagAes, ivChaCha, tagChaCha, body]);
        const ok = this.ctCoprocessor
          ? await this.ctCoprocessor.carterWegmanVerify(cwTag, kEntry.cwR, kEntry.cwB, macIn)
          : carterWegmanVerify(cwTag, kEntry.cwR, kEntry.cwB, macIn);
        if (!ok) throw new Error('RATCHET_CW128_MAC_REJECTED');
      }

      let ct = body;
      if (hasOtp) {
        if (!Buffer.isBuffer(otpPadOpt) || otpPadOpt.length < body.length) {
          throw new Error('Insufficient OTP pad on open');
        }
        unmasked = Buffer.alloc(body.length);
        for (let i = 0; i < body.length; i++) unmasked[i] = body[i] ^ otpPadOpt[i];
        ct = unmasked;
      }

      const aad = Buffer.concat([hdr, this.transcriptHash, aadExtra]);
      const plain = doubleAeadOpen(kEntry.msgKey, {
        ivAes, tagAes, ivChaCha, tagChaCha, ciphertext: ct,
      }, aad, `pkt-${this.rxDir}`);

      // Only commit ratchet advancement & replay window AFTER full cryptographic authentication!
      if (kEntry.commit) kEntry.commit();
      this.replayWindow.add(seq);
      committed = true;
      this.packetsInEpoch++;
      this.totalOpened++;
      return { plaintext: plain, epoch, seq };
    } finally {
      kEntry.msgKey.fill(0);
      kEntry.cwR.fill(0);
      kEntry.cwB.fill(0);
      if (!committed && kEntry.rollback) kEntry.rollback();
      if (unmasked) unmasked.fill(0);
    }
  }

  destroy() {
    this.rootKey.fill(0);
    if (this.txChain) this.txChain.fill(0);
    if (this.rxChain) this.rxChain.fill(0);
    if (this.skippedKeys) {
      for (const k of this.skippedKeys.values()) {
        k.msgKey.fill(0); k.cwR.fill(0); k.cwB.fill(0);
      }
      this.skippedKeys.clear();
    }
  }
}
