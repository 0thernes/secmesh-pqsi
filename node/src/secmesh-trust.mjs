// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — Zero-Trust Peer Identity Pinning & Signed Revocation Store
// Defends against MITM key substitution, silent TOFU downgrade, and compromised-node replay.
// Every peer is pinned by its SHA3-256 composite public-key fingerprint
// (Ed25519 + ML-DSA-65 + SLH-DSA-128s + X25519 + ML-KEM-768 + ML-KEM-1024).

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const TRUST_SCHEMA = 'secmesh-pqsi/trust-store/v3';

function atomicWriteJson(filePath, obj) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
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

export function computePublicBundleFingerprint(pub) {
  const h = crypto.createHash('sha3-256');
  h.update('SecMesh-PQSI-v3|PubFP|');
  for (const field of ['ed25519Pub', 'mldsa65Pub', 'slhdsa128sPub', 'x25519Pub', 'mlkem768Pub', 'mlkem1024Pub']) {
    const val = pub[field];
    const buf = val ? (Buffer.isBuffer(val) ? val : Buffer.from(val, 'base64')) : Buffer.alloc(0);
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(buf.length, 0);
    h.update(lenBuf).update(buf);
  }
  return h.digest('hex');
}

export function serializePublicBundle(pub) {
  const out = { nodeId: pub.nodeId };
  for (const field of ['ed25519Pub', 'mldsa65Pub', 'slhdsa128sPub', 'x25519Pub', 'mlkem768Pub', 'mlkem1024Pub']) {
    if (pub[field]) {
      out[field] = Buffer.isBuffer(pub[field]) ? pub[field].toString('base64') : String(pub[field]);
    } else {
      out[field] = null;
    }
  }
  out.fingerprint = computePublicBundleFingerprint(out);
  return out;
}

export function deserializePublicBundle(obj) {
  const out = { nodeId: obj.nodeId };
  for (const field of ['ed25519Pub', 'mldsa65Pub', 'slhdsa128sPub', 'x25519Pub', 'mlkem768Pub', 'mlkem1024Pub']) {
    out[field] = obj[field] ? (Buffer.isBuffer(obj[field]) ? obj[field] : Buffer.from(obj[field], 'base64')) : null;
  }
  out.fingerprint = computePublicBundleFingerprint(out);
  return out;
}

export function compositeSignV3(identity, msgBuf) {
  const payload = Buffer.isBuffer(msgBuf) ? msgBuf : Buffer.from(msgBuf);
  const sigEd = crypto.sign(null, payload, identity.priv.ed25519);
  const sigMlDsa = crypto.sign(null, payload, identity.priv.mldsa65);
  const sigSlh = identity.priv.slhdsa128s ? crypto.sign(null, payload, identity.priv.slhdsa128s) : null;
  return {
    sigEd: sigEd.toString('base64'),
    sigMlDsa: sigMlDsa.toString('base64'),
    sigSlh: sigSlh ? sigSlh.toString('base64') : null,
  };
}

export function compositeVerifyV3(pubObj, msgBuf, sigs) {
  if (!pubObj || !sigs || !sigs.sigEd || !sigs.sigMlDsa) return false;
  const pub = deserializePublicBundle(pubObj);
  const payload = Buffer.isBuffer(msgBuf) ? msgBuf : Buffer.from(msgBuf);
  try {
    const edKey = crypto.createPublicKey({ key: pub.ed25519Pub, format: 'der', type: 'spki' });
    const mlKey = crypto.createPublicKey({ key: pub.mldsa65Pub, format: 'der', type: 'spki' });
    const okEd = crypto.verify(null, payload, edKey, Buffer.from(sigs.sigEd, 'base64'));
    const okMl = crypto.verify(null, payload, mlKey, Buffer.from(sigs.sigMlDsa, 'base64'));
    let okSlh = true;
    if (pub.slhdsa128sPub) {
      if (!sigs.sigSlh) return false;
      const slhKey = crypto.createPublicKey({ key: pub.slhdsa128sPub, format: 'der', type: 'spki' });
      okSlh = crypto.verify(null, payload, slhKey, Buffer.from(sigs.sigSlh, 'base64'));
    }
    return okEd && okMl && okSlh;
  } catch {
    return false;
  }
}

export class PeerTrustStore {
  constructor(storePath) {
    this.storePath = storePath ? path.resolve(storePath) : null;
    this.data = { schema: TRUST_SCHEMA, updatedAt: new Date().toISOString(), peers: {}, revocations: {} };
    if (this.storePath && fs.existsSync(this.storePath)) {
      const loaded = JSON.parse(fs.readFileSync(this.storePath, 'utf8'));
      if (loaded.schema !== TRUST_SCHEMA) throw new Error(`Unsupported trust store schema: ${loaded.schema}`);
      this.data = loaded;
    }
  }

  save() {
    if (!this.storePath) return;
    this.data.updatedAt = new Date().toISOString();
    atomicWriteJson(this.storePath, this.data);
  }

  /**
   * Explicitly pin a peer's composite public bundle.
   * Refuses silent MITM key changes for an already-pinned nodeId!
   */
  pinPeer(pubBundle, { role = 'peer', expiresAt = null } = {}) {
    const ser = serializePublicBundle(pubBundle);
    if (!ser.nodeId || typeof ser.nodeId !== 'string') throw new Error('Peer nodeId required');
    if (this.data.revocations[ser.fingerprint]) {
      throw new Error(`PEER_REVOKED: refusing to pin revoked fingerprint ${ser.fingerprint.slice(0, 16)}`);
    }
    const existing = this.data.peers[ser.nodeId];
    if (existing && existing.fingerprint !== ser.fingerprint) {
      throw new Error(
        `MITM_KEY_CHANGE_REFUSED: nodeId "${ser.nodeId}" already pinned to ${existing.fingerprint.slice(0, 16)}, refusing overwrite with ${ser.fingerprint.slice(0, 16)}`,
      );
    }
    this.data.peers[ser.nodeId] = {
      ...ser,
      role,
      pinnedAt: existing ? existing.pinnedAt : new Date().toISOString(),
      expiresAt,
      revoked: false,
    };
    this.save();
    return this.data.peers[ser.nodeId];
  }

  /**
   * Verify that a presented peer bundle matches our pinned record, is not expired, and is not revoked.
   */
  verifyPinnedPeer(presentedPub) {
    const ser = serializePublicBundle(presentedPub);
    if (this.data.revocations[ser.fingerprint]) {
      return { ok: false, reason: 'peer-revoked', fingerprint: ser.fingerprint };
    }
    const pinned = this.data.peers[ser.nodeId];
    if (!pinned) {
      return { ok: false, reason: 'peer-unpinned', nodeId: ser.nodeId, fingerprint: ser.fingerprint };
    }
    if (pinned.revoked) {
      return { ok: false, reason: 'peer-revoked', nodeId: ser.nodeId, fingerprint: ser.fingerprint };
    }
    if (pinned.fingerprint !== ser.fingerprint) {
      return { ok: false, reason: 'peer-fingerprint-mismatch', nodeId: ser.nodeId, expected: pinned.fingerprint, got: ser.fingerprint };
    }
    if (pinned.expiresAt && Date.now() > Date.parse(pinned.expiresAt)) {
      return { ok: false, reason: 'peer-expired', nodeId: ser.nodeId };
    }
    return { ok: true, peer: pinned, fingerprint: ser.fingerprint };
  }

  getPeer(nodeId) {
    const p = this.data.peers[nodeId];
    if (!p || p.revoked || this.data.revocations[p.fingerprint]) return null;
    if (p.expiresAt && Date.now() > Date.parse(p.expiresAt)) return null;
    return deserializePublicBundle(p);
  }

  /**
   * Create a cryptographically self-signed (or quorum-signed) revocation certificate.
   */
  static createRevocationCert(signerIdentity, targetFingerprint, reason = 'key-compromise') {
    const issuedAt = new Date().toISOString();
    const payload = Buffer.from(`SecMesh-PQSI-v3|REVOKE|${targetFingerprint}|${reason}|${issuedAt}`, 'utf8');
    const sigs = compositeSignV3(signerIdentity, payload);
    return {
      schema: 'secmesh-pqsi/revocation/v3',
      targetFingerprint,
      signerNodeId: signerIdentity.nodeId,
      signerFingerprint: computePublicBundleFingerprint(signerIdentity.pub),
      reason,
      issuedAt,
      sigs,
    };
  }

  /**
   * Apply a signed revocation certificate after verifying its composite PQ+classical signature.
   */
  applyRevocationCert(cert) {
    if (!cert || cert.schema !== 'secmesh-pqsi/revocation/v3') {
      throw new Error('Invalid revocation certificate schema');
    }
    const signerEntry = Object.values(this.data.peers).find((p) => p.fingerprint === cert.signerFingerprint);
    if (!signerEntry) {
      throw new Error('Revocation signer is not a known pinned identity');
    }
    const authorized = signerEntry.fingerprint === cert.targetFingerprint || signerEntry.role === 'quorum-auditor';
    if (!authorized) {
      throw new Error('Revocation signer lacks authority (must be self or quorum-auditor)');
    }
    const payload = Buffer.from(
      `SecMesh-PQSI-v3|REVOKE|${cert.targetFingerprint}|${cert.reason}|${cert.issuedAt}`,
      'utf8',
    );
    if (!compositeVerifyV3(signerEntry, payload, cert.sigs)) {
      throw new Error('Revocation certificate composite signature INVALID');
    }
    this.data.revocations[cert.targetFingerprint] = {
      reason: cert.reason,
      issuedAt: cert.issuedAt,
      revokedBy: cert.signerFingerprint,
    };
    for (const p of Object.values(this.data.peers)) {
      if (p.fingerprint === cert.targetFingerprint) p.revoked = true;
    }
    this.save();
    return true;
  }

  listPeers() {
    return Object.values(this.data.peers).map((p) => ({
      nodeId: p.nodeId,
      fingerprint: p.fingerprint,
      role: p.role,
      revoked: !!p.revoked,
      expiresAt: p.expiresAt,
      hasSlhDsa: !!p.slhdsa128sPub,
      hasMlKem1024: !!p.mlkem1024Pub,
    }));
  }
}
