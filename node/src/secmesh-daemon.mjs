// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — Level 2 Live Over-the-Wire PQ+PSI Daemon,
// 3-Hop Onion-Artichoke Circuit Router & Encrypted TCP Port-Forwarding Tunnel
//
// Features:
//   1. Real 3-message over-the-wire authenticated Triple-KEM Hybrid Handshake
//      (X25519 + ML-KEM-768 + ML-KEM-1024 + Ed25519 + ML-DSA-65 + SLH-DSA-128s + optional PSI pad)
//      with strict mutual PeerTrustStore pinning (refuses unknown/MITM/revoked identities).
//   2. Live bidirectional PQ Double-Ratchet + fixed-size cell padding + chaff cover traffic +
//      automatic mid-stream asymmetric PQ epoch rekeying!
//   3. True 3-Hop Onion-Artichoke Circuit Routing (Client -> Relay1 -> Relay2 -> Exit):
//      each hop peels ONLY its own X25519+ML-KEM-768+AES-256-GCM+ChaCha20-Poly1305 skin;
//      no single relay sees both origin and destination or plaintext; encrypted reply path included!
//   4. Live Encrypted TCP Port-Forwarding Tunnel (`createPqsiTcpTunnel` — PQ+PSI `ssh -L`).

import crypto from 'node:crypto';
import net from 'node:net';
import { dualSurvivabilityCombine } from './pqsi-handshake.mjs';
import {
  computePublicBundleFingerprint,
  serializePublicBundle,
  deserializePublicBundle,
  compositeSignV3,
  compositeVerifyV3,
} from './secmesh-trust.mjs';
import { doubleAeadSeal, doubleAeadOpen } from './secmesh-vault.mjs';
import {
  LengthPrefixedFramer,
  encodeWireFrame,
  packFixedCell,
  unpackFixedCell,
  makeChaffCell,
  CELL_TYPE,
  DEFAULT_CELL_BYTES,
} from './secmesh-wire.mjs';
import { PqDoubleRatchetSession } from './secmesh-ratchet.mjs';
import { consumePadSlice, consumePadAtOffset } from './secmesh-pad-ledger.mjs';

function sha3(bufs) {
  const h = crypto.createHash('sha3-256');
  for (const b of bufs) h.update(Buffer.isBuffer(b) ? b : Buffer.from(b));
  return h.digest();
}

// ============================================================================
// 1. Live Two-Machine TCP Peer Server & Client (3-Msg PQ+PSI Handshake + Ratchet)
// ============================================================================
export class PqsiTcpSession {
  constructor(socket, ratchet, remotePeer, { cellBytes = DEFAULT_CELL_BYTES, onMessage = null, onTunnelOpen = null, onClose = null } = {}) {
    this.socket = socket;
    this.ratchet = ratchet;
    this.remotePeer = remotePeer;
    this.cellBytes = cellBytes;
    this.onMessage = onMessage;
    this.onTunnelOpen = onTunnelOpen;
    this.onClose = onClose;
    this.tunnels = new Map();
    this.closed = false;
    this._rekeyInFlight = false;
    this._rekeyWaiters = [];
    this._sendChain = Promise.resolve();
    this._recvChain = Promise.resolve();
    this.chaffReceived = 0;
  }

  _enqueueSend(fn) {
    this._sendChain = this._sendChain.then(fn, fn);
    return this._sendChain;
  }

  _sendRekeyInitAndWait() {
    if (this._rekeyInFlight) {
      return new Promise((resolve, reject) => this._rekeyWaiters.push({ resolve, reject }));
    }
    this._rekeyInFlight = true;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._rekeyInFlight = false;
        reject(new Error('PQ epoch rekey ACK timeout'));
      }, 5000);
      timer.unref();
      this._rekeyWaiters.push({
        resolve: () => { clearTimeout(timer); resolve(); },
        reject: (err) => { clearTimeout(timer); reject(err); },
      });
      this._enqueueSend(async () => {
        if (this.closed) return;
        const initObj = this.ratchet.beginPqRekey();
        const cell = packFixedCell(CELL_TYPE.REKEY_INIT, Buffer.from(JSON.stringify(initObj), 'utf8'), this.cellBytes);
        const wirePkt = await this.ratchet.sealPacket(cell);
        this.socket.write(encodeWireFrame(wirePkt));
      }).catch(reject);
    });
  }

  async sendCell(cellType, payloadBuf = Buffer.alloc(0)) {
    // Synchronized asymmetric PQ epoch rekey BEFORE sealing new packets in the next epoch
    if (cellType !== CELL_TYPE.REKEY_INIT && cellType !== CELL_TYPE.REKEY_ACK && this.ratchet.needsRekey()) {
      await this._sendRekeyInitAndWait();
    }
    return this._enqueueSend(async () => {
      if (this.closed) throw new Error('Session closed');
      const cell = packFixedCell(cellType, payloadBuf, this.cellBytes);
      const wirePkt = await this.ratchet.sealPacket(cell);
      this.socket.write(encodeWireFrame(wirePkt));
    });
  }

  async sendMessage(bufOrStr) {
    const payload = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(String(bufOrStr), 'utf8');
    return this.sendCell(CELL_TYPE.DATA, payload);
  }

  async sendChaff() {
    return this._enqueueSend(async () => {
      if (this.closed) return;
      const cell = makeChaffCell(this.cellBytes);
      const wirePkt = await this.ratchet.sealPacket(cell);
      this.socket.write(encodeWireFrame(wirePkt));
    });
  }

  async triggerRekey() {
    if (this.closed) return;
    await this._sendRekeyInitAndWait();
  }

  async handleEncryptedFrame(frameBuf) {
    // Serialize decryptions so epoch rekey transitions stay ordered cleanly
    this._recvChain = this._recvChain.then(async () => {
      if (this.closed) return;
      const opened = await this.ratchet.openPacket(frameBuf);
      const { cellType, payload } = unpackFixedCell(opened.plaintext);
      if (cellType === CELL_TYPE.CHAFF) {
        this.chaffReceived++;
        return;
      }
      if (cellType === CELL_TYPE.REKEY_INIT) {
        const initObj = JSON.parse(payload.toString('utf8'));
        // Send ACK under CURRENT epoch BEFORE switching keys? No — send ACK encrypted under old epoch, then switch!
        const ackObj = (() => {
          // Wait: respondPqRekey rotates immediately, so serialize ACK under current epoch first:
          const peerX = crypto.createPublicKey({ key: Buffer.from(initObj.x25519PubB64, 'base64'), format: 'der', type: 'spki' });
          const peerKem = crypto.createPublicKey({ key: Buffer.from(initObj.mlkem768PubB64, 'base64'), format: 'der', type: 'spki' });
          const myX = crypto.generateKeyPairSync('x25519');
          const ssX = crypto.diffieHellman({ privateKey: myX.privateKey, publicKey: peerX });
          const enc = crypto.encapsulate(peerKem);
          return {
            nextEpoch: initObj.nextEpoch,
            x25519PubB64: myX.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
            ctMlKem768B64: enc.ciphertext.toString('base64'),
            ssX,
            ssKem: enc.sharedKey,
          };
        })();
        await this._enqueueSend(async () => {
          const ackCell = packFixedCell(
            CELL_TYPE.REKEY_ACK,
            Buffer.from(JSON.stringify({
              nextEpoch: ackObj.nextEpoch,
              x25519PubB64: ackObj.x25519PubB64,
              ctMlKem768B64: ackObj.ctMlKem768B64,
            }), 'utf8'),
            this.cellBytes,
          );
          const wirePkt = await this.ratchet.sealPacket(ackCell);
          this.socket.write(encodeWireFrame(wirePkt));
          this.ratchet._mixEpochSecret(ackObj.nextEpoch, ackObj.ssX, ackObj.ssKem, null);
          ackObj.ssX.fill(0);
          ackObj.ssKem.fill(0);
        });
        return;
      }
      if (cellType === CELL_TYPE.REKEY_ACK) {
        const ackObj = JSON.parse(payload.toString('utf8'));
        await this._enqueueSend(async () => {
          this.ratchet.finishPqRekey(ackObj, null);
          this._rekeyInFlight = false;
          const waiters = this._rekeyWaiters.splice(0);
          for (const w of waiters) w.resolve();
        });
        return;
      }
      if (cellType === CELL_TYPE.TUNNEL_OPEN) {
        const meta = JSON.parse(payload.toString('utf8'));
        if (this.onTunnelOpen) this.onTunnelOpen(meta, this);
        return;
      }
      if (cellType === CELL_TYPE.TUNNEL_DATA) {
        const tid = payload.readUInt32BE(0);
        const chunk = payload.subarray(4);
        const sock = this.tunnels.get(tid);
        if (sock && !sock.destroyed) sock.write(chunk);
        return;
      }
      if (cellType === CELL_TYPE.TUNNEL_CLOSE) {
        const tid = payload.readUInt32BE(0);
        const sock = this.tunnels.get(tid);
        if (sock) { sock.end(); this.tunnels.delete(tid); }
        return;
      }
      if (cellType === CELL_TYPE.DATA && this.onMessage) {
        this.onMessage(payload, { epoch: opened.epoch, seq: opened.seq, peer: this.remotePeer });
      }
    }).catch((err) => {
      this.close();
      if (this.onClose) this.onClose(err);
    });
    return this._recvChain;
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    const waiters = this._rekeyWaiters.splice(0);
    for (const w of waiters) w.reject(new Error('Session closed during rekey'));
    for (const s of this.tunnels.values()) { try { s.destroy(); } catch { /* ignore */ } }
    this.tunnels.clear();
    this.ratchet.destroy();
    try { this.socket.destroy(); } catch { /* ignore */ }
  }
}

export function createPqsiTcpServer({
  identity,
  trustStore,
  host = '127.0.0.1',
  port = 0,
  padPoolPath = null,
  ctCoprocessor = null,
  firewall = null,
  rekeyAfterPackets = 1000,
  onSession = null,
  onMessage = null,
  allowedTunnelTargets = [], // e.g., ['127.0.0.1:8080']
}) {
  const activeSessions = new Set();
  const activeSockets = new Set();
  const server = net.createServer((sock) => {
    activeSockets.add(sock);
    const remoteIp = sock.remoteAddress || '127.0.0.1';
    if (firewall && firewall.isBlocked(remoteIp)) {
      sock.destroy();
      return;
    }

    let phase = 'WAIT_CLIENT_HELLO';
    let hsState = null;
    let session = null;

    const framer = new LengthPrefixedFramer({
      onError: () => {
        if (firewall) firewall.reportIncident(remoteIp, 'oversize-frame');
        sock.destroy();
      },
      onFrame: (frame) => {
        if (phase === 'ESTABLISHED' && session) {
          session.handleEncryptedFrame(frame);
          return;
        }
        try {
          if (phase === 'WAIT_CLIENT_HELLO') {
            const ch = JSON.parse(frame.toString('utf8'));
            if (ch.type !== 'CLIENT_HELLO') throw new Error('Expected CLIENT_HELLO');
            const verifyPin = trustStore.verifyPinnedPeer(ch.pub);
            if (!verifyPin.ok) {
              if (firewall) firewall.reportIncident(remoteIp, `trust-${verifyPin.reason}`);
              throw new Error(`Peer trust check failed: ${verifyPin.reason}`);
            }
            const clientPub = deserializePublicBundle(ch.pub);
            const cEphX = crypto.createPublicKey({ key: Buffer.from(ch.ephX25519PubB64, 'base64'), format: 'der', type: 'spki' });
            const cEph768 = crypto.createPublicKey({ key: Buffer.from(ch.ephMlKem768PubB64, 'base64'), format: 'der', type: 'spki' });
            const cEph1024 = crypto.createPublicKey({ key: Buffer.from(ch.ephMlKem1024PubB64, 'base64'), format: 'der', type: 'spki' });

            const sEphX = crypto.generateKeyPairSync('x25519');
            const ssX = crypto.diffieHellman({ privateKey: sEphX.privateKey, publicKey: cEphX });
            const enc768 = crypto.encapsulate(cEph768);
            const enc1024 = crypto.encapsulate(cEph1024);
            const serverNonce = crypto.randomBytes(32);

            let kItOpt = null;
            if (ch.psiPadRef) {
              if (!padPoolPath) throw new Error('Client requested PSI pad but server has no pad pool');
              kItOpt = consumePadAtOffset(padPoolPath, ch.psiPadRef.padId, ch.psiPadRef.offset, 32);
            }

            const shBody = {
              type: 'SERVER_HELLO',
              pub: serializePublicBundle(identity.pub),
              ephX25519PubB64: sEphX.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
              ctMlKem768B64: enc768.ciphertext.toString('base64'),
              ctMlKem1024B64: enc1024.ciphertext.toString('base64'),
              serverNonceB64: serverNonce.toString('base64'),
              psiUsed: !!kItOpt,
            };
            const shBodyBytes = Buffer.from(JSON.stringify(shBody), 'utf8');
            const transcript1 = sha3(['SecMesh-PQSI-v3|HS1|', frame, shBodyBytes]);
            const sigs = compositeSignV3(identity, transcript1);
            const shFull = Buffer.from(JSON.stringify({ ...shBody, sigs }), 'utf8');
            const transcript2 = sha3(['SecMesh-PQSI-v3|HS2|', frame, shFull]);

            const rootKey = dualSurvivabilityCombine({
              kX25519: ssX,
              kMlKem: Buffer.concat([enc768.sharedKey, enc1024.sharedKey]),
              kItOpt,
              transcriptBuf: transcript2,
            });
            ssX.fill(0);
            enc768.sharedKey.fill(0);
            enc1024.sharedKey.fill(0);
            if (kItOpt) kItOpt.fill(0);

            hsState = { clientPub, transcript2, rootKey };
            phase = 'WAIT_CLIENT_FINISH';
            sock.write(encodeWireFrame(shFull));
          } else if (phase === 'WAIT_CLIENT_FINISH') {
            const cf = JSON.parse(frame.toString('utf8'));
            if (cf.type !== 'CLIENT_FINISH') throw new Error('Expected CLIENT_FINISH');
            if (!compositeVerifyV3(hsState.clientPub, hsState.transcript2, cf.sigs)) {
              if (firewall) firewall.reportIncident(remoteIp, 'bad-client-sig');
              throw new Error('Client composite signature INVALID');
            }
            const expectedMac = sha3(['SecMesh-PQSI-v3|ClientConfirm|', hsState.rootKey, hsState.transcript2]);
            const gotMac = Buffer.from(cf.confirmMacB64, 'base64');
            if (gotMac.length !== 32 || !crypto.timingSafeEqual(expectedMac, gotMac)) {
              throw new Error('Client key-confirmation MAC INVALID');
            }

            const ratchet = new PqDoubleRatchetSession({
              rootKey32: hsState.rootKey,
              role: 'responder',
              transcriptHash32: hsState.transcript2,
              rekeyAfterPackets,
              ctCoprocessor,
            });
            hsState.rootKey.fill(0);
            session = new PqsiTcpSession(sock, ratchet, hsState.clientPub, {
              onMessage,
              onTunnelOpen: (meta, sess) => {
                const targetSpec = `${meta.targetHost}:${meta.targetPort}`;
                if (allowedTunnelTargets.length > 0 && !allowedTunnelTargets.includes(targetSpec)) {
                  const closeBuf = Buffer.alloc(4);
                  closeBuf.writeUInt32BE(meta.tunnelId, 0);
                  sess.sendCell(CELL_TYPE.TUNNEL_CLOSE, closeBuf).catch(() => {});
                  return;
                }
                const targetSock = net.createConnection({ host: meta.targetHost, port: meta.targetPort });
                sess.tunnels.set(meta.tunnelId, targetSock);
                targetSock.on('data', (chunk) => {
                  const hdr = Buffer.alloc(4);
                  hdr.writeUInt32BE(meta.tunnelId, 0);
                  sess.sendCell(CELL_TYPE.TUNNEL_DATA, Buffer.concat([hdr, chunk])).catch(() => {});
                });
                const cleanup = () => {
                  sess.tunnels.delete(meta.tunnelId);
                  const hdr = Buffer.alloc(4);
                  hdr.writeUInt32BE(meta.tunnelId, 0);
                  sess.sendCell(CELL_TYPE.TUNNEL_CLOSE, hdr).catch(() => {});
                };
                targetSock.on('end', cleanup);
                targetSock.on('error', cleanup);
              },
            });
            activeSessions.add(session);
            phase = 'ESTABLISHED';
            const sf = Buffer.from(JSON.stringify({
              type: 'SERVER_FINISH',
              confirmMacB64: sha3(['SecMesh-PQSI-v3|ServerConfirm|', ratchet.rootKey, hsState.transcript2]).toString('base64'),
            }), 'utf8');
            sock.write(encodeWireFrame(sf));
            if (onSession) onSession(session);
          }
        } catch {
          if (hsState && hsState.rootKey) hsState.rootKey.fill(0);
          sock.destroy();
        }
      },
    });

    sock.on('data', (chunk) => framer.push(chunk));
    sock.on('close', () => {
      activeSockets.delete(sock);
      if (session) { session.close(); activeSessions.delete(session); }
    });
    sock.on('error', () => { sock.destroy(); });
  });

  return {
    start() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          resolve({ host, port: server.address().port });
        });
      });
    },
    async stop() {
      for (const s of activeSessions) s.close();
      activeSessions.clear();
      for (const s of activeSockets) { try { s.destroy(); } catch { /* ignore */ } }
      activeSockets.clear();
      await new Promise((r) => server.close(() => r()));
    },
  };
}

export function connectPqsiTcpClient({
  identity,
  trustStore,
  host = '127.0.0.1',
  port,
  padPoolPath = null,
  ctCoprocessor = null,
  rekeyAfterPackets = 1000,
  onMessage = null,
}) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host, port });
    let phase = 'WAIT_SERVER_HELLO';
    let chBytes = null;
    let cEphX = null, cEph768 = null, cEph1024 = null;
    let kItOpt = null;
    let hsState = null;
    let session = null;

    const fail = (err) => {
      if (kItOpt) kItOpt.fill(0);
      if (hsState && hsState.rootKey) hsState.rootKey.fill(0);
      sock.destroy();
      reject(err);
    };

    const framer = new LengthPrefixedFramer({
      onError: fail,
      onFrame: (frame) => {
        if (phase === 'ESTABLISHED' && session) {
          session.handleEncryptedFrame(frame);
          return;
        }
        try {
          if (phase === 'WAIT_SERVER_HELLO') {
            const sh = JSON.parse(frame.toString('utf8'));
            if (sh.type !== 'SERVER_HELLO') throw new Error('Expected SERVER_HELLO');
            const pin = trustStore.verifyPinnedPeer(sh.pub);
            if (!pin.ok) throw new Error(`Server trust check failed: ${pin.reason}`);
            const serverPub = deserializePublicBundle(sh.pub);

            const { sigs, ...shBody } = sh;
            const shBodyBytes = Buffer.from(JSON.stringify(shBody), 'utf8');
            const transcript1 = sha3(['SecMesh-PQSI-v3|HS1|', chBytes, shBodyBytes]);
            if (!compositeVerifyV3(serverPub, transcript1, sigs)) {
              throw new Error('Server composite signature INVALID');
            }
            const transcript2 = sha3(['SecMesh-PQSI-v3|HS2|', chBytes, frame]);

            const sEphX = crypto.createPublicKey({ key: Buffer.from(sh.ephX25519PubB64, 'base64'), format: 'der', type: 'spki' });
            const ssX = crypto.diffieHellman({ privateKey: cEphX.privateKey, publicKey: sEphX });
            const ss768 = crypto.decapsulate(cEph768.privateKey, Buffer.from(sh.ctMlKem768B64, 'base64'));
            const ss1024 = crypto.decapsulate(cEph1024.privateKey, Buffer.from(sh.ctMlKem1024B64, 'base64'));

            const rootKey = dualSurvivabilityCombine({
              kX25519: ssX,
              kMlKem: Buffer.concat([ss768, ss1024]),
              kItOpt,
              transcriptBuf: transcript2,
            });
            ssX.fill(0); ss768.fill(0); ss1024.fill(0);
            if (kItOpt) { kItOpt.fill(0); kItOpt = null; }

            const cfSigs = compositeSignV3(identity, transcript2);
            const confirmMac = sha3(['SecMesh-PQSI-v3|ClientConfirm|', rootKey, transcript2]);
            hsState = { serverPub, transcript2, rootKey };
            phase = 'WAIT_SERVER_FINISH';
            sock.write(encodeWireFrame(Buffer.from(JSON.stringify({
              type: 'CLIENT_FINISH',
              sigs: cfSigs,
              confirmMacB64: confirmMac.toString('base64'),
            }), 'utf8')));
          } else if (phase === 'WAIT_SERVER_FINISH') {
            const sf = JSON.parse(frame.toString('utf8'));
            if (sf.type !== 'SERVER_FINISH') throw new Error('Expected SERVER_FINISH');
            const expectedMac = sha3(['SecMesh-PQSI-v3|ServerConfirm|', hsState.rootKey, hsState.transcript2]);
            const gotMac = Buffer.from(sf.confirmMacB64, 'base64');
            if (gotMac.length !== 32 || !crypto.timingSafeEqual(expectedMac, gotMac)) {
              throw new Error('Server key-confirmation MAC INVALID');
            }
            const ratchet = new PqDoubleRatchetSession({
              rootKey32: hsState.rootKey,
              role: 'initiator',
              transcriptHash32: hsState.transcript2,
              rekeyAfterPackets,
              ctCoprocessor,
            });
            hsState.rootKey.fill(0);
            session = new PqsiTcpSession(sock, ratchet, hsState.serverPub, { onMessage });
            phase = 'ESTABLISHED';
            resolve(session);
          }
        } catch (err) {
          fail(err);
        }
      },
    });

    sock.on('connect', () => {
      try {
        cEphX = crypto.generateKeyPairSync('x25519');
        cEph768 = crypto.generateKeyPairSync('ml-kem-768');
        cEph1024 = crypto.generateKeyPairSync('ml-kem-1024');
        let psiPadRef = null;
        if (padPoolPath) {
          const sl = consumePadSlice(padPoolPath, 32, 'tcp-handshake');
          kItOpt = sl.bytes;
          psiPadRef = { padId: sl.padId, offset: sl.offset, length: 32 };
        }
        chBytes = Buffer.from(JSON.stringify({
          type: 'CLIENT_HELLO',
          pub: serializePublicBundle(identity.pub),
          ephX25519PubB64: cEphX.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
          ephMlKem768PubB64: cEph768.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
          ephMlKem1024PubB64: cEph1024.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
          clientNonceB64: crypto.randomBytes(32).toString('base64'),
          psiPadRef,
        }), 'utf8');
        sock.write(encodeWireFrame(chBytes));
      } catch (err) {
        fail(err);
      }
    });
    sock.on('data', (chunk) => framer.push(chunk));
    sock.on('close', () => { if (phase !== 'ESTABLISHED') fail(new Error('TCP socket closed during handshake')); });
    sock.on('error', (err) => { if (phase !== 'ESTABLISHED') fail(err); });
  });
}

// ============================================================================
// 2. Real Encrypted TCP Port-Forwarding Tunnel (PQ+PSI `ssh -L`)
// ============================================================================
export function createPqsiTcpPortForward({
  session,
  localHost = '127.0.0.1',
  localPort = 0,
  targetHost,
  targetPort,
}) {
  let nextTid = 1;
  const localSockets = new Set();
  const listener = net.createServer((clientSock) => {
    const tid = nextTid++;
    localSockets.add(clientSock);
    session.tunnels.set(tid, clientSock);
    session.sendCell(
      CELL_TYPE.TUNNEL_OPEN,
      Buffer.from(JSON.stringify({ tunnelId: tid, targetHost, targetPort }), 'utf8'),
    ).catch(() => clientSock.destroy());

    clientSock.on('data', (chunk) => {
      const hdr = Buffer.alloc(4);
      hdr.writeUInt32BE(tid, 0);
      session.sendCell(CELL_TYPE.TUNNEL_DATA, Buffer.concat([hdr, chunk])).catch(() => clientSock.destroy());
    });
    const cleanup = () => {
      localSockets.delete(clientSock);
      session.tunnels.delete(tid);
      const hdr = Buffer.alloc(4);
      hdr.writeUInt32BE(tid, 0);
      session.sendCell(CELL_TYPE.TUNNEL_CLOSE, hdr).catch(() => {});
    };
    clientSock.on('end', cleanup);
    clientSock.on('error', cleanup);
  });

  return {
    start() {
      return new Promise((resolve, reject) => {
        listener.once('error', reject);
        listener.listen(localPort, localHost, () => {
          listener.off('error', reject);
          resolve({ host: localHost, port: listener.address().port });
        });
      });
    },
    async stop() {
      for (const s of localSockets) { try { s.destroy(); } catch { /* ignore */ } }
      localSockets.clear();
      await new Promise((r) => listener.close(() => r()));
    },
  };
}

// ============================================================================
// 3. True 3-Hop Onion-Artichoke Circuit Router (Client -> Relay1 -> Relay2 -> Exit)
//    Each hop peels ONLY its own X25519 + ML-KEM-768 + Dual-AEAD (AES-GCM + ChaCha20) skin.
//    Relay 1 sees origin + Relay 2 only; Relay 2 sees Relay 1 + Exit only; Exit sees plaintext!
// ============================================================================
function wrapOnionSkin(hopPubObj, innerPayloadObj) {
  const hopPub = deserializePublicBundle(hopPubObj);
  const ephX = crypto.generateKeyPairSync('x25519');
  const hopXKey = crypto.createPublicKey({ key: hopPub.x25519Pub, format: 'der', type: 'spki' });
  const hopKemKey = crypto.createPublicKey({ key: hopPub.mlkem768Pub, format: 'der', type: 'spki' });
  const ssX = crypto.diffieHellman({ privateKey: ephX.privateKey, publicKey: hopXKey });
  const enc = crypto.encapsulate(hopKemKey);
  const ephXPubDer = ephX.publicKey.export({ type: 'spki', format: 'der' });
  const aad = Buffer.from(`SecMesh-PQSI-v3|OnionSkin|${hopPub.fingerprint}`, 'utf8');
  const skinKey = dualSurvivabilityCombine({
    kX25519: ssX,
    kMlKem: enc.sharedKey,
    kItOpt: null,
    transcriptBuf: Buffer.concat([aad, ephXPubDer, enc.ciphertext]),
  });
  const innerBytes = packFixedCell(CELL_TYPE.ONION_HOP, Buffer.from(JSON.stringify(innerPayloadObj), 'utf8'), 1024);
  try {
    const sealed = doubleAeadSeal(skinKey, innerBytes, aad, 'onion-skin');
    return {
      hopFp: hopPub.fingerprint,
      ephX25519PubB64: ephXPubDer.toString('base64'),
      ctMlKem768B64: enc.ciphertext.toString('base64'),
      ivAesB64: sealed.ivAes.toString('base64'),
      tagAesB64: sealed.tagAes.toString('base64'),
      ivChaChaB64: sealed.ivChaCha.toString('base64'),
      tagChaChaB64: sealed.tagChaCha.toString('base64'),
      ciphertextB64: sealed.ciphertext.toString('base64'),
    };
  } finally {
    ssX.fill(0);
    enc.sharedKey.fill(0);
    skinKey.fill(0);
    innerBytes.fill(0);
  }
}

function peelOnionSkin(myIdentity, skinObj) {
  const myFp = computePublicBundleFingerprint(myIdentity.pub);
  if (skinObj.hopFp !== myFp) throw new Error('ONION_HOP_FINGERPRINT_MISMATCH');
  const ephXPubDer = Buffer.from(skinObj.ephX25519PubB64, 'base64');
  const ctKem = Buffer.from(skinObj.ctMlKem768B64, 'base64');
  const ephXKey = crypto.createPublicKey({ key: ephXPubDer, format: 'der', type: 'spki' });
  const ssX = crypto.diffieHellman({ privateKey: myIdentity.priv.x25519, publicKey: ephXKey });
  const ssKem = crypto.decapsulate(myIdentity.priv.mlkem768, ctKem);
  const aad = Buffer.from(`SecMesh-PQSI-v3|OnionSkin|${myFp}`, 'utf8');
  const skinKey = dualSurvivabilityCombine({
    kX25519: ssX,
    kMlKem: ssKem,
    kItOpt: null,
    transcriptBuf: Buffer.concat([aad, ephXPubDer, ctKem]),
  });
  let cellBuf = null;
  try {
    cellBuf = doubleAeadOpen(skinKey, {
      ivAes: Buffer.from(skinObj.ivAesB64, 'base64'),
      tagAes: Buffer.from(skinObj.tagAesB64, 'base64'),
      ivChaCha: Buffer.from(skinObj.ivChaChaB64, 'base64'),
      tagChaCha: Buffer.from(skinObj.tagChaChaB64, 'base64'),
      ciphertext: Buffer.from(skinObj.ciphertextB64, 'base64'),
    }, aad, 'onion-skin');
    const { payload } = unpackFixedCell(cellBuf);
    return JSON.parse(payload.toString('utf8'));
  } finally {
    ssX.fill(0);
    ssKem.fill(0);
    skinKey.fill(0);
    if (cellBuf) cellBuf.fill(0);
  }
}

export function createOnionRelayNode({ identity, host = '127.0.0.1', port = 0, onExitMessage = null }) {
  const seenNonces = new Set();
  const auditLog = [];
  const server = net.createServer((sock) => {
    const framer = new LengthPrefixedFramer({
      onError: () => sock.destroy(),
      onFrame: (frame) => {
        try {
          const skin = JSON.parse(frame.toString('utf8'));
          const inner = peelOnionSkin(identity, skin);
          if (!inner.nonce || seenNonces.has(inner.nonce)) {
            throw new Error('ONION_REPLAY_REJECTED');
          }
          if (typeof inner.ts === 'number' && Math.abs(Date.now() - inner.ts) > 300000) {
            throw new Error('ONION_STALE_TIMESTAMP');
          }
          seenNonces.add(inner.nonce);
          while (seenNonces.size > 8192) {
            seenNonces.delete(seenNonces.values().next().value);
          }

          if (inner.action === 'FORWARD') {
            // Relay ONLY sees nextHost:nextPort and opaque nextSkin — NEVER plaintext or final target!
            auditLog.push({ action: 'FORWARD', nextHost: inner.nextHost, nextPort: inner.nextPort, sawPlaintext: false });
            const fwd = net.createConnection({ host: inner.nextHost, port: inner.nextPort });
            const fwdFramer = new LengthPrefixedFramer({
              onError: () => { fwd.destroy(); sock.destroy(); },
              onFrame: (replyFrame) => {
                // Wrap return reply in this hop's ephemeral reply layer!
                const rKey = Buffer.from(inner.replyKeyB64, 'base64');
                const aad = Buffer.from(`SecMesh-PQSI-v3|OnionReply|${inner.nonce}`, 'utf8');
                const sealed = doubleAeadSeal(rKey, replyFrame, aad, 'onion-reply');
                rKey.fill(0);
                sock.write(encodeWireFrame(Buffer.from(JSON.stringify({
                  ivAesB64: sealed.ivAes.toString('base64'),
                  tagAesB64: sealed.tagAes.toString('base64'),
                  ivChaChaB64: sealed.ivChaCha.toString('base64'),
                  tagChaChaB64: sealed.tagChaCha.toString('base64'),
                  ciphertextB64: sealed.ciphertext.toString('base64'),
                }), 'utf8')));
                fwd.end();
              },
            });
            fwd.on('connect', () => {
              fwd.write(encodeWireFrame(Buffer.from(JSON.stringify(inner.nextSkin), 'utf8')));
            });
            fwd.on('data', (d) => fwdFramer.push(d));
            fwd.on('error', () => sock.destroy());
          } else if (inner.action === 'EXIT') {
            const plain = Buffer.from(inner.payloadB64, 'base64');
            auditLog.push({ action: 'EXIT', bytes: plain.length, sawPlaintext: true });
            const replyPlain = onExitMessage
              ? Buffer.from(onExitMessage(plain, inner.senderNodeId))
              : Buffer.from(`EXIT_ACK:${plain.toString('utf8')}`, 'utf8');
            const rKey = Buffer.from(inner.replyKeyB64, 'base64');
            const aad = Buffer.from(`SecMesh-PQSI-v3|OnionReply|${inner.nonce}`, 'utf8');
            const sealed = doubleAeadSeal(rKey, replyPlain, aad, 'onion-reply');
            rKey.fill(0);
            sock.write(encodeWireFrame(Buffer.from(JSON.stringify({
              ivAesB64: sealed.ivAes.toString('base64'),
              tagAesB64: sealed.tagAes.toString('base64'),
              ivChaChaB64: sealed.ivChaCha.toString('base64'),
              tagChaChaB64: sealed.tagChaCha.toString('base64'),
              ciphertextB64: sealed.ciphertext.toString('base64'),
            }), 'utf8')));
          } else {
            sock.destroy();
          }
        } catch {
          sock.destroy();
        }
      },
    });
    sock.on('data', (d) => framer.push(d));
    sock.on('error', () => sock.destroy());
  });

  return {
    auditLog,
    start() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          resolve({ host, port: server.address().port });
        });
      });
    },
    stop() {
      return new Promise((r) => server.close(() => r()));
    },
  };
}

/**
 * Send a message through an arbitrary N-hop Onion-Artichoke circuit (e.g. 3 hops: Relay1 -> Relay2 -> Exit)
 * and peel all N nested reply skins on return!
 */
export function sendOnionCircuitMessage({ hops, senderNodeId, payloadBuf }) {
  if (!Array.isArray(hops) || hops.length < 2) {
    throw new Error('Onion circuit requires at least 2 hops (3+ recommended)');
  }
  const plain = Buffer.isBuffer(payloadBuf) ? payloadBuf : Buffer.from(String(payloadBuf), 'utf8');
  const hopMeta = hops.map(() => ({
    nonce: crypto.randomBytes(16).toString('hex'),
    replyKey: crypto.randomBytes(32),
  }));

  // Build innermost skin (Exit) outward to Entry Relay 1
  const nowTs = Date.now();
  const last = hops.length - 1;
  let skin = wrapOnionSkin(hops[last].pub, {
    action: 'EXIT',
    nonce: hopMeta[last].nonce,
    ts: nowTs,
    replyKeyB64: hopMeta[last].replyKey.toString('base64'),
    senderNodeId,
    payloadB64: plain.toString('base64'),
  });
  for (let i = last - 1; i >= 0; i--) {
    skin = wrapOnionSkin(hops[i].pub, {
      action: 'FORWARD',
      nonce: hopMeta[i].nonce,
      ts: nowTs,
      replyKeyB64: hopMeta[i].replyKey.toString('base64'),
      nextHost: hops[i + 1].host,
      nextPort: hops[i + 1].port,
      nextSkin: skin,
    });
  }

  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host: hops[0].host, port: hops[0].port });
    const framer = new LengthPrefixedFramer({
      onError: (err) => { sock.destroy(); reject(err); },
      onFrame: (replyFrame) => {
        try {
          let cur = replyFrame;
          // Peel reply skins from Entry (hop 0) inward to Exit (hop last)
          for (let i = 0; i < hops.length; i++) {
            const env = JSON.parse(cur.toString('utf8'));
            const aad = Buffer.from(`SecMesh-PQSI-v3|OnionReply|${hopMeta[i].nonce}`, 'utf8');
            cur = doubleAeadOpen(hopMeta[i].replyKey, {
              ivAes: Buffer.from(env.ivAesB64, 'base64'),
              tagAes: Buffer.from(env.tagAesB64, 'base64'),
              ivChaCha: Buffer.from(env.ivChaChaB64, 'base64'),
              tagChaCha: Buffer.from(env.tagChaChaB64, 'base64'),
              ciphertext: Buffer.from(env.ciphertextB64, 'base64'),
            }, aad, 'onion-reply');
          }
          for (const hm of hopMeta) hm.replyKey.fill(0);
          sock.end();
          resolve(cur);
        } catch (err) {
          for (const hm of hopMeta) hm.replyKey.fill(0);
          sock.destroy();
          reject(err);
        }
      },
    });
    sock.on('connect', () => sock.write(encodeWireFrame(Buffer.from(JSON.stringify(skin), 'utf8'))));
    sock.on('data', (d) => framer.push(d));
    sock.on('error', (err) => { for (const hm of hopMeta) hm.replyKey.fill(0); reject(err); });
  });
}
