// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — Level 3 Encrypted UDP Layer-3 Mesh VPN, Cookie Anti-DoS,
// NAT Traversal/Roaming & RFC 791 IPv4 AllowedIPs Cryptokey Router
//
// Features:
//   - WireGuard-style stateless DoS cookie challenge (MAC1/Cookie) blocking spoofed UDP floods
//     BEFORE spending CPU on ML-KEM / ML-DSA / SLH-DSA or allocating session state.
//   - Authenticated Triple-KEM PQ+PSI UDP session + Double-Ratchet per datagram (supports out-of-order!).
//   - NAT Keepalive beacons & seamless authenticated Endpoint Roaming (survives client NAT port changes!).
//   - Real RFC 791 IPv4 packet builder/validator with AllowedIPs anti-spoofing cryptokey routing,
//     integrating cleanly with native `secmesh_core tun-probe` (Linux `/dev/net/tun` / Windows `wintun.dll`)
//     and full userspace virtual L3 mesh switching.

import crypto from 'node:crypto';
import dgram from 'node:dgram';
import { execFileSync } from 'node:child_process';
import { dualSurvivabilityCombine } from './pqsi-handshake.mjs';
import {
  serializePublicBundle,
  deserializePublicBundle,
  compositeSignV3,
  compositeVerifyV3,
} from './secmesh-trust.mjs';
import { PqDoubleRatchetSession } from './secmesh-ratchet.mjs';
import { resolveNativeCoreBinary } from './native-ct-bridge.mjs';

const UDP_MSG = Object.freeze({
  INIT: 0x10,
  COOKIE_REPLY: 0x11,
  RESP: 0x12,
  DATA: 0x13,
  KEEPALIVE: 0x14,
});

// ============================================================================
// 1. RFC 791 IPv4 Packet Construction, Checksum & AllowedIPs Cryptokey Validation
// ============================================================================
export function ipv4ToBytes(ipStr) {
  const parts = String(ipStr).split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    throw new Error(`Invalid IPv4 address: ${ipStr}`);
  }
  return Buffer.from(parts);
}

export function bytesToIpv4(buf, off = 0) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

export function computeIpv4HeaderChecksum(hdr20) {
  let sum = 0;
  for (let i = 0; i < 20; i += 2) {
    if (i === 10) continue;
    sum += hdr20.readUInt16BE(i);
  }
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return (~sum) & 0xFFFF;
}

export function buildIpv4Packet({ srcIp, dstIp, protocol = 17, ttl = 64, payload = Buffer.alloc(0) }) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const totalLen = 20 + body.length;
  if (totalLen > 65535) throw new Error('IPv4 packet exceeds 65535 bytes');
  const pkt = Buffer.alloc(totalLen);
  pkt[0] = 0x45; // IPv4, IHL=5 (20B)
  pkt[1] = 0x00;
  pkt.writeUInt16BE(totalLen, 2);
  pkt.writeUInt16BE(crypto.randomBytes(2).readUInt16BE(0), 4);
  pkt.writeUInt16BE(0x4000, 6); // Don't Fragment
  pkt[8] = ttl & 0xFF;
  pkt[9] = protocol & 0xFF;
  ipv4ToBytes(srcIp).copy(pkt, 12);
  ipv4ToBytes(dstIp).copy(pkt, 16);
  pkt.writeUInt16BE(computeIpv4HeaderChecksum(pkt), 10);
  body.copy(pkt, 20);
  return pkt;
}

export function parseAndVerifyIpv4Packet(pkt) {
  if (!Buffer.isBuffer(pkt) || pkt.length < 20) return { ok: false, reason: 'short-ipv4' };
  const ver = pkt[0] >> 4;
  const ihl = (pkt[0] & 0x0F) * 4;
  if (ver !== 4 || ihl < 20 || ihl > pkt.length) return { ok: false, reason: 'bad-ipv4-ihl' };
  const totalLen = pkt.readUInt16BE(2);
  if (totalLen < ihl || totalLen > pkt.length) return { ok: false, reason: 'bad-ipv4-len' };
  // Verify full header checksum (RFC 791: 1s-complement sum including checksum field == 0xFFFF -> ~sum == 0)
  let sum = 0;
  for (let i = 0; i < ihl; i += 2) sum += pkt.readUInt16BE(i);
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  if (((~sum) & 0xFFFF) !== 0) return { ok: false, reason: 'bad-ipv4-checksum' };
  return {
    ok: true,
    version: 4,
    ihl,
    totalLen,
    ttl: pkt[8],
    protocol: pkt[9],
    srcIp: bytesToIpv4(pkt, 12),
    dstIp: bytesToIpv4(pkt, 16),
    payload: Buffer.from(pkt.subarray(ihl, totalLen)),
  };
}

export function probeOsTunDriver() {
  const bin = resolveNativeCoreBinary();
  try {
    const out = execFileSync(bin, ['tun-probe'], { encoding: 'utf8' });
    return JSON.parse(out.trim());
  } catch (err) {
    return { supported_os: false, driver_available: false, has_privilege: false, backend: 'unavailable', detail: err.message };
  }
}

// ============================================================================
// 2. UDP Encrypted Mesh VPN Endpoint (Stateless Cookie DoS + NAT Roaming + L3)
// ============================================================================
function sha3(parts) {
  const h = crypto.createHash('sha3-256');
  for (const p of parts) h.update(Buffer.isBuffer(p) ? p : Buffer.from(p));
  return h.digest();
}

export class UdpMeshVpnNode {
  constructor({
    identity,
    trustStore,
    tunnelIp,                  // e.g. '10.99.0.1'
    allowedPeerIps = new Map(), // peerNodeId -> Set(['10.99.0.2'])
    host = '127.0.0.1',
    port = 0,
    requireCookie = true,       // WireGuard-style stateless DoS cookie enforcement!
    firewall = null,
    ctCoprocessor = null,
    onL3Packet = null,
  }) {
    this.identity = identity;
    this.trustStore = trustStore;
    this.tunnelIp = tunnelIp;
    this.allowedPeerIps = allowedPeerIps;
    this.host = host;
    this.port = port;
    this.requireCookie = requireCookie;
    this.firewall = firewall;
    this.ctCoprocessor = ctCoprocessor;
    this.onL3Packet = onL3Packet;

    this.cookieSecret = crypto.randomBytes(32);
    this.prevCookieSecret = Buffer.alloc(32);
    this.cookieEpoch = Math.floor(Date.now() / 120000);
    this.maxSessions = 4096;
    this.maxPendingInits = 1024;
    this.sessions = new Map();       // sidHex -> { ratchet, peerNodeId, peerPub, endpoint: { address, port }, roamedCount, keepalivesRx }
    this.peerToSid = new Map();      // peerNodeId -> sidHex
    this.pendingInits = new Map();   // nonceHex -> { resolve, reject, ... }
    this.stats = {
      cookiesIssued: 0,
      cookiesRejected: 0,
      handshakesCompleted: 0,
      l3PacketsRx: 0,
      l3PacketsTx: 0,
      spoofedSourceDropped: 0,
      keepalivesRx: 0,
      roamingEvents: 0,
    };
    this.socket = dgram.createSocket('udp4');
    this.socket.on('message', (msg, rinfo) => {
      this._onDatagram(msg, rinfo).catch(() => {});
    });
  }

  _rotateCookieSecretIfNeeded() {
    const curEpoch = Math.floor(Date.now() / 120000);
    if (curEpoch !== this.cookieEpoch) {
      this.prevCookieSecret.fill(0);
      this.prevCookieSecret = this.cookieSecret;
      this.cookieSecret = crypto.randomBytes(32);
      this.cookieEpoch = curEpoch;
    }
  }

  _computeCookie(address, port, secret = this.cookieSecret) {
    return sha3(['SecMesh-PQSI-v3|UDPCookie|', secret, `${address}:${port}`]).subarray(0, 16);
  }

  _verifyCookie(got, address, port) {
    this._rotateCookieSecretIfNeeded();
    if (!got || got.length !== 16) return false;
    const cur = this._computeCookie(address, port, this.cookieSecret);
    if (crypto.timingSafeEqual(cur, got)) return true;
    const prev = this._computeCookie(address, port, this.prevCookieSecret);
    return crypto.timingSafeEqual(prev, got);
  }

  start() {
    return new Promise((resolve, reject) => {
      this.socket.once('error', reject);
      this.socket.bind(this.port, this.host, () => {
        this.socket.off('error', reject);
        const addr = this.socket.address();
        this.boundPort = addr.port;
        resolve({ host: addr.address, port: addr.port, tunnelIp: this.tunnelIp });
      });
    });
  }

  stop() {
    for (const s of this.sessions.values()) s.ratchet.destroy();
    this.sessions.clear();
    this.cookieSecret.fill(0);
    this.prevCookieSecret.fill(0);
    return new Promise((resolve) => this.socket.close(() => resolve()));
  }

  _sendUdp(buf, address, port) {
    return new Promise((resolve, reject) => {
      this.socket.send(buf, port, address, (err) => (err ? reject(err) : resolve()));
    });
  }

  async _onDatagram(msg, rinfo) {
    if (!Buffer.isBuffer(msg) || msg.length < 2) return;
    if (this.firewall && this.firewall.isBlocked(rinfo.address)) return;
    const type = msg[0];
    const body = msg.subarray(1);

    if (type === UDP_MSG.INIT) {
      if (this.sessions.size >= this.maxSessions) return; // fail-closed session cap
      const init = JSON.parse(body.toString('utf8'));
      this._rotateCookieSecretIfNeeded();
      const expectedCookie = this._computeCookie(rinfo.address, rinfo.port);
      if (this.requireCookie) {
        const got = init.cookieB64 ? Buffer.from(init.cookieB64, 'base64') : null;
        if (!this._verifyCookie(got, rinfo.address, rinfo.port)) {
          this.stats.cookiesIssued++;
          if (got && got.length > 0) {
            this.stats.cookiesRejected++;
            if (this.firewall) this.firewall.reportIncident(rinfo.address, 'udp-bad-cookie');
          }
          // Stateless cookie reply — zero RAM allocated, zero ML-KEM/SLH-DSA CPU spent!
          const reply = Buffer.concat([
            Buffer.from([UDP_MSG.COOKIE_REPLY]),
            Buffer.from(JSON.stringify({ nonce: init.nonce, cookieB64: expectedCookie.toString('base64') }), 'utf8'),
          ]);
          await this._sendUdp(reply, rinfo.address, rinfo.port);
          return;
        }
      }
      // Verify client identity against pinned TrustStore + composite signature
      const pin = this.trustStore.verifyPinnedPeer(init.pub);
      if (!pin.ok) {
        if (this.firewall) this.firewall.reportIncident(rinfo.address, `udp-trust-${pin.reason}`);
        return;
      }
      const clientPub = deserializePublicBundle(init.pub);
      const { sigs, ...initUnsigned } = init;
      const initDigest = sha3(['SecMesh-PQSI-v3|UDPInit|', Buffer.from(JSON.stringify(initUnsigned), 'utf8')]);
      if (!compositeVerifyV3(clientPub, initDigest, sigs)) {
        if (this.firewall) this.firewall.reportIncident(rinfo.address, 'udp-bad-sig');
        return;
      }

      // Complete Triple-KEM responder side (X25519 + ML-KEM-768 + ML-KEM-1024)
      const cEphX = crypto.createPublicKey({ key: Buffer.from(init.ephX25519PubB64, 'base64'), format: 'der', type: 'spki' });
      const cEph768 = crypto.createPublicKey({ key: Buffer.from(init.ephMlKem768PubB64, 'base64'), format: 'der', type: 'spki' });
      const cEph1024 = crypto.createPublicKey({ key: Buffer.from(init.ephMlKem1024PubB64, 'base64'), format: 'der', type: 'spki' });
      const sEphX = crypto.generateKeyPairSync('x25519');
      const ssX = crypto.diffieHellman({ privateKey: sEphX.privateKey, publicKey: cEphX });
      const enc768 = crypto.encapsulate(cEph768);
      const enc1024 = crypto.encapsulate(cEph1024);

      const sid = crypto.randomBytes(8);
      const sidHex = sid.toString('hex');
      const respUnsigned = {
        nonce: init.nonce,
        sidHex,
        pub: serializePublicBundle(this.identity.pub),
        ephX25519PubB64: sEphX.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        ctMlKem768B64: enc768.ciphertext.toString('base64'),
        ctMlKem1024B64: enc1024.ciphertext.toString('base64'),
      };
      const transcript = sha3(['SecMesh-PQSI-v3|UDPResp|', initDigest, Buffer.from(JSON.stringify(respUnsigned), 'utf8')]);
      const respSigs = compositeSignV3(this.identity, transcript);
      const rootKey = dualSurvivabilityCombine({
        kX25519: ssX,
        kMlKem: Buffer.concat([enc768.sharedKey, enc1024.sharedKey]),
        kItOpt: null,
        transcriptBuf: transcript,
      });
      ssX.fill(0); enc768.sharedKey.fill(0); enc1024.sharedKey.fill(0);

      const ratchet = new PqDoubleRatchetSession({
        rootKey32: rootKey,
        role: 'responder',
        transcriptHash32: transcript,
        ctCoprocessor: this.ctCoprocessor,
      });
      rootKey.fill(0);
      this.sessions.set(sidHex, {
        sid,
        sidHex,
        ratchet,
        peerNodeId: clientPub.nodeId,
        peerPub: clientPub,
        endpoint: { address: rinfo.address, port: rinfo.port },
        roamedCount: 0,
        keepalivesRx: 0,
      });
      this.peerToSid.set(clientPub.nodeId, sidHex);
      this.stats.handshakesCompleted++;

      const respBuf = Buffer.concat([
        Buffer.from([UDP_MSG.RESP]),
        Buffer.from(JSON.stringify({ ...respUnsigned, sigs: respSigs }), 'utf8'),
      ]);
      await this._sendUdp(respBuf, rinfo.address, rinfo.port);
      return;
    }

    if (type === UDP_MSG.COOKIE_REPLY) {
      const cr = JSON.parse(body.toString('utf8'));
      const pending = this.pendingInits.get(cr.nonce);
      if (pending && pending.onCookie) pending.onCookie(cr.cookieB64);
      return;
    }

    if (type === UDP_MSG.RESP) {
      const resp = JSON.parse(body.toString('utf8'));
      const pending = this.pendingInits.get(resp.nonce);
      if (!pending) return;
      try {
        const pin = this.trustStore.verifyPinnedPeer(resp.pub);
        if (!pin.ok) throw new Error(`UDP responder trust check failed: ${pin.reason}`);
        const serverPub = deserializePublicBundle(resp.pub);
        const { sigs, ...respUnsigned } = resp;
        const transcript = sha3(['SecMesh-PQSI-v3|UDPResp|', pending.initDigest, Buffer.from(JSON.stringify(respUnsigned), 'utf8')]);
        if (!compositeVerifyV3(serverPub, transcript, sigs)) {
          throw new Error('UDP responder composite signature INVALID');
        }
        const sEphX = crypto.createPublicKey({ key: Buffer.from(resp.ephX25519PubB64, 'base64'), format: 'der', type: 'spki' });
        const ssX = crypto.diffieHellman({ privateKey: pending.ephX.privateKey, publicKey: sEphX });
        const ss768 = crypto.decapsulate(pending.eph768.privateKey, Buffer.from(resp.ctMlKem768B64, 'base64'));
        const ss1024 = crypto.decapsulate(pending.eph1024.privateKey, Buffer.from(resp.ctMlKem1024B64, 'base64'));
        const rootKey = dualSurvivabilityCombine({
          kX25519: ssX,
          kMlKem: Buffer.concat([ss768, ss1024]),
          kItOpt: null,
          transcriptBuf: transcript,
        });
        ssX.fill(0); ss768.fill(0); ss1024.fill(0);

        const ratchet = new PqDoubleRatchetSession({
          rootKey32: rootKey,
          role: 'initiator',
          transcriptHash32: transcript,
          ctCoprocessor: this.ctCoprocessor,
        });
        rootKey.fill(0);
        const sid = Buffer.from(resp.sidHex, 'hex');
        const sess = {
          sid,
          sidHex: resp.sidHex,
          ratchet,
          peerNodeId: serverPub.nodeId,
          peerPub: serverPub,
          endpoint: { address: rinfo.address, port: rinfo.port },
          roamedCount: 0,
          keepalivesRx: 0,
        };
        this.sessions.set(resp.sidHex, sess);
        this.peerToSid.set(serverPub.nodeId, resp.sidHex);
        this.stats.handshakesCompleted++;
        this.pendingInits.delete(resp.nonce);
        pending.resolve(sess);
      } catch (err) {
        this.pendingInits.delete(resp.nonce);
        pending.reject(err);
      }
      return;
    }

    if (type === UDP_MSG.DATA || type === UDP_MSG.KEEPALIVE) {
      if (body.length < 8) return;
      const sidHex = body.subarray(0, 8).toString('hex');
      const sess = this.sessions.get(sidHex);
      if (!sess) return;
      try {
        const opened = await sess.ratchet.openPacket(body.subarray(8), { aadExtra: sess.sid });
        // Authenticated NAT Endpoint Roaming: ONLY update peer endpoint AFTER AEAD + CW-128 pass!
        if (sess.endpoint.address !== rinfo.address || sess.endpoint.port !== rinfo.port) {
          sess.endpoint = { address: rinfo.address, port: rinfo.port };
          sess.roamedCount++;
          this.stats.roamingEvents++;
        }
        if (type === UDP_MSG.KEEPALIVE) {
          sess.keepalivesRx++;
          this.stats.keepalivesRx++;
          return;
        }
        // RFC 791 IPv4 validation + WireGuard AllowedIPs anti-spoofing cryptokey routing!
        const parsed = parseAndVerifyIpv4Packet(opened.plaintext);
        if (!parsed.ok) {
          this.stats.spoofedSourceDropped++;
          return;
        }
        const allowed = this.allowedPeerIps.get(sess.peerNodeId);
        if (allowed && !allowed.has(parsed.srcIp)) {
          // Cryptokey routing violation: authenticated peer tried to spoof another node's IP!
          this.stats.spoofedSourceDropped++;
          if (this.firewall) this.firewall.reportIncident(rinfo.address, 'l3-ip-spoof');
          return;
        }
        this.stats.l3PacketsRx++;
        if (this.onL3Packet) this.onL3Packet(parsed, opened.plaintext, sess);
      } catch {
        if (this.firewall) this.firewall.reportIncident(rinfo.address, 'udp-auth-fail');
      }
    }
  }

  connectToPeer(remoteHost, remotePort) {
    return new Promise((resolve, reject) => {
      const nonce = crypto.randomBytes(16).toString('hex');
      const ephX = crypto.generateKeyPairSync('x25519');
      const eph768 = crypto.generateKeyPairSync('ml-kem-768');
      const eph1024 = crypto.generateKeyPairSync('ml-kem-1024');

      const sendInit = (cookieB64 = null) => {
        const initUnsigned = {
          nonce,
          cookieB64,
          pub: serializePublicBundle(this.identity.pub),
          ephX25519PubB64: ephX.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
          ephMlKem768PubB64: eph768.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
          ephMlKem1024PubB64: eph1024.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        };
        const initDigest = sha3(['SecMesh-PQSI-v3|UDPInit|', Buffer.from(JSON.stringify(initUnsigned), 'utf8')]);
        const sigs = compositeSignV3(this.identity, initDigest);
        const pending = this.pendingInits.get(nonce);
        if (pending) pending.initDigest = initDigest;
        const pkt = Buffer.concat([
          Buffer.from([UDP_MSG.INIT]),
          Buffer.from(JSON.stringify({ ...initUnsigned, sigs }), 'utf8'),
        ]);
        this._sendUdp(pkt, remoteHost, remotePort).catch(reject);
      };

      const timer = setTimeout(() => {
        this.pendingInits.delete(nonce);
        reject(new Error('UDP VPN handshake timeout'));
      }, 5000);
      timer.unref();

      this.pendingInits.set(nonce, {
        ephX,
        eph768,
        eph1024,
        initDigest: null,
        onCookie: (cookieB64) => sendInit(cookieB64),
        resolve: (sess) => { clearTimeout(timer); resolve(sess); },
        reject: (err) => { clearTimeout(timer); reject(err); },
      });

      sendInit(null);
    });
  }

  async sendL3Packet(peerNodeId, ipv4PacketBuf, { overrideSocket = null } = {}) {
    const sidHex = this.peerToSid.get(peerNodeId);
    if (!sidHex) throw new Error(`No established UDP VPN session for ${peerNodeId}`);
    const sess = this.sessions.get(sidHex);
    const sealed = await sess.ratchet.sealPacket(ipv4PacketBuf, { aadExtra: sess.sid });
    const dgramBuf = Buffer.concat([Buffer.from([UDP_MSG.DATA]), sess.sid, sealed]);
    this.stats.l3PacketsTx++;
    if (overrideSocket) {
      // Used to test real authenticated NAT port roaming from a new ephemeral UDP socket!
      await new Promise((res, rej) => overrideSocket.send(dgramBuf, sess.endpoint.port, sess.endpoint.address, (e) => (e ? rej(e) : res())));
    } else {
      await this._sendUdp(dgramBuf, sess.endpoint.address, sess.endpoint.port);
    }
  }

  async sendKeepalive(peerNodeId) {
    const sidHex = this.peerToSid.get(peerNodeId);
    if (!sidHex) throw new Error(`No session for ${peerNodeId}`);
    const sess = this.sessions.get(sidHex);
    const sealed = await sess.ratchet.sealPacket(Buffer.from('KA'), { aadExtra: sess.sid });
    const dgramBuf = Buffer.concat([Buffer.from([UDP_MSG.KEEPALIVE]), sess.sid, sealed]);
    await this._sendUdp(dgramBuf, sess.endpoint.address, sess.endpoint.port);
  }
}
