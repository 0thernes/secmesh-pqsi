// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v2 — Hardened Cyber-Defense Mesh Guardian
// Fixes all network/security bugs in BoogerCheeseOnRye/SecMesh mesh-guardian.mjs:
//   1. Binds loopback 127.0.0.1 by default (no accidental 0.0.0.0 exposure)
//   2. Removes wildcard Access-Control-Allow-Origin: * on control/status endpoints
//   3. Removes UDP reflection/amplification echo (tallies & drops instead of reflecting!)
//   4. Enforces strict MAX_FRAME_BYTES=65536 preventing OOM DoS
//   5. Never emits raw secret keys over HTTP telemetry (fingerprints & counts only)
//   6. Integrates the self-stabilizing health field (w_i, sigma_i, healing, preemption)

import net from 'node:net';
import dgram from 'node:dgram';
import http from 'node:http';
import crypto from 'node:crypto';
import { verifyCwFrame, createReplayWindow } from './pqsi-handshake.mjs';

export const MAX_FRAME_BYTES = 65536;

export class HealthFieldEngine {
  constructor({ nodeCount = 60, defenderCount = 6, firewall = 0.7, threat = 0.2 } = {}) {
    if (!Number.isInteger(nodeCount) || nodeCount < 1 || nodeCount > 100000) {
      throw new Error('HealthFieldEngine requires integer nodeCount in [1, 100000]');
    }
    if (!Number.isInteger(defenderCount) || defenderCount < 0) {
      throw new Error('HealthFieldEngine requires non-negative integer defenderCount');
    }
    if (!Number.isFinite(firewall) || firewall < 0 || firewall > 1) {
      throw new Error('HealthFieldEngine requires finite firewall in [0, 1]');
    }
    if (!Number.isFinite(threat) || threat < 0) {
      throw new Error('HealthFieldEngine requires finite non-negative threat');
    }
    this.nodeCount = nodeCount;
    this.defenderCount = defenderCount;
    this.firewall = firewall;
    this.threat = threat;
    this.nodes = Array.from({ length: nodeCount }, (_, i) => ({
      id: `node-${i}`,
      health: 1.0,
      stress: 0.0,
      compromised: false,
    }));
    this.stepCount = 0;
    this.intrusions = 0;
    this.blocked = 0;
  }

  /**
   * Deterministic single policy-interval update with injectable uniform RNG [0,1).
   */
  step(rng) {
    this.stepCount++;
    const ambientAttackers = Math.round(this.threat * 30);
    const wave = this.stepCount % 100 === 0 ? 40 : 0;
    let attackers = ambientAttackers + wave;

    // Defender fleet preemption (firewall-gated p_kill = 0.35 * phi)
    const pKill = 0.35 * this.firewall;
    const contacts = Math.min(attackers, this.defenderCount * 4);
    for (let k = 0; k < contacts; k++) {
      if (rng() < pKill) {
        attackers--;
        this.blocked++;
      }
    }

    // Surviving attackers hit random nodes
    const ef = 0.03 * (this.threat + 0.2) * (1.5 - this.firewall);
    for (let a = 0; a < attackers; a++) {
      const idx = Math.floor(rng() * this.nodeCount);
      const n = this.nodes[idx];
      n.stress += ef;
      n.health = Math.max(0.05, n.health - ef);
      if (!n.compromised && n.health < 0.30) {
        n.compromised = true;
        this.intrusions++;
      }
    }

    // Continuous self-stabilizing healing field + exponential stress decay
    const pHeal = 0.05 * this.firewall;
    let degradedNow = 0;
    for (const n of this.nodes) {
      n.stress *= 0.995;
      if (n.health < 1.0 && rng() < pHeal) {
        n.health = Math.min(1.0, n.health + 0.03);
      }
      if (n.compromised && n.health > 0.55) {
        n.compromised = false;
      }
      if (n.compromised) degradedNow++;
    }
    return {
      step: this.stepCount,
      degradedNow,
      intrusions: this.intrusions,
      blocked: this.blocked,
      peakStress: Math.max(...this.nodes.map(n => n.stress)),
      minHealth: Math.min(...this.nodes.map(n => n.health)),
    };
  }
}

export function createHardenedGuardian({
  host = '127.0.0.1',
  listenPort = 0,
  statusPort = 0,
  udpEnabled = false,
  rateLimitPerSec = 40,
  maxLiveConns = 64,
  idleMs = 6000,
  allowedOrigin = 'http://127.0.0.1',
  cwControlKey = null,
} = {}) {
  const state = {
    startedAt: Date.now(),
    accepted: 0,
    blocked: 0,
    byVector: {},
    recent: [],
  };
  const rates = new Map();
  const MAX_TRACKED_IPS = 4096;
  const seenCwSeqs = createReplayWindow(4096n);
  const activeTcpSockets = new Set();
  let liveConns = 0;

  const record = (vector, src, blocked, detail) => {
    state.recent.unshift({ t: Date.now(), vector, src, blocked: !!blocked, detail });
    if (state.recent.length > 60) state.recent.pop();
    if (blocked) {
      state.blocked++;
      state.byVector[vector] = (state.byVector[vector] || 0) + 1;
    } else {
      state.accepted++;
    }
  };

  const allowRate = (src) => {
    const now = Date.now();
    const win = now - 1000;
    let arr = rates.get(src);
    if (!arr) {
      if (rates.size >= MAX_TRACKED_IPS) {
        for (const [ip, ts] of rates) {
          if (ts.length === 0 || ts[ts.length - 1] <= win) rates.delete(ip);
        }
        if (rates.size >= MAX_TRACKED_IPS) return false; // fail-closed under distributed IP flood
      }
      arr = [];
      rates.set(src, arr);
    }
    while (arr.length && arr[0] <= win) arr.shift();
    if (arr.length >= rateLimitPerSec) return false;
    arr.push(now);
    return true;
  };

  const tcpServer = net.createServer((sock) => {
    activeTcpSockets.add(sock);
    liveConns++;
    const src = sock.remoteAddress || 'unknown';
    let closed = false;
    const decLive = () => {
      activeTcpSockets.delete(sock);
      if (!closed) { closed = true; liveConns = Math.max(0, liveConns - 1); }
    };

    if (liveConns > maxLiveConns) {
      record('conn-cap', src, true, `live=${liveConns} > cap=${maxLiveConns}`);
      sock.destroy();
      decLive();
      return;
    }
    if (!allowRate(src)) {
      record('rate-flood', src, true, `exceeded ${rateLimitPerSec}/s`);
      sock.destroy();
      decLive();
      return;
    }

    let rxBytes = 0;
    const timer = setTimeout(() => {
      record('idle-linger', src, true, `idle ${idleMs}ms`);
      sock.destroy();
    }, idleMs);
    timer.unref();

    sock.on('data', (chunk) => {
      timer.refresh();
      rxBytes += chunk.length;
      if (rxBytes > MAX_FRAME_BYTES) {
        record('oversize-frame', src, true, `rx=${rxBytes} > ${MAX_FRAME_BYTES}`);
        sock.destroy();
        return;
      }
      if (cwControlKey) {
        // Expect [seq_u64be (8B) || CW-128 tag (16B) || payload] with strict anti-replay
        // and fresh per-frame one-time pad discipline (Theorem T2d; never reuse (r, b)!)
        const padSrc = cwControlKey.padPool || cwControlKey.padSeed || cwControlKey.b;
        const ver = verifyCwFrame(chunk, cwControlKey.r, padSrc, seenCwSeqs);
        if (!ver.ok) {
          record(ver.reason, src, true, `CW-128 frame rejected (${ver.reason})`);
          sock.destroy();
          return;
        }
      }
      record('authenticated-frame', src, false, `${chunk.length}B accepted`);
      try {
        // Fixed compact ACK only (never reflects arbitrary attacker payload!)
        sock.write(JSON.stringify({ ok: true, rx: chunk.length }) + '\n');
      } catch { /* socket closed */ }
    });
    sock.on('error', () => {});
    sock.on('close', () => { clearTimeout(timer); decLive(); });
  });

  let udpServer = null;
  if (udpEnabled) {
    udpServer = dgram.createSocket('udp4');
    udpServer.on('message', (msg, rinfo) => {
      // HARDENING FIX: Never echo arbitrary UDP payloads (prevents UDP amplification!)
      if (!allowRate(rinfo.address)) {
        record('udp-flood-drop', rinfo.address, true, `${msg.length}B dropped`);
        return;
      }
      record('udp-ingress-sink', rinfo.address, false, `${msg.length}B recorded (no reflection)`);
    });
    udpServer.on('error', () => {});
  }

  const statusServer = http.createServer((req, res) => {
    const origin = req.headers.origin;
    if (origin && origin === allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
      res.setHeader('Vary', 'Origin');
    }
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.statusCode = 405;
      res.setHeader('Allow', 'GET, HEAD');
      res.end('{"ok":false,"error":"method_not_allowed"}');
      return;
    }
    const pathname = (req.url || '/').split('?')[0];
    if (pathname === '/status' || pathname === '/health') {
      // Never leak raw secret keys or internal stack paths
      const body = JSON.stringify({
        ok: true,
        service: 'secmesh-pqsi-guardian-v2',
        host,
        uptimeMs: Date.now() - state.startedAt,
        accepted: state.accepted,
        blocked: state.blocked,
        byVector: state.byVector,
        liveConns,
        maxFrameBytes: MAX_FRAME_BYTES,
        cwAuthRequired: !!cwControlKey,
        recentCount: state.recent.length,
        statusDigest: crypto.createHash('sha256').update(JSON.stringify(state.byVector)).digest('hex').slice(0, 16),
      });
      res.end(req.method === 'HEAD' ? '' : body);
    } else {
      res.statusCode = 404;
      res.end(req.method === 'HEAD' ? '' : '{"ok":false,"error":"not_found"}');
    }
  });
  statusServer.headersTimeout = 5000;
  statusServer.requestTimeout = 10000;

  return {
    state,
    start: () => new Promise((resolve, reject) => {
      tcpServer.listen(listenPort, host, () => {
        const tcpAddr = tcpServer.address();
        statusServer.listen(statusPort, host, () => {
          const stAddr = statusServer.address();
          if (udpServer) {
            // Avoid ephemeral TCP<->UDP port collision deadlock when listenPort === 0
            const targetUdpPort = listenPort === 0 ? 0 : tcpAddr.port;
            const onUdpStartErr = (err) => reject(err);
            udpServer.once('error', onUdpStartErr);
            udpServer.bind(targetUdpPort, host, () => {
              udpServer.removeListener('error', onUdpStartErr);
              const udpAddr = udpServer.address();
              resolve({ tcpPort: tcpAddr.port, statusPort: stAddr.port, udpPort: udpAddr.port });
            });
          } else {
            resolve({ tcpPort: tcpAddr.port, statusPort: stAddr.port, udpPort: null });
          }
        });
      });
      tcpServer.once('error', reject);
      statusServer.once('error', reject);
    }),
    stop: () => new Promise((resolve) => {
      try { if (udpServer) udpServer.close(); } catch { /* ignore */ }
      for (const sock of activeTcpSockets) {
        try { sock.destroy(); } catch { /* ignore */ }
      }
      activeTcpSockets.clear();
      if (typeof statusServer.closeAllConnections === 'function') {
        statusServer.closeAllConnections();
      }
      tcpServer.close(() => statusServer.close(() => resolve()));
    }),
  };
}
