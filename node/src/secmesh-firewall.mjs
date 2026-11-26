// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — Active Zero-Trust Cyber-Defense Firewall & OS Quarantine Adapter
// Connects real Guardian/Daemon/VPN intrusion events + Ising HealthField telemetry to:
//   1. Instant in-process Zero-Trust L3/L4 drop list (drops quarantined IPs BEFORE crypto CPU!)
//   2. Real OS firewall rule emitters with strict IP validation (zero shell injection, execFileSync):
//        - Windows: `netsh advfirewall firewall add rule ...` (WFP backend)
//        - Linux:   `nft add element inet secmesh blocklist { <ip> timeout <ttl>s }`
//   Default mode is `in-process-and-plan` (safe without root/Admin); set `enforceOsRules: true`
//   on an elevated host to push rules straight into Windows WFP / Linux nftables.

import { execFileSync } from 'node:child_process';
import net from 'node:net';

export function normalizeAndValidateIp(rawIp) {
  if (typeof rawIp !== 'string') return null;
  let ip = rawIp.trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  const ver = net.isIP(ip);
  if (ver !== 4 && ver !== 6) return null;
  // Strict character allowlist — guarantees zero argument/command injection
  if (!/^[0-9a-fA-F.:]+$/.test(ip)) return null;
  return { ip, version: ver };
}

export function buildOsBlockCommand(ip, { platform = process.platform, ttlSec = 600 } = {}) {
  const parsed = normalizeAndValidateIp(ip);
  if (!parsed) throw new Error(`Refusing invalid IP address: ${String(ip)}`);
  const ttl = Math.max(10, Math.min(86400, Math.floor(Number(ttlSec) || 600)));
  if (platform === 'win32') {
    const ruleName = `SecMesh-PQSI-Block-${parsed.ip.replace(/:/g, '_')}`;
    return {
      backend: 'windows-netsh-wfp',
      bin: 'netsh',
      args: [
        'advfirewall', 'firewall', 'add', 'rule',
        `name=${ruleName}`, 'dir=in', 'action=block',
        `remoteip=${parsed.ip}`, 'enable=yes',
      ],
      removeArgs: ['advfirewall', 'firewall', 'delete', 'rule', `name=${ruleName}`],
      ttlSec: ttl,
    };
  }
  if (platform === 'linux') {
    const setName = parsed.version === 6 ? 'blocklist6' : 'blocklist4';
    return {
      backend: 'linux-nftables',
      bin: 'nft',
      args: ['add', 'element', 'inet', 'secmesh', setName, `{ ${parsed.ip} timeout ${ttl}s }`],
      removeArgs: ['delete', 'element', 'inet', 'secmesh', setName, `{ ${parsed.ip} }`],
      ttlSec: ttl,
    };
  }
  return {
    backend: 'in-process-only',
    bin: null,
    args: [],
    removeArgs: [],
    ttlSec: ttl,
  };
}

export class ActiveDefenseFirewall {
  constructor({
    strikeThreshold = 3,
    quarantineTtlMs = 600000,
    enforceOsRules = false,
    neverBlockLoopback = false,
    platform = process.platform,
  } = {}) {
    this.strikeThreshold = Math.max(1, Math.floor(strikeThreshold));
    this.quarantineTtlMs = Math.max(1000, Math.floor(quarantineTtlMs));
    this.enforceOsRules = !!enforceOsRules;
    this.neverBlockLoopback = !!neverBlockLoopback;
    this.platform = platform;
    this.strikes = new Map();       // ip -> [{ t, reason }]
    this.quarantine = new Map();    // ip -> { until, reason, osCmd, applied }
    this.auditTrail = [];
  }

  isBlocked(rawIp) {
    const parsed = normalizeAndValidateIp(rawIp);
    if (!parsed) return true; // fail-closed on malformed source
    const entry = this.quarantine.get(parsed.ip);
    if (!entry) return false;
    if (Date.now() >= entry.until) {
      this.quarantine.delete(parsed.ip);
      return false;
    }
    return true;
  }

  reportIncident(rawIp, reason = 'security-violation', severity = 1) {
    const parsed = normalizeAndValidateIp(rawIp);
    if (!parsed) return { blocked: true, reason: 'invalid-ip' };
    if (this.neverBlockLoopback && (parsed.ip === '127.0.0.1' || parsed.ip === '::1')) {
      this.auditTrail.push({ t: Date.now(), ip: parsed.ip, reason, action: 'loopback-exempt' });
      return { blocked: false, exempt: true };
    }
    const now = Date.now();
    const list = (this.strikes.get(parsed.ip) || []).filter((e) => now - e.t < 60000);
    for (let i = 0; i < Math.max(1, severity); i++) list.push({ t: now, reason });
    this.strikes.set(parsed.ip, list);

    if (list.length >= this.strikeThreshold) {
      return this.quarantineIp(parsed.ip, `${reason} (${list.length} strikes)`);
    }
    this.auditTrail.push({ t: now, ip: parsed.ip, reason, strikes: list.length, action: 'strike-recorded' });
    return { blocked: false, strikes: list.length, threshold: this.strikeThreshold };
  }

  quarantineIp(rawIp, reason = 'manual-quarantine') {
    const parsed = normalizeAndValidateIp(rawIp);
    if (!parsed) throw new Error(`Invalid IP: ${rawIp}`);
    const osCmd = buildOsBlockCommand(parsed.ip, {
      platform: this.platform,
      ttlSec: Math.ceil(this.quarantineTtlMs / 1000),
    });
    let applied = false;
    let osError = null;
    if (this.enforceOsRules && osCmd.bin) {
      try {
        execFileSync(osCmd.bin, osCmd.args, { stdio: 'ignore' });
        applied = true;
      } catch (err) {
        osError = err.message;
      }
    }
    const rec = {
      ip: parsed.ip,
      until: Date.now() + this.quarantineTtlMs,
      reason,
      osCmd,
      applied,
      osError,
    };
    this.quarantine.set(parsed.ip, rec);
    this.auditTrail.push({ t: Date.now(), ip: parsed.ip, reason, action: 'quarantined', backend: osCmd.backend, applied });
    return { blocked: true, ...rec };
  }

  unblockIp(rawIp) {
    const parsed = normalizeAndValidateIp(rawIp);
    if (!parsed) return false;
    const rec = this.quarantine.get(parsed.ip);
    this.quarantine.delete(parsed.ip);
    this.strikes.delete(parsed.ip);
    if (rec && rec.applied && rec.osCmd?.bin && rec.osCmd.removeArgs?.length) {
      try { execFileSync(rec.osCmd.bin, rec.osCmd.removeArgs, { stdio: 'ignore' }); } catch { /* ignore */ }
    }
    return !!rec;
  }

  status() {
    const active = [];
    const now = Date.now();
    for (const [ip, rec] of this.quarantine.entries()) {
      if (rec.until > now) {
        active.push({ ip, reason: rec.reason, ttlRemainingMs: rec.until - now, backend: rec.osCmd.backend, applied: rec.applied });
      }
    }
    return {
      enforceOsRules: this.enforceOsRules,
      strikeThreshold: this.strikeThreshold,
      activeQuarantineCount: active.length,
      active,
      recentEvents: this.auditTrail.slice(-20),
    };
  }
}
