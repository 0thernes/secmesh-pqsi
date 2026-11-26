#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 Unified CLI — Complete Post-Quantum + Post-Super-Intelligence
// Cyber-Defense Suite (Levels 1, 2 & 3: Vault, Pad Ledger, Trust Store, Live TCP/Onion/Tunnel,
// UDP L3 Mesh VPN, Active Firewall & Formal Verification Audit).

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  generatePeerIdentity,
  runPQSIHandshake,
  sealRecord,
  openRecord,
} from './pqsi-handshake.mjs';
import {
  evaluateFiniteKeyV2,
  evaluateLegacyV1BrokenGate,
  simulateE91Session,
} from './finite-key-v2.mjs';
import { createRosetteBundle } from './rosette-receipt.mjs';
import { createCtCoprocessor, resolveNativeCoreBinary } from './native-ct-bridge.mjs';
import { initPadPool, inspectPadLedger } from './secmesh-pad-ledger.mjs';
import { PeerTrustStore } from './secmesh-trust.mjs';
import {
  generateCompositeIdentityV3,
  saveEncryptedKeystore,
  loadEncryptedKeystore,
  splitKey256Byzantine,
  recoverKey256Byzantine,
  encryptArtichokeFile,
  decryptArtichokeFile,
} from './secmesh-vault.mjs';
import { probeOsTunDriver, UdpMeshVpnNode } from './secmesh-l3-vpn.mjs';
import { ActiveDefenseFirewall, buildOsBlockCommand } from './secmesh-firewall.mjs';
import {
  createPqsiTcpServer,
  connectPqsiTcpClient,
  createPqsiTcpPortForward,
  createOnionRelayNode,
} from './secmesh-daemon.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

function getFlag(args, name, fallback = null) {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return fallback;
  return args[idx + 1];
}

export function runCrossImplMlkem768Check() {
  const bin = resolveNativeCoreBinary();
  if (!fs.existsSync(bin)) {
    throw new Error(`Native binary missing: ${bin}`);
  }
  const kp = crypto.generateKeyPairSync('ml-kem-768');
  const spki = kp.publicKey.export({ type: 'spki', format: 'der' });
  const rawEk = spki.subarray(spki.length - 1184);
  const m = crypto.randomBytes(32);

  const stdout = execFileSync(bin, ['mlkem-encaps', rawEk.toString('hex'), m.toString('hex')], {
    encoding: 'utf8',
  });
  const cRes = JSON.parse(stdout.trim());
  if (!cRes.ok) throw new Error(`Moonlab C11 ML-KEM-768 encaps refused: ${cRes.error}`);

  const ct = Buffer.from(cRes.ct_hex, 'hex');
  const ssMoonlab = Buffer.from(cRes.ss_hex, 'hex');
  const ssOpenSsl = crypto.decapsulate(kp.privateKey, ct);
  const exactMatch = crypto.timingSafeEqual(ssMoonlab, ssOpenSsl);

  const ssFp = crypto.createHash('sha3-256').update(ssOpenSsl).digest('hex').slice(0, 32);
  ssMoonlab.fill(0);
  ssOpenSsl.fill(0);
  return {
    ok: exactMatch,
    ekBytes: rawEk.length,
    ctBytes: ct.length,
    sharedSecretSha3Prefix: ssFp,
    implementations: ['Moonlab-C11-FIPS203', `OpenSSL-${process.versions.openssl}-FIPS203`],
  };
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0] || 'audit';

  if (cmd === 'keygen') {
    const nodeId = getFlag(args, '--id', `secmesh-node-${crypto.randomBytes(3).toString('hex')}`);
    const outPath = getFlag(args, '--out');
    const pass = getFlag(args, '--pass') || process.env.SECMESH_KEYSTORE_PASS;
    const fast = args.includes('--fast-kdf');
    if (!outPath || !pass) {
      console.error('Usage: secmesh-cli.mjs keygen --id <nodeId> --out <keystore.json> --pass <passphrase> [--fast-kdf]');
      process.exit(2);
    }
    const id = generateCompositeIdentityV3(nodeId, { latticeHedged: true });
    const saved = saveEncryptedKeystore(outPath, id, pass, fast ? { memoryKiB: 8192, passes: 2, parallelism: 1 } : {});
    console.log(JSON.stringify({ ok: true, op: 'keygen', nodeId, fingerprint: saved.fingerprint, keystorePath: saved.keystorePath }, null, 2));
    process.exit(0);
  }

  if (cmd === 'pin') {
    const trustPath = getFlag(args, '--trust');
    const peerFile = getFlag(args, '--peer');
    const role = getFlag(args, '--role', 'peer');
    if (!trustPath || !peerFile) {
      console.error('Usage: secmesh-cli.mjs pin --trust <trust.json> --peer <keystore_or_pub.json> [--role peer|relay|quorum-auditor]');
      process.exit(2);
    }
    const raw = JSON.parse(fs.readFileSync(path.resolve(peerFile), 'utf8'));
    const pub = raw.pub || raw;
    const store = new PeerTrustStore(trustPath);
    const pinned = store.pinPeer(pub, { role });
    console.log(JSON.stringify({ ok: true, op: 'pin', nodeId: pinned.nodeId, fingerprint: pinned.fingerprint, role: pinned.role }, null, 2));
    process.exit(0);
  }

  if (cmd === 'pad-init') {
    const outPath = getFlag(args, '--out');
    const size = Number(getFlag(args, '--bytes', '65536'));
    if (!outPath || !Number.isInteger(size) || size < 512) {
      console.error('Usage: secmesh-cli.mjs pad-init --out <pad.bin> --bytes <N>=512');
      process.exit(2);
    }
    const info = initPadPool(outPath, size);
    console.log(JSON.stringify({ ok: true, op: 'pad-init', ...info }, null, 2));
    process.exit(0);
  }

  if (cmd === 'pad-status') {
    const padPath = getFlag(args, '--pad');
    if (!padPath) { console.error('Usage: secmesh-cli.mjs pad-status --pad <pad.bin>'); process.exit(2); }
    console.log(JSON.stringify({ ok: true, op: 'pad-status', ...inspectPadLedger(padPath) }, null, 2));
    process.exit(0);
  }

  if (cmd === 'encrypt') {
    const inPath = getFlag(args, '--in');
    const outPath = getFlag(args, '--out');
    const senderKs = getFlag(args, '--sender');
    const pass = getFlag(args, '--pass') || process.env.SECMESH_KEYSTORE_PASS;
    const toFile = getFlag(args, '--to');
    const padPoolPath = getFlag(args, '--pad') || process.env.SECMESH_IT_PAD_FILE || null;
    if (!inPath || !outPath || !senderKs || !pass || !toFile) {
      console.error('Usage: secmesh-cli.mjs encrypt --in <file> --out <file.sm3> --sender <ks> --pass <pw> --to <peer_ks_or_pub.json> [--pad <pad.bin>]');
      process.exit(2);
    }
    const senderIdentity = loadEncryptedKeystore(senderKs, pass);
    const rawTo = JSON.parse(fs.readFileSync(path.resolve(toFile), 'utf8'));
    const recipientPub = rawTo.pub || rawTo;
    const ct = createCtCoprocessor();
    try {
      const res = await encryptArtichokeFile(inPath, outPath, { senderIdentity, recipientPub, padPoolPath, ctCoprocessor: ct });
      console.log(JSON.stringify({ ok: true, op: 'encrypt', ...res }, null, 2));
    } finally {
      await ct.close();
    }
    process.exit(0);
  }

  if (cmd === 'decrypt') {
    const inPath = getFlag(args, '--in');
    const outPath = getFlag(args, '--out');
    const recKs = getFlag(args, '--recipient');
    const pass = getFlag(args, '--pass') || process.env.SECMESH_KEYSTORE_PASS;
    const trustPath = getFlag(args, '--trust');
    const padPoolPath = getFlag(args, '--pad') || process.env.SECMESH_IT_PAD_FILE || null;
    if (!inPath || !outPath || !recKs || !pass || !trustPath) {
      console.error('Usage: secmesh-cli.mjs decrypt --in <file.sm3> --out <file> --recipient <ks> --pass <pw> --trust <trust.json> [--pad <pad.bin>]');
      process.exit(2);
    }
    const recipientIdentity = loadEncryptedKeystore(recKs, pass);
    const trustStore = new PeerTrustStore(trustPath);
    const ct = createCtCoprocessor();
    try {
      const res = await decryptArtichokeFile(inPath, outPath, { recipientIdentity, trustStore, padPoolPath, ctCoprocessor: ct });
      console.log(JSON.stringify({ ok: true, op: 'decrypt', ...res }, null, 2));
    } finally {
      await ct.close();
    }
    process.exit(0);
  }

  if (cmd === 'shamir-backup') {
    const keyHex = getFlag(args, '--key-hex');
    const outDir = getFlag(args, '--out-dir');
    const t = Number(getFlag(args, '--t', '3'));
    const n = Number(getFlag(args, '--n', '7'));
    const b = Number(getFlag(args, '--b', '2'));
    if (!keyHex || !outDir) {
      console.error('Usage: secmesh-cli.mjs shamir-backup --key-hex <64hex> --out-dir <dir> [--t 3 --n 7 --b 2]');
      process.exit(2);
    }
    const key32 = Buffer.from(keyHex, 'hex');
    const shares = splitKey256Byzantine(key32, { threshold: t, numShares: n, maxByzantine: b });
    key32.fill(0);
    fs.mkdirSync(path.resolve(outDir), { recursive: true });
    for (const sh of shares) {
      fs.writeFileSync(path.join(path.resolve(outDir), `share-${sh.index}.json`), JSON.stringify(sh, null, 2) + '\n', { mode: 0o600 });
    }
    console.log(JSON.stringify({ ok: true, op: 'shamir-backup', outDir: path.resolve(outDir), threshold: t, numShares: n, maxByzantine: b }, null, 2));
    process.exit(0);
  }

  if (cmd === 'shamir-recover') {
    const dir = getFlag(args, '--dir');
    if (!dir) { console.error('Usage: secmesh-cli.mjs shamir-recover --dir <dir>'); process.exit(2); }
    const files = fs.readdirSync(path.resolve(dir)).filter((f) => f.endsWith('.json')).sort();
    const shares = files.map((f) => JSON.parse(fs.readFileSync(path.join(path.resolve(dir), f), 'utf8')));
    const rec = recoverKey256Byzantine(shares);
    const fp = crypto.createHash('sha3-256').update(rec.key32).digest('hex').slice(0, 32);
    rec.key32.fill(0);
    console.log(JSON.stringify({ ok: true, op: 'shamir-recover', sharesUsed: shares.length, corruptedDetected: rec.corruptedDetected, keySha3Prefix: fp }, null, 2));
    process.exit(0);
  }

  if (cmd === 'tun-probe') {
    console.log(JSON.stringify(probeOsTunDriver(), null, 2));
    process.exit(0);
  }

  if (cmd === 'firewall-plan') {
    const ip = getFlag(args, '--ip');
    const platform = getFlag(args, '--platform', process.platform);
    const ttl = Number(getFlag(args, '--ttl', '600'));
    if (!ip) { console.error('Usage: secmesh-cli.mjs firewall-plan --ip <ipv4|ipv6> [--platform win32|linux] [--ttl 600]'); process.exit(2); }
    console.log(JSON.stringify({ ok: true, op: 'firewall-plan', ...buildOsBlockCommand(ip, { platform, ttlSec: ttl }) }, null, 2));
    process.exit(0);
  }

  if (cmd === 'serve') {
    const ksPath = getFlag(args, '--identity');
    const pass = getFlag(args, '--pass') || process.env.SECMESH_KEYSTORE_PASS;
    const trustPath = getFlag(args, '--trust');
    const host = getFlag(args, '--host', '127.0.0.1');
    const port = Number(getFlag(args, '--port', '7777'));
    const allow = getFlag(args, '--allow-target', '');
    const padPoolPath = getFlag(args, '--pad') || process.env.SECMESH_IT_PAD_FILE || null;
    if (!ksPath || !pass || !trustPath) {
      console.error('Usage: secmesh-cli.mjs serve --identity <ks.json> --pass <pw> --trust <trust.json> [--host 127.0.0.1 --port 7777 --allow-target host:port --pad <pad.bin>]');
      process.exit(2);
    }
    const identity = loadEncryptedKeystore(ksPath, pass);
    const trustStore = new PeerTrustStore(trustPath);
    const firewall = new ActiveDefenseFirewall({ strikeThreshold: 3, neverBlockLoopback: host === '127.0.0.1' });
    const ct = createCtCoprocessor();
    const srv = createPqsiTcpServer({
      identity,
      trustStore,
      host,
      port,
      padPoolPath,
      ctCoprocessor: ct,
      firewall,
      allowedTunnelTargets: allow ? allow.split(',').filter(Boolean) : [],
      onMessage: (buf, meta) => {
        console.log(JSON.stringify({ event: 'message', from: meta.peer.nodeId, epoch: meta.epoch, seq: meta.seq.toString(), bytes: buf.length }));
      },
    });
    const addr = await srv.start();
    console.log(JSON.stringify({ ok: true, op: 'serve', ...addr, nodeId: identity.nodeId, fingerprint: identity.fingerprint }));
    process.on('SIGINT', async () => { await srv.stop(); await ct.close(); process.exit(0); });
    return;
  }

  if (cmd === 'tunnel') {
    const ksPath = getFlag(args, '--identity');
    const pass = getFlag(args, '--pass') || process.env.SECMESH_KEYSTORE_PASS;
    const trustPath = getFlag(args, '--trust');
    const remoteHost = getFlag(args, '--remote-host', '127.0.0.1');
    const remotePort = Number(getFlag(args, '--remote-port', '7777'));
    const localPort = Number(getFlag(args, '--local-port', '0'));
    const targetHost = getFlag(args, '--target-host', '127.0.0.1');
    const targetPort = Number(getFlag(args, '--target-port', '80'));
    if (!ksPath || !pass || !trustPath) {
      console.error('Usage: secmesh-cli.mjs tunnel --identity <ks.json> --pass <pw> --trust <trust.json> --remote-host <h> --remote-port <p> --local-port <lp> --target-host <th> --target-port <tp>');
      process.exit(2);
    }
    const identity = loadEncryptedKeystore(ksPath, pass);
    const trustStore = new PeerTrustStore(trustPath);
    const ct = createCtCoprocessor();
    const sess = await connectPqsiTcpClient({ identity, trustStore, host: remoteHost, port: remotePort, ctCoprocessor: ct });
    const fwd = createPqsiTcpPortForward({ session: sess, localPort, targetHost, targetPort });
    const addr = await fwd.start();
    console.log(JSON.stringify({ ok: true, op: 'tunnel', listen: `${addr.host}:${addr.port}`, forwardTo: `${targetHost}:${targetPort}`, via: `${remoteHost}:${remotePort}` }));
    process.on('SIGINT', async () => { await fwd.stop(); sess.close(); await ct.close(); process.exit(0); });
    return;
  }

  if (cmd === 'onion-relay') {
    const ksPath = getFlag(args, '--identity');
    const pass = getFlag(args, '--pass') || process.env.SECMESH_KEYSTORE_PASS;
    const host = getFlag(args, '--host', '127.0.0.1');
    const port = Number(getFlag(args, '--port', '7779'));
    if (!ksPath || !pass) {
      console.error('Usage: secmesh-cli.mjs onion-relay --identity <ks.json> --pass <pw> [--host 127.0.0.1 --port 7779]');
      process.exit(2);
    }
    const identity = loadEncryptedKeystore(ksPath, pass);
    const relay = createOnionRelayNode({ identity, host, port });
    const addr = await relay.start();
    console.log(JSON.stringify({ ok: true, op: 'onion-relay', ...addr, nodeId: identity.nodeId, fingerprint: identity.fingerprint }));
    process.on('SIGINT', async () => { await relay.stop(); process.exit(0); });
    return;
  }

  if (cmd === 'vpn') {
    const ksPath = getFlag(args, '--identity');
    const pass = getFlag(args, '--pass') || process.env.SECMESH_KEYSTORE_PASS;
    const trustPath = getFlag(args, '--trust');
    const tunnelIp = getFlag(args, '--tunnel-ip', '10.99.0.1');
    const host = getFlag(args, '--host', '127.0.0.1');
    const port = Number(getFlag(args, '--port', '7778'));
    if (!ksPath || !pass || !trustPath) {
      console.error('Usage: secmesh-cli.mjs vpn --identity <ks.json> --pass <pw> --trust <trust.json> [--tunnel-ip 10.99.0.1 --host 127.0.0.1 --port 7778]');
      process.exit(2);
    }
    const identity = loadEncryptedKeystore(ksPath, pass);
    const trustStore = new PeerTrustStore(trustPath);
    const firewall = new ActiveDefenseFirewall({ strikeThreshold: 3 });
    const ct = createCtCoprocessor();
    const vpn = new UdpMeshVpnNode({ identity, trustStore, tunnelIp, host, port, firewall, ctCoprocessor: ct });
    const addr = await vpn.start();
    console.log(JSON.stringify({ ok: true, op: 'vpn', ...addr, tunDriver: probeOsTunDriver() }));
    process.on('SIGINT', async () => { await vpn.stop(); await ct.close(); process.exit(0); });
    return;
  }

  if (cmd === 'handshake') {
    const hedged = args.includes('--hedged');
    const withIt = !args.includes('--pq-only');
    const a = generatePeerIdentity('mesh-node-alpha', { latticeHedged: hedged });
    const b = generatePeerIdentity('mesh-node-beta', { latticeHedged: hedged });
    const itKey = withIt ? crypto.randomBytes(32) : null;
    const cwKey = withIt
      ? { r: crypto.randomBytes(16), bClient: crypto.randomBytes(16), bServer: crypto.randomBytes(16) }
      : null;
    const hs = runPQSIHandshake(a, b, { preSharedItKey: itKey, preSharedCwKey: cwKey });
    const otpPad = withIt ? crypto.randomBytes(64) : null;
    const recCw = withIt ? { r: crypto.randomBytes(16), b: crypto.randomBytes(16) } : null;
    const msg = Buffer.from('SecMesh-PQSI v3 authenticated payload');
    const rec = sealRecord(hs.sessionKey, msg, Buffer.from('frame-0'), { otpPadOpt: otpPad, cwKeyOpt: recCw });
    const opened = openRecord(hs.sessionKeyResponder, rec, Buffer.from('frame-0'), { otpPadOpt: otpPad, cwKeyOpt: recCw });
    const roundtripOk = opened.equals(msg);
    hs.sessionKey.fill(0);
    hs.sessionKeyResponder.fill(0);
    console.log(JSON.stringify({
      ok: hs.ok && roundtripOk,
      securityTier: hs.securityTier,
      latticeHedged: hs.latticeHedged,
      sessionFingerprint: hs.sessionFingerprint,
      transcriptSha3: hs.transcriptSha3,
      wireBytes: hs.wireBytes,
      elapsedMs: Number(hs.elapsedMs.toFixed(3)),
    }, null, 2));
    process.exit(hs.ok && roundtripOk ? 0 : 1);
  }

  if (cmd === 'interop') {
    const res = runCrossImplMlkem768Check();
    console.log(JSON.stringify(res, null, 2));
    process.exit(res.ok ? 0 : 1);
  }

  if (cmd === 'audit') {
    const interop = runCrossImplMlkem768Check();
    const a = generatePeerIdentity('node-0', { latticeHedged: true });
    const b = generatePeerIdentity('node-1', { latticeHedged: true });
    const hs = runPQSIHandshake(a, b, {
      preSharedItKey: crypto.randomBytes(32),
      preSharedCwKey: { r: crypto.randomBytes(16), bClient: crypto.randomBytes(16), bServer: crypto.randomBytes(16) },
    });
    hs.sessionKey.fill(0);
    hs.sessionKeyResponder.fill(0);

    const honestSim = simulateE91Session({ nRounds: 450000, eveRate: 0, seed: 20261125 });
    const alignedSim = simulateE91Session({ nRounds: 450000, eveRate: 0.2, eveMode: 'aligned', seed: 20261125 });
    const v1Broken = evaluateLegacyV1BrokenGate({ S: 2.832, sift: 5555, QBER: 0, cnts: [5555, 5555, 5555, 5555], eps: 1e-6 });
    const v2Honest = evaluateFiniteKeyV2({ S: 2 * Math.SQRT2, cnts: [5555, 5555, 5555, 5555], nKey: 5555, qberErrors: 0, qberSample: 1111, epsTotal: 1e-6 });
    const tunProbe = probeOsTunDriver();

    const outDir = path.join(REPO_ROOT, 'rosette', 'latest-audit');
    const bundle = createRosetteBundle({
      compositionId: 'secmesh-pqsi-full-audit-v3',
      components: [
        'moonlab-c11-fips203',
        'openssl-3.5-fips203-204-205',
        'secmesh-finite-key-v2',
        'carter-wegman-gf128',
        'artichoke-v3-onion-ratchet-vpn',
      ],
      inputs: { nRounds: 450000, seed: 20261125, epsTotal: 1e-6 },
      outputs: {
        interop,
        handshakeTier: hs.securityTier,
        handshakeWireBytes: hs.wireBytes,
        honestCertBits: honestSim.cert.certBits,
        alignedEveCertBits: alignedSim.cert.certBits,
        v1BrokenAt50k: v1Broken.certBits,
        v2CorrectedAt50k: v2Honest.certBits,
        tunBackend: tunProbe.backend,
      },
      checks: [
        { name: 'moonlab_c11_vs_openssl35_mlkem768_interop', passed: interop.ok },
        { name: 'pqsi_lattice_hedged_handshake', passed: hs.ok && hs.securityTier === 'HYBRID_PQ_IT_OTP' },
        { name: 'finite_key_v2_admits_honest_450k', passed: honestSim.verdict === 'KEY' && honestSim.cert.certBits > 10000 },
        { name: 'finite_key_v2_rejects_aligned_eve', passed: alignedSim.verdict === 'ABORT' && alignedSim.cert.certBits === 0 },
      ],
      outDir,
    });
    console.log(JSON.stringify(bundle.verification, null, 2));
    process.exit(bundle.verification.verdict === 'VERIFIED' ? 0 : 1);
  }

  console.error('Usage: node secmesh-cli.mjs <audit|handshake|interop|keygen|pin|pad-init|pad-status|encrypt|decrypt|shamir-backup|shamir-recover|tun-probe|firewall-plan>');
  process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(JSON.stringify({ ok: false, error: err.message }));
    process.exit(1);
  });
}
