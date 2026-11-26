#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — "Invincible Onion Artichoke" Complete Levels 1, 2 & 3
// End-to-End & Adversarial Red-Team Verification Suite (15 Deep Tests)

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  gf128Mul,
  carterWegmanMac,
  dualSurvivabilityCombine,
  sealCwFrame,
} from '../src/pqsi-handshake.mjs';
import { createCtCoprocessor } from '../src/native-ct-bridge.mjs';
import {
  initPadPool,
  inspectPadLedger,
  consumePadSlice,
  consumePadAtOffset,
} from '../src/secmesh-pad-ledger.mjs';
import { PeerTrustStore, computePublicBundleFingerprint } from '../src/secmesh-trust.mjs';
import {
  generateCompositeIdentityV3,
  saveEncryptedKeystore,
  loadEncryptedKeystore,
  splitKey256Byzantine,
  recoverKey256Byzantine,
  encryptArtichokeBuffer,
  decryptArtichokeBuffer,
} from '../src/secmesh-vault.mjs';
import { encodeWireFrame, LengthPrefixedFramer } from '../src/secmesh-wire.mjs';
import { createHardenedGuardian } from '../src/mesh-guardian-v2.mjs';
import { PqDoubleRatchetSession } from '../src/secmesh-ratchet.mjs';
import {
  createPqsiTcpServer,
  connectPqsiTcpClient,
  createPqsiTcpPortForward,
  createOnionRelayNode,
  sendOnionCircuitMessage,
} from '../src/secmesh-daemon.mjs';
import { ActiveDefenseFirewall, buildOsBlockCommand } from '../src/secmesh-firewall.mjs';
import {
  UdpMeshVpnNode,
  buildIpv4Packet,
  parseAndVerifyIpv4Packet,
  probeOsTunDriver,
} from '../src/secmesh-l3-vpn.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');

let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [FAIL] ${name}: ${err.stack || err.message}`);
    failed++;
  }
}

console.log('=== SecMesh-PQSI v3.0 Onion-Artichoke (Levels 1+2+3) Adversarial Red-Team Suite ===');

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secmesh-v3-'));
const ct = createCtCoprocessor();

try {
  // 1. Persistent C11 Constant-Time Coprocessor differential & SP 800-90B check
  await test('V3-01 C11 Constant-Time Coprocessor: bit-exact GF128/CW128/Hybrid/MLKEM-768/SP800-90B', async () => {
    const ping = await ct.ping();
    assert.equal(ping.engine, 'secmesh-c11-ct-v3');
    const a = crypto.randomBytes(16);
    const b = crypto.randomBytes(16);
    assert.deepEqual(await ct.gf128Mul(a, b), gf128Mul(a, b));

    const msg = Buffer.from('SecMesh-PQSI v3 constant-time C11 coprocessor parity check');
    const tagC = await ct.carterWegmanMac(a, b, msg);
    const tagJs = carterWegmanMac(a, b, msg);
    assert.deepEqual(tagC, tagJs);
    assert.equal(await ct.carterWegmanVerify(tagC, a, b, msg), true);
    const badTag = Buffer.from(tagC);
    badTag[0] ^= 1;
    assert.equal(await ct.carterWegmanVerify(badTag, a, b, msg), false);

    const kX = crypto.randomBytes(32);
    const kM = crypto.randomBytes(32);
    const kIt = crypto.randomBytes(32);
    const tr = Buffer.from('transcript-parity-v3');
    const cHyb = await ct.hybridCombine(Buffer.concat([kX, kM]), kIt, tr);
    const jsHyb = dualSurvivabilityCombine({ kX25519: kX, kMlKem: kM, kItOpt: kIt, transcriptBuf: tr });
    assert.deepEqual(cHyb, jsHyb);

    // Cross-impl ML-KEM-768 via persistent worker
    const kp = crypto.generateKeyPairSync('ml-kem-768');
    const spki = kp.publicKey.export({ type: 'spki', format: 'der' });
    const rawEk = spki.subarray(spki.length - 1184);
    const { ciphertext, sharedSecret } = await ct.mlkem768Encaps(rawEk, crypto.randomBytes(32));
    assert.deepEqual(sharedSecret, crypto.decapsulate(kp.privateKey, ciphertext));

    // SP 800-90B positive & negative
    const good = await ct.sp80090bAudit(crypto.randomBytes(2048));
    const bad = await ct.sp80090bAudit(Buffer.alloc(2048, 0xAA));
    assert.equal(good.passed, true);
    assert.equal(bad.passed, false);
  });

  // 2. Argon2id + Double-AEAD Cascade 6-Algorithm Keystore
  await test('V3-02 Level 1 Keystore: Argon2id + AES-256-GCM + ChaCha20-Poly1305 cascade & tamper reject', () => {
    const ksPath = path.join(tmpRoot, 'alice.ks.json');
    const alice = generateCompositeIdentityV3('alice-v3', { latticeHedged: true });
    const pass = 'correct-horse-quantum-artichoke-99!';
    saveEncryptedKeystore(ksPath, alice, pass, { memoryKiB: 8192, passes: 2, parallelism: 1 });

    const unlocked = loadEncryptedKeystore(ksPath, pass);
    assert.equal(unlocked.nodeId, 'alice-v3');
    assert.equal(unlocked.fingerprint, alice.fingerprint);
    assert.ok(unlocked.priv.slhdsa128s && unlocked.priv.mlkem1024);

    // Wrong passphrase rejected
    assert.throws(() => loadEncryptedKeystore(ksPath, 'wrong-passphrase-12345'));
    // Short passphrase refused
    assert.throws(() => saveEncryptedKeystore(ksPath, alice, 'short'));

    // 1-bit tamper on ciphertext rejected
    const raw = JSON.parse(fs.readFileSync(ksPath, 'utf8'));
    const ctBuf = Buffer.from(raw.encryptedPrivate.ciphertextB64, 'base64');
    ctBuf[0] ^= 0x01;
    raw.encryptedPrivate.ciphertextB64 = ctBuf.toString('base64');
    const badPath = path.join(tmpRoot, 'alice-tampered.ks.json');
    fs.writeFileSync(badPath, JSON.stringify(raw));
    assert.throws(() => loadEncryptedKeystore(badPath, pass));
  });

  // 3. Byzantine Shamir (t=3, n=7, b=2) 256-bit Master Key Recovery
  await test('V3-03 Level 1 Byzantine Shamir Backup: recovers 256-bit key with b=2 poisoned shares & blocks dup-x', () => {
    const masterKey = crypto.randomBytes(32);
    const shares = splitKey256Byzantine(masterKey, { threshold: 3, numShares: 7, maxByzantine: 2 });
    assert.equal(shares.length, 7);

    // Poison 2 shares maliciously (shares[1] and shares[5])
    const poisoned = shares.map((s) => ({ ...s, limbsY: [...s.limbsY] }));
    poisoned[1].limbsY[0] = (BigInt(poisoned[1].limbsY[0]) + 1337n).toString();
    poisoned[5].limbsY[3] = (BigInt(poisoned[5].limbsY[3]) + 9999n).toString();

    const rec = recoverKey256Byzantine(poisoned);
    assert.deepEqual(rec.key32, masterKey);
    assert.equal(rec.corruptedDetected, 2);

    // Duplicate-x attack rejected (Theorem T3b guard)
    const dup = [...shares.slice(0, 6), { ...shares[0] }];
    assert.throws(() => recoverKey256Byzantine(dup), /Duplicate Shamir/);
    // Violating n >= t + 2b refused
    assert.throws(() => splitKey256Byzantine(masterKey, { threshold: 3, numShares: 6, maxByzantine: 2 }), /T3b/);
  });

  // 4. Zero-Trust Peer Trust Store, Anti-MITM Pinning & Signed Revocations
  await test('V3-04 Level 1 Trust Store: anti-MITM key change refusal & composite-signed revocation', () => {
    const trustPath = path.join(tmpRoot, 'trust.json');
    const store = new PeerTrustStore(trustPath);
    const bob1 = generateCompositeIdentityV3('bob');
    const bobImposter = generateCompositeIdentityV3('bob');
    const auditor = generateCompositeIdentityV3('quorum-auditor-1');

    store.pinPeer(bob1.pub, { role: 'peer' });
    store.pinPeer(auditor.pub, { role: 'quorum-auditor' });
    assert.equal(store.verifyPinnedPeer(bob1.pub).ok, true);

    // Silent MITM overwrite of 'bob' MUST fail closed
    assert.throws(() => store.pinPeer(bobImposter.pub), /MITM_KEY_CHANGE_REFUSED/);
    assert.equal(store.verifyPinnedPeer(bobImposter.pub).reason, 'peer-fingerprint-mismatch');

    // Forged revocation by imposter MUST fail
    const badCert = PeerTrustStore.createRevocationCert(bobImposter, bob1.fingerprint, 'spoof');
    assert.throws(() => store.applyRevocationCert(badCert));

    // Legitimate quorum-auditor revocation succeeds & permanently blocks bob1
    const goodCert = PeerTrustStore.createRevocationCert(auditor, bob1.fingerprint, 'compromised-host');
    assert.equal(store.applyRevocationCert(goodCert), true);
    assert.equal(store.verifyPinnedPeer(bob1.pub).reason, 'peer-revoked');
    assert.equal(store.getPeer('bob'), null);
  });

  // 5. Crash-Safe Atomic One-Time Pad Ledger + Physical Shred + Rollback Alarm
  await test('V3-05 Level 1 Crash-Safe Pad Ledger: SP 800-90B gate, physical disk shred & rollback alarm', () => {
    // Low-entropy constant pad MUST fail SP 800-90B admission
    const badPadPath = path.join(tmpRoot, 'bad.pad');
    assert.throws(
      () => initPadPool(badPadPath, 2048, { sourceBytes: Buffer.alloc(2048, 0x55), runSp80090b: true }),
      /SP 800-90B/,
    );
    assert.equal(fs.existsSync(badPadPath), false);

    // Valid pad pool
    const padPath = path.join(tmpRoot, 'good.pad');
    const init = initPadPool(padPath, 8192);
    assert.equal(init.totalBytes, 8192);
    assert.equal(init.consumedBytes, 0);

    const s1 = consumePadSlice(padPath, 128, 'test-1');
    const s2 = consumePadSlice(padPath, 128, 'test-2');
    assert.equal(s1.offset, 0);
    assert.equal(s2.offset, 128);
    assert.notDeepEqual(s1.bytes, s2.bytes);

    // Verify physical on-disk zeroization of [0, 256)
    const rawOnDisk = fs.readFileSync(padPath);
    assert.deepEqual(rawOnDisk.subarray(0, 256), Buffer.alloc(256, 0));
    assert.equal(inspectPadLedger(padPath).remainingBytes, 8192 - 256);

    // Simulate attacker rolling back ledger.consumedBytes = 0 -> PAD_REUSE_ALARM MUST fire!
    const lp = `${padPath}.ledger.json`;
    const rolled = JSON.parse(fs.readFileSync(lp, 'utf8'));
    rolled.consumedBytes = 0;
    fs.writeFileSync(lp, JSON.stringify(rolled));
    assert.throws(() => consumePadSlice(padPath, 64, 'rollback-attack'), /PAD_REUSE_ALARM/);
  });

  // 6. 5-Layer Onion-Artichoke File/Buffer Encryption (C11 CT Coprocessor + PSI Pad + Cross-Verify)
  await test('V3-06 Level 1 Artichoke 5-Layer Vault: Triple-KEM + Dual-AEAD + OTP + CW-128 + Composite Sig', async () => {
    const alice = generateCompositeIdentityV3('alice-vault');
    const bob = generateCompositeIdentityV3('bob-vault');
    const bobTrust = new PeerTrustStore(null);
    bobTrust.pinPeer(alice.pub);

    // Clone identical pre-shared pad pool for Alice (tx) and Bob (rx)
    const rawPad = crypto.randomBytes(16384);
    const alicePad = path.join(tmpRoot, 'alice-tx.pad');
    const bobPad = path.join(tmpRoot, 'bob-rx.pad');
    initPadPool(alicePad, rawPad.length, { sourceBytes: rawPad });
    initPadPool(bobPad, rawPad.length, { sourceBytes: rawPad });

    const secretMsg = Buffer.from('TOP SECRET PQ+PSI PAYLOAD — 99-DIMENSIONAL ONION ARTICHOKE');
    const enc = await encryptArtichokeBuffer(secretMsg, {
      senderIdentity: alice,
      recipientPub: bob.pub,
      padPoolPath: alicePad,
      ctCoprocessor: ct, // encrypted using C11 branchless CT coprocessor!
    });
    assert.equal(enc.securityTier, 'ARTICHOKE_5LAYER_TRIPLE_KEM_CASCADE_OTP_CW128');
    assert.equal(enc.bucketBytes, 4096); // Fixed-4096B traffic-analysis bucket

    // 1-bit tamper on ciphertext body MUST fail before pad/AEAD
    const tampered = Buffer.from(enc.envelope);
    tampered[tampered.length - 1] ^= 0x01;
    await assert.rejects(
      () => decryptArtichokeBuffer(tampered, { recipientIdentity: bob, trustStore: bobTrust, padPoolPath: bobPad }),
      /SIGNATURE_INVALID/,
    );

    // Decrypt WITHOUT ctCoprocessor to prove 100% bit-exact C11 <-> Node interoperability!
    const dec = await decryptArtichokeBuffer(enc.envelope, {
      recipientIdentity: bob,
      trustStore: bobTrust,
      padPoolPath: bobPad,
      ctCoprocessor: null,
    });
    assert.deepEqual(dec.plaintext, secretMsg);
    assert.equal(dec.psiVerified, true);

    // Replaying same envelope MUST fail with PAD_REUSE_ALARM (receiver shredded offset!)
    await assert.rejects(
      () => decryptArtichokeBuffer(enc.envelope, { recipientIdentity: bob, trustStore: bobTrust, padPoolPath: bobPad }),
      /PAD_REUSE_ALARM/,
    );
  });

  // 7. TCP 1-Byte Fragmentation & Burst Coalescing Torture Test on Guardian v2 (`framed: true`)
  await test('V3-07 Level 2 Wire Framer & Guardian v2: survives 1-byte TCP splits + coalesced bursts', async () => {
    const cwR = crypto.randomBytes(16);
    const cwSeed = crypto.randomBytes(32);
    const g = createHardenedGuardian({
      cwControlKey: { r: cwR, padSeed: cwSeed },
      framed: true,
    });
    const addr = await g.start();
    try {
      const f1 = encodeWireFrame(sealCwFrame(cwR, cwSeed, 1n, Buffer.from('split-frame-one')));
      const f2 = encodeWireFrame(sealCwFrame(cwR, cwSeed, 2n, Buffer.from('coalesced-two')));
      const f3 = encodeWireFrame(sealCwFrame(cwR, cwSeed, 3n, Buffer.from('coalesced-three')));

      const responses = await new Promise((resolve, reject) => {
        const sock = net.createConnection({ host: '127.0.0.1', port: addr.tcpPort });
        let acc = '';
        sock.on('data', (d) => {
          acc += d.toString('utf8');
          const lines = acc.trim().split('\n').filter(Boolean);
          if (lines.length >= 3) {
            sock.end();
            resolve(lines.map((l) => JSON.parse(l)));
          }
        });
        sock.on('error', reject);
        sock.on('connect', () => {
          // Trickle frame 1 one byte at a time, then blast f2+f3 coalesced in a single write!
          let idx = 0;
          const sendByte = () => {
            if (idx < f1.length) {
              sock.write(f1.subarray(idx, idx + 1));
              idx++;
              setImmediate(sendByte);
            } else {
              sock.write(Buffer.concat([f2, f3]));
            }
          };
          sendByte();
        });
      });
      assert.equal(responses.length, 3);
      assert.ok(responses.every((r) => r.ok === true));

      // Framer unit guard: oversize header immediately fails closed
      let overflowCaught = false;
      const fr = new LengthPrefixedFramer({ maxFrameBytes: 1024, onError: () => { overflowCaught = true; } });
      const badHdr = Buffer.alloc(4);
      badHdr.writeUInt32BE(2048, 0);
      fr.push(badHdr);
      assert.equal(overflowCaught, true);
    } finally {
      await g.stop();
    }
  });

  // 8. PQ Double-Ratchet: Forward Secrecy, Out-of-Order, Replay, Downgrade, Skip-DoS & PQ Rekey
  await test('V3-08 Level 2 PQ Double-Ratchet: out-of-order, replay/downgrade/skip-DoS reject & epoch rekey', async () => {
    const root = crypto.randomBytes(32);
    const tr = crypto.randomBytes(32);
    const init = new PqDoubleRatchetSession({ rootKey32: root, role: 'initiator', transcriptHash32: tr, ctCoprocessor: ct });
    const resp = new PqDoubleRatchetSession({ rootKey32: root, role: 'responder', transcriptHash32: tr, ctCoprocessor: ct });

    const p0 = await init.sealPacket(Buffer.from('pkt-0'));
    const p1 = await init.sealPacket(Buffer.from('pkt-1'));
    const p2 = await init.sealPacket(Buffer.from('pkt-2'));

    // Deliver out-of-order: 2, 0, 1
    assert.equal((await resp.openPacket(p2)).plaintext.toString(), 'pkt-2');
    assert.equal((await resp.openPacket(p0)).plaintext.toString(), 'pkt-0');
    assert.equal((await resp.openPacket(p1)).plaintext.toString(), 'pkt-1');

    // Replay of p0 MUST fail
    await assert.rejects(() => resp.openPacket(p0), /REPLAY/);
    // CW-128 strip downgrade attack MUST fail
    const stripped = Buffer.from(p2);
    stripped[1] = 0x00;
    await assert.rejects(() => resp.openPacket(stripped), /downgrade/);
    // Skip-DoS attack (forged seq = 9999) MUST fail
    const skipBomb = Buffer.from(p2);
    skipBomb.writeBigUInt64BE(9999n, 6);
    await assert.rejects(() => resp.openPacket(skipBomb), /SKIP_DOS/);

    // Asymmetric PQ Epoch Rekey (X25519 + ML-KEM-768)
    const rkInit = init.beginPqRekey();
    const rkAck = resp.respondPqRekey(rkInit);
    init.finishPqRekey(rkAck);
    assert.equal(init.epoch, 1);
    assert.equal(resp.epoch, 1);
    const pEp1 = await init.sealPacket(Buffer.from('post-compromise-healed'));
    assert.equal((await resp.openPacket(pEp1)).plaintext.toString(), 'post-compromise-healed');
    init.destroy();
    resp.destroy();
  });

  // 9. Live Two-Machine TCP 3-Message Handshake + Chaff + Auto-Rekey + MITM Refusal
  await test('V3-09 Level 2 Live TCP Daemon: 3-msg Triple-KEM handshake, chaff, auto-rekey & MITM reject', async () => {
    const alice = generateCompositeIdentityV3('tcp-alice');
    const bob = generateCompositeIdentityV3('tcp-bob');
    const eve = generateCompositeIdentityV3('tcp-eve');

    const aliceTrust = new PeerTrustStore(null);
    aliceTrust.pinPeer(bob.pub);
    const bobTrust = new PeerTrustStore(null);
    bobTrust.pinPeer(alice.pub);

    const received = [];
    const srv = createPqsiTcpServer({
      identity: bob,
      trustStore: bobTrust,
      rekeyAfterPackets: 3,
      ctCoprocessor: ct,
      onMessage: (buf, meta) => received.push({ text: buf.toString('utf8'), epoch: meta.epoch }),
    });
    const addr = await srv.start();
    try {
      // Unpinned MITM Eve MUST be rejected during handshake
      const eveTrust = new PeerTrustStore(null);
      eveTrust.pinPeer(bob.pub);
      await assert.rejects(
        () => new Promise((res, rej) => {
          connectPqsiTcpClient({ identity: eve, trustStore: eveTrust, port: addr.port }).then(res, rej);
          setTimeout(() => rej(new Error('MITM_REJECTED_CLOSED')), 800);
        }),
      );

      // Legitimate Alice connects, sends chaff + 6 messages triggering live PQ epoch rekey!
      const sess = await connectPqsiTcpClient({
        identity: alice,
        trustStore: aliceTrust,
        port: addr.port,
        rekeyAfterPackets: 3,
        ctCoprocessor: ct,
      });
      await sess.sendChaff();
      for (let i = 0; i < 6; i++) {
        await sess.sendMessage(`live-msg-${i}`);
        await new Promise((r) => setTimeout(r, 40));
      }
      await new Promise((r) => setTimeout(r, 150));
      assert.equal(received.length, 6);
      assert.equal(received[0].text, 'live-msg-0');
      assert.equal(received[5].text, 'live-msg-5');
      assert.ok(sess.ratchet.epoch >= 1, `Expected live PQ rekey epoch >= 1, got ${sess.ratchet.epoch}`);
      sess.close();
    } finally {
      await srv.stop();
    }
  });

  // 10. Live Encrypted TCP Port-Forwarding Tunnel (PQ+PSI `ssh -L`)
  await test('V3-10 Level 2 Live Encrypted TCP Port-Forward Tunnel (PQ+PSI ssh -L)', async () => {
    // Spin up a real plaintext backend service behind the remote peer
    const backend = net.createServer((s) => {
      s.on('data', (d) => s.write(Buffer.concat([Buffer.from('BACKEND_ECHO:'), d])));
    });
    await new Promise((r) => backend.listen(0, '127.0.0.1', r));
    const backendPort = backend.address().port;

    const alice = generateCompositeIdentityV3('tun-alice');
    const bob = generateCompositeIdentityV3('tun-bob');
    const aTrust = new PeerTrustStore(null); aTrust.pinPeer(bob.pub);
    const bTrust = new PeerTrustStore(null); bTrust.pinPeer(alice.pub);

    const srv = createPqsiTcpServer({
      identity: bob,
      trustStore: bTrust,
      allowedTunnelTargets: [`127.0.0.1:${backendPort}`],
    });
    const sAddr = await srv.start();
    const sess = await connectPqsiTcpClient({ identity: alice, trustStore: aTrust, port: sAddr.port });
    const fwd = createPqsiTcpPortForward({
      session: sess,
      targetHost: '127.0.0.1',
      targetPort: backendPort,
    });
    const fAddr = await fwd.start();

    try {
      const reply = await new Promise((resolve, reject) => {
        const sock = net.createConnection({ host: '127.0.0.1', port: fAddr.port });
        sock.on('connect', () => sock.write('HELLO_THROUGH_PQSI_TUNNEL'));
        sock.on('data', (d) => { sock.end(); resolve(d.toString('utf8')); });
        sock.on('error', reject);
      });
      assert.equal(reply, 'BACKEND_ECHO:HELLO_THROUGH_PQSI_TUNNEL');
    } finally {
      await fwd.stop();
      sess.close();
      await srv.stop();
      await new Promise((r) => backend.close(r));
    }
  });

  // 11. True 3-Hop Onion-Artichoke Circuit (Client -> Relay1 -> Relay2 -> Exit)
  await test('V3-11 Level 2 True 3-Hop Onion-Artichoke Circuit: zero relay plaintext visibility + reply peel', async () => {
    const r1Id = generateCompositeIdentityV3('onion-relay-1');
    const r2Id = generateCompositeIdentityV3('onion-relay-2');
    const exId = generateCompositeIdentityV3('onion-exit');

    const r1 = createOnionRelayNode({ identity: r1Id });
    const r2 = createOnionRelayNode({ identity: r2Id });
    const ex = createOnionRelayNode({
      identity: exId,
      onExitMessage: (plain, sender) => Buffer.from(`EXIT_GOT[${sender}]:${plain.toString('utf8')}`),
    });
    const [a1, a2, a3] = await Promise.all([r1.start(), r2.start(), ex.start()]);
    try {
      const reply = await sendOnionCircuitMessage({
        hops: [
          { host: a1.host, port: a1.port, pub: r1Id.pub },
          { host: a2.host, port: a2.port, pub: r2Id.pub },
          { host: a3.host, port: a3.port, pub: exId.pub },
        ],
        senderNodeId: 'ghost-client',
        payloadBuf: 'SECRET_3HOP_ONION_PAYLOAD',
      });
      assert.equal(reply.toString('utf8'), 'EXIT_GOT[ghost-client]:SECRET_3HOP_ONION_PAYLOAD');
      // Verify strict onion privacy invariants: Relay 1 & Relay 2 NEVER saw plaintext!
      assert.equal(r1.auditLog.length, 1);
      assert.equal(r1.auditLog[0].sawPlaintext, false);
      assert.equal(r1.auditLog[0].nextPort, a2.port);
      assert.equal(r2.auditLog.length, 1);
      assert.equal(r2.auditLog[0].sawPlaintext, false);
      assert.equal(r2.auditLog[0].nextPort, a3.port);
      assert.equal(ex.auditLog[0].sawPlaintext, true);
    } finally {
      await Promise.all([r1.stop(), r2.stop(), ex.stop()]);
    }
  });

  // 12. Level 3 Encrypted UDP Layer-3 Mesh VPN: Stateless DoS Cookie, RFC 791 IPv4, AllowedIPs & NAT Roaming
  await test('V3-12 Level 3 UDP L3 Mesh VPN: DoS cookie, RFC 791 IPv4, AllowedIPs anti-spoof & NAT roaming', async () => {
    const idA = generateCompositeIdentityV3('vpn-node-a');
    const idB = generateCompositeIdentityV3('vpn-node-b');
    const trA = new PeerTrustStore(null); trA.pinPeer(idB.pub);
    const trB = new PeerTrustStore(null); trB.pinPeer(idA.pub);

    const rxOnB = [];
    const nodeB = new UdpMeshVpnNode({
      identity: idB,
      trustStore: trB,
      tunnelIp: '10.99.0.2',
      allowedPeerIps: new Map([['vpn-node-a', new Set(['10.99.0.1'])]]),
      requireCookie: true,
      ctCoprocessor: ct,
      onL3Packet: (parsed) => rxOnB.push(parsed),
    });
    const nodeA = new UdpMeshVpnNode({
      identity: idA,
      trustStore: trA,
      tunnelIp: '10.99.0.1',
      allowedPeerIps: new Map([['vpn-node-b', new Set(['10.99.0.2'])]]),
      requireCookie: true,
      ctCoprocessor: ct,
    });
    const addrB = await nodeB.start();
    await nodeA.start();
    const roamedSock = dgram.createSocket('udp4');
    await new Promise((r) => roamedSock.bind(0, '127.0.0.1', r));

    try {
      await nodeA.connectToPeer(addrB.host, addrB.port);
      assert.ok(nodeB.stats.cookiesIssued >= 1, 'Expected WireGuard-style stateless DoS cookie challenge');
      assert.equal(nodeB.stats.handshakesCompleted, 1);

      // 1. Valid RFC 791 IPv4 packet (10.99.0.1 -> 10.99.0.2)
      const validIp4 = buildIpv4Packet({ srcIp: '10.99.0.1', dstIp: '10.99.0.2', payload: Buffer.from('L3_VPN_OK') });
      assert.equal(parseAndVerifyIpv4Packet(validIp4).ok, true);
      await nodeA.sendL3Packet('vpn-node-b', validIp4);

      // 2. Spoofed source IPv4 packet (10.99.0.99 -> 10.99.0.2) MUST be dropped by AllowedIPs!
      const spoofedIp4 = buildIpv4Packet({ srcIp: '10.99.0.99', dstIp: '10.99.0.2', payload: Buffer.from('SPOOF') });
      await nodeA.sendL3Packet('vpn-node-b', spoofedIp4);

      // 3. NAT Keepalive + Live Authenticated NAT Endpoint Roaming from new ephemeral UDP socket!
      await nodeA.sendKeepalive('vpn-node-b');
      const roamedIp4 = buildIpv4Packet({ srcIp: '10.99.0.1', dstIp: '10.99.0.2', payload: Buffer.from('ROAMED_OK') });
      await nodeA.sendL3Packet('vpn-node-b', roamedIp4, { overrideSocket: roamedSock });

      await new Promise((r) => setTimeout(r, 150));
      assert.equal(rxOnB.length, 2);
      assert.equal(rxOnB[0].payload.toString('utf8'), 'L3_VPN_OK');
      assert.equal(rxOnB[1].payload.toString('utf8'), 'ROAMED_OK');
      assert.equal(nodeB.stats.spoofedSourceDropped, 1);
      assert.equal(nodeB.stats.keepalivesRx, 1);
      assert.equal(nodeB.stats.roamingEvents, 1);
    } finally {
      await new Promise((r) => roamedSock.close(r));
      await nodeA.stop();
      await nodeB.stop();
    }
  });

  // 13. Active Zero-Trust Cyber-Defense Firewall & OS Rule Injection Defense
  await test('V3-13 Level 3 Active Firewall: 3-strike quarantine, netsh/nftables plan & injection reject', () => {
    const fw = new ActiveDefenseFirewall({ strikeThreshold: 3, enforceOsRules: false, platform: 'win32' });
    assert.equal(fw.isBlocked('198.51.100.7'), false);
    fw.reportIncident('198.51.100.7', 'cw-mac-reject');
    fw.reportIncident('198.51.100.7', 'cw-replay-reject');
    assert.equal(fw.isBlocked('198.51.100.7'), false);
    const q = fw.reportIncident('198.51.100.7', 'rate-flood');
    assert.equal(q.blocked, true);
    assert.equal(fw.isBlocked('198.51.100.7'), true);
    assert.equal(q.osCmd.bin, 'netsh');

    const linuxCmd = buildOsBlockCommand('2001:db8::1', { platform: 'linux', ttlSec: 300 });
    assert.equal(linuxCmd.bin, 'nft');
    assert.ok(linuxCmd.args.join(' ').includes('blocklist6'));

    // Command-injection IPs MUST throw!
    assert.throws(() => buildOsBlockCommand('1.2.3.4 && calc.exe', { platform: 'win32' }));
    assert.throws(() => buildOsBlockCommand('1.2.3.4; rm -rf /', { platform: 'linux' }));
    assert.equal(fw.isBlocked('not-an-ip'), true); // fail-closed!
  });

  // 14. OS TUN/Wintun Driver Probe & Deploy Packaging Presence
  await test('V3-14 Level 3 OS TUN/Wintun Driver Probe & Deploy Artifacts (Docker, systemd, Windows)', () => {
    const probe = probeOsTunDriver();
    assert.ok(typeof probe.backend === 'string' && probe.backend.length > 0);
    assert.ok(fs.existsSync(path.join(REPO_ROOT, 'deploy', 'Dockerfile')));
    assert.ok(fs.existsSync(path.join(REPO_ROOT, 'deploy', 'secmeshd.service')));
    assert.ok(fs.existsSync(path.join(REPO_ROOT, 'deploy', 'install-windows-service.ps1')));
  });

  // 15. End-to-End Unified CLI Subprocess Workflow (keygen -> pin -> pad-init -> encrypt -> decrypt)
  await test('V3-15 End-to-End Unified CLI: keygen -> pin -> pad-init -> encrypt -> decrypt -> tun-probe', () => {
    const cli = path.join(REPO_ROOT, 'node', 'src', 'secmesh-cli.mjs');
    const run = (cliArgs) => JSON.parse(execFileSync(process.execPath, [cli, ...cliArgs], { encoding: 'utf8' }));
    const cliDir = path.join(tmpRoot, 'cli-e2e');
    fs.mkdirSync(cliDir, { recursive: true });

    const ksA = path.join(cliDir, 'a.ks.json');
    const ksB = path.join(cliDir, 'b.ks.json');
    const trB = path.join(cliDir, 'b-trust.json');
    const padA = path.join(cliDir, 'a.pad');
    const padB = path.join(cliDir, 'b.pad');
    const plainIn = path.join(cliDir, 'secret.txt');
    const encOut = path.join(cliDir, 'secret.sm3');
    const decOut = path.join(cliDir, 'secret.dec.txt');
    const pw = 'cli-e2e-argon2id-test-passphrase!';

    assert.equal(run(['keygen', '--id', 'cli-a', '--out', ksA, '--pass', pw, '--fast-kdf']).ok, true);
    assert.equal(run(['keygen', '--id', 'cli-b', '--out', ksB, '--pass', pw, '--fast-kdf']).ok, true);
    assert.equal(run(['pin', '--trust', trB, '--peer', ksA]).ok, true);

    // Synchronized pad pool for CLI PSI test
    const padInit = run(['pad-init', '--out', padA, '--bytes', '16384']);
    assert.equal(padInit.ok, true);
    fs.copyFileSync(padA, padB);
    fs.copyFileSync(`${padA}.ledger.json`, `${padB}.ledger.json`);

    fs.writeFileSync(plainIn, 'REAL END-TO-END CLI ENCRYPTED PAYLOAD v3.0');
    const encRes = run(['encrypt', '--in', plainIn, '--out', encOut, '--sender', ksA, '--pass', pw, '--to', ksB, '--pad', padA]);
    assert.equal(encRes.ok, true);
    assert.equal(encRes.securityTier, 'ARTICHOKE_5LAYER_TRIPLE_KEM_CASCADE_OTP_CW128');

    const decRes = run(['decrypt', '--in', encOut, '--out', decOut, '--recipient', ksB, '--pass', pw, '--trust', trB, '--pad', padB]);
    assert.equal(decRes.ok, true);
    assert.equal(decRes.psiVerified, true);
    assert.equal(fs.readFileSync(decOut, 'utf8'), 'REAL END-TO-END CLI ENCRYPTED PAYLOAD v3.0');

    const fwPlan = run(['firewall-plan', '--ip', '203.0.113.42', '--platform', 'linux']);
    assert.equal(fwPlan.ok, true);
    assert.equal(fwPlan.bin, 'nft');
  });
} finally {
  await ct.close();
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}

console.log(`=== Onion-Artichoke v3.0 Summary: ${passed} passed, ${failed} failed ===`);
process.exit(failed === 0 ? 0 : 1);
