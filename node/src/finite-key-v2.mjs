// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v2.0 — Composable Finite-Key E91 / DI-QKD Admission Gate
// Fixes all 10 mathematical and cryptographic defects identified in
// BoogerCheeseOnRye/SecMesh@aff7dc6 (node-tests/entangle-qkd.mjs & finite-key-e91.tex).

import crypto from 'node:crypto';

export const TSIRELSON = 2 * Math.SQRT2;
// Exact singlet CHSH probabilities (fixes v1's super-quantum 0.146/0.854 => S=2.832 > 2*sqrt(2) bug!)
export const P_ANTI_EXACT = (2 - Math.SQRT2) / 4; // sin^2(pi/8) ≈ 0.14644660940672624
export const P_CORR_EXACT = (2 + Math.SQRT2) / 4; // cos^2(pi/8) ≈ 0.85355339059327376
export const CELL_P_EXACT = [
  [P_ANTI_EXACT, P_ANTI_EXACT],
  [P_ANTI_EXACT, P_CORR_EXACT],
];

export function binEntropy(p) {
  if (p <= 0 || p >= 1) return 0;
  return -(p * Math.log2(p) + (1 - p) * Math.log2(1 - p));
}

/**
 * Exact Pironio-Masanes-Acin (2010) single-round Device-Independent min-entropy:
 *   H_min^DI(S) = 1 - log2(1 + sqrt(2 - (S/2)^2))
 * Matches Tsotchke Moonlab qrng_di_min_entropy_from_chsh().
 */
export function minEntropyDI(S) {
  if (!Number.isFinite(S) || S <= 2) return 0;
  if (S >= TSIRELSON) return 1;
  const inside = Math.max(0, 2 - (S * S) / 4);
  return Math.max(0, Math.min(1, 1 - Math.log2(1 + Math.sqrt(inside))));
}

/**
 * Acin-Pironio (2007/2009) collective-attack single-round von Neumann entropy:
 *   H_vN^DI(S) = 1 - h((1 + sqrt((S/2)^2 - 1)) / 2)
 * Strictly dominates minEntropyDI(S) on (2, 2*sqrt(2)) (Theorem T1c).
 */
export function vonNeumannEntropyDI(S) {
  if (!Number.isFinite(S) || S <= 2) return 0;
  if (S >= TSIRELSON) return 1;
  const inside = Math.max(0, (S / 2) ** 2 - 1);
  const p = (1 + Math.sqrt(inside)) / 2;
  return Math.max(0, Math.min(1, 1 - binEntropy(p)));
}

/**
 * Corrected Hoeffding LOWER confidence bound on CHSH for ±1 variables (range width = 2):
 *   P(|E_c - mu_c| >= t_c) <= 2 * exp(-n_c * t_c^2 / 2) <= eps_PE / 4
 *   => t_c = sqrt(2 * ln(8 / eps_PE) / n_c)
 * Fixes the exact factor-of-2 radius / factor-of-4 exponent bug in SecMesh v1!
 */
export function chshLowerBoundV2(S, cnts, epsPE) {
  if (!Number.isFinite(S) || S <= 2 || !Array.isArray(cnts) || cnts.length !== 4) return 2;
  let err = 0;
  for (let c = 0; c < 4; c++) {
    if (!cnts[c] || cnts[c] <= 0) return 2;
    err += Math.sqrt((2 * Math.log(8 / epsPE)) / cnts[c]);
  }
  return Math.max(2, S - err);
}

function bernoulliKlNats(p, q) {
  if (q <= 0 || q >= 1) return Infinity;
  let v = 0;
  if (p > 0) v += p * Math.log(p / q);
  if (p < 1) v += (1 - p) * Math.log((1 - p) / (1 - q));
  return v;
}

/**
 * Exact Chernoff-KL upper confidence bound on Bernoulli QBER (matches C11 core):
 *   P(Bin(m, q) <= m * qberHat) <= exp(-m * D_KL(qberHat || q)) <= epsQBER
 */
export function qberUpperBound(errors, sampleSize, epsQBER) {
  if (
    !Number.isFinite(errors) ||
    !Number.isFinite(sampleSize) ||
    !Number.isFinite(epsQBER) ||
    sampleSize <= 0 ||
    errors < 0 ||
    errors > sampleSize ||
    epsQBER <= 0 ||
    epsQBER >= 1
  ) {
    return { qberHat: 1, qberUB: 0.5 };
  }
  const qberHat = errors / sampleSize;
  if (qberHat >= 0.5) return { qberHat, qberUB: 0.5 };
  const rhs = Math.log(1 / epsQBER) / sampleSize;
  if (qberHat <= 0) {
    return { qberHat: 0, qberUB: Math.min(0.5, 1 - Math.exp(-rhs)) };
  }
  if (bernoulliKlNats(qberHat, 0.5) <= rhs) return { qberHat, qberUB: 0.5 };
  let lo = qberHat;
  let hi = 0.5;
  for (let i = 0; i < 64; i++) {
    const mid = 0.5 * (lo + hi);
    if (bernoulliKlNats(qberHat, mid) < rhs) lo = mid;
    else hi = mid;
  }
  return { qberHat, qberUB: hi };
}

/**
 * Composable Finite-Key Gate v2 with disjoint 5-lane union budget:
 *   eps_PE + eps_QBER + eps_s + eps_PA + eps_cor = epsTotal
 */
export function evaluateFiniteKeyV2({
  S,
  cnts,
  nKey,
  qberErrors,
  qberSample,
  epsTotal = 1e-6,
  ecEfficiency = 1.16,
  mode = 'di_min_entropy',
  minKeyBits = 256,
}) {
  if (
    !Number.isFinite(S) ||
    !Number.isFinite(epsTotal) ||
    !Number.isFinite(ecEfficiency) ||
    !Number.isFinite(nKey) ||
    !Number.isFinite(qberSample) ||
    !Number.isFinite(qberErrors) ||
    epsTotal <= 0 ||
    epsTotal >= 1 ||
    nKey <= 0 ||
    qberSample < 0 ||
    qberSample > nKey ||
    qberErrors < 0 ||
    qberErrors > qberSample
  ) {
    return { admitted: false, certBits: 0, sLB: 2, qberHat: 1, qberUB: 0.5 };
  }
  const epsPE = epsTotal / 5;
  const epsQBER = epsTotal / 5;
  const epsS = epsTotal / 5;
  const epsPA = epsTotal / 5;
  const epsCor = epsTotal / 5;

  const sLB = chshLowerBoundV2(S, cnts, epsPE);
  const { qberHat, qberUB } = qberUpperBound(qberErrors, qberSample, epsQBER);
  const hMin = minEntropyDI(sLB);
  const hVn = vonNeumannEntropyDI(sLB);
  const hPer = mode === 'collective_vn' ? hVn : hMin;

  const nRem = Math.max(0, nKey - qberSample);
  const fEC = Math.max(1.0, ecEfficiency);
  const leakEC = nRem * fEC * binEntropy(qberUB);

  let aepPenalty = 0;
  if (nRem > 0) {
    if (mode === 'collective_vn') {
      const cTCR = 4 * Math.log2(2 + Math.SQRT2);
      aepPenalty = cTCR * Math.sqrt(nRem * Math.log2(2 / (epsS * epsS)));
    } else {
      aepPenalty = Math.sqrt(2 * nRem * Math.log(1 / epsS)) / Math.LN2;
    }
  }
  // Renner Quantum Leftover Hash Lemma: 2 * log2(1 / (2 * eps_PA))
  const paPenalty = 2 * Math.log2(1 / (2 * epsPA));
  const corPenalty = Math.ceil(Math.log2(1 / epsCor));

  const rawEll = nRem * hPer - leakEC - aepPenalty - paPenalty - corPenalty;
  const certBits = rawEll >= 1 ? Math.floor(rawEll) : 0;

  return {
    mode,
    epsTotal,
    epsBudget: { epsPE, epsQBER, epsS, epsPA, epsCor },
    sLB,
    qberHat,
    qberUB,
    hMinDI: hMin,
    hVnDI: hVn,
    nRem,
    leakEC,
    aepPenalty,
    paPenalty,
    corPenalty,
    certBits,
    admitted: certBits >= minKeyBits,
  };
}

/**
 * Exact reproduction of legacy SecMesh v1's defective formula (for contrast & regression tests ONLY).
 * NEVER use for admission decisions.
 */
export function evaluateLegacyV1BrokenGate({ S, sift, QBER, cnts, eps = 1e-6 }) {
  if (sift <= 0) return { certBits: 0, sLB: 2 };
  const epsS = eps / 3;
  let err = 0;
  for (let c = 0; c < 4; c++) {
    if (!cnts[c]) return { certBits: 0, sLB: 2 };
    err += Math.sqrt(Math.log(8 / epsS) / (2 * cnts[c])); // BUG: missing 4x factor for ±1 range
  }
  const sLB = Math.max(2, S - err);
  const per = Math.max(0, vonNeumannEntropyDI(sLB) - binEntropy(QBER)); // BUG: vN labeled H_min, point QBER
  if (per <= 0) return { certBits: 0, sLB };
  const aep = Math.sqrt(2 * sift * Math.log(1 / epsS)) / Math.LN2;
  const hash = Math.log2(3 / eps) + 3; // BUG: missing factor of 2 in LHL
  return { certBits: Math.max(0, Math.floor(sift * per - aep - hash)), sLB };
}

/**
 * 2-Universal Binary Toeplitz Privacy Amplification Extractor (pure JS mirror of
 * Moonlab qrng_di_toeplitz_extract — bit-for-bit differential verified against C11).
 * Raw and seed are Uint8Array packed LSB-first within each byte.
 */
export function toeplitzExtract(rawBytes, seedBytes, outLenBytes) {
  const nInBits = rawBytes.length * 8;
  const nOutBits = outLenBytes * 8;
  if (nInBits === 0 || nOutBits === 0) throw new Error('Invalid Toeplitz dimensions');
  const needSeedBits = nInBits + nOutBits - 1;
  if (seedBytes.length * 8 < needSeedBits) throw new Error('Toeplitz seed too short');

  const out = new Uint8Array(outLenBytes);
  for (let i = 0; i < nOutBits; i++) {
    let parity = 0;
    for (let j = 0; j < nInBits; j++) {
      const rBit = (rawBytes[j >> 3] >> (j & 7)) & 1;
      const sIdx = i + j;
      const sBit = (seedBytes[sIdx >> 3] >> (sIdx & 7)) & 1;
      parity ^= rBit & sBit;
    }
    if (parity) out[i >> 3] |= 1 << (i & 7);
  }
  return out;
}

/**
 * Seeded reproducible E91 channel simulator (explicitly labeled SIMULATION — NOT physical QKD).
 * Uses exact sin^2(pi/8) / cos^2(pi/8) singlet probabilities (never exceeds Tsirelson in expectation)
 * and CSPRNG when seed === null.
 */
export function simulateE91Session({
  nRounds = 450000,
  eveRate = 0,
  eveMode = 'flip', // 'flip' | 'aligned' | 'parked'
  seed = null,
  epsTotal = 1e-6,
  qberSampleFrac = 0.2,
} = {}) {
  // Deterministic ChaCha/SHAKE stream when seed !== null (reproducible benchmarks); OS CSPRNG otherwise
  let randBuf = Buffer.alloc(0);
  let randOff = 0;
  let blockCtr = 0n;
  const nextU32 = () => {
    if (randOff + 4 > randBuf.length) {
      if (seed !== null) {
        const hdr = Buffer.alloc(16);
        hdr.writeBigUInt64LE(BigInt(seed), 0);
        hdr.writeBigUInt64LE(blockCtr++, 8);
        randBuf = crypto.createHash('shake256', { outputLength: 4096 }).update(hdr).digest();
      } else {
        randBuf = crypto.randomBytes(4096);
      }
      randOff = 0;
    }
    const v = randBuf.readUInt32LE(randOff);
    randOff += 4;
    return v;
  };
  const nextUniform = () => nextU32() / 4294967296;
  const nextBase = () => {
    // Unbiased rejection sampling in {0, 1, 2}
    for (;;) {
      const v = nextU32();
      if (v < 4294967295) return v % 3;
    }
  };

  const sums = [0, 0, 0, 0];
  const cnts = [0, 0, 0, 0];
  let nKey = 0;
  let qberSample = 0;
  let qberErrors = 0;
  const rawKeyBytes = [];
  let curByte = 0;
  let curBit = 0;

  // For 'parked' Eve: exact disturbance eta = (1 - 2/(2*sqrt(2)))/2 * 0.6 ≈ 0.088
  // keeps |S| ≈ 2.33 > 2 while injecting ~8.8% QBER (fixes v1 paper's 0.058 typo!).
  const effEve = eveMode === 'parked' ? 0.088 : eveRate;

  for (let i = 0; i < nRounds; i++) {
    const a = nextBase();
    const b = nextBase();
    const bitA = nextU32() & 1;
    let agree;
    if (a === 0 && b === 0) {
      agree = false; // Singlet anti-correlation
    } else if (a >= 1 && b >= 1) {
      agree = nextUniform() < CELL_P_EXACT[a - 1][b - 1];
    } else {
      agree = (nextU32() & 1) === 1;
    }
    let bitB = bitA ^ (agree ? 0 : 1);
    const inKeyCell = a === 0 && b === 0;
    if (effEve > 0 && (eveMode === 'aligned' ? inKeyCell : true) && nextUniform() < effEve) {
      bitB ^= 1;
    }
    const finalAgree = bitB === bitA;

    if (a >= 1 && b >= 1) {
      const ci = (a - 1) * 2 + (b - 1);
      sums[ci] += finalAgree ? 1 : -1;
      cnts[ci]++;
    } else if (inKeyCell) {
      nKey++;
      // Random parameter-estimation sampling without replacement approximation
      if (nextUniform() < qberSampleFrac) {
        qberSample++;
        if (finalAgree) qberErrors++; // Singlet anti-correlated => agree is an error!
      } else {
        if (bitA) curByte |= 1 << curBit;
        curBit++;
        if (curBit === 8) {
          rawKeyBytes.push(curByte);
          curByte = 0;
          curBit = 0;
        }
      }
    }
  }

  let sSigned = 0;
  let missing = false;
  for (let c = 0; c < 4; c++) {
    if (cnts[c] === 0) { missing = true; break; }
    sSigned += (sums[c] / cnts[c]) * (c === 3 ? -1 : 1);
  }
  const S = missing ? 0 : Math.abs(sSigned);
  const cert = evaluateFiniteKeyV2({
    S,
    cnts,
    nKey,
    qberErrors,
    qberSample,
    epsTotal,
  });

  // Extract 32-byte (256-bit) key via 2-universal Toeplitz privacy amplification when admitted
  let extractedKeyFingerprint = null;
  if (cert.admitted && rawKeyBytes.length >= 64) {
    const rawArr = Uint8Array.from(rawKeyBytes.slice(0, Math.min(rawKeyBytes.length, 512)));
    const seedLen = Math.ceil((rawArr.length * 8 + 256 - 1) / 8);
    const seedArr = crypto.randomBytes(seedLen);
    const keyBytes = toeplitzExtract(rawArr, seedArr, 32);
    // Emit ONLY non-secret public fingerprint (SHA3-256 of domain||key) — NEVER raw key!
    extractedKeyFingerprint = crypto
      .createHash('sha3-256')
      .update('SecMesh-PQSI-PublicFingerprint|')
      .update(keyBytes)
      .digest('hex')
      .slice(0, 32);
    keyBytes.fill(0);
    rawArr.fill(0);
  }

  return {
    simulationOnly: true,
    physicalQkdHardware: false,
    nRounds,
    eveRate: effEve,
    eveMode,
    S,
    cnts,
    nKey,
    qberSample,
    qberErrors,
    cert,
    verdict: cert.admitted ? 'KEY' : 'ABORT',
    keyFingerprint: extractedKeyFingerprint,
  };
}
