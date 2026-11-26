// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Alexander S. Donahue
//
// SecMesh-PQSI v3.0 — Length-Prefixed Streaming Wire Framer & Traffic-Analysis Camouflage
// Closes the TCP stream-fragmentation / coalescing hole in raw chunk handlers:
//   - Wire format: [u32be frameLen | payload(frameLen)] with strict MAX_FRAME_BYTES OOM guard.
//   - Fixed-size Sphinx/Tor-style padded cells (`packFixedCell` / `unpackFixedCell`) + chaff cells
//     hiding message sizes and inter-arrival patterns from passive network observers.

import crypto from 'node:crypto';

export const WIRE_MAX_FRAME_BYTES = 131072; // 128 KiB hard cap per wire frame
export const DEFAULT_CELL_BYTES = 1024;

export const CELL_TYPE = Object.freeze({
  DATA: 0x01,
  REKEY_INIT: 0x02,
  REKEY_ACK: 0x03,
  TUNNEL_OPEN: 0x04,
  TUNNEL_DATA: 0x05,
  TUNNEL_CLOSE: 0x06,
  ONION_HOP: 0x07,
  ONION_REPLY: 0x08,
  L3_PACKET: 0x09,
  CHAFF: 0xFF,
});

export function encodeWireFrame(payloadBuf, maxBytes = WIRE_MAX_FRAME_BYTES) {
  const payload = Buffer.isBuffer(payloadBuf) ? payloadBuf : Buffer.from(payloadBuf);
  if (payload.length === 0 || payload.length > maxBytes) {
    throw new Error(`Invalid wire frame length: ${payload.length} (must be in 1..${maxBytes})`);
  }
  const hdr = Buffer.alloc(4);
  hdr.writeUInt32BE(payload.length, 0);
  return Buffer.concat([hdr, payload]);
}

/**
 * Stateful TCP stream reassembler surviving arbitrary 1-byte TCP fragmentation and
 * multi-frame coalescing while enforcing strict OOM bounds.
 */
export class LengthPrefixedFramer {
  constructor({ maxFrameBytes = WIRE_MAX_FRAME_BYTES, onFrame, onError } = {}) {
    this.maxFrameBytes = maxFrameBytes;
    this.onFrame = onFrame || (() => {});
    this.onError = onError || ((err) => { throw err; });
    this.buf = Buffer.alloc(0);
    this.totalFrames = 0;
    this.totalBytes = 0;
  }

  push(chunk) {
    const c = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (c.length === 0) return [];
    this.totalBytes += c.length;
    this.buf = this.buf.length === 0 ? Buffer.from(c) : Buffer.concat([this.buf, c]);

    const frames = [];
    while (this.buf.length >= 4) {
      const frameLen = this.buf.readUInt32BE(0);
      if (frameLen === 0 || frameLen > this.maxFrameBytes) {
        this.buf = Buffer.alloc(0);
        const err = new Error(`WIRE_FRAME_BOUNDS_VIOLATION: frameLen=${frameLen} (cap=${this.maxFrameBytes})`);
        this.onError(err);
        return frames;
      }
      if (this.buf.length < 4 + frameLen) {
        // Hard buffer cap check even while waiting for incomplete frame
        if (this.buf.length > 4 + this.maxFrameBytes) {
          this.buf = Buffer.alloc(0);
          this.onError(new Error('WIRE_BUFFER_OVERFLOW'));
        }
        break;
      }
      const frame = Buffer.from(this.buf.subarray(4, 4 + frameLen));
      this.buf = this.buf.length === 4 + frameLen
        ? Buffer.alloc(0)
        : Buffer.from(this.buf.subarray(4 + frameLen));
      this.totalFrames++;
      frames.push(frame);
      this.onFrame(frame);
    }
    return frames;
  }

  reset() {
    this.buf.fill(0);
    this.buf = Buffer.alloc(0);
  }
}

/**
 * Pack a typed payload into a uniform fixed-size cell (or bucket-multiple) with CSPRNG padding:
 *   [u8 cellType | u32be realPayloadLen | payload | randomPad]
 * Hides exact plaintext message lengths against traffic analysis.
 */
export function packFixedCell(cellType, payloadBuf = Buffer.alloc(0), bucketSize = DEFAULT_CELL_BYTES) {
  const payload = Buffer.isBuffer(payloadBuf) ? payloadBuf : Buffer.from(payloadBuf);
  const raw = 5 + payload.length;
  const total = Math.max(bucketSize, Math.ceil(raw / bucketSize) * bucketSize);
  const cell = Buffer.alloc(total);
  cell[0] = cellType & 0xFF;
  cell.writeUInt32BE(payload.length, 1);
  payload.copy(cell, 5);
  if (total > raw) {
    crypto.randomFillSync(cell, raw, total - raw);
  }
  return cell;
}

export function unpackFixedCell(cellBuf) {
  if (!Buffer.isBuffer(cellBuf) || cellBuf.length < 5) {
    throw new Error('Malformed fixed wire cell (< 5B)');
  }
  const cellType = cellBuf[0];
  const realLen = cellBuf.readUInt32BE(1);
  if (5 + realLen > cellBuf.length) {
    throw new Error(`Corrupt cell length (${realLen} > ${cellBuf.length - 5})`);
  }
  return {
    cellType,
    payload: Buffer.from(cellBuf.subarray(5, 5 + realLen)),
    paddedBytes: cellBuf.length,
  };
}

export function makeChaffCell(bucketSize = DEFAULT_CELL_BYTES) {
  return packFixedCell(CELL_TYPE.CHAFF, Buffer.alloc(0), bucketSize);
}
