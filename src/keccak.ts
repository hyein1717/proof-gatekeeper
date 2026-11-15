/**
 * Keccak-256 (the original Keccak padding, as used by Ethereum — NOT the
 * NIST SHA3-256 variant in node:crypto). Pure TypeScript, no dependencies.
 * Verified against known vectors in the test harness:
 *   keccak256("")    = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
 *   keccak256("abc") = 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
 */

const MASK64 = (1n << 64n) - 1n;

const RC: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets r[x][y] flattened as r[x + 5*y]
const ROT: number[] = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

// Permutation targets pi[x + 5*y] = y + 5*((2x + 3y) % 5)
const PI: number[] = [
  0, 10, 20, 5, 15,
  16, 1, 11, 21, 6,
  7, 17, 2, 12, 22,
  23, 8, 18, 3, 13,
  14, 24, 9, 19, 4,
];

function rotl(x: bigint, n: number): bigint {
  if (n === 0) return x;
  const b = BigInt(n);
  return ((x << b) | (x >> (64n - b))) & MASK64;
}

function keccakF(state: bigint[]): void {
  for (let round = 0; round < 24; round++) {
    // theta
    const c: bigint[] = new Array(5);
    const d: bigint[] = new Array(5);
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
    }
    for (let i = 0; i < 25; i++) state[i] ^= d[i % 5];
    // rho + pi
    const b: bigint[] = new Array(25);
    for (let i = 0; i < 25; i++) b[PI[i]] = rotl(state[i], ROT[i]);
    // chi
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        const i = x + 5 * y;
        state[i] = b[i] ^ (~b[((x + 1) % 5) + 5 * y] & b[((x + 2) % 5) + 5 * y]);
      }
    }
    // iota
    state[0] ^= RC[round];
  }
}

export function keccak256(data: Uint8Array): Uint8Array {
  const RATE = 136; // 1088-bit rate for 256-bit output
  const state: bigint[] = new Array(25).fill(0n);

  const padded = new Uint8Array(data.length + (RATE - (data.length % RATE)));
  padded.set(data);
  padded[data.length] = 0x01; // Keccak pad10*1 domain byte
  padded[padded.length - 1] |= 0x80;

  for (let off = 0; off < padded.length; off += RATE) {
    for (let i = 0; i < RATE / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) {
        lane = (lane << 8n) | BigInt(padded[off + i * 8 + j]);
      }
      state[i] ^= lane;
    }
    keccakF(state);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = state[i];
    for (let j = 0; j < 8; j++) {
      out[i * 8 + j] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

export function keccak256Hex(text: string): string {
  const digest = keccak256(new TextEncoder().encode(text));
  return "0x" + [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}
