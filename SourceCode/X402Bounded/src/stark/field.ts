/** Goldilocks, p = 2^64 - 2^32 + 1, and its cubic extension F_p[X]/(X^3 - X - 1). */
export const P = 0xffffffff00000001n;

/** Degree of the extension the challenges and openings live in. */
export const DEG = 3;

/** The multiplicative generator the commitment's cosets are shifted by. */
export const GENERATOR = 7n;

/** A primitive 2^32-th root of unity; every smaller two-adic generator is a power of it. */
const ROOT_32 = 0x185629dcda58878cn;

/** An element c0 + c1 X + c2 X^2 by its coefficients. */
export type E = readonly [bigint, bigint, bigint];
export const E0: E = [0n, 0n, 0n];
export const E1: E = [1n, 0n, 0n];
export const X: E = [0n, 1n, 0n];

export const add = (a: bigint, b: bigint): bigint => {
  const s = a + b;
  return s >= P ? s - P : s;
};
export const sub = (a: bigint, b: bigint): bigint => (a >= b ? a - b : a + P - b);
export const mul = (a: bigint, b: bigint): bigint => (a * b) % P;
export const neg = (a: bigint): bigint => (a === 0n ? 0n : P - a);

export function pow(a: bigint, e: bigint): bigint {
  let r = 1n;
  let b = a % P;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

export function inv(a: bigint): bigint {
  if (a === 0n) throw new Error("inverse of zero");
  return pow(a, P - 2n);
}

/** The generator of the subgroup of order 2^bits, bits at most 32. */
export function twoAdic(bits: number): bigint {
  if (bits < 0 || bits > 32) throw new Error("two-adic order out of range");
  let g = ROOT_32;
  for (let i = bits; i < 32; i++) g = (g * g) % P;
  return g;
}

export const eadd = (a: E, b: E): E => [add(a[0], b[0]), add(a[1], b[1]), add(a[2], b[2])];
export const esub = (a: E, b: E): E => [sub(a[0], b[0]), sub(a[1], b[1]), sub(a[2], b[2])];
export const eneg = (a: E): E => [neg(a[0]), neg(a[1]), neg(a[2])];

/** The product reduced by X^3 = X + 1, so X^4 = X^2 + X. */
export const emul = (a: E, b: E): E => {
  const c0 = a[0] * b[0];
  const c1 = a[0] * b[1] + a[1] * b[0];
  const c2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0];
  const c3 = a[1] * b[2] + a[2] * b[1];
  const c4 = a[2] * b[2];
  return [(c0 + c3) % P, (c1 + c3 + c4) % P, (c2 + c4) % P];
};
export const escale = (a: E, s: bigint): E => [(a[0] * s) % P, (a[1] * s) % P, (a[2] * s) % P];
export const lift = (s: bigint): E => [s, 0n, 0n];
export const eeq = (a: E, b: E): boolean => a[0] === b[0] && a[1] === b[1] && a[2] === b[2];
export const ezero = (a: E): boolean => a[0] === 0n && a[1] === 0n && a[2] === 0n;

/**
 * The inverse, by solving a * x = 1: the columns of multiplication by a are
 * a, aX and aX^2, and Gaussian elimination over F_p solves the system. Zero
 * has no pivot in its first column and is refused there.
 */
export function einv(a: E): E {
  const cols = [a, emul(a, X), emul(a, emul(X, X))];
  const m: bigint[][] = [0, 1, 2].map((r) => [cols[0][r], cols[1][r], cols[2][r], r === 0 ? 1n : 0n]);
  for (let c = 0; c < 3; c++) {
    const pivot = m.findIndex((row, r) => r >= c && row[c] !== 0n);
    if (pivot < 0) throw new Error("inverse of zero");
    [m[c], m[pivot]] = [m[pivot], m[c]];
    const iv = inv(m[c][c]);
    m[c] = m[c].map((v) => (v * iv) % P);
    for (let r = 0; r < 3; r++) {
      if (r === c) continue;
      const f = m[r][c];
      m[r] = m[r].map((v, k) => sub(v, (f * m[c][k]) % P));
    }
  }
  return [m[0][3], m[1][3], m[2][3]];
}

export function epow(a: E, e: bigint): E {
  let r: E = E1;
  let b = a;
  while (e > 0n) {
    if (e & 1n) r = emul(r, b);
    b = emul(b, b);
    e >>= 1n;
  }
  return r;
}

/** a^(2^k), by k squarings. */
export function esquarings(a: E, k: number): E {
  let r = a;
  for (let i = 0; i < k; i++) r = emul(r, r);
  return r;
}

/** Inverts many elements with one field inversion. */
export function ebatchInv(xs: readonly E[]): E[] {
  const pre: E[] = [];
  let acc: E = E1;
  for (const x of xs) {
    pre.push(acc);
    acc = emul(acc, x);
  }
  let t = einv(acc);
  const out: E[] = [];
  for (let i = xs.length - 1; i >= 0; i--) {
    out.push(emul(t, pre[i]));
    t = emul(t, xs[i]);
  }
  return out.reverse();
}

/** The index i read with its low `bits` bits in reverse order. */
export function bitrev(i: number, bits: number): number {
  let r = 0;
  for (let b = 0; b < bits; b++) r = (r * 2) + Math.floor(i / 2 ** b) % 2;
  return r;
}
