import { P, eadd, emul, eneg, esub, lift, type E } from "./field.js";

const MAGIC = "PBDAG001";

/** The AIR's constraints as an expression graph, children before parents. */
export interface Constraints {
  width: number;
  globals: number;
  rowWidth: number;
  ops: Uint8Array;
  a: Uint32Array;
  b: Uint32Array;
  constants: Map<number, bigint>;
  roots: Uint32Array;
}

const enum Op {
  MainLocal = 0,
  MainNext = 1,
  Periodic = 2,
  Public = 3,
  FirstRow = 4,
  LastRow = 5,
  Transition = 6,
  Constant = 7,
  Add = 8,
  Sub = 9,
  Neg = 10,
  Mul = 11,
}

export function loadConstraints(bytes: Uint8Array): Constraints {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (new TextDecoder().decode(bytes.subarray(0, 8)) !== MAGIC) throw new Error("not a constraint graph");
  let at = 8;
  const u32 = () => {
    const v = view.getUint32(at, true);
    at += 4;
    return v;
  };
  const width = u32();
  const globals = u32();
  const rowWidth = u32();
  const nodes = u32();
  const count = u32();
  const ops = new Uint8Array(nodes);
  const a = new Uint32Array(nodes);
  const b = new Uint32Array(nodes);
  const constants = new Map<number, bigint>();
  for (let i = 0; i < nodes; i++) {
    const op = bytes[at++];
    if (op > Op.Mul) throw new Error("unknown node");
    ops[i] = op;
    if (op === Op.Constant) {
      const v = view.getBigUint64(at, true);
      if (v >= P) throw new Error("non-canonical constant");
      constants.set(i, v);
      at += 8;
    } else if (op <= Op.Public) {
      a[i] = u32();
    } else if (op === Op.Neg) {
      a[i] = u32();
      if (a[i] >= i) throw new Error("child after parent");
    } else if (op >= Op.Add) {
      a[i] = u32();
      b[i] = u32();
      if (a[i] >= i || b[i] >= i) throw new Error("child after parent");
    }
  }
  const roots = new Uint32Array(count);
  for (let i = 0; i < count; i++) roots[i] = u32();
  if (at !== bytes.length) throw new Error("trailing bytes in constraint graph");
  return { width, globals, rowWidth, ops, a, b, constants, roots };
}

/**
 * The degree of every constraint as a polynomial in the trace, counting the
 * first- and last-row selectors as one and the transition selector, constants
 * and public values as none. The quotient's chunk count follows from the largest.
 */
export function maxDegree(c: Constraints): number {
  const deg = new Uint16Array(c.ops.length);
  c.ops.forEach((op, i) => {
    switch (op) {
      case Op.MainLocal: case Op.MainNext: case Op.Periodic: case Op.FirstRow: case Op.LastRow:
        deg[i] = 1; break;
      case Op.Add: case Op.Sub:
        deg[i] = Math.max(deg[c.a[i]], deg[c.b[i]]); break;
      case Op.Neg:
        deg[i] = deg[c.a[i]]; break;
      case Op.Mul:
        deg[i] = deg[c.a[i]] + deg[c.b[i]]; break;
    }
  });
  let m = 0;
  for (const r of c.roots) m = Math.max(m, deg[r]);
  return m;
}

export interface Point {
  local: readonly E[];
  next: readonly E[];
  periodic: readonly E[];
  publics: readonly bigint[];
  firstRow: E;
  lastRow: E;
  transition: E;
}

/**
 * Evaluates every constraint at the out-of-domain point and folds them in the
 * order the AIR asserts them: acc = acc * alpha + c. Every value is taken in the
 * extension, base-field ones lifted.
 */
export function fold(c: Constraints, at: Point, alpha: E): E {
  const v = new Map<number, E>();
  const get = (i: number): E => v.get(i) as E;
  c.ops.forEach((op, i) => {
    const x = c.a[i];
    const y = c.b[i];
    switch (op) {
      case Op.MainLocal: v.set(i, at.local[x]); break;
      case Op.MainNext: v.set(i, at.next[x]); break;
      case Op.Periodic: v.set(i, at.periodic[x]); break;
      case Op.Public: v.set(i, lift(at.publics[x])); break;
      case Op.FirstRow: v.set(i, at.firstRow); break;
      case Op.LastRow: v.set(i, at.lastRow); break;
      case Op.Transition: v.set(i, at.transition); break;
      case Op.Constant: v.set(i, lift(c.constants.get(i) as bigint)); break;
      case Op.Neg: v.set(i, eneg(get(x))); break;
      case Op.Add: v.set(i, eadd(get(x), get(y))); break;
      case Op.Sub: v.set(i, esub(get(x), get(y))); break;
      case Op.Mul: v.set(i, emul(get(x), get(y))); break;
    }
  });
  let acc: E = [0n, 0n];
  for (const r of c.roots) acc = eadd(emul(acc, alpha), get(r));
  return acc;
}
