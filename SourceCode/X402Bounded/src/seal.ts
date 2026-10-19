import { secp256k1 } from "@noble/curves/secp256k1";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { bytesToHex, hexToBytes, type Hex } from "viem";
import { decodeOpening, encodeOpening, type Opening } from "./opening.js";

const INFO = Buffer.from("x402-bounded opening seal v1");
const POINT = 33;
const NONCE = 12;
const TAG = 16;

function keyOf(shared: Uint8Array, ephemeral: Uint8Array, recipient: Uint8Array): Buffer {
  const salt = Buffer.concat([ephemeral, recipient]);
  return Buffer.from(hkdfSync("sha256", shared.subarray(1), salt, INFO, 32));
}

/** The public key, compressed, that openings are sealed to. */
export const sealingKeyOf = (privateKey: Hex): Hex => bytesToHex(secp256k1.getPublicKey(hexToBytes(privateKey), true));

/**
 * The opening encrypted to one recipient: an ephemeral key, ECDH on
 * secp256k1, HKDF-SHA256 and AES-256-GCM. Whoever stores the result learns
 * nothing of the fields, only its length, which is the same for every opening.
 */
export function seal(o: Opening, recipient: Hex): Hex {
  const to = hexToBytes(recipient);
  const e = secp256k1.utils.randomSecretKey();
  const ephemeral = secp256k1.getPublicKey(e, true);
  const key = keyOf(secp256k1.getSharedSecret(e, to, true), ephemeral, to);
  const nonce = randomBytes(NONCE);
  const c = createCipheriv("aes-256-gcm", key, nonce);
  c.setAAD(to);
  const body = Buffer.concat([c.update(hexToBytes(encodeOpening(o))), c.final()]);
  return bytesToHex(Buffer.concat([ephemeral, nonce, body, c.getAuthTag()]));
}

/** The opening a sealed blob holds. Throws if the blob was not sealed to this key or was altered. */
export function unseal(blob: Hex, privateKey: Hex): Opening {
  const b = Buffer.from(hexToBytes(blob));
  if (b.length < POINT + NONCE + TAG) throw new Error("sealed opening too short");
  const ephemeral = b.subarray(0, POINT);
  const nonce = b.subarray(POINT, POINT + NONCE);
  const body = b.subarray(POINT + NONCE, b.length - TAG);
  const sk = hexToBytes(privateKey);
  const to = secp256k1.getPublicKey(sk, true);
  const key = keyOf(secp256k1.getSharedSecret(sk, ephemeral, true), ephemeral, to);
  const d = createDecipheriv("aes-256-gcm", key, nonce);
  d.setAAD(to);
  d.setAuthTag(b.subarray(b.length - TAG));
  return decodeOpening(bytesToHex(Buffer.concat([d.update(body), d.final()])));
}
