import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Credentials are random, prefixed, shown once, and stored only as SHA-256
 * digests. A database leak does not reveal usable credentials.
 */
export function generateToken(prefix: string, bytes = 32): string {
  if (!/^[a-z][a-z0-9]{1,11}$/.test(prefix)) throw new Error("token prefix must be 2-12 lowercase letters/digits");
  return `${prefix}_${randomBytes(bytes).toString("base64url")}`;
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/** A short, non-secret label for showing which credential is which ("abc_Xy12…"). */
export function tokenHint(token: string): string {
  const underscore = token.indexOf("_");
  const prefix = underscore > 0 ? token.slice(0, underscore + 1) : "";
  return `${prefix}${token.slice(prefix.length, prefix.length + 4)}…`;
}

export function looksLikeToken(value: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => value.startsWith(`${prefix}_`)) && /^[a-z0-9]+_[A-Za-z0-9_-]{20,200}$/.test(value);
}

const CLAIM_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"; // no 0/O, 1/I/L, U

/**
 * One-time setup codes let an agent fetch its credential straight into its
 * own secret store, so the credential never appears in a chat transcript.
 * 20 symbols from a 30-symbol alphabet is ~98 bits.
 */
export function generateClaimCode(): string {
  const bytes = randomBytes(20);
  let out = "";
  for (let i = 0; i < 20; i += 1) {
    out += CLAIM_ALPHABET[bytes[i]! % CLAIM_ALPHABET.length];
    if (i % 5 === 4 && i < 19) out += "-";
  }
  return out;
}

export function normalizeClaimCode(value: string): string | null {
  const compact = value.toUpperCase().replace(/[\s-]/g, "");
  if (compact.length !== 20 || ![...compact].every((ch) => CLAIM_ALPHABET.includes(ch))) return null;
  return compact.match(/.{5}/g)!.join("-");
}

export function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/** Encrypts secrets the aggregator must use later (webhook keys, signing secrets). */
export interface SecretBox {
  encrypt(plaintext: string): string;
  decrypt(ciphertext: string): string;
}

/** AES-256-GCM with a 32-byte key given as 64 hex characters. Output: v1:<iv>:<tag>:<ciphertext> (hex). */
export function createAesGcmSecretBox(keyHex: string): SecretBox {
  if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) throw new Error("encryption key must be 64 hex characters (32 bytes)");
  const key = Buffer.from(keyHex, "hex");
  return {
    encrypt(plaintext: string): string {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      return `v1:${iv.toString("hex")}:${cipher.getAuthTag().toString("hex")}:${body.toString("hex")}`;
    },
    decrypt(ciphertext: string): string {
      const [version, ivHex, tagHex, bodyHex] = ciphertext.split(":");
      if (version !== "v1" || !ivHex || !tagHex || bodyHex === undefined) throw new Error("unrecognized ciphertext");
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
      decipher.setAuthTag(Buffer.from(tagHex, "hex"));
      return Buffer.concat([decipher.update(Buffer.from(bodyHex, "hex")), decipher.final()]).toString("utf8");
    },
  };
}
