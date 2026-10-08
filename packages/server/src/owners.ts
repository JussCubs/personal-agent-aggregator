import { generateToken, hashToken, newUuid, tokenHint, type OwnerPrincipal, type SqlDriver } from "@agent-aggregator/core";
import { TABLE_PREFIX } from "./storage.js";

/**
 * Owners are the people who connect agents and answer them. The reference
 * server authenticates an owner with a random bearer credential whose
 * SHA-256 digest is stored in owners.secret_hash; the credential itself is
 * shown once, at creation or rotation.
 */
export const OWNER_TOKEN_PREFIX = "aggown";

const table = `${TABLE_PREFIX}owners`;

export interface OwnerRecord {
  id: string;
  name: string | null;
}

export async function countOwners(driver: SqlDriver): Promise<number> {
  const rows = await driver.privileged((db) => db.query(`SELECT count(*) AS n FROM ${table}`));
  return Number(rows[0]?.n ?? 0);
}

export async function listOwners(driver: SqlDriver): Promise<OwnerRecord[]> {
  const rows = await driver.privileged((db) => db.query(`SELECT id, name FROM ${table} ORDER BY created_at, id LIMIT 1000`));
  return rows.map((row) => ({ id: String(row.id), name: (row.name as string | null) ?? null }));
}

// Built from code points so the source never contains invisible bidirectional characters.
const BIDI_CHARS = new RegExp(`[${String.fromCodePoint(0x061c, 0x200e, 0x200f)}${String.fromCodePoint(0x202a)}-${String.fromCodePoint(0x202e)}${String.fromCodePoint(0x2066)}-${String.fromCodePoint(0x2069)}]`, "g");
const CONTROL_CHARS = new RegExp(`[${String.fromCodePoint(0)}-${String.fromCodePoint(0x1f)}${String.fromCodePoint(0x7f)}-${String.fromCodePoint(0x9f)}]`, "g");

export function cleanOwnerName(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") throw new Error("owner name must be a string");
  const name = value.normalize("NFC").replace(CONTROL_CHARS, "").replace(BIDI_CHARS, "").trim();
  if (name.length > 80) throw new Error("owner name must be at most 80 characters");
  return name || null;
}

export async function createOwner(driver: SqlDriver, name: string | null): Promise<{ owner: OwnerRecord; credential: string; hint: string }> {
  const id = newUuid();
  const credential = generateToken(OWNER_TOKEN_PREFIX);
  await driver.privileged((db) =>
    db.query(`INSERT INTO ${table} (id, name, secret_hash, created_at) VALUES ($1, $2, $3, $4)`, [id, name, hashToken(credential), new Date().toISOString()]),
  );
  return { owner: { id, name }, credential, hint: tokenHint(credential) };
}

/** Replaces the owner's credential. The previous one stops working in the same transaction. */
export async function rotateOwnerCredential(driver: SqlDriver, ownerId: string): Promise<{ credential: string; hint: string } | null> {
  const credential = generateToken(OWNER_TOKEN_PREFIX);
  const rows = await driver.privileged((db) => db.query(`UPDATE ${table} SET secret_hash = $2 WHERE id = $1 RETURNING id`, [ownerId, hashToken(credential)]));
  return rows[0] ? { credential, hint: tokenHint(credential) } : null;
}

export async function authenticateOwner(driver: SqlDriver, token: string | null | undefined, surface: string | null): Promise<OwnerPrincipal | null> {
  if (typeof token !== "string" || !token.startsWith(`${OWNER_TOKEN_PREFIX}_`) || token.length < 20 || token.length > 300) return null;
  const rows = await driver.privileged((db) => db.query(`SELECT id, name FROM ${table} WHERE secret_hash = $1`, [hashToken(token)]));
  const row = rows[0];
  if (!row) return null;
  return { kind: "owner", ownerId: String(row.id), name: (row.name as string | null) ?? null, surface };
}
