// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _sodium: any = null;

/**
 * Initialize the libsodium runtime. Must be called once before any crypto operations.
 */
export async function initSodium(): Promise<void> {
  if (_sodium) return;
  const mod = await import("libsodium-wrappers-sumo");
  await mod.default.ready;
  _sodium = mod.default;
}

/**
 * Get the initialized sodium instance. Throws if initSodium() hasn't been called.
 */
export function getSodium(): any {
  if (!_sodium) throw new Error("Call initSodium() before using crypto functions");
  return _sodium;
}

// ─── Encoding ──────────────────────────────────────────

export function toBase64(bytes: Uint8Array): string {
  const s = getSodium();
  return s.to_base64(bytes, s.base64_variants.ORIGINAL);
}

export function fromBase64(b64: string): Uint8Array {
  const s = getSodium();
  return s.from_base64(b64, s.base64_variants.ORIGINAL);
}

export function toHex(bytes: Uint8Array): string {
  return getSodium().to_hex(bytes);
}

export function fromHex(hex: string): Uint8Array {
  return getSodium().from_hex(hex);
}

export function randomBytes(n: number): Uint8Array {
  return getSodium().randombytes_buf(n);
}

// ─── HKDF-SHA256 ───────────────────────────────────────
// Used by both X3DH and the Double Ratchet.
// Implements RFC 5869 using HMAC-SHA256.

/**
 * HMAC-SHA256 using libsodium's crypto_auth_hmacsha256.
 * Key must be exactly 32 bytes.
 */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return getSodium().crypto_auth_hmacsha256(data, key);
}

/**
 * HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
 */
export function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
  return hmacSha256(salt, ikm);
}

/**
 * HKDF-Expand: derive `length` bytes from PRK + info.
 * length must be <= 255 * 32 = 8160 bytes.
 */
export function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  const output = new Uint8Array(n * hashLen);
  let prev: Uint8Array = new Uint8Array(0);

  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1);
    input.set(prev, 0);
    input.set(info, prev.length);
    input[prev.length + info.length] = i;
    prev = new Uint8Array(hmacSha256(prk, input));
    output.set(prev, (i - 1) * hashLen);
  }

  return new Uint8Array(output.buffer, 0, length);
}

/**
 * Full HKDF: Extract then Expand.
 */
export function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const prk = hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}

// ─── Ratchet KDFs (Signal spec) ────────────────────────

const RATCHET_INFO = new TextEncoder().encode("haven_ratchet");
const CHAIN_MSG_KEY = new Uint8Array([0x01]);
const CHAIN_NEXT_KEY = new Uint8Array([0x02]);

/**
 * KDF_RK: Root key ratchet step.
 * Returns [newRootKey, chainKey] (32 bytes each).
 */
export function kdfRK(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  const derived = hkdf(rootKey, dhOutput, RATCHET_INFO, 64);
  return [derived.slice(0, 32), derived.slice(32, 64)];
}

/**
 * KDF_CK: Chain key ratchet step.
 * Returns [newChainKey, messageKey].
 */
export function kdfCK(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const newChainKey = hmacSha256(chainKey, CHAIN_NEXT_KEY);
  const messageKey = hmacSha256(chainKey, CHAIN_MSG_KEY);
  return [newChainKey, messageKey];
}
