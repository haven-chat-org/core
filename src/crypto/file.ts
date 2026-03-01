import { getSodium, randomBytes } from "./utils.js";

export interface EncryptedFile {
  encrypted: Uint8Array;
  key: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Encrypt a file using XSalsa20-Poly1305 (crypto_secretbox).
 * Generates a random key and nonce.
 */
export function encryptFile(plaintext: Uint8Array): EncryptedFile {
  const sodium = getSodium();
  const key = randomBytes(sodium.crypto_secretbox_KEYBYTES);
  const nonce = randomBytes(sodium.crypto_secretbox_NONCEBYTES);
  const encrypted = sodium.crypto_secretbox_easy(plaintext, nonce, key);
  return { encrypted, key, nonce };
}

/**
 * Decrypt a file encrypted with encryptFile.
 */
export function decryptFile(encrypted: Uint8Array, key: Uint8Array, nonce: Uint8Array): Uint8Array {
  const sodium = getSodium();
  return sodium.crypto_secretbox_open_easy(encrypted, nonce, key);
}

/**
 * Compute a SHA-256 hash of plaintext file bytes (before encryption).
 * Used for known-bad hash matching without breaking E2EE.
 */
export async function hashFile(plaintext: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", plaintext as unknown as ArrayBuffer);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
