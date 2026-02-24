/**
 * Profile encryption: selective encryption of about_me, custom_status, custom_status_emoji.
 *
 * Model:
 * - User generates a 32-byte profile key on registration (stored client-side)
 * - Profile fields are JSON-serialized, then encrypted with XChaCha20-Poly1305 using the profile key
 * - The encrypted blob is stored on the server as `encrypted_profile`
 * - Profile key is distributed to contacts via crypto_box_seal (using recipient's identity public key)
 * - Recipients decrypt the profile key, then use it to decrypt the profile blob
 */

import { getSodium, toBase64, fromBase64, randomBytes } from "./utils.js";
import type { ProfileFields } from "../types.js";

/** Generate a random 32-byte profile key. */
export function generateProfileKey(): Uint8Array {
  return randomBytes(32);
}

/** Encrypt profile fields into a single blob using the profile key. */
export function encryptProfile(
  profileKey: Uint8Array,
  fields: ProfileFields
): Uint8Array {
  const s = getSodium();
  const plaintext = new TextEncoder().encode(JSON.stringify(fields));
  const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null, // additional data
    null, // nsec (unused)
    nonce,
    profileKey
  );
  // Format: [nonce || ciphertext]
  const result = new Uint8Array(nonce.length + ciphertext.length);
  result.set(nonce, 0);
  result.set(ciphertext, nonce.length);
  return result;
}

/** Decrypt a profile blob using the profile key. Returns the plaintext fields. */
export function decryptProfile(
  profileKey: Uint8Array,
  encrypted: Uint8Array
): ProfileFields {
  const s = getSodium();
  const nonceLen = s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  if (encrypted.length < nonceLen) {
    throw new Error("Encrypted profile too short");
  }
  const nonce = encrypted.slice(0, nonceLen);
  const ciphertext = encrypted.slice(nonceLen);
  const plaintext = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, // nsec (unused)
    ciphertext,
    null, // additional data
    nonce,
    profileKey
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

/**
 * Encrypt a profile key for a recipient using their identity public key.
 * Uses crypto_box_seal (anonymous, authenticated encryption).
 */
export function encryptProfileKeyFor(
  profileKey: Uint8Array,
  recipientIdentityPublicKey: Uint8Array
): Uint8Array {
  const s = getSodium();
  // Convert identity key (Ed25519) to X25519 for crypto_box
  const x25519Pub = s.crypto_sign_ed25519_pk_to_curve25519(recipientIdentityPublicKey);
  return s.crypto_box_seal(profileKey, x25519Pub);
}

/**
 * Decrypt a profile key that was encrypted to our identity key.
 * Requires both the public and secret parts of our identity key pair.
 */
export function decryptProfileKey(
  encryptedKey: Uint8Array,
  identityPublicKey: Uint8Array,
  identitySecretKey: Uint8Array
): Uint8Array {
  const s = getSodium();
  // Convert Ed25519 keys to X25519
  const x25519Pub = s.crypto_sign_ed25519_pk_to_curve25519(identityPublicKey);
  const x25519Sec = s.crypto_sign_ed25519_sk_to_curve25519(identitySecretKey);
  return s.crypto_box_seal_open(encryptedKey, x25519Pub, x25519Sec);
}

/** Convenience: encrypt profile fields and return as base64. */
export function encryptProfileToBase64(
  profileKey: Uint8Array,
  fields: ProfileFields
): string {
  return toBase64(encryptProfile(profileKey, fields));
}

/** Convenience: decrypt a base64 profile blob. */
export function decryptProfileFromBase64(
  profileKey: Uint8Array,
  encryptedBase64: string
): ProfileFields {
  return decryptProfile(profileKey, fromBase64(encryptedBase64));
}
