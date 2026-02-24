import { getSodium, toBase64 } from "./utils.js";

// ─── Key Types ─────────────────────────────────────────

/** Ed25519 identity keypair — used for signing and converted to X25519 for DH. */
export interface IdentityKeyPair {
  publicKey: Uint8Array;  // Ed25519 public key (32 bytes)
  privateKey: Uint8Array; // Ed25519 secret key (64 bytes)
}

/** X25519 keypair for Diffie-Hellman (prekeys, ephemeral keys). */
export interface DHKeyPair {
  publicKey: Uint8Array;  // 32 bytes
  privateKey: Uint8Array; // 32 bytes
}

/** Signed prekey with Ed25519 signature from identity key. */
export interface SignedPreKey {
  keyPair: DHKeyPair;
  signature: Uint8Array; // Ed25519 signature over the public key
}

// ─── Key Generation ────────────────────────────────────

/**
 * Generate a new Ed25519 identity keypair.
 * The identity key is used for:
 *   - Signing the signed prekey (Ed25519)
 *   - X3DH DH operations (converted to X25519)
 */
export function generateIdentityKeyPair(): IdentityKeyPair {
  const kp = getSodium().crypto_sign_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/**
 * Generate a new X25519 DH keypair (for prekeys and ephemeral keys).
 */
export function generateDHKeyPair(): DHKeyPair {
  const kp = getSodium().crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/**
 * Generate a signed prekey: a DH keypair signed with the identity key.
 */
export function generateSignedPreKey(identityKeyPair: IdentityKeyPair): SignedPreKey {
  const keyPair = generateDHKeyPair();
  const signature = getSodium().crypto_sign_detached(keyPair.publicKey, identityKeyPair.privateKey);
  return { keyPair, signature };
}

/**
 * Generate a batch of one-time prekeys (X25519 DH keypairs).
 * Returns the keypairs — public keys get uploaded, private keys stored locally.
 */
export function generateOneTimePreKeys(count: number): DHKeyPair[] {
  return Array.from({ length: count }, () => generateDHKeyPair());
}

// ─── Key Conversion ────────────────────────────────────

/**
 * Convert an Ed25519 public key to an X25519 public key for DH.
 */
export function ed25519PkToX25519(edPk: Uint8Array): Uint8Array {
  return getSodium().crypto_sign_ed25519_pk_to_curve25519(edPk);
}

/**
 * Convert an Ed25519 secret key to an X25519 secret key for DH.
 */
export function ed25519SkToX25519(edSk: Uint8Array): Uint8Array {
  return getSodium().crypto_sign_ed25519_sk_to_curve25519(edSk);
}

// ─── DH & Signatures ──────────────────────────────────

/**
 * Perform X25519 Diffie-Hellman: shared_secret = DH(ourPrivate, theirPublic).
 */
export function dh(ourPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {
  return getSodium().crypto_scalarmult(ourPrivateKey, theirPublicKey);
}

/**
 * Verify an Ed25519 signature.
 */
export function verifySignature(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return getSodium().crypto_sign_verify_detached(signature, message, publicKey);
  } catch {
    return false;
  }
}

// ─── Serialization Helpers ─────────────────────────────

/**
 * Prepare the local key material for registration.
 * Returns base64-encoded values ready for the register API.
 */
export function prepareRegistrationKeys(
  identityKeyPair: IdentityKeyPair,
  signedPreKey: SignedPreKey,
  oneTimePreKeys: DHKeyPair[],
) {
  return {
    identity_key: toBase64(identityKeyPair.publicKey),
    signed_prekey: toBase64(signedPreKey.keyPair.publicKey),
    signed_prekey_signature: toBase64(signedPreKey.signature),
    one_time_prekeys: oneTimePreKeys.map((kp) => toBase64(kp.publicKey)),
  };
}
