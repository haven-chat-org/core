/**
 * Signal-style Sender Keys protocol for group E2EE.
 *
 * Each member generates a sender key per channel. Messages are encrypted O(1)
 * using a symmetric chain ratchet. Distribution uses crypto_box_seal to each
 * recipient's X25519 identity key.
 *
 * Wire format (type 0x03):
 *   [0x03][distributionId:16][chainIndex:4 LE][nonce:24][ciphertext+tag]
 *   Overhead: 45 bytes + ciphertext
 *
 * References:
 *   - https://signal.org/docs/specifications/group-v2/
 */

import { getSodium, kdfCK, randomBytes, toBase64, fromBase64 } from "./utils.js";
import { ed25519PkToX25519, ed25519SkToX25519, type IdentityKeyPair } from "./keys.js";

// ─── Constants ─────────────────────────────────────────

const NONCE_LEN = 24;    // XChaCha20-Poly1305
const UUID_LEN = 16;     // UUID as bytes
const CHAIN_IDX_LEN = 4; // uint32 LE
const MAX_SKIP = 256;

export const GROUP_MSG_TYPE = 0x03;

// ─── Types ─────────────────────────────────────────────

/** The sender's own key state for one channel. */
export interface SenderKeyState {
  distributionId: Uint8Array;   // 16 bytes (UUID)
  chainKey: Uint8Array;         // 32 bytes — current chain key
  chainIndex: number;           // Current position in the chain
}

/** A received sender key from another member. */
export interface ReceivedSenderKey {
  distributionId: Uint8Array;   // 16 bytes
  chainKey: Uint8Array;         // 32 bytes — chain key at the index we received
  chainIndex: number;           // Chain index when this key was distributed
}

/** SKDM payload fields (before encryption). */
export interface SenderKeyDistributionPayload {
  distributionId: Uint8Array;   // 16 bytes
  chainKey: Uint8Array;         // 32 bytes
  chainIndex: number;
}

// ─── Sender Key Generation ─────────────────────────────

/**
 * Generate a fresh sender key for a channel.
 * Called when first joining a channel or after a re-key event.
 */
export function generateSenderKey(): SenderKeyState {
  return {
    distributionId: randomBytes(UUID_LEN),
    chainKey: randomBytes(32),
    chainIndex: 0,
  };
}

// ─── SKDM Payload Serialization ────────────────────────

/**
 * Serialize an SKDM payload for distribution.
 * Format: [distributionId:16][chainIndex:4 LE][chainKey:32] = 52 bytes
 */
export function createSkdmPayload(state: SenderKeyState): Uint8Array {
  const buf = new Uint8Array(16 + 4 + 32);
  const view = new DataView(buf.buffer);
  buf.set(state.distributionId, 0);
  view.setUint32(16, state.chainIndex, true);
  buf.set(state.chainKey, 20);
  return buf;
}

/**
 * Parse an SKDM payload back into structured data.
 */
export function parseSkdmPayload(buf: Uint8Array): SenderKeyDistributionPayload {
  if (buf.length < 52) throw new Error("SKDM payload too short");
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return {
    distributionId: buf.slice(0, 16),
    chainIndex: view.getUint32(16, true),
    chainKey: buf.slice(20, 52),
  };
}

// ─── SKDM Encryption / Decryption ─────────────────────

/**
 * Encrypt an SKDM for a single recipient using crypto_box_seal.
 * The recipient's Ed25519 identity key is converted to X25519 for sealing.
 */
export function encryptSkdm(
  skdmPayload: Uint8Array,
  recipientIdentityKeyEd25519: Uint8Array,
): Uint8Array {
  const sodium = getSodium();
  const recipientX25519 = ed25519PkToX25519(recipientIdentityKeyEd25519);
  return sodium.crypto_box_seal(skdmPayload, recipientX25519);
}

/**
 * Decrypt an SKDM received for us.
 */
export function decryptSkdm(
  encrypted: Uint8Array,
  ourIdentityKeyPair: IdentityKeyPair,
): Uint8Array {
  const sodium = getSodium();
  const ourX25519Pk = ed25519PkToX25519(ourIdentityKeyPair.publicKey);
  const ourX25519Sk = ed25519SkToX25519(ourIdentityKeyPair.privateKey);
  return sodium.crypto_box_seal_open(encrypted, ourX25519Pk, ourX25519Sk);
}

// ─── Group Message Encryption ──────────────────────────

/**
 * Encrypt a message using the sender's key for a channel.
 * Ratchets the chain forward. Returns the full wire-format bytes.
 *
 * Wire format:
 *   [0x03][distributionId:16][chainIndex:4 LE][nonce:24][ciphertext+tag]
 *
 * @param senderKey  The sender's key state (mutated: chain ratchets forward)
 * @param plaintext  The message plaintext bytes
 */
export function senderKeyEncrypt(
  senderKey: SenderKeyState,
  plaintext: Uint8Array,
): Uint8Array {
  const sodium = getSodium();

  // Ratchet the chain
  const [newChainKey, messageKey] = kdfCK(senderKey.chainKey);
  const currentIndex = senderKey.chainIndex;

  // Update sender state
  senderKey.chainKey = newChainKey;
  senderKey.chainIndex = currentIndex + 1;

  // Encrypt with AAD bound to the distribution ID
  const nonce = randomBytes(NONCE_LEN);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    senderKey.distributionId, // AAD
    null,
    nonce,
    messageKey,
  );

  // Build wire format
  const headerLen = 1 + UUID_LEN + CHAIN_IDX_LEN + NONCE_LEN;
  const buf = new Uint8Array(headerLen + ciphertext.length);
  const view = new DataView(buf.buffer);

  buf[0] = GROUP_MSG_TYPE;
  buf.set(senderKey.distributionId, 1);
  view.setUint32(1 + UUID_LEN, currentIndex, true);
  buf.set(nonce, 1 + UUID_LEN + CHAIN_IDX_LEN);
  buf.set(ciphertext, headerLen);

  return buf;
}

/**
 * Decrypt a group message using a received sender key.
 * Ratchets the received key forward to match the message's chain index.
 *
 * @param wireBytes   Full wire-format bytes (including type byte 0x03)
 * @param receivedKey The sender's key (mutated: ratchets forward)
 */
export function senderKeyDecrypt(
  wireBytes: Uint8Array,
  receivedKey: ReceivedSenderKey,
): Uint8Array {
  const sodium = getSodium();

  if (wireBytes[0] !== GROUP_MSG_TYPE) {
    throw new Error(`Expected group message type 0x03, got 0x${wireBytes[0].toString(16)}`);
  }

  const view = new DataView(wireBytes.buffer, wireBytes.byteOffset, wireBytes.byteLength);
  const distributionId = wireBytes.slice(1, 1 + UUID_LEN);
  const chainIndex = view.getUint32(1 + UUID_LEN, true);
  const nonce = wireBytes.slice(
    1 + UUID_LEN + CHAIN_IDX_LEN,
    1 + UUID_LEN + CHAIN_IDX_LEN + NONCE_LEN,
  );
  const ciphertext = wireBytes.slice(1 + UUID_LEN + CHAIN_IDX_LEN + NONCE_LEN);

  // Verify distribution ID matches
  if (!uint8Eq(distributionId, receivedKey.distributionId)) {
    throw new Error("Distribution ID mismatch");
  }

  // Advance the chain to the required index
  const stepsNeeded = chainIndex - receivedKey.chainIndex;
  if (stepsNeeded < 0) {
    throw new Error("Message chain index is before our current state (already consumed)");
  }
  if (stepsNeeded > MAX_SKIP) {
    throw new Error(`Too many skipped messages: ${stepsNeeded}`);
  }

  // Ratchet forward to derive the correct message key
  let currentChainKey = receivedKey.chainKey;
  let messageKey: Uint8Array = new Uint8Array(32);

  for (let i = 0; i <= stepsNeeded; i++) {
    const [newCK, mk] = kdfCK(currentChainKey);
    if (i === stepsNeeded) {
      messageKey = mk;
      // Update received key to one past the message we just decrypted
      receivedKey.chainKey = newCK;
      receivedKey.chainIndex = chainIndex + 1;
    }
    currentChainKey = newCK;
  }

  // Decrypt
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    distributionId, // AAD
    nonce,
    messageKey,
  );
}

// ─── Helpers ───────────────────────────────────────────

function uint8Eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
