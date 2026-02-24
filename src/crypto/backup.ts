/**
 * Encrypted key backup — derives a symmetric key from a security phrase
 * using Argon2id, then encrypts all crypto state with XSalsa20-Poly1305.
 */

import { getSodium, toBase64, fromBase64, randomBytes } from "./utils.js";

// Argon2id parameters — OWASP recommended for interactive hashing
const ARGON2_OPSLIMIT = 3;       // crypto_pwhash_OPSLIMIT_MODERATE
const ARGON2_MEMLIMIT = 67108864; // 64 MB — safe for browsers (256MB can OOM on mobile)
const SALT_BYTES = 16;            // crypto_pwhash_SALTBYTES

export interface BackupEncryptResult {
  encrypted: Uint8Array;
  nonce: Uint8Array;
  salt: Uint8Array;
}

/**
 * The plaintext JSON structure that gets encrypted into the backup blob.
 */
export interface BackupPayload {
  version: 1;
  identity: {
    publicKey: string;   // base64
    privateKey: string;  // base64
  };
  signedPreKey: {
    publicKey: string;   // base64
    privateKey: string;  // base64
    signature: string;   // base64
  };
  sessions: Record<string, {
    state: SerializedSessionState;
    ad: string; // base64
  }>;
  mySenderKeys: Record<string, {
    distributionId: string; // base64
    chainKey: string;       // base64
    chainIndex: number;
  }>;
  receivedSenderKeys: Record<string, {
    fromUserId: string;
    key: {
      distributionId: string; // base64
      chainKey: string;       // base64
      chainIndex: number;
    };
  }>;
  distributedChannels: string[];
  channelPeerMap: Record<string, string>;
  timestamp: string; // ISO-8601
}

/**
 * SessionState with Uint8Arrays serialized to base64 strings for JSON safety.
 */
export interface SerializedSessionState {
  dhSend: { publicKey: string; privateKey: string };
  dhRecv: string | null;
  rootKey: string;
  chainKeySend: string | null;
  chainKeyRecv: string | null;
  sendCount: number;
  recvCount: number;
  prevSendCount: number;
  skippedKeys: Array<{ dhPub: string; n: number; mk: string }>;
}

/**
 * Derive a 32-byte symmetric key from a security phrase using Argon2id.
 */
export function deriveBackupKey(
  securityPhrase: string,
  salt: Uint8Array,
): Uint8Array {
  const sodium = getSodium();
  return sodium.crypto_pwhash(
    sodium.crypto_secretbox_KEYBYTES, // 32
    securityPhrase,
    salt,
    ARGON2_OPSLIMIT,
    ARGON2_MEMLIMIT,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/**
 * Encrypt a backup payload with a security phrase.
 * Generates a fresh salt and nonce.
 */
export function encryptBackup(
  plaintext: Uint8Array,
  securityPhrase: string,
): BackupEncryptResult {
  const sodium = getSodium();
  const salt = randomBytes(SALT_BYTES);
  const key = deriveBackupKey(securityPhrase, salt);
  const nonce = randomBytes(sodium.crypto_secretbox_NONCEBYTES); // 24 bytes
  const encrypted = sodium.crypto_secretbox_easy(plaintext, nonce, key);
  return { encrypted, nonce, salt };
}

/**
 * Decrypt a backup payload using a security phrase, salt, and nonce.
 * Throws if the phrase is wrong (authentication failure).
 */
export function decryptBackup(
  encrypted: Uint8Array,
  nonce: Uint8Array,
  salt: Uint8Array,
  securityPhrase: string,
): Uint8Array {
  const sodium = getSodium();
  const key = deriveBackupKey(securityPhrase, salt);
  return sodium.crypto_secretbox_open_easy(encrypted, nonce, key);
}

/**
 * Generate a cryptographically random recovery key as a human-readable
 * string (groups of 4 base32 characters separated by dashes).
 *
 * Example: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567"
 * 20 random bytes = 160 bits of entropy.
 */
export function generateRecoveryKey(): string {
  const bytes = randomBytes(20);
  // Encode as base32 for human readability
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const b of bytes) {
    bits += b.toString(2).padStart(8, "0");
  }
  let encoded = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    encoded += base32Chars[parseInt(bits.slice(i, i + 5), 2)];
  }
  // Format into groups of 4
  const groups = encoded.match(/.{1,4}/g) || [];
  return groups.join("-");
}
