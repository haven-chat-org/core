/**
 * Signal Protocol Double Ratchet implementation.
 *
 * Provides forward secrecy and break-in recovery for 1-on-1 DM sessions.
 * After X3DH establishes a shared secret, this module handles all subsequent
 * message encryption and decryption.
 *
 * References:
 *   - https://signal.org/docs/specifications/doubleratchet/
 *   - https://signal.org/docs/specifications/x3dh/
 */

import { type DHKeyPair, dh, generateDHKeyPair } from "./keys.js";
import { getSodium, kdfRK, kdfCK, randomBytes } from "./utils.js";

// ─── Constants ─────────────────────────────────────────

const MAX_SKIP = 256;
const NONCE_LEN = 24; // XChaCha20-Poly1305
const TAG_LEN = 16;   // Poly1305 auth tag

// ─── Types ─────────────────────────────────────────────

/** Message header sent in the clear (alongside ciphertext). */
export interface MessageHeader {
  dhPublicKey: Uint8Array; // Sender's current DH ratchet public key (32 bytes)
  pn: number;              // Previous sending chain length
  n: number;               // Message number in current sending chain
}

/** An encrypted Double Ratchet message ready for the wire. */
export interface EncryptedMessage {
  header: MessageHeader;
  nonce: Uint8Array;       // 24 bytes
  ciphertext: Uint8Array;  // Encrypted payload + Poly1305 tag
}

/** Serializable session state for persistence. */
export interface SessionState {
  dhSend: { publicKey: Uint8Array; privateKey: Uint8Array };
  dhRecv: Uint8Array | null;
  rootKey: Uint8Array;
  chainKeySend: Uint8Array | null;
  chainKeyRecv: Uint8Array | null;
  sendCount: number;
  recvCount: number;
  prevSendCount: number;
  skippedKeys: Array<{ dhPub: Uint8Array; n: number; mk: Uint8Array }>;
}

// ─── Session ───────────────────────────────────────────

export class DoubleRatchetSession {
  private dhSend: DHKeyPair;
  private dhRecv: Uint8Array | null;
  private rootKey: Uint8Array;
  private chainKeySend: Uint8Array | null;
  private chainKeyRecv: Uint8Array | null;
  private sendCount: number;
  private recvCount: number;
  private prevSendCount: number;
  private skippedKeys: Map<string, Uint8Array>; // "hex(dhPub):n" -> messageKey
  private associatedData: Uint8Array;

  private constructor(ad: Uint8Array) {
    this.dhSend = { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) };
    this.dhRecv = null;
    this.rootKey = new Uint8Array(32);
    this.chainKeySend = null;
    this.chainKeyRecv = null;
    this.sendCount = 0;
    this.recvCount = 0;
    this.prevSendCount = 0;
    this.skippedKeys = new Map();
    this.associatedData = ad;
  }

  /**
   * Initialize as the INITIATOR (Alice).
   * Called after X3DH produces a shared key.
   *
   * @param sharedKey       The SK from X3DH (32 bytes)
   * @param associatedData  AD = IK_A || IK_B (64 bytes)
   * @param bobSignedPreKeyPub  Bob's signed prekey public key (the one from X3DH)
   */
  static initAlice(
    sharedKey: Uint8Array,
    associatedData: Uint8Array,
    bobSignedPreKeyPub: Uint8Array,
  ): DoubleRatchetSession {
    const session = new DoubleRatchetSession(associatedData);

    session.dhSend = generateDHKeyPair();
    session.dhRecv = bobSignedPreKeyPub;

    // First ratchet step: derive initial sending chain key
    const [rk, cks] = kdfRK(sharedKey, dh(session.dhSend.privateKey, session.dhRecv));
    session.rootKey = rk;
    session.chainKeySend = cks;

    return session;
  }

  /**
   * Initialize as the RESPONDER (Bob).
   * Called after X3DH when Bob receives Alice's initial message.
   *
   * @param sharedKey       The SK from X3DH (32 bytes)
   * @param associatedData  AD = IK_A || IK_B (64 bytes)
   * @param bobSignedPreKeyPair  Bob's signed prekey pair (used in X3DH)
   */
  static initBob(
    sharedKey: Uint8Array,
    associatedData: Uint8Array,
    bobSignedPreKeyPair: DHKeyPair,
  ): DoubleRatchetSession {
    const session = new DoubleRatchetSession(associatedData);

    session.dhSend = bobSignedPreKeyPair;
    session.rootKey = sharedKey;
    // CKs and CKr are null — will be derived on first message

    return session;
  }

  // ─── Encrypt ───────────────────────────────────────

  /**
   * Encrypt a plaintext message.
   */
  encrypt(plaintext: Uint8Array): EncryptedMessage {
    if (!this.chainKeySend) {
      throw new Error("Sending chain not initialized");
    }

    const [newCK, mk] = kdfCK(this.chainKeySend);
    this.chainKeySend = newCK;

    const header: MessageHeader = {
      dhPublicKey: this.dhSend.publicKey,
      pn: this.prevSendCount,
      n: this.sendCount,
    };
    this.sendCount++;

    const { nonce, ciphertext } = this.aedEncrypt(mk, plaintext, header);
    return { header, nonce, ciphertext };
  }

  // ─── Decrypt ───────────────────────────────────────

  /**
   * Decrypt a received message.
   */
  decrypt(message: EncryptedMessage): Uint8Array {
    // Try skipped message keys first (out-of-order delivery)
    const skippedResult = this.trySkippedKeys(message);
    if (skippedResult) return skippedResult;

    // Check if we need a DH ratchet step (new DH key from sender)
    const needsRatchet =
      !this.dhRecv || !uint8Eq(message.header.dhPublicKey, this.dhRecv);

    if (needsRatchet) {
      this.skipKeys(message.header.pn);
      this.dhRatchet(message.header.dhPublicKey);
    }

    this.skipKeys(message.header.n);

    if (!this.chainKeyRecv) {
      throw new Error("Receiving chain not initialized");
    }

    const [newCK, mk] = kdfCK(this.chainKeyRecv);
    this.chainKeyRecv = newCK;
    this.recvCount++;

    return this.aedDecrypt(mk, message.ciphertext, message.nonce, message.header);
  }

  // ─── DH Ratchet Step ──────────────────────────────

  private dhRatchet(newDhPub: Uint8Array): void {
    this.prevSendCount = this.sendCount;
    this.sendCount = 0;
    this.recvCount = 0;
    this.dhRecv = newDhPub;

    // Derive new receiving chain
    const [rk1, ckr] = kdfRK(this.rootKey, dh(this.dhSend.privateKey, this.dhRecv));
    this.rootKey = rk1;
    this.chainKeyRecv = ckr;

    // Generate new DH keypair and derive new sending chain
    this.dhSend = generateDHKeyPair();
    const [rk2, cks] = kdfRK(this.rootKey, dh(this.dhSend.privateKey, this.dhRecv));
    this.rootKey = rk2;
    this.chainKeySend = cks;
  }

  // ─── Skipped Keys ─────────────────────────────────

  private skipKeys(until: number): void {
    if (!this.chainKeyRecv) return;

    if (until - this.recvCount > MAX_SKIP) {
      throw new Error("Too many skipped messages");
    }

    while (this.recvCount < until) {
      const [newCK, mk] = kdfCK(this.chainKeyRecv);
      this.chainKeyRecv = newCK;
      const key = skippedKeyId(this.dhRecv!, this.recvCount);
      this.skippedKeys.set(key, mk);
      this.recvCount++;
    }
  }

  private trySkippedKeys(message: EncryptedMessage): Uint8Array | null {
    const key = skippedKeyId(message.header.dhPublicKey, message.header.n);
    const mk = this.skippedKeys.get(key);
    if (!mk) return null;

    this.skippedKeys.delete(key);
    return this.aedDecrypt(mk, message.ciphertext, message.nonce, message.header);
  }

  // ─── AEAD Encryption ──────────────────────────────

  private aedEncrypt(
    mk: Uint8Array,
    plaintext: Uint8Array,
    header: MessageHeader,
  ): { nonce: Uint8Array; ciphertext: Uint8Array } {
    const nonce = randomBytes(NONCE_LEN);
    const ad = buildAD(this.associatedData, header);

    const ciphertext = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      ad,
      null, // nsec (unused in this AEAD)
      nonce,
      mk,
    );

    return { nonce, ciphertext };
  }

  private aedDecrypt(
    mk: Uint8Array,
    ciphertext: Uint8Array,
    nonce: Uint8Array,
    header: MessageHeader,
  ): Uint8Array {
    const ad = buildAD(this.associatedData, header);

    return getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // nsec
      ciphertext,
      ad,
      nonce,
      mk,
    );
  }

  // ─── Serialization ────────────────────────────────

  /**
   * Export session state for persistent storage.
   */
  serialize(): SessionState {
    return {
      dhSend: { publicKey: this.dhSend.publicKey, privateKey: this.dhSend.privateKey },
      dhRecv: this.dhRecv,
      rootKey: this.rootKey,
      chainKeySend: this.chainKeySend,
      chainKeyRecv: this.chainKeyRecv,
      sendCount: this.sendCount,
      recvCount: this.recvCount,
      prevSendCount: this.prevSendCount,
      skippedKeys: Array.from(this.skippedKeys.entries()).map(([id, mk]) => {
        const [hexPub, nStr] = id.split(":");
        return { dhPub: hexToBytes(hexPub), n: parseInt(nStr, 10), mk };
      }),
    };
  }

  /**
   * Restore a session from serialized state.
   */
  static deserialize(state: SessionState, associatedData: Uint8Array): DoubleRatchetSession {
    const session = new DoubleRatchetSession(associatedData);
    session.dhSend = state.dhSend;
    session.dhRecv = state.dhRecv;
    session.rootKey = state.rootKey;
    session.chainKeySend = state.chainKeySend;
    session.chainKeyRecv = state.chainKeyRecv;
    session.sendCount = state.sendCount;
    session.recvCount = state.recvCount;
    session.prevSendCount = state.prevSendCount;
    for (const { dhPub, n, mk } of state.skippedKeys) {
      session.skippedKeys.set(skippedKeyId(dhPub, n), mk);
    }
    return session;
  }
}

// ─── Wire Format ───────────────────────────────────────

/**
 * Serialize an encrypted message to bytes for transmission.
 * Format: [dh_pub:32][pn:4 LE][n:4 LE][nonce:24][ciphertext:rest]
 */
export function serializeMessage(msg: EncryptedMessage): Uint8Array {
  const buf = new Uint8Array(32 + 4 + 4 + NONCE_LEN + msg.ciphertext.length);
  const view = new DataView(buf.buffer);

  buf.set(msg.header.dhPublicKey, 0);
  view.setUint32(32, msg.header.pn, true);
  view.setUint32(36, msg.header.n, true);
  buf.set(msg.nonce, 40);
  buf.set(msg.ciphertext, 40 + NONCE_LEN);

  return buf;
}

/**
 * Deserialize bytes back into an encrypted message.
 */
export function deserializeMessage(buf: Uint8Array): EncryptedMessage {
  if (buf.length < 40 + NONCE_LEN + TAG_LEN) {
    throw new Error("Message too short");
  }

  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

  return {
    header: {
      dhPublicKey: buf.slice(0, 32),
      pn: view.getUint32(32, true),
      n: view.getUint32(36, true),
    },
    nonce: buf.slice(40, 40 + NONCE_LEN),
    ciphertext: buf.slice(40 + NONCE_LEN),
  };
}

// ─── Helpers ───────────────────────────────────────────

function buildAD(sessionAD: Uint8Array, header: MessageHeader): Uint8Array {
  const ad = new Uint8Array(sessionAD.length + 32 + 4 + 4);
  const view = new DataView(ad.buffer);

  ad.set(sessionAD, 0);
  ad.set(header.dhPublicKey, sessionAD.length);
  view.setUint32(sessionAD.length + 32, header.pn, true);
  view.setUint32(sessionAD.length + 36, header.n, true);

  return ad;
}

function skippedKeyId(dhPub: Uint8Array, n: number): string {
  return `${bytesToHex(dhPub)}:${n}`;
}

function uint8Eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
