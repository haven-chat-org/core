/**
 * X3DH (Extended Triple Diffie-Hellman) key agreement.
 *
 * Establishes a shared secret between Alice (initiator) and Bob (responder)
 * even if Bob is offline. Alice fetches Bob's key bundle from the server.
 *
 * Protocol:
 *   DH1 = DH(IK_A, SPK_B)        — Alice's identity × Bob's signed prekey
 *   DH2 = DH(EK_A, IK_B)         — Alice's ephemeral × Bob's identity
 *   DH3 = DH(EK_A, SPK_B)        — Alice's ephemeral × Bob's signed prekey
 *   DH4 = DH(EK_A, OPK_B)        — Alice's ephemeral × Bob's one-time prekey (if available)
 *   SK  = HKDF(DH1 || DH2 || DH3 || DH4)
 *
 * All identity keys are Ed25519 (converted to X25519 for DH).
 * All prekeys and ephemeral keys are X25519 natively.
 */

import {
  type IdentityKeyPair,
  type DHKeyPair,
  dh,
  ed25519PkToX25519,
  ed25519SkToX25519,
  generateDHKeyPair,
  verifySignature,
} from "./keys.js";
import { hkdf, fromBase64 } from "./utils.js";
import type { KeyBundle } from "../types.js";

const X3DH_INFO = new TextEncoder().encode("haven_x3dh");
const PADDING = new Uint8Array(32).fill(0xff);

export interface X3DHResult {
  /** The derived shared secret (32 bytes). Initializes the Double Ratchet. */
  sharedKey: Uint8Array;

  /** Associated data: IK_A || IK_B (for AEAD binding in Double Ratchet). */
  associatedData: Uint8Array;

  /** The ephemeral public key Alice used (sent to Bob in the initial message). */
  ephemeralPublicKey: Uint8Array;
}

/**
 * Alice (initiator): compute X3DH shared secret from Bob's key bundle.
 *
 * @param aliceIdentity  Alice's long-term Ed25519 identity keypair
 * @param bobBundle      Bob's key bundle fetched from the server
 * @returns The shared key, associated data, and ephemeral key to include in the initial message
 */
export function x3dhInitiate(
  aliceIdentity: IdentityKeyPair,
  bobBundle: KeyBundle,
): X3DHResult {
  // Decode Bob's keys from base64
  const bobIdentityEd = fromBase64(bobBundle.identity_key);
  const bobSignedPreKey = fromBase64(bobBundle.signed_prekey);
  const bobSignedPreKeySig = fromBase64(bobBundle.signed_prekey_sig);
  const bobOneTimePreKey = bobBundle.one_time_prekey
    ? fromBase64(bobBundle.one_time_prekey)
    : null;

  // Verify Bob's signed prekey signature using his Ed25519 identity key
  if (!verifySignature(bobSignedPreKeySig, bobSignedPreKey, bobIdentityEd)) {
    throw new Error("X3DH: invalid signed prekey signature");
  }

  // Convert identity keys to X25519 for DH
  const aliceIdentityX = ed25519SkToX25519(aliceIdentity.privateKey);
  const bobIdentityX = ed25519PkToX25519(bobIdentityEd);

  // Generate Alice's ephemeral X25519 keypair
  const ephemeral = generateDHKeyPair();

  // Compute DH values
  const dh1 = dh(aliceIdentityX, bobSignedPreKey);
  const dh2 = dh(ephemeral.privateKey, bobIdentityX);
  const dh3 = dh(ephemeral.privateKey, bobSignedPreKey);

  // Concatenate: F || DH1 || DH2 || DH3 [|| DH4]
  const parts = [PADDING, dh1, dh2, dh3];
  if (bobOneTimePreKey) {
    parts.push(dh(ephemeral.privateKey, bobOneTimePreKey));
  }

  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const ikm = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    ikm.set(part, offset);
    offset += part.length;
  }

  // Derive shared key: HKDF(salt=zeros, ikm, info="haven_x3dh", L=32)
  const salt = new Uint8Array(32);
  const sharedKey = hkdf(salt, ikm, X3DH_INFO, 32);

  // Associated data binds the session to both identities
  const associatedData = new Uint8Array(64);
  associatedData.set(aliceIdentity.publicKey, 0);
  associatedData.set(bobIdentityEd, 32);

  return { sharedKey, associatedData, ephemeralPublicKey: ephemeral.publicKey };
}

/**
 * Bob (responder): compute X3DH shared secret from Alice's initial message.
 *
 * @param bobIdentity       Bob's long-term Ed25519 identity keypair
 * @param bobSignedPreKey   Bob's signed prekey pair (the one used in his bundle)
 * @param bobOneTimePreKey  Bob's one-time prekey pair (null if not used)
 * @param aliceIdentityPub  Alice's Ed25519 public identity key (from the initial message)
 * @param aliceEphemeralPub Alice's ephemeral X25519 public key (from the initial message)
 * @returns The shared key and associated data
 */
export function x3dhRespond(
  bobIdentity: IdentityKeyPair,
  bobSignedPreKey: DHKeyPair,
  bobOneTimePreKey: DHKeyPair | null,
  aliceIdentityPub: Uint8Array,
  aliceEphemeralPub: Uint8Array,
): Omit<X3DHResult, "ephemeralPublicKey"> {
  // Convert identity keys to X25519 for DH
  const bobIdentityX = ed25519SkToX25519(bobIdentity.privateKey);
  const aliceIdentityX = ed25519PkToX25519(aliceIdentityPub);

  // Compute DH values (mirror of Alice's computation)
  const dh1 = dh(bobSignedPreKey.privateKey, aliceIdentityX);
  const dh2 = dh(bobIdentityX, aliceEphemeralPub);
  const dh3 = dh(bobSignedPreKey.privateKey, aliceEphemeralPub);

  const parts = [PADDING, dh1, dh2, dh3];
  if (bobOneTimePreKey) {
    parts.push(dh(bobOneTimePreKey.privateKey, aliceEphemeralPub));
  }

  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const ikm = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    ikm.set(part, offset);
    offset += part.length;
  }

  const salt = new Uint8Array(32);
  const sharedKey = hkdf(salt, ikm, X3DH_INFO, 32);

  const associatedData = new Uint8Array(64);
  associatedData.set(aliceIdentityPub, 0);
  associatedData.set(bobIdentity.publicKey, 32);

  return { sharedKey, associatedData };
}
