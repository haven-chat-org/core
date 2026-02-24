import type { IdentityKeyPair, DHKeyPair, SignedPreKey, SessionState } from "../crypto/index.js";

/**
 * Platform-agnostic storage interface for Haven crypto state.
 *
 * Implementations:
 *   - MemoryStore (dev/testing)
 *   - IndexedDB (web)
 *   - SQLite/SQLCipher (React Native, Tauri)
 */
export interface HavenStore {
  // ─── Identity Keys ─────────────────────────────────
  saveIdentityKeyPair(kp: IdentityKeyPair): Promise<void>;
  loadIdentityKeyPair(): Promise<IdentityKeyPair | null>;

  // ─── Signed Pre-Key ────────────────────────────────
  saveSignedPreKey(spk: SignedPreKey): Promise<void>;
  loadSignedPreKey(): Promise<SignedPreKey | null>;

  // ─── One-Time Pre-Keys (private halves) ────────────
  saveOneTimePreKeys(keys: DHKeyPair[]): Promise<void>;
  consumeOneTimePreKey(publicKey: Uint8Array): Promise<DHKeyPair | null>;

  // ─── Double Ratchet Sessions ───────────────────────
  saveSession(peerId: string, state: SessionState, associatedData: Uint8Array): Promise<void>;
  loadSession(peerId: string): Promise<{ state: SessionState; associatedData: Uint8Array } | null>;
  deleteSession(peerId: string): Promise<void>;
}
