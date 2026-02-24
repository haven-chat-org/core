import type { IdentityKeyPair, DHKeyPair, SignedPreKey, SessionState } from "../crypto/index.js";
import type { HavenStore } from "./types.js";

/**
 * In-memory implementation of HavenStore.
 * Useful for development and testing. Data is lost on page reload.
 */
export class MemoryStore implements HavenStore {
  private identityKeyPair: IdentityKeyPair | null = null;
  private signedPreKey: SignedPreKey | null = null;
  private oneTimePreKeys: DHKeyPair[] = [];
  private sessions = new Map<string, { state: SessionState; associatedData: Uint8Array }>();

  async saveIdentityKeyPair(kp: IdentityKeyPair): Promise<void> {
    this.identityKeyPair = kp;
  }

  async loadIdentityKeyPair(): Promise<IdentityKeyPair | null> {
    return this.identityKeyPair;
  }

  async saveSignedPreKey(spk: SignedPreKey): Promise<void> {
    this.signedPreKey = spk;
  }

  async loadSignedPreKey(): Promise<SignedPreKey | null> {
    return this.signedPreKey;
  }

  async saveOneTimePreKeys(keys: DHKeyPair[]): Promise<void> {
    this.oneTimePreKeys.push(...keys);
  }

  async consumeOneTimePreKey(publicKey: Uint8Array): Promise<DHKeyPair | null> {
    const idx = this.oneTimePreKeys.findIndex(
      (kp) => uint8Eq(kp.publicKey, publicKey),
    );
    if (idx === -1) return null;
    return this.oneTimePreKeys.splice(idx, 1)[0];
  }

  async saveSession(
    peerId: string,
    state: SessionState,
    associatedData: Uint8Array,
  ): Promise<void> {
    this.sessions.set(peerId, { state, associatedData });
  }

  async loadSession(
    peerId: string,
  ): Promise<{ state: SessionState; associatedData: Uint8Array } | null> {
    return this.sessions.get(peerId) ?? null;
  }

  async deleteSession(peerId: string): Promise<void> {
    this.sessions.delete(peerId);
  }
}

function uint8Eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
