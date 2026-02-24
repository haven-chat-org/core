import { getSodium, toBase64, fromBase64 } from "../crypto/utils.js";
import type { HavenManifest } from "./types.js";

/**
 * Produce a canonical JSON representation of the manifest for signing.
 * Excludes signature fields and uses sorted keys for determinism.
 */
function canonicalManifest(manifest: HavenManifest): string {
  const { user_signature: _u, server_signature: _s, ...rest } = manifest;
  return JSON.stringify(rest, Object.keys(rest).sort());
}

/**
 * Sign a manifest with an Ed25519 private key.
 * Returns a base64-encoded detached signature.
 */
export function signManifest(manifest: HavenManifest, privateKey: Uint8Array): string {
  const sodium = getSodium();
  const message = new TextEncoder().encode(canonicalManifest(manifest));
  const signature = sodium.crypto_sign_detached(message, privateKey);
  return toBase64(signature);
}

/**
 * Verify an Ed25519 signature over a manifest.
 */
export function verifyManifest(
  manifest: HavenManifest,
  signature: string,
  publicKey: Uint8Array,
): boolean {
  const sodium = getSodium();
  const message = new TextEncoder().encode(canonicalManifest(manifest));
  try {
    return sodium.crypto_sign_verify_detached(fromBase64(signature), message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Compute SHA-256 hex digest of arbitrary data.
 * Uses libsodium for Node.js + browser compatibility.
 */
export async function computeFileHash(data: Uint8Array): Promise<string> {
  const sodium = getSodium();
  const hash = sodium.crypto_hash_sha256(data);
  return Array.from(hash as Uint8Array)
    .map((b: number) => b.toString(16).padStart(2, "0"))
    .join("");
}
