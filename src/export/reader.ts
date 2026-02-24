import { unzipSync } from "fflate";
import { fromBase64 } from "../crypto/utils.js";
import type {
  HavenManifest,
  HavenChannelExport,
  HavenServerExport,
} from "./types.js";
import { verifyManifest, computeFileHash } from "./signing.js";

/**
 * Reads and verifies a .haven archive (ZIP).
 */
export class HavenArchiveReader {
  private files: Record<string, Uint8Array>;
  private manifest: HavenManifest;

  private constructor(files: Record<string, Uint8Array>, manifest: HavenManifest) {
    this.files = files;
    this.manifest = manifest;
  }

  /**
   * Parse a .haven archive from raw ZIP bytes.
   */
  static async fromBlob(data: Uint8Array): Promise<HavenArchiveReader> {
    const files = unzipSync(data);
    const manifestData = files["manifest.json"];
    if (!manifestData) {
      throw new Error("Invalid .haven archive: missing manifest.json");
    }
    const manifest: HavenManifest = JSON.parse(new TextDecoder().decode(manifestData));
    return new HavenArchiveReader(files, manifest);
  }

  getManifest(): HavenManifest {
    return this.manifest;
  }

  getChannelExport(channelName: string): HavenChannelExport | null {
    // Try channels/ first, then dms/
    const key = `channels/${channelName}.json`;
    const dmKey = `dms/${channelName}.json`;
    const data = this.files[key] ?? this.files[dmKey];
    if (!data) return null;
    return JSON.parse(new TextDecoder().decode(data));
  }

  /** Return all channel exports (channels/ and dms/ directories). */
  getChannelExports(): HavenChannelExport[] {
    const results: HavenChannelExport[] = [];
    const decoder = new TextDecoder();
    for (const [path, data] of Object.entries(this.files)) {
      if ((path.startsWith("channels/") || path.startsWith("dms/")) && path.endsWith(".json")) {
        try {
          results.push(JSON.parse(decoder.decode(data)));
        } catch {
          // Skip malformed channel files
        }
      }
    }
    return results;
  }

  getServerMeta(): HavenServerExport | null {
    const data = this.files["server.json"];
    if (!data) return null;
    return JSON.parse(new TextDecoder().decode(data));
  }

  getAttachment(fileRef: string): Uint8Array | null {
    return this.files[fileRef] ?? null;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getAuditLog(): any[] | null {
    const data = this.files["audit-log.json"];
    if (!data) return null;
    return JSON.parse(new TextDecoder().decode(data));
  }

  /**
   * Verify archive integrity: file hashes and optional Ed25519 signature.
   */
  async verify(): Promise<{ valid: boolean; issues: string[] }> {
    const issues: string[] = [];

    // Check all files listed in manifest exist and match hashes
    for (const [path, expected] of Object.entries(this.manifest.files)) {
      const fileData = this.files[path];
      if (!fileData) {
        issues.push(`Missing file: ${path}`);
        continue;
      }
      const actualHash = await computeFileHash(fileData);
      if (actualHash !== expected.sha256) {
        issues.push(`Hash mismatch for ${path}: expected ${expected.sha256}, got ${actualHash}`);
      }
      if (fileData.byteLength !== expected.size) {
        issues.push(`Size mismatch for ${path}: expected ${expected.size}, got ${fileData.byteLength}`);
      }
    }

    // Verify Ed25519 signature if present
    if (this.manifest.user_signature) {
      const publicKey = fromBase64(this.manifest.exported_by.identity_key);
      const valid = verifyManifest(this.manifest, this.manifest.user_signature, publicKey);
      if (!valid) {
        issues.push("User signature verification failed");
      }
    }

    return { valid: issues.length === 0, issues };
  }
}
