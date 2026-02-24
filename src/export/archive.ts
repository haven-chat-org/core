import { zipSync, type Zippable } from "fflate";
import { toBase64 } from "../crypto/utils.js";
import type {
  HavenManifest,
  HavenChannelExport,
  HavenServerExport,
} from "./types.js";
import { signManifest, computeFileHash } from "./signing.js";

interface ArchiveMetadata {
  exportedBy: { user_id: string; username: string; identity_key: string };
  scope?: "server" | "channel" | "dm";
  serverId?: string;
  channelId?: string;
  instanceUrl: string;
}

/**
 * Builds a .haven archive (ZIP) containing channel exports,
 * server metadata, attachments, and an optional audit log.
 */
export class HavenArchiveBuilder {
  private metadata: ArchiveMetadata;
  private channels: Map<string, Uint8Array> = new Map();
  private attachments: Map<string, Uint8Array> = new Map();
  private serverMeta: Uint8Array | null = null;
  private auditLog: Uint8Array | null = null;
  private messageCount = 0;
  private earliestDate: string | null = null;
  private latestDate: string | null = null;

  constructor(metadata: ArchiveMetadata) {
    this.metadata = metadata;
  }

  addChannel(channelExport: HavenChannelExport): void {
    const name = channelExport.channel.name.replace(/[^a-zA-Z0-9_-]/g, "_");
    const dir = channelExport.channel.type === "dm" || channelExport.channel.type === "group_dm"
      ? "dms"
      : "channels";
    const key = `${dir}/${name}.json`;
    const data = new TextEncoder().encode(JSON.stringify(channelExport, null, 2));
    this.channels.set(key, data);

    this.messageCount += channelExport.message_count;
    this.updateDateRange(channelExport.date_range.from, channelExport.date_range.to);
  }

  addAttachment(id: string, data: Uint8Array): void {
    this.attachments.set(`attachments/${id}.bin`, data);
  }

  addServerMeta(serverExport: HavenServerExport): void {
    this.serverMeta = new TextEncoder().encode(JSON.stringify(serverExport, null, 2));
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  addAuditLog(entries: any[]): void {
    this.auditLog = new TextEncoder().encode(JSON.stringify(entries, null, 2));
  }

  /**
   * Build the .haven archive as a ZIP Uint8Array.
   * If signingKey is provided, the manifest is signed with Ed25519.
   */
  async build(signingKey?: Uint8Array): Promise<Uint8Array> {
    const files: Record<string, Uint8Array> = {};
    const fileHashes: Record<string, { sha256: string; size: number }> = {};

    // Collect all files
    for (const [path, data] of this.channels) {
      files[path] = data;
    }
    for (const [path, data] of this.attachments) {
      files[path] = data;
    }
    if (this.serverMeta) {
      files["server.json"] = this.serverMeta;
    }
    if (this.auditLog) {
      files["audit-log.json"] = this.auditLog;
    }

    // Compute hashes for all files
    for (const [path, data] of Object.entries(files)) {
      fileHashes[path] = {
        sha256: await computeFileHash(data),
        size: data.byteLength,
      };
    }

    // Build manifest
    const manifest: HavenManifest = {
      version: 1,
      format: "haven-export",
      exported_by: this.metadata.exportedBy,
      exported_at: new Date().toISOString(),
      instance_url: this.metadata.instanceUrl,
      files: fileHashes,
      message_count: this.messageCount,
      date_range: {
        from: this.earliestDate ?? new Date().toISOString(),
        to: this.latestDate ?? new Date().toISOString(),
      },
    };
    if (this.metadata.serverId) manifest.server_id = this.metadata.serverId;
    if (this.metadata.channelId) manifest.channel_id = this.metadata.channelId;
    if (this.metadata.scope) manifest.scope = this.metadata.scope;

    // Sign if key provided
    if (signingKey) {
      manifest.user_signature = signManifest(manifest, signingKey);
    }

    // Add manifest to archive
    files["manifest.json"] = new TextEncoder().encode(JSON.stringify(manifest, null, 2));

    // Build ZIP
    const zippable: Zippable = {};
    for (const [path, data] of Object.entries(files)) {
      zippable[path] = data;
    }

    return zipSync(zippable);
  }

  private updateDateRange(from: string, to: string): void {
    if (!this.earliestDate || from < this.earliestDate) this.earliestDate = from;
    if (!this.latestDate || to > this.latestDate) this.latestDate = to;
  }
}
