import { describe, it, expect, beforeAll } from "vitest";
import { initSodium, getSodium, toBase64 } from "../../crypto/utils.js";
import { HavenArchiveBuilder } from "../archive.js";
import { HavenArchiveReader } from "../reader.js";
import { signManifest, verifyManifest, computeFileHash } from "../signing.js";
import type { HavenChannelExport, HavenServerExport } from "../types.js";

// ── Test Data ───────────────────────────────────────────

function makeChannelExport(name = "general"): HavenChannelExport {
  return {
    channel: {
      id: "ch-001",
      name,
      type: "text",
      encrypted: true,
      category: "Text Channels",
      created_at: "2025-03-01T00:00:00Z",
    },
    exported_at: "2026-02-22T12:00:00Z",
    exported_by: "user-001",
    message_count: 2,
    date_range: { from: "2025-03-15T14:30:00Z", to: "2025-03-15T15:00:00Z" },
    messages: [
      {
        id: "msg-001",
        sender_id: "user-001",
        sender_name: "alice",
        sender_display_name: "Alice",
        timestamp: "2025-03-15T14:30:00Z",
        text: "Hello everyone!",
        content_type: "text/plain",
        formatting: null,
        edited: false,
        reply_to: null,
        type: "user",
        reactions: [{ emoji: "wave", count: 2, users: ["bob", "charlie"] }],
        pinned: false,
        attachments: [],
      },
      {
        id: "msg-002",
        sender_id: "user-002",
        sender_name: "bob",
        sender_display_name: "Bob",
        timestamp: "2025-03-15T15:00:00Z",
        text: "Hey Alice!",
        content_type: "text/plain",
        formatting: null,
        edited: false,
        reply_to: "msg-001",
        type: "user",
        reactions: [],
        pinned: true,
        attachments: [],
      },
    ],
  };
}

function makeServerExport(): HavenServerExport {
  return {
    server: {
      id: "srv-001",
      name: "Test Server",
      description: "A test server",
      icon_url: null,
      created_at: "2025-03-01T00:00:00Z",
    },
    categories: [{ id: "cat-001", name: "Text Channels", position: 0 }],
    channels: [
      {
        id: "ch-001",
        name: "general",
        type: "text",
        category_id: "cat-001",
        position: 0,
        encrypted: true,
        is_private: false,
      },
    ],
    roles: [
      {
        id: "role-001",
        name: "Moderator",
        color: "#3498db",
        permissions: 8192,
        position: 1,
        is_default: false,
      },
    ],
    members: [
      {
        user_id: "user-001",
        username: "alice",
        display_name: "Alice",
        nickname: null,
        roles: ["role-001"],
        joined_at: "2025-03-01T00:00:00Z",
      },
    ],
    emojis: [],
    permission_overwrites: [],
  };
}

// ── Tests ───────────────────────────────────────────────

beforeAll(async () => {
  await initSodium();
});

describe("HavenArchiveBuilder + HavenArchiveReader", () => {
  const metadata = {
    exportedBy: { user_id: "user-001", username: "alice", identity_key: "" },
    serverId: "srv-001",
    instanceUrl: "https://haven.example.com",
  };

  it("round-trips channel data through build and read", async () => {
    const sodium = getSodium();
    const kp = sodium.crypto_sign_keypair();
    const meta = {
      ...metadata,
      exportedBy: { ...metadata.exportedBy, identity_key: toBase64(kp.publicKey) },
    };

    const builder = new HavenArchiveBuilder(meta);
    builder.addChannel(makeChannelExport());
    builder.addServerMeta(makeServerExport());
    builder.addAuditLog([{ action: "test", timestamp: "2026-02-22T12:00:00Z" }]);

    const attachment = new TextEncoder().encode("fake image data");
    builder.addAttachment("att-001", attachment);

    const zip = await builder.build(kp.privateKey);
    expect(zip).toBeInstanceOf(Uint8Array);
    expect(zip.byteLength).toBeGreaterThan(0);

    const reader = await HavenArchiveReader.fromBlob(zip);
    const manifest = reader.getManifest();

    expect(manifest.version).toBe(1);
    expect(manifest.format).toBe("haven-export");
    expect(manifest.exported_by.username).toBe("alice");
    expect(manifest.server_id).toBe("srv-001");
    expect(manifest.message_count).toBe(2);
    expect(manifest.user_signature).toBeDefined();
    expect(Object.keys(manifest.files)).toContain("channels/general.json");
    expect(Object.keys(manifest.files)).toContain("server.json");
    expect(Object.keys(manifest.files)).toContain("attachments/att-001.bin");
    expect(Object.keys(manifest.files)).toContain("audit-log.json");

    // Channel export round-trip
    const channel = reader.getChannelExport("general");
    expect(channel).not.toBeNull();
    expect(channel!.message_count).toBe(2);
    expect(channel!.messages[0].text).toBe("Hello everyone!");
    expect(channel!.messages[1].pinned).toBe(true);

    // Server meta round-trip
    const server = reader.getServerMeta();
    expect(server).not.toBeNull();
    expect(server!.server.name).toBe("Test Server");
    expect(server!.roles).toHaveLength(1);

    // Attachment round-trip
    const att = reader.getAttachment("attachments/att-001.bin");
    expect(att).not.toBeNull();
    expect(new TextDecoder().decode(att!)).toBe("fake image data");

    // Audit log round-trip
    const log = reader.getAuditLog();
    expect(log).not.toBeNull();
    expect(log).toHaveLength(1);
    expect(log![0].action).toBe("test");
  });

  it("verification passes for untampered archive", async () => {
    const sodium = getSodium();
    const kp = sodium.crypto_sign_keypair();
    const meta = {
      ...metadata,
      exportedBy: { ...metadata.exportedBy, identity_key: toBase64(kp.publicKey) },
    };

    const builder = new HavenArchiveBuilder(meta);
    builder.addChannel(makeChannelExport());
    const zip = await builder.build(kp.privateKey);

    const reader = await HavenArchiveReader.fromBlob(zip);
    const result = await reader.verify();
    expect(result.valid).toBe(true);
    expect(result.issues).toHaveLength(0);
  });

  it("verification fails for tampered file", async () => {
    const sodium = getSodium();
    const kp = sodium.crypto_sign_keypair();
    const meta = {
      ...metadata,
      exportedBy: { ...metadata.exportedBy, identity_key: toBase64(kp.publicKey) },
    };

    const builder = new HavenArchiveBuilder(meta);
    builder.addChannel(makeChannelExport());
    const zip = await builder.build(kp.privateKey);

    // Read the archive, tamper with a file, then verify
    const reader = await HavenArchiveReader.fromBlob(zip);
    // Access internal files and tamper
    const manifest = reader.getManifest();

    // Tamper: change a hash in the manifest to simulate file corruption
    const firstFile = Object.keys(manifest.files)[0];
    manifest.files[firstFile].sha256 = "0000000000000000000000000000000000000000000000000000000000000000";

    // Re-verify with tampered manifest — the hash won't match
    const result = await reader.verify();
    // The reader still has the original manifest, so we need to test differently.
    // Let's instead rebuild with tampered data.
    // Actually the reader's verify checks files against its own manifest,
    // and since we mutated the manifest object in place, it should fail.
    expect(result.valid).toBe(false);
    expect(result.issues.length).toBeGreaterThan(0);
    expect(result.issues[0]).toContain("Hash mismatch");
  });

  it("verification fails for missing file referenced in manifest", async () => {
    const sodium = getSodium();
    const kp = sodium.crypto_sign_keypair();
    const meta = {
      ...metadata,
      exportedBy: { ...metadata.exportedBy, identity_key: toBase64(kp.publicKey) },
    };

    const builder = new HavenArchiveBuilder(meta);
    builder.addChannel(makeChannelExport());
    const zip = await builder.build(kp.privateKey);

    const reader = await HavenArchiveReader.fromBlob(zip);
    const manifest = reader.getManifest();

    // Add a fake file entry to manifest
    manifest.files["channels/nonexistent.json"] = { sha256: "abc", size: 100 };

    const result = await reader.verify();
    expect(result.valid).toBe(false);
    expect(result.issues.some((i) => i.includes("Missing file"))).toBe(true);
  });
});

describe("signManifest / verifyManifest", () => {
  it("round-trips signing and verification", async () => {
    const sodium = getSodium();
    const kp = sodium.crypto_sign_keypair();

    const manifest = {
      version: 1 as const,
      format: "haven-export" as const,
      exported_by: {
        user_id: "user-001",
        username: "alice",
        identity_key: toBase64(kp.publicKey),
      },
      exported_at: "2026-02-22T12:00:00Z",
      instance_url: "https://haven.example.com",
      files: {},
      message_count: 0,
      date_range: { from: "2026-01-01T00:00:00Z", to: "2026-02-22T12:00:00Z" },
    };

    const sig = signManifest(manifest, kp.privateKey);
    expect(typeof sig).toBe("string");
    expect(sig.length).toBeGreaterThan(0);

    expect(verifyManifest(manifest, sig, kp.publicKey)).toBe(true);
  });

  it("rejects invalid signature", async () => {
    const sodium = getSodium();
    const kp1 = sodium.crypto_sign_keypair();
    const kp2 = sodium.crypto_sign_keypair();

    const manifest = {
      version: 1 as const,
      format: "haven-export" as const,
      exported_by: {
        user_id: "user-001",
        username: "alice",
        identity_key: toBase64(kp1.publicKey),
      },
      exported_at: "2026-02-22T12:00:00Z",
      instance_url: "https://haven.example.com",
      files: {},
      message_count: 0,
      date_range: { from: "2026-01-01T00:00:00Z", to: "2026-02-22T12:00:00Z" },
    };

    const sig = signManifest(manifest, kp1.privateKey);
    // Verify with wrong key should fail
    expect(verifyManifest(manifest, sig, kp2.publicKey)).toBe(false);
  });
});

describe("computeFileHash", () => {
  it("produces consistent SHA-256 hex digest", async () => {
    const data = new TextEncoder().encode("hello world");
    const hash = await computeFileHash(data);
    // SHA-256 of "hello world"
    expect(hash).toBe("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
  });
});
