// ─── Haven Export Archive Types ─────────────────────────

/** Top-level manifest included in every .haven archive. */
export interface HavenManifest {
  version: number;
  format: "haven-export";
  exported_by: {
    user_id: string;
    username: string;
    identity_key: string; // base64 Ed25519 public key
  };
  exported_at: string; // ISO 8601
  scope?: "server" | "channel" | "dm";
  server_id?: string;
  channel_id?: string;
  instance_url: string;
  files: Record<string, { sha256: string; size: number }>;
  message_count: number;
  date_range: { from: string; to: string };
  user_signature?: string; // base64 Ed25519 detached signature
  server_signature?: string; // base64 Ed25519 detached signature
}

/** Per-channel export data stored in channels/<name>.json or dms/<name>.json. */
export interface HavenChannelExport {
  channel: {
    id: string;
    name: string;
    type: string;
    encrypted: boolean;
    category?: string;
    created_at: string;
  };
  exported_at: string;
  exported_by: string; // user_id
  message_count: number;
  date_range: { from: string; to: string };
  messages: HavenExportMessage[];
}

/** A single message in the export. */
export interface HavenExportMessage {
  id: string;
  sender_id: string;
  sender_name: string;
  sender_display_name: string | null;
  timestamp: string;
  text: string | null;
  content_type: string;
  formatting: string | null;
  edited: boolean;
  reply_to: string | null;
  type: string;
  reactions: { emoji: string; count: number; users: string[] }[];
  pinned: boolean;
  attachments: HavenAttachmentRef[];
}

/** Reference to an attachment file within the archive. */
export interface HavenAttachmentRef {
  id: string;
  filename: string;
  mime_type: string;
  size: number;
  width?: number;
  height?: number;
  file_ref: string; // path within archive, e.g. "attachments/<uuid>.bin"
}

/** Server-level metadata export stored in server.json. */
export interface HavenServerExport {
  server: {
    id: string;
    name: string;
    description: string | null;
    icon_url: string | null;
    created_at: string;
  };
  categories: {
    id: string;
    name: string;
    position: number;
  }[];
  channels: {
    id: string;
    name: string;
    type: string;
    category_id: string | null;
    position: number;
    encrypted: boolean;
    is_private: boolean;
  }[];
  roles: {
    id: string;
    name: string;
    color: string | null;
    permissions: number;
    position: number;
    is_default: boolean;
  }[];
  members: {
    user_id: string;
    username: string;
    display_name: string | null;
    nickname: string | null;
    roles: string[];
    joined_at: string;
  }[];
  emojis: {
    id: string;
    name: string;
    image_ref?: string;
  }[];
  permission_overwrites: {
    channel_id: string;
    target_type: string;
    target_id: string;
    allow: number;
    deny: number;
  }[];
}
