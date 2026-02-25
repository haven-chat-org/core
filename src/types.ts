// ─── Auth ──────────────────────────────────────────────

export interface RegisterRequest {
  username: string;
  password: string;
  display_name?: string;
  email?: string;
  identity_key: string;       // base64
  signed_prekey: string;      // base64
  signed_prekey_signature: string; // base64
  one_time_prekeys: string[]; // base64[]
  pow_challenge: string;
  pow_nonce: string;
  invite_code?: string;
  turnstile_token?: string;
}

/** Fields the caller provides — PoW fields are auto-filled by the API client */
export type RegisterInput = Omit<RegisterRequest, "pow_challenge" | "pow_nonce">;

export interface PowChallengeResponse {
  challenge: string;
  difficulty: number;
  turnstile_site_key?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
  totp_code?: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: UserPublic;
}

export interface LoginTotpRequiredResponse {
  totp_required: true;
}

export type LoginResponse = AuthResponse | LoginTotpRequiredResponse;

export function isLoginSuccess(res: LoginResponse): res is AuthResponse {
  return "access_token" in res;
}

export interface RefreshRequest {
  refresh_token: string;
}

export interface TotpSetupResponse {
  secret: string;
  qr_code_uri: string;
}

export interface TotpVerifyRequest {
  code: string;
}

export interface SessionResponse {
  id: string;
  family_id: string | null;
  device_name: string | null;
  ip_address: string | null;
  last_activity: string | null;
  created_at: string;
  is_current: boolean;
}

// ─── Users ─────────────────────────────────────────────

export interface UserPublic {
  id: string;
  username: string;
  display_name: string | null;
  about_me: string | null;
  avatar_url: string | null;
  banner_url: string | null;
  custom_status: string | null;
  custom_status_emoji: string | null;
  created_at: string;
  encrypted_profile?: string | null; // base64 encrypted blob
  is_instance_admin?: boolean;
  is_system?: boolean;
  totp_enabled?: boolean;
}

export interface MutualFriendInfo {
  user_id: string;
  username: string;
  display_name: string | null;
  avatar_url: string | null;
}

export interface UserProfileResponse {
  id: string;
  username: string;
  display_name: string | null;
  about_me: string | null;
  avatar_url: string | null;
  banner_url: string | null;
  custom_status: string | null;
  custom_status_emoji: string | null;
  created_at: string;
  is_blocked: boolean;
  is_friend: boolean;
  friend_request_status: "pending_incoming" | "pending_outgoing" | null;
  friendship_id: string | null;
  mutual_friend_count: number;
  mutual_friends: MutualFriendInfo[];
  mutual_server_count: number;
  roles?: RoleResponse[];
  encrypted_profile?: string | null; // base64 encrypted blob
  is_system?: boolean;
}

export interface UpdateProfileRequest {
  display_name?: string | null;
  about_me?: string | null;
  custom_status?: string | null;
  custom_status_emoji?: string | null;
  encrypted_profile?: string; // base64 encrypted blob
}

export interface ProfileKeyDistributionEntry {
  to_user_id: string;
  encrypted_profile_key: string; // base64
}

export interface DistributeProfileKeysRequest {
  distributions: ProfileKeyDistributionEntry[];
}

export interface ProfileKeyResponse {
  from_user_id: string;
  encrypted_profile_key: string; // base64
}

/** Plaintext fields stored inside the encrypted profile blob */
export interface ProfileFields {
  about_me?: string | null;
  custom_status?: string | null;
  custom_status_emoji?: string | null;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface BlockedUserResponse {
  user_id: string;
  username: string;
  display_name: string | null;
  avatar_url: string | null;
  blocked_at: string;
}

// ─── Keys ──────────────────────────────────────────────

export interface KeyBundle {
  identity_key: string;          // base64
  signed_prekey: string;         // base64
  signed_prekey_sig: string;     // base64
  one_time_prekey: string | null; // base64, consumed on fetch
}

export interface UploadPreKeysRequest {
  prekeys: string[]; // base64[]
}

export interface PreKeyCountResponse {
  count: number;
  needs_replenishment: boolean;
}

export interface UpdateKeysRequest {
  identity_key: string;          // base64
  signed_prekey: string;         // base64
  signed_prekey_signature: string; // base64
}

// ─── Key Backup ──────────────────────────────────────

export interface UploadKeyBackupRequest {
  encrypted_data: string;  // base64
  nonce: string;           // base64
  salt: string;            // base64
  version?: number;
}

export interface KeyBackupResponse {
  encrypted_data: string;  // base64
  nonce: string;           // base64
  salt: string;            // base64
  version: number;
  updated_at: string;
}

export interface KeyBackupStatusResponse {
  has_backup: boolean;
  version: number | null;
  updated_at: string | null;
}

// ─── Servers ───────────────────────────────────────────

export interface CreateServerRequest {
  encrypted_meta: string; // base64
}

export interface ServerResponse {
  id: string;
  encrypted_meta: string; // base64
  owner_id: string;
  created_at: string;
  my_permissions?: string; // i64 as string for JS BigInt safety
  system_channel_id?: string; // channel where system messages (joins, etc.) are posted
  icon_url?: string;
  is_system?: boolean;
}

// ─── Channels ──────────────────────────────────────────

export interface CreateChannelRequest {
  encrypted_meta: string; // base64
  channel_type?: string;
  position?: number;
  category_id?: string | null;
  is_private?: boolean;
  encrypted?: boolean;
}

export interface ChannelResponse {
  id: string;
  server_id: string | null;
  encrypted_meta: string; // base64
  channel_type: string;
  position: number;
  created_at: string;
  category_id: string | null;
  dm_status?: string; // "active", "pending", "declined" — only for DM channels
  last_message_id?: string;
  is_private: boolean;
  encrypted: boolean;
  export_allowed: boolean;
}

// ─── Channel Categories ───────────────────────────────

export interface CategoryResponse {
  id: string;
  server_id: string;
  name: string;
  position: number;
  created_at: string;
}

export interface CreateCategoryRequest {
  name: string;
  position?: number;
}

export interface UpdateCategoryRequest {
  name?: string;
  position?: number;
}

export interface ReorderCategoriesRequest {
  order: Array<{ id: string; position: number }>;
}

export interface SetChannelCategoryRequest {
  category_id: string | null;
}

export interface ReorderChannelsRequest {
  order: Array<{ id: string; position: number; category_id: string | null }>;
}

export interface CreateDmRequest {
  target_user_id: string;
  encrypted_meta: string; // base64
}

export interface CreateGroupDmRequest {
  member_ids: string[];
  encrypted_meta: string; // base64
}

// ─── Channel Members ─────────────────────────────────

export interface ChannelMemberInfo {
  user_id: string;
  username: string;
  display_name: string | null;
  avatar_url: string | null;
  joined_at: string;
}

// ─── Messages ──────────────────────────────────────────

export interface SendMessageRequest {
  channel_id: string;
  sender_token: string;   // base64
  encrypted_body: string;  // base64
  expires_at?: string;
  has_attachments: boolean;
}

export interface MessageResponse {
  id: string;
  channel_id: string;
  sender_token: string;   // base64
  encrypted_body: string;  // base64
  timestamp: string;
  expires_at: string | null;
  has_attachments: boolean;
  edited: boolean;
  reply_to_id: string | null;
  message_type?: string;  // "user" | "system"
}

export interface MessageQuery {
  before?: string;
  limit?: number;
}

// ─── Attachments ───────────────────────────────────────

export interface UploadResponse {
  attachment_id: string;
  storage_key: string;
}

// ─── Sender Keys ──────────────────────────────────────

export interface DistributeSenderKeyRequest {
  distributions: Array<{
    to_user_id: string;
    distribution_id: string;
    encrypted_skdm: string; // base64
  }>;
}

export interface SenderKeyDistributionResponse {
  id: string;
  channel_id: string;
  from_user_id: string;
  distribution_id: string;
  encrypted_skdm: string; // base64
  created_at: string;
}

export interface ChannelMemberKeyInfo {
  user_id: string;
  identity_key: string; // base64
}

// ─── Reactions ─────────────────────────────────────────

export interface ReactionGroup {
  message_id: string;
  emoji: string;
  count: number;
  user_ids: string[];
}

// ─── WebSocket ─────────────────────────────────────────

export type WsClientMessage =
  | { type: "SendMessage"; payload: { channel_id: string; sender_token: string; encrypted_body: string; expires_at?: string; attachment_ids?: string[]; reply_to_id?: string } }
  | { type: "EditMessage"; payload: { message_id: string; encrypted_body: string } }
  | { type: "DeleteMessage"; payload: { message_id: string } }
  | { type: "AddReaction"; payload: { message_id: string; emoji: string } }
  | { type: "RemoveReaction"; payload: { message_id: string; emoji: string } }
  | { type: "Subscribe"; payload: { channel_id: string } }
  | { type: "Unsubscribe"; payload: { channel_id: string } }
  | { type: "Typing"; payload: { channel_id: string } }
  | { type: "SetStatus"; payload: { status: string } }
  | { type: "PinMessage"; payload: { channel_id: string; message_id: string } }
  | { type: "UnpinMessage"; payload: { channel_id: string; message_id: string } }
  | { type: "CallInvite"; payload: { channel_id: string } }
  | { type: "CallAccept"; payload: { channel_id: string } }
  | { type: "CallReject"; payload: { channel_id: string } }
  | { type: "CallEnd"; payload: { channel_id: string } }
  | { type: "Ping" }
  | { type: "MarkRead"; payload: { channel_id: string } }
  | { type: "Resume"; payload: { session_id: string } };

export type WsServerMessage =
  | { type: "NewMessage"; payload: MessageResponse }
  | { type: "MessageEdited"; payload: { message_id: string; channel_id: string; encrypted_body: string } }
  | { type: "UserTyping"; payload: { channel_id: string; user_id: string; username: string } }
  | { type: "MessageAck"; payload: { message_id: string } }
  | { type: "Subscribed"; payload: { channel_id: string } }
  | { type: "Error"; payload: { message: string } }
  | { type: "Pong" }
  | { type: "SenderKeysUpdated"; payload: { channel_id: string } }
  | { type: "MessageDeleted"; payload: { message_id: string; channel_id: string } }
  | { type: "ReactionAdded"; payload: { message_id: string; channel_id: string; sender_token: string; emoji: string } }
  | { type: "ReactionRemoved"; payload: { message_id: string; channel_id: string; sender_token: string; emoji: string } }
  | { type: "PresenceUpdate"; payload: { user_id: string; status: string } }
  | { type: "FriendRequestReceived"; payload: { from_user_id: string; from_username: string; friendship_id: string } }
  | { type: "FriendRequestAccepted"; payload: { user_id: string; username: string; friendship_id: string } }
  | { type: "FriendRemoved"; payload: { user_id: string } }
  | { type: "DmRequestReceived"; payload: { channel_id: string; from_user_id: string } }
  | { type: "MessagePinned"; payload: { channel_id: string; message_id: string; pinned_by: string } }
  | { type: "MessageUnpinned"; payload: { channel_id: string; message_id: string } }
  | { type: "VoiceStateUpdate"; payload: { channel_id: string; user_id: string; username: string; joined: boolean } }
  | { type: "EmojiCreated"; payload: { server_id: string; emoji: CustomEmojiResponse } }
  | { type: "EmojiDeleted"; payload: { server_id: string; emoji_id: string } }
  | { type: "VoiceMuteUpdate"; payload: { channel_id: string; user_id: string; server_muted: boolean; server_deafened: boolean } }
  | { type: "CallRinging"; payload: { channel_id: string; caller_id: string; caller_name: string } }
  | { type: "CallAccepted"; payload: { channel_id: string; user_id: string } }
  | { type: "CallRejected"; payload: { channel_id: string; user_id: string } }
  | { type: "CallEnded"; payload: { channel_id: string; ended_by: string } }
  | { type: "BulkMessagesDeleted"; payload: { channel_id: string; message_ids: string[] } }
  | { type: "MemberTimedOut"; payload: { server_id: string; user_id: string; timed_out_until: string | null } }
  | { type: "ReadStateUpdated"; payload: { channel_id: string; last_read_at: string } }
  | { type: "ServerUpdated"; payload: { server_id: string } }
  | { type: "Hello"; payload: { session_id: string; heartbeat_interval_ms: number } }
  | { type: "Resumed"; payload: { replayed_count: number } }
  | { type: "InvalidSession" };

// ─── Presence ─────────────────────────────────────────

export interface PresenceEntry {
  user_id: string;
  status: string;
}

// ─── Admin Dashboard ─────────────────────────────────

export interface AdminStats {
  total_users: number;
  total_servers: number;
  total_channels: number;
  total_messages: number;
  active_connections: number;
}

export interface AdminUserResponse {
  id: string;
  username: string;
  display_name: string | null;
  avatar_url: string | null;
  created_at: string;
  is_instance_admin: boolean;
  server_count: number;
}

export interface SetAdminRequest {
  is_admin: boolean;
}

// ─── Invites ──────────────────────────────────────────

export interface CreateInviteRequest {
  max_uses?: number;
  expires_in_hours?: number;
}

export interface InviteResponse {
  id: string;
  code: string;
  server_id: string;
  max_uses: number | null;
  use_count: number;
  expires_at: string | null;
  created_at: string;
}

// ─── Server Members ───────────────────────────────────

export interface ServerMemberResponse {
  user_id: string;
  username: string;
  display_name: string | null;
  avatar_url: string | null;
  joined_at: string;
  nickname?: string | null;
  role_ids: string[];
  timed_out_until?: string | null;
  is_system?: boolean;
}

// ─── Roles & Permissions ─────────────────────────────

export const Permission = {
  ADMINISTRATOR:        BigInt(1) << BigInt(0),
  MANAGE_SERVER:        BigInt(1) << BigInt(1),
  MANAGE_ROLES:         BigInt(1) << BigInt(2),
  MANAGE_CHANNELS:      BigInt(1) << BigInt(3),
  KICK_MEMBERS:         BigInt(1) << BigInt(4),
  BAN_MEMBERS:          BigInt(1) << BigInt(5),
  MANAGE_MESSAGES:      BigInt(1) << BigInt(6),
  VIEW_CHANNELS:        BigInt(1) << BigInt(7),
  SEND_MESSAGES:        BigInt(1) << BigInt(8),
  CREATE_INVITES:       BigInt(1) << BigInt(9),
  MANAGE_INVITES:       BigInt(1) << BigInt(10),
  ADD_REACTIONS:        BigInt(1) << BigInt(11),
  MENTION_EVERYONE:     BigInt(1) << BigInt(12),
  ATTACH_FILES:         BigInt(1) << BigInt(13),
  READ_MESSAGE_HISTORY: BigInt(1) << BigInt(14),
  MANAGE_EMOJIS:        BigInt(1) << BigInt(15),
  MUTE_MEMBERS:         BigInt(1) << BigInt(16),
  STREAM:               BigInt(1) << BigInt(17),
  PRIORITY_SPEAKER:     BigInt(1) << BigInt(18),
  USE_VOICE_ACTIVITY:   BigInt(1) << BigInt(19),
  USE_EXTERNAL_EMOJIS:  BigInt(1) << BigInt(20),
  MANAGE_WEBHOOKS:      BigInt(1) << BigInt(21),
  VIEW_AUDIT_LOG:       BigInt(1) << BigInt(22),
  MANAGE_EVENTS:        BigInt(1) << BigInt(23),
  MANAGE_THREADS:       BigInt(1) << BigInt(24),
  MODERATE_MEMBERS:     BigInt(1) << BigInt(25),
  MANAGE_NICKNAMES:     BigInt(1) << BigInt(26),
} as const;

export interface RoleResponse {
  id: string;
  server_id: string;
  name: string;
  color: string | null;
  permissions: string; // bigint as string
  position: number;
  is_default: boolean;
  created_at: string;
}

export interface CreateRoleRequest {
  name: string;
  color?: string;
  permissions?: string;
  position?: number;
}

export interface UpdateRoleRequest {
  name?: string;
  color?: string;
  permissions?: string;
  position?: number;
}

export interface AssignRoleRequest {
  role_id: string;
}

export interface OverwriteResponse {
  id: string;
  channel_id: string;
  target_type: string;
  target_id: string;
  allow_bits: string;
  deny_bits: string;
}

export interface SetOverwriteRequest {
  target_type: string;
  target_id: string;
  allow_bits: string;
  deny_bits: string;
}

// ─── Custom Emojis ──────────────────────────────────

export interface CustomEmojiResponse {
  id: string;
  server_id: string;
  name: string;
  uploaded_by: string | null;
  animated: boolean;
  image_url: string;
  created_at: string;
}

// ─── Delete Account ─────────────────────────────────

export interface DeleteAccountRequest {
  password: string;
}

// ─── Bans ────────────────────────────────────────────

export interface BanResponse {
  id: string;
  user_id: string;
  username: string;
  reason: string | null;
  banned_by: string;
  created_at: string;
}

export interface CreateBanRequest {
  reason?: string;
}

export interface AddGroupMemberRequest {
  user_id: string;
}

// ─── Friends ──────────────────────────────────────────

export interface FriendResponse {
  id: string;           // friendship ID
  user_id: string;      // the other user
  username: string;
  display_name: string | null;
  avatar_url: string | null;
  status: string;       // "pending", "accepted"
  is_incoming: boolean;  // true if the other user sent the request
  created_at: string;
  is_system?: boolean;
}

export interface FriendRequestBody {
  username: string;
}

export interface DmRequestAction {
  action: string; // "accept" or "decline"
}

export interface UpdateDmPrivacyRequest {
  dm_privacy: string; // "everyone", "friends_only", "server_members"
}

// ─── Reports ─────────────────────────────────────────

export interface CreateReportRequest {
  message_id: string;
  channel_id: string;
  reason: string;
}

export interface ReportResponse {
  id: string;
  message_id: string;
  reason: string;
  status: string;
  created_at: string;
}

// ─── Voice ────────────────────────────────────────────

export interface VoiceTokenResponse {
  token: string;
  url: string;
  channel_id: string;
}

export interface VoiceParticipant {
  user_id: string;
  username: string;
  display_name: string | null;
  avatar_url: string | null;
  server_muted: boolean;
  server_deafened: boolean;
}

// ─── Read States ──────────────────────────────────────

export interface ReadStateResponse {
  user_id: string;
  channel_id: string;
  last_read_at: string;
}

export interface ChannelUnreadInfo {
  channel_id: string;
  last_message_id: string | null;
  last_message_at: string | null;
  unread_count: number;
}

// ─── Audit Log ────────────────────────────────────────

export interface AuditLogEntry {
  id: string;
  actor_id: string;
  actor_username: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  changes: Record<string, unknown> | null;
  reason: string | null;
  created_at: string;
}

// ─── Timeout ──────────────────────────────────────────

export interface TimeoutMemberRequest {
  duration_seconds: number;
  reason?: string;
}

// ─── Bulk Delete ──────────────────────────────────────

export interface BulkDeleteRequest {
  message_ids: string[];
}

// ─── Registration Invites ────────────────────────────────

export interface InviteRequiredResponse {
  invite_required: boolean;
}

export interface RegistrationInviteResponse {
  id: string;
  code: string;
  created_by: string | null;
  used: boolean;
  used_by: string | null;
  expires_at: string | null;
  created_at: string;
}

// ─── GIF Search ──────────────────────────────────────

export interface GifResult {
  id: string;
  title: string;
  url: string;
  preview_url: string;
  width: number;
  height: number;
}

export interface GifSearchResponse {
  results: GifResult[];
  total_count: number;
}

// ─── Server Restore ─────────────────────────────────────

export interface RestoreServerResponse {
  categories_created: number;
  channels_created: number;
  roles_created: number;
  roles_updated: number;
  overwrites_applied: number;
  channel_id_map: Record<string, string>;
}

export interface ImportMessage {
  sender_token: string;
  encrypted_body: string;
  timestamp: string;
  sender_id: string | null;
  message_type: string;
  reply_to_id: string | null;
  has_attachments: boolean;
}

// ─── API Error ─────────────────────────────────────────

export interface ApiError {
  error: string;
  status: number;
}
