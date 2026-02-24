import { getSodium, initSodium } from "../crypto/utils.js";
import {
  isLoginSuccess,
} from "../types.js";
import type {
  RegisterInput,
  LoginRequest,
  AuthResponse,
  LoginResponse,
  RefreshRequest,
  TotpSetupResponse,
  TotpVerifyRequest,
  KeyBundle,
  UploadPreKeysRequest,
  PreKeyCountResponse,
  CreateServerRequest,
  ServerResponse,
  CreateChannelRequest,
  ChannelResponse,
  CreateDmRequest,
  SendMessageRequest,
  MessageResponse,
  MessageQuery,
  UploadResponse,
  CreateInviteRequest,
  InviteResponse,
  ServerMemberResponse,
  ApiError,
  DistributeSenderKeyRequest,
  SenderKeyDistributionResponse,
  ChannelMemberKeyInfo,
  PresenceEntry,
  UpdateKeysRequest,
  ReactionGroup,
  UserProfileResponse,
  UpdateProfileRequest,
  BlockedUserResponse,
  CategoryResponse,
  CreateCategoryRequest,
  UpdateCategoryRequest,
  ReorderCategoriesRequest,
  ReorderChannelsRequest,
  SetChannelCategoryRequest,
  RoleResponse,
  CreateRoleRequest,
  UpdateRoleRequest,
  AssignRoleRequest,
  OverwriteResponse,
  SetOverwriteRequest,
  FriendResponse,
  FriendRequestBody,
  DmRequestAction,
  UpdateDmPrivacyRequest,
  ChangePasswordRequest,
  CreateGroupDmRequest,
  ChannelMemberInfo,
  BanResponse,
  CreateBanRequest,
  CreateReportRequest,
  ReportResponse,
  VoiceTokenResponse,
  VoiceParticipant,
  UploadKeyBackupRequest,
  KeyBackupResponse,
  KeyBackupStatusResponse,
  CustomEmojiResponse,
  PowChallengeResponse,
  AuditLogEntry,
  TimeoutMemberRequest,
  BulkDeleteRequest,
  ReadStateResponse,
  ChannelUnreadInfo,
  AdminStats,
  AdminUserResponse,
  SetAdminRequest,
  InviteRequiredResponse,
  RegistrationInviteResponse,
  GifSearchResponse,
  SessionResponse,
  RestoreServerResponse,
  ImportMessage,
} from "../types.js";

export interface ApiClientOptions {
  baseUrl: string;
  onTokenExpired?: () => void;
}

/**
 * Type-safe REST client for the Haven backend.
 * Handles JWT token management and automatic refresh.
 */
export class HavenApi {
  private baseUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private onTokenExpired?: () => void;

  constructor(options: ApiClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.onTokenExpired = options.onTokenExpired;
  }

  /** Set auth tokens (after login/register/refresh). */
  setTokens(access: string, refresh: string): void {
    this.accessToken = access;
    this.refreshToken = refresh;
  }

  clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
  }

  get currentAccessToken(): string | null {
    return this.accessToken;
  }

  // ─── Auth ────────────────────────────────────────

  /** Fetch a PoW challenge from the server. */
  async getChallenge(): Promise<PowChallengeResponse> {
    return this.get<PowChallengeResponse>("/api/v1/auth/challenge");
  }

  /**
   * Register a new account. Automatically fetches and solves a PoW challenge.
   * The PoW solving runs in a Web Worker when available, otherwise falls back to main thread.
   */
  async register(input: RegisterInput): Promise<AuthResponse> {
    // 1. Fetch challenge
    const { challenge, difficulty } = await this.getChallenge();

    // 2. Solve PoW
    const nonce = await solvePoW(challenge, difficulty);

    // 3. Submit registration with PoW solution
    const res = await this.post<AuthResponse>("/api/v1/auth/register", {
      ...input,
      pow_challenge: challenge,
      pow_nonce: nonce,
    });
    this.setTokens(res.access_token, res.refresh_token);
    return res;
  }

  async login(req: LoginRequest): Promise<LoginResponse> {
    const res = await this.post<LoginResponse>("/api/v1/auth/login", req);
    if (isLoginSuccess(res)) {
      this.setTokens(res.access_token, res.refresh_token);
    }
    return res;
  }

  async refresh(): Promise<AuthResponse> {
    if (!this.refreshToken) throw new Error("No refresh token");
    const req: RefreshRequest = { refresh_token: this.refreshToken };
    const res = await this.post<AuthResponse>("/api/v1/auth/refresh", req);
    this.setTokens(res.access_token, res.refresh_token);
    return res;
  }

  async logout(): Promise<void> {
    await this.post("/api/v1/auth/logout", {});
    this.clearTokens();
  }

  async totpSetup(): Promise<TotpSetupResponse> {
    return this.post<TotpSetupResponse>("/api/v1/auth/totp/setup", {});
  }

  async totpVerify(req: TotpVerifyRequest): Promise<void> {
    await this.post("/api/v1/auth/totp/verify", req);
  }

  async totpDisable(): Promise<void> {
    await this.delete("/api/v1/auth/totp");
  }

  async changePassword(req: ChangePasswordRequest): Promise<void> {
    await this.put("/api/v1/auth/password", req);
  }

  async getSessions(): Promise<SessionResponse[]> {
    return this.get<SessionResponse[]>("/api/v1/auth/sessions");
  }

  async revokeSession(familyId: string): Promise<void> {
    await this.delete(`/api/v1/auth/sessions/${familyId}`);
  }

  // ─── Users ────────────────────────────────────────

  async getUserByUsername(username: string): Promise<import("../types.js").UserPublic> {
    return this.get(`/api/v1/users/search?username=${encodeURIComponent(username)}`);
  }

  // ─── Keys ────────────────────────────────────────

  async getKeyBundle(userId: string): Promise<KeyBundle> {
    return this.get<KeyBundle>(`/api/v1/users/${userId}/keys`);
  }

  async uploadPreKeys(req: UploadPreKeysRequest): Promise<void> {
    await this.post("/api/v1/keys/prekeys", req);
  }

  /** Delete all unused one-time prekeys from the server (stale keys whose private keys are lost). */
  async clearPreKeys(): Promise<void> {
    await this.delete("/api/v1/keys/prekeys");
  }

  async getPreKeyCount(): Promise<PreKeyCountResponse> {
    return this.get<PreKeyCountResponse>("/api/v1/keys/prekeys/count");
  }

  async updateKeys(req: UpdateKeysRequest): Promise<void> {
    await this.put("/api/v1/keys/identity", req);
  }

  // ─── Key Backup ─────────────────────────────────

  async uploadKeyBackup(req: UploadKeyBackupRequest): Promise<void> {
    await this.put("/api/v1/keys/backup", req);
  }

  async getKeyBackup(): Promise<KeyBackupResponse> {
    return this.get<KeyBackupResponse>("/api/v1/keys/backup");
  }

  async getKeyBackupStatus(): Promise<KeyBackupStatusResponse> {
    return this.get<KeyBackupStatusResponse>("/api/v1/keys/backup/status");
  }

  async deleteKeyBackup(): Promise<void> {
    await this.delete("/api/v1/keys/backup");
  }

  // ─── Servers ─────────────────────────────────────

  async listServers(): Promise<ServerResponse[]> {
    return this.get<ServerResponse[]>("/api/v1/servers");
  }

  async createServer(req: CreateServerRequest): Promise<ServerResponse> {
    return this.post<ServerResponse>("/api/v1/servers", req);
  }

  async getServer(serverId: string): Promise<ServerResponse> {
    return this.get<ServerResponse>(`/api/v1/servers/${serverId}`);
  }

  async getMyPermissions(serverId: string): Promise<{ permissions: string; is_owner: boolean }> {
    return this.get(`/api/v1/servers/${serverId}/members/@me/permissions`);
  }

  async updateServer(serverId: string, req: { system_channel_id?: string | null; encrypted_meta?: string }): Promise<{ ok: boolean }> {
    return this.patch(`/api/v1/servers/${serverId}`, req);
  }

  async listServerChannels(serverId: string): Promise<ChannelResponse[]> {
    return this.get<ChannelResponse[]>(`/api/v1/servers/${serverId}/channels`);
  }

  async createChannel(serverId: string, req: CreateChannelRequest): Promise<ChannelResponse> {
    return this.post<ChannelResponse>(`/api/v1/servers/${serverId}/channels`, req);
  }

  // ─── Channels ────────────────────────────────────

  async joinChannel(channelId: string): Promise<void> {
    await this.post(`/api/v1/channels/${channelId}/join`, {});
  }

  async updateChannel(channelId: string, req: { encrypted_meta: string; encrypted?: boolean }): Promise<ChannelResponse> {
    return this.put<ChannelResponse>(`/api/v1/channels/${channelId}`, req);
  }

  async deleteChannel(channelId: string): Promise<void> {
    await this.delete(`/api/v1/channels/${channelId}`);
  }

  async listDmChannels(): Promise<ChannelResponse[]> {
    return this.get<ChannelResponse[]>("/api/v1/dm");
  }

  async createDm(req: CreateDmRequest): Promise<ChannelResponse> {
    return this.post<ChannelResponse>("/api/v1/dm", req);
  }

  async createGroupDm(req: CreateGroupDmRequest): Promise<ChannelResponse> {
    return this.post<ChannelResponse>("/api/v1/dm/group", req);
  }

  async listChannelMembers(channelId: string): Promise<ChannelMemberInfo[]> {
    return this.get<ChannelMemberInfo[]>(`/api/v1/channels/${channelId}/members`);
  }

  async leaveChannel(channelId: string): Promise<void> {
    await this.delete(`/api/v1/channels/${channelId}/leave`);
  }

  async hideChannel(channelId: string): Promise<void> {
    await this.put(`/api/v1/channels/${channelId}/hide`, {});
  }

  async logExport(req: { scope: string; server_id?: string; channel_id?: string; message_count: number }): Promise<void> {
    await this.post(`/api/v1/exports/log`, req);
  }

  async restoreServer(serverId: string, data: import("../export/types.js").HavenServerExport): Promise<RestoreServerResponse> {
    return this.post<RestoreServerResponse>(`/api/v1/servers/${serverId}/restore`, data);
  }

  async importMessages(channelId: string, messages: ImportMessage[]): Promise<{ imported: number }> {
    return this.post<{ imported: number }>(`/api/v1/channels/${channelId}/import-messages`, { messages });
  }

  // ─── Channel Categories ─────────────────────────

  async listCategories(serverId: string): Promise<CategoryResponse[]> {
    return this.get<CategoryResponse[]>(`/api/v1/servers/${serverId}/categories`);
  }

  async createCategory(serverId: string, req: CreateCategoryRequest): Promise<CategoryResponse> {
    return this.post<CategoryResponse>(`/api/v1/servers/${serverId}/categories`, req);
  }

  async updateCategory(serverId: string, categoryId: string, req: UpdateCategoryRequest): Promise<CategoryResponse> {
    return this.put<CategoryResponse>(`/api/v1/servers/${serverId}/categories/${categoryId}`, req);
  }

  async deleteCategory(serverId: string, categoryId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}/categories/${categoryId}`);
  }

  async reorderCategories(serverId: string, req: ReorderCategoriesRequest): Promise<void> {
    await this.put(`/api/v1/servers/${serverId}/categories/reorder`, req);
  }

  async reorderChannels(serverId: string, req: ReorderChannelsRequest): Promise<void> {
    await this.put(`/api/v1/servers/${serverId}/channels/reorder`, req);
  }

  async setChannelCategory(channelId: string, req: SetChannelCategoryRequest): Promise<ChannelResponse> {
    return this.put<ChannelResponse>(`/api/v1/channels/${channelId}/category`, req);
  }

  // ─── Roles & Permissions ────────────────────────

  async listRoles(serverId: string): Promise<RoleResponse[]> {
    return this.get<RoleResponse[]>(`/api/v1/servers/${serverId}/roles`);
  }

  async createRole(serverId: string, req: CreateRoleRequest): Promise<RoleResponse> {
    return this.post<RoleResponse>(`/api/v1/servers/${serverId}/roles`, req);
  }

  async updateRole(serverId: string, roleId: string, req: UpdateRoleRequest): Promise<RoleResponse> {
    return this.put<RoleResponse>(`/api/v1/servers/${serverId}/roles/${roleId}`, req);
  }

  async deleteRole(serverId: string, roleId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}/roles/${roleId}`);
  }

  async assignRole(serverId: string, userId: string, req: AssignRoleRequest): Promise<void> {
    await this.put(`/api/v1/servers/${serverId}/members/${userId}/roles`, req);
  }

  async unassignRole(serverId: string, userId: string, roleId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}/members/${userId}/roles/${roleId}`);
  }

  async listOverwrites(channelId: string): Promise<OverwriteResponse[]> {
    return this.get<OverwriteResponse[]>(`/api/v1/channels/${channelId}/overwrites`);
  }

  async setOverwrite(channelId: string, req: SetOverwriteRequest): Promise<OverwriteResponse> {
    return this.put<OverwriteResponse>(`/api/v1/channels/${channelId}/overwrites`, req);
  }

  async deleteOverwrite(channelId: string, targetType: string, targetId: string): Promise<void> {
    await this.delete(`/api/v1/channels/${channelId}/overwrites/${targetType}/${targetId}`);
  }

  // ─── Messages ────────────────────────────────────

  async getMessages(channelId: string, query?: MessageQuery): Promise<MessageResponse[]> {
    const params = new URLSearchParams();
    if (query?.before) params.set("before", query.before);
    if (query?.limit) params.set("limit", String(query.limit));
    const qs = params.toString();
    return this.get<MessageResponse[]>(
      `/api/v1/channels/${channelId}/messages${qs ? `?${qs}` : ""}`,
    );
  }

  async sendMessage(channelId: string, req: SendMessageRequest): Promise<MessageResponse> {
    return this.post<MessageResponse>(`/api/v1/channels/${channelId}/messages`, req);
  }

  async getChannelReactions(channelId: string): Promise<ReactionGroup[]> {
    return this.get<ReactionGroup[]>(`/api/v1/channels/${channelId}/reactions`);
  }

  async getMessageReactions(messageId: string): Promise<ReactionGroup[]> {
    return this.get<ReactionGroup[]>(`/api/v1/messages/${messageId}/reactions`);
  }

  async getPinnedMessages(channelId: string): Promise<MessageResponse[]> {
    return this.get<MessageResponse[]>(`/api/v1/channels/${channelId}/pins`);
  }

  async getPinnedMessageIds(channelId: string): Promise<string[]> {
    return this.get<string[]>(`/api/v1/channels/${channelId}/pin-ids`);
  }

  // ─── Attachments ─────────────────────────────────

  /** Upload encrypted blob directly to backend. Returns attachment_id + storage_key. */
  async uploadAttachment(blob: ArrayBuffer): Promise<UploadResponse> {
    const headers: Record<string, string> = {
      "Content-Type": "application/octet-stream",
    };
    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

    const res = await fetch(`${this.baseUrl}/api/v1/attachments/upload`, {
      method: "POST",
      headers,
      body: blob,
    });

    if (!res.ok) {
      if (res.status === 401 && this.onTokenExpired) {
        this.onTokenExpired();
      }
      const err: ApiError = await res.json().catch(() => ({
        error: res.statusText,
        status: res.status,
      }));
      throw new HavenApiError(err.error, err.status);
    }

    return res.json() as Promise<UploadResponse>;
  }

  /** Download encrypted blob from backend. Returns raw bytes. */
  async downloadAttachment(attachmentId: string): Promise<ArrayBuffer> {
    const headers: Record<string, string> = {};
    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

    const res = await fetch(`${this.baseUrl}/api/v1/attachments/${attachmentId}`, {
      method: "GET",
      headers,
    });

    if (!res.ok) {
      if (res.status === 401 && this.onTokenExpired) {
        this.onTokenExpired();
      }
      throw new HavenApiError(`Download failed: ${res.statusText}`, res.status);
    }

    return res.arrayBuffer();
  }

  // ─── Export ────────────────────────────────────────

  /** Toggle DM export consent for a channel. */
  async setExportConsent(channelId: string, allowed: boolean): Promise<void> {
    await this.put<void>(`/api/v1/channels/${channelId}/export-consent`, { export_allowed: allowed });
  }

  // ─── Invites ───────────────────────────────────────

  async createInvite(serverId: string, req: CreateInviteRequest): Promise<InviteResponse> {
    return this.post<InviteResponse>(`/api/v1/servers/${serverId}/invites`, req);
  }

  async listInvites(serverId: string): Promise<InviteResponse[]> {
    return this.get<InviteResponse[]>(`/api/v1/servers/${serverId}/invites`);
  }

  async deleteInvite(serverId: string, inviteId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}/invites/${inviteId}`);
  }

  async joinByInvite(code: string): Promise<ServerResponse> {
    return this.post<ServerResponse>(`/api/v1/invites/${code}/join`, {});
  }

  // ─── Server Members ───────────────────────────────

  async listServerMembers(serverId: string): Promise<ServerMemberResponse[]> {
    return this.get<ServerMemberResponse[]>(`/api/v1/servers/${serverId}/members?limit=100`);
  }

  async kickMember(serverId: string, userId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}/members/${userId}`);
  }

  async setNickname(serverId: string, nickname: string | null): Promise<void> {
    await this.put(`/api/v1/servers/${serverId}/nickname`, { nickname });
  }

  async setMemberNickname(serverId: string, userId: string, nickname: string | null): Promise<void> {
    await this.put(`/api/v1/servers/${serverId}/members/${userId}/nickname`, { nickname });
  }

  async leaveServer(serverId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}/members/@me`);
  }

  async deleteServer(serverId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}`);
  }

  // ─── Bans ──────────────────────────────────────────

  async banMember(serverId: string, userId: string, req: CreateBanRequest): Promise<BanResponse> {
    return this.post<BanResponse>(`/api/v1/servers/${serverId}/bans/${userId}`, req);
  }

  async revokeBan(serverId: string, userId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}/bans/${userId}`);
  }

  async listBans(serverId: string): Promise<BanResponse[]> {
    return this.get<BanResponse[]>(`/api/v1/servers/${serverId}/bans`);
  }

  // ─── Read States ─────────────────────────────────────

  async markChannelRead(channelId: string): Promise<ReadStateResponse> {
    return this.put<ReadStateResponse>(`/api/v1/channels/${channelId}/read-state`, {});
  }

  async getReadStates(): Promise<ChannelUnreadInfo[]> {
    return this.get<ChannelUnreadInfo[]>("/api/v1/channels/read-states");
  }

  // ─── Admin Dashboard ────────────────────────────────

  async getAdminStats(): Promise<AdminStats> {
    return this.get<AdminStats>("/api/v1/admin/stats");
  }

  async listAdminUsers(search?: string, limit?: number, offset?: number): Promise<AdminUserResponse[]> {
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    if (limit !== undefined) params.set("limit", String(limit));
    if (offset !== undefined) params.set("offset", String(offset));
    const qs = params.toString();
    return this.get<AdminUserResponse[]>(`/api/v1/admin/users${qs ? `?${qs}` : ""}`);
  }

  async setUserAdmin(userId: string, isAdmin: boolean): Promise<void> {
    const body: SetAdminRequest = { is_admin: isAdmin };
    await this.put(`/api/v1/admin/users/${userId}/admin`, body);
  }

  async adminDeleteUser(userId: string): Promise<void> {
    await this.delete(`/api/v1/admin/users/${userId}`);
  }

  // ─── Timeouts ───────────────────────────────────────

  async timeoutMember(serverId: string, userId: string, durationSeconds: number, reason?: string): Promise<void> {
    const body: TimeoutMemberRequest = { duration_seconds: durationSeconds, reason };
    await this.put(`/api/v1/servers/${serverId}/members/${userId}/timeout`, body);
  }

  async removeTimeout(serverId: string, userId: string): Promise<void> {
    await this.put(`/api/v1/servers/${serverId}/members/${userId}/timeout`, { duration_seconds: 0 });
  }

  // ─── Bulk Delete ────────────────────────────────────

  async bulkDeleteMessages(channelId: string, messageIds: string[]): Promise<void> {
    const body: BulkDeleteRequest = { message_ids: messageIds };
    await this.post(`/api/v1/channels/${channelId}/messages/bulk-delete`, body);
  }

  // ─── Audit Log ──────────────────────────────────────

  async getAuditLog(serverId: string, opts?: { limit?: number; before?: string }): Promise<AuditLogEntry[]> {
    const params = new URLSearchParams();
    if (opts?.limit) params.set("limit", String(opts.limit));
    if (opts?.before) params.set("before", opts.before);
    const qs = params.toString();
    return this.get<AuditLogEntry[]>(`/api/v1/servers/${serverId}/audit-log${qs ? `?${qs}` : ""}`);
  }

  // ─── Group DM Members ──────────────────────────────

  async addGroupMember(channelId: string, userId: string): Promise<void> {
    await this.post(`/api/v1/channels/${channelId}/members`, { user_id: userId });
  }

  // ─── Sender Keys ───────────────────────────────────

  async distributeSenderKeys(
    channelId: string,
    req: DistributeSenderKeyRequest,
  ): Promise<void> {
    await this.post(`/api/v1/channels/${channelId}/sender-keys`, req);
  }

  async getSenderKeys(
    channelId: string,
  ): Promise<SenderKeyDistributionResponse[]> {
    return this.get<SenderKeyDistributionResponse[]>(
      `/api/v1/channels/${channelId}/sender-keys`,
    );
  }

  async getChannelMemberKeys(
    channelId: string,
  ): Promise<ChannelMemberKeyInfo[]> {
    return this.get<ChannelMemberKeyInfo[]>(
      `/api/v1/channels/${channelId}/members/keys`,
    );
  }

  // ─── Link Previews ──────────────────────────────

  async fetchLinkPreview(
    url: string,
  ): Promise<{ url: string; title?: string; description?: string; image?: string; site_name?: string }> {
    return this.get(`/api/v1/link-preview?url=${encodeURIComponent(url)}`);
  }

  // ─── Presence ─────────────────────────────────────

  async getPresence(userIds: string[]): Promise<PresenceEntry[]> {
    return this.get<PresenceEntry[]>(
      `/api/v1/presence?user_ids=${userIds.join(",")}`,
    );
  }

  // ─── User Profiles ──────────────────────────────

  async getUserProfile(userId: string, serverId?: string): Promise<UserProfileResponse> {
    const qs = serverId ? `?server_id=${serverId}` : "";
    return this.get<UserProfileResponse>(`/api/v1/users/${userId}/profile${qs}`);
  }

  async updateProfile(req: UpdateProfileRequest): Promise<import("../types.js").UserPublic> {
    return this.put(`/api/v1/users/profile`, req);
  }

  async uploadAvatar(blob: ArrayBuffer): Promise<import("../types.js").UserPublic> {
    const headers: Record<string, string> = {
      "Content-Type": "application/octet-stream",
    };
    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

    const res = await fetch(`${this.baseUrl}/api/v1/users/avatar`, {
      method: "POST",
      headers,
      body: blob,
    });

    if (!res.ok) {
      if (res.status === 401 && this.onTokenExpired) {
        this.onTokenExpired();
      }
      const err: ApiError = await res.json().catch(() => ({
        error: res.statusText,
        status: res.status,
      }));
      throw new HavenApiError(err.error, err.status);
    }

    return res.json() as Promise<import("../types.js").UserPublic>;
  }

  async uploadBanner(blob: ArrayBuffer): Promise<import("../types.js").UserPublic> {
    const headers: Record<string, string> = {
      "Content-Type": "application/octet-stream",
    };
    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

    const res = await fetch(`${this.baseUrl}/api/v1/users/banner`, {
      method: "POST",
      headers,
      body: blob,
    });

    if (!res.ok) {
      if (res.status === 401 && this.onTokenExpired) {
        this.onTokenExpired();
      }
      const err: ApiError = await res.json().catch(() => ({
        error: res.statusText,
        status: res.status,
      }));
      throw new HavenApiError(err.error, err.status);
    }

    return res.json() as Promise<import("../types.js").UserPublic>;
  }

  // ─── Profile Key Distribution ────────────────────

  async distributeProfileKeys(
    req: import("../types.js").DistributeProfileKeysRequest
  ): Promise<{ distributed: number }> {
    return this.put(`/api/v1/users/profile-keys`, req);
  }

  async getProfileKey(
    userId: string
  ): Promise<import("../types.js").ProfileKeyResponse> {
    return this.get(`/api/v1/users/${userId}/profile-key`);
  }

  // ─── Friends ──────────────────────────────────────

  async listFriends(): Promise<FriendResponse[]> {
    return this.get<FriendResponse[]>("/api/v1/friends");
  }

  async sendFriendRequest(req: FriendRequestBody): Promise<FriendResponse> {
    return this.post<FriendResponse>("/api/v1/friends/request", req);
  }

  async acceptFriendRequest(friendshipId: string): Promise<FriendResponse> {
    return this.post<FriendResponse>(`/api/v1/friends/${friendshipId}/accept`, {});
  }

  async declineFriendRequest(friendshipId: string): Promise<void> {
    await this.post(`/api/v1/friends/${friendshipId}/decline`, {});
  }

  async removeFriend(friendshipId: string): Promise<void> {
    await this.delete(`/api/v1/friends/${friendshipId}`);
  }

  // ─── DM Requests ─────────────────────────────────

  async listDmRequests(): Promise<ChannelResponse[]> {
    return this.get<ChannelResponse[]>("/api/v1/dm/requests");
  }

  async handleDmRequest(channelId: string, req: DmRequestAction): Promise<void> {
    await this.post(`/api/v1/dm/${channelId}/request`, req);
  }

  async updateDmPrivacy(req: UpdateDmPrivacyRequest): Promise<void> {
    await this.put("/api/v1/users/dm-privacy", req);
  }

  // ─── Blocked Users ─────────────────────────────

  async blockUser(userId: string): Promise<void> {
    await this.post(`/api/v1/users/${userId}/block`, {});
  }

  async unblockUser(userId: string): Promise<void> {
    await this.delete(`/api/v1/users/${userId}/block`);
  }

  async getBlockedUsers(): Promise<BlockedUserResponse[]> {
    return this.get<BlockedUserResponse[]>("/api/v1/users/blocked");
  }

  // ─── Reports ──────────────────────────────────────

  async reportMessage(req: CreateReportRequest): Promise<ReportResponse> {
    return this.post<ReportResponse>("/api/v1/reports", req);
  }

  // ─── Custom Emojis ──────────────────────────────

  async listServerEmojis(serverId: string): Promise<CustomEmojiResponse[]> {
    return this.get<CustomEmojiResponse[]>(`/api/v1/servers/${serverId}/emojis`);
  }

  async uploadEmoji(serverId: string, name: string, imageData: ArrayBuffer): Promise<CustomEmojiResponse> {
    const headers: Record<string, string> = {
      "Content-Type": "application/octet-stream",
    };
    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

    const res = await fetch(
      `${this.baseUrl}/api/v1/servers/${serverId}/emojis?name=${encodeURIComponent(name)}`,
      { method: "POST", headers, body: imageData },
    );

    if (!res.ok) {
      if (res.status === 401 && this.onTokenExpired) {
        this.onTokenExpired();
      }
      const err: ApiError = await res.json().catch(() => ({
        error: res.statusText,
        status: res.status,
      }));
      throw new HavenApiError(err.error, err.status);
    }

    return res.json() as Promise<CustomEmojiResponse>;
  }

  async renameEmoji(serverId: string, emojiId: string, name: string): Promise<CustomEmojiResponse> {
    return this.patch<CustomEmojiResponse>(`/api/v1/servers/${serverId}/emojis/${emojiId}`, { name });
  }

  async deleteEmoji(serverId: string, emojiId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}/emojis/${emojiId}`);
  }

  // ─── Server Icons ──────────────────────────────

  async uploadServerIcon(serverId: string, blob: ArrayBuffer): Promise<{ icon_url: string }> {
    const headers: Record<string, string> = {
      "Content-Type": "application/octet-stream",
    };
    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

    const res = await fetch(`${this.baseUrl}/api/v1/servers/${serverId}/icon`, {
      method: "POST",
      headers,
      body: blob,
    });

    if (!res.ok) {
      if (res.status === 401 && this.onTokenExpired) {
        this.onTokenExpired();
      }
      const err: ApiError = await res.json().catch(() => ({
        error: res.statusText,
        status: res.status,
      }));
      throw new HavenApiError(err.error, err.status);
    }

    return res.json() as Promise<{ icon_url: string }>;
  }

  async deleteServerIcon(serverId: string): Promise<void> {
    await this.delete(`/api/v1/servers/${serverId}/icon`);
  }

  // ─── Registration Invites ──────────────────────

  /** Check if the instance requires an invite code to register (no auth needed). */
  async checkInviteRequired(): Promise<InviteRequiredResponse> {
    return this.get<InviteRequiredResponse>("/api/v1/auth/invite-required");
  }

  /** List the current user's registration invite codes. */
  async listMyRegistrationInvites(): Promise<RegistrationInviteResponse[]> {
    return this.get<RegistrationInviteResponse[]>("/api/v1/registration-invites");
  }

  // ─── Account Deletion ──────────────────────────

  async deleteAccount(password: string): Promise<void> {
    await this.post("/api/v1/auth/delete-account", { password });
  }

  // ─── Voice ──────────────────────────────────────

  async joinVoice(channelId: string): Promise<VoiceTokenResponse> {
    return this.post<VoiceTokenResponse>(`/api/v1/voice/${channelId}/join`, {});
  }

  async leaveVoice(channelId: string): Promise<void> {
    await this.post<unknown>(`/api/v1/voice/${channelId}/leave`, {});
  }

  async getVoiceParticipants(channelId: string): Promise<VoiceParticipant[]> {
    return this.get<VoiceParticipant[]>(`/api/v1/voice/${channelId}/participants`);
  }

  async serverMuteUser(channelId: string, userId: string, muted: boolean): Promise<void> {
    await this.put(`/api/v1/voice/${channelId}/members/${userId}/mute`, { muted });
  }

  async serverDeafenUser(channelId: string, userId: string, deafened: boolean): Promise<void> {
    await this.put(`/api/v1/voice/${channelId}/members/${userId}/deafen`, { deafened });
  }

  // ─── GIF Search ─────────────────────────────────

  async searchGifs(query: string, offset?: number): Promise<GifSearchResponse> {
    const params = new URLSearchParams({ q: query });
    if (offset !== undefined) params.set("offset", String(offset));
    return this.get<GifSearchResponse>(`/api/v1/gifs/search?${params}`);
  }

  async trendingGifs(): Promise<GifSearchResponse> {
    return this.get<GifSearchResponse>("/api/v1/gifs/trending");
  }

  // ─── HTTP Helpers ────────────────────────────────

  private async get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("POST", path, body);
  }

  private async put<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("PUT", path, body);
  }

  private async patch<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("PATCH", path, body);
  }

  private async delete<T>(path: string): Promise<T> {
    return this.request<T>("DELETE", path);
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (!res.ok) {
      if (res.status === 401 && this.onTokenExpired) {
        this.onTokenExpired();
      }
      const err: ApiError = await res.json().catch(() => ({
        error: res.statusText,
        status: res.status,
      }));
      throw new HavenApiError(err.error, err.status);
    }

    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }
}

export class HavenApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "HavenApiError";
    this.status = status;
  }
}

// ─── Proof-of-Work Solver ────────────────────────────

/**
 * Solve a PoW challenge: find a nonce such that SHA-256(challenge + nonce)
 * has at least `difficulty` leading zero bits.
 * Uses libsodium's crypto_hash_sha256 (works in insecure HTTP contexts,
 * unlike crypto.subtle which requires HTTPS or localhost).
 */
async function solvePoW(challenge: string, difficulty: number): Promise<string> {
  await initSodium();
  const sodium = getSodium();
  const encoder = new TextEncoder();
  const prefix = encoder.encode(challenge);

  for (let nonce = 0; ; nonce++) {
    const nonceStr = String(nonce);
    const nonceBytes = encoder.encode(nonceStr);

    // Concatenate challenge + nonce
    const data = new Uint8Array(prefix.length + nonceBytes.length);
    data.set(prefix);
    data.set(nonceBytes, prefix.length);

    const hash: Uint8Array = sodium.crypto_hash_sha256(data);

    if (hasLeadingZeroBits(hash, difficulty)) {
      return nonceStr;
    }

    // Yield to event loop every 10000 iterations to avoid blocking UI
    if (nonce % 10000 === 0 && nonce > 0) {
      await new Promise((r) => setTimeout(r, 0));
    }
  }
}

/** Check if a hash has at least `n` leading zero bits. */
function hasLeadingZeroBits(hash: Uint8Array, n: number): boolean {
  let bits = 0;
  for (const byte of hash) {
    if (byte === 0) {
      bits += 8;
    } else {
      // Count leading zeros of this byte
      bits += Math.clz32(byte) - 24; // clz32 counts 32-bit, byte is 8-bit
      break;
    }
    if (bits >= n) return true;
  }
  return bits >= n;
}
