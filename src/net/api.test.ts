import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock libsodium so tests don't need the native WASM module.
// solvePoW() calls initSodium + getSodium().crypto_hash_sha256.
// Returning all-zero bytes satisfies any difficulty check.
vi.mock("../crypto/utils.js", () => ({
  initSodium: vi.fn(),
  getSodium: vi.fn(() => ({
    crypto_hash_sha256: () => new Uint8Array(32),
  })),
}));

import { HavenApi, HavenApiError } from "./api.js";

// ── Mock fetch ──────────────────────────────────────────

function mockResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    text: () => Promise.resolve(body != null ? JSON.stringify(body) : ""),
    json: () => Promise.resolve(body),
    headers: new Headers(),
  } as unknown as Response;
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ── Token management ────────────────────────────────────

describe("token management", () => {
  it("starts with no token", () => {
    const api = new HavenApi({ baseUrl: "http://localhost" });
    expect(api.currentAccessToken).toBeNull();
  });

  it("setTokens stores tokens", () => {
    const api = new HavenApi({ baseUrl: "http://localhost" });
    api.setTokens("access-123", "refresh-456");
    expect(api.currentAccessToken).toBe("access-123");
  });

  it("clearTokens removes tokens", () => {
    const api = new HavenApi({ baseUrl: "http://localhost" });
    api.setTokens("access-123", "refresh-456");
    api.clearTokens();
    expect(api.currentAccessToken).toBeNull();
  });
});

// ── Auth endpoints ──────────────────────────────────────

describe("auth", () => {
  it("login sends POST with correct body and sets tokens", async () => {
    const authResponse = {
      access_token: "at-1",
      refresh_token: "rt-1",
      user: { id: "uuid-1", username: "alice" },
    };
    fetchMock.mockResolvedValueOnce(mockResponse(authResponse));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    const result = await api.login({ username: "alice", password: "secret" });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/auth/login");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({
      username: "alice",
      password: "secret",
    });
    expect("access_token" in result && result.access_token).toBe("at-1");
    expect(api.currentAccessToken).toBe("at-1");
  });

  it("register sends POST and sets tokens", async () => {
    // First call: getChallenge()
    const challengeResponse = { challenge: "test-challenge", difficulty: 0 };
    // Second call: register POST
    const authResponse = {
      access_token: "at-reg",
      refresh_token: "rt-reg",
      user: { id: "uuid-2", username: "bob" },
    };
    fetchMock
      .mockResolvedValueOnce(mockResponse(challengeResponse))
      .mockResolvedValueOnce(mockResponse(authResponse));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    const result = await api.register({
      username: "bob",
      password: "password123",
      identity_key: "key1",
      signed_prekey: "key2",
      signed_prekey_signature: "sig1",
      one_time_prekeys: [],
    });

    // First call is GET /challenge, second is POST /register
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [challengeUrl] = fetchMock.mock.calls[0];
    expect(challengeUrl).toBe("http://localhost:8080/api/v1/auth/challenge");
    const [regUrl, regOpts] = fetchMock.mock.calls[1];
    expect(regUrl).toBe("http://localhost:8080/api/v1/auth/register");
    expect(regOpts.method).toBe("POST");
    expect(result.user.username).toBe("bob");
    expect(api.currentAccessToken).toBe("at-reg");
  });

  it("logout clears tokens", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("at", "rt");
    await api.logout();

    expect(api.currentAccessToken).toBeNull();
  });
});

// ── Auth header ─────────────────────────────────────────

describe("auth header", () => {
  it("includes Bearer token when set", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("my-token", "rt");
    await api.listServers();

    const [, opts] = fetchMock.mock.calls[0];
    expect(opts.headers["Authorization"]).toBe("Bearer my-token");
  });

  it("omits auth header when no token", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    // Don't set tokens
    // listServers will still make the request (server would return 401)
    try {
      await api.listServers();
    } catch {
      // ignore
    }

    const [, opts] = fetchMock.mock.calls[0];
    expect(opts.headers["Authorization"]).toBeUndefined();
  });
});

// ── Error handling ──────────────────────────────────────

describe("error handling", () => {
  it("non-ok response throws HavenApiError with status", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ error: "Forbidden", status: 403 }, 403),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");

    try {
      await api.listServers();
      expect.unreachable("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(HavenApiError);
      expect((e as HavenApiError).status).toBe(403);
    }
  });

  it("401 triggers onTokenExpired callback", async () => {
    const onExpired = vi.fn();
    fetchMock.mockResolvedValue(
      mockResponse({ error: "Unauthorized", status: 401 }, 401),
    );

    const api = new HavenApi({
      baseUrl: "http://localhost:8080",
      onTokenExpired: onExpired,
    });
    api.setTokens("old-token", "rt");

    await expect(api.listServers()).rejects.toThrow();
    expect(onExpired).toHaveBeenCalledOnce();
  });
});

// ── Server endpoints ────────────────────────────────────

describe("servers", () => {
  it("listServers sends GET", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse([{ id: "s1", encrypted_meta: "bWV0YQ==" }]),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const servers = await api.listServers();

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers");
    expect(opts.method).toBe("GET");
    expect(servers).toHaveLength(1);
  });

  it("createServer sends POST with encrypted_meta", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "s2", encrypted_meta: "dGVzdA==" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.createServer({ encrypted_meta: "dGVzdA==" });

    const [, opts] = fetchMock.mock.calls[0];
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({
      encrypted_meta: "dGVzdA==",
    });
  });
});

// ── Channel endpoints ───────────────────────────────────

describe("channels", () => {
  it("createChannel sends POST to server channels endpoint", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "ch1", server_id: "s1" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.createChannel("s1", { encrypted_meta: "Y2hhbg==" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/channels");
    expect(opts.method).toBe("POST");
  });

  it("deleteChannel sends DELETE", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.deleteChannel("ch1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1");
    expect(opts.method).toBe("DELETE");
  });
});

// ── Friends endpoints ───────────────────────────────────

describe("friends", () => {
  it("sendFriendRequest sends POST", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "f1", status: "pending" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const result = await api.sendFriendRequest({ username: "carol" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/friends/request");
    expect(opts.method).toBe("POST");
    expect(result.status).toBe("pending");
  });

  it("acceptFriendRequest sends POST", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "f1", status: "accepted" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.acceptFriendRequest("f1");

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/friends/f1/accept");
  });

  it("listFriends sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const friends = await api.listFriends();

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/friends");
    expect(opts.method).toBe("GET");
    expect(friends).toEqual([]);
  });
});

// ── URL construction ────────────────────────────────────

describe("URL construction", () => {
  it("strips trailing slash from baseUrl", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080/" });
    api.setTokens("tok", "rt");
    await api.listServers();

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers");
  });

  it("getMessages constructs query params", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.getMessages("ch1", { before: "msg-99", limit: 25 });

    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/v1/channels/ch1/messages?");
    expect(url).toContain("before=msg-99");
    expect(url).toContain("limit=25");
  });
});

// ── Roles ───────────────────────────────────────────────

describe("roles", () => {
  it("createRole sends POST", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "r1", name: "Admin" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.createRole("s1", { name: "Admin", permissions: "8" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/roles");
    expect(opts.method).toBe("POST");
  });

  it("assignRole sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.assignRole("s1", "u1", { role_id: "r1" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/members/u1/roles");
    expect(opts.method).toBe("PUT");
  });

  it("updateRole sends PUT with correct path", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse({ id: "r1", name: "Mod" }));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.updateRole("s1", "r1", { name: "Mod" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/roles/r1");
    expect(opts.method).toBe("PUT");
  });

  it("deleteRole sends DELETE", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.deleteRole("s1", "r1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/roles/r1");
    expect(opts.method).toBe("DELETE");
  });

  it("unassignRole sends DELETE with role in path", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.unassignRole("s1", "u1", "r1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/members/u1/roles/r1");
    expect(opts.method).toBe("DELETE");
  });

  it("listRoles sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([{ id: "r1", name: "Admin" }]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const roles = await api.listRoles("s1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/roles");
    expect(opts.method).toBe("GET");
    expect(roles).toHaveLength(1);
  });
});

// ── Pins ────────────────────────────────────────────────

describe("pins", () => {
  it("getPinnedMessages sends GET to /pins", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const pins = await api.getPinnedMessages("ch1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/pins");
    expect(opts.method).toBe("GET");
    expect(pins).toEqual([]);
  });

  it("getPinnedMessageIds sends GET to /pin-ids", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(["id1", "id2"]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const ids = await api.getPinnedMessageIds("ch1");

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/pin-ids");
    expect(ids).toEqual(["id1", "id2"]);
  });
});

// ── Reports ─────────────────────────────────────────────

describe("reports", () => {
  it("reportMessage sends POST to /reports", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "rep1", status: "pending" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const result = await api.reportMessage({
      message_id: "msg1",
      channel_id: "ch1",
      reason: "spam content here",
    });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/reports");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({
      message_id: "msg1",
      channel_id: "ch1",
      reason: "spam content here",
    });
    expect(result.status).toBe("pending");
  });
});

// ── Reactions ───────────────────────────────────────────

describe("reactions", () => {
  it("getChannelReactions sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const reactions = await api.getChannelReactions("ch1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/reactions");
    expect(opts.method).toBe("GET");
    expect(reactions).toEqual([]);
  });
});

// ── User profiles ───────────────────────────────────────

describe("user profiles", () => {
  it("getUserProfile sends GET without server_id", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "u1", username: "alice" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.getUserProfile("u1");

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/users/u1/profile");
  });

  it("getUserProfile includes server_id query param", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "u1", username: "alice" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.getUserProfile("u1", "s1");

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/users/u1/profile?server_id=s1");
  });

  it("updateProfile sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "u1", display_name: "Alice" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.updateProfile({ display_name: "Alice" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/users/profile");
    expect(opts.method).toBe("PUT");
  });

  it("getUserByUsername encodes username in query", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "u1", username: "test user" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.getUserByUsername("test user");

    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/v1/users/search?username=test%20user");
  });
});

// ── Blocked users ───────────────────────────────────────

describe("blocked users", () => {
  it("blockUser sends POST", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.blockUser("u2");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/users/u2/block");
    expect(opts.method).toBe("POST");
  });

  it("unblockUser sends DELETE", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.unblockUser("u2");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/users/u2/block");
    expect(opts.method).toBe("DELETE");
  });

  it("getBlockedUsers sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const blocked = await api.getBlockedUsers();

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/users/blocked");
    expect(opts.method).toBe("GET");
    expect(blocked).toEqual([]);
  });
});

// ── Bans ────────────────────────────────────────────────

describe("bans", () => {
  it("banMember sends POST with reason", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "ban1", user_id: "u2" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.banMember("s1", "u2", { reason: "rule violation" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/bans/u2");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({ reason: "rule violation" });
  });

  it("revokeBan sends DELETE", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.revokeBan("s1", "u2");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/bans/u2");
    expect(opts.method).toBe("DELETE");
  });

  it("listBans sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const bans = await api.listBans("s1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/bans");
    expect(opts.method).toBe("GET");
    expect(bans).toEqual([]);
  });
});

// ── DMs ─────────────────────────────────────────────────

describe("DMs", () => {
  it("listDmChannels sends GET to /dm", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const dms = await api.listDmChannels();

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/dm");
    expect(opts.method).toBe("GET");
    expect(dms).toEqual([]);
  });

  it("createDm sends POST to /dm", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "ch1", channel_type: "dm" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.createDm({ target_user_id: "u2", encrypted_meta: "bWV0YQ==" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/dm");
    expect(opts.method).toBe("POST");
  });

  it("createGroupDm sends POST to /dm/group", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "ch2", channel_type: "group_dm" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.createGroupDm({ member_ids: ["u2", "u3"], encrypted_meta: "bWV0YQ==" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/dm/group");
    expect(opts.method).toBe("POST");
  });

  it("listDmRequests sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const reqs = await api.listDmRequests();

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/dm/requests");
    expect(reqs).toEqual([]);
  });

  it("handleDmRequest sends POST with action", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.handleDmRequest("ch1", { action: "accept" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/dm/ch1/request");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({ action: "accept" });
  });

  it("updateDmPrivacy sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.updateDmPrivacy({ dm_privacy: "friends_only" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/users/dm-privacy");
    expect(opts.method).toBe("PUT");
  });
});

// ── Channel members ─────────────────────────────────────

describe("channel members", () => {
  it("listChannelMembers sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const members = await api.listChannelMembers("ch1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/members");
    expect(opts.method).toBe("GET");
    expect(members).toEqual([]);
  });

  it("leaveChannel sends DELETE", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.leaveChannel("ch1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/leave");
    expect(opts.method).toBe("DELETE");
  });

  it("addGroupMember sends POST with user_id", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.addGroupMember("ch1", "u2");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/members");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body)).toEqual({ user_id: "u2" });
  });
});

// ── Channel updates ─────────────────────────────────────

describe("channel updates", () => {
  it("updateChannel sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "ch1", encrypted_meta: "dXBkYXRlZA==" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.updateChannel("ch1", { encrypted_meta: "dXBkYXRlZA==" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1");
    expect(opts.method).toBe("PUT");
  });

  it("joinChannel sends POST to /join", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.joinChannel("ch1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/join");
    expect(opts.method).toBe("POST");
  });
});

// ── Overwrites ──────────────────────────────────────────

describe("overwrites", () => {
  it("listOverwrites sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const overwrites = await api.listOverwrites("ch1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/overwrites");
    expect(opts.method).toBe("GET");
    expect(overwrites).toEqual([]);
  });

  it("setOverwrite sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "ow1", channel_id: "ch1" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.setOverwrite("ch1", {
      target_type: "role",
      target_id: "r1",
      allow_bits: "8",
      deny_bits: "0",
    });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/overwrites");
    expect(opts.method).toBe("PUT");
  });

  it("deleteOverwrite sends DELETE with target in path", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.deleteOverwrite("ch1", "role", "r1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/overwrites/role/r1");
    expect(opts.method).toBe("DELETE");
  });
});

// ── Server members & invites ────────────────────────────

describe("server members and invites", () => {
  it("listServerMembers sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const members = await api.listServerMembers("s1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/members?limit=100");
    expect(opts.method).toBe("GET");
    expect(members).toEqual([]);
  });

  it("kickMember sends DELETE", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.kickMember("s1", "u2");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/members/u2");
    expect(opts.method).toBe("DELETE");
  });

  it("createInvite sends POST", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "inv1", code: "abc123" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.createInvite("s1", { expires_in_hours: 24 });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/invites");
    expect(opts.method).toBe("POST");
  });

  it("listInvites sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const invites = await api.listInvites("s1");

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/invites");
    expect(invites).toEqual([]);
  });

  it("deleteInvite sends DELETE", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.deleteInvite("s1", "inv1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/invites/inv1");
    expect(opts.method).toBe("DELETE");
  });

  it("joinByInvite sends POST with invite code", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "s1", encrypted_meta: "bWV0YQ==" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.joinByInvite("abc123");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/invites/abc123/join");
    expect(opts.method).toBe("POST");
  });
});

// ── Categories ──────────────────────────────────────────

describe("categories", () => {
  it("listCategories sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const cats = await api.listCategories("s1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/categories");
    expect(opts.method).toBe("GET");
    expect(cats).toEqual([]);
  });

  it("createCategory sends POST", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "cat1", name: "General" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.createCategory("s1", { name: "General" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/categories");
    expect(opts.method).toBe("POST");
  });

  it("updateCategory sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "cat1", name: "Updated" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.updateCategory("s1", "cat1", { name: "Updated" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/categories/cat1");
    expect(opts.method).toBe("PUT");
  });

  it("deleteCategory sends DELETE", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.deleteCategory("s1", "cat1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/categories/cat1");
    expect(opts.method).toBe("DELETE");
  });

  it("reorderCategories sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.reorderCategories("s1", { order: [{ id: "cat2", position: 0 }, { id: "cat1", position: 1 }] });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/servers/s1/categories/reorder");
    expect(opts.method).toBe("PUT");
  });

  it("setChannelCategory sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "ch1", category_id: "cat1" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.setChannelCategory("ch1", { category_id: "cat1" });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/category");
    expect(opts.method).toBe("PUT");
  });
});

// ── Friends extended ────────────────────────────────────

describe("friends extended", () => {
  it("declineFriendRequest sends POST", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.declineFriendRequest("f1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/friends/f1/decline");
    expect(opts.method).toBe("POST");
  });

  it("removeFriend sends DELETE", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.removeFriend("f1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/friends/f1");
    expect(opts.method).toBe("DELETE");
  });
});

// ── Auth extended ───────────────────────────────────────

describe("auth extended", () => {
  it("changePassword sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.changePassword({
      current_password: "old",
      new_password: "new123",
    });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/auth/password");
    expect(opts.method).toBe("PUT");
  });

  it("refresh sends POST with refresh token", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({
        access_token: "new-at",
        refresh_token: "new-rt",
        user: { id: "u1" },
      }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("old-at", "old-rt");
    const result = await api.refresh();

    const [, opts] = fetchMock.mock.calls[0];
    expect(JSON.parse(opts.body)).toEqual({ refresh_token: "old-rt" });
    expect(result.access_token).toBe("new-at");
    expect(api.currentAccessToken).toBe("new-at");
  });

  it("refresh throws without refresh token", async () => {
    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    await expect(api.refresh()).rejects.toThrow("No refresh token");
  });
});

// ── Keys ────────────────────────────────────────────────

describe("keys", () => {
  it("getKeyBundle sends GET", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ identity_key: "key1", signed_prekey: "key2" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const bundle = await api.getKeyBundle("u1");

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/users/u1/keys");
    expect(opts.method).toBe("GET");
    expect(bundle.identity_key).toBe("key1");
  });

  it("uploadPreKeys sends POST", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.uploadPreKeys({ prekeys: ["pk1", "pk2"] });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/keys/prekeys");
    expect(opts.method).toBe("POST");
  });

  it("getPreKeyCount sends GET", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse({ count: 42 }));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const result = await api.getPreKeyCount();

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/keys/prekeys/count");
    expect(result.count).toBe(42);
  });

  it("updateKeys sends PUT", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse(null));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.updateKeys({
      identity_key: "new-key",
      signed_prekey: "new-spk",
      signed_prekey_signature: "new-sig",
    });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/keys/identity");
    expect(opts.method).toBe("PUT");
  });
});

// ── Messages ────────────────────────────────────────────

describe("messages", () => {
  it("sendMessage sends POST to channel messages", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ id: "msg1", channel_id: "ch1" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.sendMessage("ch1", {
      channel_id: "ch1",
      sender_token: "st",
      encrypted_body: "eb",
      has_attachments: false,
    });

    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/messages");
    expect(opts.method).toBe("POST");
  });

  it("getMessages with no query params omits query string", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.getMessages("ch1");

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/channels/ch1/messages");
  });
});

// ── Presence ────────────────────────────────────────────

describe("presence", () => {
  it("getPresence sends GET with comma-joined user_ids", async () => {
    fetchMock.mockResolvedValueOnce(mockResponse([]));

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    await api.getPresence(["u1", "u2", "u3"]);

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/presence?user_ids=u1,u2,u3");
  });
});

// ── Link preview ────────────────────────────────────────

describe("link preview", () => {
  it("fetchLinkPreview sends GET with encoded URL", async () => {
    fetchMock.mockResolvedValueOnce(
      mockResponse({ url: "https://example.com", title: "Example" }),
    );

    const api = new HavenApi({ baseUrl: "http://localhost:8080" });
    api.setTokens("tok", "rt");
    const preview = await api.fetchLinkPreview("https://example.com/path?q=1");

    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/v1/link-preview?url=");
    expect(url).toContain(encodeURIComponent("https://example.com/path?q=1"));
    expect(preview.title).toBe("Example");
  });
});
