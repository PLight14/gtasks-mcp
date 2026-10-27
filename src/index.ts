import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { DurableObject } from "cloudflare:workers";
import { z } from "zod";

const GOOGLE_SCOPE = "openid email https://www.googleapis.com/auth/tasks";
const TASKS_SCOPE = "https://www.googleapis.com/auth/tasks";
const MCP_SCOPE = "tasks";
const MCP_ACCESS_TTL = 3600;
const MCP_REFRESH_TTL = 2_592_000;
const MCP_RETIRED_REFRESHES = 8;
const GRANT_PREFIX = "grant:";
const SESSION_PREFIX = "mcp_session:";
const PENDING_PREFIX = "pending:";
const HANDOFF_PREFIX = "handoff:";
const CODE_PREFIX = "code:";
const IN_FLIGHT_CAP = 8;
const SEARCH_LISTS = 10;
const SEARCH_PAGES = 2;
const SEARCH_MATCHES = 40;

type LinkedAccount = { id: string; email: string | null };
type TokenRecord = {
  access_token: string;
  expires_at: number;
  refresh_token: string;
  credential_tag: string;
  user: LinkedAccount;
};
type StoredToken = Partial<TokenRecord> & { user?: unknown };
type Minted = { access_token: string; expires_at: number; refresh_token: string | null };
type PendingAuth = { state: string; verifier: string; redirect_uri: string; expires_at: number; mcp_handoff_id?: string };
type Notice = { ticket: string; expires_at: number; ok: true; user: LinkedAccount | null } | { ticket: string; expires_at: number; ok: false; message: string };
type McpHandoff = { id: string; client_id: string; redirect_uri: string; code_challenge: string; client_state: string; expires_at: number };
type McpCode = { code_hash: string; client_id: string; redirect_uri: string; code_challenge: string; expires_at: number; user_id: string };
type McpSession = { access_hash: string; access_expires_at: number; refresh_hash: string; refresh_expires_at: number; client_id: string; user_id: string; retired_refresh_hashes?: string[] };
type McpGrant = { access_token: string; token_type: "Bearer"; expires_in: number; refresh_token: string; scope: typeof MCP_SCOPE };

function googleSub(value: string): boolean {
  return /^[0-9]{1,30}$/.test(value);
}
function clientId(env: Env): string {
  const id = (env.GOOGLE_CLIENT_ID ?? "").trim();
  if (!id || id.startsWith("replace-me")) throw new Error("Set GOOGLE_CLIENT_ID to the Web client id from Google Cloud.");
  if (!/^[A-Za-z0-9_-]{6,120}\.apps\.googleusercontent\.com$/.test(id)) throw new Error("GOOGLE_CLIENT_ID should look like 123-abc.apps.googleusercontent.com.");
  return id;
}
function clientSecret(env: Env): string {
  const secret = env.GOOGLE_CLIENT_SECRET ?? "";
  if (secret.trim().length < 8) throw new Error("Set GOOGLE_CLIENT_SECRET with wrangler secret put GOOGLE_CLIENT_SECRET.");
  return secret;
}
async function credentialTag(id: string, secret: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${id}\0${secret}`));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function linkedAccount(value: unknown): LinkedAccount | null {
  const user = asObject(value);
  if (!user || typeof user.id !== "string" || !googleSub(user.id)) return null;
  if (user.email != null && (typeof user.email !== "string" || user.email.length > 320 || !/^[^@\s]+@[^@\s]+$/.test(user.email))) return null;
  return { id: user.id, email: typeof user.email === "string" ? user.email : null };
}
function reusableRecord(record: StoredToken | undefined, tag: string): boolean {
  return !!record
    && typeof record.access_token === "string"
    && record.access_token.length > 0
    && typeof record.refresh_token === "string"
    && record.refresh_token.length > 0
    && record.credential_tag === tag
    && typeof record.expires_at === "number"
    && Number.isFinite(record.expires_at)
    && record.expires_at > 0
    && linkedAccount(record.user) != null;
}
function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function randomToken(bytes = 32): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return base64url(buffer);
}
async function codeChallenge(verifier: string): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
}
function boundedParam(value: string): boolean {
  return value.length > 0 && value.length <= 512 && !/[\u0000-\u001f\s]/.test(value);
}
function authCode(value: string): boolean {
  return value.length > 0 && value.length <= 2048 && !/[\u0000-\u001f\s]/.test(value);
}
function callbackUrl(origin: string): string {
  const url = new URL(origin);
  const local = url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
  if (url.protocol !== "https:" && !local) throw new Error("OAuth callback requires HTTPS");
  return `${url.origin}/oauth/callback`;
}
function publicOrigin(origin: string): string {
  return new URL(callbackUrl(origin)).origin;
}
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
const BLOCKED_REDIRECT_SCHEMES = new Set(["javascript", "data", "file", "blob", "vbscript", "about"]);
const GROK_CLIENT_ID = "grokbot";
const GROK_REDIRECTS = new Set([
  "https://www.cursor.com/agents/mcp/oauth/callback",
  "https://www.cursor.com/bot/mcp/oauth/callback",
  "https://grok.com/connectors-oauth-exchange-code/",
  "cursor://anysphere.cursor-mcp/oauth/callback",
  "http://localhost:8787/callback",
  "http://127.0.0.1:8787/callback",
]);
function grokRedirect(value: string): boolean {
  if (value.length > 2000 || value.includes("#") || /[\u0000-\u001f\s]/.test(value)) return false;
  let url: URL;
  try { url = new URL(value); } catch { return false; }
  if (url.username || url.password || url.search) return false;
  return GROK_REDIRECTS.has(url.href);
}
function clientName(value: unknown, fallback: string): string {
  const raw = typeof value === "string" ? value : "";
  const cleaned = raw.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069\u200e\u200f\ufeff]/g, "").replace(/\s+/g, " ").trim().slice(0, 120);
  return cleaned || fallback;
}
function maxAccounts(env: Env): number {
  const raw = (env.MAX_ACCOUNTS ?? "1").trim();
  if (!/^[1-9][0-9]*$/.test(raw)) throw new Error("MAX_ACCOUNTS must be a whole number from 1 to 10.");
  const value = Number(raw);
  if (value > 10) throw new Error("MAX_ACCOUNTS must be a whole number from 1 to 10.");
  return value;
}
function redirectSchemes(env: Env): Set<string> {
  const schemes = new Set<string>();
  for (const part of (env.MCP_REDIRECT_SCHEMES ?? "").split(",")) {
    const scheme = part.trim().toLowerCase();
    if (!/^[a-z][a-z0-9+.-]*$/.test(scheme) || BLOCKED_REDIRECT_SCHEMES.has(scheme) || scheme === "http" || scheme === "https") continue;
    schemes.add(scheme);
  }
  return schemes;
}
function redirectHost(value: string): string | null {
  let url: URL;
  try { url = new URL(value); } catch { return null; }
  const scheme = url.protocol.replace(":", "").toLowerCase();
  if (!/^[a-z][a-z0-9+.-]*$/.test(scheme) || BLOCKED_REDIRECT_SCHEMES.has(scheme)) return null;
  const host = url.hostname.toLowerCase();
  const web = scheme === "https" || scheme === "http";
  if (host && !(web ? /^[a-z0-9.-]+$/ : /^[a-z0-9._-]+$/).test(host)) return null;
  if (web && !host) return null;
  if (!web && !host && !url.pathname.startsWith("/")) return null;
  const port = url.port ? `:${url.port}` : "";
  if (host) return `${scheme}://${host}${port}`;
  return `${scheme}:${url.pathname.slice(0, 80)}`;
}
function allowedRedirect(value: string, schemes: ReadonlySet<string>): boolean {
  if (value.length > 2000 || value.includes("#") || /[\u0000-\u001f\s]/.test(value)) return false;
  let url: URL;
  try { url = new URL(value); } catch { return false; }
  if (url.username || url.password || !redirectHost(value)) return false;
  const scheme = url.protocol.replace(":", "").toLowerCase();
  if (scheme === "https") return true;
  if (scheme === "http") return url.hostname === "localhost" || url.hostname === "127.0.0.1";
  return schemes.has(scheme);
}
function staticClients(env: Env, schemes: ReadonlySet<string>): { client_id: string; redirect_uris: string[]; name: string }[] {
  const raw = (env.MCP_CLIENTS ?? "").trim();
  if (!raw) return [];
  if (raw.length > 16_000) throw new Error("MCP_CLIENTS is too large.");
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("MCP_CLIENTS is not valid JSON."); }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 20) throw new Error("MCP_CLIENTS must be a list of 1 to 20 clients.");
  const clients: { client_id: string; redirect_uris: string[]; name: string }[] = [];
  for (const entry of parsed) {
    const record = asObject(entry);
    const id = record?.client_id;
    const uris = Array.isArray(record?.redirect_uris) ? record.redirect_uris : null;
    const name = clientName(record?.client_name, "");
    if (typeof id !== "string" || id.length > 2000 || !id || /[\u0000-\u001f\s]/.test(id)) throw new Error("MCP_CLIENTS has a client without a valid client_id.");
    if (!name) throw new Error("MCP_CLIENTS has a client without a client_name.");
    if (!uris || uris.length < 1 || uris.length > 8 || uris.some((uri) => typeof uri !== "string" || !allowedRedirect(uri, schemes))) throw new Error("MCP_CLIENTS has a client without a valid redirect_uris list.");
    if (clients.some((client) => client.client_id === id)) throw new Error("MCP_CLIENTS lists the same client_id twice.");
    clients.push({ client_id: id, redirect_uris: uris as string[], name });
  }
  return clients;
}
function mcpRedirect(redirectUri: string, params: Record<string, string>): string {
  const target = new URL(redirectUri);
  for (const [key, value] of Object.entries(params)) target.searchParams.set(key, value);
  return target.toString();
}
class RefreshRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RefreshRejected";
  }
}
class GrantRejected extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GrantRejected";
  }
}

// One Durable Object holds the Google grants. Access-token refreshes are serialized so two requests cannot race a replacement.
// A single alarm deletes expired logins, notices, and MCP refresh grants, then schedules the next expiry.
export class OAuthVault extends DurableObject<Env> {
  private tail: Promise<void> = Promise.resolve();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      if ((await this.ctx.storage.getAlarm()) == null) await this.scheduleCleanup();
    });
  }

  private exclusive<T>(task: () => Promise<T>): Promise<T> {
    const previous = this.tail;
    let release: () => void = () => {};
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    return previous.then(task).finally(release);
  }

  async alarm(): Promise<void> {
    await this.exclusive(async () => {
      await this.deleteExpired();
      await this.scheduleCleanup();
    });
  }

  private grantKey(userId: string): string {
    return `${GRANT_PREFIX}${userId}`;
  }

  private async grantMap(tag: string): Promise<Map<string, TokenRecord>> {
    const grants = new Map<string, TokenRecord>();
    const listed = await this.ctx.storage.list<StoredToken>({ prefix: GRANT_PREFIX });
    for (const [key, value] of listed) {
      const user = linkedAccount(value?.user);
      if (!user || !reusableRecord(value, tag)) {
        const token = typeof value?.refresh_token === "string" && value.refresh_token ? value.refresh_token : value?.access_token;
        if (typeof token === "string" && token) await this.revoke(token);
        await this.ctx.storage.delete(key);
        continue;
      }
      grants.set(user.id, {
        access_token: value.access_token as string,
        expires_at: value.expires_at as number,
        refresh_token: value.refresh_token as string,
        credential_tag: value.credential_tag as string,
        user,
      });
    }
    return grants;
  }

  private async deleteExpired(now = Date.now()): Promise<void> {
    await this.pruneInFlight(PENDING_PREFIX, now);
    await this.pruneInFlight(HANDOFF_PREFIX, now);
    await this.pruneInFlight(CODE_PREFIX, now);
    const notice = await this.ctx.storage.get<Notice>("oauth_notice");
    if (notice && Number.isFinite(notice.expires_at) && notice.expires_at <= now) await this.ctx.storage.delete("oauth_notice");
    for (const [userId, session] of await this.sessionMap()) {
      if (session.refresh_expires_at <= now) await this.dropLogin(userId);
    }
  }

  private async scheduleCleanup(): Promise<void> {
    const times: number[] = [];
    times.push(...await this.inFlightExpiries(PENDING_PREFIX));
    const notice = await this.ctx.storage.get<Notice>("oauth_notice");
    if (notice && Number.isFinite(notice.expires_at)) times.push(notice.expires_at);
    times.push(...await this.inFlightExpiries(HANDOFF_PREFIX));
    times.push(...await this.inFlightExpiries(CODE_PREFIX));
    for (const session of (await this.sessionMap()).values()) times.push(session.refresh_expires_at);
    const next = times.length === 0 ? null : Math.min(...times);
    const current = await this.ctx.storage.getAlarm();
    if (next == null) {
      if (current != null) await this.ctx.storage.deleteAlarm();
      return;
    }
    if (current !== next) await this.ctx.storage.setAlarm(next);
  }

  private pendingKey(state: string): string {
    return `${PENDING_PREFIX}${state}`;
  }

  private async pruneInFlight(prefix: string, now: number): Promise<void> {
    const listed = await this.ctx.storage.list<{ expires_at?: number }>({ prefix });
    for (const [key, value] of listed) {
      const expiry = value?.expires_at;
      if (typeof expiry !== "number" || !Number.isFinite(expiry) || expiry <= now) await this.ctx.storage.delete(key);
    }
  }

  private async inFlightExpiries(prefix: string): Promise<number[]> {
    const times: number[] = [];
    const listed = await this.ctx.storage.list<{ expires_at?: number }>({ prefix });
    for (const value of listed.values()) {
      if (typeof value?.expires_at === "number" && Number.isFinite(value.expires_at)) times.push(value.expires_at);
    }
    return times;
  }

  private async reserveInFlight(prefix: string): Promise<void> {
    const now = Date.now();
    let count = 0;
    const listed = await this.ctx.storage.list<{ expires_at?: number }>({ prefix });
    for (const [key, value] of listed) {
      const expiry = value?.expires_at;
      if (typeof expiry !== "number" || !Number.isFinite(expiry) || expiry <= now) await this.ctx.storage.delete(key);
      else count++;
    }
    if (count >= IN_FLIGHT_CAP) throw new Error("Too many sign-ins are already in progress. Wait for one to finish.");
  }

  private async findPending(state: string): Promise<{ key: string; pending: PendingAuth } | null> {
    if (!boundedParam(state)) return null;
    const key = this.pendingKey(state);
    const pending = await this.ctx.storage.get<PendingAuth>(key);
    if (!pending) return null;
    if (pending.expires_at <= Date.now() || !secretEquals(state, pending.state)) {
      await this.ctx.storage.delete(key);
      await this.scheduleCleanup();
      return null;
    }
    return { key, pending };
  }

  async getToken(userId: string, force = false, previouslyUsed?: string): Promise<string> {
    return this.exclusive(() => this.readOrRefresh(userId, force, previouslyUsed));
  }

  async beginConnect(origin: string): Promise<string> {
    return this.exclusive(() => this.startGoogle(origin));
  }

  async approveMcp(origin: string, handoffId: string): Promise<string> {
    return this.exclusive(async () => {
      const handoff = await this.handoffById(handoffId);
      if (!handoff) throw new Error("This sign-in has expired. Start it again from the app.");
      return this.startGoogle(origin, handoff.id);
    });
  }

  private async startGoogle(origin: string, mcpHandoffId?: string): Promise<string> {
    const redirectUri = callbackUrl(origin);
    const state = randomToken();
    const verifier = randomToken(48);
    const pending: PendingAuth = { state, verifier, redirect_uri: redirectUri, expires_at: Date.now() + 30 * 60_000, ...(mcpHandoffId ? { mcp_handoff_id: mcpHandoffId } : {}) };
    await this.reserveInFlight(PENDING_PREFIX);
    await this.ctx.storage.put(this.pendingKey(state), pending);
    await this.scheduleCleanup();
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", clientId(this.env));
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", GOOGLE_SCOPE);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", await codeChallenge(verifier));
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("prompt", "consent");
    return url.toString();
  }

  async finishConnect(code: string, state: string): Promise<{ ticket: string } | { error: string } | { redirect: string }> {
    return this.exclusive(async () => {
      if (!authCode(code) || !boundedParam(state)) return { error: "The Google redirect was incomplete. Start again at /oauth/start." };
      const found = await this.findPending(state);
      if (!found) return { error: "This Google authorization has expired. Start again at /oauth/start." };
      const pending = found.pending;
      await this.ctx.storage.delete(found.key);
      try {
        const limit = maxAccounts(this.env);
        const id = clientId(this.env);
        const secret = clientSecret(this.env);
        const minted = await this.requestToken("authorization_code", {
          grant_type: "authorization_code",
          code,
          client_id: id,
          client_secret: secret,
          redirect_uri: pending.redirect_uri,
          code_verifier: pending.verifier,
        });
        if (!minted.refresh_token) {
          await this.revoke(minted.access_token);
          throw new Error("Google did not return a refresh token. Start again and allow offline access.");
        }
        const tag = await credentialTag(id, secret);
        const user = await this.acceptedUser(minted.access_token, minted.refresh_token);
        const grants = await this.grantMap(tag);
        const previous = grants.get(user.id);
        if (!previous && grants.size >= limit) {
          await this.revoke(minted.refresh_token);
          const noun = limit === 1 ? "account is" : "accounts are";
          throw new GrantRejected(`${limit} Google ${noun} already connected. The previous connection was left unchanged.`);
        }
        const next: TokenRecord = {
          access_token: minted.access_token,
          expires_at: minted.expires_at,
          refresh_token: minted.refresh_token,
          credential_tag: tag,
          user,
        };
        await this.ctx.storage.put(this.grantKey(user.id), next);
        await this.scheduleCleanup();
        if (previous && previous.refresh_token !== next.refresh_token) await this.revoke(previous.refresh_token);
        if (pending.mcp_handoff_id) {
          const handoff = await this.handoffById(pending.mcp_handoff_id);
          if (handoff) return { redirect: await this.issueMcpCode(handoff, user.id) };
        }
        return { ticket: await this.writeNotice({ ok: true, user }) };
      } catch (e) {
        await this.scheduleCleanup();
        if (pending.mcp_handoff_id) {
          const location = await this.failHandoff(pending.mcp_handoff_id, e instanceof GrantRejected ? "access_denied" : "server_error");
          if (location) return { redirect: location };
        }
        return { error: e instanceof Error ? e.message.slice(0, 300) : "Google authorization failed." };
      }
    });
  }

  async failNotice(message: string): Promise<string | null> {
    return this.exclusive(async () => {
      const existing = await this.ctx.storage.get<Notice>("oauth_notice");
      if (existing && existing.expires_at > Date.now()) return null;
      return this.writeNotice({ ok: false, message: message.slice(0, 300) });
    });
  }

  async takeNotice(ticket: string): Promise<Notice | null> {
    return this.exclusive(async () => {
      const notice = await this.ctx.storage.get<Notice>("oauth_notice");
      if (!notice || notice.expires_at <= Date.now()) {
        if (notice) {
          await this.ctx.storage.delete("oauth_notice");
          await this.scheduleCleanup();
        }
        return null;
      }
      if (!boundedParam(ticket) || !secretEquals(ticket, notice.ticket)) return null;
      await this.ctx.storage.delete("oauth_notice");
      await this.scheduleCleanup();
      return notice;
    });
  }

  async connection(userId: string): Promise<{ connected: false } | { connected: true; account: { user: LinkedAccount; access_expires_at: string } }> {
    return this.exclusive(async () => {
      const tag = await credentialTag(clientId(this.env), clientSecret(this.env));
      const stored = (await this.grantMap(tag)).get(userId);
      const user = stored ? linkedAccount(stored.user) : null;
      if (!stored || !user) return { connected: false };
      return { connected: true, account: { user, access_expires_at: new Date(stored.expires_at).toISOString() } };
    });
  }

  async beginMcpAuthorization(input: { origin: string; clientId: string; redirectUri: string; responseType: string; codeChallenge: string; codeChallengeMethod: string; clientState: string; resource: string | null }): Promise<{ id: string; name: string; redirectHost: string } | { redirect: string }> {
    return this.exclusive(async () => {
      if (input.clientId.length > 2000 || input.redirectUri.length > 2000) throw new Error("This app is not a recognized OAuth client.");
      const client = await this.clientRedirects(input.clientId);
      if (!client) throw new Error("This app is not a recognized OAuth client.");
      if (input.clientId === GROK_CLIENT_ID ? !grokRedirect(input.redirectUri) : !client.redirect_uris.some((uri) => secretEquals(uri, input.redirectUri))) throw new Error("The app's redirect URL is not registered.");
      const redirectHostName = redirectHost(input.redirectUri);
      if (!redirectHostName) throw new Error("The app's redirect URL is not registered.");
      const challengeOk = input.responseType === "code" && /^[A-Za-z0-9_-]{43,128}$/.test(input.codeChallenge) && input.codeChallengeMethod === "S256";
      const stateOk = boundedParam(input.clientState);
      const resourceOk = input.resource == null || input.resource === `${input.origin}/mcp`;
      if (!challengeOk || !stateOk || !resourceOk) return { redirect: mcpRedirect(input.redirectUri, { error: "invalid_request", state: stateOk ? input.clientState : "" }) };
      const handoff: McpHandoff = { id: randomToken(), client_id: input.clientId, redirect_uri: input.redirectUri, code_challenge: input.codeChallenge, client_state: input.clientState, expires_at: Date.now() + 30 * 60_000 };
      await this.reserveInFlight(HANDOFF_PREFIX);
      await this.ctx.storage.put(`${HANDOFF_PREFIX}${handoff.id}`, handoff);
      await this.scheduleCleanup();
      return { id: handoff.id, name: client.name, redirectHost: redirectHostName };
    });
  }

  async denyConnect(state: string): Promise<{ redirect: string } | { error: string }> {
    return this.exclusive(async () => {
      const found = await this.findPending(state);
      if (!found) return { error: "Google did not grant access. Start again at /oauth/start." };
      const pending = found.pending;
      await this.ctx.storage.delete(found.key);
      await this.scheduleCleanup();
      if (pending.mcp_handoff_id) {
        const location = await this.failHandoff(pending.mcp_handoff_id, "access_denied");
        if (location) return { redirect: location };
      }
      return { error: "Google did not grant access. Start again at /oauth/start." };
    });
  }

  async grantMcp(input: { grantType: string; code: string; redirectUri: string; clientId: string; verifier: string; refreshToken: string }): Promise<{ error: string } | McpGrant> {
    return this.exclusive(async () => input.grantType === "authorization_code" ? this.exchangeCode(input) : input.grantType === "refresh_token" ? this.exchangeRefresh(input) : { error: "unsupported_grant_type" });
  }

  async sessionUser(token: string): Promise<string | null> {
    return this.exclusive(async () => {
      if (!boundedParam(token)) return null;
      const presented = await sha256Hex(token);
      let userId: string | null = null;
      for (const [id, session] of await this.sessionMap()) {
        if (session.access_expires_at <= Date.now()) continue;
        if (secretEquals(presented, session.access_hash)) userId = id;
      }
      if (userId == null) return null;
      const tag = await credentialTag(clientId(this.env), clientSecret(this.env));
      return (await this.grantMap(tag)).has(userId) ? userId : null;
    });
  }

  async revokePresented(token: string, presentedClientId: string): Promise<void> {
    return this.exclusive(async () => {
      if (!boundedParam(token)) return;
      const presented = await sha256Hex(token);
      let matched: McpSession | null = null;
      for (const session of (await this.sessionMap()).values()) {
        const access = secretEquals(presented, session.access_hash);
        const refresh = secretEquals(presented, session.refresh_hash) || this.priorRefreshHashes(session).some((hash) => secretEquals(presented, hash));
        if (access || refresh) matched = session;
      }
      if (!matched || (presentedClientId && !secretEquals(presentedClientId, matched.client_id))) return;
      await this.dropLogin(matched.user_id);
    });
  }

  private async readOrRefresh(userId: string, force: boolean, previouslyUsed?: string): Promise<string> {
    const tag = await credentialTag(clientId(this.env), clientSecret(this.env));
    const stored = (await this.grantMap(tag)).get(userId);
    if (!stored) throw new Error("This Google account is not connected. Approve it from Grokbot again.");
    if (force && previouslyUsed && previouslyUsed !== stored.access_token) return stored.access_token;
    if (!force && Date.now() < stored.expires_at - 5 * 60_000) return stored.access_token;
    return (await this.issue(stored)).access_token;
  }

  private async issue(current: TokenRecord): Promise<TokenRecord> {
    const user = linkedAccount(current.user);
    if (!user) throw new Error("The stored Google account is incomplete.");
    let minted: Minted;
    try {
      minted = await this.requestToken("refresh_token", {
        grant_type: "refresh_token",
        refresh_token: current.refresh_token,
        client_id: clientId(this.env),
        client_secret: clientSecret(this.env),
      });
    } catch (e) {
      if (e instanceof RefreshRejected) {
        await this.ctx.storage.delete(this.grantKey(user.id));
        await this.scheduleCleanup();
      }
      throw e;
    }
    const next: TokenRecord = {
      access_token: minted.access_token,
      expires_at: minted.expires_at,
      refresh_token: minted.refresh_token ?? current.refresh_token,
      credential_tag: await credentialTag(clientId(this.env), clientSecret(this.env)),
      user,
    };
    await this.ctx.storage.put(this.grantKey(user.id), next);
    await this.scheduleCleanup();
    return next;
  }

  private async requestToken(kind: "authorization_code" | "refresh_token", body: Record<string, string>): Promise<Minted> {
    const res = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      redirect: "manual",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams(body),
    });
    const text = await res.text();
    let parsed: unknown = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; }
    if (isRedirect(res) || !res.ok) {
      const reason = oauthFailure(parsed, res.status);
      if (kind === "refresh_token" && reason.startsWith("invalid_grant")) throw new RefreshRejected("The Google approval is no longer valid. Approve the account again.");
      throw new Error(`Google OAuth token request failed: ${reason}`);
    }
    const tokens = asObject(parsed);
    const accessToken = tokens?.access_token;
    const refreshToken = typeof tokens?.refresh_token === "string" && tokens.refresh_token ? tokens.refresh_token : null;
    const expiresIn = tokens?.expires_in;
    if (typeof accessToken !== "string" || !accessToken) throw new Error("Incomplete OAuth token response");
    if (typeof expiresIn !== "number" || !Number.isFinite(expiresIn) || expiresIn <= 0) throw new Error("Incomplete OAuth token response");
    const scope = tokens?.scope;
    if (kind === "authorization_code" && !tasksScopeGranted(scope)) throw new Error("Google did not grant the Tasks scope. Start again and allow Tasks access.");
    if (kind === "refresh_token" && scope != null && !tasksScopeGranted(scope)) throw new RefreshRejected("The Google approval no longer includes Tasks. Approve the account again.");
    return { access_token: accessToken, expires_at: Date.now() + expiresIn * 1000, refresh_token: refreshToken };
  }

  private async acceptedUser(accessToken: string, refreshToken: string): Promise<LinkedAccount> {
    try {
      return await this.identify(accessToken);
    } catch (e) {
      await this.revoke(refreshToken);
      const reason = e instanceof Error ? e.message : "Google profile request failed";
      throw new GrantRejected(`${reason} The previous connection was left unchanged.`);
    }
  }

  private async identify(accessToken: string): Promise<LinkedAccount> {
    const res = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      redirect: "manual",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
    });
    if (isRedirect(res) || !res.ok) {
      await res.body?.cancel();
      throw new Error(`Google profile request failed: HTTP ${res.status}`);
    }
    const data = asObject(await res.json());
    const sub = data?.sub;
    if (typeof sub !== "string" || !googleSub(sub)) throw new Error("Google profile response was incomplete");
    const email = typeof data?.email === "string" && data.email.length <= 320 && /^[^@\s]+@[^@\s]+$/.test(data.email) ? data.email : null;
    return { id: sub, email };
  }

  private async revoke(token: string): Promise<void> {
    try {
      const res = await fetch("https://oauth2.googleapis.com/revoke", {
        method: "POST",
        redirect: "manual",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token }),
      });
      await res.body?.cancel();
    } catch { /* Revocation is best-effort. The caller keeps or discards the stored grant. */ }
  }

  private async writeNotice(body: { ok: true; user: LinkedAccount | null } | { ok: false; message: string }): Promise<string> {
    const ticket = randomToken();
    const notice = { ...body, ticket, expires_at: Date.now() + 120_000 } as Notice;
    await this.ctx.storage.put("oauth_notice", notice);
    await this.scheduleCleanup();
    return ticket;
  }

  private async clientRedirects(presentedClientId: string): Promise<{ redirect_uris: string[]; name: string } | null> {
    if (presentedClientId === GROK_CLIENT_ID) return { redirect_uris: [], name: "Grok Bot" };
    const schemes = redirectSchemes(this.env);
    for (const client of staticClients(this.env, schemes)) {
      if (secretEquals(presentedClientId, client.client_id)) return { redirect_uris: client.redirect_uris, name: client.name };
    }
    return null;
  }

  private async handoffById(id: string): Promise<McpHandoff | null> {
    if (!boundedParam(id)) return null;
    const key = `${HANDOFF_PREFIX}${id}`;
    const handoff = await this.ctx.storage.get<McpHandoff>(key);
    if (!handoff) return null;
    if (handoff.expires_at <= Date.now() || !secretEquals(id, handoff.id)) {
      await this.ctx.storage.delete(key);
      await this.scheduleCleanup();
      return null;
    }
    return handoff;
  }

  private async deleteHandoff(handoff: McpHandoff): Promise<void> {
    const key = `${HANDOFF_PREFIX}${handoff.id}`;
    const stored = await this.ctx.storage.get<McpHandoff>(key);
    if (stored && secretEquals(handoff.id, stored.id)) await this.ctx.storage.delete(key);
  }

  private sessionKey(userId: string): string {
    return `${SESSION_PREFIX}${userId}`;
  }

  private boundSession(value: Partial<McpSession> | undefined, userId: string): McpSession | null {
    if (!googleSub(userId) || !value || value.user_id !== userId) return null;
    if (typeof value.access_hash !== "string" || !value.access_hash || typeof value.refresh_hash !== "string" || !value.refresh_hash) return null;
    if (typeof value.client_id !== "string" || !value.client_id) return null;
    if (typeof value.access_expires_at !== "number" || !Number.isFinite(value.access_expires_at)) return null;
    if (typeof value.refresh_expires_at !== "number" || !Number.isFinite(value.refresh_expires_at)) return null;
    return {
      access_hash: value.access_hash,
      access_expires_at: value.access_expires_at,
      refresh_hash: value.refresh_hash,
      refresh_expires_at: value.refresh_expires_at,
      client_id: value.client_id,
      user_id: userId,
      retired_refresh_hashes: this.priorRefreshHashes(value as McpSession),
    };
  }

  private async sessionMap(): Promise<Map<string, McpSession>> {
    const sessions = new Map<string, McpSession>();
    const listed = await this.ctx.storage.list<Partial<McpSession>>({ prefix: SESSION_PREFIX });
    for (const [key, value] of listed) {
      const userId = key.slice(SESSION_PREFIX.length);
      const session = this.boundSession(value, userId);
      if (!session) {
        await this.ctx.storage.delete(key);
        continue;
      }
      sessions.set(userId, session);
    }
    return sessions;
  }

  private async dropLogin(userId: string): Promise<void> {
    await this.ctx.storage.delete(this.sessionKey(userId));
    const tag = await credentialTag(clientId(this.env), clientSecret(this.env));
    const stored = (await this.grantMap(tag)).get(userId);
    if (stored) {
      await this.revoke(stored.refresh_token);
      await this.ctx.storage.delete(this.grantKey(userId));
    }
    await this.scheduleCleanup();
  }

  private async issueMcpCode(handoff: McpHandoff, userId: string): Promise<string> {
    const code = randomToken();
    const record: McpCode = { code_hash: await sha256Hex(code), client_id: handoff.client_id, redirect_uri: handoff.redirect_uri, code_challenge: handoff.code_challenge, expires_at: Date.now() + 60_000, user_id: userId };
    await this.reserveInFlight(CODE_PREFIX);
    await this.ctx.storage.put(`${CODE_PREFIX}${record.code_hash}`, record);
    await this.deleteHandoff(handoff);
    await this.scheduleCleanup();
    return mcpRedirect(handoff.redirect_uri, { code, state: handoff.client_state });
  }

  private async failHandoff(id: string, error: string): Promise<string | null> {
    const handoff = await this.handoffById(id);
    if (!handoff) return null;
    await this.deleteHandoff(handoff);
    await this.scheduleCleanup();
    return mcpRedirect(handoff.redirect_uri, { error, state: handoff.client_state });
  }

  private async issueSession(presentedClientId: string, userId: string, previous?: McpSession): Promise<McpGrant> {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const retired = previous ? [...this.priorRefreshHashes(previous), previous.refresh_hash].slice(-MCP_RETIRED_REFRESHES) : [];
    const session: McpSession = {
      access_hash: await sha256Hex(accessToken),
      access_expires_at: Date.now() + MCP_ACCESS_TTL * 1000,
      refresh_hash: await sha256Hex(refreshToken),
      refresh_expires_at: Date.now() + MCP_REFRESH_TTL * 1000,
      client_id: presentedClientId,
      user_id: userId,
      retired_refresh_hashes: retired,
    };
    await this.ctx.storage.put(this.sessionKey(userId), session);
    await this.scheduleCleanup();
    return { access_token: accessToken, token_type: "Bearer", expires_in: MCP_ACCESS_TTL, refresh_token: refreshToken, scope: MCP_SCOPE };
  }

  private priorRefreshHashes(session: McpSession): string[] {
    const prior = session.retired_refresh_hashes;
    return Array.isArray(prior) ? prior.filter((hash) => typeof hash === "string") : [];
  }

  private async exchangeCode(input: { code: string; redirectUri: string; clientId: string; verifier: string }): Promise<{ error: string } | McpGrant> {
    if (!boundedParam(input.code)) return { error: "invalid_grant" };
    const codeHash = await sha256Hex(input.code);
    const key = `${CODE_PREFIX}${codeHash}`;
    const record = await this.ctx.storage.get<McpCode>(key);
    if (!record || record.expires_at <= Date.now() || !secretEquals(codeHash, record.code_hash)) {
      if (record && record.expires_at <= Date.now()) {
        await this.ctx.storage.delete(key);
        await this.scheduleCleanup();
      }
      return { error: "invalid_grant" };
    }
    await this.ctx.storage.delete(key);
    await this.scheduleCleanup();
    const verifier = input.verifier;
    const verifierOk = verifier.length >= 43 && verifier.length <= 128 && /^[A-Za-z0-9._~-]+$/.test(verifier);
    if (!verifierOk || !secretEquals(input.clientId, record.client_id) || !secretEquals(input.redirectUri, record.redirect_uri) || !secretEquals(await codeChallenge(verifier), record.code_challenge)) return { error: "invalid_grant" };
    if (!googleSub(record.user_id)) return { error: "invalid_grant" };
    const previous = (await this.sessionMap()).get(record.user_id);
    return this.issueSession(record.client_id, record.user_id, previous);
  }

  private async exchangeRefresh(input: { clientId: string; refreshToken: string }): Promise<{ error: string } | McpGrant> {
    if (!boundedParam(input.refreshToken)) return { error: "invalid_grant" };
    const presented = await sha256Hex(input.refreshToken);
    let current: McpSession | null = null;
    let retired: McpSession | null = null;
    for (const session of (await this.sessionMap()).values()) {
      if (session.refresh_expires_at <= Date.now()) continue;
      if (this.priorRefreshHashes(session).some((hash) => secretEquals(presented, hash))) retired = session;
      else if (secretEquals(presented, session.refresh_hash) && secretEquals(input.clientId, session.client_id)) current = session;
    }
    if (retired) {
      await this.dropLogin(retired.user_id);
      return { error: "invalid_grant" };
    }
    if (!current) return { error: "invalid_grant" };
    return this.issueSession(current.client_id, current.user_id, current);
  }
}

function vault(env: Env) {
  return env.OAUTH.get(env.OAUTH.idFromName("google-tasks-main"));
}
type Json = Record<string, any>;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const resourceId = z.string().trim().min(1).max(512).regex(/^[A-Za-z0-9_@=+-]+$/);
const pageToken = z.string().min(1).max(2048).refine((value) => !/[\u0000-\u001f\s]/.test(value), "Invalid page token").optional();
const calendarDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine((value) => {
  const [year, month, day] = value.split("-").map(Number);
  if (year < 1970 || year > 2100) return false;
  const utc = new Date(Date.UTC(year, month - 1, day));
  return utc.getUTCFullYear() === year && utc.getUTCMonth() === month - 1 && utc.getUTCDate() === day;
}, "Use a real calendar date, YYYY-MM-DD");
const taskTitle = z.string().trim().min(1).max(1024).refine((value) => !/[\u0000-\u001f]/.test(value), "Title cannot contain control characters");
const taskNotes = z.string().max(8000).refine((value) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value), "Notes contain unsupported control characters");
const listTitle = z.string().trim().min(1).max(1024).refine((value) => !/[\u0000-\u001f]/.test(value), "Title cannot contain control characters");

function isRedirect(response: Response) {
  return response.redirected || (response.status >= 300 && response.status < 400);
}
function asObject(value: unknown): Json | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Json : null;
}
function tasksScopeGranted(scope: unknown): boolean {
  return typeof scope === "string" && scope.split(/\s+/).includes(TASKS_SCOPE);
}
function idPath(id: string): string {
  const parsed = resourceId.parse(id);
  if (parsed === "@default") return "@default";
  return encodeURIComponent(parsed);
}
function withQuery(path: string, query: Record<string, string | undefined>): string {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) if (value != null && value !== "") qs.set(key, value);
  const text = qs.toString();
  return text ? `${path}?${text}` : path;
}
function dueDate(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const match = /^(\d{4}-\d{2}-\d{2})T/.exec(value);
  return match ? match[1] : null;
}
function httpsLink(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 2000) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password) return null;
    return url.toString();
  } catch { return null; }
}
function cleanAssignment(value: unknown): { surface_type: string | null; link: string | null } | null {
  const info = asObject(value);
  if (!info) return null;
  const surface = typeof info.surfaceType === "string" ? info.surfaceType.slice(0, 40) : null;
  const link = httpsLink(info.linkToTask);
  if (!surface && !link) return null;
  return { surface_type: surface, link };
}
function cleanTask(value: unknown): Json {
  const task = asObject(value);
  if (!task || typeof task.id !== "string" || !task.id) throw new Error("Google Tasks response missing task id");
  const links = Array.isArray(task.links) ? task.links.flatMap((item: unknown) => {
    const link = asObject(item);
    const href = httpsLink(link?.link);
    if (!link || !href) return [];
    return [{
      type: typeof link.type === "string" ? link.type.slice(0, 40) : null,
      description: typeof link.description === "string" ? link.description.slice(0, 300) : null,
      link: href,
    }];
  }) : [];
  const assignment = cleanAssignment(task.assignmentInfo);
  return {
    id: task.id,
    title: typeof task.title === "string" ? task.title : "",
    notes: typeof task.notes === "string" ? task.notes : "",
    status: task.status === "completed" ? "completed" : "needsAction",
    due: dueDate(task.due),
    completed: typeof task.completed === "string" ? task.completed : null,
    updated: typeof task.updated === "string" ? task.updated : null,
    parent: typeof task.parent === "string" ? task.parent : null,
    position: typeof task.position === "string" ? task.position : null,
    hidden: task.hidden === true,
    deleted: task.deleted === true,
    web_view_link: httpsLink(task.webViewLink),
    ...(links.length ? { links } : {}),
    ...(assignment ? { assignment } : {}),
  };
}
function cleanList(value: unknown): Json {
  const list = asObject(value);
  if (!list || typeof list.id !== "string" || !list.id) throw new Error("Google Tasks response missing task list id");
  return {
    id: list.id,
    title: typeof list.title === "string" ? list.title : "",
    updated: typeof list.updated === "string" ? list.updated : null,
  };
}
function nextPage(data: Json | null): string | null {
  return typeof data?.nextPageToken === "string" && data.nextPageToken ? data.nextPageToken : null;
}
function googleFailure(parsed: unknown, status: number): string {
  const body = asObject(parsed);
  const error = asObject(body?.error);
  const message = typeof error?.message === "string" ? error.message : "";
  const clean = message.replace(/\s+/g, " ").trim().slice(0, 240);
  return clean ? `Google Tasks ${status}: ${clean}` : `Google Tasks ${status}`;
}
async function google(env: Env, accountId: string, path: string, init: RequestInit = {}): Promise<Json | null> {
  if (!path.startsWith("/tasks/v1/")) throw new Error("Disallowed Tasks API path");
  let accessToken = await vault(env).getToken(accountId);
  const method = (init.method ?? "GET").toUpperCase();
  const retryTransientStatus = method === "GET" || method === "HEAD";
  for (let attempt = 0; attempt < 4; attempt++) {
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${accessToken}`);
    headers.set("Accept", "application/json");
    if (init.body != null) headers.set("Content-Type", "application/json");
    const response = await fetch(`https://tasks.googleapis.com${path}`, { ...init, redirect: "manual", headers });
    if (isRedirect(response)) throw new Error(`Google redirect refused: HTTP ${response.status}`);
    if (response.status === 401 && attempt === 0) {
      await response.body?.cancel();
      accessToken = await vault(env).getToken(accountId, true, accessToken);
      continue;
    }
    if (retryTransientStatus && (response.status === 429 || response.status >= 500) && attempt < 3) {
      const seconds = Number(response.headers.get("Retry-After"));
      await response.body?.cancel();
      await sleep(Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds * 1000, 10000) : 300 * 2 ** attempt);
      continue;
    }
    const text = await response.text();
    if (!response.ok) {
      let parsed: unknown = null;
      try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; }
      throw new Error(googleFailure(parsed, response.status));
    }
    if (!text) return null;
    let parsed: unknown = null;
    try { parsed = JSON.parse(text); } catch { throw new Error("Google Tasks returned a response that was not JSON"); }
    const data = asObject(parsed);
    if (!data) throw new Error("Google Tasks returned an unexpected response");
    return data;
  }
  throw new Error("Google Tasks retry limit reached");
}
async function listTaskLists(env: Env, accountId: string, page?: string, limit = 100) {
  const data = await google(env, accountId, withQuery("/tasks/v1/users/@me/lists", { maxResults: String(limit), pageToken: page }));
  const taskLists = Array.isArray(data?.items) ? data.items.map((item: unknown) => cleanList(item)) : [];
  return { task_lists: taskLists, next_page_token: nextPage(data) };
}
async function getTaskList(env: Env, accountId: string, taskListId: string) {
  const data = await google(env, accountId, `/tasks/v1/users/@me/lists/${idPath(taskListId)}`);
  return { task_list: cleanList(data) };
}
async function createTaskList(env: Env, accountId: string, title: string) {
  const data = await google(env, accountId, "/tasks/v1/users/@me/lists", { method: "POST", body: JSON.stringify({ title }) });
  return { task_list: cleanList(data) };
}
async function renameTaskList(env: Env, accountId: string, taskListId: string, title: string) {
  const data = await google(env, accountId, `/tasks/v1/users/@me/lists/${idPath(taskListId)}`, { method: "PATCH", body: JSON.stringify({ title }) });
  return { task_list: cleanList(data) };
}
async function deleteTaskList(env: Env, accountId: string, taskListId: string) {
  await google(env, accountId, `/tasks/v1/users/@me/lists/${idPath(taskListId)}`, { method: "DELETE" });
  return { ok: true, task_list_id: taskListId };
}
type TaskQuery = {
  task_list_id: string;
  page_token?: string;
  limit: number;
  include_completed: boolean;
  include_hidden: boolean;
  include_deleted: boolean;
  include_assigned: boolean;
  due_min?: string;
  due_max?: string;
  completed_min?: string;
  completed_max?: string;
  updated_min?: string;
};
async function listTasks(env: Env, accountId: string, input: TaskQuery) {
  const data = await google(env, accountId, withQuery(`/tasks/v1/lists/${idPath(input.task_list_id)}/tasks`, {
    maxResults: String(input.limit),
    pageToken: input.page_token,
    showCompleted: input.include_completed ? "true" : "false",
    showHidden: input.include_hidden ? "true" : "false",
    showDeleted: input.include_deleted ? "true" : "false",
    showAssigned: input.include_assigned ? "true" : "false",
    dueMin: input.due_min ? `${input.due_min}T00:00:00.000Z` : undefined,
    dueMax: input.due_max ? `${input.due_max}T23:59:59.000Z` : undefined,
    completedMin: input.completed_min ? `${input.completed_min}T00:00:00.000Z` : undefined,
    completedMax: input.completed_max ? `${input.completed_max}T23:59:59.000Z` : undefined,
    updatedMin: input.updated_min ? `${input.updated_min}T00:00:00.000Z` : undefined,
  }));
  const tasks = Array.isArray(data?.items) ? data.items.map((item: unknown) => cleanTask(item)) : [];
  return { task_list_id: input.task_list_id, tasks, next_page_token: nextPage(data) };
}
async function getTask(env: Env, accountId: string, taskListId: string, taskId: string) {
  const data = await google(env, accountId, `/tasks/v1/lists/${idPath(taskListId)}/tasks/${idPath(taskId)}`);
  return { task: cleanTask(data) };
}
async function createTask(env: Env, accountId: string, input: { task_list_id: string; title: string; notes?: string; due?: string; status?: "needsAction" | "completed"; parent?: string; previous?: string }) {
  const body: Json = { title: input.title };
  if (input.notes != null) body.notes = input.notes;
  if (input.due != null) body.due = `${input.due}T00:00:00.000Z`;
  if (input.status) body.status = input.status;
  const data = await google(env, accountId, withQuery(`/tasks/v1/lists/${idPath(input.task_list_id)}/tasks`, {
    parent: input.parent,
    previous: input.previous,
  }), { method: "POST", body: JSON.stringify(body) });
  return { task: cleanTask(data) };
}
async function updateTask(env: Env, accountId: string, input: { task_list_id: string; task_id: string; title?: string; notes?: string; due?: string; clear_due?: boolean; status?: "needsAction" | "completed" }) {
  const body: Json = {};
  if (input.title != null) body.title = input.title;
  if (input.notes != null) body.notes = input.notes;
  if (input.clear_due) body.due = null;
  else if (input.due != null) body.due = `${input.due}T00:00:00.000Z`;
  if (input.status) body.status = input.status;
  const data = await google(env, accountId, `/tasks/v1/lists/${idPath(input.task_list_id)}/tasks/${idPath(input.task_id)}`, { method: "PATCH", body: JSON.stringify(body) });
  return { task: cleanTask(data) };
}
async function setStatus(env: Env, accountId: string, taskListId: string, taskId: string, status: "needsAction" | "completed") {
  const data = await google(env, accountId, `/tasks/v1/lists/${idPath(taskListId)}/tasks/${idPath(taskId)}`, { method: "PATCH", body: JSON.stringify({ status }) });
  return { task: cleanTask(data) };
}
async function moveTask(env: Env, accountId: string, input: { task_list_id: string; task_id: string; parent: string | null; previous: string | null }) {
  const data = await google(env, accountId, withQuery(`/tasks/v1/lists/${idPath(input.task_list_id)}/tasks/${idPath(input.task_id)}/move`, {
    parent: input.parent ?? undefined,
    previous: input.previous ?? undefined,
  }), { method: "POST" });
  return { task: cleanTask(data) };
}
async function deleteTask(env: Env, accountId: string, taskListId: string, taskId: string) {
  await google(env, accountId, `/tasks/v1/lists/${idPath(taskListId)}/tasks/${idPath(taskId)}`, { method: "DELETE" });
  return { ok: true, task_list_id: taskListId, task_id: taskId };
}
async function clearCompleted(env: Env, accountId: string, taskListId: string) {
  await google(env, accountId, `/tasks/v1/lists/${idPath(taskListId)}/clear`, { method: "POST" });
  return { ok: true, task_list_id: taskListId, hidden: true };
}
async function searchTasks(env: Env, accountId: string, input: { query: string; task_list_id?: string; include_completed: boolean }) {
  const needle = input.query.trim().toLowerCase();
  let lists: { id: string; title: string | null }[];
  let listsTruncated = false;
  if (input.task_list_id) {
    lists = [{ id: input.task_list_id, title: null }];
  } else {
    const page = await listTaskLists(env, accountId, undefined, 100);
    lists = page.task_lists.slice(0, SEARCH_LISTS).map((list) => ({
      id: String(list.id),
      title: typeof list.title === "string" ? list.title : null,
    }));
    listsTruncated = page.task_lists.length > SEARCH_LISTS || page.next_page_token != null;
  }
  const matches: Json[] = [];
  let scanned = 0;
  let tasksTruncated = false;
  const pageCap = input.task_list_id ? 5 : SEARCH_PAGES;
  for (const list of lists) {
    let token: string | undefined;
    for (let page = 0; page < pageCap; page++) {
      const result = await listTasks(env, accountId, {
        task_list_id: list.id,
        page_token: token,
        limit: 100,
        include_completed: input.include_completed,
        include_hidden: input.include_completed,
        include_deleted: false,
        include_assigned: false,
      });
      for (const task of result.tasks) {
        scanned++;
        const title = typeof task.title === "string" ? task.title : "";
        const notes = typeof task.notes === "string" ? task.notes : "";
        if (`${title}\n${notes}`.toLowerCase().includes(needle)) matches.push({ task_list_id: list.id, task_list_title: list.title, task });
      }
      if (matches.length >= SEARCH_MATCHES) {
        tasksTruncated = true;
        break;
      }
      if (!result.next_page_token) break;
      token = result.next_page_token;
      if (page === pageCap - 1) tasksTruncated = true;
    }
    if (matches.length >= SEARCH_MATCHES) break;
  }
  return { query: input.query.trim(), matches: matches.slice(0, SEARCH_MATCHES), scanned, truncated: listsTruncated || tasksTruncated };
}

const listTasksInput = z.object({
  task_list_id: resourceId.describe("Task list id from list_task_lists, or @default."),
  page_token: pageToken.describe("Pass next_page_token from the previous page."),
  limit: z.number().int().min(1).max(100).default(100),
  include_completed: z.boolean().default(false).describe("Include tasks whose status is completed. Tasks completed in the Google Tasks app also need include_hidden."),
  include_hidden: z.boolean().default(false).describe("Include tasks Google has marked hidden, including tasks completed in the Google Tasks app and tasks hidden by clear_completed."),
  include_deleted: z.boolean().default(false),
  include_assigned: z.boolean().default(false).describe("Include tasks assigned from Docs or Chat. An assigned task cannot be given a parent."),
  due_min: calendarDate.optional().describe("Inclusive calendar date, YYYY-MM-DD."),
  due_max: calendarDate.optional().describe("Inclusive calendar date, YYYY-MM-DD."),
  completed_min: calendarDate.optional(),
  completed_max: calendarDate.optional(),
  updated_min: calendarDate.optional(),
}).strict();
const createTaskInput = z.object({
  task_list_id: resourceId.describe("Task list id from list_task_lists, or @default."),
  title: taskTitle,
  notes: taskNotes.optional(),
  due: calendarDate.optional().describe("Calendar date YYYY-MM-DD. Google records the UTC date and discards the time of day. There is no time-of-day field."),
  status: z.enum(["needsAction", "completed"]).optional(),
  parent: resourceId.optional().describe("Parent task id, to create a subtask. Omit for a top-level task. Assigned tasks cannot be parents."),
  previous: resourceId.optional().describe("Sibling task id that should sit immediately before the new task. Omit to insert it first among its siblings."),
}).strict();
const updateTaskInput = z.object({
  task_list_id: resourceId,
  task_id: resourceId,
  title: taskTitle.optional(),
  notes: taskNotes.optional().describe("Replaces the notes. Pass an empty string to clear them."),
  due: calendarDate.optional().describe("Calendar date YYYY-MM-DD. Google records the UTC date and discards the time of day."),
  clear_due: z.boolean().optional().describe("Set true to remove the due date."),
  status: z.enum(["needsAction", "completed"]).optional(),
}).strict()
  .refine((obj) => obj.title != null || obj.notes != null || obj.due != null || obj.clear_due === true || obj.status != null, { message: "Provide a field to change" })
  .refine((obj) => !(obj.due != null && obj.clear_due === true), { message: "Pass either due or clear_due" });
const moveTaskInput = z.object({
  task_list_id: resourceId,
  task_id: resourceId,
  parent: resourceId.nullable().describe("New parent task id. null moves the task to the top level. Assigned tasks cannot be moved under a parent."),
  previous: resourceId.nullable().describe("Task id that should sit immediately before this one. null makes it first among its siblings."),
}).strict();
const searchInput = z.object({
  query: z.string().trim().min(1).max(200).describe("Case-insensitive match against the title and notes."),
  task_list_id: resourceId.optional().describe("Scan only this list, up to five pages. Without it, only the first 10 lists are scanned, two pages each."),
  include_completed: z.boolean().default(true),
}).strict();

function mcp(env: Env, accountId: string) {
  const server = new McpServer({ name: "tasks-gateway", version: "0.1.0" });
  const tool = (name: string, description: string, inputSchema: any, fn: (id: string, arg: any) => Promise<unknown>) => {
    server.registerTool(name, { description, inputSchema }, async (args: any) => {
      try {
        return { content: [{ type: "text" as const, text: JSON.stringify(await fn(accountId, args ?? {})) }] };
      } catch (e) { return { isError: true, content: [{ type: "text" as const, text: String(e) }] }; }
    });
  };
  server.registerTool("list_accounts", { description: "Show the Google account this token acts as.", inputSchema: {} }, async () => {
    try {
      return { content: [{ type: "text" as const, text: JSON.stringify(await vault(env).connection(accountId)) }] };
    } catch (e) { return { isError: true, content: [{ type: "text" as const, text: String(e) }] }; }
  });
  tool("list_task_lists", "List Google task lists (id, title, updated). Pass next_page_token back as page_token. Use @default with the task tools for the default list.", { page_token: pageToken, limit: z.number().int().min(1).max(100).default(100) },
    async (id, { page_token, limit }) => listTaskLists(env, id, page_token, limit));
  tool("get_task_list", "Get one task list by id, or @default.", { task_list_id: resourceId },
    async (id, { task_list_id }) => getTaskList(env, id, task_list_id));
  tool("create_task_list", "Create a task list. The title is the list name shown in Google Tasks.", { title: listTitle },
    async (id, { title }) => createTaskList(env, id, title));
  tool("rename_task_list", "Rename a task list.", { task_list_id: resourceId, title: listTitle },
    async (id, { task_list_id, title }) => renameTaskList(env, id, task_list_id, title));
  tool("delete_task_list", "DESTRUCTIVE: deletes the task list and every task on it. This cannot be undone. confirm_delete must be true.", { task_list_id: resourceId, confirm_delete: z.literal(true) },
    async (id, { task_list_id }) => deleteTaskList(env, id, task_list_id));
  tool("list_tasks", "List one page of tasks. Defaults to open tasks. Tasks are flat: a subtask has parent set to another task id. due is a calendar date. Pass next_page_token back as page_token. To see tasks completed in the Google Tasks app, set include_completed and include_hidden to true.", listTasksInput,
    async (id, input) => listTasks(env, id, input));
  tool("get_task", "Get one task by list id and task id.", { task_list_id: resourceId, task_id: resourceId },
    async (id, { task_list_id, task_id }) => getTask(env, id, task_list_id, task_id));
  tool("create_task", "Create a task. due is a calendar date YYYY-MM-DD; Google stores midnight UTC and ignores the time of day. parent creates a subtask. previous inserts it after that sibling. Omit previous to insert it first. Assigned tasks cannot be parents.", createTaskInput,
    async (id, input) => createTask(env, id, input));
  tool("update_task", "Change a task's title, notes, due date, or status. notes replaces the whole note; an empty string clears it. clear_due removes the date. due is a calendar date, and Google ignores the time of day. Use move_task to change parent or position.", updateTaskInput,
    async (id, input) => updateTask(env, id, input));
  tool("complete_task", "Mark a task completed. Google sets the completion time.", { task_list_id: resourceId, task_id: resourceId },
    async (id, { task_list_id, task_id }) => setStatus(env, id, task_list_id, task_id, "completed"));
  tool("reopen_task", "Mark a completed task as needsAction.", { task_list_id: resourceId, task_id: resourceId },
    async (id, { task_list_id, task_id }) => setStatus(env, id, task_list_id, task_id, "needsAction"));
  tool("move_task", "Move a task within its list. parent null puts it at the top level. previous null puts it first among its siblings. This cannot move a task to another list. Assigned tasks cannot be given a parent.", moveTaskInput,
    async (id, input) => moveTask(env, id, input));
  tool("delete_task", "DESTRUCTIVE: deletes one task. If the task was assigned from Docs or Chat, Google also deletes the original there. confirm_delete must be true. There is no undelete tool.", { task_list_id: resourceId, task_id: resourceId, confirm_delete: z.literal(true) },
    async (id, { task_list_id, task_id }) => deleteTask(env, id, task_list_id, task_id));
  tool("clear_completed", "Hides every completed task on this list. Google calls this clearing. The tasks are marked hidden and disappear from a normal list. They can still be returned with include_hidden true. confirm_clear must be true.", { task_list_id: resourceId, confirm_clear: z.literal(true) },
    async (id, { task_list_id }) => clearCompleted(env, id, task_list_id));
  tool("search_tasks", "Find tasks by a case-insensitive title or notes match. Google Tasks has no search API, so this reads tasks and filters them. Without task_list_id it scans the first 10 lists, two pages of 100 tasks each. With task_list_id it scans five pages of that list. truncated is true when more lists or tasks were not read. Matches stop at 40.", searchInput,
    async (id, input) => searchTasks(env, id, input));
  return server;
}
function secretEquals(supplied: string, key: string): boolean {
  if (!supplied || !key) return false;
  const limit = 4096;
  let diff = supplied.length ^ key.length;
  if (supplied.length > limit || key.length > limit) diff |= 1;
  for (let i = 0; i < limit; i++) diff |= supplied.charCodeAt(i) ^ key.charCodeAt(i);
  return diff === 0;
}
function bearerToken(request: Request): string {
  const header = request.headers.get("Authorization") || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}
async function authenticated(request: Request, env: Env): Promise<string | null> {
  const supplied = bearerToken(request);
  if (!supplied) return null;
  return vault(env).sessionUser(supplied);
}
function wwwAuthenticate(origin: string, supplied: boolean): string {
  const metadata = `${origin}/.well-known/oauth-protected-resource/mcp`;
  const parts = [`resource_metadata="${metadata}"`];
  if (supplied) parts.push(`error="invalid_token"`, `error_description="The access token is missing, expired, or invalid"`);
  return `Bearer ${parts.join(", ")}`;
}
function unauthorized(request: Request): Response {
  const supplied = bearerToken(request).length > 0;
  let header = "Bearer";
  try { header = wwwAuthenticate(publicOrigin(new URL(request.url).origin), supplied); } catch { /* Keep a bare challenge when the origin is not a valid callback origin. */ }
  return Response.json({ error: "unauthorized" }, { status: 401, headers: { "WWW-Authenticate": header, "Cache-Control": "no-store" } });
}
function discoveryCors(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Cache-Control", "no-store");
  return new Response(response.body, { status: response.status, headers });
}
function oauthJson(body: unknown, status = 200): Response {
  return discoveryCors(Response.json(body, { status }));
}
function preflight(): Response {
  return discoveryCors(new Response(null, { status: 204 }));
}
function oauthFailure(parsed: unknown, status: number): string {
  const body = asObject(parsed);
  const code = typeof body?.error === "string" && /^[a-z0-9_]{1,40}$/.test(body.error) ? body.error : `HTTP ${status}`;
  const description = typeof body?.error_description === "string" && /^[\w .,'():-]{1,200}$/.test(body.error_description) ? body.error_description : "";
  return description ? `${code}: ${description}` : code;
}
function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[ch] ?? ch);
}
function page(title: string, body: string, status = 200): Response {
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.45;background:#fff;color:#1b1b1b}code{word-break:break-all}button,input{font:inherit}button{margin:0 .6rem .6rem 0;padding:.5rem .9rem;border:1px solid #1b1b1b;border-radius:.35rem;background:#1b1b1b;color:#fff;cursor:pointer}button.secondary{background:#fff;color:#1b1b1b}form{display:inline}</style><h1>${escapeHtml(title)}</h1>${body}</html>`;
  return new Response(html, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY" } });
}
function directVisit(request: Request): boolean {
  const site = request.headers.get("Sec-Fetch-Site");
  return site === "none" || site === "same-origin";
}
function allowedStart(request: Request, origin: string): boolean {
  if (request.headers.get("Sec-Fetch-Site") === "cross-site") return false;
  const header = request.headers.get("Origin");
  return header === origin;
}
function connectForm(): string {
  return `<p>Continue only if this is the Google account the gateway should use for Tasks. Connecting a different account is refused while one is already stored.</p><form method="post" action="/oauth/start"><button type="submit">Continue to Google</button></form>`;
}
function redirect(location: string): Response {
  return new Response(null, { status: 303, headers: { Location: location, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
}
async function startOAuth(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.method !== "GET" && request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, POST" } });
  let origin: string;
  try { origin = publicOrigin(url.origin); } catch (e) { return page("Connect Google Tasks", `<p>${escapeHtml(e instanceof Error ? e.message : "OAuth callback requires HTTPS")}</p>`, 400); }
  if (request.method === "GET" && !directVisit(request)) return page("Connect Google Tasks", connectForm());
  if (request.method === "POST" && !allowedStart(request, origin)) return page("Connect Google Tasks", `<p>Submit this confirmation in the browser.</p>${connectForm()}`, 403);
  try {
    return redirect(await vault(env).beginConnect(origin));
  } catch (e) {
    return page("Could not start Google authorization", `<p>${escapeHtml(e instanceof Error ? e.message : "Authorization could not be started.")}</p>`, 502);
  }
}
function connectedRedirect(origin: string, ticket: string): Response {
  const done = new URL(callbackUrl(origin));
  done.pathname = "/oauth/connected";
  done.searchParams.set("ticket", ticket);
  return redirect(done.toString());
}
async function finishOAuth(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET" } });
  const denied = url.searchParams.get("error");
  const outcome = denied
    ? await vault(env).denyConnect(url.searchParams.get("state") ?? "")
    : await vault(env).finishConnect(url.searchParams.get("code") ?? "", url.searchParams.get("state") ?? "");
  if ("redirect" in outcome) return redirect(outcome.redirect);
  if ("ticket" in outcome) return connectedRedirect(url.origin, outcome.ticket);
  const ticket = await vault(env).failNotice(outcome.error);
  if (!ticket) return page("Google Tasks was not connected", `<p>Google authorization failed.</p><p><a href="/oauth/start">Try again</a></p>`, 400);
  return connectedRedirect(url.origin, ticket);
}
function connectedUser(user: LinkedAccount): string {
  if (user.email) return `<strong>${escapeHtml(user.email)}</strong>`;
  return `Google account <strong>${escapeHtml(user.id)}</strong>`;
}
async function connectedPage(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET" } });
  const notice = await vault(env).takeNotice(url.searchParams.get("ticket") ?? "");
  if (!notice) return page("Google Tasks", `<p>This connection attempt has expired. Start again at <a href="/oauth/start">/oauth/start</a>.</p>`, 404);
  if (!notice.ok) return page("Google Tasks was not connected", `<p>${escapeHtml(notice.message)}</p><p><a href="/oauth/start">Try again</a></p>`, 400);
  const who = notice.user ? connectedUser(notice.user) : "the approving Google account";
  const limit = maxAccounts(env);
  const room = limit > 1
    ? `Up to ${limit} Google accounts can be connected. Each one gets a separate Grokbot token. Connecting the same account again refreshes that account's grant.`
    : "One Google account can be connected. Connecting it again refreshes that grant.";
  return page("Google Tasks connected", `<p>This gateway will use ${who}.</p><p>You can close this page. ${room}</p>`);
}
const handlerFor = (env: Env, accountId: string) => createMcpHandler(() => mcp(env, accountId), { route: "/mcp", corsOptions: false, responseMode: "json" });

function metadata(origin: string): { resource: Record<string, unknown>; authorization: Record<string, unknown> } {
  const authorization: Record<string, unknown> = {
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint: `${origin}/revoke`,
    revocation_endpoint_auth_methods_supported: ["none"],
    registration_endpoint: `${origin}/register`,
    scopes_supported: [MCP_SCOPE],
  };
  return {
    resource: { resource: `${origin}/mcp`, authorization_servers: [origin], bearer_methods_supported: ["header"], scopes_supported: [MCP_SCOPE] },
    authorization,
  };
}
function discovery(request: Request, url: URL): Response {
  if (request.method === "OPTIONS") return preflight();
  if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET" } });
  let origin: string;
  try { origin = publicOrigin(url.origin); } catch (e) { return oauthJson({ error: e instanceof Error ? e.message : "invalid origin" }, 400); }
  const documents = metadata(origin);
  if (url.pathname === "/.well-known/oauth-authorization-server") return oauthJson(documents.authorization);
  return oauthJson(documents.resource);
}
async function authorize(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.method === "OPTIONS") return preflight();
  let origin: string;
  try { origin = publicOrigin(url.origin); } catch (e) { return page("Connect Google Tasks", `<p>${escapeHtml(e instanceof Error ? e.message : "OAuth callback requires HTTPS")}</p>`, 400); }
  if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers: { Allow: "GET" } });
  try {
    const started = await vault(env).beginMcpAuthorization({
      origin,
      clientId: url.searchParams.get("client_id") ?? "",
      redirectUri: url.searchParams.get("redirect_uri") ?? "",
      responseType: url.searchParams.get("response_type") ?? "",
      codeChallenge: url.searchParams.get("code_challenge") ?? "",
      codeChallengeMethod: url.searchParams.get("code_challenge_method") ?? "",
      clientState: url.searchParams.get("state") ?? "",
      resource: url.searchParams.get("resource"),
    });
    if ("redirect" in started) return redirect(started.redirect);
    return redirect(await vault(env).approveMcp(origin, started.id));
  } catch (e) {
    return page("Could not start sign-in", `<p>${escapeHtml(e instanceof Error ? e.message : "Sign-in could not be started.")}</p>`, 400);
  }
}
async function registerClient(request: Request): Promise<Response> {
  if (request.method === "OPTIONS") return preflight();
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "POST" } });
  const type = request.headers.get("Content-Type") || "";
  if (!type.includes("application/json")) return oauthJson({ error: "invalid_client_metadata" }, 400);
  let body: Json | null;
  try {
    const text = await request.text();
    if (text.length > 16_000) return oauthJson({ error: "invalid_client_metadata" }, 400);
    body = asObject(JSON.parse(text));
  } catch {
    return oauthJson({ error: "invalid_client_metadata" }, 400);
  }
  const uris = body?.redirect_uris;
  const sent = Array.isArray(uris) ? uris.filter((uri): uri is string => typeof uri === "string") : [];
  const accepted = sent.filter((uri) => grokRedirect(uri));
  const listed = Array.isArray(uris) && uris.length >= 1 && uris.length <= 8 && sent.length === uris.length && sent.length === accepted.length;
  if (!listed) {
    const logged = sent.map((uri) => uri.slice(0, 300));
    console.log(JSON.stringify({ registration: "invalid_redirect_uri", redirect_uris: logged }));
    return oauthJson({ error: "invalid_redirect_uri", error_description: logged.length ? `Unrecognized redirect_uris: ${logged.join(", ")}` : "redirect_uris must be a list of allowed callbacks" }, 400);
  }
  const authMethod = body?.token_endpoint_auth_method;
  if (authMethod != null && authMethod !== "none") return oauthJson({ error: "invalid_client_metadata" }, 400);
  const grants = body?.grant_types;
  if (grants != null && (!Array.isArray(grants) || grants.some((grant) => grant !== "authorization_code" && grant !== "refresh_token"))) {
    return oauthJson({ error: "invalid_client_metadata" }, 400);
  }
  const responses = body?.response_types;
  if (responses != null && (!Array.isArray(responses) || responses.some((response) => response !== "code"))) {
    return oauthJson({ error: "invalid_client_metadata" }, 400);
  }
  return oauthJson({
    client_id: GROK_CLIENT_ID,
    client_name: "Grok Bot",
    redirect_uris: accepted,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    scope: MCP_SCOPE,
  }, 201);
}
async function mcpToken(request: Request, env: Env): Promise<Response> {
  if (request.method === "OPTIONS") return preflight();
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "POST" } });
  const type = request.headers.get("Content-Type") || "";
  const params = new URLSearchParams();
  try {
    if (type.includes("application/json")) {
      const text = await request.text();
      if (text.length > 16_000) return oauthJson({ error: "invalid_request" }, 400);
      const body = asObject(JSON.parse(text));
      for (const [key, value] of Object.entries(body ?? {})) if (typeof value === "string") params.set(key, value);
    } else {
      const text = await request.text();
      if (text.length > 16_000) return oauthJson({ error: "invalid_request" }, 400);
      for (const [key, value] of new URLSearchParams(text)) params.set(key, value);
    }
  } catch {
    return oauthJson({ error: "invalid_request" }, 400);
  }
  const granted = await vault(env).grantMcp({
    grantType: params.get("grant_type") ?? "",
    code: params.get("code") ?? "",
    redirectUri: params.get("redirect_uri") ?? "",
    clientId: params.get("client_id") ?? "",
    verifier: params.get("code_verifier") ?? "",
    refreshToken: params.get("refresh_token") ?? "",
  });
  if ("error" in granted) return oauthJson({ error: granted.error }, 400);
  return oauthJson(granted);
}
async function revokeToken(request: Request, env: Env): Promise<Response> {
  if (request.method === "OPTIONS") return preflight();
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: { Allow: "POST" } });
  const params = new URLSearchParams();
  try {
    const type = request.headers.get("Content-Type") || "";
    const text = await request.text();
    if (text.length <= 16_000) {
      if (type.includes("application/json")) {
        const body = asObject(JSON.parse(text));
        for (const [key, value] of Object.entries(body ?? {})) if (typeof value === "string") params.set(key, value);
      } else {
        for (const [key, value] of new URLSearchParams(text)) params.set(key, value);
      }
    }
  } catch { /* An unreadable body revokes nothing. The response stays empty. */ }
  await vault(env).revokePresented(params.get("token") ?? "", params.get("client_id") ?? "");
  return discoveryCors(new Response(null, { status: 200 }));
}
function discoveryPath(pathname: string): boolean {
  return pathname === "/.well-known/oauth-protected-resource"
    || pathname === "/.well-known/oauth-protected-resource/mcp"
    || pathname === "/.well-known/oauth-authorization-server";
}
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health") return Response.json({ ok: true });
    if (discoveryPath(url.pathname)) return discovery(request, url);
    if (url.pathname === "/authorize") return authorize(request, env, url);
    if (url.pathname === "/register") return registerClient(request);
    if (url.pathname === "/token") return mcpToken(request, env);
    if (url.pathname === "/revoke") return revokeToken(request, env);
    if (url.pathname === "/oauth/start") return startOAuth(request, env, url);
    if (url.pathname === "/oauth/callback") return finishOAuth(request, env, url);
    if (url.pathname === "/oauth/connected") return connectedPage(request, env, url);
    const accountId = await authenticated(request, env);
    if (!accountId) return unauthorized(request);
    if (url.pathname === "/oauth/status" && request.method === "GET") return Response.json(await vault(env).connection(accountId), { headers: { "Cache-Control": "no-store" } });
    if (url.pathname === "/mcp") return handlerFor(env, accountId)(request, env, ctx);
    return Response.json({ error: "not_found" }, { status: 404 });
  }
} satisfies ExportedHandler<Env>;
