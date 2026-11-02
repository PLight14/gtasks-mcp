// Tasks completed in the Google Tasks app are hidden. Both flags are required or those completions never appear.
export const MONITOR_TASK_QUERY = {
  task_list_id: "@default",
  limit: 100,
  include_completed: true,
  include_hidden: true,
  include_deleted: true,
  include_assigned: false,
} as const;

export const MONITOR_MAX_PAGES = 20;
export const MONITOR_BATCH = 10;

export type MonitorAccount = { id: string; email: string | null };
export type MonitorCursor = { since: number; sent: { id: string; updated: string }[] };
export type MonitorTask = { id: string; updated: string | null } & Record<string, unknown>;
export type MonitorBody = {
  source: "google-tasks";
  task_list_id: typeof MONITOR_TASK_QUERY.task_list_id;
  account: MonitorAccount;
  tasks: Record<string, unknown>[];
};
export type MonitorReport = {
  skipped: "webhook" | "account" | null;
  baselined: number;
  postedTasks: number;
  held: number;
  idle: number;
};
export type MonitorRun = {
  at: number;
  skipped: "webhook" | "account" | null;
  baselined: number;
  postedTasks: number;
  held: number;
  idle: number;
  failed: boolean;
};
export type MonitorStatus = {
  last_run_at: string | null;
  result: "checked" | "skipped" | "failed" | null;
  reason: "webhook" | "account" | null;
  baselined: number;
  posted_tasks: number;
  held: number;
  idle: number;
};
export type MonitorDeps = {
  now: number;
  webhookUrl: string;
  webhookKey: string;
  maxPages?: number;
  accounts: () => Promise<MonitorAccount[]>;
  loadCursor: (accountId: string) => Promise<unknown>;
  saveCursor: (accountId: string, cursor: MonitorCursor) => Promise<void>;
  listPage: (accountId: string, updatedMin: string, pageToken?: string) => Promise<{ tasks: MonitorTask[]; next_page_token: string | null }>;
  postWebhook: (body: MonitorBody) => Promise<boolean>;
};

export function googleUpdatedMin(input: { updated_min?: string; updated_min_rfc3339?: string }): string | undefined {
  if (input.updated_min_rfc3339) return input.updated_min_rfc3339;
  if (input.updated_min) return `${input.updated_min}T00:00:00.000Z`;
  return undefined;
}

export function grokWebhookUrl(value: string): string | null {
  let url: URL;
  try { url = new URL(value.trim()); } catch { return null; }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return null;
  if (url.hostname !== "api2.cursor.sh") return null;
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length !== 3 || parts[0] !== "automations" || parts[1] !== "webhook" || !/^[A-Za-z0-9_-]{1,200}$/.test(parts[2])) return null;
  return `${url.origin}/${parts.join("/")}`;
}

export function webhookKey(value: string): string | null {
  const key = value.trim().replace(/^Bearer\s+/i, "").trim();
  if (key.length < 8 || /[\u0000-\u001f\s]/.test(key)) return null;
  return key;
}

export function webhookAccepted(status: number, redirected: boolean): boolean {
  return status === 200 && !redirected;
}

export function parseCursor(value: unknown): MonitorCursor | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as { since?: unknown; sent?: unknown };
  if (typeof record.since !== "number" || !Number.isFinite(record.since) || !Array.isArray(record.sent)) return null;
  const sent: MonitorCursor["sent"] = [];
  for (const item of record.sent) {
    if (!item || typeof item !== "object" || Array.isArray(item)) return null;
    const entry = item as { id?: unknown; updated?: unknown };
    if (typeof entry.id !== "string" || !entry.id || typeof entry.updated !== "string" || !entry.updated) return null;
    sent.push({ id: entry.id, updated: entry.updated });
  }
  return { since: record.since, sent };
}

function wholeCount(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

export function parseMonitorRun(value: unknown): MonitorRun | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Partial<MonitorRun>;
  const baselined = wholeCount(record.baselined);
  const postedTasks = wholeCount(record.postedTasks);
  const held = wholeCount(record.held);
  const idle = wholeCount(record.idle);
  const skipped = record.skipped === null || record.skipped === "webhook" || record.skipped === "account" ? record.skipped : undefined;
  if (typeof record.at !== "number" || !Number.isFinite(record.at) || skipped === undefined || record.failed !== true && record.failed !== false) return null;
  if (baselined == null || postedTasks == null || held == null || idle == null) return null;
  return { at: record.at, skipped, baselined, postedTasks, held, idle, failed: record.failed };
}

export function monitorStatus(run: MonitorRun | null): MonitorStatus {
  if (!run) return { last_run_at: null, result: null, reason: null, baselined: 0, posted_tasks: 0, held: 0, idle: 0 };
  const result = run.failed ? "failed" : run.skipped ? "skipped" : "checked";
  return {
    last_run_at: new Date(run.at).toISOString(),
    result,
    reason: run.skipped,
    baselined: run.baselined,
    posted_tasks: run.postedTasks,
    held: run.held,
    idle: run.idle,
  };
}

const WEBHOOK_TASK_FIELDS = ["id", "title", "status", "due", "deleted", "completed"] as const;

function webhookTask(task: MonitorTask): Record<string, unknown> {
  const posted: Record<string, unknown> = {};
  for (const field of WEBHOOK_TASK_FIELDS) posted[field] = task[field] ?? null;
  return posted;
}

function versionKey(id: string, updated: string): string {
  return `${id}\0${updated}`;
}

export function changesToSend<T extends { id: string; updated: string | null }>(tasks: T[], cursor: MonitorCursor): T[] {
  const seen = new Set(cursor.sent.map((item) => versionKey(item.id, item.updated)));
  return tasks.filter((task) => typeof task.updated !== "string" || !task.updated || !seen.has(versionKey(task.id, task.updated)));
}

function atBoundary(updated: string | null, since: number): updated is string {
  if (!updated) return false;
  const ms = Date.parse(updated);
  return Number.isFinite(ms) && ms >= since;
}

function updatedMillis(updated: string | null): number {
  if (!updated) return Number.NEGATIVE_INFINITY;
  const ms = Date.parse(updated);
  return Number.isFinite(ms) ? ms : Number.NEGATIVE_INFINITY;
}

export function batchForWebhook<T extends { id: string; updated: string | null }>(tasks: T[]): { batch: T[]; truncated: boolean } {
  const sorted = [...tasks].sort((a, b) => updatedMillis(a.updated) - updatedMillis(b.updated));
  return { batch: sorted.slice(0, MONITOR_BATCH), truncated: sorted.length > MONITOR_BATCH };
}

export function cursorAfterBatch(previous: MonitorCursor, pollStartedAt: number, batch: { id: string; updated: string | null }[], truncated: boolean): MonitorCursor {
  if (!truncated) return advanceCursor(previous, pollStartedAt, batch);
  const latest = batch.reduce((max, task) => Math.max(max, updatedMillis(task.updated)), Number.NEGATIVE_INFINITY);
  if (!Number.isFinite(latest)) return previous;
  return advanceCursor(previous, latest, batch);
}

export function advanceCursor(previous: MonitorCursor, pollStartedAt: number, delivered: { id: string; updated: string | null }[]): MonitorCursor {
  const since = Math.max(previous.since, pollStartedAt);
  const sent = new Map<string, { id: string; updated: string }>();
  for (const item of [...previous.sent, ...delivered]) {
    if (!atBoundary(item.updated, since)) continue;
    sent.set(versionKey(item.id, item.updated), { id: item.id, updated: item.updated });
  }
  return { since, sent: [...sent.values()] };
}

async function collectPages(deps: MonitorDeps, accountId: string, updatedMin: string, maxPages: number): Promise<{ complete: true; tasks: MonitorTask[] } | { complete: false }> {
  const tasks: MonitorTask[] = [];
  const seenTokens = new Set<string>();
  let pageToken: string | undefined;
  for (let page = 0; page < maxPages; page++) {
    const result = await deps.listPage(accountId, updatedMin, pageToken);
    for (const item of result.tasks) {
      if (item && typeof item.id === "string" && item.id) tasks.push(item);
    }
    const next = result.next_page_token;
    if (!next) return { complete: true, tasks };
    if (seenTokens.has(next)) return { complete: false };
    seenTokens.add(next);
    pageToken = next;
    if (page === maxPages - 1) return { complete: false };
  }
  return { complete: false };
}

export async function runMonitor(deps: MonitorDeps): Promise<MonitorReport> {
  const report: MonitorReport = { skipped: null, baselined: 0, postedTasks: 0, held: 0, idle: 0 };
  if (!grokWebhookUrl(deps.webhookUrl) || !webhookKey(deps.webhookKey)) {
    report.skipped = "webhook";
    return report;
  }
  const accounts = await deps.accounts();
  if (accounts.length === 0) {
    report.skipped = "account";
    return report;
  }
  const maxPages = deps.maxPages ?? MONITOR_MAX_PAGES;
  for (const account of accounts) {
    const current = parseCursor(await deps.loadCursor(account.id));
    if (!current) {
      await deps.saveCursor(account.id, { since: deps.now, sent: [] });
      report.baselined++;
      continue;
    }
    let tasks: MonitorTask[];
    try {
      const collected = await collectPages(deps, account.id, new Date(current.since).toISOString(), maxPages);
      if (!collected.complete) {
        report.held++;
        continue;
      }
      tasks = collected.tasks;
    } catch {
      report.held++;
      continue;
    }
    const ready = changesToSend(tasks, current);
    const { batch, truncated } = batchForWebhook(ready);
    if (batch.length === 0) {
      await deps.saveCursor(account.id, advanceCursor(current, deps.now, []));
      report.idle++;
      continue;
    }
    let accepted = false;
    try {
      accepted = await deps.postWebhook({
        source: "google-tasks",
        task_list_id: MONITOR_TASK_QUERY.task_list_id,
        account,
        tasks: batch.map(webhookTask),
      });
    } catch {
      accepted = false;
    }
    if (!accepted) {
      report.held++;
      continue;
    }
    await deps.saveCursor(account.id, cursorAfterBatch(current, deps.now, batch, truncated));
    report.postedTasks += batch.length;
  }
  return report;
}
