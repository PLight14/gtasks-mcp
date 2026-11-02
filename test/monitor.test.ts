import assert from "node:assert/strict";
import { test } from "node:test";
import {
  MONITOR_TASK_QUERY,
  advanceCursor,
  changesToSend,
  googleUpdatedMin,
  grokWebhookUrl,
  monitorStatus,
  parseCursor,
  parseMonitorRun,
  runMonitor,
  webhookAccepted,
  webhookKey,
  type MonitorCursor,
  type MonitorDeps,
  type MonitorTask,
} from "../src/monitor.ts";

const NOW = Date.parse("2026-11-02T19:00:00.000Z");
const SINCE = Date.parse("2026-11-02T18:00:00.000Z");
const SINCE_ISO = "2026-11-02T18:00:00.000Z";

function cursor(sent: MonitorCursor["sent"] = []): MonitorCursor {
  return { since: SINCE, sent };
}

function task(partial: Record<string, unknown> & { id: string; updated: string | null }): MonitorTask {
  return {
    title: "Buy milk",
    notes: "",
    status: "needsAction",
    hidden: false,
    deleted: false,
    ...partial,
  };
}

function harness(overrides: Partial<MonitorDeps> = {}): MonitorDeps & { saved: MonitorCursor[]; posted: unknown[] } {
  const saved: MonitorCursor[] = [];
  const posted: unknown[] = [];
  const deps: MonitorDeps & { saved: MonitorCursor[]; posted: unknown[] } = {
    now: NOW,
    webhookUrl: "https://api2.cursor.sh/automations/webhook/routine123",
    webhookKey: "crsr_example_key",
    accounts: async () => [{ id: "100", email: "ada@example.com" }],
    loadCursor: async () => cursor(),
    saveCursor: async (_accountId, next) => { saved.push(next); },
    listPage: async () => ({ tasks: [], next_page_token: null }),
    postWebhook: async (body) => { posted.push(body); return true; },
    saved,
    posted,
    ...overrides,
  };
  return deps;
}

test("monitor query includes completed, hidden, and deleted tasks", () => {
  assert.equal(MONITOR_TASK_QUERY.task_list_id, "@default");
  assert.equal(MONITOR_TASK_QUERY.include_completed, true);
  assert.equal(MONITOR_TASK_QUERY.include_hidden, true);
  assert.equal(MONITOR_TASK_QUERY.include_deleted, true);
  assert.equal(MONITOR_TASK_QUERY.limit, 100);
});

test("a full timestamp is sent to Google unchanged", () => {
  assert.equal(googleUpdatedMin({ updated_min_rfc3339: "2026-11-02T18:00:00.000Z" }), "2026-11-02T18:00:00.000Z");
  assert.equal(googleUpdatedMin({ updated_min: "2026-11-02" }), "2026-11-02T00:00:00.000Z");
  assert.equal(googleUpdatedMin({}), undefined);
});

test("webhook url and key are accepted only for a Grok routine", () => {
  assert.equal(grokWebhookUrl(" https://api2.cursor.sh/automations/webhook/routine123 "), "https://api2.cursor.sh/automations/webhook/routine123");
  assert.equal(grokWebhookUrl("http://api2.cursor.sh/automations/webhook/routine123"), null);
  assert.equal(grokWebhookUrl("https://user:pw@api2.cursor.sh/automations/webhook/routine123"), null);
  assert.equal(grokWebhookUrl("https://example.com/automations/webhook/routine123"), null);
  assert.equal(grokWebhookUrl("https://api2.cursor.sh/automations/webhook/routine123?x=1"), null);
  assert.equal(webhookKey(" Bearer crsr_example_key "), "crsr_example_key");
  assert.equal(webhookKey("short"), null);
  assert.equal(webhookAccepted(200, false), true);
  assert.equal(webhookAccepted(400, false), false);
  assert.equal(webhookAccepted(200, true), false);
});

test("a stored cursor rejects a missing timestamp", () => {
  assert.deepEqual(parseCursor({ since: SINCE, sent: [{ id: "t1", updated: SINCE_ISO }] }), cursor([{ id: "t1", updated: SINCE_ISO }]));
  assert.equal(parseCursor({ sent: [] }), null);
  assert.equal(parseCursor(null), null);
});

test("the same task version is not sent twice, and a newer version is", () => {
  const previous = cursor([{ id: "same", updated: SINCE_ISO }]);
  const tasks = [
    task({ id: "same", updated: SINCE_ISO, status: "completed", hidden: true }),
    task({ id: "same", updated: "2026-11-02T18:30:00.000Z", status: "completed", hidden: true }),
    task({ id: "fresh", updated: "2026-11-02T18:40:00.000Z", status: "completed", hidden: true, deleted: false }),
  ];
  const chosen = changesToSend(tasks, previous);
  assert.deepEqual(chosen.map((item) => item.id + "@" + item.updated), [
    "same@2026-11-02T18:30:00.000Z",
    "fresh@2026-11-02T18:40:00.000Z",
  ]);
});

test("the next cursor keeps only versions at the new boundary", () => {
  const next = advanceCursor(cursor([{ id: "old", updated: SINCE_ISO }]), NOW, [
    task({ id: "earlier", updated: "2026-11-02T18:30:00.000Z" }),
    task({ id: "boundary", updated: "2026-11-02T19:00:00.000Z" }),
  ]);
  assert.deepEqual(next, { since: NOW, sent: [{ id: "boundary", updated: "2026-11-02T19:00:00.000Z" }] });
});

test("an unconfigured webhook does not read tasks or record a start time", async () => {
  let listed = false;
  let accounts = false;
  const deps = harness({
    webhookUrl: "",
    accounts: async () => { accounts = true; return []; },
    listPage: async () => { listed = true; return { tasks: [], next_page_token: null }; },
  });
  const report = await runMonitor(deps);
  assert.deepEqual(report, { skipped: "webhook", baselined: 0, postedTasks: 0, held: 0, idle: 0 });
  assert.equal(accounts, false);
  assert.equal(listed, false);
  assert.equal(deps.saved.length, 0);
});

test("no connected account does not record a start time", async () => {
  const deps = harness({ accounts: async () => [] });
  const report = await runMonitor(deps);
  assert.equal(report.skipped, "account");
  assert.equal(deps.saved.length, 0);
  assert.equal(deps.posted.length, 0);
});

test("the first check records the start time and sends nothing", async () => {
  let listed = false;
  const deps = harness({
    loadCursor: async () => null,
    listPage: async () => { listed = true; return { tasks: [], next_page_token: null }; },
  });
  const report = await runMonitor(deps);
  assert.equal(report.baselined, 1);
  assert.equal(listed, false);
  assert.equal(deps.posted.length, 0);
  assert.deepEqual(deps.saved, [{ since: NOW, sent: [] }]);
});

test("a completed hidden task is posted as it is now", async () => {
  const completed = task({
    id: "done",
    updated: "2026-11-02T18:30:00.000Z",
    status: "completed",
    hidden: true,
    completed: "2026-11-02T18:30:00.000Z",
    title: "File taxes",
    notes: "secret details",
    due: "2026-11-02",
    web_view_link: "https://tasks.google.com/task/done",
    position: "0000000000000001",
    parent: "parent-task",
    links: [{ link: "https://example.com/extra" }],
  });
  let sawUpdatedMin = "";
  const deps = harness({
    listPage: async (_accountId, updatedMin) => {
      sawUpdatedMin = updatedMin;
      return { tasks: [completed], next_page_token: null };
    },
  });
  const report = await runMonitor(deps);
  assert.equal(sawUpdatedMin, SINCE_ISO);
  assert.equal(report.postedTasks, 1);
  assert.equal(deps.posted.length, 1);
  const body = deps.posted[0] as { source: string; task_list_id: string; account: { email: string | null }; tasks: MonitorTask[] };
  assert.equal(body.source, "google-tasks");
  assert.equal(body.task_list_id, "@default");
  assert.equal(body.account.email, "ada@example.com");
  assert.deepEqual(body.tasks, [{
    id: "done",
    title: "File taxes",
    status: "completed",
    due: "2026-11-02",
    deleted: false,
    completed: "2026-11-02T18:30:00.000Z",
  }]);
  assert.equal(JSON.stringify(body).includes("secret details"), false);
  assert.equal(JSON.stringify(body).includes("example.com/extra"), false);
  assert.equal(JSON.stringify(body).includes("crsr_example_key"), false);
  assert.deepEqual(deps.saved, [{ since: NOW, sent: [] }]);
});

test("a check posts at most 10 tasks and continues from the latest one sent", async () => {
  const tasks = Array.from({ length: 12 }, (_, index) => {
    const minute = String(index + 1).padStart(2, "0");
    return task({ id: `t${minute}`, updated: `2026-11-02T18:${minute}:00.000Z`, title: `Task ${minute}` });
  });
  const deps = harness({
    listPage: async () => ({ tasks: [...tasks].reverse(), next_page_token: null }),
  });
  const report = await runMonitor(deps);
  assert.equal(report.postedTasks, 10);
  const body = deps.posted[0] as { tasks: { id: string }[] };
  assert.deepEqual(body.tasks.map((item) => item.id), tasks.slice(0, 10).map((item) => item.id));
  assert.equal(Object.hasOwn(body.tasks[0], "updated"), false);
  assert.deepEqual(deps.saved, [{
    since: Date.parse("2026-11-02T18:10:00.000Z"),
    sent: [{ id: "t10", updated: "2026-11-02T18:10:00.000Z" }],
  }]);
});

test("later pages are included and a repeated page token holds the cursor", async () => {
  const calls: (string | undefined)[] = [];
  const first = harness({
    listPage: async (_accountId, _updatedMin, pageToken) => {
      calls.push(pageToken);
      if (!pageToken) return { tasks: [task({ id: "a", updated: "2026-11-02T18:10:00.000Z" })], next_page_token: "page-2" };
      return { tasks: [task({ id: "b", updated: "2026-11-02T18:20:00.000Z", status: "completed", hidden: true })], next_page_token: null };
    },
  });
  const posted = await runMonitor(first);
  assert.deepEqual(calls, [undefined, "page-2"]);
  assert.equal(posted.postedTasks, 2);
  assert.deepEqual((first.posted[0] as { tasks: MonitorTask[] }).tasks.map((item) => item.id), ["a", "b"]);

  const stuck = harness({
    maxPages: 1,
    listPage: async () => ({ tasks: [task({ id: "a", updated: "2026-11-02T18:10:00.000Z" })], next_page_token: "more" }),
  });
  const held = await runMonitor(stuck);
  assert.equal(held.held, 1);
  assert.equal(held.postedTasks, 0);
  assert.equal(stuck.posted.length, 0);
  assert.equal(stuck.saved.length, 0);
});

test("a failed webhook leaves the cursor where it was", async () => {
  const deps = harness({
    listPage: async () => ({ tasks: [task({ id: "a", updated: "2026-11-02T18:10:00.000Z", status: "completed", hidden: true })], next_page_token: null }),
    postWebhook: async (body) => { deps.posted.push(body); return false; },
  });
  const report = await runMonitor(deps);
  assert.equal(report.held, 1);
  assert.equal(report.postedTasks, 0);
  assert.equal(deps.posted.length, 1);
  assert.equal(deps.saved.length, 0);
});

test("no changes move the cursor forward without calling the webhook", async () => {
  const deps = harness({
    loadCursor: async () => cursor([{ id: "same", updated: SINCE_ISO }]),
    listPage: async () => ({ tasks: [task({ id: "same", updated: SINCE_ISO })], next_page_token: null }),
  });
  const report = await runMonitor(deps);
  assert.equal(report.idle, 1);
  assert.equal(deps.posted.length, 0);
  assert.deepEqual(deps.saved, [{ since: NOW, sent: [] }]);
});

test("the status endpoint reports the last run time", () => {
  const checked = parseMonitorRun({ at: NOW, skipped: null, baselined: 0, postedTasks: 2, held: 0, idle: 0, failed: false });
  assert.deepEqual(monitorStatus(checked), {
    last_run_at: "2026-11-02T19:00:00.000Z",
    result: "checked",
    reason: null,
    baselined: 0,
    posted_tasks: 2,
    held: 0,
    idle: 0,
  });
  const skipped = parseMonitorRun({ at: NOW, skipped: "webhook", baselined: 0, postedTasks: 0, held: 0, idle: 0, failed: false });
  assert.equal(monitorStatus(skipped).result, "skipped");
  assert.equal(monitorStatus(skipped).reason, "webhook");
  const failed = parseMonitorRun({ at: NOW, skipped: null, baselined: 0, postedTasks: 0, held: 0, idle: 0, failed: true });
  assert.equal(monitorStatus(failed).result, "failed");
  assert.deepEqual(monitorStatus(null), {
    last_run_at: null,
    result: null,
    reason: null,
    baselined: 0,
    posted_tasks: 0,
    held: 0,
    idle: 0,
  });
  assert.equal(parseMonitorRun({ skipped: null }), null);
});

test("a list failure does not move the cursor", async () => {
  const deps = harness({
    listPage: async () => { throw new Error("Google Tasks 403"); },
  });
  const report = await runMonitor(deps);
  assert.equal(report.held, 1);
  assert.equal(deps.saved.length, 0);
  assert.equal(deps.posted.length, 0);
});
