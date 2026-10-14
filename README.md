# Google Tasks MCP gateway

Cloudflare Worker that exposes one Google account's Tasks to Grok Bot. The worker shape matches the Zendesk gateway: one Durable Object holds the Google grant, Grok Bot signs in through this worker's own OAuth endpoints, and `/mcp` is Streamable HTTP.

There is no static API key. A call to `/mcp` without a token gets `401` and the OAuth discovery challenge. Grok Bot registers at `/register`, then this worker sends the browser to Google.

## What you do in Google

Stay in one Cloud project the whole way. The project picker is in the top bar.

1. Open [Google Cloud Console](https://console.cloud.google.com/) and create a project, for example `Grok Tasks`.
2. Open [Google Tasks API](https://console.cloud.google.com/apis/library/tasks.googleapis.com) and click **Enable**.
3. Open [Google Auth Platform](https://console.cloud.google.com/auth/overview). If the console still shows the older name, use **APIs & Services → OAuth consent screen**.
4. Set the audience.
   - Personal Gmail: **External**.
   - A Google Workspace account, and your admin allows internal apps: **Internal**. Use this when you can. It skips the unverified-app warning and the seven-day testing limit.
5. Branding. App name `Grok Tasks` (you will see this name on Google's warning). User support email and developer contact: your email. Leave the logo empty. A logo starts a separate brand review.
6. Data access. Add only these scopes:
   - `https://www.googleapis.com/auth/tasks` (sensitive; create, edit, and delete tasks)
   - `openid`
   - `email` (`https://www.googleapis.com/auth/userinfo.email`)
   Do not add Gmail, Drive, or Calendar.
7. Deploy this worker once so you have a hostname. See [Deploy](#deploy). The redirect below has to be the real host.
8. [Create an OAuth client](https://console.cloud.google.com/auth/clients). Type: **Web application**. Name: `gtasks-mcp`. Authorized redirect URI, exactly:

   `https://<your-worker-host>/oauth/callback`

   No trailing slash. Leave Authorized JavaScript origins empty. Copy the client id and the client secret. Google shows the secret once.
9. Publish the app. On the Audience page, click **Publish app** so the status is **In production**.

   Leave it in **Testing** only if you are willing to reconnect every 7 days. In Testing, add your own Gmail under test users, and the refresh token dies seven days after consent.

   `tasks` is a sensitive scope. For a single personal account you do **not** submit the app for verification. Verification is what removes the warning and the 100-user cap. One account is inside that cap.

10. The first time you approve access, Google shows an unverified-app screen (External apps only):

    - **Advanced**
    - **Go to Grok Tasks (unsafe)**
    - Allow Tasks and email

    That warning is expected. This is your own project and your own account.

Replace `GOOGLE_CLIENT_ID` in `wrangler.toml` with the client id, then deploy again. Set the secret separately:

```bash
npx wrangler secret put GOOGLE_CLIENT_SECRET
```

## Deploy

Requires Node 20+.

```bash
npm install
npm run types
npm run typecheck
npm run deploy
```

`npm run dev` serves it locally. Put `GOOGLE_CLIENT_SECRET` in `.dev.vars` (see `.dev.vars.example`). The local redirect is `http://127.0.0.1:<port>/oauth/callback` or the localhost equivalent, and that exact URI has to be on the OAuth client too. Production should be the `https://…workers.dev/oauth/callback` URI.

`MAX_ACCOUNTS` defaults to `1`. Raising it above 1 allows that many distinct Google accounts, each with its own Grok Bot token, up to 10.

Point Grok Bot at `https://<your-worker-host>/mcp` with no bearer header. After Grok Bot's own approval, the worker opens Google. Approve while signed in as the account whose tasks this connection should use.

`GET /oauth/start` in a browser does the same Google consent without Grok Bot. A visit from another site stops on a confirmation step first.

## OAuth

Two logins are involved.

- **Grok Bot → this worker.** Public client, PKCE, client id `grokbot`. Access tokens last one hour. Refresh tokens last 30 days, and each refresh starts a new 30 days. `POST /revoke` with either token drops that login and revokes the Google grant. Redirects have no query string. HTTPS is limited to `cursor.com`, `www.cursor.com`, and `grok.com`, and the path must contain an `oauth` segment and end in `callback`. `grok.com` may also use `/connectors-oauth-exchange-code`. The custom scheme is only `cursor://anysphere.cursor-mcp/oauth/callback`. Loopback redirects are refused. A registration that also lists one is accepted without that URI.
- **This worker → Google.** Confidential Web client. The grant is stored in the Durable Object. Access tokens last about an hour and are refreshed five minutes early. Google does not rotate the refresh token on each refresh; if it returns a new one, that one is stored. Re-approving the same account replaces the grant and revokes the previous refresh token.

Google refresh tokens stay valid until you revoke them, the app stays in Testing (7 days), the token is unused for about 6 months, or you pass 100 refresh tokens for this client (the oldest is dropped). Publishing to production is what avoids the 7-day rule. It does not remove the unverified-app screen.

Rotating `GOOGLE_CLIENT_SECRET` drops stored grants. Approve again after that.

`GET /oauth/status` with a Grok Bot access token shows the connected account and the access-token expiry.

## Tools

`@default` is the default task list. `due` is a calendar date `YYYY-MM-DD`. Google records that UTC date and discards the time of day. In timezones behind UTC, the Tasks app can show the previous day.

- `list_accounts()`
- `list_task_lists(page_token?, limit?)`
- `get_task_list(task_list_id)`
- `create_task_list(title)`
- `rename_task_list(task_list_id, title)`
- `delete_task_list(task_list_id, confirm_delete=true)` deletes the list and every task on it
- `list_tasks(task_list_id, …)` defaults to open tasks. Set `include_completed` and `include_hidden` to see tasks completed in the Google Tasks app
- `get_task(task_list_id, task_id)`
- `create_task(task_list_id, title, notes?, due?, status?, parent?, previous?)`
- `update_task(task_list_id, task_id, …)` `clear_due` removes the date. An empty `notes` clears the note
- `complete_task(task_list_id, task_id)`
- `reopen_task(task_list_id, task_id)`
- `move_task(task_list_id, task_id, parent, previous)` `parent: null` is top level, `previous: null` is first among siblings. This stays inside one list
- `delete_task(task_list_id, task_id, confirm_delete=true)` if the task was assigned from Docs or Chat, Google deletes the original there too
- `clear_completed(task_list_id, confirm_clear=true)` hides completed tasks. It does not delete them. `include_hidden: true` still returns them
- `search_tasks(query, task_list_id?, include_completed?)` reads tasks and filters titles and notes. Without a list id it scans the first 10 lists, two pages of 100. With a list id it scans five pages. `truncated` means more was not read

A confirmation flag is not a human approval. The agent can pass `true` itself. Say so in the bot's instructions before it deletes a list, deletes a task, or clears completed tasks.

Subtasks come back in a flat list with `parent` set. Assigned tasks cannot be given a parent.

## REST

- `GET /.well-known/oauth-protected-resource/mcp` and `GET /.well-known/oauth-authorization-server`
- `POST /register`, `GET /authorize`, `POST /token`, `POST /revoke`
- `GET /oauth/start`, `GET /oauth/callback`, `GET /oauth/connected`
- `GET /oauth/status` requires the bearer token from `/token`
- `POST /mcp` requires that bearer token
- `GET /health`

## Notes

Reads retry `429` and `5xx`. Writes do not, because a lost response can arrive after Google has already applied the change. Task contents and tokens are not logged. `MCP_CLIENTS` is only for an app other than Grok Bot: a JSON list of `client_id`, `client_name`, and `redirect_uris`.
