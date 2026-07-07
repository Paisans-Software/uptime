# Code Review Fixes

Tracking doc for the security/logic fixes applied after the July 2026 code review.
Severity and status are updated as each item is addressed.

## HIGH

- [x] **Heartbeat token exposure to view-only users** — `heartbeat_token` was returned by
  the REST API (`GET /api/v1/sites`, `GET /api/v1/sites/:id`) and rendered on the site
  detail page for anyone with `view` access. Since `/ping/:token` is unauthenticated, a
  viewer could forge heartbeats. Now the token is only emitted to callers who can *manage*
  the monitor. (`src/routes/api.js`, `views/site-detail.ejs`)
- [x] **Telegram alerts break on `&`/`<`/`>`** — templates render into `parse_mode: HTML`
  without entity-escaping, so real URLs/errors produced HTTP 400 and the alert silently
  failed. Values are now HTML-escaped before interpolation. (`src/lib/channels.js`)
- [x] **Generic webhook sends malformed JSON** — `{{placeholders}}` were substituted into a
  JSON template with no escaping; the computed `jsonValid` flag was ignored. Placeholders
  are now JSON-escaped when the body parses as JSON, and invalid bodies are blocked.
  (`src/lib/channels.js`)
- [x] **2FA step had no rate-limit/lockout** — `complete2fa` never checked the lockout
  buckets, allowing unlimited TOTP/recovery guesses within the pending window. Added a
  `checkLocked` gate. (`src/auth.js`)
- [x] **Open redirect via `return_to`** — `startsWith('/')` allowed `//evil.com`. Bulk
  actions now route `return_to` through `safeReturnTo`. (`src/routes/sites.js`)
- [x] **Stored XSS via inline `confirm()` handlers** — HTML-escaped names decoded back to
  `'` inside the JS string, allowing `');alert(1)//`. Replaced with a safe `data-confirm`
  handler that reads the (attribute-escaped) message as text.
  (`views/settings-tags.ejs`, `views/settings-api-tokens.ejs`, `views/settings-account.ejs`,
  `public/js/modal.js`)
- [x] **Stored XSS via `javascript:` branding URL** — the footer credit URL was rendered
  into `href` unvalidated. URLs are now restricted to `http(s)`/relative. (`src/lib/branding.js`)

## MEDIUM

- [x] **Public badges ignored `status_page_excluded`** — hidden monitors leaked live state
  via `/badge/:id/*.svg`. Excluded monitors now return a neutral `not found` badge.
  (`src/routes/badge.js`)
- [x] **Heartbeat ping bodies visible to viewers** — captured job output was rendered for
  any `view` user. Now gated behind `canManage`. (`views/site-detail.ejs`)
- [x] **API error handler leaked `err.message`** — replaced with a generic message; details
  stay in server logs. (`src/routes/api.js`)
- [x] **P95 percentile off-by-one** — `floor(n*q)` overstated the tail (often == max).
  Switched to nearest-rank with `ceil`. (`src/lib/stats.js`)
- [x] **Web create/edit skipped strict validation** — `validateForApi` now runs on the form
  routes too, so invalid monitors are rejected consistently. (`src/routes/sites.js`)
- [x] **`tcp_port` defaulted to 1** — a missing/invalid port silently became port 1. Now
  left as `null` so validation rejects it. (`src/lib/sitePayload.js`)
- [x] **API `?state=paused` returned nothing** — filtered `current_state='paused'` (never a
  value). Now maps to `paused=1` and excludes paused rows from up/down/unknown filters.
  (`src/routes/api.js`)
- [x] **Viewer + `manage` grant silently ignored** — a `manage` grant on a `viewer` did
  nothing. The sharing/grants UIs now refuse to assign `manage` to viewers, keeping stored
  grants and enforcement consistent. (`src/routes/sites.js`, `src/routes/settings.js`)
- [x] **`ping` false-negatives + macOS `-W`** — unparseable output defaulted to 100% loss;
  `-W` units differ on BSD/macOS. Parsing is more tolerant and the timeout flag is chosen
  per platform. (`src/lib/ping.js`)
- [x] **RDAP non-200 bodies not drained** — undici connections leaked on 404/429/5xx and
  bootstrap errors. Bodies are now consumed. (`src/lib/whois.js`)
- [x] **Backup dropped tags** — export/import now round-trips tag names and associations.
  (`src/lib/backup.js`)
- [x] **Backup `replace` didn't restore heartbeat token** — the backup token is now written
  on replace. (`src/lib/backup.js`, `src/lib/sitePayload.js`)

## MONITOR LOGIC

- [x] **Heartbeat + `failure_threshold > 1` never opened an incident** — the watchdog only
  fed the *first* failure through `processResult`, so the counter stalled at 1. It now keeps
  processing failures until the threshold is reached and the incident opens. (`src/monitor.js`)
- [x] **Spurious "recovered" notifications** — recovery fired even when no incident was
  actually open (e.g. failures below threshold, or stale state after a restart).
  `closeOpenIncident` now signals whether an incident existed and recovery alerts only then.
  (`src/monitor.js`)
- [x] **New heartbeat monitors alerted DOWN within 15 s of creation** — "never pinged" now
  evaluates as *inconclusive* (state `unknown`) instead of down, so nobody gets paged before
  the cron job is even wired up. (`src/lib/checker.js`)
- [x] **Cert/domain expiry alert bands never reset after renewal** — once
  `*_alerted_at_days` was set, a renewed cert/domain suppressed most future expiry alerts.
  The band is now cleared whenever days-remaining climbs back above the warn window.
  (`src/monitor.js`)

## AUTH HARDENING

- [x] **Session fixation** — the session ID is now regenerated at login (both password-only
  and 2FA completion). Verified: cookie value changes across login. (`src/auth.js`)
- [x] **Weak default `SESSION_SECRET`** — the hardcoded `dev-secret-please-change` fallback
  is replaced by a random per-boot secret plus a boot warning. (`src/config.js`, `src/server.js`)

## MISC

- [x] **`HEARTBEAT_PINGS_RETENTION_DAYS` env name mismatch** — README documents the long
  name but config only read `HEARTBEAT_RETENTION_DAYS`; both are accepted now. (`src/config.js`)
- [x] **SQLite `isReadStatement` regex unanchored** — ` PRAGMA`/` EXPLAIN` anywhere in a
  statement (even in a string literal) classified a write as a read. Alternatives are now
  anchored to the statement start. (`src/drivers/sqlite.js`)
- [x] **More inline `confirm()` XSS sites found during the pass** — grant revoke on the site
  detail page and reset-password / disable-2FA / delete-user on the users page interpolated
  usernames into JS. All converted to `data-confirm`. (`views/site-detail.ejs`,
  `views/settings-users.ejs`)

## LOW

- [x] **Bulk delete orphaned `site_grants`** — bulk delete now cleans grants like single
  delete. (`src/routes/sites.js`)
- [x] **Email From display-name not escaped** — quotes/backslashes in the name are now
  escaped per RFC 5322. (`src/lib/email.js`)
- [x] **SMTP password couldn't be cleared via backup** — an explicit `smtp_pass: null` now
  clears it; only an absent field falls back to the stored value. (`src/lib/backup.js`)

## Validation — end-to-end smoke test (2026-07-07, SQLite, Node 22)

All checks passed against a live instance (`APP_DEBUG=true`, port 3005):

- Boot: schema + migrations apply, `/healthz` OK, no errors in the server log.
- Login: admin login works; **session ID changes across login** (fixation fix verified).
- Monitors: created active-HTTP, TCP and heartbeat monitors via the web form; invalid
  payloads (TCP without port, bad `check_type`) are **rejected with a flash error** instead
  of being silently persisted.
- Heartbeat: `/ping/:token` returns 200 and flips state to `up`; a monitor left past its
  grace window goes `down` (incident opened) and **recovers with the incident closed** on
  the next ping. A **freshly created heartbeat stays `unknown`** (previously alerted DOWN
  within 15 s).
- Token privacy: admin sees ping URLs + `heartbeat_token` (UI and API); a **viewer sees
  neither** — no ping URLs, no recent-pings table, `heartbeat_token` absent from
  `GET /api/v1/sites` and `GET /api/v1/sites/:id`.
- Grants: assigning `manage` to a viewer is coerced to `view` with a warning flash.
- Open redirect: bulk action with `return_to=//evil.com` redirects to `/`.
- Badges: `/badge/:id/status.svg` shows state normally and returns the neutral
  "not found" badge once `status_page_excluded` is set.
- API: `?state=paused` returns paused monitors; `?state=up` excludes them; create/patch
  round-trips tags; `/metrics` reports correct per-state counts.
- Notifications (dry-run): Telegram body correctly entity-escapes `&`, `<`, `>` in names,
  URLs and errors while keeping template tags; webhook body with quotes/newlines in
  variables renders **valid JSON** (`jsonValid: true`).
- Branding: storing `javascript:alert(1)` as the credit URL is rejected; the resolved URL
  falls back to the safe default.
- Backup: export includes per-monitor `tags`; import with `conflict=replace` **restores the
  original heartbeat token and tags** after both were wiped.
- Unit-level: P95 nearest-rank (`p95(1..100)=95`), RFC 5322 From-name escaping,
  login lockout after repeated failures, `ping 127.0.0.1` parses `0% loss`.

---

## Follow-up: status page query performance (2026-07-07)

**Problem** — With ~1 month of minute-level checks, `GET /status` re-aggregated the
entire `checks` window on every view: `dailyUptime(90d)` + `uptimePct(24h)` +
`lastCheck` per monitor. At 8 monitors that is ~1M rows scanned per page load
(~340 ms of pure query time on SQLite; worse on MySQL over the wire), and every
row required a table lookup because the old index `(site_id, checked_at)` did not
cover `is_up`.

**Fixes** (`src/lib/stats.js`, `src/routes/status.js`, `sql/schema.*.sql`,
`src/lib/migrations.js`):

1. **Covering index** — replaced `idx_checks_site_time (site_id, checked_at)` with
   `idx_checks_site_time_up (site_id, checked_at, is_up)`. The uptime %, daily-uptime
   and timeseries aggregates now run as index-only scans. Applied idempotently by a
   migration on next boot (new index created, redundant old one dropped).
2. **Daily-bucket memoization** — completed UTC days are immutable, so `dailyUptime`
   now caches per-day aggregates in memory (keyed by site + UTC date + window) and
   only queries *today's* bucket live. First view of a day pays the full scan once;
   every later view is a single small index range per monitor. Cache is invalidated
   on site delete (single, bulk, API).
3. **Batched 24h uptime** — the status page now fetches 24h uptime for all monitors
   in one `GROUP BY site_id` query instead of one query per monitor.

**Measured** (SQLite, 8 monitors × 90 days × 1 check/min = 1,036,800 rows):

| | before | after |
|---|---|---|
| status page data, first view of the day | ~342 ms | ~313 ms (cache build) |
| status page data, every subsequent view | ~342 ms | **~4 ms** |

Validated end-to-end: live server boots, migration swaps the index, `/status` and
`/status.json` render identical data (90 daily buckets per monitor) in ~5 ms warm.
