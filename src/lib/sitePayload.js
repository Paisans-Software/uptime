'use strict';

// Shared payload normalization + persistence for monitors. The form route
// (src/routes/sites.js) and the REST API (src/routes/api.js) both go through
// these helpers so there's exactly one definition of:
//   - what a valid monitor payload looks like (buildPayload)
//   - which fields are required per monitor_type (validateForApi)
//   - the INSERT / UPDATE SQL (insertSite / updateSite)
// Audit, logging, monitor reload, and flash messages are intentionally left
// to the route handlers — they need req, and behaviour differs between
// form-submit (redirect + flash) and JSON API (return DTO).

const crypto = require('crypto');
const db = require('../db');
const channels = require('./channels');
const tagsLib = require('./tags');

const VALID_MONITOR_TYPES = ['active', 'heartbeat', 'cert', 'tcp', 'ping', 'dns', 'domain'];
const VALID_CHECK_TYPES = ['status', 'string', 'regex', 'json'];
const VALID_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const VALID_DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'SOA', 'PTR'];
const VALID_BODY_TYPES = ['text', 'json', 'form'];
const VALID_AUTH_TYPES = ['none', 'basic', 'bearer'];

// Domain WHOIS/RDAP probes shouldn't hit registries more often than ~daily.
// Registries rate-limit aggressively (some at 1/10s/IP) and expiry data
// changes once per year. We clamp at 12h regardless of what the caller sent.
const DOMAIN_MIN_INTERVAL_SECONDS = 12 * 60 * 60;
const DOMAIN_DEFAULT_INTERVAL_SECONDS = 24 * 60 * 60;

// Boolean coercion that accepts both form-encoded (`'1'`, `'on'`) and
// JSON-encoded (`true`, `1`, `'true'`) representations. Anything else is
// treated as falsy. Returns 0/1 because that's what the DB stores.
function coerceBool(v) {
  if (v === true || v === 1) return 1;
  if (typeof v === 'string') {
    const s = v.toLowerCase();
    if (s === '1' || s === 'on' || s === 'true' || s === 'yes') return 1;
  }
  return 0;
}

// Parse headers from either a JSON string (form submit) or an already-
// parsed object (JSON API). Throws Error with a stable prefix so route
// handlers can branch on it.
function parseHeadersJson(raw) {
  if (raw == null) return null;
  if (typeof raw === 'object') {
    if (Array.isArray(raw)) throw new Error('Invalid JSON in headers: must be an object');
    return Object.keys(raw).length ? raw : null;
  }
  const s = String(raw).trim();
  if (!s) return null;
  try {
    const parsed = JSON.parse(s);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('headers must be a JSON object');
    }
    return Object.keys(parsed).length ? parsed : null;
  } catch (e) {
    throw new Error('Invalid JSON in headers: ' + e.message);
  }
}

function pickChannelIds(body) {
  let raw = body.channel_ids;
  if (!Array.isArray(raw)) raw = raw == null ? [] : [raw];
  return raw.map((v) => parseInt(v, 10)).filter((n) => Number.isFinite(n) && n > 0);
}

function pickTagIds(body) {
  let raw = body.tag_ids;
  if (!Array.isArray(raw)) raw = raw == null ? [] : [raw];
  return raw.map((v) => parseInt(v, 10)).filter((n) => Number.isFinite(n) && n > 0);
}

// Normalize a request body (form or JSON) into the canonical monitor row
// shape. Doesn't validate required fields — call validateForApi(data) if
// you need strict mode. The form route is intentionally lenient because
// the user can return to /edit and fix things.
function buildPayload(body) {
  const monitor_type = VALID_MONITOR_TYPES.includes(body.monitor_type) ? body.monitor_type : 'active';
  const failure_threshold = Math.max(1, parseInt(body.failure_threshold, 10) || 1);
  const interval_seconds = Math.max(10, parseInt(body.interval_seconds, 10) || 60);
  const timeout_ms = Math.max(1000, parseInt(body.timeout_ms, 10) || 10000);
  const heartbeat_grace_seconds = Math.max(5, parseInt(body.heartbeat_grace_seconds, 10) || 60);
  const cloudflare_mode = coerceBool(body.cloudflare_mode);
  const paused = coerceBool(body.paused);
  const double_verify = coerceBool(body.double_verify);
  const renotify = coerceBool(body.renotify);
  const renotify_raw = parseInt(body.renotify_interval_minutes, 10);
  // Clamp to [1, 10080] (1 minute .. 7 days); default 60.
  const renotify_interval_minutes = Number.isFinite(renotify_raw) && renotify_raw > 0
    ? Math.min(10080, renotify_raw)
    : 60;
  const rawMethod = String(body.method || 'GET').toUpperCase();
  const method = VALID_METHODS.includes(rawMethod) ? rawMethod : 'GET';
  const check_type = VALID_CHECK_TYPES.includes(body.check_type) ? body.check_type : 'status';

  let enforced_interval;
  if (monitor_type === 'domain') {
    const raw = parseInt(body.interval_seconds, 10);
    enforced_interval = Math.max(
      DOMAIN_MIN_INTERVAL_SECONDS,
      Number.isFinite(raw) && raw > 0 ? raw : DOMAIN_DEFAULT_INTERVAL_SECONDS
    );
  } else if (monitor_type === 'active' && cloudflare_mode) {
    enforced_interval = Math.max(60, interval_seconds);
  } else {
    enforced_interval = interval_seconds;
  }

  const display_name = (body.display_name || '').toString().trim().slice(0, 255) || null;
  const status_page_group = (body.status_page_group || '').toString().trim().slice(0, 120) || null;
  const status_page_excluded = coerceBool(body.status_page_excluded);
  const status_page_order = Math.max(0, parseInt(body.status_page_order, 10) || 0);

  const cert_warn_raw = parseInt(body.cert_expiry_warn_days, 10);
  const cert_expiry_warn_days = Number.isFinite(cert_warn_raw)
    ? Math.max(0, Math.min(365, cert_warn_raw))
    : 14;
  const cert_host = monitor_type === 'cert' ? (body.cert_host || '').toString().trim().slice(0, 255) || null : null;
  const cert_port = monitor_type === 'cert'
    ? Math.max(1, Math.min(65535, parseInt(body.cert_port, 10) || 443))
    : null;

  const tcp_host = monitor_type === 'tcp' ? (body.tcp_host || '').toString().trim().slice(0, 255) || null : null;
  // Leave an omitted/invalid port as null so validateForApi can reject it,
  // rather than silently coercing to port 1.
  const tcp_port_raw = parseInt(body.tcp_port, 10);
  const tcp_port = monitor_type === 'tcp'
    ? (Number.isFinite(tcp_port_raw) && tcp_port_raw >= 1 && tcp_port_raw <= 65535 ? tcp_port_raw : null)
    : null;

  const ping_host = monitor_type === 'ping' ? (body.ping_host || '').toString().trim().slice(0, 255) || null : null;
  const ping_count = monitor_type === 'ping'
    ? Math.max(1, Math.min(10, parseInt(body.ping_count, 10) || 1))
    : 1;

  const rawDnsType = String(body.dns_record_type || 'A').toUpperCase();
  const dns_query = monitor_type === 'dns' ? (body.dns_query || '').toString().trim().slice(0, 255) || null : null;
  const dns_record_type = monitor_type === 'dns'
    ? (VALID_DNS_TYPES.includes(rawDnsType) ? rawDnsType : 'A')
    : null;
  const dns_resolver = monitor_type === 'dns'
    ? (body.dns_resolver || '').toString().trim().slice(0, 255) || null
    : null;
  const dns_expected = monitor_type === 'dns'
    ? (body.dns_expected || '').toString().slice(0, 1024) || null
    : null;

  // Domain (WHOIS/RDAP). Strip schemes / paths / www. defensively so callers
  // can paste a URL and still get a usable apex domain.
  const whois_domain = monitor_type === 'domain'
    ? String(body.whois_domain || '').trim().toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '')
        .replace(/:\d+$/, '')
        .replace(/^www\./, '')
        .slice(0, 255) || null
    : null;
  const domain_warn_raw = parseInt(body.domain_expiry_warn_days, 10);
  const domain_expiry_warn_days = Number.isFinite(domain_warn_raw)
    ? Math.max(0, Math.min(365, domain_warn_raw))
    : 30;

  const isActive = monitor_type === 'active';
  const request_body = isActive ? (body.request_body || '').toString().slice(0, 64 * 1024) || null : null;
  const request_body_type = isActive && VALID_BODY_TYPES.includes(body.request_body_type)
    ? body.request_body_type : 'text';
  const auth_type = isActive && VALID_AUTH_TYPES.includes(body.auth_type) ? body.auth_type : 'none';
  const auth_username = isActive && auth_type === 'basic'
    ? (body.auth_username || '').toString().slice(0, 255) || null
    : null;
  const auth_password = isActive && auth_type === 'basic'
    ? (body.auth_password || '').toString().slice(0, 255) || null
    : null;
  const auth_token = isActive && auth_type === 'bearer'
    ? (body.auth_token || '').toString().slice(0, 1024) || null
    : null;
  // follow_redirects defaults to 1 unless explicitly set to false-ish.
  let follow_redirects = 1;
  if (isActive && body.follow_redirects != null) {
    follow_redirects = coerceBool(body.follow_redirects);
  } else if (!isActive) {
    follow_redirects = 1;
  }
  const skip_tls_verify = isActive ? coerceBool(body.skip_tls_verify) : 0;
  const max_rt = parseInt(body.max_response_time_ms, 10);
  const max_response_time_ms = isActive && Number.isFinite(max_rt) && max_rt > 0
    ? Math.min(max_rt, 600000) : null;

  const notes = (body.notes || '').toString().slice(0, 16 * 1024) || null;
  const mute_notifications = coerceBool(body.mute_notifications);

  const heartbeat_schedule_kind = monitor_type === 'heartbeat' && body.heartbeat_schedule_kind === 'cron'
    ? 'cron' : 'interval';
  const heartbeat_cron = monitor_type === 'heartbeat' && heartbeat_schedule_kind === 'cron'
    ? (body.heartbeat_cron || '').toString().trim().slice(0, 160) || null
    : null;
  const heartbeat_timezone = monitor_type === 'heartbeat' && heartbeat_schedule_kind === 'cron'
    ? (body.heartbeat_timezone || 'UTC').toString().trim().slice(0, 64) || 'UTC'
    : null;

  // For TCP/ping/DNS the "string" check_type is meaningless at the routes
  // layer (no body to inspect), but TCP banner-match still uses
  // expected_string via the expected_banner field.
  const expected_string =
    (monitor_type === 'active' && (check_type === 'string' || check_type === 'regex'))
      ? (body.expected_string || '').toString()
      : monitor_type === 'tcp'
        ? (body.expected_banner || '').toString().slice(0, 256) || null
        : null;

  return {
    name: (body.name || '').toString().trim() || 'Untitled',
    url: monitor_type === 'active' ? (body.url || '').toString().trim() : '',
    monitor_type,
    method,
    interval_seconds: enforced_interval,
    timeout_ms,
    check_type: monitor_type === 'active' ? check_type : null,
    expected_status: monitor_type === 'active' && check_type === 'status'
      ? (body.expected_status || '200').toString().trim()
      : null,
    expected_string,
    json_path: monitor_type === 'active' && check_type === 'json'
      ? (body.json_path || '').toString().trim()
      : null,
    expected_json_value: monitor_type === 'active' && check_type === 'json'
      ? (body.expected_json_value || '').toString()
      : null,
    request_headers: monitor_type === 'active' ? parseHeadersJson(body.request_headers) : null,
    failure_threshold,
    heartbeat_grace_seconds,
    cloudflare_mode,
    paused,
    double_verify,
    renotify,
    renotify_interval_minutes,
    display_name,
    status_page_group,
    status_page_excluded,
    status_page_order,
    cert_expiry_warn_days,
    cert_host,
    cert_port,
    tcp_host,
    tcp_port,
    ping_host,
    ping_count,
    dns_query,
    dns_record_type,
    dns_resolver,
    dns_expected,
    whois_domain,
    domain_expiry_warn_days,
    heartbeat_schedule_kind,
    heartbeat_cron,
    heartbeat_timezone,
    request_body,
    request_body_type,
    auth_type,
    auth_username,
    auth_password,
    auth_token,
    follow_redirects,
    skip_tls_verify,
    max_response_time_ms,
    notes,
    mute_notifications,
  };
}

// Strict validation for API callers. Returns an array of human-readable
// error strings (empty array = OK). The form route doesn't call this —
// it's deliberately lenient so the user can come back and finish editing
// without losing their work to a 400.
//
// `rawBody` (optional) lets us catch values that buildPayload silently
// defaults — e.g. an unknown monitor_type would otherwise become 'active'
// and pass downstream checks.
function validateForApi(data, rawBody) {
  const errors = [];
  if (!data.name || data.name === 'Untitled' || !data.name.trim()) {
    errors.push('name is required');
  }
  if (rawBody && rawBody.monitor_type != null
      && !VALID_MONITOR_TYPES.includes(String(rawBody.monitor_type))) {
    errors.push(`monitor_type must be one of: ${VALID_MONITOR_TYPES.join(', ')}`);
  }
  if (rawBody && rawBody.method != null
      && !VALID_METHODS.includes(String(rawBody.method).toUpperCase())) {
    errors.push(`method must be one of: ${VALID_METHODS.join(', ')}`);
  }
  if (rawBody && rawBody.check_type != null
      && !VALID_CHECK_TYPES.includes(String(rawBody.check_type))) {
    errors.push(`check_type must be one of: ${VALID_CHECK_TYPES.join(', ')}`);
  }
  if (rawBody && rawBody.dns_record_type != null
      && !VALID_DNS_TYPES.includes(String(rawBody.dns_record_type).toUpperCase())) {
    errors.push(`dns_record_type must be one of: ${VALID_DNS_TYPES.join(', ')}`);
  }
  switch (data.monitor_type) {
    case 'active':
      if (!data.url) errors.push('url is required for active monitors');
      else if (!/^https?:\/\//i.test(data.url)) errors.push('url must start with http:// or https://');
      if (data.check_type === 'string' && !data.expected_string) {
        errors.push('expected_string is required when check_type=string');
      }
      if (data.check_type === 'regex' && !data.expected_string) {
        errors.push('expected_string (regex pattern) is required when check_type=regex');
      }
      if (data.check_type === 'json') {
        if (!data.json_path) errors.push('json_path is required when check_type=json');
        if (data.expected_json_value == null || data.expected_json_value === '') {
          errors.push('expected_json_value is required when check_type=json');
        }
      }
      break;
    case 'cert':
      if (!data.cert_host) errors.push('cert_host is required for cert monitors');
      break;
    case 'tcp':
      if (!data.tcp_host) errors.push('tcp_host is required for tcp monitors');
      if (!data.tcp_port || data.tcp_port < 1 || data.tcp_port > 65535) {
        errors.push('tcp_port must be 1-65535');
      }
      break;
    case 'ping':
      if (!data.ping_host) errors.push('ping_host is required for ping monitors');
      break;
    case 'dns':
      if (!data.dns_query) errors.push('dns_query is required for dns monitors');
      break;
    case 'domain':
      if (!data.whois_domain) errors.push('whois_domain is required for domain monitors');
      else if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i.test(data.whois_domain)) {
        errors.push('whois_domain must look like an apex domain (e.g. example.com)');
      }
      break;
    case 'heartbeat':
      // heartbeats are passive; the token is generated server-side on insert
      // and the only required field is `name`, already validated above.
      if (data.heartbeat_schedule_kind === 'cron' && !data.heartbeat_cron) {
        errors.push('heartbeat_cron is required when heartbeat_schedule_kind=cron');
      }
      break;
    default:
      break;
  }
  return errors;
}

// Insert a new site row + attach channels and tags. Returns the freshly-
// loaded site row (with the heartbeat_token populated for heartbeats).
// `heartbeatToken` lets callers preserve a token (e.g. backup restore); when
// omitted or invalid a fresh one is generated. Conflicting tokens are
// regenerated so the column stays unique.
async function insertSite(data, { channelIds = [], tagIds = [], ownerUserId = null, heartbeatToken = null } = {}) {
  let heartbeat_token = null;
  if (data.monitor_type === 'heartbeat') {
    const valid = typeof heartbeatToken === 'string' && /^[a-f0-9]{16,64}$/i.test(heartbeatToken);
    heartbeat_token = valid ? heartbeatToken : crypto.randomBytes(16).toString('hex');
    if (valid) {
      const conflict = await db.query('SELECT id FROM sites WHERE heartbeat_token = ? LIMIT 1', [heartbeat_token]);
      if (conflict.length) heartbeat_token = crypto.randomBytes(16).toString('hex');
    }
  }
  const result = await db.query(
    `INSERT INTO sites
       (name, url, monitor_type, method, interval_seconds, timeout_ms,
        check_type, expected_status, expected_string, json_path, expected_json_value,
        request_headers, failure_threshold, heartbeat_token, heartbeat_grace_seconds,
        cloudflare_mode, paused, double_verify, renotify, renotify_interval_minutes,
        display_name, status_page_group, status_page_excluded, status_page_order,
        cert_expiry_warn_days, cert_host, cert_port,
        tcp_host, tcp_port, ping_host, ping_count,
        dns_query, dns_record_type, dns_resolver, dns_expected,
        whois_domain, domain_expiry_warn_days,
        heartbeat_schedule_kind, heartbeat_cron, heartbeat_timezone,
        request_body, request_body_type,
        auth_type, auth_username, auth_password, auth_token,
        follow_redirects, skip_tls_verify, max_response_time_ms,
        notes, mute_notifications, owner_user_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      data.name, data.url, data.monitor_type, data.method, data.interval_seconds, data.timeout_ms,
      data.check_type, data.expected_status, data.expected_string, data.json_path, data.expected_json_value,
      data.request_headers ? JSON.stringify(data.request_headers) : null,
      data.failure_threshold, heartbeat_token, data.heartbeat_grace_seconds,
      data.cloudflare_mode, data.paused, data.double_verify, data.renotify, data.renotify_interval_minutes,
      data.display_name, data.status_page_group, data.status_page_excluded, data.status_page_order,
      data.cert_expiry_warn_days, data.cert_host, data.cert_port,
      data.tcp_host, data.tcp_port, data.ping_host, data.ping_count,
      data.dns_query, data.dns_record_type, data.dns_resolver, data.dns_expected,
      data.whois_domain, data.domain_expiry_warn_days,
      data.heartbeat_schedule_kind, data.heartbeat_cron, data.heartbeat_timezone,
      data.request_body, data.request_body_type,
      data.auth_type, data.auth_username, data.auth_password, data.auth_token,
      data.follow_redirects, data.skip_tls_verify, data.max_response_time_ms,
      data.notes, data.mute_notifications, ownerUserId,
    ]
  );
  const id = result.insertId;
  await channels.setSiteChannels(id, channelIds);
  await tagsLib.setSiteTags(id, tagIds);
  const rows = await db.query(`SELECT * FROM sites WHERE id = ? LIMIT 1`, [id]);
  return { id, site: rows[0] };
}

// Update an existing site row. Returns the freshly-loaded row.
// `channelIds` / `tagIds` are only applied when explicitly provided so
// PATCH callers can update scalar fields without nuking their channels.
async function updateSite(id, data, { channelIds, tagIds, ownerUserId, ownerUserIdProvided, heartbeatToken } = {}) {
  await db.query(
    `UPDATE sites SET
       name=?, url=?, monitor_type=?, method=?, interval_seconds=?, timeout_ms=?,
       check_type=?, expected_status=?, expected_string=?, json_path=?, expected_json_value=?,
       request_headers=?, failure_threshold=?, heartbeat_grace_seconds=?,
       cloudflare_mode=?, paused=?, double_verify=?, renotify=?, renotify_interval_minutes=?,
       display_name=?, status_page_group=?, status_page_excluded=?, status_page_order=?,
       cert_expiry_warn_days=?, cert_host=?, cert_port=?,
       tcp_host=?, tcp_port=?, ping_host=?, ping_count=?,
       dns_query=?, dns_record_type=?, dns_resolver=?, dns_expected=?,
       whois_domain=?, domain_expiry_warn_days=?,
       heartbeat_schedule_kind=?, heartbeat_cron=?, heartbeat_timezone=?,
       request_body=?, request_body_type=?,
       auth_type=?, auth_username=?, auth_password=?, auth_token=?,
       follow_redirects=?, skip_tls_verify=?, max_response_time_ms=?,
       notes=?, mute_notifications=?
     WHERE id=?`,
    [
      data.name, data.url, data.monitor_type, data.method, data.interval_seconds, data.timeout_ms,
      data.check_type, data.expected_status, data.expected_string, data.json_path, data.expected_json_value,
      data.request_headers ? JSON.stringify(data.request_headers) : null,
      data.failure_threshold, data.heartbeat_grace_seconds,
      data.cloudflare_mode, data.paused, data.double_verify, data.renotify, data.renotify_interval_minutes,
      data.display_name, data.status_page_group, data.status_page_excluded, data.status_page_order,
      data.cert_expiry_warn_days, data.cert_host, data.cert_port,
      data.tcp_host, data.tcp_port, data.ping_host, data.ping_count,
      data.dns_query, data.dns_record_type, data.dns_resolver, data.dns_expected,
      data.whois_domain, data.domain_expiry_warn_days,
      data.heartbeat_schedule_kind, data.heartbeat_cron, data.heartbeat_timezone,
      data.request_body, data.request_body_type,
      data.auth_type, data.auth_username, data.auth_password, data.auth_token,
      data.follow_redirects, data.skip_tls_verify, data.max_response_time_ms,
      data.notes, data.mute_notifications,
      id,
    ]
  );

  // Reset the domain-alert band when the warn-days threshold changes or the
  // user repoints at a different apex domain. Otherwise tightening the
  // threshold or rebinding would silently suppress the first alert.
  if (data.monitor_type === 'domain') {
    await db.query(`UPDATE sites SET domain_alerted_at_days = NULL WHERE id = ?`, [id]);
  }
  // Heartbeat token handling:
  //   - if the caller supplied a valid token (e.g. backup restore), adopt it
  //     unless it collides with another monitor's token;
  //   - otherwise regenerate only when the current token is missing (e.g. a
  //     monitor was just converted to the heartbeat type).
  if (data.monitor_type === 'heartbeat') {
    const suppliedValid = typeof heartbeatToken === 'string' && /^[a-f0-9]{16,64}$/i.test(heartbeatToken);
    if (suppliedValid) {
      const conflict = await db.query(
        'SELECT id FROM sites WHERE heartbeat_token = ? AND id <> ? LIMIT 1',
        [heartbeatToken, id]
      );
      const token = conflict.length ? crypto.randomBytes(16).toString('hex') : heartbeatToken;
      await db.query(`UPDATE sites SET heartbeat_token=? WHERE id=?`, [token, id]);
    } else {
      const cur = await db.query(`SELECT heartbeat_token FROM sites WHERE id=?`, [id]);
      if (!cur[0]?.heartbeat_token) {
        await db.query(
          `UPDATE sites SET heartbeat_token=? WHERE id=?`,
          [crypto.randomBytes(16).toString('hex'), id]
        );
      }
    }
  }
  if (ownerUserIdProvided) {
    await db.query(`UPDATE sites SET owner_user_id = ? WHERE id = ?`, [ownerUserId, id]);
  }
  if (Array.isArray(channelIds)) await channels.setSiteChannels(id, channelIds);
  if (Array.isArray(tagIds)) await tagsLib.setSiteTags(id, tagIds);

  const rows = await db.query(`SELECT * FROM sites WHERE id = ? LIMIT 1`, [id]);
  return rows[0];
}

// Field set copied verbatim when duplicating a monitor. Excludes identity
// (id, name), runtime state (current_state, last_*, *_alerted_*,
// heartbeat_token), and ownership/timestamps — those are reset on the clone.
const CLONE_FIELDS = [
  'url', 'monitor_type', 'method', 'interval_seconds', 'timeout_ms',
  'check_type', 'expected_status', 'expected_string', 'json_path', 'expected_json_value',
  'request_headers', 'failure_threshold', 'heartbeat_grace_seconds',
  'cloudflare_mode', 'paused', 'double_verify', 'renotify', 'renotify_interval_minutes',
  'display_name', 'status_page_group', 'status_page_excluded', 'status_page_order',
  'cert_expiry_warn_days', 'cert_host', 'cert_port',
  'tcp_host', 'tcp_port', 'ping_host', 'ping_count',
  'dns_query', 'dns_record_type', 'dns_resolver', 'dns_expected',
  'whois_domain', 'domain_expiry_warn_days',
  'heartbeat_schedule_kind', 'heartbeat_cron', 'heartbeat_timezone',
  'request_body', 'request_body_type',
  'auth_type', 'auth_username', 'auth_password', 'auth_token',
  'follow_redirects', 'skip_tls_verify', 'max_response_time_ms',
  'notes', 'mute_notifications',
];

// Find a unique "<base> (copy)" / "(copy 2)" … name so clones never collide.
async function uniqueCopyName(base) {
  const root = `${base} (copy)`;
  let candidate = root;
  let n = 2;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const rows = await db.query('SELECT id FROM sites WHERE name = ? LIMIT 1', [candidate]);
    if (!rows.length) return candidate;
    candidate = `${base} (copy ${n})`;
    n += 1;
  }
}

// Duplicate an existing monitor (config only — no history/incidents/state).
// Channels and tags are copied. Heartbeat monitors get a brand-new token so
// the clone has its own ping URL. Returns { id, site } like insertSite.
async function cloneSite(sourceId, { ownerUserId = null } = {}) {
  const rows = await db.query('SELECT * FROM sites WHERE id = ? LIMIT 1', [sourceId]);
  const src = rows[0];
  if (!src) throw new Error('source monitor not found');

  const data = {};
  for (const f of CLONE_FIELDS) data[f] = src[f] === undefined ? null : src[f];
  // request_headers is stored as a JSON string; insertSite re-serializes, so
  // hand it an object (or null) to avoid double-encoding.
  if (typeof data.request_headers === 'string') {
    try { data.request_headers = JSON.parse(data.request_headers); }
    catch { data.request_headers = null; }
  }
  data.name = await uniqueCopyName(String(src.name || 'Monitor'));

  const channelIds = await channels.listSiteChannelIds(sourceId);
  const tagIds = (await tagsLib.listSiteTags(sourceId)).map((t) => Number(t.id));

  return insertSite(data, { channelIds, tagIds, ownerUserId });
}

module.exports = {
  buildPayload,
  parseHeadersJson,
  pickChannelIds,
  pickTagIds,
  coerceBool,
  validateForApi,
  insertSite,
  updateSite,
  cloneSite,
  VALID_MONITOR_TYPES,
  VALID_CHECK_TYPES,
  VALID_METHODS,
  VALID_DNS_TYPES,
  DOMAIN_MIN_INTERVAL_SECONDS,
  DOMAIN_DEFAULT_INTERVAL_SECONDS,
};
