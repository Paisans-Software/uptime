'use strict';

const express = require('express');
const db = require('../db');
const stats = require('../lib/stats');
const monitor = require('../monitor');
const channels = require('../lib/channels');
const tagsLib = require('../lib/tags');
const apiTokens = require('../lib/apiTokens');
const users = require('../lib/users');
const acl = require('../lib/acl');
const logger = require('../logger');
const audit = require('../lib/audit');
const { parseId } = require('../lib/ids');
const sitePayload = require('../lib/sitePayload');

const router = express.Router();

// ─── Auth middleware ─────────────────────────────────────────────────────
// Resolves the bearer token AND the acting user (token.user_id → users.id,
// or env admin synthetic user when user_id IS NULL). All downstream ACL
// checks read req.apiUser.
function requireApi(scope = 'read') {
  return async (req, res, next) => {
    try {
      const token = apiTokens.extractToken(req);
      if (!token) return res.status(401).json({ error: 'missing bearer token' });
      const t = await apiTokens.findByToken(token);
      if (!t) return res.status(401).json({ error: 'invalid token' });
      if (scope === 'write' && t.scope !== 'write') {
        return res.status(403).json({ error: 'token does not have write scope' });
      }
      let actingUser;
      if (t.user_id == null) {
        actingUser = users.envAdminUser();
      } else {
        const u = await users.getById(t.user_id);
        if (!u || u.disabled) {
          return res.status(401).json({ error: 'token owner disabled or deleted' });
        }
        actingUser = {
          id: u.id,
          isEnv: false,
          username: u.username,
          role: u.role,
          disabled: !!u.disabled,
        };
      }
      req.apiToken = t;
      req.apiUser = actingUser;
      next();
    } catch (err) {
      next(err);
    }
  };
}

async function loadSiteWithAccess(req, res, mode) {
  const id = parseId(req.params.id);
  if (id == null) {
    res.status(404).json({ error: 'not found' });
    return null;
  }
  const rows = await db.query(`SELECT * FROM sites WHERE id = ? LIMIT 1`, [id]);
  const site = rows[0];
  if (!site) {
    res.status(404).json({ error: 'not found' });
    return null;
  }
  const ok = mode === 'manage'
    ? await acl.canManageSite(req.apiUser, site)
    : await acl.canSeeSite(req.apiUser, site);
  if (!ok) {
    res.status(403).json({ error: 'forbidden' });
    return null;
  }
  return site;
}

function tagToApi(row) {
  return {
    id: row.id,
    name: row.name,
    color: row.color,
    site_count: row.site_count != null ? row.site_count : 0,
  };
}

async function loadTag(req, res) {
  const id = parseId(req.params.id);
  if (id == null) {
    res.status(404).json({ error: 'not found' });
    return null;
  }
  const row = await tagsLib.getTagListed(id);
  if (!row) {
    res.status(404).json({ error: 'not found' });
    return null;
  }
  return row;
}

function safeJsonParse(s) {
  if (s == null) return null;
  if (typeof s === 'object') return s;
  try { return JSON.parse(s); } catch { return null; }
}

function siteToApi(s) {
  return {
    id: s.id,
    name: s.name,
    display_name: s.display_name || null,
    url: s.url || null,
    monitor_type: s.monitor_type,
    method: s.method,
    interval_seconds: s.interval_seconds,
    timeout_ms: s.timeout_ms,
    check_type: s.check_type,
    expected_status: s.expected_status,
    expected_string: s.expected_string,
    json_path: s.json_path,
    expected_json_value: s.expected_json_value,
    request_headers: safeJsonParse(s.request_headers),
    failure_threshold: s.failure_threshold,
    heartbeat_grace_seconds: s.heartbeat_grace_seconds,
    heartbeat_schedule_kind: s.heartbeat_schedule_kind || null,
    heartbeat_cron: s.heartbeat_cron || null,
    heartbeat_timezone: s.heartbeat_timezone || null,
    heartbeat_token: s.heartbeat_token || null,
    cloudflare_mode: !!s.cloudflare_mode,
    paused: !!s.paused,
    double_verify: !!s.double_verify,
    renotify: !!s.renotify,
    renotify_interval_minutes: s.renotify_interval_minutes,
    current_state: s.current_state,
    last_checked_at: s.last_checked_at || null,
    last_heartbeat_at: s.last_heartbeat_at || null,
    last_heartbeat_kind: s.last_heartbeat_kind || null,
    last_response_time_ms: s.last_response_time_ms || null,
    last_status_code: s.last_status_code || null,
    last_error_message: s.last_error_message || null,
    last_cert_subject: s.last_cert_subject || null,
    last_cert_issuer: s.last_cert_issuer || null,
    last_cert_valid_to: s.last_cert_valid_to || null,
    last_cert_days_remaining: s.last_cert_days_remaining,
    tcp_host: s.tcp_host || null,
    tcp_port: s.tcp_port || null,
    ping_host: s.ping_host || null,
    ping_count: s.ping_count || null,
    dns_query: s.dns_query || null,
    dns_record_type: s.dns_record_type || null,
    dns_resolver: s.dns_resolver || null,
    dns_expected: s.dns_expected || null,
    cert_host: s.cert_host || null,
    cert_port: s.cert_port || null,
    cert_expiry_warn_days: s.cert_expiry_warn_days || null,
    whois_domain: s.whois_domain || null,
    domain_expiry_warn_days: s.domain_expiry_warn_days || null,
    domain_expires_at: s.domain_expires_at || null,
    domain_registrar: s.domain_registrar || null,
    domain_status: s.domain_status || null,
    domain_last_checked_at: s.domain_last_checked_at || null,
    domain_days_remaining: computeDomainDays(s.domain_expires_at),
    created_at: s.created_at,
    updated_at: s.updated_at,
  };
}

function computeDomainDays(expiresAt) {
  if (!expiresAt) return null;
  const t = Date.parse(expiresAt);
  if (!Number.isFinite(t)) return null;
  return Math.floor((t - Date.now()) / 86400000);
}

// ─── READ endpoints ──────────────────────────────────────────────────────
router.get('/api/v1/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

router.get('/api/v1/sites', requireApi('read'), async (req, res, next) => {
  try {
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    const where = [];
    const params = [];
    if (req.query.state) { where.push('current_state = ?'); params.push(String(req.query.state)); }
    if (req.query.monitor_type) { where.push('monitor_type = ?'); params.push(String(req.query.monitor_type)); }
    if (req.query.tag) {
      const t = parseId(req.query.tag);
      if (t != null) { where.push('id IN (SELECT site_id FROM site_tags WHERE tag_id = ?)'); params.push(t); }
    }
    const aclClause = acl.siteFilterClause(req.apiUser);
    if (aclClause.sql !== '1 = 1') {
      where.push(aclClause.sql);
      params.push(...aclClause.params);
    }
    const sql = `SELECT * FROM sites ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY id ASC LIMIT ${limit} OFFSET ${offset}`;
    const rows = await db.query(sql, params);
    const totalRow = await db.query(`SELECT COUNT(*) AS c FROM sites ${where.length ? 'WHERE ' + where.join(' AND ') : ''}`, params);
    const total = totalRow[0]?.c || 0;
    const tagMap = await tagsLib.tagsForSites(rows.map((r) => r.id));
    res.json({
      total, limit, offset,
      data: rows.map((r) => ({ ...siteToApi(r), tags: tagMap.get(r.id) || [] })),
    });
  } catch (err) { next(err); }
});

router.get('/api/v1/sites/:id', requireApi('read'), async (req, res, next) => {
  try {
    const site = await loadSiteWithAccess(req, res, 'see');
    if (!site) return;
    const id = site.id;
    const [last, up24, up7, up30, incidents, attachedChannels, siteTagRows] = await Promise.all([
      stats.lastCheck(id),
      stats.uptimePct(id, 24),
      stats.uptimePct(id, 24 * 7),
      stats.uptimePct(id, 24 * 30),
      stats.recentIncidents(id, 10),
      channels.loadSiteChannels(id),
      tagsLib.listSiteTags(id),
    ]);
    res.json({
      ...siteToApi(site),
      tags: siteTagRows,
      uptime_24h: up24,
      uptime_7d: up7,
      uptime_30d: up30,
      last_check: last,
      recent_incidents: incidents,
      channel_ids: attachedChannels.map((c) => c.id),
    });
  } catch (err) { next(err); }
});

router.get('/api/v1/sites/:id/checks', requireApi('read'), async (req, res, next) => {
  try {
    const site = await loadSiteWithAccess(req, res, 'see');
    if (!site) return;
    const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const rows = await db.query(
      `SELECT id, site_id, is_up, status_code, response_time_ms, error_message, checked_at
         FROM checks WHERE site_id = ? ORDER BY id DESC LIMIT ${limit}`,
      [site.id]
    );
    res.json({ data: rows });
  } catch (err) { next(err); }
});

router.get('/api/v1/sites/:id/incidents', requireApi('read'), async (req, res, next) => {
  try {
    const site = await loadSiteWithAccess(req, res, 'see');
    if (!site) return;
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const rows = await db.query(
      `SELECT id, site_id, started_at, ended_at, last_error, during_maintenance,
              ${db.diffSecondsSql('started_at', 'COALESCE(ended_at, ' + db.nowMs() + ')')} AS duration_seconds
         FROM incidents WHERE site_id = ? ORDER BY id DESC LIMIT ${limit}`,
      [site.id]
    );
    res.json({ data: rows });
  } catch (err) { next(err); }
});

router.get('/api/v1/incidents', requireApi('read'), async (req, res, next) => {
  try {
    const limit = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 100));
    const aclClause = acl.siteFilterClause(req.apiUser, { table: 's' });
    const rows = await db.query(
      `SELECT i.id, i.site_id, s.name AS site_name, i.started_at, i.ended_at, i.last_error, i.during_maintenance,
              ${db.diffSecondsSql('i.started_at', 'COALESCE(i.ended_at, ' + db.nowMs() + ')')} AS duration_seconds
         FROM incidents i JOIN sites s ON s.id = i.site_id
        WHERE ${aclClause.sql}
        ORDER BY i.id DESC LIMIT ${limit}`,
      aclClause.params
    );
    res.json({ data: rows });
  } catch (err) { next(err); }
});

router.get('/api/v1/tags', requireApi('read'), async (req, res, next) => {
  try { res.json({ data: await tagsLib.listTags() }); }
  catch (err) { next(err); }
});

router.get('/api/v1/stats', requireApi('read'), async (req, res, next) => {
  try {
    const aclClause = acl.siteFilterClause(req.apiUser);
    const where = aclClause.sql === '1 = 1' ? '' : `AND ${aclClause.sql}`;
    const total = (await db.query(`SELECT COUNT(*) AS c FROM sites WHERE 1=1 ${where}`, aclClause.params))[0]?.c || 0;
    const up = (await db.query(`SELECT COUNT(*) AS c FROM sites WHERE paused=0 AND current_state='up' ${where}`, aclClause.params))[0]?.c || 0;
    const down = (await db.query(`SELECT COUNT(*) AS c FROM sites WHERE paused=0 AND current_state='down' ${where}`, aclClause.params))[0]?.c || 0;
    const paused = (await db.query(`SELECT COUNT(*) AS c FROM sites WHERE paused=1 ${where}`, aclClause.params))[0]?.c || 0;
    // Open incidents — filter via sites join.
    const aclSitesIn = acl.siteFilterClause(req.apiUser, { table: 's' });
    const openIncidents = (await db.query(
      `SELECT COUNT(*) AS c FROM incidents i JOIN sites s ON s.id = i.site_id
        WHERE i.ended_at IS NULL AND ${aclSitesIn.sql}`,
      aclSitesIn.params
    ))[0]?.c || 0;
    res.json({ total, up, down, paused, open_incidents: openIncidents });
  } catch (err) { next(err); }
});

// ─── WRITE endpoints ─────────────────────────────────────────────────────

// Wraps an Error message so the JSON error body never leaks an SQL stack
// trace or other internal detail. Keeps the {error, details?} shape stable.
function jsonError(res, status, message, details) {
  const body = { error: message };
  if (details) body.details = details;
  return res.status(status).json(body);
}

function isUniqueConstraintError(err) {
  return String(err?.message || '').toLowerCase().includes('unique');
}

// POST /api/v1/tags — create tag (idempotent when name already exists).
// Required scope: write. Role: admin (tags are global, same as /settings/tags).
router.post('/api/v1/tags', requireApi('write'), async (req, res, next) => {
  try {
    if (!acl.isAdmin(req.apiUser)) {
      return jsonError(res, 403, 'role must be admin');
    }
    const body = req.body || {};
    const name = tagsLib.normalizeName(body.name);
    if (!name) {
      return jsonError(res, 400, 'tag name required');
    }
    const color = Object.prototype.hasOwnProperty.call(body, 'color')
      ? body.color
      : undefined;

    const existing = await tagsLib.getTagByName(name);
    if (existing) {
      return res.json(tagToApi(existing));
    }

    try {
      const id = await tagsLib.createTag(name, color);
      const row = await tagsLib.getTagListed(id);
      await audit.record({
        actor: req.apiUser.username || null,
        actorUserId: req.apiUser.isEnv ? null : req.apiUser.id,
        ip: req.ip || null,
        action: 'tag.created',
        targetType: 'tag',
        targetId: id,
        meta: { name, via: 'api' },
      });
      logger.info({ tagId: id, name, via: 'api' }, 'tags.created');
      return res.status(201).json(tagToApi(row));
    } catch (err) {
      if (isUniqueConstraintError(err)) {
        const row = await tagsLib.getTagByName(name);
        if (row) return res.json(tagToApi(row));
      }
      throw err;
    }
  } catch (err) {
    next(err);
  }
});

// PATCH /api/v1/tags/:id — partial update (name and/or color).
router.patch('/api/v1/tags/:id', requireApi('write'), async (req, res, next) => {
  try {
    if (!acl.isAdmin(req.apiUser)) {
      return jsonError(res, 403, 'role must be admin');
    }
    const existing = await loadTag(req, res);
    if (!existing) return;
    const body = req.body || {};
    const name = Object.prototype.hasOwnProperty.call(body, 'name')
      ? tagsLib.normalizeName(body.name)
      : existing.name;
    if (!name) {
      return jsonError(res, 400, 'tag name required');
    }
    const color = Object.prototype.hasOwnProperty.call(body, 'color')
      ? body.color
      : existing.color;

    try {
      await tagsLib.updateTag(existing.id, name, color);
    } catch (err) {
      if (isUniqueConstraintError(err)) {
        return jsonError(res, 409, 'tag name already exists');
      }
      throw err;
    }

    const row = await tagsLib.getTagListed(existing.id);
    await audit.record({
      actor: req.apiUser.username || null,
      actorUserId: req.apiUser.isEnv ? null : req.apiUser.id,
      ip: req.ip || null,
      action: 'tag.updated',
      targetType: 'tag',
      targetId: existing.id,
      meta: { name, via: 'api' },
    });
    logger.info({ tagId: existing.id, name, via: 'api' }, 'tags.updated');
    res.json(tagToApi(row));
  } catch (err) {
    next(err);
  }
});

// DELETE /api/v1/tags/:id
router.delete('/api/v1/tags/:id', requireApi('write'), async (req, res, next) => {
  try {
    if (!acl.isAdmin(req.apiUser)) {
      return jsonError(res, 403, 'role must be admin');
    }
    const existing = await loadTag(req, res);
    if (!existing) return;
    await tagsLib.deleteTag(existing.id);
    await audit.record({
      actor: req.apiUser.username || null,
      actorUserId: req.apiUser.isEnv ? null : req.apiUser.id,
      ip: req.ip || null,
      action: 'tag.deleted',
      targetType: 'tag',
      targetId: existing.id,
      meta: { via: 'api' },
    });
    logger.info({ tagId: existing.id, via: 'api' }, 'tags.deleted');
    res.json({ ok: true, id: existing.id, deleted: true });
  } catch (err) {
    next(err);
  }
});

// POST /api/v1/sites — create monitor of any type.
// Required scope: write. Role: admin OR editor (env-admin token bypasses).
// Body fields mirror the form-submit names so a single sitePayload helper
// drives both create paths. Returns 201 + the freshly-loaded site DTO.
router.post('/api/v1/sites', requireApi('write'), async (req, res, next) => {
  try {
    if (!acl.isEditor(req.apiUser)) {
      return jsonError(res, 403, 'role must be admin or editor');
    }
    const body = req.body || {};
    let data;
    try {
      data = sitePayload.buildPayload(body);
    } catch (err) {
      // parseHeadersJson throws when request_headers isn't a valid object.
      return jsonError(res, 400, err.message);
    }
    const errors = sitePayload.validateForApi(data, body);
    if (errors.length) {
      return jsonError(res, 400, 'validation failed', errors);
    }
    const channelIds = sitePayload.pickChannelIds(body);
    const tagIds = sitePayload.pickTagIds(body);
    // Ownership: env-admin and admins can pick any owner; everyone else gets
    // their own user id (so future editors automatically have manage).
    let ownerUserId = req.apiUser.isEnv ? null : (req.apiUser.id || null);
    if (acl.isAdmin(req.apiUser)
        && Object.prototype.hasOwnProperty.call(body, 'owner_user_id')) {
      const raw = parseId(body.owner_user_id);
      ownerUserId = raw != null ? raw : null;
    }
    const { id, site } = await sitePayload.insertSite(data, { channelIds, tagIds, ownerUserId });
    await audit.record({
      actor: req.apiUser.username || null,
      actorUserId: req.apiUser.isEnv ? null : req.apiUser.id,
      ip: req.ip || null,
      action: 'site.created',
      targetType: 'site',
      targetId: id,
      meta: { name: data.name, monitor_type: data.monitor_type, via: 'api' },
    });
    logger.info({ siteId: id, name: data.name, monitor_type: data.monitor_type, via: 'api' }, 'sites.created');
    await monitor.reloadSite(id);
    res.status(201).json(siteToApi(site));
  } catch (err) {
    next(err);
  }
});

// PATCH /api/v1/sites/:id — partial update.
// Required scope: write. ACL: manage permission on the target site.
// Merges req.body over the existing row before normalizing, so callers can
// flip a single field (e.g. {"paused": true}) without resending the whole
// monitor. Returns 200 + the updated site DTO.
router.patch('/api/v1/sites/:id', requireApi('write'), async (req, res, next) => {
  try {
    const existing = await loadSiteWithAccess(req, res, 'manage');
    if (!existing) return;
    // Build the merged body: existing row values fill in anything the caller
    // didn't send. Boolean / number / string coercion is handled downstream
    // by buildPayload, which already deals with row-shaped (0/1, NULL) and
    // JSON-shaped (true/false, null) inputs.
    const body = req.body || {};
    const merged = { ...existing, ...body };
    let data;
    try {
      data = sitePayload.buildPayload(merged);
    } catch (err) {
      return jsonError(res, 400, err.message);
    }
    // Validate using the raw patch body (not the merged) so we only complain
    // about values the caller actually sent — the existing row is trusted.
    const errors = sitePayload.validateForApi(data, body);
    if (errors.length) {
      return jsonError(res, 400, 'validation failed', errors);
    }
    const opts = {};
    if (Object.prototype.hasOwnProperty.call(body, 'channel_ids')) {
      opts.channelIds = sitePayload.pickChannelIds(body);
    }
    if (Object.prototype.hasOwnProperty.call(body, 'tag_ids')) {
      opts.tagIds = sitePayload.pickTagIds(body);
    }
    // Owner reassignment is admin-only — same rule as the form route.
    if (acl.isAdmin(req.apiUser)
        && Object.prototype.hasOwnProperty.call(body, 'owner_user_id')) {
      opts.ownerUserIdProvided = true;
      const raw = parseId(body.owner_user_id);
      opts.ownerUserId = raw != null ? raw : null;
    }
    const updated = await sitePayload.updateSite(existing.id, data, opts);
    await audit.record({
      actor: req.apiUser.username || null,
      actorUserId: req.apiUser.isEnv ? null : req.apiUser.id,
      ip: req.ip || null,
      action: 'site.updated',
      targetType: 'site',
      targetId: existing.id,
      meta: { name: data.name, via: 'api' },
    });
    logger.info({ siteId: existing.id, name: data.name, via: 'api' }, 'sites.updated');
    await monitor.reloadSite(existing.id);
    res.json(siteToApi(updated));
  } catch (err) {
    next(err);
  }
});

router.post('/api/v1/sites/:id/pause', requireApi('write'), async (req, res, next) => {
  try {
    const site = await loadSiteWithAccess(req, res, 'manage');
    if (!site) return;
    await db.query(`UPDATE sites SET paused=1 WHERE id=?`, [site.id]);
    await monitor.reloadSite(site.id);
    res.json({ ok: true, id: site.id, paused: true });
  } catch (err) { next(err); }
});

router.post('/api/v1/sites/:id/resume', requireApi('write'), async (req, res, next) => {
  try {
    const site = await loadSiteWithAccess(req, res, 'manage');
    if (!site) return;
    await db.query(`UPDATE sites SET paused=0 WHERE id=?`, [site.id]);
    await monitor.reloadSite(site.id);
    res.json({ ok: true, id: site.id, paused: false });
  } catch (err) { next(err); }
});

router.delete('/api/v1/sites/:id', requireApi('write'), async (req, res, next) => {
  try {
    const site = await loadSiteWithAccess(req, res, 'manage');
    if (!site) return;
    monitor.stopSite(site.id);
    const result = await db.query(`DELETE FROM sites WHERE id=?`, [site.id]);
    await db.query(`DELETE FROM site_grants WHERE site_id=?`, [site.id]);
    res.json({ ok: true, id: site.id, deleted: (result.affectedRows ?? result.changes ?? 0) > 0 });
  } catch (err) { next(err); }
});

router.post('/api/v1/sites/:id/check-now', requireApi('write'), async (req, res, next) => {
  try {
    const site = await loadSiteWithAccess(req, res, 'manage');
    if (!site) return;
    monitor.checkNow(site.id).catch((err) => logger.error({ err, id: site.id }, 'api.check_now_failed'));
    res.json({ ok: true, id: site.id, queued: true });
  } catch (err) { next(err); }
});

// ─── Prometheus /metrics ─────────────────────────────────────────────────
function promEscape(s) {
  return String(s || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

router.get('/metrics', async (req, res, next) => {
  try {
    // /metrics is gated by API token if any tokens exist; otherwise public.
    // When gated, the acting user's ACL filters the visible sites.
    let actingUser = users.envAdminUser();
    const tokenCount = (await db.query(`SELECT COUNT(*) AS c FROM api_tokens`))[0]?.c || 0;
    if (tokenCount > 0) {
      const token = apiTokens.extractToken(req);
      const t = token ? await apiTokens.findByToken(token) : null;
      if (!t) return res.status(401).type('text/plain').send('# unauthorized\n');
      if (t.user_id == null) {
        actingUser = users.envAdminUser();
      } else {
        const u = await users.getById(t.user_id);
        if (!u || u.disabled) return res.status(401).type('text/plain').send('# unauthorized\n');
        actingUser = { id: u.id, isEnv: false, username: u.username, role: u.role };
      }
    }

    const aclClause = acl.siteFilterClause(actingUser);
    const sql = aclClause.sql === '1 = 1'
      ? `SELECT * FROM sites`
      : `SELECT * FROM sites WHERE ${aclClause.sql}`;
    const sites = await db.query(sql, aclClause.params);
    const lines = [];
    lines.push('# HELP uptime_monitor_up Monitor is currently up (1) or down (0). Paused monitors emit no value.');
    lines.push('# TYPE uptime_monitor_up gauge');
    lines.push('# HELP uptime_monitor_response_time_ms Last observed response time in milliseconds.');
    lines.push('# TYPE uptime_monitor_response_time_ms gauge');
    lines.push('# HELP uptime_monitor_last_check_age_seconds Seconds since the most recent check.');
    lines.push('# TYPE uptime_monitor_last_check_age_seconds gauge');
    lines.push('# HELP uptime_monitor_uptime_pct_24h 24-hour uptime percentage.');
    lines.push('# TYPE uptime_monitor_uptime_pct_24h gauge');
    lines.push('# HELP uptime_cert_days_remaining TLS certificate days until expiry.');
    lines.push('# TYPE uptime_cert_days_remaining gauge');
    lines.push('# HELP uptime_domain_days_remaining Registered domain days until expiry (WHOIS / RDAP).');
    lines.push('# TYPE uptime_domain_days_remaining gauge');
    lines.push('# HELP uptime_monitors_total Total monitor count by state.');
    lines.push('# TYPE uptime_monitors_total gauge');
    lines.push('# HELP uptime_open_incidents Currently open incidents.');
    lines.push('# TYPE uptime_open_incidents gauge');

    let countUp = 0, countDown = 0, countPaused = 0;
    const now = Date.now();
    for (const s of sites) {
      if (s.paused) { countPaused++; continue; }
      if (s.current_state === 'up') countUp++;
      if (s.current_state === 'down') countDown++;
      const labels = `id="${s.id}",name="${promEscape(s.name)}",monitor_type="${promEscape(s.monitor_type)}"`;
      const upVal = s.current_state === 'up' ? 1 : s.current_state === 'down' ? 0 : null;
      if (upVal != null) lines.push(`uptime_monitor_up{${labels}} ${upVal}`);
      const last = await stats.lastCheck(s.id);
      if (last && last.response_time_ms != null) {
        lines.push(`uptime_monitor_response_time_ms{${labels}} ${last.response_time_ms}`);
      }
      if (last && last.checked_at) {
        const age = Math.max(0, Math.floor((now - new Date(last.checked_at).getTime()) / 1000));
        lines.push(`uptime_monitor_last_check_age_seconds{${labels}} ${age}`);
      }
      const pct = await stats.uptimePct(s.id, 24);
      if (pct != null) lines.push(`uptime_monitor_uptime_pct_24h{${labels}} ${pct.toFixed(4)}`);
      if (s.last_cert_days_remaining != null) {
        lines.push(`uptime_cert_days_remaining{${labels}} ${s.last_cert_days_remaining}`);
      }
      if (s.monitor_type === 'domain' && s.domain_expires_at) {
        const t = Date.parse(s.domain_expires_at);
        if (Number.isFinite(t)) {
          const days = Math.floor((t - now) / 86400000);
          lines.push(`uptime_domain_days_remaining{${labels}} ${days}`);
        }
      }
    }
    lines.push(`uptime_monitors_total{state="up"} ${countUp}`);
    lines.push(`uptime_monitors_total{state="down"} ${countDown}`);
    lines.push(`uptime_monitors_total{state="paused"} ${countPaused}`);
    const aclSitesIn = acl.siteFilterClause(actingUser, { table: 's' });
    const openInc = (await db.query(
      `SELECT COUNT(*) AS c FROM incidents i JOIN sites s ON s.id = i.site_id
        WHERE i.ended_at IS NULL AND ${aclSitesIn.sql}`,
      aclSitesIn.params
    ))[0]?.c || 0;
    lines.push(`uptime_open_incidents ${openInc}`);

    res.type('text/plain; version=0.0.4').send(lines.join('\n') + '\n');
  } catch (err) { next(err); }
});

// ─── Friendly error handler scoped to /api/v1/* ──────────────────────────
// NOTE: this middleware is mounted at '/api/v1', so `req.path` inside is the
// path *relative* to the mount. Use `req.originalUrl` for the full URL in logs.
router.use('/api/v1', (err, req, res, _next) => {
  logger.error({ err, reqId: req.id, path: req.originalUrl }, 'api.error');
  res.status(500).json({ error: 'internal error', detail: err.message });
});

module.exports = router;
