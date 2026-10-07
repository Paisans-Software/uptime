'use strict';

const express = require('express');
const db = require('../db');
const monitor = require('../monitor');
const stats = require('../lib/stats');
const channels = require('../lib/channels');
const config = require('../config');
const logger = require('../logger');
const { idParam, parseId } = require('../lib/ids');
const maintenance = require('../lib/maintenance');
const tagsLib = require('../lib/tags');
const audit = require('../lib/audit');
const acl = require('../lib/acl');
const users = require('../lib/users');
const grants = require('../lib/grants');
const { safeReturnTo } = require('../auth');

const sitePayload = require('../lib/sitePayload');

const router = express.Router();
router.param('id', idParam);

// Single source of truth for payload normalization + INSERT/UPDATE lives in
// src/lib/sitePayload.js so the form route and the REST API both go through
// the same code path. The form route stays lenient (no validateForApi call);
// the API route is strict.
const { buildPayload, pickChannelIds, pickTagIds, insertSite, updateSite } = sitePayload;


const PAGE_SIZE = 50;

// Listing order prioritises unhealthy monitors so a site admin paging
// through 1000+ monitors always sees actionable issues on page 1 first.
// Portable between SQLite and MySQL: both support CASE in ORDER BY.
//   1. down (and not paused)      → first
//   2. unknown                    → second (may be transitioning to down)
//   3. up                         → third
//   4. anything else / null state → fourth
//   5. paused                     → last (explicitly silenced)
const SITE_HEALTH_ORDER_SQL = `
  CASE
    WHEN paused = 1 THEN 4
    WHEN current_state = 'down' THEN 0
    WHEN current_state = 'unknown' THEN 1
    WHEN current_state = 'up' THEN 2
    ELSE 3
  END,
  name ASC
`.trim();
const VALID_STATES = ['up', 'down', 'unknown', 'paused'];
const VALID_TYPES = ['active', 'heartbeat', 'cert', 'tcp', 'ping', 'dns', 'domain'];

function parseListFilters(query) {
  const q = String(query.q || '').trim().slice(0, 120);
  const stateRaw = String(query.state || '').trim().toLowerCase();
  const typeRaw = String(query.type || '').trim().toLowerCase();
  const cfRaw = String(query.cf || '').trim().toLowerCase();
  const state = VALID_STATES.includes(stateRaw) ? stateRaw : '';
  const type = VALID_TYPES.includes(typeRaw) ? typeRaw : '';
  const cf = cfRaw === 'on' || cfRaw === 'off' ? cfRaw : '';
  const tagId = parseInt(query.tag, 10);
  const tag = Number.isFinite(tagId) && tagId > 0 ? tagId : '';
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  return { q, state, type, cf, tag, page };
}

function buildSiteWhere(filters, user) {
  const where = [];
  const params = [];
  if (filters.q) {
    where.push('(name LIKE ? OR url LIKE ?)');
    const like = `%${filters.q.replace(/[%_\\]/g, (c) => '\\' + c)}%`;
    params.push(like, like);
  }
  if (filters.state) {
    if (filters.state === 'paused') {
      where.push('paused = 1');
    } else {
      where.push('paused = 0 AND current_state = ?');
      params.push(filters.state);
    }
  }
  if (filters.type) {
    where.push('monitor_type = ?');
    params.push(filters.type);
  }
  if (filters.cf) {
    where.push('cloudflare_mode = ?');
    params.push(filters.cf === 'on' ? 1 : 0);
  }
  if (filters.tag) {
    where.push('id IN (SELECT site_id FROM site_tags WHERE tag_id = ?)');
    params.push(filters.tag);
  }
  // Per-monitor ACL — admins get 1=1, everyone else owner|grant.
  const aclClause = acl.siteFilterClause(user);
  if (aclClause.sql && aclClause.sql !== '1 = 1') {
    where.push(aclClause.sql);
    params.push(...aclClause.params);
  }
  return { sql: where.length ? 'WHERE ' + where.join(' AND ') : '', params };
}

function qsExceptPage(filters) {
  const parts = [];
  if (filters.q) parts.push('q=' + encodeURIComponent(filters.q));
  if (filters.state) parts.push('state=' + encodeURIComponent(filters.state));
  if (filters.type) parts.push('type=' + encodeURIComponent(filters.type));
  if (filters.cf) parts.push('cf=' + encodeURIComponent(filters.cf));
  if (filters.tag) parts.push('tag=' + encodeURIComponent(filters.tag));
  return parts.join('&');
}

router.get('/', async (req, res, next) => {
  try {
    const filters = parseListFilters(req.query);
    const { sql: whereSql, params } = buildSiteWhere(filters, req.session.user);

    const totalRows = await db.query(`SELECT COUNT(*) AS n FROM sites ${whereSql}`, params);
    const total = Number(totalRows[0]?.n || 0);
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    const page = Math.min(filters.page, totalPages);
    const offset = (page - 1) * PAGE_SIZE;

    const sites = await db.query(
      `SELECT * FROM sites ${whereSql} ORDER BY ${SITE_HEALTH_ORDER_SQL} LIMIT ${PAGE_SIZE} OFFSET ${offset}`,
      params
    );

    const enriched = await Promise.all(
      sites.map(async (s) => {
        const [last, pct] = await Promise.all([stats.lastCheck(s.id), stats.uptimePct(s.id, 24)]);
        return { ...s, last_check: last, uptime24: pct };
      })
    );

    // Tag chips on each card
    const tagsBySite = await tagsLib.tagsForSites(enriched.map((s) => s.id));
    enriched.forEach((s) => { s.tags = tagsBySite.get(s.id) || []; });

    // Per-card manage flag. Admins always manage; otherwise we attach a flag
    // for owner-or-manage-grant. This drives whether the delete-pill on each
    // card is rendered.
    const isAdminUser = acl.isAdmin(req.session.user);
    if (isAdminUser) {
      enriched.forEach((s) => { s.canManage = true; });
    } else {
      const uid = req.session.user?.id;
      const manageRows = enriched.length
        ? await db.query(
            `SELECT site_id FROM site_grants
              WHERE user_id = ? AND permission = 'manage'
                AND site_id IN (${enriched.map(() => '?').join(',')})`,
            [uid, ...enriched.map((s) => s.id)]
          )
        : [];
      const manageSet = new Set(manageRows.map((r) => Number(r.site_id)));
      enriched.forEach((s) => {
        s.canManage = (s.owner_user_id != null && s.owner_user_id === uid) || manageSet.has(s.id);
      });
    }

    // Surface active maintenance windows so users know why no alerts are firing.
    const now = new Date();
    const allWindows = await maintenance.listWindows();
    const activeWindows = allWindows
      .filter((w) => maintenance.windowIsActive(w, now))
      .map((w) => ({
        ...w,
        ends_at_display: maintenance.currentEnd(w, now)?.toISOString() || null,
      }));

    const allTags = await tagsLib.listTags();
    const activeTag = filters.tag ? allTags.find((t) => t.id === filters.tag) || null : null;

    res.render('dashboard', {
      title: 'Dashboard',
      sites: enriched,
      filters,
      total,
      page,
      pageSize: PAGE_SIZE,
      totalPages,
      qsExceptPage: qsExceptPage(filters),
      hasFilters: Boolean(filters.q || filters.state || filters.type || filters.cf || filters.tag),
      publicBaseUrl: config.publicBaseUrl,
      activeMaintenance: activeWindows,
      allTags,
      activeTag,
      // Only an admin is offered channel bulk actions (the route enforces it).
      allChannels: acl.isAdmin(req.session.user) ? await channels.listChannels() : [],
      isAdmin: acl.isAdmin(req.session.user),
      canCreate: acl.isAdmin(req.session.user) || req.session.user?.role === 'editor',
    });
  } catch (err) {
    next(err);
  }
});

router.get('/api/sites', async (req, res, next) => {
  try {
    const idsRaw = String(req.query.ids || '');
    const ids = idsRaw
      .split(',')
      .map((s) => parseInt(s, 10))
      .filter((n) => Number.isFinite(n) && n > 0)
      .slice(0, 100);

    const aclClause = acl.siteFilterClause(req.session.user);
    const isAdminQuery = aclClause.sql === '1 = 1';

    let sites;
    if (ids.length) {
      const placeholders = ids.map(() => '?').join(',');
      const sql = `SELECT id, name, current_state, paused, monitor_type, last_heartbeat_at
                     FROM sites WHERE id IN (${placeholders})
                     ${isAdminQuery ? '' : ' AND ' + aclClause.sql}
                     ORDER BY id ASC`;
      sites = await db.query(sql, isAdminQuery ? ids : [...ids, ...aclClause.params]);
    } else {
      const sql = `SELECT id, name, current_state, paused, monitor_type, last_heartbeat_at
                     FROM sites
                     ${isAdminQuery ? '' : 'WHERE ' + aclClause.sql}
                     ORDER BY id ASC LIMIT 100`;
      sites = await db.query(sql, isAdminQuery ? [] : aclClause.params);
    }
    const lasts = await Promise.all(sites.map((s) => stats.lastCheck(s.id)));
    res.json(
      sites.map((s, i) => ({
        id: s.id,
        name: s.name,
        state: s.paused ? 'paused' : s.current_state,
        monitor_type: s.monitor_type,
        last_check: lasts[i],
        last_heartbeat_at: s.last_heartbeat_at,
      }))
    );
  } catch (err) {
    next(err);
  }
});

router.get('/sites/new', acl.requireRole('admin', 'editor'), async (req, res, next) => {
  try {
    const [allChannels, allTags] = await Promise.all([
      channels.listChannels(),
      tagsLib.listTags(),
    ]);
    // Owner picker is admin-only; everyone else owns what they create.
    let allOwners = [];
    if (acl.isAdmin(req.session.user)) {
      allOwners = await users.list();
    }
    res.render('site-form', {
      title: 'New monitor',
      site: {
        monitor_type: 'active',
        method: 'GET',
        interval_seconds: 60,
        timeout_ms: 10000,
        heartbeat_grace_seconds: 60,
        failure_threshold: 1,
        check_type: 'status',
        expected_status: '200',
        cloudflare_mode: 0,
        paused: 0,
        double_verify: 0,
        owner_user_id: req.session.user?.id || null,
      },
      allChannels,
      selectedChannelIds: [],
      allTags,
      selectedTagIds: [],
      allOwners,
      isAdmin: acl.isAdmin(req.session.user),
      formAction: '/sites',
      submitLabel: 'Create monitor',
      CHANNEL_META: channels.CHANNEL_META,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/sites', acl.requireRole('admin', 'editor'), async (req, res, next) => {
  try {
    const data = buildPayload(req.body);
    const validationErrors = sitePayload.validateForApi(data, req.body);
    if (validationErrors.length) {
      req.flash('error', validationErrors.join('; '));
      return res.redirect('/sites/new');
    }
    const channelIds = pickChannelIds(req.body);
    const tagIds = pickTagIds(req.body);
    // Owner: admins may pick; everyone else implicitly owns their own.
    let ownerUserId = req.session.user?.id || null;
    if (acl.isAdmin(req.session.user)) {
      const raw = parseId(req.body.owner_user_id);
      if (raw != null) ownerUserId = raw;
      else if (req.body.owner_user_id === '' || req.body.owner_user_id === '0') ownerUserId = null;
      else ownerUserId = req.session.user?.id || null;
    }
    const { id } = await insertSite(data, { channelIds, tagIds, ownerUserId });
    audit.fromReq(req, 'site.created', { targetType: 'site', targetId: id, meta: { name: data.name, monitor_type: data.monitor_type } });
    logger.info({ siteId: id, name: data.name, monitor_type: data.monitor_type, channelIds }, 'sites.created');
    await monitor.reloadSite(id);
    req.flash('success', `Monitor "${data.name}" created`);
    res.redirect(`/sites/${id}`);
  } catch (err) {
    if (err.message?.startsWith('Invalid JSON')) {
      req.flash('error', err.message);
      return res.redirect('/sites/new');
    }
    next(err);
  }
});

router.get('/sites/:id', acl.requireSiteSee, async (req, res, next) => {
  try {
    const site = req.site;
    const id = site.id;

    const [up24, up7, up30, rt24, rtAll, recent, incidents, downtime24, last, attachedChannels, siteTagRows] = await Promise.all([
      stats.uptimePct(id, 24),
      stats.uptimePct(id, 24 * 7),
      stats.uptimePct(id, 24 * 30),
      stats.responseTimeStats(id, 24),
      stats.responseTimeStats(id, 24 * 30),
      stats.recentChecks(id, 50),
      stats.recentIncidents(id, 25),
      stats.totalDowntimeSeconds(id, 24),
      stats.lastCheck(id),
      channels.loadSiteChannels(id),
      tagsLib.listSiteTags(id),
    ]);

    let recentPings = [];
    if (site.monitor_type === 'heartbeat') {
      recentPings = await db.query(
        `SELECT id, kind, exit_code, duration_ms, body, source_ip, user_agent, received_at
           FROM heartbeat_pings
          WHERE site_id = ?
          ORDER BY id DESC LIMIT 25`,
        [id]
      );
    }

    const canManage = await acl.canManageSite(req.session.user, site);
    const canShare = canManage && (acl.isAdmin(req.session.user) || site.owner_user_id === req.session.user.id);
    let ownerUser = null;
    let siteGrants = [];
    let eligibleUsers = [];
    if (canShare) {
      if (site.owner_user_id != null) ownerUser = await users.getById(site.owner_user_id);
      siteGrants = await grants.listForSite(id);
      const allUsers = await users.list();
      const grantedIds = new Set(siteGrants.map((g) => g.user_id));
      eligibleUsers = allUsers.filter((u) => !u.disabled
        && u.id !== site.owner_user_id
        && !grantedIds.has(u.id));
    }

    res.render('site-detail', {
      title: site.name,
      site,
      up24, up7, up30,
      rt24, rtAll,
      recent, incidents,
      downtime24, last,
      attachedChannels,
      siteTags: siteTagRows,
      recentPings,
      publicBaseUrl: config.publicBaseUrl,
      canManage,
      canShare,
      isAdmin: acl.isAdmin(req.session.user),
      ownerUser,
      siteGrants,
      eligibleUsers,
    });
  } catch (err) {
    next(err);
  }
});

router.get('/sites/:id/edit', acl.requireSiteManage, async (req, res, next) => {
  try {
    const site = req.site;
    const id = site.id;
    let rh = site.request_headers;
    if (typeof rh === 'string' && rh.trim()) {
      try { rh = JSON.parse(rh); } catch { rh = null; }
    }
    site.request_headers_str = (rh && typeof rh === 'object' && !Array.isArray(rh))
      ? JSON.stringify(rh, null, 2)
      : '';
    const [allChannels, selectedChannelIds, allTags, siteTagRows] = await Promise.all([
      channels.listChannels(),
      channels.listSiteChannelIds(id),
      tagsLib.listTags(),
      tagsLib.listSiteTags(id),
    ]);
    const selectedTagIds = siteTagRows.map((t) => t.id);
    let allOwners = [];
    if (acl.isAdmin(req.session.user)) allOwners = await users.list();
    res.render('site-form', {
      title: `Edit ${site.name}`,
      site,
      allChannels,
      selectedChannelIds,
      allTags,
      selectedTagIds,
      allOwners,
      isAdmin: acl.isAdmin(req.session.user),
      formAction: `/sites/${id}/edit`,
      submitLabel: 'Save changes',
      CHANNEL_META: channels.CHANNEL_META,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/sites/:id/edit', acl.requireSiteManage, async (req, res, next) => {
  try {
    const id = req.site.id;
    const data = buildPayload(req.body);
    const validationErrors = sitePayload.validateForApi(data, req.body);
    if (validationErrors.length) {
      req.flash('error', validationErrors.join('; '));
      return res.redirect(`/sites/${id}/edit`);
    }
    const channelIds = pickChannelIds(req.body);
    const tagIds = pickTagIds(req.body);

    // Owner reassignment is admin-only; viewers/editors can't change ownership
    // even when granted manage on the monitor.
    let ownerUserId = null;
    let ownerUserIdProvided = false;
    if (acl.isAdmin(req.session.user) && Object.prototype.hasOwnProperty.call(req.body, 'owner_user_id')) {
      ownerUserIdProvided = true;
      const raw = parseId(req.body.owner_user_id);
      if (raw != null) ownerUserId = raw;
    }

    await updateSite(id, data, { channelIds, tagIds, ownerUserId, ownerUserIdProvided });
    audit.fromReq(req, 'site.updated', { targetType: 'site', targetId: id, meta: { name: data.name } });
    logger.info({ siteId: id, name: data.name, channelIds }, 'sites.updated');
    await monitor.reloadSite(id);
    req.flash('success', 'Monitor updated');
    res.redirect(`/sites/${id}`);
  } catch (err) {
    if (err.message?.startsWith('Invalid JSON')) {
      req.flash('error', err.message);
      return res.redirect(`/sites/${req.params.id}/edit`);
    }
    next(err);
  }
});

router.post('/sites/:id/delete', acl.requireSiteManage, async (req, res, next) => {
  try {
    const id = req.site.id;
    monitor.stopSite(id);
    await db.query(`DELETE FROM sites WHERE id=?`, [id]);
    // Tidy up dangling grants (no FK on SQLite).
    await db.query(`DELETE FROM site_grants WHERE site_id=?`, [id]);
    stats.invalidateDailyCache(id);
    audit.fromReq(req, 'site.deleted', { targetType: 'site', targetId: id });
    logger.info({ siteId: id }, 'sites.deleted');
    req.flash('success', 'Monitor deleted');
    res.redirect('/');
  } catch (err) {
    next(err);
  }
});

router.post('/sites/:id/pause', acl.requireSiteManage, async (req, res, next) => {
  try {
    const id = req.site.id;
    const nextVal = req.site.paused ? 0 : 1;
    await db.query(`UPDATE sites SET paused=? WHERE id=?`, [nextVal, id]);
    await monitor.reloadSite(id);
    logger.info({ siteId: id, paused: nextVal }, 'sites.toggled_pause');
    req.flash('success', nextVal ? 'Monitor paused' : 'Monitor resumed');
    res.redirect(`/sites/${id}`);
  } catch (err) {
    next(err);
  }
});

router.post('/sites/:id/check-now', acl.requireSiteManage, async (req, res, next) => {
  try {
    const id = req.site.id;
    const result = await monitor.checkNow(id);
    logger.info({ siteId: id, result }, 'sites.manual_check');
    req.flash(
      result.isUp === 1 ? 'success' : result.isUp === 0 ? 'error' : 'warning',
      result.isUp === 1
        ? `Check passed (${result.responseTimeMs ?? '-'}ms)`
        : result.isUp === 0
        ? `Check failed: ${result.errorMessage || 'unknown'}`
        : `Inconclusive: ${result.errorMessage || 'cloudflare challenge'}`
    );
    res.redirect(`/sites/${id}`);
  } catch (err) {
    next(err);
  }
});

// Duplicate a monitor's configuration into a new "(copy)" monitor. Requires
// create rights (admin/editor) plus manage on the source. Channels + tags are
// copied; history/incidents/state are not. The clone starts paused so it
// doesn't immediately alert before the user reviews it.
router.post('/sites/:id/clone', acl.requireRole('admin', 'editor'), acl.requireSiteManage, async (req, res, next) => {
  try {
    const srcId = req.site.id;
    // Editors own their clones; admins inherit the source's owner.
    const ownerUserId = acl.isAdmin(req.session.user)
      ? (req.site.owner_user_id ?? null)
      : (req.session.user?.id || null);
    const { id, site } = await sitePayload.cloneSite(srcId, { ownerUserId });
    audit.fromReq(req, 'site.cloned', {
      targetType: 'site', targetId: id,
      meta: { name: site.name, source_id: srcId },
    });
    logger.info({ siteId: id, sourceId: srcId, name: site.name }, 'sites.cloned');
    await monitor.reloadSite(id);
    req.flash('success', `Cloned to "${site.name}" — review and edit before use.`);
    res.redirect(`/sites/${id}/edit`);
  } catch (err) {
    next(err);
  }
});

router.get('/api/sites/:id/timeseries', acl.requireSiteSee, async (req, res, next) => {
  try {
    const id = req.site.id;
    const hours = Math.min(720, Math.max(1, parseInt(req.query.hours, 10) || 24));
    const bucket = hours <= 6 ? 1 : hours <= 24 ? 5 : hours <= 72 ? 15 : 60;
    const data = await stats.timeseries(id, hours, bucket);
    res.json({ hours, bucketMinutes: bucket, points: data });
  } catch (err) {
    next(err);
  }
});

// ─── CSV export helpers ──────────────────────────────────────────────────
function csvCell(v) {
  if (v == null) return '';
  const s = String(v);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function rowsToCsv(headers, rows) {
  const out = [headers.join(',')];
  for (const r of rows) out.push(headers.map((h) => csvCell(r[h])).join(','));
  return out.join('\n') + '\n';
}

router.get('/sites/:id/checks.csv', acl.requireSiteSee, async (req, res, next) => {
  try {
    const id = req.site.id;
    const limit = Math.min(50000, Math.max(1, parseInt(req.query.limit, 10) || 5000));
    const rows = await db.query(
      `SELECT id, site_id, is_up, status_code, response_time_ms, error_message, checked_at
         FROM checks WHERE site_id = ? ORDER BY id DESC LIMIT ${limit}`,
      [id]
    );
    const csv = rowsToCsv(
      ['id', 'site_id', 'is_up', 'status_code', 'response_time_ms', 'error_message', 'checked_at'],
      rows
    );
    res.type('text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="site-${id}-checks.csv"`);
    res.send(csv);
  } catch (err) { next(err); }
});

router.get('/sites/:id/incidents.csv', acl.requireSiteSee, async (req, res, next) => {
  try {
    const id = req.site.id;
    const rows = await db.query(
      `SELECT id, site_id, started_at, ended_at, last_error, during_maintenance,
              ${db.diffSecondsSql('started_at', 'COALESCE(ended_at, ' + db.nowMs() + ')')} AS duration_seconds
         FROM incidents WHERE site_id = ? ORDER BY id DESC`,
      [id]
    );
    const csv = rowsToCsv(
      ['id', 'site_id', 'started_at', 'ended_at', 'duration_seconds', 'during_maintenance', 'last_error'],
      rows
    );
    res.type('text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="site-${id}-incidents.csv"`);
    res.send(csv);
  } catch (err) { next(err); }
});

router.get('/incidents.csv', async (req, res, next) => {
  try {
    // Non-admins get filtered to visible sites; admins see everything.
    const aclClause = acl.siteFilterClause(req.session.user, { table: 's' });
    const sql = `SELECT i.id, i.site_id, s.name AS site_name, i.started_at, i.ended_at, i.last_error, i.during_maintenance,
              ${db.diffSecondsSql('i.started_at', 'COALESCE(i.ended_at, ' + db.nowMs() + ')')} AS duration_seconds
         FROM incidents i JOIN sites s ON s.id = i.site_id
        WHERE ${aclClause.sql}
        ORDER BY i.id DESC`;
    const rows = await db.query(sql, aclClause.params);
    const csv = rowsToCsv(
      ['id', 'site_id', 'site_name', 'started_at', 'ended_at', 'duration_seconds', 'during_maintenance', 'last_error'],
      rows
    );
    res.type('text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="incidents.csv"`);
    res.send(csv);
  } catch (err) { next(err); }
});

// Bulk actions invoked from the dashboard. Accepts:
//   action     ∈ pause | resume | delete | tag_add | tag_remove
//                | channel_add | channel_remove
//   site_ids[] = array of integer site IDs
//   tag_id     = integer (only for tag_add / tag_remove)
//   channel_id = integer (only for channel_add / channel_remove)
const BULK_ACTIONS = new Set(['pause', 'resume', 'delete', 'tag_add', 'tag_remove', 'channel_add', 'channel_remove']);
// Channels are admin-only everywhere else, so attaching one in bulk is too.
const ADMIN_BULK_ACTIONS = new Set(['channel_add', 'channel_remove']);

router.post('/sites/bulk', acl.requireRole('admin', 'editor'), async (req, res, next) => {
  try {
    const action = String(req.body.action || '').toLowerCase();
    if (!BULK_ACTIONS.has(action)) {
      req.flash('error', `Unknown bulk action: ${action}`);
      return res.redirect('/');
    }
    if (ADMIN_BULK_ACTIONS.has(action) && !acl.isAdmin(req.session.user)) {
      req.flash('error', 'Only an admin can attach or detach notification channels.');
      return res.redirect(safeReturnTo(req.body.return_to));
    }
    let raw = req.body.site_ids;
    if (!Array.isArray(raw)) raw = raw == null ? [] : [raw];
    const requestedIds = raw
      .map((v) => parseId(v))
      .filter((v) => v != null);
    if (!requestedIds.length) {
      req.flash('warning', 'No monitors selected');
      return res.redirect(safeReturnTo(req.body.return_to));
    }
    // Filter to only the sites this user may manage. Skipped ones get
    // reported back in the flash.
    let siteIds = requestedIds;
    let skipped = 0;
    if (!acl.isAdmin(req.session.user)) {
      const requestedPh = requestedIds.map(() => '?').join(',');
      const visible = await db.query(
        `SELECT id, owner_user_id FROM sites WHERE id IN (${requestedPh})`,
        requestedIds
      );
      const allowed = [];
      for (const r of visible) {
        if (await acl.canManageSite(req.session.user, r)) allowed.push(r.id);
      }
      skipped = requestedIds.length - allowed.length;
      siteIds = allowed;
    }
    if (!siteIds.length) {
      req.flash('error', 'You do not have permission to act on the selected monitors.');
      return res.redirect(safeReturnTo(req.body.return_to));
    }
    const ph = siteIds.map(() => '?').join(',');

    if (action === 'pause' || action === 'resume') {
      const v = action === 'pause' ? 1 : 0;
      await db.query(`UPDATE sites SET paused=? WHERE id IN (${ph})`, [v, ...siteIds]);
      for (const id of siteIds) await monitor.reloadSite(id);
      req.flash('success', `${action === 'pause' ? 'Paused' : 'Resumed'} ${siteIds.length} monitor${siteIds.length === 1 ? '' : 's'}`);
    } else if (action === 'delete') {
      for (const id of siteIds) monitor.stopSite(id);
      await db.query(`DELETE FROM sites WHERE id IN (${ph})`, siteIds);
      // Tidy up dangling grants (no FK cascade on SQLite), same as single delete.
      await db.query(`DELETE FROM site_grants WHERE site_id IN (${ph})`, siteIds);
      for (const id of siteIds) stats.invalidateDailyCache(id);
      req.flash('success', `Deleted ${siteIds.length} monitor${siteIds.length === 1 ? '' : 's'}`);
    } else if (action === 'tag_add') {
      const tagId = parseId(req.body.tag_id);
      if (tagId == null) {
        req.flash('error', 'Pick a tag to add');
      } else {
        await tagsLib.attachToSites(siteIds, tagId);
        req.flash('success', `Tagged ${siteIds.length} monitor${siteIds.length === 1 ? '' : 's'}`);
      }
    } else if (action === 'channel_add' || action === 'channel_remove') {
      const channelId = parseId(req.body.channel_id);
      if (channelId == null || !(await channels.getChannel(channelId))) {
        req.flash('error', 'Pick a channel');
      } else if (action === 'channel_add') {
        await channels.attachToSites(siteIds, channelId);
        req.flash('success', `Attached the channel to ${siteIds.length} monitor${siteIds.length === 1 ? '' : 's'}`);
      } else {
        await channels.detachFromSites(siteIds, channelId);
        req.flash('success', `Detached the channel from ${siteIds.length} monitor${siteIds.length === 1 ? '' : 's'}`);
      }
    } else if (action === 'tag_remove') {
      const tagId = parseId(req.body.tag_id);
      if (tagId == null) {
        req.flash('error', 'Pick a tag to remove');
      } else {
        await tagsLib.detachFromSites(siteIds, tagId);
        req.flash('success', `Removed tag from ${siteIds.length} monitor${siteIds.length === 1 ? '' : 's'}`);
      }
    }
    audit.fromReq(req, 'site.bulk_' + action, { meta: { ids: siteIds, count: siteIds.length, skipped } });
    logger.info({ action, count: siteIds.length, ids: siteIds, skipped }, 'sites.bulk_action');
    if (skipped > 0) {
      req.flash('warning', `${skipped} monitor${skipped === 1 ? '' : 's'} skipped (no permission)`);
    }
    res.redirect(safeReturnTo(req.body.return_to));
  } catch (err) {
    next(err);
  }
});

// ─── Sharing (per-monitor grants) ────────────────────────────────────────
// Visible to admins and the site owner. Editors with a 'manage' grant can
// edit the site itself but cannot reassign sharing.
function requireSharingAdmin(req, res, next) {
  const site = req.site;
  const u = req.session.user;
  if (!site || !u) return res.status(403).render('error', { title: 'Forbidden', error: 'You cannot manage sharing for this monitor.' });
  if (acl.isAdmin(u) || (site.owner_user_id != null && site.owner_user_id === u.id)) return next();
  return res.status(403).render('error', { title: 'Forbidden', error: 'Only the site owner or an admin can manage sharing.' });
}

router.post('/sites/:id/grants', acl.requireSiteManage, requireSharingAdmin, async (req, res, next) => {
  try {
    const site = req.site;
    const userId = parseId(req.body.user_id);
    const permission = String(req.body.permission || 'view').toLowerCase();
    if (userId == null) {
      req.flash('error', 'Pick a user to grant access to.');
      return res.redirect(`/sites/${site.id}`);
    }
    if (userId === req.session.user?.id) {
      req.flash('error', 'You already have access to your own monitors.');
      return res.redirect(`/sites/${site.id}`);
    }
    const target = await users.getById(userId);
    if (!target) {
      req.flash('error', 'Selected user no longer exists.');
      return res.redirect(`/sites/${site.id}`);
    }
    // Viewers can never manage (see acl.canManageSite), so a "manage" grant on
    // a viewer would be silently ignored. Coerce it to "view" and say so,
    // keeping the stored grant consistent with what's actually enforced.
    let effectivePermission = permission;
    if (target.role === 'viewer' && permission === 'manage') {
      effectivePermission = 'view';
      req.flash('warning', `${target.username} is a viewer and cannot manage monitors — granted view instead.`);
    }
    await grants.set(site.id, userId, effectivePermission, req.session.user?.id || null);
    audit.fromReq(req, 'site.grant_set', { targetType: 'site', targetId: site.id, meta: { user_id: userId, permission: effectivePermission } });
    req.flash('success', `Granted ${effectivePermission} to ${target.username}`);
    res.redirect(`/sites/${site.id}`);
  } catch (err) { next(err); }
});

router.post('/sites/:id/grants/:userId/delete', acl.requireSiteManage, requireSharingAdmin, async (req, res, next) => {
  try {
    const site = req.site;
    const userId = parseId(req.params.userId);
    if (userId == null) return res.redirect(`/sites/${site.id}`);
    await grants.revoke(site.id, userId);
    audit.fromReq(req, 'site.grant_revoked', { targetType: 'site', targetId: site.id, meta: { user_id: userId } });
    req.flash('success', 'Access revoked');
    res.redirect(`/sites/${site.id}`);
  } catch (err) { next(err); }
});

router.post('/theme', (req, res) => {
  const next = req.body.theme === 'dark' ? 'dark' : 'light';
  res.cookie('theme', next, { httpOnly: false, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 365 });
  res.json({ ok: true, theme: next });
});

module.exports = router;
