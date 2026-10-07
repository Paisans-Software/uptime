'use strict';

const crypto = require('crypto');
const db = require('../db');
const channels = require('./channels');
const monitor = require('../monitor');
const logger = require('../logger');
const sitePayload = require('./sitePayload');
const tagsLib = require('./tags');

const BACKUP_VERSION = 1;
const BACKUP_APP = 'uptime';

// Round-trip the full monitor configuration for every monitor type. Excludes
// runtime state (current_state, last_*, *_alerted_*) and identity (id, owner,
// timestamps) — a backup captures config, not history.
const SITE_EXPORT_FIELDS = [
  'name', 'url', 'monitor_type', 'method', 'interval_seconds', 'timeout_ms',
  'check_type', 'expected_status', 'expected_string', 'json_path', 'expected_json_value',
  'request_headers', 'failure_threshold', 'heartbeat_token', 'heartbeat_grace_seconds',
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

const SITE_BOOL_FIELDS = new Set([
  'cloudflare_mode', 'paused', 'double_verify', 'renotify',
  'status_page_excluded', 'follow_redirects', 'skip_tls_verify', 'mute_notifications',
]);

const VALID_MONITOR_TYPES = sitePayload.VALID_MONITOR_TYPES;
const VALID_CHECK_TYPES = sitePayload.VALID_CHECK_TYPES;
const VALID_METHODS = sitePayload.VALID_METHODS;
const VALID_CHANNEL_TYPES = channels.CHANNEL_TYPES;
const VALID_CONFLICT = ['skip', 'replace', 'rename'];

function normalizeSiteRow(row) {
  const out = {};
  for (const f of SITE_EXPORT_FIELDS) {
    let v = row[f];
    if (f === 'request_headers') {
      if (typeof v === 'string') {
        try { v = JSON.parse(v); } catch { v = null; }
      }
      if (!v || typeof v !== 'object' || Array.isArray(v)) v = null;
    }
    if (SITE_BOOL_FIELDS.has(f)) v = v ? 1 : 0;
    if (v === undefined) v = null;
    out[f] = v;
  }
  return out;
}

function parseChannelConfig(row) {
  let cfg = row.config;
  if (typeof cfg === 'string') {
    try { cfg = JSON.parse(cfg); } catch { cfg = {}; }
  }
  return cfg && typeof cfg === 'object' ? cfg : {};
}

async function loadSitesByIds(ids) {
  if (!ids || !ids.length) return [];
  const placeholders = ids.map(() => '?').join(',');
  return db.query(`SELECT * FROM sites WHERE id IN (${placeholders}) ORDER BY name ASC`, ids);
}

async function loadAllSites() {
  return db.query('SELECT * FROM sites ORDER BY name ASC');
}

async function loadSiteChannelMap(siteIds) {
  if (!siteIds.length) return new Map();
  const placeholders = siteIds.map(() => '?').join(',');
  const rows = await db.query(
    `SELECT sc.site_id, c.name AS channel_name
       FROM site_channels sc JOIN channels c ON c.id = sc.channel_id
      WHERE sc.site_id IN (${placeholders})
      ORDER BY c.name ASC`,
    siteIds
  );
  const map = new Map();
  for (const r of rows) {
    const arr = map.get(Number(r.site_id)) || [];
    arr.push(r.channel_name);
    map.set(Number(r.site_id), arr);
  }
  return map;
}

async function loadAllChannels() {
  const rows = await db.query('SELECT * FROM channels ORDER BY name ASC');
  return rows;
}

async function loadSettingsRow() {
  const rows = await db.query('SELECT * FROM settings WHERE id = 1');
  return rows[0] || null;
}

async function exportConfig({ siteIds, includeChannels, includeSmtp, includeSmtpPassword } = {}) {
  const sites = Array.isArray(siteIds) && siteIds.length ? await loadSitesByIds(siteIds) : await loadAllSites();
  const sitesIdsResolved = sites.map((s) => Number(s.id));
  const channelMap = await loadSiteChannelMap(sitesIdsResolved);
  const tagMap = await tagsLib.tagsForSites(sitesIdsResolved);

  const monitorsOut = sites.map((s) => ({
    ...normalizeSiteRow(s),
    channels: channelMap.get(Number(s.id)) || [],
    tags: (tagMap.get(Number(s.id)) || []).map((t) => t.name),
  }));

  const usedChannelNames = new Set();
  for (const m of monitorsOut) for (const n of m.channels) usedChannelNames.add(n);

  let channelsOut;
  if (includeChannels) {
    const allChannels = await loadAllChannels();
    channelsOut = allChannels.map((c) => ({
      name: c.name,
      type: c.type,
      enabled: !!c.enabled,
      config: parseChannelConfig(c),
    }));
  } else {
    channelsOut = [];
  }

  let settingsOut;
  if (includeSmtp) {
    const s = await loadSettingsRow();
    if (s) {
      settingsOut = {
        smtp_host: s.smtp_host || null,
        smtp_port: Number(s.smtp_port) || 587,
        smtp_secure: s.smtp_secure ? 1 : 0,
        smtp_user: s.smtp_user || null,
        smtp_from_address: s.smtp_from_address || null,
        smtp_from_name: s.smtp_from_name || 'Uptime',
      };
      if (includeSmtpPassword) settingsOut.smtp_pass = s.smtp_pass || null;
    }
  }

  return {
    version: BACKUP_VERSION,
    app: BACKUP_APP,
    exported_at: new Date().toISOString(),
    counts: {
      monitors: monitorsOut.length,
      channels: channelsOut.length,
      attached_channel_refs: usedChannelNames.size,
      includes_smtp: !!settingsOut,
      includes_smtp_password: !!(settingsOut && Object.prototype.hasOwnProperty.call(settingsOut, 'smtp_pass')),
    },
    monitors: monitorsOut,
    channels: channelsOut,
    settings: settingsOut || null,
  };
}

function validatePayload(raw) {
  if (!raw || typeof raw !== 'object') throw new Error('Backup must be a JSON object');
  if (raw.app && raw.app !== BACKUP_APP) throw new Error(`Backup is not from this app (app="${raw.app}")`);
  if (raw.version && Number(raw.version) > BACKUP_VERSION) {
    throw new Error(`Backup format version ${raw.version} is newer than this app supports (${BACKUP_VERSION})`);
  }
  if (!Array.isArray(raw.monitors) && !Array.isArray(raw.channels) && !raw.settings) {
    throw new Error('Backup contains no monitors, channels, or settings');
  }
  if (raw.monitors && !Array.isArray(raw.monitors)) throw new Error('"monitors" must be an array');
  if (raw.channels && !Array.isArray(raw.channels)) throw new Error('"channels" must be an array');
}

function sanitizeImportSite(raw) {
  if (!raw || typeof raw !== 'object') throw new Error('monitor entry is not an object');
  const name = String(raw.name || '').trim();
  if (!name) throw new Error('monitor missing name');

  // Normalize through the shared payload builder so every monitor type (and
  // every type-specific field) is handled identically to the UI / API. The
  // only field-name mismatch is the TCP banner: it lives in the
  // `expected_string` column on export but buildPayload reads `expected_banner`.
  const body = { ...raw };
  if (body.monitor_type === 'tcp' && body.expected_banner == null && body.expected_string != null) {
    body.expected_banner = body.expected_string;
  }

  const data = sitePayload.buildPayload(body);
  data.name = name;

  const channelNames = Array.isArray(raw.channels)
    ? raw.channels.map((s) => String(s || '').trim()).filter(Boolean)
    : [];
  data.channels = channelNames;

  const tagNames = Array.isArray(raw.tags)
    ? raw.tags.map((s) => String(s || '').trim()).filter(Boolean)
    : [];
  data.tags = tagNames;

  // Preserve a valid heartbeat token so ping URLs survive a restore.
  data.heartbeat_token = (data.monitor_type === 'heartbeat'
    && typeof raw.heartbeat_token === 'string'
    && /^[a-f0-9]{16,64}$/i.test(raw.heartbeat_token))
    ? raw.heartbeat_token
    : null;

  return data;
}

function sanitizeImportChannel(raw) {
  if (!raw || typeof raw !== 'object') throw new Error('channel entry is not an object');
  const name = String(raw.name || '').trim();
  if (!name) throw new Error('channel missing name');
  const type = String(raw.type || '').toLowerCase();
  if (!VALID_CHANNEL_TYPES.includes(type)) throw new Error(`channel "${name}" has invalid type "${raw.type}"`);
  let cfg = raw.config;
  if (typeof cfg === 'string') {
    try { cfg = JSON.parse(cfg); } catch { cfg = {}; }
  }
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) cfg = {};
  return {
    name,
    type,
    enabled: raw.enabled === false ? 0 : 1,
    config: cfg,
  };
}

async function uniqueSiteName(base) {
  let candidate = base;
  let n = 1;
  while (true) {
    const rows = await db.query('SELECT id FROM sites WHERE name = ? LIMIT 1', [candidate]);
    if (!rows.length) return candidate;
    n += 1;
    candidate = `${base} (${n})`;
    if (n > 999) return `${base} (${crypto.randomBytes(2).toString('hex')})`;
  }
}

async function uniqueChannelName(base) {
  let candidate = base;
  let n = 1;
  while (true) {
    const rows = await db.query('SELECT id FROM channels WHERE name = ? LIMIT 1', [candidate]);
    if (!rows.length) return candidate;
    n += 1;
    candidate = `${base} (${n})`;
    if (n > 999) return `${base} (${crypto.randomBytes(2).toString('hex')})`;
  }
}

async function findChannelByName(name) {
  const rows = await db.query('SELECT id FROM channels WHERE name = ? LIMIT 1', [name]);
  return rows[0] || null;
}

async function findSiteByName(name) {
  const rows = await db.query('SELECT id FROM sites WHERE name = ? LIMIT 1', [name]);
  return rows[0] || null;
}

// Both insert + update delegate to the shared sitePayload persistence so the
// full column set (all monitor types) is written from one place. We forward
// the backup's heartbeat token so restored heartbeats keep their ping URLs.
async function insertSite(data, channelIds) {
  const { id } = await sitePayload.insertSite(data, {
    channelIds,
    heartbeatToken: data.heartbeat_token || null,
  });
  return Number(id);
}

async function updateSiteRow(id, data, channelIds) {
  // Forward the backup's heartbeat token so a `replace` restore keeps the
  // monitor's original ping URL instead of silently keeping the old one.
  await sitePayload.updateSite(id, data, {
    channelIds,
    heartbeatToken: data.heartbeat_token || null,
  });
  return Number(id);
}

// Resolve tag names to ids, creating any tag that doesn't exist yet, then
// apply the full set to the site. A backup with no tags leaves them untouched.
async function applySiteTags(siteId, tagNames) {
  if (!Array.isArray(tagNames) || !tagNames.length) return;
  const ids = [];
  for (const name of tagNames) {
    const existing = await tagsLib.getTagByName(name);
    if (existing) { ids.push(Number(existing.id)); continue; }
    try {
      const id = await tagsLib.createTag(name);
      ids.push(Number(id));
    } catch {
      const again = await tagsLib.getTagByName(name);
      if (again) ids.push(Number(again.id));
    }
  }
  await tagsLib.setSiteTags(siteId, ids);
}

async function importChannels(items, conflict, log) {
  const stats = { created: 0, updated: 0, skipped: 0, renamed: 0, errors: [] };
  const nameToId = new Map();

  for (const raw of items) {
    let item;
    try { item = sanitizeImportChannel(raw); }
    catch (e) {
      stats.errors.push(e.message);
      continue;
    }
    try {
      const existing = await findChannelByName(item.name);
      if (!existing) {
        const id = await channels.createChannel({
          name: item.name, type: item.type, enabled: !!item.enabled, config: item.config,
        });
        nameToId.set(item.name, Number(id));
        stats.created += 1;
      } else if (conflict === 'skip') {
        nameToId.set(item.name, Number(existing.id));
        stats.skipped += 1;
      } else if (conflict === 'replace') {
        await channels.updateChannel(Number(existing.id), {
          name: item.name, type: item.type, enabled: !!item.enabled, config: item.config,
        });
        nameToId.set(item.name, Number(existing.id));
        stats.updated += 1;
      } else if (conflict === 'rename') {
        const newName = await uniqueChannelName(item.name);
        const id = await channels.createChannel({
          name: newName, type: item.type, enabled: !!item.enabled, config: item.config,
        });
        nameToId.set(item.name, Number(id));
        stats.renamed += 1;
      }
    } catch (err) {
      log.error({ err, channel: item?.name }, 'backup.import_channel_failed');
      stats.errors.push(`channel "${item?.name || '?'}": ${err.message}`);
    }
  }

  return { stats, nameToId };
}

async function resolveChannelIds(names, nameToIdFromImport) {
  const out = [];
  const missing = [];
  for (const name of names) {
    let id = nameToIdFromImport.get(name);
    if (!id) {
      const row = await findChannelByName(name);
      if (row) id = Number(row.id);
    }
    if (id) out.push(id); else missing.push(name);
  }
  return { ids: out, missing };
}

async function importMonitors(items, conflict, nameToChannelId, log) {
  const stats = { created: 0, updated: 0, skipped: 0, renamed: 0, errors: [], missingChannels: new Set() };
  const reloadIds = [];

  for (const raw of items) {
    let item;
    try { item = sanitizeImportSite(raw); }
    catch (e) {
      stats.errors.push(e.message);
      continue;
    }

    const { ids: channelIds, missing } = await resolveChannelIds(item.channels, nameToChannelId);
    for (const m of missing) stats.missingChannels.add(m);

    try {
      const existing = await findSiteByName(item.name);
      if (!existing) {
        const id = await insertSite(item, channelIds);
        await applySiteTags(id, item.tags);
        reloadIds.push(id);
        stats.created += 1;
      } else if (conflict === 'skip') {
        stats.skipped += 1;
      } else if (conflict === 'replace') {
        const id = await updateSiteRow(Number(existing.id), item, channelIds);
        await applySiteTags(id, item.tags);
        reloadIds.push(id);
        stats.updated += 1;
      } else if (conflict === 'rename') {
        const newName = await uniqueSiteName(item.name);
        const id = await insertSite({ ...item, name: newName }, channelIds);
        await applySiteTags(id, item.tags);
        reloadIds.push(id);
        stats.renamed += 1;
      }
    } catch (err) {
      log.error({ err, monitor: item?.name }, 'backup.import_monitor_failed');
      stats.errors.push(`monitor "${item?.name || '?'}": ${err.message}`);
    }
  }

  for (const id of reloadIds) {
    try { await monitor.reloadSite(id); }
    catch (err) { log.error({ err, siteId: id }, 'backup.reload_failed'); }
  }

  stats.missingChannels = Array.from(stats.missingChannels);
  return stats;
}

async function importSmtp(payload, log) {
  if (!payload || typeof payload !== 'object') return { applied: false, reason: 'no settings in backup' };
  const fields = ['smtp_host', 'smtp_port', 'smtp_secure', 'smtp_user', 'smtp_pass',
    'smtp_from_address', 'smtp_from_name'];
  const cur = await loadSettingsRow();
  const out = {};
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(payload, f)) {
      let v = payload[f];
      if (f === 'smtp_secure') v = v ? 1 : 0;
      if (f === 'smtp_port') v = Number(v) || 587;
      out[f] = v;
    } else {
      // Field absent from the backup → preserve the current stored value.
      // (An export without the password simply omits the key.) An explicit
      // null in the backup is honored above and clears the value.
      out[f] = cur ? cur[f] : null;
    }
  }
  await db.query(
    `UPDATE settings SET smtp_host=?, smtp_port=?, smtp_secure=?, smtp_user=?, smtp_pass=?, smtp_from_address=?, smtp_from_name=? WHERE id=1`,
    [out.smtp_host, out.smtp_port, out.smtp_secure, out.smtp_user, out.smtp_pass, out.smtp_from_address, out.smtp_from_name]
  );
  log.info({ smtp_host: out.smtp_host }, 'backup.smtp_imported');
  return { applied: true };
}

async function importConfig(raw, opts = {}) {
  const log = logger.child({ feature: 'backup.import' });
  validatePayload(raw);

  const conflict = VALID_CONFLICT.includes(opts.conflict) ? opts.conflict : 'skip';
  const importMonitorsFlag = opts.importMonitors !== false;
  const importChannelsFlag = opts.importChannels !== false;
  const importSmtpFlag = !!opts.importSmtp;

  const summary = {
    conflict,
    monitors: { created: 0, updated: 0, skipped: 0, renamed: 0, errors: [], missingChannels: [] },
    channels: { created: 0, updated: 0, skipped: 0, renamed: 0, errors: [] },
    smtp: { applied: false },
  };

  let nameToChannelId = new Map();
  if (importChannelsFlag && Array.isArray(raw.channels) && raw.channels.length) {
    const r = await importChannels(raw.channels, conflict, log);
    summary.channels = r.stats;
    nameToChannelId = r.nameToId;
  }

  if (importMonitorsFlag && Array.isArray(raw.monitors) && raw.monitors.length) {
    summary.monitors = await importMonitors(raw.monitors, conflict, nameToChannelId, log);
  }

  if (importSmtpFlag && raw.settings && require('./seed').smtpManaged()) {
    log.warn('backup.smtp_skipped_managed');
    summary.smtp = { applied: false, error: require('./seed').SMTP_LOCKED_MESSAGE };
  } else if (importSmtpFlag && raw.settings) {
    try {
      summary.smtp = await importSmtp(raw.settings, log);
    } catch (err) {
      log.error({ err }, 'backup.smtp_failed');
      summary.smtp = { applied: false, error: err.message };
    }
  }

  log.info({ summary }, 'backup.import_complete');
  return summary;
}

module.exports = {
  BACKUP_VERSION,
  BACKUP_APP,
  exportConfig,
  importConfig,
  VALID_CONFLICT,
};
