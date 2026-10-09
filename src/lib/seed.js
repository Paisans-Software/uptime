'use strict';

// Reconciles settings and monitors from a file the deployment renders and
// mounts read only, named by SEED_FILE. It runs at every boot, after
// migrations and before the monitor starts, so a deployment that changes the
// file and restarts the container converges without anyone opening the UI.
//
// Ownership is by tag. A monitor tagged `managed` belongs to the file: it is
// created, updated and deleted to match it. Anything else belongs to whoever
// made it and is never touched, even when its name collides with one the
// file uses. Channel links on an existing monitor are never touched either:
// they are the admins' subscriptions, and a reseed that reset them would
// undo every admin's choices on every restart (which is what
// backup.importConfig's `replace` path does, so it is not reused here).

const fs = require('fs');
const db = require('../db');
const logger = require('../logger');
const sitePayload = require('./sitePayload');
const tagsLib = require('./tags');
const channels = require('./channels');

const { MANAGED_TAG } = tagsLib;

// The settings the file may carry, and nothing else: a file that could set
// any column could change sign in or branding without anyone deciding to.
const SETTINGS_FIELDS = [
  'smtp_host', 'smtp_port', 'smtp_secure', 'smtp_user', 'smtp_pass',
  'smtp_from_address', 'smtp_from_name', 'status_page_enabled',
];
const BOOLEAN_SETTINGS = new Set(['smtp_secure', 'status_page_enabled']);

// Columns an admin sets in the UI rather than the deployment in the file.
// updateSite writes every column buildPayload produces, and buildPayload
// fills an absent one with its default, so without this a reseed would
// unpause, unmute and blank whatever an admin did to a managed monitor. A
// file that does name one of these still wins.
const ADMIN_FIELDS = [
  'paused', 'mute_notifications', 'renotify', 'renotify_interval_minutes',
  'notes', 'display_name', 'status_page_group', 'status_page_excluded',
  'status_page_order', 'double_verify',
];

// When a seed file supplies SMTP, the file is where SMTP is decided, and the
// settings page, its save route and backup import refuse to change it. It is
// recomputed at every apply, so a file that stops supplying SMTP hands it back
// to the UI on the next start.
let managedSmtp = false;
const SMTP_LOCKED_MESSAGE = "SMTP settings are defined in this server's configuration and can't be changed from the UI.";

function smtpManaged() {
  return managedSmtp;
}

async function applySettings(settings) {
  const keys = SETTINGS_FIELDS.filter((k) => Object.prototype.hasOwnProperty.call(settings, k));
  if (!keys.length) return [];
  const values = keys.map((k) => {
    const v = settings[k];
    if (BOOLEAN_SETTINGS.has(k)) return v ? 1 : 0;
    if (k === 'smtp_port') return Number(v) || 587;
    return v == null ? null : String(v);
  });
  await db.query(`UPDATE settings SET ${keys.map((k) => `${k} = ?`).join(', ')} WHERE id = 1`, values);
  return keys;
}

async function managedTagId() {
  const tag = await tagsLib.getTagByName(MANAGED_TAG);
  if (tag) return Number(tag.id);
  return Number(await tagsLib.createTag(MANAGED_TAG));
}

// A heartbeat entry may carry `heartbeat_token`, the token in the /ping/<token>
// URL the deployment has already handed to the host that will push to it. The
// host knows no other URL, so the token must be stored exactly as given or the
// entry refused: insertSite and updateSite swap a conflicting token for a
// random one, which would leave the host pushing to a dead URL, so every
// conflict is caught here first. The file decides the token (its host is
// already configured with it), and an entry without one keeps whatever the
// monitor has. On any other monitor type the field is dropped, as buildPayload
// drops every field that does not apply to the type. Error messages never
// carry the token: they are logged, and the token marks the site up.
const TOKEN_RE = /^[a-f0-9]{16,64}$/i;

async function seedToken(raw, id, seen) {
  if (raw.monitor_type !== 'heartbeat' || raw.heartbeat_token == null) return { token: null };
  const token = raw.heartbeat_token;
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
    return { error: 'heartbeat_token must be 16 to 64 hex characters' };
  }
  if (seen.has(token)) return { error: 'heartbeat_token is already used by an earlier entry in this file' };
  const holder = await db.query(
    'SELECT name FROM sites WHERE heartbeat_token = ? AND id <> ? LIMIT 1',
    [token, id || 0]
  );
  if (holder.length) return { error: `heartbeat_token is already used by the monitor named "${holder[0].name}"` };
  return { token };
}

async function reconcileMonitors(monitors) {
  const tagId = await managedTagId();
  const owned = await db.query(
    `SELECT s.id, s.name FROM sites s JOIN site_tags st ON st.site_id = s.id WHERE st.tag_id = ?`,
    [tagId]
  );
  const ownedByName = new Map(owned.map((r) => [r.name, Number(r.id)]));
  const autoChannels = await channels.listAutoAttachChannelIds();
  const summary = { created: [], updated: [], deleted: [], skipped: [] };
  // Every name the file mentions, valid or not: an entry the fork rejects
  // must not cost the deployment the monitor it already has under that name.
  const named = new Set(monitors.map((raw) => String((raw && raw.name) || '').trim()));

  // Deletions first, so a site the file renamed can take its token from the
  // monitor that held it under the old name in the same pass.
  for (const [name, id] of ownedByName) {
    if (named.has(name)) continue;
    // ON DELETE CASCADE takes its checks, incidents and channel links.
    await db.query('DELETE FROM sites WHERE id = ?', [id]);
    summary.deleted.push(name);
  }

  const tokensSeen = new Set();
  for (const raw of monitors) {
    const name = String((raw && raw.name) || '').trim();
    let data;
    let errors;
    try {
      data = sitePayload.buildPayload(raw);
      errors = sitePayload.validateForApi(data, raw);
    } catch (err) {
      errors = [err.message];
    }
    if (errors.length) {
      summary.skipped.push({ name, errors });
      continue;
    }
    const id = ownedByName.get(data.name);
    const { token, error } = await seedToken(raw, id, tokensSeen);
    if (error) {
      summary.skipped.push({ name, errors: [error] });
      continue;
    }
    if (token) tokensSeen.add(token);
    if (id) {
      const [current] = await db.query('SELECT * FROM sites WHERE id = ?', [id]);
      for (const field of ADMIN_FIELDS) {
        if (!Object.prototype.hasOwnProperty.call(raw, field)) data[field] = current[field];
      }
      // No channelIds and no tagIds: updateSite leaves both as they are. No
      // heartbeatToken: it leaves the token as it is too.
      await sitePayload.updateSite(id, data, { heartbeatToken: token });
      summary.updated.push(data.name);
      continue;
    }
    const clash = await db.query('SELECT id FROM sites WHERE name = ? LIMIT 1', [data.name]);
    if (clash.length) {
      summary.skipped.push({ name: data.name, errors: ['a monitor not tagged managed already has this name'] });
      continue;
    }
    await sitePayload.insertSite(data, { channelIds: autoChannels, tagIds: [tagId], heartbeatToken: token });
    summary.created.push(data.name);
  }
  return summary;
}

async function applySeedFile(file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const settings = raw.settings ? await applySettings(raw.settings) : [];
  managedSmtp = settings.some((k) => k.startsWith('smtp_'));
  // Absent means "this file says nothing about monitors", not "none".
  const monitors = Array.isArray(raw.monitors) ? await reconcileMonitors(raw.monitors) : null;
  for (const s of (monitors && monitors.skipped) || []) {
    logger.warn({ name: s.name, errors: s.errors }, 'seed.monitor_skipped');
  }
  // Setting names only: smtp_pass must never reach a log.
  logger.info({ file, settings, monitors: monitors && {
    created: monitors.created.length, updated: monitors.updated.length,
    deleted: monitors.deleted.length, skipped: monitors.skipped.length,
  } }, 'seed.applied');
  return { settings, monitors };
}

module.exports = { applySeedFile, applySettings, reconcileMonitors, smtpManaged, SMTP_LOCKED_MESSAGE, MANAGED_TAG };
