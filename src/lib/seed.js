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

const MANAGED_TAG = 'managed';

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
  const named = new Set();

  for (const raw of monitors) {
    const name = String((raw && raw.name) || '').trim();
    named.add(name);
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
    if (id) {
      const [current] = await db.query('SELECT * FROM sites WHERE id = ?', [id]);
      for (const field of ADMIN_FIELDS) {
        if (!Object.prototype.hasOwnProperty.call(raw, field)) data[field] = current[field];
      }
      // No channelIds and no tagIds: updateSite leaves both as they are.
      await sitePayload.updateSite(id, data, {});
      summary.updated.push(data.name);
      continue;
    }
    const clash = await db.query('SELECT id FROM sites WHERE name = ? LIMIT 1', [data.name]);
    if (clash.length) {
      summary.skipped.push({ name: data.name, errors: ['a monitor not tagged managed already has this name'] });
      continue;
    }
    await sitePayload.insertSite(data, { channelIds: autoChannels, tagIds: [tagId] });
    summary.created.push(data.name);
  }

  for (const [name, id] of ownedByName) {
    if (named.has(name)) continue;
    // ON DELETE CASCADE takes its checks, incidents and channel links.
    await db.query('DELETE FROM sites WHERE id = ?', [id]);
    summary.deleted.push(name);
  }
  return summary;
}

async function applySeedFile(file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const settings = raw.settings ? await applySettings(raw.settings) : [];
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

module.exports = { applySeedFile, applySettings, reconcileMonitors, MANAGED_TAG };
