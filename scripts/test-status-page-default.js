#!/usr/bin/env node
'use strict';

// A monitor is hidden from the public status page unless whoever made it
// says otherwise:
//   node scripts/test-status-page-default.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-status-default-'));
Object.assign(process.env, { DB_DRIVER: 'sqlite', SQLITE_PATH: path.join(dir, 'test.sqlite') });

const db = require('../src/db');
const sitePayload = require('../src/lib/sitePayload');
const seed = require('../src/lib/seed');

const http = (name, extra = {}) => ({
  name, monitor_type: 'active', url: `https://${name}.example.test/`, method: 'GET',
  check_type: 'status', expected_status: '200', interval_seconds: 60, timeout_ms: 10000, ...extra,
});
const excluded = (body) => sitePayload.buildPayload(body).status_page_excluded;
const byName = async (name) => (await db.query('SELECT * FROM sites WHERE name = ?', [name]))[0];

async function main() {
  await db.ensureSchema();
  await require('../src/lib/migrations').run();

  // The JSON API, backup import and the seed: an absent flag hides.
  assert.strictEqual(excluded(http('absent')), 1);
  assert.strictEqual(excluded(http('null', { status_page_excluded: null })), 1);
  assert.strictEqual(excluded(http('false', { status_page_excluded: false })), 0);
  assert.strictEqual(excluded(http('zero', { status_page_excluded: 0 })), 0);
  assert.strictEqual(excluded(http('true', { status_page_excluded: true })), 1);

  // The form sends a hidden 0 ahead of the checkbox, so an unticked box
  // arrives as '0' and a ticked one as ['0', '1']: the last value wins.
  assert.strictEqual(excluded(http('unticked', { status_page_excluded: '0' })), 0);
  assert.strictEqual(excluded(http('ticked', { status_page_excluded: ['0', '1'] })), 1);

  // The status page lists only what was explicitly shown.
  const file = path.join(dir, 'seed.json');
  fs.writeFileSync(file, JSON.stringify({ monitors: [
    http('shown', { status_page_excluded: false }),
    http('unsaid'),
  ] }));
  const r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.skipped, []);
  assert.strictEqual(Number((await byName('shown')).status_page_excluded), 0);
  assert.strictEqual(Number((await byName('unsaid')).status_page_excluded), 1);

  // A copy is made by hand, whatever the original showed.
  const { site } = await sitePayload.cloneSite((await byName('shown')).id);
  assert.strictEqual(Number((await byName(site.name)).status_page_excluded), 1);
  console.log('ok');
}

main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1); });
