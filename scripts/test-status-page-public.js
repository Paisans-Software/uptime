#!/usr/bin/env node
'use strict';

// The public status page carries state and timing, never a monitor's URL,
// status code or the checker's error text:
//   node scripts/test-status-page-public.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-status-public-'));
Object.assign(process.env, { DB_DRIVER: 'sqlite', SQLITE_PATH: path.join(dir, 'test.sqlite') });

const db = require('../src/db');
const status = require('../src/routes/status');

const SECRETS = ['10.9.9.9', 'internal-path', 'ssl3_read_bytes', 'ECONNREFUSED', '502'];
const leaks = (text) => SECRETS.filter((s) => text.includes(s));

async function main() {
  await db.ensureSchema();
  await require('../src/lib/migrations').run();

  const r = await db.query(
    `INSERT INTO sites (name, url, current_state, status_page_excluded)
     VALUES ('wiki', 'https://10.9.9.9/internal-path', 'down', 0)`
  );
  const siteId = r.insertId;
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  await db.query(
    `INSERT INTO incidents (site_id, started_at, last_error) VALUES (?, ?, ?)`,
    [siteId, now, 'Error: SSL routines:ssl3_read_bytes:tlsv1 alert internal error']
  );
  await db.query(
    `INSERT INTO checks (site_id, checked_at, is_up, status_code, response_time_ms, error_message)
     VALUES (?, ?, 0, 502, 12, 'connect ECONNREFUSED 10.9.9.9:443')`,
    [siteId, now]
  );

  // The data behind /status, /status.json and /status.rss.
  const data = await status.buildStatusData();
  assert.strictEqual(data.groups[0].monitors[0].name, 'wiki');
  assert.strictEqual(data.groups[0].monitors[0].current_state, 'down');
  assert.strictEqual(data.groups[0].monitors[0].last_check.response_time_ms, 12);
  assert.strictEqual(data.incidents[0].site_name, 'wiki');
  assert.deepStrictEqual(leaks(JSON.stringify(data)), []);

  // The feed builds its own text from the incidents.
  const app = express();
  app.use(status);
  const server = app.listen(0);
  try {
    const res = await fetch(`http://127.0.0.1:${server.address().port}/status.rss`);
    const body = await res.text();
    assert.strictEqual(res.status, 200);
    assert.ok(body.includes('Incident reported'), body);
    assert.deepStrictEqual(leaks(body), []);
  } finally {
    server.close();
  }
  console.log('ok');
}

main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1); });
