#!/usr/bin/env node
'use strict';

// Exercises src/lib/seed.js against a throwaway SQLite database:
//   node scripts/test-seed.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-seed-'));
Object.assign(process.env, { DB_DRIVER: 'sqlite', SQLITE_PATH: path.join(dir, 'test.sqlite') });

const db = require('../src/db');
const channels = require('../src/lib/channels');
const sitePayload = require('../src/lib/sitePayload');
const seed = require('../src/lib/seed');

const file = path.join(dir, 'seed.json');
const write = (obj) => fs.writeFileSync(file, JSON.stringify(obj));
const http = (name, url, extra = {}) => ({
  name, monitor_type: 'active', url, method: 'GET', check_type: 'status',
  expected_status: '200', follow_redirects: false, interval_seconds: 60,
  timeout_ms: 10000, failure_threshold: 2, ...extra,
});
const ping = (name, host) => ({ name, monitor_type: 'ping', ping_host: host, interval_seconds: 60, timeout_ms: 10000, failure_threshold: 2 });
const byName = async (name) => (await db.query('SELECT * FROM sites WHERE name = ?', [name]))[0];

async function main() {
  await db.ensureSchema();
  await require('../src/lib/migrations').run();

  const email = { to: 'ops@example.test', templates: channels.emptyTemplates() };
  const auto = await channels.createChannel({ name: 'auto', type: 'email', enabled: 1, config: email, auto_attach_managed: 1 });
  const manual = await channels.createChannel({ name: 'manual', type: 'email', enabled: 1, config: email });

  // A hand-made monitor that happens to share a name the seed will use.
  const hand = sitePayload.buildPayload(http('docs — public', 'https://hand.example.test/'));
  const handId = (await sitePayload.insertSite(hand, {})).id;

  write({
    settings: { smtp_host: 'smtp.example.test', smtp_port: 465, smtp_secure: true, status_page_enabled: false },
    monitors: [
      http('talk — public', 'https://talk.example.test/'),
      http('talk — direct (home-a)', 'http://10.44.0.1:8080/', { request_headers: { Host: 'talk.example.test' } }),
      ping('home-b — ping', '10.44.0.2'),
      http('docs — public', 'https://docs.example.test/'),
    ],
  });
  let r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.created.sort(), ['home-b — ping', 'talk — direct (home-a)', 'talk — public']);
  assert.deepStrictEqual(r.monitors.skipped.map((s) => s.name), ['docs — public']);
  assert.strictEqual((await byName('docs — public')).url, 'https://hand.example.test/');
  assert.strictEqual((await db.query('SELECT COUNT(*) AS c FROM sites WHERE name = ?', ['docs — public']))[0].c, 1);

  const s = (await db.query('SELECT * FROM settings WHERE id = 1'))[0];
  assert.strictEqual(s.smtp_host, 'smtp.example.test');
  assert.strictEqual(Number(s.smtp_port), 465);
  assert.strictEqual(Number(s.smtp_secure), 1);
  assert.strictEqual(Number(s.status_page_enabled), 0);

  const talk = await byName('talk — public');
  assert.deepStrictEqual(await channels.listSiteChannelIds(talk.id), [auto]);
  const direct = await byName('talk — direct (home-a)');
  assert.deepStrictEqual(JSON.parse(direct.request_headers), { Host: 'talk.example.test' });

  // An admin subscribes their own channel; reseeding must not undo it.
  await channels.setSiteChannels(talk.id, [auto, manual]);
  write({ monitors: [
    http('talk — public', 'https://talk2.example.test/'),
    http('talk — direct (home-a)', 'http://10.44.0.1:8080/'),
    ping('home-b — ping', '10.44.0.2'),
  ] });
  r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.settings, []);
  assert.strictEqual((await byName('talk — public')).id, talk.id);
  assert.strictEqual((await byName('talk — public')).url, 'https://talk2.example.test/');
  assert.deepStrictEqual((await channels.listSiteChannelIds(talk.id)).sort(), [auto, manual].sort());

  // An entry the fork rejects keeps the existing monitor exactly as it was.
  write({ monitors: [
    http('talk — public', 'https://talk2.example.test/'),
    { name: 'talk — direct (home-a)', monitor_type: 'nonsense' },
    ping('home-b — ping', '10.44.0.2'),
  ] });
  r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.skipped.map((x) => x.name), ['talk — direct (home-a)']);
  assert.ok(await byName('talk — direct (home-a)'));

  // A removed site's monitor goes; nothing else does.
  write({ monitors: [http('talk — public', 'https://talk2.example.test/'), http('talk — direct (home-a)', 'http://10.44.0.1:8080/')] });
  r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.deleted, ['home-b — ping']);
  assert.strictEqual(await byName('home-b — ping'), undefined);
  assert.ok(await byName('docs — public'));
  assert.deepStrictEqual((await channels.listSiteChannelIds(talk.id)).sort(), [auto, manual].sort());

  // No monitors key: nothing about monitors changes.
  write({ settings: { status_page_enabled: false } });
  r = await seed.applySeedFile(file);
  assert.strictEqual(r.monitors, null);
  assert.ok(await byName('talk — public'));
  assert.strictEqual((await byName('docs — public')).id, handId);
  console.log('ok');
}

main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1); });
