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
const ping = (name, host, extra = {}) => ({ name, monitor_type: 'ping', ping_host: host, interval_seconds: 60, timeout_ms: 10000, failure_threshold: 2, ...extra });
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

  // What an admin does to a managed monitor in the UI (pause it, mute it,
  // annotate it) is not the file's to undo: a reseed that is silent about a
  // field keeps the admin's value.
  await db.query('UPDATE sites SET paused = 1, mute_notifications = 1, notes = ?, display_name = ? WHERE id = ?',
    ['flapping, see ticket', 'Talk', talk.id]);
  await seed.applySeedFile(file);
  const kept = await byName('talk — public');
  assert.strictEqual(Number(kept.paused), 1);
  assert.strictEqual(Number(kept.mute_notifications), 1);
  assert.strictEqual(kept.notes, 'flapping, see ticket');
  assert.strictEqual(kept.display_name, 'Talk');

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

  // Heartbeat tokens. A deployment that renders the file also tells each host
  // which /ping/<token> URL to push to, so the file may set the token and the
  // app must never swap it for one the host does not know.
  const hb = (name, extra = {}) => ({ name, monitor_type: 'heartbeat', interval_seconds: 60, heartbeat_grace_seconds: 120, ...extra });
  const T1 = 'a'.repeat(32);
  const T2 = 'b'.repeat(32);
  const T3 = 'c'.repeat(32);
  const TH = 'd'.repeat(32);
  const hbHand = (await sitePayload.insertSite(sitePayload.buildPayload(hb('cron by hand')), { heartbeatToken: TH })).site;
  assert.strictEqual(hbHand.heartbeat_token, TH);
  const keep = [http('talk — public', 'https://talk2.example.test/'), http('talk — direct (home-a)', 'http://10.44.0.1:8080/')];

  // Insert with a token; a token on a non-heartbeat entry is not a token field
  // for that type and is dropped, as buildPayload drops every inapplicable
  // field.
  write({ monitors: [...keep, hb('home-a heartbeat', { heartbeat_token: T1 }), ping('home-b — ping', '10.44.0.2', { heartbeat_token: T2 })] });
  r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.skipped, []);
  assert.deepStrictEqual(r.monitors.created.sort(), ['home-a heartbeat', 'home-b — ping']);
  const hbSite = await byName('home-a heartbeat');
  assert.strictEqual(hbSite.heartbeat_token, T1);
  assert.strictEqual((await byName('home-b — ping')).heartbeat_token, null);

  // Update changes the token (the file's wins); the monitor is the same row.
  write({ monitors: [...keep, hb('home-a heartbeat', { heartbeat_token: T2 })] });
  r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.updated.sort(), ['home-a heartbeat', 'talk — direct (home-a)', 'talk — public']);
  assert.strictEqual((await byName('home-a heartbeat')).id, hbSite.id);
  assert.strictEqual((await byName('home-a heartbeat')).heartbeat_token, T2);

  // No token in the file: the token stays what it was.
  write({ monitors: [...keep, hb('home-a heartbeat')] });
  r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.skipped, []);
  assert.strictEqual((await byName('home-a heartbeat')).heartbeat_token, T2);

  // An invalid token skips the entry and keeps the monitor, token included.
  for (const bad of ['zz', '', 'a'.repeat(15), 'a'.repeat(65), 'g'.repeat(32), 12345]) {
    write({ monitors: [...keep, hb('home-a heartbeat', { heartbeat_token: bad })] });
    r = await seed.applySeedFile(file);
    assert.deepStrictEqual(r.monitors.skipped.map((x) => x.name), ['home-a heartbeat']);
    if (bad !== '') assert.ok(!JSON.stringify(r.monitors.skipped).includes(String(bad)), 'skip reason must not echo the token');
    assert.strictEqual((await byName('home-a heartbeat')).heartbeat_token, T2);
  }

  // A token held by a monitor the file does not own is never taken, and never
  // replaced with a random one: on update the managed monitor keeps its own,
  // on insert nothing is created.
  write({ monitors: [...keep, hb('home-a heartbeat', { heartbeat_token: TH }), hb('home-c heartbeat', { heartbeat_token: TH })] });
  r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.skipped.map((x) => x.name), ['home-a heartbeat', 'home-c heartbeat']);
  assert.ok(!JSON.stringify(r.monitors.skipped).includes(TH));
  assert.strictEqual((await byName('home-a heartbeat')).heartbeat_token, T2);
  assert.strictEqual(await byName('home-c heartbeat'), undefined);
  assert.strictEqual((await byName('cron by hand')).heartbeat_token, TH);

  // Two entries with the same token: the first wins, the later is skipped.
  write({ monitors: [...keep, hb('home-a heartbeat', { heartbeat_token: T3 }), hb('home-c heartbeat', { heartbeat_token: T3 })] });
  r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.skipped.map((x) => x.name), ['home-c heartbeat']);
  assert.strictEqual((await byName('home-a heartbeat')).heartbeat_token, T3);
  assert.strictEqual(await byName('home-c heartbeat'), undefined);

  // A site renamed in the file keeps its token: the old managed monitor goes
  // and the new one takes the token in the same pass.
  write({ monitors: [...keep, hb('home-a renamed', { heartbeat_token: T3 })] });
  r = await seed.applySeedFile(file);
  assert.deepStrictEqual(r.monitors.skipped, []);
  assert.deepStrictEqual(r.monitors.deleted, ['home-a heartbeat']);
  assert.deepStrictEqual(r.monitors.created, ['home-a renamed']);
  assert.strictEqual((await byName('home-a renamed')).heartbeat_token, T3);
  console.log('ok');
}

main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1); });
