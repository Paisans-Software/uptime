#!/usr/bin/env node
'use strict';

// Exercises bulk channel attach/detach and retroactive auto-attach against a
// throwaway SQLite database, then the bulk route over HTTP for the admin-only
// rule:   node scripts/test-bulk-channels.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-bulkch-'));
const SQLITE_PATH = path.join(dir, 'test.sqlite');
Object.assign(process.env, { DB_DRIVER: 'sqlite', SQLITE_PATH });

const db = require('../src/db');
const channels = require('../src/lib/channels');
const tagsLib = require('../src/lib/tags');
const sitePayload = require('../src/lib/sitePayload');
const users = require('../src/lib/users');

const email = { to: 'ops@example.test', templates: null };
const site = async (name, tagIds = []) => (await sitePayload.insertSite(
  sitePayload.buildPayload({ name, monitor_type: 'ping', ping_host: '127.0.0.1' }), { tagIds })).id;
const linked = async (siteId) => (await channels.listSiteChannelIds(siteId)).sort();

async function main() {
  await db.ensureSchema();
  await require('../src/lib/migrations').run();
  email.templates = channels.emptyTemplates();

  const managed = Number(await tagsLib.createTag(tagsLib.MANAGED_TAG));
  const m1 = await site('m1', [managed]);
  const m2 = await site('m2', [managed]);
  const hand = await site('hand');

  // Bulk attach and detach touch only the named channel on the named monitors.
  const a = await channels.createChannel({ name: 'a', type: 'email', enabled: 1, config: email });
  const b = await channels.createChannel({ name: 'b', type: 'email', enabled: 1, config: email });
  await channels.setSiteChannels(m1, [b]);
  await channels.attachToSites([m1, hand], a);
  assert.deepStrictEqual(await linked(m1), [a, b].sort());
  assert.deepStrictEqual(await linked(hand), [a]);
  assert.deepStrictEqual(await linked(m2), []);
  await channels.attachToSites([m1], a); // already linked: no duplicate, no error
  assert.deepStrictEqual(await linked(m1), [a, b].sort());
  await channels.detachFromSites([m1], a);
  assert.deepStrictEqual(await linked(m1), [b]);
  assert.deepStrictEqual(await linked(hand), [a]);

  // Creating a channel with the flag attaches it to every managed monitor,
  // and only those.
  const c = await channels.createChannel({ name: 'c', type: 'email', enabled: 1, config: email, auto_attach_managed: 1 });
  assert.ok((await linked(m1)).includes(c));
  assert.ok((await linked(m2)).includes(c));
  assert.ok(!(await linked(hand)).includes(c));

  // Leaving the flag on does not re-attach where an admin detached it.
  await channels.detachFromSites([m2], c);
  await channels.updateChannel(c, { name: 'c', enabled: 1, config: email, auto_attach_managed: 1 });
  await channels.updateChannel(c, { name: 'c2', enabled: 1, config: email });
  assert.ok(!(await linked(m2)).includes(c));

  // Switching it off and on again is a fresh off-to-on: everything again.
  await channels.updateChannel(c, { name: 'c', enabled: 1, config: email, auto_attach_managed: 0 });
  await channels.updateChannel(c, { name: 'c', enabled: 1, config: email, auto_attach_managed: 1 });
  assert.ok((await linked(m2)).includes(c));

  // Over HTTP: an editor may bulk pause but not bulk attach a channel.
  await users.create({ username: 'ed', password: 'password123', role: 'editor' });
  await users.create({ username: 'boss', password: 'password123', role: 'admin' });
  const port = 3998;
  const server = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(port), ADMIN_PASS: 'not-used-here-1', SESSION_SECRET: 'x' },
    stdio: 'ignore',
  });
  try {
    const base = `http://127.0.0.1:${port}`;
    for (let i = 0; i < 40; i++) {
      try { if ((await fetch(base + '/healthz')).ok) break; } catch (_) { /* not up yet */ }
      await new Promise((r) => setTimeout(r, 250));
    }
    const login = async (username) => {
      const r = await fetch(base + '/login', {
        method: 'POST', redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username, password: 'password123' }),
      });
      return r.headers.get('set-cookie').split(';')[0];
    };
    const bulk = (cookie, fields) => fetch(base + '/sites/bulk', {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams(fields),
    });
    const d = await channels.createChannel({ name: 'd', type: 'email', enabled: 1, config: email });
    await bulk(await login('ed'), [['action', 'channel_add'], ['channel_id', String(d)], ['site_ids', String(hand)]]);
    assert.ok(!(await linked(hand)).includes(d), 'an editor attached a channel');
    await bulk(await login('boss'), [['action', 'channel_add'], ['channel_id', String(d)], ['site_ids', String(hand)], ['site_ids', String(m1)]]);
    assert.ok((await linked(hand)).includes(d) && (await linked(m1)).includes(d), 'an admin could not attach a channel');
    await bulk(await login('boss'), [['action', 'channel_remove'], ['channel_id', String(d)], ['site_ids', String(m1)]]);
    assert.ok(!(await linked(m1)).includes(d) && (await linked(hand)).includes(d), 'detach touched the wrong monitor');
  } finally {
    server.kill();
  }
  console.log('ok');
}

main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1); });
