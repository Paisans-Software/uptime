#!/usr/bin/env node
'use strict';

// Exercises the auto_attach_managed channel flag against a throwaway SQLite
// database:   node scripts/test-channel-auto-attach.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-autoattach-'));
Object.assign(process.env, { DB_DRIVER: 'sqlite', SQLITE_PATH: path.join(dir, 'test.sqlite') });

const db = require('../src/db');
const channels = require('../src/lib/channels');

async function main() {
  await db.ensureSchema();
  await require('../src/lib/migrations').run();

  const email = { to: 'ops@example.test', templates: channels.emptyTemplates() };
  const a = await channels.createChannel({ name: 'a', type: 'email', enabled: 1, config: email, auto_attach_managed: 1 });
  const b = await channels.createChannel({ name: 'b', type: 'email', enabled: 1, config: email });
  assert.deepStrictEqual(await channels.listAutoAttachChannelIds(), [a]);

  // An update that does not mention the flag keeps it: backup import and any
  // other caller written before the flag existed must not clear it.
  await channels.updateChannel(a, { name: 'a2', enabled: 1, config: email });
  assert.deepStrictEqual(await channels.listAutoAttachChannelIds(), [a]);

  await channels.updateChannel(b, { name: 'b', enabled: 1, config: email, auto_attach_managed: 1 });
  await channels.updateChannel(a, { name: 'a2', enabled: 1, config: email, auto_attach_managed: 0 });
  assert.deepStrictEqual(await channels.listAutoAttachChannelIds(), [b]);
  console.log('ok');
}

main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1); });
