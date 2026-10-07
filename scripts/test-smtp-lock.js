#!/usr/bin/env node
'use strict';

// Exercises the SMTP lock: a seed file that carries SMTP settings makes them
// read-only in the UI and in backup import; one that does not leaves them
// editable.   node scripts/test-smtp-lock.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-smtplock-'));
const SQLITE_PATH = path.join(dir, 'test.sqlite');
Object.assign(process.env, { DB_DRIVER: 'sqlite', SQLITE_PATH });

const db = require('../src/db');
const seed = require('../src/lib/seed');
const backup = require('../src/lib/backup');
const users = require('../src/lib/users');

const withSmtp = path.join(dir, 'with-smtp.json');
const withoutSmtp = path.join(dir, 'without-smtp.json');
fs.writeFileSync(withSmtp, JSON.stringify({ settings: { smtp_host: 'smtp.deploy.test', smtp_port: 587, status_page_enabled: false } }));
fs.writeFileSync(withoutSmtp, JSON.stringify({ settings: { status_page_enabled: false } }));
// Pages are HTML: EJS escapes the message's apostrophes.
const text = (html) => html.replace(/&#39;/g, "'");
const host = async () => (await db.query('SELECT smtp_host FROM settings WHERE id = 1'))[0].smtp_host;

async function serve(seedFile, fn) {
  const port = 3997;
  const server = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(port), ADMIN_PASS: 'not-used-here-1', SESSION_SECRET: 'x', SEED_FILE: seedFile },
    stdio: 'ignore',
  });
  try {
    const base = `http://127.0.0.1:${port}`;
    for (let i = 0; i < 40; i++) {
      try { if ((await fetch(base + '/healthz')).ok) break; } catch (_) { /* not up yet */ }
      await new Promise((r) => setTimeout(r, 250));
    }
    const r = await fetch(base + '/login', {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'boss', password: 'password123' }),
    });
    const cookie = r.headers.get('set-cookie').split(';')[0];
    await fn(base, cookie);
  } finally {
    server.kill();
    await new Promise((r) => server.on('exit', r));
  }
}

const save = (base, cookie, smtpHost) => fetch(base + '/settings/smtp', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
  body: new URLSearchParams({ smtp_host: smtpHost, smtp_port: '25', smtp_from_address: 'x@ui.test' }),
});

async function main() {
  await db.ensureSchema();
  await require('../src/lib/migrations').run();
  await users.create({ username: 'boss', password: 'password123', role: 'admin' });

  // In process: the file decides, at every apply.
  await seed.applySeedFile(withSmtp);
  assert.strictEqual(seed.smtpManaged(), true);
  const summary = await backup.importConfig({
    app: 'uptime', version: 1, monitors: [], channels: [],
    settings: { smtp_host: 'smtp.backup.test', smtp_port: 25 },
  }, { importSmtp: true });
  assert.strictEqual(summary.smtp.applied, false);
  assert.strictEqual(await host(), 'smtp.deploy.test');
  await seed.applySeedFile(withoutSmtp);
  assert.strictEqual(seed.smtpManaged(), false);

  // Over HTTP, seeded with SMTP: the page says so and a save changes nothing.
  await serve(withSmtp, async (base, cookie) => {
    const page = text(await (await fetch(base + '/settings/smtp', { headers: { cookie } })).text());
    assert.ok(page.includes(seed.SMTP_LOCKED_MESSAGE), 'the page does not say SMTP is locked');
    assert.ok(/<fieldset[^>]*disabled/.test(page), 'the form is not disabled');
    assert.ok(!/paisans/i.test(page), 'the page names a particular deployment tool');
    await save(base, cookie, 'smtp.ui.test');
    assert.strictEqual(await host(), 'smtp.deploy.test');
  });

  // Seeded without SMTP: the UI owns it.
  await serve(withoutSmtp, async (base, cookie) => {
    const page = text(await (await fetch(base + '/settings/smtp', { headers: { cookie } })).text());
    assert.ok(!page.includes(seed.SMTP_LOCKED_MESSAGE));
    await save(base, cookie, 'smtp.ui.test');
    assert.strictEqual(await host(), 'smtp.ui.test');
  });
  console.log('ok');
}

main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1); });
