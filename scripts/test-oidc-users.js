#!/usr/bin/env node
'use strict';

// Exercises the OIDC identity → user mapping in src/lib/oidc.js against a
// throwaway SQLite database. No identity provider needed:
//
//   node scripts/test-oidc-users.js

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'uptime-oidc-'));
// Set before src/config loads; dotenv never overrides existing variables.
Object.assign(process.env, {
  DB_DRIVER: 'sqlite',
  SQLITE_PATH: path.join(dir, 'test.sqlite'),
  ADMIN_USER: 'admin',
  OIDC_ISSUER: 'https://id.example.test',
  OIDC_CLIENT_ID: 'test',
  OIDC_ADMIN_GROUP: 'uptime-admins',
  OIDC_EDITOR_GROUP: 'uptime-editors',
  OIDC_DEFAULT_ROLE: 'viewer',
  OIDC_AUTO_CREATE: 'true',
});

const db = require('../src/db');
const users = require('../src/lib/users');
const oidc = require('../src/lib/oidc');
const config = require('../src/config');

async function main() {
  await db.ensureSchema();
  await require('../src/lib/migrations').run();

  const bob = await users.create({ username: 'bob', password: 'password123', role: 'viewer', email: 'Bob@Example.com' });

  // Unverified email never links to an existing account.
  let r = await oidc.resolveUser({ sub: 's1', email: 'bob@example.com', email_verified: false, preferred_username: 'bob' });
  assert.strictEqual(r.how, 'created');
  assert.notStrictEqual(r.user.id, bob.id);
  assert.strictEqual(r.user.username, 'bob-2');

  // Verified email links to the single matching account; role from groups.
  r = await oidc.resolveUser({ sub: 's2', email: 'bob@example.com', email_verified: true, groups: ['uptime-editors'] });
  assert.strictEqual(r.how, 'email_link');
  assert.strictEqual(r.user.id, bob.id);
  assert.strictEqual(r.user.role, 'editor');

  // Later logins match on sub; admin group wins; leaving groups demotes.
  r = await oidc.resolveUser({ sub: 's2', groups: ['uptime-editors', 'uptime-admins'] });
  assert.strictEqual(r.how, 'sub');
  assert.strictEqual(r.user.role, 'admin');
  r = await oidc.resolveUser({ sub: 's2', groups: [] });
  assert.strictEqual(r.user.role, 'viewer');

  // Ambiguous verified email is refused rather than guessed.
  await users.create({ username: 'c1', password: 'password123', role: 'viewer', email: 'dup@example.com' });
  await users.create({ username: 'c2', password: 'password123', role: 'viewer', email: 'dup@example.com' });
  r = await oidc.resolveUser({ sub: 's3', email: 'dup@example.com', email_verified: true });
  assert.ok(r.error);

  // Usernames: reserved env-admin name, invalid characters, email fallback.
  r = await oidc.resolveUser({ sub: 's4', preferred_username: 'Admin' });
  assert.strictEqual(r.user.username, 'admin-2');
  r = await oidc.resolveUser({ sub: 's5', preferred_username: 'Jöhn Smith!' });
  assert.strictEqual(r.user.username, 'jhnsmith');
  r = await oidc.resolveUser({ sub: 's6', email: 'carol@example.com' });
  assert.strictEqual(r.user.username, 'carol');
  r = await oidc.resolveUser({ sub: 's7', preferred_username: 'x' });
  assert.strictEqual(r.user.username, 'user');

  // Missing subject is rejected.
  r = await oidc.resolveUser({});
  assert.ok(r.error);

  // Space- or comma-separated string groups claim.
  assert.deepStrictEqual(oidc.groupsFromClaims({ groups: 'a, b c' }), ['a', 'b', 'c']);

  // Parallel first logins for one identity yield a single account.
  const [p1, p2] = await Promise.all([
    oidc.resolveUser({ sub: 's9', preferred_username: 'erin' }),
    oidc.resolveUser({ sub: 's9', preferred_username: 'erin' }),
  ]);
  assert.strictEqual(p1.user.id, p2.user.id);

  // An existing link is never overwritten.
  assert.strictEqual(await users.linkOidcSub(bob.id, 'someone-else'), false);
  assert.strictEqual((await users.findByOidcSub('s2')).id, bob.id);

  // Auto-create off: unknown identities are refused.
  config.oidc.autoCreate = false;
  r = await oidc.resolveUser({ sub: 's8', preferred_username: 'dave' });
  assert.ok(r.error);
  config.oidc.autoCreate = true;

  console.log('oidc user mapping: all checks passed');
}

main()
  .then(() => { fs.rmSync(dir, { recursive: true, force: true }); process.exit(0); })
  .catch((err) => { console.error(err); fs.rmSync(dir, { recursive: true, force: true }); process.exit(1); });
