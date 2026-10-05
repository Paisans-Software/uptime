'use strict';

// Generic OpenID Connect login (authorization code flow + PKCE).
//
// Protocol work — discovery, state/nonce/PKCE checks, ID token signature and
// claim validation — is delegated to `openid-client`. This module only maps a
// validated identity onto a row in the `users` table:
//
//   1. a user already linked to this `sub`          → that user
//   2. exactly one unlinked user with the same,
//      provider-verified email address              → link `sub`, that user
//   3. OIDC_AUTO_CREATE (default on)                → new user
//
// Roles come from the groups claim when OIDC_ADMIN_GROUP / OIDC_EDITOR_GROUP
// are configured and are re-synced on every login. The env super-admin is
// never reachable through OIDC; it stays a password-only break-glass account.

const config = require('../config');
const logger = require('../logger');
const users = require('./users');

const CALLBACK_PATH = '/login/oidc/callback';

let clientLib = null;
let serverConfigPromise = null;

// openid-client v6 is ESM-only; load it lazily from this CommonJS module.
async function lib() {
  if (!clientLib) clientLib = await import('openid-client');
  return clientLib;
}

function redirectUri() {
  return `${config.publicBaseUrl}${CALLBACK_PATH}`;
}

// client_secret_basic with RFC 3986 percent-encoding. openid-client's built-in
// variant form-encodes the credentials (e.g. "-" → "%2D"), and providers that
// don't decode them — PocketID with its UUID client ids — reject the request.
function clientSecretBasic(clientId, clientSecret) {
  const creds = `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`;
  return (_as, _client, _body, headers) => {
    headers.set('authorization', `Basic ${Buffer.from(creds).toString('base64')}`);
  };
}

// Discovery is cached for the process lifetime. A failure is not cached, so a
// provider that was down at boot is picked up on the next login attempt.
async function serverConfig() {
  if (!serverConfigPromise) {
    serverConfigPromise = (async () => {
      const client = await lib();
      const issuer = new URL(config.oidc.issuer);
      const options = {};
      if (issuer.protocol === 'http:') {
        logger.warn({ issuer: issuer.href }, 'oidc.insecure_issuer');
        options.execute = [client.allowInsecureRequests];
      }
      const discovered = await client.discovery(issuer, config.oidc.clientId, undefined, client.None(), options);
      const meta = discovered.serverMetadata();
      // No client secret → public client (PKCE only). Otherwise use
      // client_secret_basic (the spec default) unless the provider only
      // advertises client_secret_post.
      let auth = client.None();
      let authMethod = 'none';
      if (config.oidc.clientSecret) {
        const supported = meta.token_endpoint_auth_methods_supported || ['client_secret_basic'];
        authMethod = !supported.includes('client_secret_basic') && supported.includes('client_secret_post')
          ? 'client_secret_post'
          : 'client_secret_basic';
        auth = authMethod === 'client_secret_post'
          ? client.ClientSecretPost(config.oidc.clientSecret)
          : clientSecretBasic(config.oidc.clientId, config.oidc.clientSecret);
      }
      const cfg = new client.Configuration(meta, config.oidc.clientId, undefined, auth);
      if (options.execute) client.allowInsecureRequests(cfg);
      logger.info({ issuer: issuer.href, authMethod }, 'oidc.discovery_ok');
      return cfg;
    })().catch((err) => {
      serverConfigPromise = null;
      throw err;
    });
  }
  return serverConfigPromise;
}

// Returns the provider URL to redirect to, plus the per-attempt secrets the
// caller must keep in the session until the callback.
async function beginLogin() {
  const client = await lib();
  const cfg = await serverConfig();
  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const url = client.buildAuthorizationUrl(cfg, {
    redirect_uri: redirectUri(),
    scope: config.oidc.scopes,
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
    nonce,
  });
  return { url: url.href, pending: { codeVerifier, state, nonce, ts: Date.now() } };
}

// Exchange the authorization code and return the merged ID token + userinfo
// claims. Throws on any validation failure.
async function finishLogin(originalUrl, pending) {
  const client = await lib();
  const cfg = await serverConfig();
  // Rebuild the callback URL from PUBLIC_BASE_URL rather than the Host header
  // so it matches the registered redirect URI behind a reverse proxy.
  const currentUrl = new URL(originalUrl, `${config.publicBaseUrl}/`);
  const tokens = await client.authorizationCodeGrant(cfg, currentUrl, {
    pkceCodeVerifier: pending.codeVerifier,
    expectedState: pending.state,
    expectedNonce: pending.nonce,
    idTokenExpected: true,
  });
  const claims = { ...tokens.claims() };
  // Some providers only put groups/email in the userinfo response.
  if (tokens.access_token && cfg.serverMetadata().userinfo_endpoint) {
    try {
      const info = await client.fetchUserInfo(cfg, tokens.access_token, claims.sub);
      for (const [k, v] of Object.entries(info)) {
        if (claims[k] === undefined) claims[k] = v;
      }
    } catch (err) {
      logger.warn({ err: err.message }, 'oidc.userinfo_failed');
    }
  }
  return claims;
}

function groupsFromClaims(claims) {
  const raw = claims[config.oidc.groupsClaim];
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw === 'string') return raw.split(/[\s,]+/).filter(Boolean);
  return [];
}

function roleMappingConfigured() {
  return !!(config.oidc.adminGroup || config.oidc.editorGroup);
}

function roleFromClaims(claims) {
  const groups = groupsFromClaims(claims);
  if (config.oidc.adminGroup && groups.includes(config.oidc.adminGroup)) return 'admin';
  if (config.oidc.editorGroup && groups.includes(config.oidc.editorGroup)) return 'editor';
  return users.validateRole(config.oidc.defaultRole);
}

// Resolve (and if allowed, provision) the DB user for a validated identity.
// Returns { user } or { error } with a message safe to show on the login page.
async function resolveUser(claims) {
  const sub = claims.sub ? String(claims.sub) : '';
  if (!sub) return { error: 'Identity provider did not return a subject' };
  const email = typeof claims.email === 'string' ? claims.email.trim() : null;
  const emailVerified = claims.email_verified === true || claims.email_verified === 'true';
  const role = roleFromClaims(claims);

  let user = await users.findByOidcSub(sub);
  let how = 'sub';

  if (!user && email && emailVerified) {
    const matches = await users.findUnlinkedByEmail(email);
    if (matches.length === 1) {
      if (!(await users.linkOidcSub(matches[0].id, sub))) {
        return { error: 'This account was just linked to another identity; please try again' };
      }
      user = matches[0];
      how = 'email_link';
      logger.info({ userId: user.id, username: user.username }, 'oidc.user_linked');
    } else if (matches.length > 1) {
      logger.warn({ email }, 'oidc.ambiguous_email');
      return { error: 'More than one account uses this email address; ask an admin to resolve it' };
    }
  }

  if (!user) {
    if (!config.oidc.autoCreate) {
      return { error: 'No account is linked to this identity' };
    }
    try {
      user = await users.createOidcUser({
        sub,
        preferredUsername: claims.preferred_username || claims.nickname || claims.name,
        email,
        displayName: claims.name || null,
        role,
      });
    } catch (err) {
      // A concurrent first login for the same identity won the insert
      // (unique index on oidc_sub, or the same derived username).
      const existing = await users.findByOidcSub(sub);
      if (!existing) throw err;
      return { user: existing, how: 'sub' };
    }
    how = 'created';
    logger.info({ userId: user.id, username: user.username, role }, 'oidc.user_created');
    return { user, how };
  }

  if (roleMappingConfigured() && user.role !== role) {
    await users.updateRole(user.id, role);
    logger.info({ userId: user.id, from: user.role, to: role }, 'oidc.role_synced');
    user = await users.getById(user.id);
  }
  return { user, how };
}

module.exports = {
  CALLBACK_PATH,
  redirectUri,
  beginLogin,
  finishLogin,
  resolveUser,
  roleFromClaims,
  groupsFromClaims,
};
