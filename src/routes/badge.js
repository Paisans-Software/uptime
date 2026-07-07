'use strict';

// Public, embeddable SVG status badges (shields.io style). Mounted before the
// auth gate so they can be dropped into READMEs / external dashboards. They
// expose only what a public status page would (state + uptime %), keyed by
// monitor id — no config, no history, no secrets.

const express = require('express');
const db = require('../db');
const stats = require('../lib/stats');
const { renderBadge } = require('../lib/svgBadge');

const router = express.Router();

function sendBadge(res, badge, { status = 200 } = {}) {
  res.status(status);
  res.set('Content-Type', 'image/svg+xml; charset=utf-8');
  // Short cache so embeds stay roughly live without hammering us. no-transform
  // stops proxies/CDNs from mangling the SVG.
  res.set('Cache-Control', 'public, max-age=60, no-transform');
  res.send(badge);
}

async function loadSite(id) {
  if (!Number.isInteger(id) || id <= 0) return null;
  const rows = await db.query(
    'SELECT id, current_state, paused, monitor_type, status_page_excluded FROM sites WHERE id = ? LIMIT 1',
    [id]
  );
  const site = rows[0] || null;
  // Badges are public, so a monitor hidden from the status page must not leak
  // its state here either — treat it as if it doesn't exist.
  if (site && site.status_page_excluded) return null;
  return site;
}

router.get('/badge/:id/status.svg', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const label = (req.query.label || 'status').toString().slice(0, 40);
  let site;
  try { site = await loadSite(id); }
  catch { return sendBadge(res, renderBadge({ label, message: 'error', color: 'lightgrey' }), { status: 500 }); }

  if (!site) {
    return sendBadge(res, renderBadge({ label, message: 'not found', color: 'lightgrey' }), { status: 404 });
  }

  let message = 'unknown';
  let color = 'lightgrey';
  if (site.paused) {
    message = 'paused';
    color = 'lightgrey';
  } else if (site.current_state === 'up') {
    message = 'up';
    color = 'brightgreen';
  } else if (site.current_state === 'down') {
    message = 'down';
    color = 'red';
  }
  sendBadge(res, renderBadge({ label, message, color }));
});

router.get('/badge/:id/uptime.svg', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const label = (req.query.label || 'uptime').toString().slice(0, 40);
  let hours = parseInt(req.query.hours, 10);
  if (!Number.isFinite(hours) || hours <= 0) hours = 24;
  hours = Math.min(hours, 24 * 365); // cap at 1 year

  let site;
  try { site = await loadSite(id); }
  catch { return sendBadge(res, renderBadge({ label, message: 'error', color: 'lightgrey' }), { status: 500 }); }

  if (!site) {
    return sendBadge(res, renderBadge({ label, message: 'not found', color: 'lightgrey' }), { status: 404 });
  }

  let pct = null;
  try { pct = await stats.uptimePct(id, hours); }
  catch { /* fall through to n/a */ }

  if (pct == null) {
    return sendBadge(res, renderBadge({ label, message: 'n/a', color: 'lightgrey' }));
  }

  const rounded = Math.round(pct * 100) / 100;
  let color = 'red';
  if (rounded >= 99.9) color = 'brightgreen';
  else if (rounded >= 99) color = 'green';
  else if (rounded >= 95) color = 'yellow';
  else if (rounded >= 90) color = 'orange';
  sendBadge(res, renderBadge({ label, message: `${rounded}%`, color }));
});

module.exports = router;
