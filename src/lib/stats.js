'use strict';

const db = require('../db');

async function uptimePct(siteId, hours) {
  const rows = await db.query(
    `SELECT
       SUM(CASE WHEN is_up = 1 THEN 1 ELSE 0 END) AS up_count,
       SUM(CASE WHEN is_up = 0 THEN 1 ELSE 0 END) AS down_count
     FROM checks
     WHERE site_id = ? AND checked_at > ${db.intervalAgoSql()} AND is_up IS NOT NULL`,
    [siteId, hours]
  );
  const r = rows[0] || {};
  const up = Number(r.up_count || 0);
  const down = Number(r.down_count || 0);
  const total = up + down;
  if (!total) return null;
  return (up / total) * 100;
}

// Batched variant for pages that render many monitors at once (public status
// page, dashboard): one grouped scan instead of a query per monitor.
// Returns Map<siteId, pct|null>.
async function uptimePctForSites(siteIds, hours) {
  const out = new Map();
  if (!siteIds || !siteIds.length) return out;
  const ph = siteIds.map(() => '?').join(',');
  const rows = await db.query(
    `SELECT site_id,
            SUM(CASE WHEN is_up = 1 THEN 1 ELSE 0 END) AS up_count,
            SUM(CASE WHEN is_up = 0 THEN 1 ELSE 0 END) AS down_count
       FROM checks
      WHERE site_id IN (${ph}) AND checked_at > ${db.intervalAgoSql()} AND is_up IS NOT NULL
      GROUP BY site_id`,
    [...siteIds, hours]
  );
  for (const r of rows) {
    const up = Number(r.up_count || 0);
    const down = Number(r.down_count || 0);
    const total = up + down;
    out.set(Number(r.site_id), total ? (up / total) * 100 : null);
  }
  return out;
}

async function responseTimeStats(siteId, hours) {
  const rows = await db.query(
    `SELECT response_time_ms FROM checks
     WHERE site_id = ? AND is_up = 1 AND response_time_ms IS NOT NULL
       AND checked_at > ${db.intervalAgoSql()}
     ORDER BY response_time_ms ASC`,
    [siteId, hours]
  );
  if (!rows.length) return null;
  const arr = rows.map((r) => r.response_time_ms);
  const sum = arr.reduce((a, b) => a + b, 0);
  const avg = sum / arr.length;
  // Nearest-rank percentile: rank = ceil(q * n), 1-indexed → clamp to [1, n].
  const p = (q) => {
    const rank = Math.max(1, Math.min(arr.length, Math.ceil(q * arr.length)));
    return arr[rank - 1];
  };
  return {
    count: arr.length,
    min: arr[0],
    max: arr[arr.length - 1],
    avg: Math.round(avg),
    p50: p(0.5),
    p95: p(0.95),
  };
}

async function recentChecks(siteId, limit = 50) {
  return db.query(
    `SELECT id, checked_at, is_up, status_code, response_time_ms, error_message
     FROM checks WHERE site_id = ? ORDER BY checked_at DESC LIMIT ?`,
    [siteId, limit]
  );
}

async function timeseries(siteId, hours, bucketMinutes = 5) {
  const rows = await db.query(
    `SELECT
       ${db.bucketTimeSql('checked_at')} AS bucket,
       AVG(response_time_ms) AS avg_ms,
       SUM(CASE WHEN is_up = 1 THEN 1 ELSE 0 END) AS up_count,
       SUM(CASE WHEN is_up = 0 THEN 1 ELSE 0 END) AS down_count,
       SUM(CASE WHEN is_up IS NULL THEN 1 ELSE 0 END) AS inconclusive_count
     FROM checks
     WHERE site_id = ? AND checked_at > ${db.intervalAgoSql()}
     GROUP BY bucket
     ORDER BY bucket ASC`,
    [bucketMinutes, bucketMinutes, siteId, hours]
  );
  return rows.map((r) => ({
    bucket: r.bucket,
    avgMs: r.avg_ms == null ? null : Math.round(Number(r.avg_ms)),
    up: Number(r.up_count || 0),
    down: Number(r.down_count || 0),
    inconclusive: Number(r.inconclusive_count || 0),
  }));
}

async function recentIncidents(siteId, limit = 25) {
  return db.query(
    `SELECT id, started_at, ended_at, duration_seconds, last_error
     FROM incidents WHERE site_id = ?
     ORDER BY started_at DESC LIMIT ?`,
    [siteId, limit]
  );
}

async function totalDowntimeSeconds(siteId, hours) {
  const rows = await db.query(
    `SELECT COALESCE(SUM(
       CASE
         WHEN ended_at IS NULL THEN ${db.diffSecondsSql(db.greatestSql('started_at', db.intervalAgoSql()), db.nowMs())}
         ELSE ${db.diffSecondsSql(db.greatestSql('started_at', db.intervalAgoSql()), 'ended_at')}
       END
     ), 0) AS total_sec
     FROM incidents
     WHERE site_id = ? AND (ended_at IS NULL OR ended_at > ${db.intervalAgoSql()})`,
    [hours, hours, siteId, hours]
  );
  return Number(rows[0]?.total_sec || 0);
}

async function lastCheck(siteId) {
  const rows = await db.query(
    `SELECT checked_at, is_up, status_code, response_time_ms, error_message
     FROM checks WHERE site_id = ? ORDER BY checked_at DESC LIMIT 1`,
    [siteId]
  );
  return rows[0] || null;
}

// Per-day uptime bucket for the public status page.
// Returns an array of { date: 'YYYY-MM-DD', total, up, down, uptime_pct }
// ordered oldest first. Days with no probes get uptime_pct = null.
//
// Performance: with N days of minute-level checks this used to scan every
// row in the window on every page view (hundreds of ms per monitor at 90
// days). Completed days are immutable, so their aggregates are computed once
// per UTC day and memoized; only *today's* bucket is queried live. The cache
// self-invalidates when the UTC date (or requested window) changes.
const dailyCache = new Map(); // siteId -> { key, byDay: Map<day, agg> }

function aggRow(r) {
  const up = Number(r.up_count || 0);
  const down = Number(r.down_count || 0);
  const total = up + down;
  return {
    total,
    up,
    down,
    inconclusive: Number(r.inconclusive_count || 0),
    uptime_pct: total ? (up / total) * 100 : null,
  };
}

function invalidateDailyCache(siteId) {
  if (siteId == null) dailyCache.clear();
  else dailyCache.delete(Number(siteId));
}

async function dailyUptime(siteId, days = 90) {
  const dayExprByDialect = db.dialect === 'sqlite'
    ? `substr(checked_at, 1, 10)`
    : `DATE_FORMAT(checked_at, '%Y-%m-%d')`;
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  const todayIso = today.toISOString().slice(0, 10);
  // MySQL DATETIME comparisons need a driver-friendly literal; SQLite stores
  // ISO strings so the same boundary works lexicographically for both.
  const todayStart = db.dialect === 'sqlite'
    ? `${todayIso}T00:00:00.000Z`
    : `${todayIso} 00:00:00`;

  const cacheKey = `${todayIso}:${days}`;
  let cached = dailyCache.get(Number(siteId));
  if (!cached || cached.key !== cacheKey) {
    // (Re)build the immutable part: all completed days in the window.
    const rows = await db.query(
      `SELECT ${dayExprByDialect} AS day,
              SUM(CASE WHEN is_up = 1 THEN 1 ELSE 0 END) AS up_count,
              SUM(CASE WHEN is_up = 0 THEN 1 ELSE 0 END) AS down_count,
              SUM(CASE WHEN is_up IS NULL THEN 1 ELSE 0 END) AS inconclusive_count
       FROM checks
       WHERE site_id = ? AND checked_at > ${db.intervalAgoSql()} AND checked_at < ?
       GROUP BY day
       ORDER BY day ASC`,
      [siteId, days * 24, todayStart]
    );
    const byDay = new Map();
    for (const r of rows) byDay.set(r.day, aggRow(r));
    cached = { key: cacheKey, byDay };
    dailyCache.set(Number(siteId), cached);
  }

  // Today's bucket is always queried live — it's a single small index range.
  const todayRows = await db.query(
    `SELECT SUM(CASE WHEN is_up = 1 THEN 1 ELSE 0 END) AS up_count,
            SUM(CASE WHEN is_up = 0 THEN 1 ELSE 0 END) AS down_count,
            SUM(CASE WHEN is_up IS NULL THEN 1 ELSE 0 END) AS inconclusive_count
     FROM checks
     WHERE site_id = ? AND checked_at >= ?`,
    [siteId, todayStart]
  );
  const todayAgg = aggRow(todayRows[0] || {});

  const out = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setUTCDate(d.getUTCDate() - i);
    const iso = d.toISOString().slice(0, 10);
    if (iso === todayIso) {
      out.push({ date: iso, ...todayAgg });
    } else {
      out.push({ date: iso, ...(cached.byDay.get(iso) || { total: 0, up: 0, down: 0, inconclusive: 0, uptime_pct: null }) });
    }
  }
  return out;
}

// Most recent N incidents across all sites (newest first), for the public
// status page feed/RSS.
async function recentIncidentsGlobal(limit = 25) {
  return db.query(
    `SELECT i.id, i.site_id, i.started_at, i.ended_at, i.duration_seconds, i.last_error,
            s.name AS site_name, s.display_name AS site_display_name, s.url AS site_url,
            s.status_page_group, s.status_page_excluded
       FROM incidents i
       JOIN sites s ON s.id = i.site_id
      WHERE s.status_page_excluded = 0
      ORDER BY i.started_at DESC
      LIMIT ?`,
    [limit]
  );
}

module.exports = {
  uptimePct,
  uptimePctForSites,
  responseTimeStats,
  recentChecks,
  recentIncidents,
  recentIncidentsGlobal,
  totalDowntimeSeconds,
  timeseries,
  lastCheck,
  dailyUptime,
  invalidateDailyCache,
};
