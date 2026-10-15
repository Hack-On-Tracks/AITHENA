#!/usr/bin/env node
// AITHENA central admin server (0 runtime dependencies)
// -----------------------------------------------------------------------------
// Responsibilities:
//   1. Serve the existing LeakLens static UI.
//   2. Enroll authorised devices (admin-authenticated) and issue per-device secrets.
//   3. Ingest authenticated telemetry from endpoint agents, isolated per device.
//   4. Score each device independently via the existing device-risk engine.
//   5. Push near-real-time updates to the admin UI over Server-Sent Events (SSE).
//   6. Expose an admin device registry with honest LIVE/STALE/OFFLINE status.
//
// Security posture:
//   - Admin API requires AITHENA_ADMIN_TOKEN (Bearer header, or ?token= for SSE).
//   - Agents authenticate with a per-device Bearer secret (hashed at rest).
//   - All telemetry is strictly validated; oversized bodies are rejected.
//   - Bounded in-memory retention; registry metadata optionally persisted.
//   - HTTPS when a cert/key is configured; otherwise HTTP for trusted LANs/VPNs
//     only, with a clear startup warning.
//   - NO enforcement/blocking/quarantine actions are performed by this server.
// -----------------------------------------------------------------------------
'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const auth = require('./lib/auth');
const validate = require('./lib/validate');
const { Store } = require('./lib/store');
const riskAdapter = require('./lib/risk-adapter');

// ---------------- configuration ----------------
function loadConfig() {
  const cfgPath = process.env.AITHENA_CONFIG || path.join(__dirname, 'config.json');
  let fileCfg = {};
  try { if (fs.existsSync(cfgPath)) fileCfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8')); } catch (e) {
    console.error('[config] failed to parse', cfgPath, e.message);
  }
  const cfg = {
    port: parseInt(process.env.PORT || fileCfg.port || '8443', 10),
    host: process.env.HOST || fileCfg.host || '0.0.0.0',
    adminToken: process.env.AITHENA_ADMIN_TOKEN || fileCfg.adminToken || null,
    staticRoot: path.resolve(__dirname, '..'),
    tlsKey: process.env.AITHENA_TLS_KEY || fileCfg.tlsKey || null,
    tlsCert: process.env.AITHENA_TLS_CERT || fileCfg.tlsCert || null,
    // An explicitly empty AITHENA_REGISTRY disables persistence (in-memory only).
    persistPath: process.env.AITHENA_REGISTRY === '' ? null
      : (process.env.AITHENA_REGISTRY || fileCfg.persistPath || path.join(__dirname, 'data', 'registry.json')),
    maxFlowsPerDevice: fileCfg.maxFlowsPerDevice || 2000,
    retentionMs: fileCfg.retentionMs || 6 * 60 * 60 * 1000,
    liveMs: fileCfg.liveMs || 30 * 1000,
    staleMs: fileCfg.staleMs || 120 * 1000,
    maxBodyBytes: fileCfg.maxBodyBytes || 512 * 1024,
    // CORS: agents may post from other hosts. Default same-origin only; set to a
    // list or "*" (not recommended) to allow browser cross-origin admin UIs.
    allowOrigins: fileCfg.allowOrigins || process.env.AITHENA_ALLOW_ORIGINS || null
  };
  if (!cfg.adminToken) {
    cfg.adminToken = auth.newToken(24);
    console.warn('\n[AITHENA] No AITHENA_ADMIN_TOKEN set. Generated an ephemeral admin token:\n');
    console.warn('    ' + cfg.adminToken + '\n');
    console.warn('[AITHENA] Set AITHENA_ADMIN_TOKEN in the environment to keep it stable across restarts.\n');
  }
  return cfg;
}

const CFG = loadConfig();
const store = new Store({
  maxFlowsPerDevice: CFG.maxFlowsPerDevice,
  retentionMs: CFG.retentionMs,
  liveMs: CFG.liveMs,
  staleMs: CFG.staleMs,
  persistPath: CFG.persistPath
});

// ---------------- SSE hub ----------------
const sseClients = new Set();
function sseBroadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch (e) { /* drop on next tick */ }
  }
}

// ---------------- helpers ----------------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2'
};

function sendJson(res, code, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  }, extraHeaders || {}));
  res.end(body);
}

function corsHeaders(req) {
  if (!CFG.allowOrigins) return {};
  const origin = req.headers.origin;
  if (CFG.allowOrigins === '*') {
    return { 'Access-Control-Allow-Origin': '*' };
  }
  const list = Array.isArray(CFG.allowOrigins) ? CFG.allowOrigins : String(CFG.allowOrigins).split(',');
  if (origin && list.indexOf(origin) >= 0) {
    return { 'Access-Control-Allow-Origin': origin, 'Vary': 'Origin' };
  }
  return {};
}

function isAdmin(req, url) {
  const token = auth.bearer(req.headers['authorization']) || url.searchParams.get('token');
  return token && auth.safeEqual(token, CFG.adminToken);
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > maxBytes) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve(null);
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new Error('invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// Re-score one device from its own flows and update registry + push.
function rescore(deviceId) {
  const d = store.getDevice(deviceId);
  if (!d) return null;
  const pub = store.registry().find(x => x.deviceId === deviceId);
  const flows = store.getFlows(deviceId);
  const risk = riskAdapter.scoreFromFlows(pub, flows);
  store.setRisk(deviceId, risk);
  return risk;
}

// ---------------- static serving ----------------
function serveStatic(req, res, url) {
  let reqPath = decodeURIComponent(url.pathname);
  if (reqPath === '/' || reqPath === '') reqPath = '/index.html';
  // prevent path traversal
  const safe = path.normalize(reqPath).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(CFG.staticRoot, safe);
  if (!filePath.startsWith(CFG.staticRoot)) { res.writeHead(403); res.end('forbidden'); return; }
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('404 Not Found'); return; }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff'
    });
    fs.createReadStream(filePath).pipe(res);
  });
}

// ---------------- request handler ----------------
async function handler(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS' && p.startsWith('/api/')) {
    res.writeHead(204, Object.assign({
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization,Content-Type',
      'Access-Control-Max-Age': '600'
    }, corsHeaders(req)));
    res.end();
    return;
  }

  // ---- API ----
  if (p.startsWith('/api/')) {
    try {
      // Health (public, no secrets)
      if (p === '/api/v1/health' && req.method === 'GET') {
        return sendJson(res, 200, { ok: true, time: Date.now(), devices: store.registry().length }, corsHeaders(req));
      }

      // Enroll a device (ADMIN)
      if (p === '/api/v1/enroll' && req.method === 'POST') {
        if (!isAdmin(req, url)) return sendJson(res, 401, { error: 'admin auth required' });
        const body = await readBody(req, CFG.maxBodyBytes);
        const v = validate.validateEnroll(body);
        if (!v.ok) return sendJson(res, 400, { error: v.reason });
        const out = store.enroll(v.enroll);
        sseBroadcast('device', { action: 'enrolled', device: out.device });
        // The plaintext secret is returned exactly once.
        return sendJson(res, 201, {
          deviceId: out.deviceId,
          agentSecret: out.secret,
          device: out.device,
          note: 'Store agentSecret now; it is not retrievable again. Put it in the agent config.'
        }, corsHeaders(req));
      }

      // Telemetry ingest (AGENT, per-device bearer secret)
      if (p === '/api/v1/telemetry' && req.method === 'POST') {
        const deviceId = url.searchParams.get('device') || (req.headers['x-device-id']);
        const secret = auth.bearer(req.headers['authorization']);
        if (!deviceId || !secret) return sendJson(res, 401, { error: 'device id and bearer secret required' });
        if (!store.authAgent(deviceId, secret)) return sendJson(res, 403, { error: 'agent authentication failed' });

        const body = await readBody(req, CFG.maxBodyBytes);
        const v = validate.validateBatch(body);
        if (!v.ok) return sendJson(res, 400, { error: v.reason });

        const r = store.ingest(deviceId, v.flows, v.agentMeta);
        if (!r.ok) return sendJson(res, 409, { error: r.reason });

        const risk = rescore(deviceId);
        const pub = store.registry().find(x => x.deviceId === deviceId);

        // Push live update to admin UIs — scoped to this device only.
        sseBroadcast('telemetry', { deviceId, flows: r.stored, device: pub, risk });

        return sendJson(res, 200, {
          ok: true, accepted: r.stored.length, rejected: v.rejected,
          device: pub, risk
        }, corsHeaders(req));
      }

      // Device registry (ADMIN)
      if (p === '/api/v1/devices' && req.method === 'GET') {
        if (!isAdmin(req, url)) return sendJson(res, 401, { error: 'admin auth required' });
        return sendJson(res, 200, { devices: store.registry() }, corsHeaders(req));
      }

      // Per-device flows (ADMIN)
      const mFlows = p.match(/^\/api\/v1\/devices\/([A-Za-z0-9_-]+)\/flows$/);
      if (mFlows && req.method === 'GET') {
        if (!isAdmin(req, url)) return sendJson(res, 401, { error: 'admin auth required' });
        const deviceId = mFlows[1];
        if (!store.getDevice(deviceId)) return sendJson(res, 404, { error: 'unknown device' });
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '200', 10) || 200, 2000);
        return sendJson(res, 200, {
          deviceId, flows: store.getFlows(deviceId, limit), risk: rescore(deviceId)
        }, corsHeaders(req));
      }

      // Revoke / deregister a device (ADMIN) — opt-in shutdown of telemetry
      const mRevoke = p.match(/^\/api\/v1\/devices\/([A-Za-z0-9_-]+)\/revoke$/);
      if (mRevoke && req.method === 'POST') {
        if (!isAdmin(req, url)) return sendJson(res, 401, { error: 'admin auth required' });
        const deviceId = mRevoke[1];
        if (!store.revoke(deviceId)) return sendJson(res, 404, { error: 'unknown device' });
        const pub = store.registry().find(x => x.deviceId === deviceId);
        sseBroadcast('device', { action: 'revoked', device: pub });
        return sendJson(res, 200, { ok: true, device: pub }, corsHeaders(req));
      }

      // SSE stream (ADMIN) — EventSource cannot set headers, so ?token= is accepted.
      if (p === '/api/v1/stream' && req.method === 'GET') {
        if (!isAdmin(req, url)) return sendJson(res, 401, { error: 'admin auth required' });
        res.writeHead(200, Object.assign({
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-transform',
          'Connection': 'keep-alive',
          'X-Accel-Buffering': 'no'
        }, corsHeaders(req)));
        res.write('retry: 3000\n\n');
        // initial snapshot (registry + recent flows per device)
        const snapshot = store.registry().map(d => ({
          device: d, risk: rescore(d.deviceId), flows: store.getFlows(d.deviceId, 50)
        }));
        res.write(`event: snapshot\ndata: ${JSON.stringify({ devices: snapshot, serverTime: Date.now() })}\n\n`);
        sseClients.add(res);
        const ka = setInterval(() => { try { res.write(': keepalive\n\n'); } catch (e) {} }, 15000);
        req.on('close', () => { clearInterval(ka); sseClients.delete(res); });
        return;
      }

      return sendJson(res, 404, { error: 'no such endpoint' });
    } catch (e) {
      const msg = e && e.message === 'body too large' ? 'request body too large'
        : e && e.message === 'invalid JSON' ? 'invalid JSON body' : 'server error';
      return sendJson(res, e && (e.message === 'body too large' || e.message === 'invalid JSON') ? 400 : 500, { error: msg });
    }
  }

  // ---- static ----
  if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, url);
  res.writeHead(405); res.end('method not allowed');
}

// ---------------- periodic status ticker ----------------
// Pushes registry status so LIVE->STALE->OFFLINE transitions reach the UI even
// when no new telemetry is arriving.
const _ticker = setInterval(() => {
  if (!sseClients.size) return;
  sseBroadcast('registry', { devices: store.registry(), serverTime: Date.now() });
}, 5000);
// Don't let the status ticker alone keep the process alive (e.g. under tests).
if (_ticker.unref) _ticker.unref();

// ---------------- boot ----------------
function start() {
  let server;
  if (CFG.tlsKey && CFG.tlsCert) {
    try {
      const opts = { key: fs.readFileSync(CFG.tlsKey), cert: fs.readFileSync(CFG.tlsCert) };
      server = https.createServer(opts, handler);
      console.log('[AITHENA] HTTPS enabled.');
    } catch (e) {
      console.error('[AITHENA] Failed to load TLS cert/key:', e.message);
      process.exit(1);
    }
  } else {
    server = http.createServer(handler);
    console.warn('[AITHENA] TLS NOT configured — running plain HTTP.');
    console.warn('[AITHENA] Use this only on a trusted LAN or inside a VPN. Set AITHENA_TLS_CERT/KEY for HTTPS.');
  }
  server.listen(CFG.port, CFG.host, () => {
    const proto = (CFG.tlsKey && CFG.tlsCert) ? 'https' : 'http';
    console.log(`[AITHENA] Admin server on ${proto}://${CFG.host}:${CFG.port}/`);
    console.log(`[AITHENA] Open the UI, then connect it with the admin token on the Live bar.`);
    console.log(`[AITHENA] Registry persistence: ${CFG.persistPath}`);
  });
}

if (require.main === module) start();
module.exports = { handler, store, CFG, rescore }; // exported for tests
