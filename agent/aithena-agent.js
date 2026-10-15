#!/usr/bin/env node
// AITHENA endpoint agent (0 runtime dependencies)
// =============================================================================
// Runs ON a participating laptop, WITH THE OWNER'S CONSENT, and reports that
// laptop's OWN outbound connection metadata to the AITHENA admin server.
//
// It does NOT, and cannot, capture any other machine's traffic. It reads only
// the local host's own socket table (via the OS's netstat/ss), the same list
// the owner can see by running those commands themselves. No packet payloads are
// read, captured, or transmitted — only connection metadata (remote IP, remote
// port, protocol-by-port, connection count, duration, and byte counts where the
// OS exposes them per connection).
//
// Usage:
//   node aithena-agent.js --config ./agent-config.json          # run
//   node aithena-agent.js --config ./agent-config.json --once    # single report
//   node aithena-agent.js --config ./agent-config.json --dry-run # print, don't send
//   node aithena-agent.js --uninstall --config ./agent-config.json
// =============================================================================
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const { execFile } = require('child_process');

const AGENT_VERSION = '1.0.0';

// ---------------- args & config ----------------
function parseArgs(argv) {
  const a = { config: path.join(__dirname, 'agent-config.json') };
  for (let i = 2; i < argv.length; i++) {
    const t = argv[i];
    if (t === '--config') a.config = argv[++i];
    else if (t === '--once') a.once = true;
    else if (t === '--dry-run') a.dryRun = true;
    else if (t === '--uninstall') a.uninstall = true;
    else if (t === '--yes' || t === '--i-consent') a.consentFlag = true;
  }
  return a;
}

function loadConfig(p) {
  if (!fs.existsSync(p)) {
    console.error('[agent] Config not found:', p);
    console.error('[agent] Run enroll.js on the admin server to generate one, or copy agent-config.example.json.');
    process.exit(2);
  }
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { console.error('[agent] Invalid config JSON:', e.message); process.exit(2); }
}

// ---------------- consent gate ----------------
function requireConsent(cfg, args) {
  const consented = cfg.consent === true || args.consentFlag === true;
  if (!consented) {
    console.error('\n==================== CONSENT REQUIRED ====================');
    console.error('This agent will report THIS laptop\'s own outbound connection');
    console.error('metadata (destination IP/port, protocol, counts, duration) to:');
    console.error('    ' + (cfg.serverUrl || '(server not set)'));
    console.error('It reads only this machine\'s own socket table. It does not');
    console.error('capture packet contents or any other device\'s traffic.');
    console.error('');
    console.error('To run, either set  "consent": true  in the config file, or');
    console.error('pass  --i-consent  on the command line. Stop any time with');
    console.error('Ctrl-C, or remove the agent with  --uninstall.');
    console.error('==========================================================\n');
    process.exit(3);
  }
}

// ---------------- local IP ----------------
function primaryIp() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const i of ifaces[name]) {
      if (i.family === 'IPv4' && !i.internal) return i.address;
    }
  }
  return null;
}

// ---------------- protocol by port (honest, metadata-only labelling) ----------------
const PORT_PROTO = {
  443: 'HTTPS/TLS', 8443: 'HTTPS/TLS (alt)', 80: 'HTTP', 8080: 'HTTP (alt)',
  53: 'DNS', 853: 'DNS-over-TLS', 123: 'NTP',
  22: 'SSH', 3389: 'RDP', 5900: 'VNC',
  993: 'IMAPS', 995: 'POP3S', 465: 'SMTPS', 587: 'SMTP (submission)', 25: 'SMTP',
  5223: 'Push (TLS)', 5228: 'Push', 51820: 'WireGuard', 1194: 'OpenVPN',
  500: 'IPsec IKE', 4500: 'IPsec NAT-T', 3478: 'STUN/TURN'
};
function protoFor(port, transport) {
  if (PORT_PROTO[port]) return PORT_PROTO[port];
  return (transport === 'udp' ? 'UDP/' : 'TCP/') + port;
}

// ---------------- address helpers ----------------
function isLocalAddr(ip) {
  if (!ip) return true;
  if (ip === '0.0.0.0' || ip === '::' || ip === '*') return true;
  if (ip === '127.0.0.1' || ip.startsWith('127.') || ip === '::1') return true;
  if (ip.startsWith('169.254.') || ip.toLowerCase().startsWith('fe80')) return true; // link-local
  return false;
}

// Split a netstat/ss "address:port" where address may be IPv6 (contains colons).
function splitAddr(s) {
  if (!s) return null;
  s = s.trim();
  // IPv6 with brackets: [::1]:443
  let m = s.match(/^\[(.+)\]:(\d+)$/);
  if (m) return { ip: m[1], port: parseInt(m[2], 10) };
  // Windows IPv6 without brackets uses %scope sometimes; and a.b.c.d:port
  const idx = s.lastIndexOf(':');
  if (idx < 0) return null;
  const ip = s.slice(0, idx);
  const port = parseInt(s.slice(idx + 1), 10);
  if (isNaN(port)) return null;
  return { ip: ip.replace(/%.*$/, ''), port };
}

function run(cmd, cmdArgs) {
  return new Promise(resolve => {
    execFile(cmd, cmdArgs, { timeout: 8000, maxBuffer: 8 * 1024 * 1024, windowsHide: true },
      (err, stdout) => resolve(err ? '' : (stdout || '')));
  });
}

// ---------------- collectors (per OS) ----------------
// Each returns an array of { ip, port, transport, state, bytesOut, bytesIn }.

// Parse hex "address:port" from /proc/net/{tcp,udp}. Handles IPv4 and IPv6.
function parseProcHexAddr(hex) {
  const [addrHex, portHex] = hex.split(':');
  const port = parseInt(portHex, 16);
  if (isNaN(port)) return null;
  let ip;
  if (addrHex.length === 8) {
    // IPv4, little-endian per word
    const b = addrHex.match(/../g).reverse().map(h => parseInt(h, 16));
    ip = b.join('.');
  } else if (addrHex.length === 32) {
    // IPv6: 4 little-endian 32-bit words
    const words = [];
    for (let i = 0; i < 32; i += 8) {
      const w = addrHex.slice(i, i + 8).match(/../g).reverse().join('');
      words.push(w.slice(0, 4), w.slice(4, 8));
    }
    ip = words.join(':').replace(/(^|:)0+(?=[0-9a-f])/g, '$1');
  } else return null;
  return { ip, port };
}

function readProcNet(file, transport, estOnly) {
  const conns = [];
  let text = '';
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { return conns; }
  const lines = text.split('\n').slice(1);
  for (const line of lines) {
    const p = line.trim().split(/\s+/);
    if (p.length < 4) continue;
    const st = p[3];
    if (estOnly && st !== '01') continue; // 01 = ESTABLISHED
    const rem = parseProcHexAddr(p[2]);
    if (!rem || isLocalAddr(rem.ip) || rem.port === 0) continue;
    conns.push({ ip: rem.ip, port: rem.port, transport, state: 'ESTAB', bytesOut: null, bytesIn: null });
  }
  return conns;
}

// Dependency-free Linux collector via /proc/net (no ss/netstat binary required).
function collectProcNet() {
  let conns = [];
  conns = conns.concat(readProcNet('/proc/net/tcp', 'tcp', true));
  conns = conns.concat(readProcNet('/proc/net/tcp6', 'tcp', true));
  // UDP has no connection state; include entries with a real remote peer.
  conns = conns.concat(readProcNet('/proc/net/udp', 'udp', false).filter(c => c.ip !== '0.0.0.0'));
  conns = conns.concat(readProcNet('/proc/net/udp6', 'udp', false));
  return conns;
}

async function collectLinux() {
  // Prefer ss -tin for per-socket byte counters; fall back to /proc/net, then netstat.
  let out = await run('ss', ['-tunH', 'state', 'established']);
  const conns = [];
  if (out) {
    // ss -tin gives a socket line then (sometimes) an indented info line.
    const full = await run('ss', ['-tin']);
    const byteMap = parseSsBytes(full);
    out.split('\n').forEach(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 5) return;
      const transport = parts[0] === 'udp' ? 'udp' : 'tcp';
      const peer = splitAddr(parts[parts.length - 1]);
      if (!peer || isLocalAddr(peer.ip)) return;
      const key = peer.ip + ':' + peer.port;
      const b = byteMap[key] || {};
      conns.push({ ip: peer.ip, port: peer.port, transport, state: 'ESTAB', bytesOut: b.sent != null ? b.sent : null, bytesIn: b.recv != null ? b.recv : null });
    });
    return conns;
  }
  // No ss binary: use /proc/net directly (dependency-free), then netstat as last resort.
  const procConns = collectProcNet();
  if (procConns.length) return procConns;
  return collectNetstatGeneric();
}

// Parse `ss -tin` to map "peerIp:port" -> {sent, recv} from bytes_sent/bytes_received.
function parseSsBytes(text) {
  const map = {};
  if (!text) return map;
  const lines = text.split('\n');
  let curKey = null;
  for (const line of lines) {
    if (!/^\s/.test(line)) {
      const parts = line.trim().split(/\s+/);
      const peer = splitAddr(parts[parts.length - 1]);
      curKey = peer && !isLocalAddr(peer.ip) ? peer.ip + ':' + peer.port : null;
    } else if (curKey) {
      const sent = line.match(/bytes_sent:(\d+)/);
      const recv = line.match(/bytes_received:(\d+)/);
      if (sent || recv) {
        map[curKey] = { sent: sent ? +sent[1] : null, recv: recv ? +recv[1] : null };
      }
    }
  }
  return map;
}

async function collectWindows() {
  // netstat -n -p TCP / UDP. No per-connection bytes on Windows without ETW,
  // so bytesOut/bytesIn are left null (honest "unavailable").
  const conns = [];
  for (const proto of ['TCP', 'UDP']) {
    const out = await run('netstat', ['-n', '-p', proto]);
    out.split('\n').forEach(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 3) return;
      if (!/^(TCP|UDP)$/i.test(parts[0])) return;
      const transport = parts[0].toLowerCase() === 'udp' ? 'udp' : 'tcp';
      const peer = splitAddr(parts[2]);
      const state = parts[3] || (transport === 'udp' ? '' : '');
      if (transport === 'tcp' && state && !/ESTABLISHED/i.test(state)) return;
      if (!peer || isLocalAddr(peer.ip) || peer.port === 0) return;
      conns.push({ ip: peer.ip, port: peer.port, transport, state: state || 'ESTAB', bytesOut: null, bytesIn: null });
    });
  }
  return conns;
}

async function collectNetstatGeneric() {
  // macOS / BSD / fallback: netstat -n ; bytes not available per connection.
  const conns = [];
  const out = await run('netstat', ['-n']);
  out.split('\n').forEach(line => {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) return;
    if (!/^(tcp|udp)/i.test(parts[0])) return;
    const transport = /udp/i.test(parts[0]) ? 'udp' : 'tcp';
    // macOS format: proto recvq sendq localaddr foreignaddr state
    const peer = splitAddr(parts[4]) || splitAddr(parts[3]);
    const state = parts[5] || '';
    if (transport === 'tcp' && state && !/ESTABLISHED/i.test(state)) return;
    if (!peer || isLocalAddr(peer.ip) || peer.port === 0) return;
    conns.push({ ip: peer.ip, port: peer.port, transport, state: state || 'ESTAB', bytesOut: null, bytesIn: null });
  });
  return conns;
}

function pickCollector() {
  const plat = process.platform;
  if (plat === 'win32') return { fn: collectWindows, name: 'netstat(win)', bytes: false };
  if (plat === 'linux') return { fn: collectLinux, name: 'ss/procnet(linux)', bytes: true };
  if (plat === 'darwin') return { fn: collectNetstatGeneric, name: 'netstat(macos)', bytes: false };
  return { fn: collectNetstatGeneric, name: 'netstat(generic)', bytes: false };
}

// ---------------- aggregation with persistent first-seen for duration ----------------
const firstSeen = new Map(); // key -> ts of first observation (this agent run)

function aggregate(conns) {
  const now = Date.now();
  const groups = new Map();
  conns.forEach(c => {
    const key = c.transport + '|' + c.ip + '|' + c.port;
    if (!groups.has(key)) {
      groups.set(key, { ip: c.ip, port: c.port, transport: c.transport, state: c.state, count: 0, bytesOut: null, bytesIn: null });
    }
    const g = groups.get(key);
    g.count += 1;
    if (c.bytesOut != null) g.bytesOut = (g.bytesOut || 0) + c.bytesOut;
    if (c.bytesIn != null) g.bytesIn = (g.bytesIn || 0) + c.bytesIn;
  });

  // prune first-seen entries that are no longer active
  const activeKeys = new Set(groups.keys());
  for (const k of firstSeen.keys()) if (!activeKeys.has(k)) firstSeen.delete(k);

  const flows = [];
  for (const [key, g] of groups) {
    if (!firstSeen.has(key)) firstSeen.set(key, now);
    const durationSec = Math.max(0, Math.round((now - firstSeen.get(key)) / 1000));
    flows.push({
      ts: now,
      dest: g.ip,
      destPort: g.port,
      transport: g.transport,
      protocol: protoFor(g.port, g.transport),
      connectionCount: g.count,
      durationSec,
      bytesOut: g.bytesOut,
      bytesIn: g.bytesIn,
      state: g.state
    });
  }
  return flows;
}

// ---------------- send ----------------
function send(cfg, batch) {
  return new Promise((resolve, reject) => {
    const url = new URL(cfg.serverUrl.replace(/\/$/, '') + '/api/v1/telemetry?device=' + encodeURIComponent(cfg.deviceId));
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;
    const data = Buffer.from(JSON.stringify(batch));
    const opts = {
      method: 'POST',
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length,
        'Authorization': 'Bearer ' + cfg.agentSecret
      },
      timeout: 10000
    };
    if (isHttps) {
      if (cfg.caCertPath && fs.existsSync(cfg.caCertPath)) {
        opts.ca = fs.readFileSync(cfg.caCertPath); // trust the lab's own CA properly
      } else if (cfg.allowSelfSigned === true) {
        opts.rejectUnauthorized = false; // lab fallback only; warn once
        if (!send._warned) { console.warn('[agent] WARNING: TLS verification disabled (allowSelfSigned). Use caCertPath in production.'); send._warned = true; }
      }
    }
    const req = lib.request(opts, res => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(body)); } catch (e) { resolve({ ok: true }); }
        } else {
          reject(new Error('server ' + res.statusCode + ': ' + body.slice(0, 200)));
        }
      });
    });
    req.on('timeout', () => { req.destroy(new Error('request timeout')); });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// ---------------- one reporting cycle ----------------
async function cycle(cfg, collector, args) {
  const conns = await collector.fn();
  const flows = aggregate(conns);
  // Honest byte availability: based on whether any flow actually carried counts,
  // not a static assumption (e.g. Linux without `ss` yields no per-flow bytes).
  const bytesAvailable = flows.some(f => f.bytesOut != null);
  const batch = {
    agentVersion: AGENT_VERSION,
    hostname: os.hostname(),
    reportedIp: primaryIp(),
    os: process.platform + ' ' + os.release(),
    collector: collector.name,
    telemetryHealth: { endpoint: 'ok', bytes: bytesAvailable ? 'ok' : 'unavailable' },
    flows
  };

  if (args.dryRun) {
    console.log('[agent] (dry-run) would send', flows.length, 'flows:');
    console.log(JSON.stringify(batch, null, 2));
    return;
  }
  try {
    const resp = await send(cfg, batch);
    console.log(`[agent] sent ${flows.length} flow(s) for ${cfg.deviceId}; server accepted ${resp.accepted != null ? resp.accepted : '?'}${resp.risk ? `, risk ${resp.risk.severity} (${resp.risk.score})` : ''}`);
  } catch (e) {
    console.error('[agent] send failed:', e.message);
  }
}

// ---------------- uninstall ----------------
function uninstall(cfg, args) {
  console.log('[agent] Uninstall requested.');
  console.log('[agent] 1. Stopping agent (this process will exit).');
  console.log('[agent] 2. To stop reporting permanently, also remove any scheduled task/service you created');
  console.log('          (Windows: schtasks /Delete /TN AithenaAgent /F).');
  console.log('[agent] 3. Ask the admin to REVOKE ' + (cfg.deviceId || 'this device') + ' on the server so its');
  console.log('          secret can no longer authenticate (admin: POST /api/v1/devices/<id>/revoke).');
  try {
    if (args.config && fs.existsSync(args.config) && cfg.deleteConfigOnUninstall !== false) {
      fs.unlinkSync(args.config);
      console.log('[agent] Removed local config:', args.config);
    }
  } catch (e) { console.error('[agent] Could not remove config:', e.message); }
  process.exit(0);
}

// ---------------- main ----------------
async function main() {
  const args = parseArgs(process.argv);
  const cfg = loadConfig(args.config);

  if (args.uninstall) return uninstall(cfg, args);

  if (!cfg.serverUrl || !cfg.deviceId || !cfg.agentSecret) {
    console.error('[agent] Config must include serverUrl, deviceId and agentSecret.');
    process.exit(2);
  }
  requireConsent(cfg, args);

  const collector = pickCollector();
  const intervalSec = Math.max(5, parseInt(cfg.intervalSec || 10, 10));

  console.log(`[agent] AITHENA agent ${AGENT_VERSION} starting.`);
  console.log(`[agent] device=${cfg.deviceId} host=${os.hostname()} ip=${primaryIp()} os=${process.platform}`);
  console.log(`[agent] collector=${collector.name} bytes=${collector.bytes ? 'available' : 'unavailable'} interval=${intervalSec}s`);
  console.log(`[agent] server=${cfg.serverUrl}`);

  let stopping = false;
  const shutdown = () => {
    if (stopping) return; stopping = true;
    console.log('\n[agent] Shutting down (opt-out). Server will show this device as OFFLINE shortly.');
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  await cycle(cfg, collector, args);
  if (args.once || args.dryRun) return;

  const tick = async () => {
    if (stopping) return;
    await cycle(cfg, collector, args);
    if (!stopping) setTimeout(tick, intervalSec * 1000);
  };
  setTimeout(tick, intervalSec * 1000);
}

if (require.main === module) {
  main().catch(e => { console.error('[agent] fatal:', e.message); process.exit(1); });
}
module.exports = { aggregate, splitAddr, protoFor, isLocalAddr, parseSsBytes, pickCollector };
