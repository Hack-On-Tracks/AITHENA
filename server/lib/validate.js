// AITHENA live telemetry — strict input validation (0 dependencies)
// Every field arriving from an agent is validated and coerced here before it is
// stored or scored. Unknown fields are dropped; bad records are rejected with a
// reason. Nothing from the network is trusted as-is.
'use strict';

const MAX_FLOWS_PER_BATCH = 500;
const MAX_STR = 256;

function isFiniteNum(n) { return typeof n === 'number' && isFinite(n); }

function clampStr(v, max) {
  if (v == null) return '';
  const s = String(v);
  return s.length > (max || MAX_STR) ? s.slice(0, max || MAX_STR) : s;
}

// A destination may be an IPv4/IPv6 literal or a hostname. We validate shape but
// keep it a string; no DNS or network action is taken on it.
function validDest(v) {
  if (typeof v !== 'string') return false;
  if (v.length === 0 || v.length > MAX_STR) return false;
  // Reject control characters / whitespace injection.
  return !/[\s\u0000-\u001f]/.test(v);
}

function validPort(p) {
  return Number.isInteger(p) && p >= 0 && p <= 65535;
}

const PROTO_OK = /^[A-Za-z0-9 ._:+()\/-]{1,48}$/;

// Validate & normalise a single flow record from an agent.
// Returns { ok:true, flow } or { ok:false, reason }.
function validateFlow(raw) {
  if (!raw || typeof raw !== 'object') return { ok: false, reason: 'flow not an object' };

  if (!validDest(raw.dest)) return { ok: false, reason: 'invalid dest' };
  if (!validPort(raw.destPort)) return { ok: false, reason: 'invalid destPort' };

  const ts = isFiniteNum(raw.ts) ? raw.ts : Date.now();
  // Reject absurd timestamps (more than 1 day in the future or 30 days old).
  const now = Date.now();
  if (ts > now + 86400000 || ts < now - 30 * 86400000) {
    return { ok: false, reason: 'timestamp out of range' };
  }

  const flow = {
    ts,
    dest: clampStr(raw.dest),
    destPort: raw.destPort,
    protocol: (typeof raw.protocol === 'string' && PROTO_OK.test(raw.protocol)) ? raw.protocol : 'TCP',
    transport: raw.transport === 'udp' ? 'udp' : 'tcp',
    connectionCount: Number.isInteger(raw.connectionCount) && raw.connectionCount >= 0
      ? Math.min(raw.connectionCount, 1e6) : 1,
    durationSec: isFiniteNum(raw.durationSec) && raw.durationSec >= 0
      ? Math.min(raw.durationSec, 2592000) : null,
    // Bytes are "where available"; null is an honest unknown, never coerced to 0.
    bytesOut: isFiniteNum(raw.bytesOut) && raw.bytesOut >= 0 ? Math.round(raw.bytesOut) : null,
    bytesIn: isFiniteNum(raw.bytesIn) && raw.bytesIn >= 0 ? Math.round(raw.bytesIn) : null,
    packetsOut: isFiniteNum(raw.packetsOut) && raw.packetsOut >= 0 ? Math.round(raw.packetsOut) : null,
    packetsIn: isFiniteNum(raw.packetsIn) && raw.packetsIn >= 0 ? Math.round(raw.packetsIn) : null,
    state: clampStr(raw.state, 32),
    provenance: 'reported'
  };
  return { ok: true, flow };
}

// Validate a whole telemetry batch body.
function validateBatch(body) {
  if (!body || typeof body !== 'object') return { ok: false, reason: 'body not an object' };
  if (!Array.isArray(body.flows)) return { ok: false, reason: 'flows must be an array' };
  if (body.flows.length > MAX_FLOWS_PER_BATCH) {
    return { ok: false, reason: 'too many flows in batch (max ' + MAX_FLOWS_PER_BATCH + ')' };
  }

  const flows = [];
  const rejected = [];
  body.flows.forEach((f, i) => {
    const r = validateFlow(f);
    if (r.ok) flows.push(r.flow);
    else rejected.push({ index: i, reason: r.reason });
  });

  const agentMeta = {
    agentVersion: clampStr(body.agentVersion, 32),
    hostname: clampStr(body.hostname, 128),
    reportedIp: validDest(body.reportedIp) ? clampStr(body.reportedIp) : null,
    os: clampStr(body.os, 64),
    collector: clampStr(body.collector, 64),
    // Telemetry self-health as reported by the agent (e.g. bytes unavailable on this OS).
    telemetryHealth: (body.telemetryHealth && typeof body.telemetryHealth === 'object')
      ? sanitizeHealth(body.telemetryHealth) : null
  };

  return { ok: true, flows, rejected, agentMeta };
}

function sanitizeHealth(h) {
  const out = {};
  ['endpoint', 'flow', 'idp', 'vpn', 'mdm', 'bytes'].forEach(k => {
    if (typeof h[k] === 'string') out[k] = clampStr(h[k], 16);
  });
  return out;
}

// Validate an enrollment request body (admin-initiated).
function validateEnroll(body) {
  if (!body || typeof body !== 'object') return { ok: false, reason: 'body not an object' };
  const label = clampStr(body.label, 64).trim();
  const assignedUser = clampStr(body.assignedUser, 64).trim();
  const department = clampStr(body.department, 64).trim();
  if (!label) return { ok: false, reason: 'label required' };
  const trusted = Array.isArray(body.trustedNetworks)
    ? body.trustedNetworks.filter(x => typeof x === 'string').slice(0, 16).map(x => clampStr(x, 32))
    : ['corp_wifi'];
  return {
    ok: true,
    enroll: {
      label,
      assignedUser: assignedUser || label,
      department: department || 'Unassigned',
      trustedNetworks: trusted.length ? trusted : ['corp_wifi']
    }
  };
}

module.exports = {
  validateFlow, validateBatch, validateEnroll,
  MAX_FLOWS_PER_BATCH, MAX_STR
};
