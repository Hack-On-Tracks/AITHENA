// AITHENA live telemetry — device registry + per-device flow store (0 dependencies)
// - Each device's flows are kept in a bounded ring buffer. Flows from different
//   devices are NEVER merged into a shared list.
// - Destination novelty is computed per device from that device's own history.
// - Optional JSON persistence so enrolled devices survive a restart. Flow data is
//   kept in memory only (bounded retention) and is not persisted by default.
'use strict';

const fs = require('fs');
const path = require('path');
const auth = require('./auth');

function nowId(prefix) {
  return prefix + '-' + Math.random().toString(36).slice(2, 8).toUpperCase();
}

class Store {
  constructor(opts) {
    opts = opts || {};
    this.maxFlowsPerDevice = opts.maxFlowsPerDevice || 2000;
    this.retentionMs = opts.retentionMs || 6 * 60 * 60 * 1000; // 6 h bounded retention
    this.liveMs = opts.liveMs || 30 * 1000;      // seen within 30s  => LIVE
    this.staleMs = opts.staleMs || 120 * 1000;   // seen within 2m   => STALE, else OFFLINE
    this.persistPath = opts.persistPath || null;  // registry persistence (no flow bodies)
    this.noveltyWindowMs = opts.noveltyWindowMs || this.retentionMs;

    this.devices = Object.create(null); // deviceId -> device record
    this.flows = Object.create(null);   // deviceId -> [flow,...] (bounded)
    this.seenDest = Object.create(null); // deviceId -> Map(dest -> firstTs)

    this._nextDevNum = 1;
    this._load();
  }

  // ---- persistence (registry only) ----
  _load() {
    if (!this.persistPath) return;
    try {
      if (fs.existsSync(this.persistPath)) {
        const raw = JSON.parse(fs.readFileSync(this.persistPath, 'utf8'));
        (raw.devices || []).forEach(d => {
          this.devices[d.deviceId] = d;
          this.flows[d.deviceId] = [];
          this.seenDest[d.deviceId] = new Map();
          const n = parseInt((d.deviceId.split('-')[1] || '0'), 10);
          if (!isNaN(n) && n >= this._nextDevNum) this._nextDevNum = n + 1;
        });
      }
    } catch (e) { /* start clean on corrupt file */ }
  }

  _save() {
    if (!this.persistPath) return;
    try {
      const dir = path.dirname(this.persistPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      // Persist registry metadata and the hashed secret only — never flow bodies.
      const devices = Object.values(this.devices).map(d => Object.assign({}, d, { _recentFlow: undefined }));
      fs.writeFileSync(this.persistPath, JSON.stringify({ devices }, null, 2));
    } catch (e) { /* non-fatal */ }
  }

  // ---- enrollment ----
  enroll(meta) {
    const deviceId = 'DEV-' + String(this._nextDevNum++).padStart(3, '0');
    const secret = auth.newAgentSecret();
    const rec = {
      deviceId,
      label: meta.label,
      assignedUser: meta.assignedUser,
      department: meta.department,
      trustedNetworks: meta.trustedNetworks,
      status: 'active',
      secretHash: auth.hashSecret(secret),
      enrolledAt: Date.now(),
      lastSeen: null,
      lastIp: null,
      hostname: null,
      os: null,
      agentVersion: null,
      telemetryHealth: { endpoint: 'ok', flow: 'unknown', idp: 'unknown', vpn: 'unknown', mdm: 'unknown' },
      revoked: false,
      flowCount: 0,
      risk: null
    };
    this.devices[deviceId] = rec;
    this.flows[deviceId] = [];
    this.seenDest[deviceId] = new Map();
    this._save();
    // Return the plaintext secret exactly once; it is never stored or logged.
    return { deviceId, secret, device: this._public(rec) };
  }

  getDevice(deviceId) { return this.devices[deviceId] || null; }

  // Authenticate an agent request for a given device.
  authAgent(deviceId, secret) {
    const d = this.devices[deviceId];
    if (!d || d.revoked) return false;
    return auth.verifySecret(secret, d.secretHash);
  }

  revoke(deviceId) {
    const d = this.devices[deviceId];
    if (!d) return false;
    d.revoked = true;
    d.status = 'revoked';
    // Rotate the secret hash so the old agent secret can never authenticate again.
    d.secretHash = auth.hashSecret(auth.newToken(32));
    this._save();
    return true;
  }

  // ---- ingest ----
  // flows: array of validated flow records (no deviceId inside — scoped by caller).
  ingest(deviceId, flows, agentMeta) {
    const d = this.devices[deviceId];
    if (!d || d.revoked) return { ok: false, reason: 'unknown or revoked device' };

    const buf = this.flows[deviceId];
    const seen = this.seenDest[deviceId];
    const cutoff = Date.now() - this.noveltyWindowMs;

    // prune novelty memory
    for (const [dest, ts] of seen) { if (ts < cutoff) seen.delete(dest); }

    const stored = [];
    flows.forEach(f => {
      const key = f.dest + ':' + f.destPort;
      const firstTs = seen.get(key);
      const destNovelty = firstTs == null ? 'new' : 'known';
      if (firstTs == null) seen.set(key, f.ts);
      const rec = Object.assign({}, f, { deviceId, destNovelty });
      buf.push(rec);
      stored.push(rec);
    });

    // bounded retention: cap count and age
    this._prune(deviceId);

    // update device liveness + metadata
    d.lastSeen = Date.now();
    d.flowCount = buf.length;
    if (agentMeta) {
      if (agentMeta.reportedIp) d.lastIp = agentMeta.reportedIp;
      if (agentMeta.hostname) d.hostname = agentMeta.hostname;
      if (agentMeta.os) d.os = agentMeta.os;
      if (agentMeta.agentVersion) d.agentVersion = agentMeta.agentVersion;
      d.telemetryHealth.flow = stored.length > 0 ? 'ok' : 'delayed';
      if (agentMeta.telemetryHealth) {
        Object.assign(d.telemetryHealth, agentMeta.telemetryHealth);
      }
    }
    return { ok: true, stored };
  }

  _prune(deviceId) {
    const buf = this.flows[deviceId];
    if (!buf) return;
    const ageCut = Date.now() - this.retentionMs;
    let i = 0;
    while (i < buf.length && buf[i].ts < ageCut) i++;
    if (i > 0) buf.splice(0, i);
    if (buf.length > this.maxFlowsPerDevice) {
      buf.splice(0, buf.length - this.maxFlowsPerDevice);
    }
  }

  getFlows(deviceId, limit) {
    const buf = this.flows[deviceId] || [];
    const n = limit || buf.length;
    return buf.slice(Math.max(0, buf.length - n));
  }

  // ---- status derivation (honest LIVE / STALE / OFFLINE) ----
  connStatus(d) {
    if (d.revoked) return 'REVOKED';
    if (!d.lastSeen) return 'OFFLINE';
    const age = Date.now() - d.lastSeen;
    if (age <= this.liveMs) return 'LIVE';
    if (age <= this.staleMs) return 'STALE';
    return 'OFFLINE';
  }

  _public(d) {
    return {
      deviceId: d.deviceId,
      label: d.label,
      assignedUser: d.assignedUser,
      department: d.department,
      trustedNetworks: d.trustedNetworks,
      status: d.status,
      connStatus: this.connStatus(d),
      lastSeen: d.lastSeen,
      lastIp: d.lastIp,
      hostname: d.hostname,
      os: d.os,
      agentVersion: d.agentVersion,
      telemetryHealth: d.telemetryHealth,
      revoked: d.revoked,
      flowCount: d.flowCount,
      enrolledAt: d.enrolledAt,
      risk: d.risk
    };
  }

  registry() {
    return Object.values(this.devices).map(d => this._public(d));
  }

  setRisk(deviceId, risk) {
    const d = this.devices[deviceId];
    if (d) d.risk = risk;
  }
}

module.exports = { Store, nowId };
