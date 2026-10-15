// AITHENA live client (browser, 0 dependencies)
// =============================================================================
// Connects the LeakLens UI to the AITHENA admin server over Server-Sent Events.
//
// Hard rules honoured here:
//   - DEMO (simulated) and LIVE (real telemetry) are never mixed. A persistent
//     banner states which mode is active; switching modes hides one set of
//     panels and shows the other.
//   - Device status is reported honestly: LIVE / STALE / OFFLINE as computed by
//     the server from last-seen time. The client never invents "connected".
//   - Flows are always scoped to the device that reported them.
//   - The admin token is held only in this browser tab's sessionStorage and sent
//     only to the configured server origin.
// =============================================================================
(function () {
  'use strict';

  var CFG_KEY = 'lldr_live_cfg';
  var MODE_KEY = 'lldr_mode'; // 'demo' | 'live'

  var state = {
    connected: false,
    mode: 'demo',
    serverUrl: (location.origin && location.origin.indexOf('http') === 0) ? location.origin : '',
    adminToken: '',
    devices: {},        // deviceId -> public device record
    flowsByDevice: {},  // deviceId -> [flow,...] (bounded client-side)
    serverTime: null,
    lastError: null
  };

  var MAX_CLIENT_FLOWS = 300;
  var subscribers = [];
  var es = null;

  // ---------------- config persistence ----------------
  function loadCfg() {
    try {
      var raw = sessionStorage.getItem(CFG_KEY);
      if (raw) {
        var c = JSON.parse(raw);
        if (c.serverUrl) state.serverUrl = c.serverUrl;
        if (c.adminToken) state.adminToken = c.adminToken;
      }
      var m = sessionStorage.getItem(MODE_KEY);
      if (m === 'live' || m === 'demo') state.mode = m;
    } catch (e) {}
  }
  function saveCfg() {
    try {
      sessionStorage.setItem(CFG_KEY, JSON.stringify({ serverUrl: state.serverUrl, adminToken: state.adminToken }));
      sessionStorage.setItem(MODE_KEY, state.mode);
    } catch (e) {}
  }

  function esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function notify() { subscribers.forEach(function (cb) { try { cb(state); } catch (e) {} }); }

  // ---------------- SSE connection ----------------
  function connect() {
    disconnect();
    if (!state.serverUrl || !state.adminToken) {
      state.lastError = 'Server URL and admin token required';
      renderBar();
      return;
    }
    var url = state.serverUrl.replace(/\/$/, '') + '/api/v1/stream?token=' + encodeURIComponent(state.adminToken);
    try {
      es = new EventSource(url);
    } catch (e) {
      state.lastError = 'EventSource failed: ' + e.message;
      renderBar();
      return;
    }

    es.addEventListener('open', function () { state.connected = true; state.lastError = null; renderBar(); });

    es.addEventListener('snapshot', function (ev) {
      var d = safeParse(ev.data);
      if (!d) return;
      state.devices = {};
      state.flowsByDevice = {};
      (d.devices || []).forEach(function (entry) {
        state.devices[entry.device.deviceId] = applyRisk(entry.device, entry.risk);
        state.flowsByDevice[entry.device.deviceId] = (entry.flows || []).slice(-MAX_CLIENT_FLOWS);
      });
      state.serverTime = d.serverTime;
      state.connected = true;
      renderAll();
    });

    es.addEventListener('registry', function (ev) {
      var d = safeParse(ev.data);
      if (!d) return;
      (d.devices || []).forEach(function (dev) {
        var prev = state.devices[dev.deviceId];
        state.devices[dev.deviceId] = applyRisk(dev, dev.risk || (prev && prev.risk));
      });
      state.serverTime = d.serverTime;
      renderAll();
    });

    es.addEventListener('telemetry', function (ev) {
      var d = safeParse(ev.data);
      if (!d || !d.deviceId) return;
      state.devices[d.deviceId] = applyRisk(d.device || state.devices[d.deviceId] || {}, d.risk);
      var arr = state.flowsByDevice[d.deviceId] || (state.flowsByDevice[d.deviceId] = []);
      (d.flows || []).forEach(function (f) { arr.push(f); });
      if (arr.length > MAX_CLIENT_FLOWS) arr.splice(0, arr.length - MAX_CLIENT_FLOWS);
      renderAll();
      if (d.risk && (d.risk.severity === 'High' || d.risk.severity === 'Critical') && typeof window.toast === 'function') {
        window.toast('⚠ ' + d.risk.severity + ' risk on ' + (d.device ? (d.device.label || d.device.deviceId) : d.deviceId));
      }
    });

    es.addEventListener('device', function (ev) {
      var d = safeParse(ev.data);
      if (!d || !d.device) return;
      state.devices[d.device.deviceId] = applyRisk(d.device, d.device.risk);
      renderAll();
    });

    es.addEventListener('error', function () {
      state.connected = false;
      state.lastError = 'Disconnected (retrying)';
      renderBar();
    });
    saveCfg();
  }

  function disconnect() { if (es) { try { es.close(); } catch (e) {} es = null; } state.connected = false; }

  function applyRisk(dev, risk) { if (risk) dev.risk = risk; return dev; }
  function safeParse(s) { try { return JSON.parse(s); } catch (e) { return null; } }

  // ---------------- public API ----------------
  function devicesList() {
    return Object.keys(state.devices).map(function (k) { return state.devices[k]; })
      .sort(function (a, b) { return (a.deviceId || '').localeCompare(b.deviceId || ''); });
  }
  function flowsFor(deviceId) { return (state.flowsByDevice[deviceId] || []).slice(); }
  function allFlows() {
    var out = [];
    Object.keys(state.flowsByDevice).forEach(function (id) {
      state.flowsByDevice[id].forEach(function (f) { out.push(Object.assign({ deviceId: id }, f)); });
    });
    return out.sort(function (a, b) { return b.ts - a.ts; });
  }

  var API = {
    state: state,
    isLive: function () { return state.mode === 'live'; },
    isConnected: function () { return state.connected; },
    getDevices: devicesList,
    getFlows: flowsFor,
    getAllFlows: allFlows,
    subscribe: function (cb) { subscribers.push(cb); return function () { subscribers = subscribers.filter(function (x) { return x !== cb; }); }; },
    connect: connect,
    setMode: setMode,
    connStatusPill: connStatusPill
  };
  window.AithenaLive = API;

  function setMode(m) {
    state.mode = (m === 'live') ? 'live' : 'demo';
    saveCfg();
    document.body.classList.toggle('aithena-live', state.mode === 'live');
    if (state.mode === 'live' && !es) connect();
    if (state.mode === 'demo') { /* keep connection for registry but hide live panels */ }
    applyMode();
    renderAll();
  }

  function connStatusPill(cs) {
    var map = { LIVE: 'ok', STALE: 'amb', OFFLINE: 'hi', REVOKED: 'mu' };
    var cls = map[cs] || 'mu';
    return '<span class="aithena-dot aithena-' + cls + '"></span>' + esc(cs || 'OFFLINE');
  }

  // ---------------- panel show/hide (never mix) ----------------
  var demoPanels = [];
  function captureDemoPanels() {
    // Snapshot demo panels present per page BEFORE injecting live panels.
    var page = document.body.dataset.page;
    var sels = {
      dashboard: ['#s1 .panel'], traffic: ['#s2 .panel'], alerts: ['#s4 .panel'],
      incidents: ['#s5 .panel'], dev: ['#s6 .panel']
    };
    (sels[page] || []).forEach(function (sel) {
      document.querySelectorAll(sel).forEach(function (el) {
        if (!el.classList.contains('aithena-live-panel')) demoPanels.push(el);
      });
    });
  }
  function applyMode() {
    var live = state.mode === 'live';
    demoPanels.forEach(function (el) { el.style.display = live ? 'none' : ''; });
    document.querySelectorAll('.aithena-live-panel').forEach(function (el) { el.style.display = live ? '' : 'none'; });
  }

  // ---------------- the Live bar (all pages) ----------------
  var barEl = null, panelOpen = false;
  function ensureBar() {
    if (barEl) return;
    barEl = document.createElement('div');
    barEl.id = 'aithena-livebar';
    document.body.appendChild(barEl);
    renderBar();
  }
  function renderBar() {
    if (!barEl) return;
    var live = state.mode === 'live';
    var nDev = devicesList().length;
    var nLive = devicesList().filter(function (d) { return d.connStatus === 'LIVE'; }).length;
    var statusTxt = live
      ? (state.connected ? ('LIVE — ' + nLive + '/' + nDev + ' device(s) online') : ('LIVE (connecting…)' + (state.lastError ? ' — ' + esc(state.lastError) : '')))
      : 'DEMO MODE — simulated data only';
    barEl.className = live ? 'live' : 'demo';
    barEl.innerHTML =
      '<div class="ab-left">' +
        '<span class="ab-badge">' + (live ? '● LIVE' : '◉ DEMO') + '</span>' +
        '<span class="ab-status">' + statusTxt + '</span>' +
      '</div>' +
      '<div class="ab-right">' +
        '<button class="ab-btn" id="ab-mode">Switch to ' + (live ? 'Demo' : 'Live') + '</button>' +
        '<button class="ab-btn" id="ab-cfg">⚙ Connection</button>' +
      '</div>' +
      (panelOpen ? cfgPanelHtml() : '');
    wireBar();
  }
  function cfgPanelHtml() {
    return '<div class="ab-panel">' +
      '<label>Server URL<input id="ab-url" type="text" value="' + esc(state.serverUrl) + '" placeholder="https://admin-host:8443"></label>' +
      '<label>Admin token<input id="ab-token" type="password" value="' + esc(state.adminToken) + '" placeholder="AITHENA_ADMIN_TOKEN"></label>' +
      '<div class="ab-panel-row"><button class="ab-btn ab-primary" id="ab-connect">Connect &amp; go Live</button>' +
      '<span class="ab-note">Token is kept only in this browser tab and sent only to the server above.</span></div>' +
      (state.lastError ? '<div class="ab-err">' + esc(state.lastError) + '</div>' : '') +
    '</div>';
  }
  function wireBar() {
    var m = barEl.querySelector('#ab-mode'); if (m) m.onclick = function () { setMode(state.mode === 'live' ? 'demo' : 'live'); };
    var c = barEl.querySelector('#ab-cfg'); if (c) c.onclick = function () { panelOpen = !panelOpen; renderBar(); };
    var conn = barEl.querySelector('#ab-connect');
    if (conn) conn.onclick = function () {
      var u = barEl.querySelector('#ab-url').value.trim();
      var t = barEl.querySelector('#ab-token').value.trim();
      state.serverUrl = u; state.adminToken = t; saveCfg();
      state.mode = 'live'; document.body.classList.add('aithena-live');
      panelOpen = false;
      connect(); applyMode(); renderAll();
    };
  }

  // ---------------- per-page live rendering ----------------
  function renderAll() { renderBar(); renderInspector(); renderRegistry(); renderDashLive(); renderAlertsLive(); }

  // Traffic page: Encrypted Flow Anomaly Inspector (all laptops, filter, status)
  var inspectorEl = null, inspectorFilter = 'ALL';
  function ensureInspector() {
    if (document.body.dataset.page !== 'traffic') return;
    if (inspectorEl) return;
    var s2 = document.querySelector('#s2'); if (!s2) return;
    inspectorEl = document.createElement('div');
    inspectorEl.className = 'panel dr-panel aithena-live-panel';
    inspectorEl.id = 'aithena-live-inspector';
    s2.appendChild(inspectorEl);
  }
  function renderInspector() {
    if (!inspectorEl) return;
    var devs = devicesList();
    var opts = '<option value="ALL">All devices (' + devs.length + ')</option>' +
      devs.map(function (d) { return '<option value="' + esc(d.deviceId) + '"' + (d.deviceId === inspectorFilter ? ' selected' : '') + '>' + esc(d.deviceId) + ' · ' + esc(d.label || '') + '</option>'; }).join('');

    var statusStrip = devs.map(function (d) {
      return '<span class="dr-pill aithena-devpill">' + esc(d.deviceId) + ' ' + connStatusPill(d.connStatus) +
        (d.risk ? ' <b class="aithena-sev-' + (d.risk.severity || 'Low').toLowerCase() + '">' + esc(d.risk.severity) + '</b>' : '') + '</span>';
    }).join('');

    var rows = [];
    var src = (inspectorFilter === 'ALL') ? allFlows()
      : flowsFor(inspectorFilter).map(function (f) { return Object.assign({ deviceId: inspectorFilter }, f); }).sort(function (a, b) { return b.ts - a.ts; });

    src.slice(0, 60).forEach(function (f) {
      var dev = state.devices[f.deviceId] || {};
      var finding = inferFinding(f);
      var bytes = (f.bytesOut != null) ? fmtBytes(f.bytesOut) : '<span class="aithena-mu">n/a</span>';
      rows.push('<tr>' +
        '<td>' + esc(new Date(f.ts).toLocaleTimeString()) + '</td>' +
        '<td><b>' + esc(f.deviceId) + '</b><br><span class="aithena-mu" style="font-size:11px">' + esc(dev.label || '') + '</span></td>' +
        '<td><code>' + esc(f.dest) + '</code>:' + esc(f.destPort) + ' &bull; <span class="dr-pill">' + esc(f.protocol) + '</span></td>' +
        '<td>×' + esc(f.connectionCount) + ' &bull; ' + esc(f.durationSec != null ? f.durationSec + 's' : 'n/a') + ' &bull; ' + bytes + '</td>' +
        '<td><span class="dr-badge ' + finding.cls + '">' + esc(finding.text) + '</span></td>' +
        '<td>' + connStatusPill(dev.connStatus) + '</td>' +
      '</tr>');
    });

    inspectorEl.innerHTML =
      '<div class="dr-header"><div>' +
        '<h3 class="dr-title">Encrypted Flow Anomaly Inspector — <span class="aithena-mu">Live</span></h3>' +
        '<span style="font-size:12px;color:var(--mu);">Authorised endpoint telemetry across all connected laptops · metadata only</span>' +
      '</div><div>' +
        '<select id="aithena-insp-filter" class="b" style="padding:4px 8px;">' + opts + '</select>' +
      '</div></div>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;">' + (statusStrip || '<span class="aithena-mu">No devices enrolled yet. Enroll one from the admin server.</span>') + '</div>' +
      '<div class="tw"><table class="dr-audit-table"><thead><tr>' +
        '<th>Time</th><th>Device</th><th>Observed: Dest / Port / Proto</th><th>Conn / Duration / Bytes</th><th>Inferred finding</th><th>Status</th>' +
      '</tr></thead><tbody>' + (rows.join('') || '<tr><td colspan="6" style="text-align:center;color:var(--mu);padding:16px;">No live flows yet. Start an agent on an enrolled laptop.</td></tr>') + '</tbody></table></div>' +
      '<p class="aithena-mu" style="font-size:11px;margin:8px 0 0;">Bytes shown only where the endpoint OS exposes per-connection counters; "n/a" is an honest unknown, never treated as zero.</p>';

    var fsel = inspectorEl.querySelector('#aithena-insp-filter');
    if (fsel) fsel.onchange = function () { inspectorFilter = fsel.value; renderInspector(); };
  }

  function inferFinding(f) {
    if (f.destNovelty === 'new') return { text: 'Destination novelty (+unfamiliar)', cls: 'dr-medium' };
    if (f.bytesOut != null && f.bytesOut > 300 * 1024 * 1024) return { text: 'Large outbound (+deviation)', cls: 'dr-high' };
    return { text: 'Normal baseline', cls: 'dr-low' };
  }
  function fmtBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
  }

  // Admin device registry (dashboard + developer pages)
  var registryEl = null;
  function ensureRegistry() {
    var page = document.body.dataset.page;
    if (page !== 'dashboard' && page !== 'dev') return;
    if (registryEl) return;
    var host = document.querySelector(page === 'dashboard' ? '#s1' : '#s6');
    if (!host) return;
    registryEl = document.createElement('div');
    registryEl.className = 'panel dr-panel aithena-live-panel';
    registryEl.id = 'aithena-registry';
    host.insertBefore(registryEl, host.firstChild ? host.firstChild.nextSibling : null);
  }
  function renderRegistry() {
    if (!registryEl) return;
    var devs = devicesList();
    var rows = devs.map(function (d) {
      var sev = d.risk ? d.risk.severity : '—';
      var sc = d.risk ? d.risk.score : '—';
      var seen = d.lastSeen ? timeAgo(d.lastSeen) : 'never';
      var health = d.telemetryHealth || {};
      var hp = ['endpoint', 'flow', 'bytes'].map(function (k) {
        return health[k] ? '<span class="dr-pill" style="font-size:10px">' + k + ':' + esc(String(health[k]).toUpperCase()) + '</span>' : '';
      }).join(' ');
      return '<tr>' +
        '<td><b>' + esc(d.deviceId) + '</b></td>' +
        '<td>' + esc(d.label || '') + '<br><span class="aithena-mu" style="font-size:11px">' + esc(d.assignedUser || '') + ' · ' + esc(d.hostname || '?') + '</span></td>' +
        '<td>' + connStatusPill(d.connStatus) + '</td>' +
        '<td>' + esc(seen) + '</td>' +
        '<td>' + hp + '</td>' +
        '<td><span class="aithena-sev-' + String(sev).toLowerCase() + '">' + esc(sev) + '</span> <span class="aithena-mu">(' + esc(sc) + ')</span></td>' +
        '<td><code class="aithena-mu">' + esc(d.lastIp || '?') + '</code></td>' +
        '<td>' + (d.revoked ? '<span class="aithena-mu">revoked</span>' : '<button class="ab-btn ab-revoke" data-rev="' + esc(d.deviceId) + '">Revoke</button>') + '</td>' +
      '</tr>';
    }).join('');
    registryEl.innerHTML =
      '<div class="dr-header"><div><h3 class="dr-title">Admin Device Registry — <span class="aithena-mu">Live</span></h3>' +
      '<span style="font-size:12px;color:var(--mu);">Authorised laptops, connection status, last-seen, telemetry health &amp; independent risk</span></div></div>' +
      '<div class="tw"><table class="dr-audit-table"><thead><tr>' +
      '<th>Device ID</th><th>Owner / Host</th><th>Status</th><th>Last seen</th><th>Telemetry</th><th>Risk</th><th>Source IP</th><th></th>' +
      '</tr></thead><tbody>' + (rows || '<tr><td colspan="8" style="text-align:center;color:var(--mu);padding:16px;">No devices enrolled.</td></tr>') + '</tbody></table></div>';
    registryEl.querySelectorAll('.ab-revoke').forEach(function (btn) {
      btn.onclick = function () { revokeDevice(btn.getAttribute('data-rev')); };
    });
  }

  function revokeDevice(deviceId) {
    if (!state.serverUrl || !state.adminToken) return;
    if (!window.confirm('Revoke ' + deviceId + '? Its agent secret will stop authenticating and the owner should uninstall the agent.')) return;
    fetch(state.serverUrl.replace(/\/$/, '') + '/api/v1/devices/' + encodeURIComponent(deviceId) + '/revoke', {
      method: 'POST', headers: { 'Authorization': 'Bearer ' + state.adminToken }
    }).then(function (r) { return r.json(); }).then(function () {
      if (typeof window.toast === 'function') window.toast(deviceId + ' revoked');
    }).catch(function (e) { if (typeof window.toast === 'function') window.toast('Revoke failed: ' + e.message); });
  }

  // Dashboard live KPI tiles
  var dashEl = null;
  function ensureDashLive() {
    if (document.body.dataset.page !== 'dashboard') return;
    if (dashEl) return;
    var s1 = document.querySelector('#s1'); if (!s1) return;
    dashEl = document.createElement('div');
    dashEl.className = 'panel dr-panel aithena-live-panel';
    dashEl.id = 'aithena-dash-live';
    s1.insertBefore(dashEl, s1.firstChild ? s1.firstChild.nextSibling : null);
  }
  function renderDashLive() {
    if (!dashEl) return;
    var devs = devicesList();
    var online = devs.filter(function (d) { return d.connStatus === 'LIVE'; }).length;
    var stale = devs.filter(function (d) { return d.connStatus === 'STALE'; }).length;
    var offline = devs.filter(function (d) { return d.connStatus === 'OFFLINE' || d.connStatus === 'REVOKED'; }).length;
    var atRisk = devs.filter(function (d) { return d.risk && (d.risk.severity === 'High' || d.risk.severity === 'Critical'); }).length;
    var totalFlows = Object.keys(state.flowsByDevice).reduce(function (a, k) { return a + state.flowsByDevice[k].length; }, 0);
    function tile(n, label, cls) { return '<div class="aithena-tile ' + (cls || '') + '"><b>' + n + '</b><span>' + label + '</span></div>'; }
    dashEl.innerHTML =
      '<div class="dr-header"><div><h3 class="dr-title">Fleet Overview — <span class="aithena-mu">Live</span></h3>' +
      '<span style="font-size:12px;color:var(--mu);">Across all authorised laptops</span></div></div>' +
      '<div class="aithena-tiles">' + tile(online, 'Online (LIVE)', 'ok') + tile(stale, 'Stale', 'amb') +
      tile(offline, 'Offline', 'hi') + tile(atRisk, 'High / Critical', atRisk ? 'hi' : '') +
      tile(totalFlows, 'Live flows held', '') + '</div>';
  }

  // Alerts/Incidents live summary
  var alertsEl = null;
  function ensureAlertsLive() {
    var page = document.body.dataset.page;
    if (page !== 'alerts' && page !== 'incidents') return;
    if (alertsEl) return;
    var host = document.querySelector(page === 'alerts' ? '#s4' : '#s5'); if (!host) return;
    alertsEl = document.createElement('div');
    alertsEl.className = 'panel dr-panel aithena-live-panel';
    alertsEl.id = 'aithena-alerts-live';
    host.appendChild(alertsEl);
  }
  function renderAlertsLive() {
    if (!alertsEl) return;
    var devs = devicesList().filter(function (d) { return d.risk && d.risk.severity !== 'Low'; })
      .sort(function (a, b) { return (b.risk.score || 0) - (a.risk.score || 0); });
    var rows = devs.map(function (d) {
      var contribs = (d.risk.contributions || []).map(function (c) { return '<li>+' + esc(c.points) + ' pts [' + esc(c.group) + ']: ' + esc(c.reason) + '</li>'; }).join('');
      var unknowns = (d.risk.unknowns && d.risk.unknowns.length) ? '<div class="aithena-unknown">Missing telemetry: ' + esc(d.risk.unknowns.join(', ')) + ' — not treated as safe; confidence ' + esc(d.risk.confidence) + '.</div>' : '';
      return '<div class="dr-card" style="margin-bottom:10px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;">' +
        '<b>' + esc(d.deviceId) + ' · ' + esc(d.label || '') + '</b>' +
        '<span class="dr-badge dr-' + String(d.risk.severity).toLowerCase() + '">' + esc(d.risk.severity) + ' (' + esc(d.risk.score) + '/100) · ' + connStatusPill(d.connStatus) + '</span></div>' +
        '<ul class="rs" style="margin:6px 0 0;padding-left:16px;font-size:13px;">' + (contribs || '<li>No anomalous signals.</li>') + '</ul>' + unknowns +
      '</div>';
    }).join('');
    alertsEl.innerHTML =
      '<div class="dr-header"><div><h3 class="dr-title">Live Risk by Device — <span class="aithena-mu">' + (document.body.dataset.page === 'incidents' ? 'Incident view' : 'Alerts') + '</span></h3>' +
      '<span style="font-size:12px;color:var(--mu);">Per-device scores from authorised telemetry. No automatic containment is performed.</span></div></div>' +
      (rows || '<p class="aithena-mu">No elevated devices. All connected laptops are at baseline Low risk.</p>');
  }

  function timeAgo(ts) {
    var s = Math.round((Date.now() - ts) / 1000);
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.round(s / 60) + 'm ago';
    return Math.round(s / 3600) + 'h ago';
  }

  // ---------------- init ----------------
  function init() {
    loadCfg();
    captureDemoPanels();
    ensureBar();
    ensureInspector();
    ensureRegistry();
    ensureDashLive();
    ensureAlertsLive();
    document.body.classList.toggle('aithena-live', state.mode === 'live');
    applyMode();
    if (state.mode === 'live' && state.serverUrl && state.adminToken) connect();
    renderAll();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
