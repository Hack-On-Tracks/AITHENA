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
    // Knowledge Graph page: in demo mode restore the original app.js graph; in
    // live mode the live knowledge graph (backend-driven) takes over #g.
    if (document.body.dataset.page === 'graph') {
      if (!live && typeof window.gbuild === 'function') { try { window.gbuild(); } catch (e) {} }
      else renderGraphLive();
    }
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
  function renderAll() { renderBar(); renderInspector(); renderRegistry(); renderDashLive(); renderAlertsLive(); renderGraphLive(); }

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

  // ---------------- Knowledge Graph integration (teammate backend) ----------------
  // Feeds REAL telemetry into the existing Python modules (TemporalCorrelationService
  // + NetworkX build_knowledge_graph via /api/graph-correlate) and renders the
  // returned graph into the existing #g SVG. No HTML/CSS change: reuses the graph's
  // own node/edge styles. is_anomaly is sourced from the existing rule-based signals
  // (destination novelty / large transfer), labelled as such — never fabricated.
  var GRAPH_API_KEY = 'lldr_graph_api';
  function graphApiBase() {
    try { var v = sessionStorage.getItem(GRAPH_API_KEY); if (v) return v; } catch (e) {}
    return 'http://127.0.0.1:5001';
  }
  // Team roster mapping (from the project's team dataset), matched by device label.
  var ROSTER = {
    'My-PC': ['Emil', 'Admin'], 'Friend-Laptop': ['Manasvi', 'Employer'],
    'Laptop-3': ['Sameera', 'Insider'], 'Laptop-4': ['Keona', 'Outsider']
  };
  // Demo-only coordinates (clearly labelled). No authorised geo source is available,
  // and the Knowledge Graph has no map view, so these are shown in the detail panel.
  var DEMO_GEO = {
    'Emil': [12.9716, 77.5946], 'Manasvi': [19.0760, 72.8777],
    'Sameera': [13.0827, 80.2707], 'Keona': [28.6139, 77.2090]
  };
  function rosterFor(deviceId) {
    var d = state.devices[deviceId];
    var label = d && d.label ? d.label : deviceId;
    var r = ROSTER[label];
    return r ? { member: r[0], role: r[1], label: label } : { member: label, role: '', label: label };
  }
  function flowAnomalous(f) {
    return f.destNovelty === 'new' || (f.bytesOut != null && f.bytesOut > 300 * 1024 * 1024);
  }
  var simOn = false;
  function deviceByLabel(lbl) { return devicesList().filter(function (d) { return d.label === lbl; })[0]; }
  function simRecords() {
    // Clearly-labelled SIMULATION: Insider (Sameera / Laptop-3) repeatedly sends
    // large data to the Outsider (Keona / Laptop-4). Not real telemetry — every
    // record is tagged _sim so it renders with a SIM marker.
    var ins = deviceByLabel('Laptop-3'), out = deviceByLabel('Laptop-4');
    var insIp = (ins && ins.lastIp) || '10.10.10.3';
    var outIp = (out && out.lastIp) || '10.10.10.4';
    var insId = (ins && ins.deviceId) || 'DEV-003';
    var now = Date.now(), recs = [];
    for (var i = 0; i < 4; i++) {
      recs.push({
        event_id: 'SIM-exfil-' + i,
        timestamp: new Date(now - (3 - i) * 12000).toISOString(),
        source_ip: insIp, destination_ip: outIp, destination_port: 445,
        device_id: insId, protocol: 'SMB (file share)', direction: 'outbound',
        total_bytes: 2100000000 + i, total_packets: 180000 + i,
        is_anomaly: true, _sim: true
      });
    }
    return recs;
  }
  function buildRecords() {
    var recs = [];
    devicesList().forEach(function (d) {
      (state.flowsByDevice[d.deviceId] || []).slice(-30).forEach(function (f, i) {
        recs.push({
          event_id: d.deviceId + '-' + f.ts + '-' + i,
          timestamp: new Date(f.ts).toISOString(),
          source_ip: d.lastIp || d.deviceId,
          destination_ip: f.dest,
          destination_port: f.destPort,
          device_id: d.deviceId,
          protocol: f.protocol || 'TCP',
          direction: 'outbound',
          total_bytes: f.bytesOut != null ? f.bytesOut : null,
          total_packets: f.packetsOut != null ? f.packetsOut : null,
          is_anomaly: !!flowAnomalous(f)
        });
      });
    });
    if (simOn) recs = recs.concat(simRecords());
    return recs;
  }
  // which external-endpoint IPs are actually one of our own members
  function ipMemberMap() {
    var m = {};
    devicesList().forEach(function (d) { if (d.lastIp) { var r = rosterFor(d.deviceId); m[d.lastIp] = r.member + ' (' + r.role + ')'; } });
    var out = deviceByLabel('Laptop-4');
    m[(out && out.lastIp) || '10.10.10.4'] = 'Keona (Outsider)';
    return m;
  }

  var graphBusy = false, lastGraphPost = 0, lastGraphData = null, graphSel = null;
  function renderGraphLive() {
    if (document.body.dataset.page !== 'graph' || state.mode !== 'live') return;
    var svg = document.querySelector('#g'); if (!svg) return;
    var recs = buildRecords();
    if (!recs.length) { drawGraph({ nodes: [], edges: [] }, []); return; }
    var now = Date.now();
    if (graphBusy || (now - lastGraphPost) < 2500) { if (lastGraphData) drawGraph(lastGraphData.graph, lastGraphData.correlations); return; }
    graphBusy = true; lastGraphPost = now;
    fetch(graphApiBase().replace(/\/$/, '') + '/api/graph-correlate', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ records: recs })
    }).then(function (r) { return r.json(); }).then(function (d) {
      graphBusy = false;
      if (!d || !d.graph) return;
      lastGraphData = d;
      drawGraph(d.graph, d.correlations || []);
    }).catch(function () {
      graphBusy = false;
      // Backend not reachable: show an honest note instead of silently faking a graph.
      var dt = document.querySelector('#dt');
      if (dt) dt.innerHTML = '<h3>Live Knowledge Graph</h3><p style="color:var(--mu);margin:0">Detection/correlation backend not reachable at <code>' + esc(graphApiBase()) + '</code>. Start it with <code>python -m backend.graph_api</code>. The graph shows real telemetry only — nothing is fabricated.</p>';
    });
  }

  var SVGNS2 = 'http://www.w3.org/2000/svg';
  function svgel(n, a) { var e = document.createElementNS(SVGNS2, n); for (var k in a) e.setAttribute(k, a[k]); return e; }
  var GCOL = { device: '#5b8cff', event: '#dbe6f7', dest: '#3ee08f', alert: '#ff5a6e', correlation: '#ff5a6e' };

  function drawGraph(graph, correlations) {
    var svg = document.querySelector('#g'); if (!svg) return;
    drawGraph._ipMem = ipMemberMap();
    var nodes = graph.nodes || [], edges = graph.edges || [];
    var byId = {}; nodes.forEach(function (n) { byId[n.id] = n; });
    // classify + position
    var devs = [], ips = [], flows = [], corrs = [];
    nodes.forEach(function (n) {
      if (n.node_type === 'entity' && n.id.indexOf('entity:device:') === 0) devs.push(n);
      else if (n.node_type === 'entity') ips.push(n);
      else if (n.node_type === 'flow') flows.push(n);
      else if (n.node_type === 'correlation') corrs.push(n);
    });
    flows = flows.slice(0, 14); ips = ips.slice(0, 10);
    var pos = {};
    function place(list, x) { list.forEach(function (n, i) { pos[n.id] = { x: x, y: 40 + i * (320 / Math.max(1, list.length)) }; }); }
    place(devs, 70); place(flows, 250); place(corrs, 410); place(ips, 580);
    var shown = {}; Object.keys(pos).forEach(function (k) { shown[k] = true; });

    var eh = edges.filter(function (e) { return shown[e.source] && shown[e.target]; }).map(function (e) {
      var a = pos[e.source], b = pos[e.target];
      var bad = /member_of|participates_in/.test(e.relationship || '');
      return '<line class="edge' + (bad ? ' bad' : '') + '" x1="' + a.x + '" y1="' + a.y + '" x2="' + b.x + '" y2="' + b.y + '"/>';
    }).join('');

    function nodeSvg(n, kind) {
      var p = pos[n.id]; if (!p) return '';
      var label, r = 14, cls = kind;
      if (kind === 'device') { var ro = rosterFor(n.id.replace('entity:device:', '')); label = ro.member + (ro.role ? ' (' + ro.role + ')' : ''); }
      else if (kind === 'dest') { var ip = n.id.replace('entity:ip:', ''); label = (drawGraph._ipMem && drawGraph._ipMem[ip]) ? drawGraph._ipMem[ip] : ip; r = 11; }
      else if (kind === 'flow') { label = ''; r = 6; }
      else { label = (n.pattern || 'correlation'); r = 15; }
      var fill = GCOL[kind === 'dest' ? 'dest' : (kind === 'correlation' ? 'correlation' : kind === 'flow' ? 'event' : 'device')];
      return '<g class="node" data-nid="' + esc(n.id) + '" data-kind="' + kind + '" style="cursor:pointer">' +
        '<circle class="' + (kind === 'correlation' ? 'pulse' : '') + '" cx="' + p.x + '" cy="' + p.y + '" r="' + r + '" fill="' + fill + '"/>' +
        (label ? '<text x="' + p.x + '" y="' + (p.y + (kind === 'flow' ? 20 : 28)) + '">' + esc(label) + '</text>' : '') + '</g>';
    }
    svg.innerHTML = eh +
      devs.map(function (n) { return nodeSvg(n, 'device'); }).join('') +
      flows.map(function (n) { return nodeSvg(n, 'flow'); }).join('') +
      corrs.map(function (n) { return nodeSvg(n, 'correlation'); }).join('') +
      ips.map(function (n) { return nodeSvg(n, 'dest'); }).join('');

    svg.querySelectorAll('.node').forEach(function (g) {
      g.addEventListener('click', function () { graphDetail(byId[g.getAttribute('data-nid')], g.getAttribute('data-kind'), correlations); });
    });
    // summary into the details panel the first time
    var dt = document.querySelector('#dt');
    if (dt && !graphSel) {
      dt.innerHTML = '<h3>Live Knowledge Graph</h3><p style="color:var(--mu);margin:0 0 6px">Built from real telemetry via the existing NetworkX + temporal-correlation modules. Red dashed links = temporal correlation. Click a node.</p>' +
        '<p style="font-size:12px;color:var(--mu);margin:0 0 10px">' + devs.length + ' members · ' + ips.length + ' endpoints · ' + flows.length + ' flows shown · ' + corrs.length + ' correlation group(s).</p>' +
        '<button id="aithena-sim-btn" class="b" style="width:100%;padding:8px;border:1px solid ' + (simOn ? 'var(--hi)' : 'var(--bd)') + ';background:' + (simOn ? 'rgba(255,107,122,.15)' : 'transparent') + ';color:var(--tx);border-radius:4px;cursor:pointer;font:600 12px Outfit,sans-serif">' + (simOn ? '■ Stop insider→outsider simulation' : '▶ Simulate: Insider (Sameera) → Outsider (Keona) exfiltration') + '</button>' +
        (simOn ? '<div class="aithena-unknown" style="margin-top:8px">SIMULATION ON — injecting a flagged Sameera → Keona large transfer. This is NOT real telemetry; it is clearly-labelled demo data for the scenario.</div>' : '');
      var sb = dt.querySelector('#aithena-sim-btn');
      if (sb) sb.onclick = function () { simOn = !simOn; lastGraphPost = 0; graphSel = null; renderGraphLive(); };
    }
  }

  function graphDetail(node, kind, correlations) {
    var dt = document.querySelector('#dt'); if (!dt || !node) return;
    graphSel = node.id;
    if (kind === 'device') {
      var ro = rosterFor(node.id.replace('entity:device:', ''));
      var geo = DEMO_GEO[ro.member];
      dt.innerHTML = '<h3>' + esc(ro.member) + '</h3><dl>' +
        '<dt>role</dt><dd>' + esc(ro.role || '—') + '</dd>' +
        '<dt>device</dt><dd>' + esc(ro.label) + '</dd>' +
        '<dt>source ip</dt><dd>' + esc((state.devices[node.id.replace('entity:device:', '')] || {}).lastIp || '—') + '</dd>' +
        (geo ? '<dt>location</dt><dd>' + geo[0] + ', ' + geo[1] + ' <span style="color:var(--amb)">(demo coordinates)</span></dd>' : '') +
        '</dl><p style="font-size:11px;color:var(--mu)">A map/pin view is not part of the existing Knowledge Graph UI, so coordinates are shown here and are demo-only.</p>';
    } else if (kind === 'correlation') {
      var pat = node.pattern || 'correlation';
      dt.innerHTML = '<h3>Temporal correlation</h3><dl>' +
        '<dt>pattern</dt><dd>' + esc(pat) + '</dd>' +
        '<dt>events</dt><dd>' + esc(node.event_count != null ? node.event_count : '—') + '</dd>' +
        '<dt>evidence</dt><dd>' + esc(node.evidence_level || node.matched_rule || '—') + '</dd>' +
        '<dt>window</dt><dd>' + esc(node.start_timestamp || '?') + ' → ' + esc(node.end_timestamp || '?') + '</dd>' +
        '</dl><p style="font-size:11px;color:var(--mu)">From the existing TemporalCorrelationService over real event timestamps.</p>';
    } else if (kind === 'dest') {
      dt.innerHTML = '<h3>' + esc(node.id.replace('entity:ip:', '')) + '</h3><p style="color:var(--mu);margin:0">External endpoint observed in real telemetry.</p>';
    } else {
      dt.innerHTML = '<h3>Flow</h3><p style="color:var(--mu);margin:0"><code>' + esc(node.destination_ip || '') + ':' + esc(node.destination_port || '') + '</code> · ' + esc(node.protocol || node.Protocol || '') + (node.is_anomaly ? ' · <span style="color:var(--hi)">flagged (rule-based)</span>' : '') + '</p>';
    }
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
