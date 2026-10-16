// Device Risk UI integration (multi-page rendering, wiring, interactive controls)
// Seamlessly augments LeakLens pages without altering existing functionality.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.lldrDeviceUI = factory();
  }
}(this, function () {
  const Engine = typeof lldrDeviceEngine !== 'undefined' ? lldrDeviceEngine : (typeof window !== 'undefined' ? window.lldrDeviceEngine : null);
  const Data = typeof lldrDeviceData !== 'undefined' ? lldrDeviceData : (typeof window !== 'undefined' ? window.lldrDeviceData : null);
  const Response = typeof lldrDeviceResponse !== 'undefined' ? lldrDeviceResponse : (typeof window !== 'undefined' ? window.lldrDeviceResponse : null);

  // Storage keys (prefixed with lldr_)
  const SK_SEEDED = 'lldr_seeded';
  const SK_DEVICES = 'lldr_devices';
  const SK_EVENTS = 'lldr_events';
  const SK_CONFIG = 'lldr_config';
  const SK_ROLE = 'lldr_role';
  const SK_HEALTH = 'lldr_telemetry_health';
  const SK_INFERRED = 'lldr_inferred';

  function esc(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ---------------- Seed sample data on first load ----------------
  function seedSampleDataIfNeeded(force) {
    const sample = typeof LL_SAMPLE_DEVICE_DATA !== 'undefined' ? LL_SAMPLE_DEVICE_DATA : (typeof window !== 'undefined' ? window.LL_SAMPLE_DEVICE_DATA : null);
    if (!sample) return;

    try {
      const alreadySeeded = sessionStorage.getItem(SK_SEEDED);
      const existingEvents = sessionStorage.getItem(SK_EVENTS);
      if (!force && alreadySeeded && existingEvents) {
        return; // already initialized
      }

      // Seed devices
      sessionStorage.setItem(SK_DEVICES, JSON.stringify(sample.devices || []));

      // Build initial event map grouped by device
      const eventsMap = {};
      (sample.devices || []).forEach(d => { eventsMap[d.deviceId] = []; });

      (sample.flows || []).forEach(f => {
        if (!eventsMap[f.deviceId]) eventsMap[f.deviceId] = [];
        eventsMap[f.deviceId].push(f);
      });

      (sample.networkChanges || []).forEach(nc => {
        if (!eventsMap[nc.deviceId]) eventsMap[nc.deviceId] = [];
        eventsMap[nc.deviceId].push(nc);
      });

      (sample.authEvents || []).forEach(a => {
        if (!eventsMap[a.deviceId]) eventsMap[a.deviceId] = [];
        eventsMap[a.deviceId].push(a);
      });

      (sample.statusEvents || []).forEach(s => {
        if (!eventsMap[s.deviceId]) eventsMap[s.deviceId] = [];
        eventsMap[s.deviceId].push(s);
      });

      sessionStorage.setItem(SK_EVENTS, JSON.stringify(eventsMap));

      // Seed telemetry health
      if (sample.telemetryHealth) {
        sessionStorage.setItem(SK_HEALTH, JSON.stringify(sample.telemetryHealth));
      }

      // Seed inferred findings
      if (sample.inferredFindings) {
        sessionStorage.setItem(SK_INFERRED, JSON.stringify(sample.inferredFindings));
      }

      sessionStorage.setItem(SK_SEEDED, 'true');
    } catch (e) {
      console.error('Error seeding device risk sample data:', e);
    }
  }

  function getSavedConfig() {
    try {
      const c = sessionStorage.getItem(SK_CONFIG);
      if (c) return JSON.parse(c);
    } catch (e) {}
    return Engine && Engine.DEFAULT_CONFIG ? JSON.parse(JSON.stringify(Engine.DEFAULT_CONFIG)) : null;
  }

  function saveConfig(cfg) {
    try { sessionStorage.setItem(SK_CONFIG, JSON.stringify(cfg)); } catch (e) {}
  }

  function getStoredEvents(deviceId) {
    try {
      const raw = sessionStorage.getItem(SK_EVENTS);
      if (raw) {
        const map = JSON.parse(raw);
        if (deviceId) return map[deviceId] || [];
        return map;
      }
    } catch (e) {}
    return deviceId ? [] : {};
  }

  function saveStoredEvents(map) {
    try { sessionStorage.setItem(SK_EVENTS, JSON.stringify(map)); } catch (e) {}
  }

  function addStoredEvents(deviceId, events) {
    const map = getStoredEvents();
    map[deviceId] = (map[deviceId] || []).concat(events);
    saveStoredEvents(map);
  }

  function clearStoredEvents() {
    try { sessionStorage.removeItem(SK_EVENTS); } catch (e) {}
  }

  function getDeviceCombinedEvents(device) {
    const custom = getStoredEvents(device.deviceId);
    // Combine with global app.js events if available
    const appEv = (typeof ev !== 'undefined' && Array.isArray(ev))
      ? ev.filter(e => e.d === device.deviceId || e.deviceId === device.deviceId)
      : [];
    return custom.concat(appEv);
  }

  function evaluateDevice(device, cfg) {
    if (!Engine) return { score: 0, severity: 'Low', confidence: 'Low', contributions: [], unknowns: [], explanation: 'Engine unavailable' };
    const config = cfg || getSavedConfig() || Engine.DEFAULT_CONFIG;
    const events = getDeviceCombinedEvents(device);
    const baseline = { avgBytesOut: 150, avgDuration: 60, avgConnCount: 2 };

    const netS = Engine.detectNetworkChanges(device, events);
    const flowS = Engine.analyseFlows(device, events.filter(e => e.type === 'flow' || e.s != null), baseline);
    const idS = Engine.correlateIdentity(device, events.filter(e => e.type === 'auth'), events.filter(e => e.type === 'device_status'));
    
    // Check telemetry health
    const health = Data ? Data.getTelemetryHealth(device.deviceId) : { vpn: 'ok' };
    const missingSignals = [];
    if (health.vpn === 'missing') {
      missingSignals.push({
        signal: 'unknown_telemetry',
        group: 'vpn',
        confidence: 'Low',
        description: 'No VPN logs for 6 h: authentication risk could not be assessed',
        timestamp: Date.now(),
        provenance: 'observed'
      });
    }
    if (health.flow === 'missing') {
      missingSignals.push({
        signal: 'missing_flow_telemetry',
        group: 'traffic',
        confidence: 'Low',
        description: 'No flow telemetry received, status unknown, not evidence of safety',
        timestamp: Date.now(),
        provenance: 'observed'
      });
    }

    const transferSignals = Engine.detectTransferAnomalies(device, events, config);
    const allSignals = netS.concat(flowS, idS, missingSignals, transferSignals);
    return Engine.scoreDevice(device, allSignals, config);
  }

  function ingestSimulationTransfer(event) {
    if (!event || event.type !== 'transfer' || event.provenance !== 'SIMULATED' || !event.sourceDeviceId) {
      throw new Error('Only explicitly SIMULATED transfer events can enter the device-risk pipeline.');
    }
    addStoredEvents(event.sourceDeviceId, [event]);
  }

  function evaluateSimulationDevice(deviceId) {
    const identities = {
      'DEV-001': { assignedUser: 'Emil', department: 'Admin', trustedNetworks: ['corp_wifi', 'vpn'] },
      'DEV-002': { assignedUser: 'Manasvi', department: 'Employer', trustedNetworks: ['corp_wifi'] },
      'DEV-003': { assignedUser: 'Sameera', department: 'Insider', trustedNetworks: ['home'] },
      'DEV-004': { assignedUser: 'Keona', department: 'Outsider', trustedNetworks: [] }
    };
    const identity = identities[deviceId];
    if (!identity) throw new Error(`Unknown simulation device: ${deviceId}`);
    const device = Object.assign({ deviceId, status: 'active' }, identity);
    if (!Engine) throw new Error('Device risk engine is unavailable.');

    return evaluateDevice(device);
  }

  function resetSimulationEvents() {
    const map = getStoredEvents();
    Object.keys(map).forEach(deviceId => {
      map[deviceId] = (map[deviceId] || []).filter(event => event.provenance !== 'SIMULATED');
    });
    saveStoredEvents(map);
  }

  // ---------------- PAGE: Dashboard ----------------
  function renderDashboard() {
    const s1 = document.querySelector('#s1');
    if (!s1 || document.querySelector('#dr-dashboard-panel')) return;
    if (!Data || !Engine) return;

    const panel = document.createElement('div');
    panel.id = 'dr-dashboard-panel';
    panel.className = 'panel dr-panel';

    const devices = Data.getDevices();
    let cardsHtml = '';

    devices.forEach(dev => {
      const result = evaluateDevice(dev);
      const sevClass = result.severity.toLowerCase();
      const statusLabel = dev.status === 'reported_stolen' ? 'REPORTED STOLEN' : 'Active';
      const actionLabel = result.score >= 30 ? 'SIMULATED' : 'Monitored';

      cardsHtml += `
        <div class="dr-card">
          <div class="dr-meta-row">
            <b>${esc(dev.deviceId)}</b>
            <span class="dr-badge dr-${sevClass}">${esc(result.severity)} (${result.score})</span>
          </div>
          <div class="dr-score-bar">
            <div class="dr-score-fill dr-${sevClass}" style="width: ${Math.min(100, Math.max(8, result.score))}%"></div>
          </div>
          <div class="dr-meta-row" style="font-size:12px;">
            <span>User: ${esc(dev.assignedUser)} (${esc(dev.department)})</span>
            <span>Conf: <b>${esc(result.confidence)}</b></span>
          </div>
          <div class="dr-meta-row" style="font-size:11px; margin-top:4px;">
            <span>Status: <b style="${dev.status === 'reported_stolen' ? 'color:var(--hi)' : ''}">${esc(statusLabel)}</b></span>
            <span class="dr-label-sim">${esc(actionLabel)}</span>
          </div>
        </div>
      `;
    });

    panel.innerHTML = `
      <div class="dr-header">
        <div>
          <h3 class="dr-title">Device Risk Overview</h3>
          <span style="font-size:12px;color:var(--mu);">Adaptive risk detection from encrypted traffic, identity &amp; network telemetry</span>
        </div>
        <div class="dr-banner">
          <span>●</span> DEMO MODE — All response actions are simulated
        </div>
      </div>
      <div class="dr-grid">
        ${cardsHtml}
      </div>
    `;

    s1.appendChild(panel);
  }

  // ---------------- PAGE: Traffic Analysis ----------------
  function renderTraffic() {
    const s2 = document.querySelector('#s2');
    if (!s2 || document.querySelector('#dr-traffic-panel')) return;
    if (!Data) return;

    const panel = document.createElement('div');
    panel.id = 'dr-traffic-panel';
    panel.className = 'panel dr-panel';

    const devices = Data.getDevices();
    let devOptions = devices.map(d => `<option value="${esc(d.deviceId)}">${esc(d.deviceId)} (${esc(d.assignedUser)})</option>`).join('');

    panel.innerHTML = `
      <div class="dr-header">
        <div>
          <h3 class="dr-title">Encrypted Flow Anomaly Inspector</h3>
          <span style="font-size:12px;color:var(--mu);">Per-device transfer timeline &amp; telemetry provenance</span>
        </div>
        <div>
          <select id="dr-traffic-dev-select" class="b" style="padding:4px 8px;">
            ${devOptions}
          </select>
        </div>
      </div>
      <div style="display:flex;gap:12px;margin-bottom:12px;font-size:12px;flex-wrap:wrap;">
        <span class="dr-pill" style="border:1px solid var(--bd);">Observed Metadata (Raw Flows)</span>
        <span class="dr-pill" style="border:1px solid var(--amb);color:var(--amb);">Inferred Behaviour (Matching Detection Engine Findings)</span>
      </div>
      <div class="tw">
        <table class="dr-audit-table" id="dr-traffic-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Device</th>
              <th>Observed: Dest / Bytes / Duration</th>
              <th>Observed: Protocol &amp; Conn</th>
              <th>Inferred Findings &amp; Severity</th>
            </tr>
          </thead>
          <tbody id="dr-traffic-tbody">
          </tbody>
        </table>
      </div>
    `;

    s2.appendChild(panel);

    function updateTrafficTable(devId) {
      const dev = devices.find(d => d.deviceId === devId) || devices[0];
      const tbody = document.querySelector('#dr-traffic-tbody');
      if (!tbody) return;

      // Special handling for DEV-003 or devices with missing flow telemetry
      const health = Data.getTelemetryHealth(dev.deviceId);
      if (dev.deviceId === 'DEV-003' || health.flow === 'missing') {
        const epStatus = (health.endpoint || 'delayed').toUpperCase();
        const flowStatus = (health.flow || 'missing').toUpperCase();
        const idpStatus = (health.idp || 'ok').toUpperCase();
        const vpnStatus = (health.vpn || 'missing').toUpperCase();
        const mdmStatus = (health.mdm || 'delayed').toUpperCase();

        tbody.innerHTML = `
          <tr>
            <td colspan="5" style="padding:22px 14px; text-align:center;">
              <div style="font-size:14px; font-weight:600; color:var(--amb); margin-bottom:10px;">
                ⚠ No flow telemetry received, status unknown, not evidence of safety
              </div>
              <div style="font-size:12px; color:var(--mu); margin-bottom:10px;">
                Telemetry Source Health for <b>${esc(dev.deviceId)}</b> (${esc(dev.assignedUser)} · ${esc(dev.department)}):
              </div>
              <div style="display:flex; justify-content:center; gap:8px; flex-wrap:wrap;">
                <span class="dr-pill" style="border:1px solid ${epStatus === 'OK' ? 'var(--ok)' : 'var(--amb)'}; color:${epStatus === 'OK' ? 'var(--ok)' : 'var(--amb)'};">Endpoint: ${esc(epStatus)}</span>
                <span class="dr-pill" style="border:1px solid var(--hi); color:var(--hi); font-weight:700;">Flow: ${esc(flowStatus)}</span>
                <span class="dr-pill" style="border:1px solid ${idpStatus === 'OK' ? 'var(--ok)' : 'var(--amb)'}; color:${idpStatus === 'OK' ? 'var(--ok)' : 'var(--amb)'};">IdP: ${esc(idpStatus)}</span>
                <span class="dr-pill" style="border:1px solid ${vpnStatus === 'OK' ? 'var(--ok)' : 'var(--hi)'}; color:${vpnStatus === 'OK' ? 'var(--ok)' : 'var(--hi)'};">VPN: ${esc(vpnStatus)}</span>
                <span class="dr-pill" style="border:1px solid ${mdmStatus === 'OK' ? 'var(--ok)' : 'var(--amb)'}; color:${mdmStatus === 'OK' ? 'var(--ok)' : 'var(--amb)'};">MDM: ${esc(mdmStatus)}</span>
              </div>
            </td>
          </tr>
        `;
        return;
      }

      const events = getDeviceCombinedEvents(dev);
      const flows = events.filter(e => e.type === 'flow' || e.s != null);

      if (flows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--mu);padding:14px;">No flow events recorded for ${esc(dev.deviceId)}. Run a scenario from the Developer Console to populate live anomalies.</td></tr>`;
        return;
      }

      let rows = '';
      flows.slice(-10).reverse().forEach(f => {
        const ts = f.ts ? new Date(f.ts).toLocaleTimeString() : 'Recent';
        const dest = f.dest || f.d || 'unknown.internal';
        const bytes = f.bytesOut != null ? `${f.bytesOut} MB` : (f.b ? `${Math.round(f.b/1000)} KB` : 'N/A');
        const dur = f.durationSec ? `${f.durationSec}s` : (f.dur ? `${f.dur}s` : '30s');
        const proto = f.protocol || 'HTTPS';
        const conns = f.connectionCount || 1;

        // Inferred finding
        let inferredText = '';
        let badgeClass = 'dr-low';

        if (f.inferred && f.inferred.anomaly) {
          inferredText = f.inferred.anomaly;
          badgeClass = f.inferred.badgeClass || (f.inferred.severity === 'High' ? 'dr-high' : f.inferred.severity === 'Medium' ? 'dr-medium' : 'dr-low');
        } else {
          const isNovel = f.destNovelty === 'new' || (f.risk && f.risk !== 'normal');
          const isOutlier = (f.bytesOut && f.bytesOut > 300) || f.risk === 'high';
          if (isOutlier) {
            inferredText = 'Large Outbound Anomaly (+Deviation)';
            badgeClass = 'dr-high';
          } else if (isNovel) {
            inferredText = 'Destination Novelty (+Unfamiliar)';
            badgeClass = 'dr-medium';
          } else {
            inferredText = 'Normal baseline';
            badgeClass = 'dr-low';
          }
        }

        rows += `
          <tr>
            <td>${esc(ts)}</td>
            <td><b>${esc(dev.deviceId)}</b></td>
            <td><code>${esc(dest)}</code> &bull; ${esc(bytes)} &bull; ${esc(dur)}</td>
            <td><span class="dr-pill">${esc(proto)}</span> &times;${esc(conns)}</td>
            <td><span class="dr-badge ${badgeClass}">${esc(inferredText)}</span></td>
          </tr>
        `;
      });
      tbody.innerHTML = rows;
    }

    const sel = document.querySelector('#dr-traffic-dev-select');
    if (sel) {
      sel.addEventListener('change', e => updateTrafficTable(e.target.value));
      updateTrafficTable(sel.value);
    }
  }

  // ---------------- PAGE: Alerts ----------------
  function renderAlerts() {
    const s4 = document.querySelector('#s4');
    if (!s4 || document.querySelector('#dr-alerts-panel')) return;
    if (!Data) return;

    const panel = document.createElement('div');
    panel.id = 'dr-alerts-panel';
    panel.className = 'panel dr-panel';

    const dev = Data.getDevices()[0]; // Default to DEV-001 (Alice)
    const result = evaluateDevice(dev);

    panel.innerHTML = `
      <div class="dr-header">
        <div>
          <h3 class="dr-title">Device Risk Correlation &amp; Explanations</h3>
          <span style="font-size:12px;color:var(--mu);">Score breakdown, contributing factors, missing telemetry &amp; recommended actions</span>
        </div>
        <div>
          <span class="dr-badge dr-${result.severity.toLowerCase()}">${esc(result.severity)} Risk (Score ${result.score}/100)</span>
          <span class="dr-pill">Confidence: ${esc(result.confidence)}</span>
        </div>
      </div>
      <div class="dr-grid" style="grid-template-columns: 1fr 1fr;">
        <div class="dr-card">
          <h4 style="margin:0 0 6px;color:var(--tx);">Contributing Risk Factors</h4>
          <ul class="rs" id="dr-alert-factors" style="padding-left:16px;margin:0;">
            ${result.contributions.length > 0
              ? result.contributions.map(c => `<li><b>+${c.points} pts</b> [${esc(c.group)}]: ${esc(c.reason)}</li>`).join('')
              : '<li>No anomalous signals detected for baseline device.</li>'
            }
          </ul>
          ${result.unknowns.length > 0 ? `
            <div style="margin-top:10px;padding:8px;background:rgba(227,182,96,.1);border-left:3px solid var(--amb);font-size:12px;color:var(--amb);">
              <b>Missing Telemetry Warning:</b> ${esc(result.unknowns.join(', '))} telemetry absent. Risk was NOT marked safe; confidence lowered to ${esc(result.confidence)}.
            </div>
          ` : ''}
        </div>
        <div class="dr-card">
          <h4 style="margin:0 0 6px;color:var(--tx);">Recommended Response</h4>
          <p style="font-size:13px;margin:4px 0;" id="dr-alert-rec">
            ${result.severity === 'Critical'
              ? '<b>Immediate Containment Recommended:</b> Initiate endpoint isolation and credential revocation with responder approval.'
              : result.severity === 'High'
                ? '<b>Active Investigation Recommended:</b> Request step-up MFA and review destination novelty.'
                : '<b>Monitor &amp; Log:</b> Retain flow logs and track baseline.'
            }
          </p>
          <div style="display:flex;gap:8px;margin-top:12px;">
            <button class="b" id="dr-btn-ack">Acknowledge</button>
            <button class="b" id="dr-btn-note">Add Note</button>
            <a href="incidents.html" class="b p">Open Investigation &rarr;</a>
          </div>
        </div>
      </div>
    `;

    s4.appendChild(panel);

    const btnAck = panel.querySelector('#dr-btn-ack');
    if (btnAck) {
      btnAck.addEventListener('click', () => {
        if (Response) {
          Response.addAudit({
            when: Date.now(),
            who: Response.getCurrentRole(),
            what: 'acknowledge_alert',
            device: dev.deviceId,
            result: 'CONFIRMED by analyst',
            message: `Alert acknowledged for ${dev.deviceId}`
          });
        }
        btnAck.disabled = true;
        btnAck.textContent = 'Acknowledged ✓';
        if (typeof toast === 'function') toast(`Alert acknowledged for ${dev.deviceId}`);
      });
    }

    const btnNote = panel.querySelector('#dr-btn-note');
    if (btnNote) {
      btnNote.addEventListener('click', () => {
        const note = prompt(`Add analyst investigation note for ${dev.deviceId}:`);
        if (note && note.trim()) {
          if (Response) {
            Response.addAudit({
              when: Date.now(),
              who: Response.getCurrentRole(),
              what: 'add_note',
              device: dev.deviceId,
              result: 'CONFIRMED by analyst',
              message: `Note: ${note.trim()}`
            });
          }
          if (typeof toast === 'function') toast(`Note saved for ${dev.deviceId}`);
        }
      });
    }
  }

  // ---------------- PAGE: Incidents ----------------
  function renderIncidents() {
    const s5 = document.querySelector('#s5');
    if (!s5 || document.querySelector('#dr-incidents-panel')) return;
    if (!Data || !Response) return;

    const panel = document.createElement('div');
    panel.id = 'dr-incidents-panel';
    panel.className = 'panel dr-panel';

    const devices = Data.getDevices();
    const dev = devices[0]; // DEV-001 (Alice)
    const result = evaluateDevice(dev);
    const auditLogs = Response.loadAudit();
    const role = Response.getCurrentRole();

    let auditRows = '';
    if (auditLogs.length === 0) {
      auditRows = `<tr><td colspan="4" style="text-align:center;color:var(--mu);">No actions logged in audit trail yet.</td></tr>`;
    } else {
      auditLogs.slice(-6).reverse().forEach(a => {
        auditRows += `
          <tr>
            <td>${new Date(a.when).toLocaleTimeString()}</td>
            <td><b>${esc(a.who)}</b></td>
            <td><code>${esc(a.what)}</code> (${esc(a.device || '-')})</td>
            <td><span class="dr-label-sim">${esc(a.result || 'SIMULATED')}</span> ${esc(a.message || '')}</td>
          </tr>
        `;
      });
    }

    panel.innerHTML = `
      <div class="dr-header">
        <div>
          <h3 class="dr-title">Incident Response &amp; Containment Workflow</h3>
          <span style="font-size:12px;color:var(--mu);">Graduated response actions, two-step confirmation safeguards &amp; append-only audit log</span>
        </div>
        <div class="dr-banner">
          <span>●</span> Current Role: <b id="dr-incident-role">${esc(role.toUpperCase())}</b>
        </div>
      </div>
      <div class="dr-grid" style="grid-template-columns: 1fr 1fr;">
        <div class="dr-card">
          <div class="dr-meta-row">
            <h4>Target Device: ${esc(dev.deviceId)} (${esc(dev.assignedUser)})</h4>
            <span class="dr-badge dr-${result.severity.toLowerCase()}">${esc(result.severity)}</span>
          </div>
          <p style="font-size:13px;color:var(--mu);margin:4px 0;">
            Containment actions require <b>responder</b> or <b>admin</b> privileges and strict two-step confirmation.
          </p>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;">
            <button class="b" id="dr-btn-stepup" style="border-color:var(--amb);">Request Step-Up Auth</button>
            <button class="b p" id="dr-btn-isolate" style="background:var(--hi);color:#fff;">Isolate Endpoint</button>
          </div>
          <div id="dr-incident-response-msg" style="margin-top:10px;font-size:13px;"></div>
        </div>
        <div class="dr-card">
          <h4>Append-Only Audit Trail (lldr_audit)</h4>
          <div class="tw" style="max-height:160px;overflow-y:auto;">
            <table class="dr-audit-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Result &amp; Details</th>
                </tr>
              </thead>
              <tbody id="dr-incident-audit-body">
                ${auditRows}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    s5.appendChild(panel);

    // Two-step confirmation dialog handler
    function showConfirmDialog(actionName, targetDeviceId, onConfirmed) {
      const backdrop = document.createElement('div');
      backdrop.className = 'dr-dialog-backdrop';
      backdrop.innerHTML = `
        <div class="dr-dialog">
          <h4>⚠ Confirm Destructive Containment Action</h4>
          <p>You are requesting <b>${esc(actionName.toUpperCase())}</b> for <code>${esc(targetDeviceId)}</code>.</p>
          <p>To prevent accidental isolation, type the exact device ID below to confirm:</p>
          <input type="text" id="dr-confirm-input" placeholder="Type ${esc(targetDeviceId)}" autocomplete="off" />
          <div class="dr-actions">
            <button class="b" id="dr-dialog-cancel">Cancel</button>
            <button class="b p" id="dr-dialog-proceed" style="background:var(--hi);color:#fff;" disabled>Confirm Action</button>
          </div>
        </div>
      `;
      document.body.appendChild(backdrop);

      const input = backdrop.querySelector('#dr-confirm-input');
      const btnProceed = backdrop.querySelector('#dr-dialog-proceed');
      const btnCancel = backdrop.querySelector('#dr-dialog-cancel');

      input.addEventListener('input', () => {
        btnProceed.disabled = input.value.trim() !== targetDeviceId;
      });

      btnCancel.addEventListener('click', () => {
        backdrop.remove();
      });

      btnProceed.addEventListener('click', () => {
        backdrop.remove();
        onConfirmed();
      });
    }

    const btnStepup = panel.querySelector('#dr-btn-stepup');
    const btnIsolate = panel.querySelector('#dr-btn-isolate');
    const msgDiv = panel.querySelector('#dr-incident-response-msg');

    if (btnStepup) {
      btnStepup.addEventListener('click', async () => {
        msgDiv.textContent = 'Executing step-up auth...';
        try {
          const res = await Response.performAction('stepup', dev, { user: Response.getCurrentRole() });
          msgDiv.innerHTML = `<span class="dr-label-sim">${esc(res.statusLabel || 'SIMULATED')}</span> ${esc(res.message)}`;
          refreshAuditTable();
        } catch (err) {
          msgDiv.innerHTML = `<span style="color:var(--hi);">Error: ${esc(err.message)}</span>`;
        }
      });
    }

    if (btnIsolate) {
      btnIsolate.addEventListener('click', () => {
        // First check role
        if (!Response.canExecute('contain')) {
          msgDiv.innerHTML = `<span style="color:var(--hi);">Access Denied: Current role '${esc(Response.getCurrentRole())}' cannot execute isolation. Switch to 'responder' or 'admin' in Developer Console.</span>`;
          return;
        }

        showConfirmDialog('Endpoint Isolation', dev.deviceId, async () => {
          msgDiv.textContent = 'Executing containment request...';
          try {
            const res = await Response.performAction('contain', dev, { user: Response.getCurrentRole() });
            msgDiv.innerHTML = `<span class="dr-label-sim">${esc(res.statusLabel || 'SIMULATED')}</span> ${esc(res.message)}`;
            refreshAuditTable();
            if (typeof toast === 'function') toast(`Isolation requested for ${dev.deviceId}`);
          } catch (err) {
            msgDiv.innerHTML = `<span style="color:var(--hi);">Error: ${esc(err.message)}</span>`;
          }
        });
      });
    }

    function refreshAuditTable() {
      const tbody = document.querySelector('#dr-incident-audit-body');
      if (!tbody) return;
      const logs = Response.loadAudit();
      let rows = '';
      logs.slice(-6).reverse().forEach(a => {
        rows += `
          <tr>
            <td>${new Date(a.when).toLocaleTimeString()}</td>
            <td><b>${esc(a.who)}</b></td>
            <td><code>${esc(a.what)}</code> (${esc(a.device || '-')})</td>
            <td><span class="dr-label-sim">${esc(a.result || 'SIMULATED')}</span> ${esc(a.message || '')}</td>
          </tr>
        `;
      });
      tbody.innerHTML = rows;
    }
  }

  // ---------------- PAGE: Developer Console ----------------
  function renderDeveloper() {
    const s6 = document.querySelector('#s6');
    if (!s6 || document.querySelector('#dr-dev-panel')) return;
    if (!Data || !Engine || !Response) return;

    const panel = document.createElement('div');
    panel.id = 'dr-dev-panel';
    panel.className = 'panel dr-panel';

    const cfg = getSavedConfig() || Engine.DEFAULT_CONFIG;
    const health = Data.getTelemetryHealth('DEV-001');
    const currentRole = Response.getCurrentRole();

    panel.innerHTML = `
      <div class="dr-header">
        <div>
          <h3 class="dr-title">Adaptive Engine &amp; Response Diagnostics</h3>
          <span style="font-size:12px;color:var(--mu);">Live scenario injection, tunable thresholds, telemetry health &amp; role simulation</span>
        </div>
        <div>
          <label style="font-size:12px;color:var(--mu);margin-right:8px;">Demo Role:</label>
          <select id="dr-role-select" class="b" style="padding:4px 8px;">
            <option value="viewer" ${currentRole === 'viewer' ? 'selected' : ''}>Viewer</option>
            <option value="analyst" ${currentRole === 'analyst' ? 'selected' : ''}>Analyst</option>
            <option value="responder" ${currentRole === 'responder' ? 'selected' : ''}>Responder</option>
            <option value="admin" ${currentRole === 'admin' ? 'selected' : ''}>Admin</option>
          </select>
        </div>
      </div>

      <!-- Demo Scenarios -->
      <div class="dr-card" style="margin-bottom:14px;background:rgba(47,74,129,.3);">
        <h4 style="margin:0 0 6px;color:var(--tx);">Interactive Reviewer Demo Scenarios</h4>
        <p style="font-size:13px;color:var(--mu);margin:0 0 10px;">
          Inject synthetic telemetry to test acceptance criteria live across all pages.
        </p>
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <button class="b p" id="dr-scen-stolen">Run Stolen-Laptop Scenario (Criterion c)</button>
          <button class="b" id="dr-scen-net">Run Network-Change-Only (Criterion a)</button>
          <button class="b" id="dr-scen-gap">Run Telemetry Gap (Criterion d)</button>
          <button class="b" id="dr-scen-reset" style="color:var(--hi);border-color:rgba(255,107,122,.5);">Reset Demo State</button>
        </div>
        <div id="dr-scen-feedback" style="margin-top:8px;font-size:12px;color:var(--cy);"></div>
      </div>

      <div class="dr-grid" style="grid-template-columns: 1fr 1fr;">
        <!-- Thresholds & Weights -->
        <div class="dr-card">
          <h4>Configurable Thresholds &amp; Weights</h4>
          <div style="font-size:12px;display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:6px;">
            <div>
              <label>Weight (Traffic):</label>
              <input type="number" step="0.05" id="dr-cfg-w-traffic" value="${cfg.weights.traffic}" style="width:100%;padding:4px;background:#10131a;border:1px solid var(--bd);color:var(--tx);" />
            </div>
            <div>
              <label>Weight (Network):</label>
              <input type="number" step="0.05" id="dr-cfg-w-net" value="${cfg.weights.network}" style="width:100%;padding:4px;background:#10131a;border:1px solid var(--bd);color:var(--tx);" />
            </div>
            <div>
              <label>Weight (Identity):</label>
              <input type="number" step="0.05" id="dr-cfg-w-id" value="${cfg.weights.identity}" style="width:100%;padding:4px;background:#10131a;border:1px solid var(--bd);color:var(--tx);" />
            </div>
            <div>
              <label>Weight (Status):</label>
              <input type="number" step="0.05" id="dr-cfg-w-stat" value="${cfg.weights.status}" style="width:100%;padding:4px;background:#10131a;border:1px solid var(--bd);color:var(--tx);" />
            </div>
            <div>
              <label>Threshold (Critical):</label>
              <input type="number" id="dr-cfg-th-crit" value="${cfg.thresholds.critical}" style="width:100%;padding:4px;background:#10131a;border:1px solid var(--bd);color:var(--tx);" />
            </div>
            <div>
              <label>Threshold (High):</label>
              <input type="number" id="dr-cfg-th-high" value="${cfg.thresholds.high}" style="width:100%;padding:4px;background:#10131a;border:1px solid var(--bd);color:var(--tx);" />
            </div>
          </div>
          <div style="display:flex;gap:8px;margin-top:12px;">
            <button class="b" id="dr-cfg-apply">Apply &amp; Live Re-score</button>
            <button class="b" id="dr-cfg-reset">Reset to Defaults</button>
          </div>
        </div>

        <!-- Telemetry Health & Adapters -->
        <div class="dr-card">
          <h4>Telemetry Health &amp; Integrations</h4>
          <div style="font-size:12px;margin-top:6px;">
            <p style="margin:4px 0;">Telemetry Sources:</p>
            <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;">
              <span class="dr-pill">Endpoint: ${esc((health.endpoint || 'ok').toUpperCase())}</span>
              <span class="dr-pill">Flow: ${esc((health.flow || 'ok').toUpperCase())}</span>
              <span class="dr-pill">IdP: ${esc((health.idp || 'ok').toUpperCase())}</span>
              <span class="dr-pill" style="${health.vpn === 'missing' ? 'color:var(--amb);border-color:var(--amb);' : ''}">VPN: ${esc((health.vpn || 'ok').toUpperCase())}</span>
              <span class="dr-pill">MDM: ${esc((health.mdm || 'ok').toUpperCase())}</span>
            </div>
            <p style="margin:4px 0;">Response Adapters:</p>
            <ul style="padding-left:16px;margin:4px 0;color:var(--mu);">
              <li><b>SimulatedAdapter:</b> Active (Demonstration mode)</li>
              <li><b>ExampleIdentityAdapter:</b> Not configured (Stubs only)</li>
              <li><b>ExampleEndpointAdapter:</b> Not configured (Stubs only)</li>
            </ul>
          </div>
        </div>
      </div>
    `;

    s6.appendChild(panel);

    // Wire Role change
    const roleSel = panel.querySelector('#dr-role-select');
    if (roleSel) {
      roleSel.addEventListener('change', () => {
        Response.setRole(roleSel.value);
        if (typeof toast === 'function') toast(`Active role changed to ${roleSel.value}`);
      });
    }

    // Wire Scenarios
    const fb = panel.querySelector('#dr-scen-feedback');
    const btnStolen = panel.querySelector('#dr-scen-stolen');
    const btnNet = panel.querySelector('#dr-scen-net');
    const btnGap = panel.querySelector('#dr-scen-gap');
    const btnReset = panel.querySelector('#dr-scen-reset');

    if (btnStolen) {
      btnStolen.addEventListener('click', () => {
        const events = Data.getStolenLaptopScenario('DEV-001');
        addStoredEvents('DEV-001', events);
        Response.addAudit({
          when: Date.now(),
          who: 'demo_runner',
          what: 'scenario_stolen_laptop',
          device: 'DEV-001',
          result: 'SIMULATED',
          message: 'Stolen-laptop scenario injected: unfamiliar network, large flow, and auth anomaly.'
        });
        fb.textContent = '✓ Stolen-laptop scenario injected into DEV-001. Score raised to Critical. View in Dashboard, Traffic, Alerts or Incidents.';
        if (typeof toast === 'function') toast('Stolen laptop scenario injected for DEV-001');
      });
    }

    if (btnNet) {
      btnNet.addEventListener('click', () => {
        const events = Data.getNetworkChangeOnlyScenario('DEV-001');
        addStoredEvents('DEV-001', events);
        fb.textContent = '✓ Network-change-only scenario injected. Verifies score does NOT reach Critical on network change alone.';
        if (typeof toast === 'function') toast('Network change event injected');
      });
    }

    if (btnGap) {
      btnGap.addEventListener('click', () => {
        Data.setTelemetryHealth('vpn', 'missing');
        const events = Data.getTelemetryGapScenario('DEV-001');
        addStoredEvents('DEV-001', events);
        fb.textContent = '✓ Telemetry gap scenario injected. VPN marked missing; confidence drops to Low while score is preserved.';
        if (typeof toast === 'function') toast('VPN telemetry gap injected');
      });
    }

    if (btnReset) {
      btnReset.addEventListener('click', () => {
        clearStoredEvents();
        try {
          sessionStorage.removeItem(SK_EVENTS);
          sessionStorage.removeItem(SK_DEVICES);
          sessionStorage.removeItem(SK_HEALTH);
          sessionStorage.removeItem(SK_INFERRED);
          sessionStorage.removeItem(SK_SEEDED);
          sessionStorage.removeItem('lldr_audit');
        } catch (e) {}
        seedSampleDataIfNeeded(true);
        if (Data && Data.resetTelemetryHealth) Data.resetTelemetryHealth();
        fb.textContent = '✓ Demo state reset and sample data re-seeded.';
        if (typeof toast === 'function') toast('Demo state reset');
      });
    }

    // Wire Config Apply
    const btnApply = panel.querySelector('#dr-cfg-apply');
    const btnResetCfg = panel.querySelector('#dr-cfg-reset');

    if (btnApply) {
      btnApply.addEventListener('click', () => {
        const newCfg = {
          weights: {
            traffic: parseFloat(panel.querySelector('#dr-cfg-w-traffic').value) || 0.35,
            network: parseFloat(panel.querySelector('#dr-cfg-w-net').value) || 0.3,
            identity: parseFloat(panel.querySelector('#dr-cfg-w-id').value) || 0.25,
            status: parseFloat(panel.querySelector('#dr-cfg-w-stat').value) || 0.2
          },
          thresholds: {
            low: cfg.thresholds.low || 0,
            medium: cfg.thresholds.medium || 5,
            high: parseInt(panel.querySelector('#dr-cfg-th-high').value, 10) || 15,
            critical: parseInt(panel.querySelector('#dr-cfg-th-crit').value, 10) || 30
          },
          damping: cfg.damping || 0.3,
          corroborationBonus: cfg.corroborationBonus || 0.1
        };
        saveConfig(newCfg);
        fb.textContent = '✓ Engine weights and thresholds updated and saved.';
        if (typeof toast === 'function') toast('Engine config updated');
      });
    }

    if (btnResetCfg) {
      btnResetCfg.addEventListener('click', () => {
        try { sessionStorage.removeItem(SK_CONFIG); } catch (e) {}
        fb.textContent = '✓ Engine config reset to default values.';
        if (typeof toast === 'function') toast('Config reset to defaults');
      });
    }
  }

  // ---------------- Master Init ----------------
  function init() {
    seedSampleDataIfNeeded(false);
    const page = document.body ? document.body.dataset.page : '';
    if (page === 'dashboard') renderDashboard();
    else if (page === 'traffic') renderTraffic();
    else if (page === 'alerts') renderAlerts();
    else if (page === 'incidents') renderIncidents();
    else if (page === 'dev') renderDeveloper();
  }

  return {
    init,
    seedSampleDataIfNeeded,
    evaluateDevice,
    getConfig: getSavedConfig,
    ingestSimulationTransfer,
    evaluateSimulationDevice,
    resetSimulationEvents,
    renderDashboard,
    renderTraffic,
    renderAlerts,
    renderIncidents,
    renderDeveloper
  };
}));
