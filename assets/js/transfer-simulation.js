(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.lldrTransferSimulation = factory();
  }
}(this, function () {
  const DEVICE_LIST = [
    { id: 'DEV-001', user: 'Emil', role: 'Admin' },
    { id: 'DEV-002', user: 'Manasvi', role: 'Employer' },
    { id: 'DEV-003', user: 'Sameera', role: 'Insider' },
    { id: 'DEV-004', user: 'Keona', role: 'Outsider' }
  ];
  const STORAGE_KEY = 'lldr_simulated_transfers';
  const DEVICE_POSITIONS = {
    'DEV-001': { x: 135, y: 105 },
    'DEV-002': { x: 505, y: 105 },
    'DEV-003': { x: 505, y: 295 },
    'DEV-004': { x: 135, y: 295 }
  };
  const listeners = { transfer: [], reset: [] };
  let intervalId = null;
  let sequence = 0;
  let insiderCount = 0;

  function createTransfer(sequenceNumber, now) {
    const isInsiderTransfer = sequenceNumber % 2 === 0;
    let sourceDeviceId;
    let destinationDeviceId;
    let bytes;
    let protocol;

    if (isInsiderTransfer) {
      insiderCount += 1;
      sourceDeviceId = 'DEV-003';
      destinationDeviceId = 'DEV-004';
      bytes = 450000 + insiderCount * 520000;
      protocol = 'HTTPS';
    } else {
      const background = [
        ['DEV-001', 'DEV-002'],
        ['DEV-002', 'DEV-001'],
        ['DEV-001', 'DEV-003']
      ][Math.floor((sequenceNumber - 1) / 2) % 3];
      sourceDeviceId = background[0];
      destinationDeviceId = background[1];
      bytes = 24000 + (sequenceNumber % 4) * 17000;
      protocol = sequenceNumber % 3 === 0 ? 'SMB' : 'HTTPS';
    }

    return {
      id: `SIM-${String(sequenceNumber).padStart(5, '0')}`,
      type: 'transfer',
      sourceDeviceId,
      destinationDeviceId,
      ts: now,
      timestamp: new Date(now).toISOString(),
      protocol,
      bytes,
      status: 'SIMULATED',
      provenance: 'SIMULATED'
    };
  }

  function emit(type, value) {
    listeners[type].slice().forEach(listener => listener(value));
  }

  function on(type, listener) {
    if (!listeners[type] || typeof listener !== 'function') throw new Error(`Unsupported simulation event: ${type}`);
    listeners[type].push(listener);
    return () => {
      listeners[type] = listeners[type].filter(candidate => candidate !== listener);
    };
  }

  function start(intervalMs = 1800) {
    if (intervalId !== null) return;
    intervalId = setInterval(() => {
      sequence += 1;
      emit('transfer', createTransfer(sequence, Date.now()));
    }, intervalMs);
  }

  function pause() {
    if (intervalId === null) return;
    clearInterval(intervalId);
    intervalId = null;
  }

  function reset() {
    pause();
    sequence = 0;
    insiderCount = 0;
    emit('reset');
  }

  return {
    DEVICE_LIST,
    DEVICE_POSITIONS,
    createTransfer,
    on,
    start,
    pause,
    reset,
    isRunning: () => intervalId !== null
  };
}));

(function (root) {
  if (typeof window === 'undefined' || !document.querySelector('#g')) return;

  const Simulation = root.lldrTransferSimulation;
  const DEVICE_POSITIONS = Simulation.DEVICE_POSITIONS;
  const RiskUI = root.lldrDeviceUI;
  const Engine = root.lldrDeviceEngine;
  const svg = document.querySelector('#g');
  const controls = document.querySelector('#transfer-controls');
  const feed = document.querySelector('#transfer-feed');
  const details = document.querySelector('#dt');
  const events = [];
  let selectedEventId = null;
  let activeWindow = 24;

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, char => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
  }

  function formatBytes(bytes) {
    return bytes >= 1048576 ? `${(bytes / 1048576).toFixed(2)} MB` : `${Math.round(bytes / 1024)} KB`;
  }

  function readStoredEvents() {
    try {
      const stored = sessionStorage.getItem('lldr_simulated_transfers');
      const parsed = stored ? JSON.parse(stored) : [];
      return Array.isArray(parsed) ? parsed.filter(event => event.provenance === 'SIMULATED') : [];
    } catch (error) {
      console.error('Could not load simulated transfer history:', error);
      return [];
    }
  }

  function saveEvents() {
    try {
      sessionStorage.setItem('lldr_simulated_transfers', JSON.stringify(events));
    } catch (error) {
      console.error('Could not save simulated transfer history:', error);
    }
  }

  function device(id) {
    return Simulation.DEVICE_LIST.find(entry => entry.id === id);
  }

  function deviceRisk(id) {
    return RiskUI.evaluateSimulationDevice(id);
  }

  function assessEvent(event) {
    const config = RiskUI.getConfig() || Engine.DEFAULT_CONFIG;
    const risk = deviceRisk(event.sourceDeviceId);
    const signals = Engine.detectTransferAnomalies(
      { deviceId: event.sourceDeviceId },
      events.filter(candidate => candidate.sourceDeviceId === event.sourceDeviceId),
      config
    );
    const reasons = [...new Set(signals
      .filter(signal => signal.timestamp === event.ts)
      .map(signal => signal.description))];
    const suspicious = reasons.length > 0;
    const status = suspicious
      ? (risk.score >= config.thresholds.high ? 'HIGH' : 'SUSPICIOUS')
      : 'NORMAL';
    return { risk, reasons, status };
  }

  function eventAssessment(event) {
    if (event.riskScore != null) {
      return { risk: { score: event.riskScore, severity: event.riskSeverity }, reasons: event.detectionReasons || [], status: event.status };
    }
    return assessEvent(event);
  }

  function eventDetails(event) {
    const result = eventAssessment(event);
    return `<h3>${esc(event.id)} · SIMULATED</h3><dl>
      <dt>Source device</dt><dd>${esc(event.sourceDeviceId)} · ${esc(device(event.sourceDeviceId).user)} (${esc(device(event.sourceDeviceId).role)})</dd>
      <dt>Destination device</dt><dd>${esc(event.destinationDeviceId)} · ${esc(device(event.destinationDeviceId).user)} (${esc(device(event.destinationDeviceId).role)})</dd>
      <dt>Direction</dt><dd>${esc(event.sourceDeviceId)} → ${esc(event.destinationDeviceId)}</dd>
      <dt>Timestamp</dt><dd>${esc(event.timestamp)}</dd>
      <dt>Protocol</dt><dd>${esc(event.protocol)}</dd>
      <dt>Transfer size</dt><dd>${esc(formatBytes(event.bytes))} (${event.bytes.toLocaleString()} bytes)</dd>
      <dt>Event status</dt><dd>${esc(result.status)} · SIMULATED</dd>
      <dt>Device risk</dt><dd>${esc(result.risk.severity)} (${result.risk.score}/100)</dd>
      <dt>Detection reason</dt><dd>${result.reasons.map(esc).join('<br>') || 'No anomaly detected'}</dd>
    </dl>`;
  }

  function renderGraph(windowHours = activeWindow) {
    activeWindow = windowHours;
    const scores = {};
    Simulation.DEVICE_LIST.forEach(entry => { scores[entry.id] = deviceRisk(entry.id); });
    const visibleEvents = events.filter(event => Date.now() - event.ts <= windowHours * 3600000).slice(-16);
    const paths = visibleEvents.map((event, index) => {
      const from = DEVICE_POSITIONS[event.sourceDeviceId];
      const to = DEVICE_POSITIONS[event.destinationDeviceId];
      const result = eventAssessment(event);
      const className = result.status === 'HIGH' ? 'sim-edge sim-high' : result.status === 'SUSPICIOUS' ? 'sim-edge sim-suspicious' : 'sim-edge';
      const offset = (index % 5 - 2) * 9;
      const midX = (from.x + to.x) / 2 + offset;
      const midY = (from.y + to.y) / 2 - offset;
      return `<path id="edge-${esc(event.id)}" class="${className}${event.id === selectedEventId ? ' sim-selected' : ''}" d="M ${from.x} ${from.y} Q ${midX} ${midY} ${to.x} ${to.y}" marker-end="url(#sim-arrow)"/>`;
    }).join('');
    const animated = visibleEvents.map(event =>
      `<circle class="sim-packet" r="4"><animateMotion dur="1.4s" repeatCount="indefinite"><mpath href="#edge-${esc(event.id)}"/></animateMotion></circle>`
    ).join('');
    const nodes = Simulation.DEVICE_LIST.map(entry => {
      const position = DEVICE_POSITIONS[entry.id];
      const risk = scores[entry.id];
      const riskClass = risk.severity === 'High' || risk.severity === 'Critical' ? 'sim-risk-high' : risk.severity === 'Medium' ? 'sim-risk-medium' : '';
      return `<g class="node sim-device" data-device="${esc(entry.id)}">
        <circle cx="${position.x}" cy="${position.y}" r="28" class="${riskClass}"/>
        <text x="${position.x}" y="${position.y + 4}">${esc(entry.id)}</text>
        <text class="sim-user" x="${position.x}" y="${position.y + 45}">${esc(entry.user)} · ${esc(entry.role)}</text>
        <text class="sim-score" x="${position.x}" y="${position.y + 61}">RISK ${risk.score}</text>
      </g>`;
    }).join('');

    svg.innerHTML = `<defs><marker id="sim-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="context-stroke"/></marker></defs>${paths}${animated}${nodes}`;
    svg.querySelectorAll('.sim-device').forEach(node => {
      node.addEventListener('click', () => {
        const id = node.dataset.device;
        const identity = device(id);
        const risk = scores[id];
        details.innerHTML = `<h3>${esc(id)}</h3><dl><dt>Identity</dt><dd>${esc(identity.user)} (${esc(identity.role)})</dd><dt>Risk score</dt><dd>${esc(risk.severity)} (${risk.score}/100)</dd><dt>Risk evidence</dt><dd>${esc(risk.explanation)}</dd></dl>`;
      });
    });
    renderFeed();
    const selected = events.find(event => event.id === selectedEventId);
    if (selected) details.innerHTML = eventDetails(selected);
  }

  function renderFeed() {
    if (!feed) return;
    feed.innerHTML = events.slice().reverse().slice(0, 30).map(event => {
      const result = eventAssessment(event);
      const source = device(event.sourceDeviceId);
      const destination = device(event.destinationDeviceId);
      const rowClass = result.status === 'HIGH' ? 'high' : result.status === 'SUSPICIOUS' ? 'suspicious' : '';
      return `<button type="button" class="sim-event ${rowClass}${event.id === selectedEventId ? ' sim-event-selected' : ''}" data-transfer="${esc(event.id)}">
        <span><b>${esc(event.sourceDeviceId)} → ${esc(event.destinationDeviceId)}</b><small>${esc(source.user)} → ${esc(destination.user)} · ${esc(event.timestamp)}</small></span>
        <span>${esc(formatBytes(event.bytes))}<small>${esc(event.protocol)}</small></span>
        <span>Risk ${result.risk.score}<small>${esc(result.status)} · SIMULATED</small></span>
        <span class="sim-reason">${esc(result.reasons[0] || 'Normal background activity')}</span>
      </button>`;
    }).join('') || '<p class="sim-empty">No simulated transfers yet. Start the simulation to generate isolated sample events.</p>';
  }

  function updateControls() {
    const running = Simulation.isRunning();
    controls.querySelector('[data-sim-start]').textContent = running ? 'Simulation Running' : (events.length && !running ? 'Resume Simulation' : 'Start Simulation');
    controls.querySelector('[data-sim-start]').disabled = running;
    controls.querySelector('[data-sim-pause]').disabled = !running;
  }

  function receiveTransfer(event) {
    if (event.provenance !== 'SIMULATED') throw new Error('Rejected transfer without SIMULATED provenance.');
    RiskUI.ingestSimulationTransfer(event);
    events.push(event);
    const result = assessEvent(event);
    event.riskScore = result.risk.score;
    event.riskSeverity = result.risk.severity;
    event.status = result.status;
    event.detectionReasons = result.reasons;
    saveEvents();
    if (result.status === 'HIGH') {
      const toast = document.querySelector('#toast');
      toast.textContent = `SIMULATED HIGH-SEVERITY ALERT · ${event.sourceDeviceId} → ${event.destinationDeviceId} · Risk ${result.risk.score}`;
      toast.classList.add('on');
      clearTimeout(receiveTransfer.toastTimer);
      receiveTransfer.toastTimer = setTimeout(() => toast.classList.remove('on'), 4500);
    }
    renderGraph(activeWindow);
  }

  Simulation.on('transfer', receiveTransfer);
  Simulation.on('reset', () => {
    events.length = 0;
    selectedEventId = null;
    RiskUI.resetSimulationEvents();
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch (error) {
      console.error('Could not clear simulated transfer history:', error);
    }
    details.innerHTML = '<h3>Details</h3><p style="color:var(--mu);margin:0">Select a node to investigate.</p>';
    renderGraph();
  });

  if (RiskUI) RiskUI.seedSampleDataIfNeeded(false);
  events.push(...readStoredEvents());
  events.sort((a, b) => a.ts - b.ts);

  controls.addEventListener('click', event => {
    const target = event.target.closest('button');
    if (!target) return;
    if (target.hasAttribute('data-sim-start')) Simulation.start();
    else if (target.hasAttribute('data-sim-pause')) Simulation.pause();
    else if (target.hasAttribute('data-sim-reset')) Simulation.reset();
    updateControls();
  });
  feed.addEventListener('click', event => {
    const target = event.target.closest('[data-transfer]');
    if (!target) return;
    selectedEventId = target.dataset.transfer;
    renderGraph();
  });

  root.lldrRenderTransferGraph = renderGraph;
  updateControls();
  renderGraph();
}(typeof window !== 'undefined' ? window : this));
