// AITHENA live telemetry — bridges live flows into the existing device-risk engine.
// Scores each device INDEPENDENTLY from its own flows only. No cross-device mixing.
'use strict';

const Engine = require('../../assets/js/device-risk-engine.js');

// Map a stored live flow (bytes in raw bytes) to the engine's flow event shape,
// where bytesOut is expressed in MB (matching the engine's MB-based baseline).
function toEngineFlow(f, deviceId) {
  const bytesOutMb = (f.bytesOut != null) ? (f.bytesOut / (1024 * 1024)) : null;
  return {
    type: 'flow',
    deviceId,
    ts: f.ts,
    srcDevice: deviceId,
    dest: f.dest,
    destNovelty: f.destNovelty || 'known',
    protocol: f.protocol || 'TCP',
    durationSec: f.durationSec != null ? f.durationSec : 0,
    // When bytes are unavailable the engine's large-outbound test must not fire,
    // so we pass 0 (never fabricated) and rely on novelty/frequency signals.
    bytesOut: bytesOutMb != null ? +bytesOutMb.toFixed(3) : 0,
    bytesIn: (f.bytesIn != null) ? +(f.bytesIn / (1024 * 1024)).toFixed(3) : 0,
    connectionCount: f.connectionCount || 1,
    provenance: 'reported'
  };
}

// device: public device record from the store (needs deviceId, trustedNetworks).
// flows: that device's own stored flows.
function scoreFromFlows(device, flows, config) {
  const dev = {
    deviceId: device.deviceId,
    trustedNetworks: device.trustedNetworks || [],
    lastScore: device.risk ? device.risk.score : null
  };
  const engineFlows = flows.map(f => toEngineFlow(f, device.deviceId));

  // baseline reflects ordinary endpoint traffic; tuned for MB units like the UI.
  const baseline = { avgBytesOut: 150, avgDuration: 60, avgConnCount: 2 };

  const flowSignals = Engine.analyseFlows(dev, engineFlows, baseline);

  // Missing-telemetry signals are honest UNKNOWNs: they never deduct risk, only
  // lower confidence. Bytes unavailable on this OS => flag the gap.
  const missing = [];
  const health = device.telemetryHealth || {};
  if (health.bytes === 'unavailable' || health.bytes === 'missing') {
    missing.push({
      signal: 'missing_byte_telemetry', group: 'traffic', confidence: 'Low',
      description: 'Per-flow byte counts unavailable on this endpoint OS; volume anomalies cannot be assessed.',
      timestamp: Date.now(), provenance: 'reported'
    });
  }

  const signals = flowSignals.concat(missing);
  const result = Engine.scoreDevice(dev, signals, config || Engine.DEFAULT_CONFIG);
  result.flowsConsidered = engineFlows.length;
  result.computedAt = Date.now();
  return result;
}

module.exports = { scoreFromFlows, toEngineFlow };
