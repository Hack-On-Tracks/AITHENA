// Device Risk Detection Engine (pure, testable)
// Exported as UMD for browser and Node usage.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.lldrDeviceEngine = factory();
  }
}(this, function () {
  // ---------- Default configuration ----------
  const DEFAULT_CONFIG = {
    // weight per signal group (0-1)
    weights: {
      network: 0.3,
      traffic: 0.35,
      identity: 0.25,
      status: 0.2
    },
    // thresholds for severity (score 0-100)
    thresholds: {
      low: 0,
      medium: 5,
      high: 15,
      critical: 30
    },
    transferDetection: {
      unusualOutboundBytes: 1048576,
      repeatedTransferCount: 3,
      burstTransferCount: 4,
      windowMs: 60000,
      outsiderDeviceId: 'DEV-004'
    },
    // correlation damping factor for additional signals in same group
    damping: 0.3,
    // bonus for corroborating groups (0-1)
    corroborationBonus: 0.1
  };

  // ---------- Helper utilities ----------
  const severityFromScore = (score, cfg) => {
    if (score >= cfg.thresholds.critical) return 'Critical';
    if (score >= cfg.thresholds.high) return 'High';
    if (score >= cfg.thresholds.medium) return 'Medium';
    if (score >= cfg.thresholds.low) return 'Low';
    return 'Low';
  };

  const confidenceFromUnknowns = (unknownsCount, totalGroups) => {
    // Simple heuristic: more unknown groups => lower confidence
    const ratio = unknownsCount / totalGroups;
    if (ratio === 0) return 'High';
    if (ratio <= 0.25) return 'Medium';
    return 'Low';
  };

  // ---------- Detection functions ----------
  // 1. Network changes detection
  function detectNetworkChanges(device, events) {
    const signals = [];
    events.filter(e => e.type === 'network_change' && e.deviceId === device.deviceId)
      .forEach(e => {
        const trustedFrom = device.trustedNetworks.includes(e.from.type);
        const trustedTo = device.trustedNetworks.includes(e.to.type);
        const transition = trustedFrom !== trustedTo;
        if (transition) {
          signals.push({
            signal: 'network_change',
            group: 'network',
            confidence: 'Low', // per spec
            description: `Device moved from ${e.from.type} (${trustedFrom ? 'trusted' : 'untrusted'}) to ${e.to.type} (${trustedTo ? 'trusted' : 'untrusted'})`,
            timestamp: e.ts,
            provenance: e.provenance
          });
        }
      });
    return signals;
  }

  // 2. Flow analysis
  function analyseFlows(device, flows, baseline) {
    const signals = [];
    // baseline: { avgBytesOut, avgDuration, avgConnCount }
    const outlier = flow => flow.bytesOut > (baseline.avgBytesOut * 3);
    const frequent = flow => flow.connectionCount > (baseline.avgConnCount * 2);
    const novelty = flow => flow.destNovelty === 'new';
    flows.filter(f => f.deviceId === device.deviceId).forEach(f => {
      if (outlier(f)) {
        signals.push({
          signal: 'large_outbound',
          group: 'traffic',
          confidence: 'Medium',
          description: `Outbound ${f.bytesOut} MB exceeds typical ${baseline.avgBytesOut} MB`,
          timestamp: f.ts,
          provenance: f.provenance
        });
      }
      if (frequent(f)) {
        signals.push({
          signal: 'high_freq',
          group: 'traffic',
          confidence: 'Medium',
          description: `Connection count ${f.connectionCount} high vs baseline ${baseline.avgConnCount}`,
          timestamp: f.ts,
          provenance: f.provenance
        });
      }
      if (novelty(f)) {
        signals.push({
          signal: 'dest_novelty',
          group: 'traffic',
          confidence: 'Medium',
          description: `Destination ${f.dest} is novel for this device`,
          timestamp: f.ts,
          provenance: f.provenance
        });
      }
    });
    return signals;
  }

  function detectTransferAnomalies(device, events, config = DEFAULT_CONFIG) {
    const rules = config.transferDetection || DEFAULT_CONFIG.transferDetection;
    const transfers = events
      .filter(e => e.type === 'transfer' && e.sourceDeviceId === device.deviceId && e.provenance === 'SIMULATED')
      .sort((a, b) => a.ts - b.ts);
    const signals = [];

    transfers.forEach(event => {
      const recent = transfers.filter(candidate =>
        candidate.ts <= event.ts && event.ts - candidate.ts <= rules.windowMs
      );
      if (event.bytes >= rules.unusualOutboundBytes) {
        signals.push({
          signal: 'unusual_outbound_transfer',
          group: 'traffic',
          confidence: 'Medium',
          description: `Simulated outbound volume ${event.bytes} bytes exceeds the configured threshold`,
          timestamp: event.ts,
          provenance: 'SIMULATED'
        });
      }
      if (event.destinationDeviceId === rules.outsiderDeviceId) {
        signals.push({
          signal: 'unexpected_destination',
          group: 'network',
          confidence: 'High',
          description: `Simulated transfer to unexpected outsider device ${event.destinationDeviceId}`,
          timestamp: event.ts,
          provenance: 'SIMULATED'
        });
      }
      if (recent.filter(candidate => candidate.destinationDeviceId === event.destinationDeviceId).length >= rules.repeatedTransferCount) {
        signals.push({
          signal: 'repeated_insider_transfer',
          group: 'traffic',
          confidence: 'High',
          description: `Repeated simulated transfers to ${event.destinationDeviceId} within ${Math.round(rules.windowMs / 1000)} seconds`,
          timestamp: event.ts,
          provenance: 'SIMULATED'
        });
      }
      if (recent.length >= rules.burstTransferCount) {
        signals.push({
          signal: 'transfer_burst',
          group: 'traffic',
          confidence: 'High',
          description: `${recent.length} simulated transfers within ${Math.round(rules.windowMs / 1000)} seconds`,
          timestamp: event.ts,
          provenance: 'SIMULATED'
        });
      }
    });
    return signals;
  }

  // 3. Identity correlation
  function correlateIdentity(device, authEvents, statusEvents) {
    const signals = [];
    // Stolen status
    const stolen = statusEvents.find(s => s.deviceId === device.deviceId && s.type === 'device_status' && s.status === 'reported_stolen');
    if (stolen) {
      signals.push({
        signal: 'reported_stolen',
        group: 'status',
        confidence: 'High',
        description: `Device reported stolen at ${new Date(stolen.ts).toISOString()}`,
        timestamp: stolen.ts,
        provenance: stolen.provenance
      });
    }
    // Unusual auth events
    authEvents.filter(a => a.deviceId === device.deviceId).forEach(a => {
      if (a.result === 'failure') {
        signals.push({
          signal: 'auth_failure',
          group: 'identity',
          confidence: 'Medium',
          description: `Auth failure via ${a.source}`,
          timestamp: a.ts,
          provenance: a.provenance
        });
      }
      if (a.newLocationOrClient) {
        signals.push({
          signal: 'auth_new_location',
          group: 'identity',
          confidence: 'Medium',
          description: `Auth from new location/client`,
          timestamp: a.ts,
          provenance: a.provenance
        });
      }
    });
    return signals;
  }

  // ---------- Scoring ----------
  function scoreDevice(device, signals, config = DEFAULT_CONFIG) {
    // group signals, keep strongest per group
    const groups = {};
    const unknowns = [];
    signals.forEach(sig => {
      if (!config.weights[sig.group]) {
        unknowns.push(sig.group);
        return;
      }
      if (!groups[sig.group]) groups[sig.group] = [];
      groups[sig.group].push(sig);
    });

    // compute raw score via weighted sum of points (assign 30 points per high, 20 medium, 10 low)
    const pointMap = { High: 30, Medium: 20, Low: 10 };
    let rawScore = 0;
    const contributions = [];
    Object.entries(groups).forEach(([group, groupSignals]) => {
      const weight = config.weights[group] || 0;
      const ranked = groupSignals.slice().sort((a, b) => (pointMap[b.confidence] || 0) - (pointMap[a.confidence] || 0));
      let groupPoints = 0;
      ranked.forEach((sig, index) => {
        const points = weight * (pointMap[sig.confidence] || 0) * (index === 0 ? 1 : config.damping);
        groupPoints += points;
        contributions.push({ signal: sig.signal, group, points: Math.round(points), reason: sig.description });
      });
      rawScore += groupPoints;
    });

    // corroboration bonus: if >=2 groups present, add bonus
    if (Object.keys(groups).length >= 2) {
      rawScore += rawScore * config.corroborationBonus;
    }

    // cap score at 100
    const score = Math.min(100, Math.round(rawScore));
    let severity = severityFromScore(score, config);
    const confidence = confidenceFromUnknowns(unknowns.length, Object.keys(config.weights).length);

    // special rule for reported_stolen alone
    if (signals.some(s => s.signal === 'reported_stolen') && Object.keys(groups).length === 1) {
      // downgrade severity if only this signal
      const maxSeverity = severityFromScore(config.thresholds.high, config);
      if (severity === 'Critical') severity = 'High';
    }

    return {
      score,
      severity,
      confidence,
      contributions,
      timeline: signals.map(s => ({ signal: s.signal, ts: s.timestamp, group: s.group, confidence: s.confidence })),
      unknowns,
      explanation: `Score computed from ${Object.keys(groups).length} signal groups; ${unknowns.length} unknown groups.`,
      previousScore: device.lastScore || null,
      scoreChangeReasons: device.lastScore != null ? [`Score changed from ${device.lastScore} to ${score}`] : []
    };
  }

  // Export public API
  return {
    DEFAULT_CONFIG,
    detectNetworkChanges,
    analyseFlows,
    detectTransferAnomalies,
    correlateIdentity,
    scoreDevice
  };
}));
