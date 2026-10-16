// Device Risk Data Generator (synthetic)
// This module provides synthetic device inventory and telemetry events.
// It mirrors the existing event generation style (mk()) but focuses on devices.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.lldrDeviceData = factory();
  }
}(this, function () {
  // Simple PRNG (same as in app.js) for reproducibility
  let seed = 11;
  const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
  const pick = (a) => a[Math.floor(rnd() * a.length)];

  // Synthetic device inventory
  const DEVICES = [
    { deviceId: 'DEV-001', assignedUser: 'Emil', department: 'Admin', status: 'active', trustedNetworks: ['corp_wifi', 'vpn'] },
    { deviceId: 'DEV-002', assignedUser: 'Manasvi', department: 'Employer', status: 'active', trustedNetworks: ['corp_wifi'] },
    { deviceId: 'DEV-003', assignedUser: 'Sameera', department: 'Insider', status: 'active', trustedNetworks: ['home'] },
    { deviceId: 'DEV-004', assignedUser: 'Keona', department: 'Outsider', status: 'active', trustedNetworks: ['corp_wifi', 'vpn'] }
  ];

  // Helper to generate a timestamp (ms)
  const now = () => Date.now();

  // Generate a network_change event for a device
  function genNetworkChange(device) {
    const fromType = pick(device.trustedNetworks);
    const toType = pick(['corp_wifi', 'vpn', 'home', 'unknown']);
    const trusted = device.trustedNetworks.includes(toType);
    return {
      type: 'network_change',
      deviceId: device.deviceId,
      ts: now(),
      from: { type: fromType },
      to: { type: toType },
      trusted,
      provenance: 'observed'
    };
  }

  // Generate a flow event
  function genFlow(device) {
    const dest = pick(['10.0.1.5', 'files.mega.nz', '45.77.12.9', 'github.com']);
    const destNovelty = Math.random() < 0.2 ? 'new' : 'known';
    const bytesOut = Math.round(50 + rnd() * 1500);
    const durationSec = Math.round(5 + rnd() * 300);
    return {
      type: 'flow',
      deviceId: device.deviceId,
      ts: now(),
      srcDevice: device.deviceId,
      dest,
      destNovelty,
      protocol: pick(['HTTPS', 'SMB', 'RDP']),
      durationSec,
      bytesOut,
      bytesIn: Math.round(rnd() * bytesOut),
      connectionCount: Math.ceil(rnd() * 5),
      provenance: 'observed'
    };
  }

  // Generate an auth event
  function genAuth(device) {
    const source = pick(['idp', 'vpn', 'mdm']);
    const result = Math.random() < 0.9 ? 'success' : 'failure';
    const newLocationOrClient = Math.random() < 0.1;
    const resourceAccessed = pick(['internal_app', 'cloud_storage', 'admin_portal']);
    return {
      type: 'auth',
      deviceId: device.deviceId,
      ts: now(),
      source,
      result,
      newLocationOrClient,
      resourceAccessed,
      anomalyFlags: [],
      provenance: 'observed'
    };
  }

  // Generate a device_status event
  function genDeviceStatus(device, status) {
    return {
      type: 'device_status',
      deviceId: device.deviceId,
      ts: now(),
      status,
      provenance: 'observed'
    };
  }

  // Telemetry health tracking
  let telemetryHealth = {
    endpoint: 'ok',
    flow: 'ok',
    idp: 'ok',
    vpn: 'ok',
    mdm: 'ok'
  };

  // Scenario generators for live reviewer demonstration
  function getStolenLaptopScenario(targetDevId = 'DEV-001') {
    const dev = DEVICES.find(d => d.deviceId === targetDevId) || DEVICES[0];
    const t0 = Date.now() - 3600000;
    return [
      {
        type: 'device_status',
        deviceId: dev.deviceId,
        ts: t0,
        status: 'reported_stolen',
        provenance: 'observed'
      },
      {
        type: 'network_change',
        deviceId: dev.deviceId,
        ts: t0 + 1200000,
        from: { type: 'corp_wifi' },
        to: { type: 'unknown_public_hotspot' },
        trusted: false,
        provenance: 'observed'
      },
      {
        type: 'flow',
        deviceId: dev.deviceId,
        ts: t0 + 1800000,
        srcDevice: dev.deviceId,
        dest: 'mega-cloud-sync.ch',
        destNovelty: 'new',
        protocol: 'HTTPS',
        durationSec: 420,
        bytesOut: 2450,
        bytesIn: 12,
        connectionCount: 4,
        provenance: 'observed'
      },
      {
        type: 'auth',
        deviceId: dev.deviceId,
        ts: t0 + 2400000,
        source: 'idp',
        result: 'success',
        newLocationOrClient: true,
        resourceAccessed: 'admin_portal',
        anomalyFlags: ['impossible_travel'],
        provenance: 'observed'
      }
    ];
  }

  function getNetworkChangeOnlyScenario(targetDevId = 'DEV-001') {
    const dev = DEVICES.find(d => d.deviceId === targetDevId) || DEVICES[0];
    return [
      {
        type: 'network_change',
        deviceId: dev.deviceId,
        ts: Date.now() - 600000,
        from: { type: 'corp_wifi' },
        to: { type: 'hotel_guest_wifi' },
        trusted: false,
        provenance: 'observed'
      }
    ];
  }

  function getTelemetryGapScenario(targetDevId = 'DEV-001') {
    const dev = DEVICES.find(d => d.deviceId === targetDevId) || DEVICES[0];
    telemetryHealth.vpn = 'missing';
    return [
      {
        type: 'flow',
        deviceId: dev.deviceId,
        ts: Date.now() - 300000,
        srcDevice: dev.deviceId,
        dest: 'app.slack.com',
        destNovelty: 'known',
        protocol: 'HTTPS',
        durationSec: 120,
        bytesOut: 45,
        bytesIn: 120,
        connectionCount: 1,
        provenance: 'observed'
      }
    ];
  }

  // Public API
  return {
    getDevices: () => {
      try {
        if (typeof sessionStorage !== 'undefined') {
          const stored = sessionStorage.getItem('lldr_devices');
          if (stored) return JSON.parse(stored);
        }
      } catch (e) {}
      if (typeof LL_SAMPLE_DEVICE_DATA !== 'undefined' && LL_SAMPLE_DEVICE_DATA && LL_SAMPLE_DEVICE_DATA.devices) {
        return LL_SAMPLE_DEVICE_DATA.devices.map(d => Object.assign({}, d));
      }
      return DEVICES.map(d => Object.assign({}, d));
    },
    getTelemetryHealth: (deviceId) => {
      try {
        if (typeof sessionStorage !== 'undefined') {
          const stored = sessionStorage.getItem('lldr_telemetry_health');
          if (stored) {
            const parsed = JSON.parse(stored);
            if (deviceId && parsed[deviceId]) return Object.assign({}, parsed[deviceId]);
            if (deviceId && parsed.vpn) return Object.assign({}, parsed);
            return Object.assign({}, parsed);
          }
        }
      } catch (e) {}
      if (typeof LL_SAMPLE_DEVICE_DATA !== 'undefined' && LL_SAMPLE_DEVICE_DATA && LL_SAMPLE_DEVICE_DATA.telemetryHealth) {
        if (deviceId && LL_SAMPLE_DEVICE_DATA.telemetryHealth[deviceId]) {
          return Object.assign({}, LL_SAMPLE_DEVICE_DATA.telemetryHealth[deviceId]);
        }
      }
      return Object.assign({}, telemetryHealth);
    },
    setTelemetryHealth: (src, state) => { if (telemetryHealth[src] !== undefined) telemetryHealth[src] = state; },
    resetTelemetryHealth: () => { telemetryHealth = { endpoint: 'ok', flow: 'ok', idp: 'ok', vpn: 'ok', mdm: 'ok' }; },
    getStolenLaptopScenario,
    getNetworkChangeOnlyScenario,
    getTelemetryGapScenario,
    generateEvents: (deviceId) => {
      const device = DEVICES.find(d => d.deviceId === deviceId) || DEVICES[0];
      return {
        network_change: genNetworkChange(device),
        flow: genFlow(device),
        auth: genAuth(device),
        device_status: genDeviceStatus(device, device.status)
      };
    }
  };
}));
