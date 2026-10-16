// Device Risk Sample Data Seed (window.LL_SAMPLE_DEVICE_DATA)
// Provides initial synthetic inventory, flows, network changes, auth events,
// status events, telemetry health, and inferred findings for LeakLens.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.LL_SAMPLE_DEVICE_DATA = factory();
  }
}(this, function () {
  const now = Date.now();

  const devices = [
    { deviceId: 'DEV-001', assignedUser: 'Emil', department: 'Admin', status: 'reported_stolen', trustedNetworks: ['corp_wifi', 'vpn'] },
    { deviceId: 'DEV-002', assignedUser: 'Manasvi', department: 'Employer', status: 'active', trustedNetworks: ['corp_wifi'] },
    { deviceId: 'DEV-003', assignedUser: 'Sameera', department: 'Insider', status: 'active', trustedNetworks: ['home'] },
    { deviceId: 'DEV-004', assignedUser: 'Keona', department: 'Outsider', status: 'active', trustedNetworks: ['corp_wifi', 'vpn'] }
  ];

  const flows = [
    {
      type: 'flow',
      deviceId: 'DEV-001',
      srcDevice: 'DEV-001',
      ts: now - 1800000,
      dest: 'mega-cloud-sync.ch',
      destNovelty: 'new',
      protocol: 'HTTPS',
      durationSec: 420,
      bytesOut: 2450,
      bytesIn: 14,
      connectionCount: 4,
      provenance: 'observed',
      inferred: {
        anomaly: 'Large Outbound Anomaly (+Deviation) & Novel Destination',
        severity: 'High',
        badgeClass: 'dr-high'
      }
    },
    {
      type: 'flow',
      deviceId: 'DEV-001',
      srcDevice: 'DEV-001',
      ts: now - 2400000,
      dest: '45.77.12.9',
      destNovelty: 'new',
      protocol: 'HTTPS',
      durationSec: 180,
      bytesOut: 850,
      bytesIn: 8,
      connectionCount: 2,
      provenance: 'observed',
      inferred: {
        anomaly: 'Unfamiliar External IP Transfer',
        severity: 'Medium',
        badgeClass: 'dr-medium'
      }
    },
    {
      type: 'flow',
      deviceId: 'DEV-001',
      srcDevice: 'DEV-001',
      ts: now - 3200000,
      dest: 'internal-portal.corp',
      destNovelty: 'known',
      protocol: 'HTTPS',
      durationSec: 60,
      bytesOut: 45,
      bytesIn: 120,
      connectionCount: 1,
      provenance: 'observed',
      inferred: {
        anomaly: 'Normal baseline flow',
        severity: 'Low',
        badgeClass: 'dr-low'
      }
    },
    {
      type: 'flow',
      deviceId: 'DEV-002',
      srcDevice: 'DEV-002',
      ts: now - 1200000,
      dest: 'github.com',
      destNovelty: 'known',
      protocol: 'HTTPS',
      durationSec: 90,
      bytesOut: 110,
      bytesIn: 220,
      connectionCount: 2,
      provenance: 'observed',
      inferred: {
        anomaly: 'Normal development traffic',
        severity: 'Low',
        badgeClass: 'dr-low'
      }
    },
    // DEV-003 has NO flow telemetry recorded (missing telemetry demonstration)
    {
      type: 'flow',
      deviceId: 'DEV-004',
      srcDevice: 'DEV-004',
      ts: now - 900000,
      dest: 'api.aws.amazon.com',
      destNovelty: 'known',
      protocol: 'HTTPS',
      durationSec: 110,
      bytesOut: 140,
      bytesIn: 380,
      connectionCount: 3,
      provenance: 'observed',
      inferred: {
        anomaly: 'Expected ops telemetry',
        severity: 'Low',
        badgeClass: 'dr-low'
      }
    }
  ];

  const networkChanges = [
    {
      type: 'network_change',
      deviceId: 'DEV-001',
      ts: now - 2800000,
      from: { type: 'corp_wifi' },
      to: { type: 'unknown_public_hotspot' },
      trusted: false,
      provenance: 'observed',
      inferred: {
        anomaly: 'Untrusted Network Transition',
        severity: 'Low',
        confidence: 'Low'
      }
    }
  ];

  const authEvents = [
    {
      type: 'auth',
      deviceId: 'DEV-001',
      ts: now - 1500000,
      source: 'idp',
      result: 'success',
      newLocationOrClient: true,
      resourceAccessed: 'admin_portal',
      anomalyFlags: ['impossible_travel'],
      provenance: 'observed',
      inferred: {
        anomaly: 'Impossible Travel & High Privilege Portal Access',
        severity: 'High'
      }
    }
  ];

  const statusEvents = [
    {
      type: 'device_status',
      deviceId: 'DEV-001',
      ts: now - 3600000,
      status: 'reported_stolen',
      provenance: 'observed',
      inferred: {
        anomaly: 'Device Stolen Status Active',
        severity: 'High'
      }
    }
  ];

  const telemetryHealth = {
    'DEV-001': { endpoint: 'ok', flow: 'ok', idp: 'ok', vpn: 'ok', mdm: 'ok' },
    'DEV-002': { endpoint: 'ok', flow: 'ok', idp: 'ok', vpn: 'ok', mdm: 'ok' },
    'DEV-003': { endpoint: 'delayed', flow: 'missing', idp: 'ok', vpn: 'missing', mdm: 'delayed' },
    'DEV-004': { endpoint: 'ok', flow: 'ok', idp: 'ok', vpn: 'ok', mdm: 'ok' }
  };

  const inferredFindings = {
    'DEV-001': [
      'Outbound flow 2450 MB exceeds typical 150 MB baseline by >16x',
      'Novel destination mega-cloud-sync.ch with HTTPS protocol',
      'Device reported stolen prior to suspicious outbound transfer',
      'Impossible travel flag on IdP admin_portal authentication'
    ],
    'DEV-003': [
      'No flow telemetry received, status unknown, not evidence of safety'
    ]
  };

  return {
    devices,
    flows,
    networkChanges,
    authEvents,
    statusEvents,
    telemetryHealth,
    inferredFindings
  };
}));
