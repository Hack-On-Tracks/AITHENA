// Device Response Layer (adapters, safeguards, audit log)
// Exported as UMD for browser and Node.

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.lldrDeviceResponse = factory();
  }
}(this, function () {
  // ---------- Role & permission model ----------
  const ROLES = ['viewer', 'analyst', 'responder', 'admin'];
  let currentRole = 'viewer'; // default; UI can change via developer console.

  function setRole(role) {
    if (ROLES.includes(role)) currentRole = role;
  }

  function canExecute(action) {
    // action: 'contain', 'stepup', 'notify'
    if (action === 'contain') return ['responder', 'admin'].includes(currentRole);
    return ['analyst', 'responder', 'admin'].includes(currentRole);
  }

  // ---------- Cooldown & protection ----------
  const cooldownMs = 5 * 60 * 1000; // 5 minutes per device per action
  const lastAction = {}; // {deviceId: {action: timestamp}}
  const protectedDevices = new Set(['SRV-PROD-01', 'SRV-DC-01', 'DEV-CORE-INFRA']); // infrastructure servers protected from isolation

  function isCooldownOk(deviceId, action) {
    const now = Date.now();
    if (!lastAction[deviceId]) return true;
    const entry = lastAction[deviceId][action];
    return !entry || now - entry > cooldownMs;
  }

  function recordAction(deviceId, action) {
    if (!lastAction[deviceId]) lastAction[deviceId] = {};
    lastAction[deviceId][action] = Date.now();
  }

  // ---------- Audit log ----------
  const AUDIT_KEY = 'lldr_audit';
  function loadAudit() {
    try { const txt = sessionStorage.getItem(AUDIT_KEY); return txt ? JSON.parse(txt) : []; } catch (e) { return []; }
  }
  function saveAudit(log) { try { sessionStorage.setItem(AUDIT_KEY, JSON.stringify(log)); } catch (e) {} }
  function addAudit(entry) {
    const log = loadAudit();
    log.push(entry);
    saveAudit(log);
  }

  // ---------- Adapter interface ----------
  class Adapter {
    constructor(name, capabilities) {
      this.name = name;
      this.capabilities = capabilities; // array of strings
    }
    isConfigured() { return false; }
    async execute(action, device, context) {
      return { confirmed: false, statusLabel: 'REQUESTED, awaiting confirmation from ' + this.name, externalRef: null, message: `${this.name} not configured` };
    }
  }

  // ---------- Simulated Adapter (demo mode) ----------
  class SimulatedAdapter extends Adapter {
    constructor() { super('SimulatedAdapter', ['contain', 'stepup', 'notify']); }
    isConfigured() { return true; }
    async execute(action, device, context) {
      await new Promise(r => setTimeout(r, 100));
      const actionDesc = action === 'contain' ? 'isolation' : (action === 'stepup' ? 'step-up auth' : 'analyst notification');
      const msg = `Simulated: ${actionDesc} would be requested for ${device.deviceId}`;
      const entry = { when: Date.now(), who: context.user || currentRole, what: action, device: device.deviceId, result: 'SIMULATED', message: msg };
      addAudit(entry);
      return { confirmed: true, statusLabel: 'SIMULATED', externalRef: 'SIM-' + Date.now().toString(36), message: msg };
    }
  }

  // ---------- Example stubs (not configured) ----------
  class ExampleIdentityAdapter extends Adapter {
    constructor() { super('ExampleIdentityAdapter', ['stepup']); }
    // isConfigured stays false -> not usable.
  }

  class ExampleEndpointAdapter extends Adapter {
    constructor() { super('ExampleEndpointAdapter', ['contain']); }
  }

  // ---------- Public API ----------
  const adapters = [new SimulatedAdapter(), new ExampleIdentityAdapter(), new ExampleEndpointAdapter()];

  async function performAction(action, device, context = {}) {
    if (!canExecute(action)) throw new Error('Insufficient role');
    if (protectedDevices.has(device.deviceId) && action === 'contain') throw new Error('Device protected from isolation');
    if (!isCooldownOk(device.deviceId, action)) throw new Error('Action cooldown active');
    const adapter = adapters.find(a => a.isConfigured() && a.capabilities.includes(action));
    if (!adapter) throw new Error('No configured adapter for action');
    const result = await adapter.execute(action, device, context);
    if (result.confirmed) recordAction(device.deviceId, action);
    return result;
  }

  return {
    ROLES,
    setRole,
    getCurrentRole: () => currentRole,
    canExecute,
    adapters,
    performAction,
    loadAudit,
    addAudit
  };
}));
