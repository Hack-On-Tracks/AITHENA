// AITHENA Live Telemetry Tests (plain Node, no framework, 0 dependencies)
// Run:  node tests/live-telemetry.test.js
//
// Covers acceptance criteria for the centralized live-monitoring layer:
//   A. Enrollment issues a unique device ID + secret; secret stored hashed.
//   B. Agent authentication: valid secret accepted, wrong/revoked rejected.
//   C. Input validation rejects malformed telemetry; bytes "null" stays unknown.
//   D. Per-device isolation: flows never mix across devices.
//   E. Destination novelty computed per device from its own history.
//   F. Bounded retention caps stored flows per device.
//   G. Honest status derivation: LIVE / STALE / OFFLINE from last-seen.
//   H. Independent per-device risk scoring via the existing engine.
//   I. Revoke stops further authentication.
//   J. End-to-end over real HTTP: enroll + ingest + registry + SSE push.

const assert = require('assert');
const http = require('http');

const auth = require('../server/lib/auth');
const validate = require('../server/lib/validate');
const { Store } = require('../server/lib/store');
const riskAdapter = require('../server/lib/risk-adapter');

let passed = 0;
function ok(name) { console.log('  ✓ ' + name); passed++; }

// ---------------- A. Enrollment & secret hashing ----------------
function testEnroll() {
  console.log('A. Enrollment & secret hashing');
  const store = new Store({ persistPath: null });
  const a = store.enroll({ label: 'Laptop-A', assignedUser: 'Alice', department: 'Friends', trustedNetworks: ['home'] });
  const b = store.enroll({ label: 'Laptop-B', assignedUser: 'Bob', department: 'Friends', trustedNetworks: ['home'] });
  assert(a.deviceId !== b.deviceId, 'device IDs must be unique');
  assert(/^DEV-\d{3}$/.test(a.deviceId), 'device ID format');
  assert(a.secret && a.secret.startsWith('agt_'), 'agent secret issued');
  const rec = store.getDevice(a.deviceId);
  assert(rec.secretHash && rec.secretHash.indexOf(a.secret) === -1, 'secret is not stored in plaintext');
  assert(auth.verifySecret(a.secret, rec.secretHash), 'hashed secret verifies');
  ok('unique IDs, secret issued once, stored hashed');
  return { store, a, b };
}

// ---------------- B. Agent authentication ----------------
function testAuth(ctx) {
  console.log('B. Agent authentication');
  const { store, a } = ctx;
  assert(store.authAgent(a.deviceId, a.secret) === true, 'valid secret accepted');
  assert(store.authAgent(a.deviceId, 'agt_wrong') === false, 'wrong secret rejected');
  assert(store.authAgent('DEV-999', a.secret) === false, 'unknown device rejected');
  assert(auth.safeEqual('abc', 'abc') === true && auth.safeEqual('abc', 'abd') === false, 'constant-time compare works');
  ok('valid accepted; wrong / unknown rejected');
}

// ---------------- C. Input validation ----------------
function testValidation() {
  console.log('C. Input validation');
  const good = validate.validateBatch({ flows: [{ dest: '93.184.216.34', destPort: 443, protocol: 'HTTPS/TLS', connectionCount: 2, durationSec: 10, bytesOut: 1000 }] });
  assert(good.ok && good.flows.length === 1, 'valid batch accepted');
  assert(good.flows[0].bytesIn === null, 'absent bytes stay null (honest unknown)');

  const badPort = validate.validateFlow({ dest: 'x', destPort: 99999 });
  assert(!badPort.ok, 'out-of-range port rejected');
  const badDest = validate.validateFlow({ dest: 'has space', destPort: 80 });
  assert(!badDest.ok, 'malformed dest rejected');
  const noDest = validate.validateFlow({ destPort: 80 });
  assert(!noDest.ok, 'missing dest rejected');

  const tooMany = validate.validateBatch({ flows: new Array(validate.MAX_FLOWS_PER_BATCH + 1).fill({ dest: '1.1.1.1', destPort: 53 }) });
  assert(!tooMany.ok, 'oversized batch rejected');

  const mixed = validate.validateBatch({ flows: [{ dest: '1.1.1.1', destPort: 53 }, { dest: 'bad dest', destPort: 1 }] });
  assert(mixed.ok && mixed.flows.length === 1 && mixed.rejected.length === 1, 'bad records dropped, good kept, rejects reported');
  ok('malformed telemetry rejected; null bytes preserved');
}

// ---------------- D & E. Isolation + per-device novelty ----------------
function testIsolationAndNovelty(ctx) {
  console.log('D/E. Per-device isolation & novelty');
  const { store, a, b } = ctx;
  store.ingest(a.deviceId, validate.validateBatch({ flows: [{ dest: '10.0.0.5', destPort: 443 }] }).flows, { reportedIp: '192.168.1.10' });
  store.ingest(b.deviceId, validate.validateBatch({ flows: [{ dest: '203.0.113.9', destPort: 443 }] }).flows, { reportedIp: '192.168.1.11' });

  const fa = store.getFlows(a.deviceId), fb = store.getFlows(b.deviceId);
  assert(fa.length === 1 && fb.length === 1, 'each device has its own flows');
  assert(fa[0].dest === '10.0.0.5' && fb[0].dest === '203.0.113.9', 'flows not mixed across devices');
  assert(fa.every(f => f.deviceId === a.deviceId), 'every flow tagged with owning device');
  assert(fa[0].destNovelty === 'new', 'first sighting is novel');

  // second sighting of same dest on A is known; same dest first-seen on B is novel for B
  store.ingest(a.deviceId, validate.validateBatch({ flows: [{ dest: '10.0.0.5', destPort: 443 }] }).flows, {});
  store.ingest(b.deviceId, validate.validateBatch({ flows: [{ dest: '10.0.0.5', destPort: 443 }] }).flows, {});
  const fa2 = store.getFlows(a.deviceId), fb2 = store.getFlows(b.deviceId);
  assert(fa2[fa2.length - 1].destNovelty === 'known', 'repeat dest on A is known');
  assert(fb2[fb2.length - 1].destNovelty === 'new', 'same dest first-seen on B is novel for B (per-device baseline)');
  ok('isolation holds; novelty is per device');
}

// ---------------- F. Bounded retention ----------------
function testRetention() {
  console.log('F. Bounded retention');
  const store = new Store({ persistPath: null, maxFlowsPerDevice: 50 });
  const d = store.enroll({ label: 'Cap', assignedUser: 'C', department: 'x', trustedNetworks: ['home'] });
  for (let i = 0; i < 200; i++) {
    store.ingest(d.deviceId, validate.validateBatch({ flows: [{ dest: '1.2.3.' + (i % 250), destPort: 443 }] }).flows, {});
  }
  assert(store.getFlows(d.deviceId).length <= 50, 'flow count capped at maxFlowsPerDevice');
  ok('retention bound enforced (<= 50)');
}

// ---------------- G. Status derivation ----------------
function testStatus() {
  console.log('G. Honest status derivation');
  const store = new Store({ persistPath: null, liveMs: 1000, staleMs: 3000 });
  const d = store.enroll({ label: 'S', assignedUser: 'S', department: 'x', trustedNetworks: ['home'] });
  const rec = store.getDevice(d.deviceId);
  assert(store.connStatus(rec) === 'OFFLINE', 'never-seen device is OFFLINE (not assumed safe/online)');
  rec.lastSeen = Date.now();
  assert(store.connStatus(rec) === 'LIVE', 'recent = LIVE');
  rec.lastSeen = Date.now() - 2000;
  assert(store.connStatus(rec) === 'STALE', 'older = STALE');
  rec.lastSeen = Date.now() - 10000;
  assert(store.connStatus(rec) === 'OFFLINE', 'stale beyond window = OFFLINE');
  ok('LIVE / STALE / OFFLINE derived from last-seen');
}

// ---------------- H. Independent scoring ----------------
function testScoring() {
  console.log('H. Independent per-device scoring');
  const store = new Store({ persistPath: null });
  const d = store.enroll({ label: 'R', assignedUser: 'R', department: 'x', trustedNetworks: ['home'] });
  store.ingest(d.deviceId, validate.validateBatch({ flows: [
    { dest: 'files.example-sync.net', destPort: 443, bytesOut: 2 * 1024 * 1024 * 1024, durationSec: 400, connectionCount: 3 }
  ] }).flows, { telemetryHealth: { bytes: 'ok' } });
  const pub = store.registry().find(x => x.deviceId === d.deviceId);
  const risk = riskAdapter.scoreFromFlows(pub, store.getFlows(d.deviceId));
  assert(typeof risk.score === 'number' && risk.score >= 0 && risk.score <= 100, 'score bounded 0..100');
  assert(['Low', 'Medium', 'High', 'Critical'].includes(risk.severity), 'severity label valid');
  assert(risk.flowsConsidered === 1, 'scored only this device\'s flows');
  // a large, novel, high-volume flow should lift above Low
  assert(risk.score > 0, 'anomalous flow produced a non-zero score');
  ok('score bounded, per-device, driven by that device\'s flows only');
}

// ---------------- I. Revoke ----------------
function testRevoke() {
  console.log('I. Revoke');
  const store = new Store({ persistPath: null });
  const d = store.enroll({ label: 'Z', assignedUser: 'Z', department: 'x', trustedNetworks: ['home'] });
  assert(store.authAgent(d.deviceId, d.secret) === true, 'auth works before revoke');
  store.revoke(d.deviceId);
  assert(store.authAgent(d.deviceId, d.secret) === false, 'auth fails after revoke');
  const ing = store.ingest(d.deviceId, [], {});
  assert(ing.ok === false, 'ingest refused for revoked device');
  ok('revoked device can no longer authenticate or ingest');
}

// ---------------- J. End-to-end over HTTP + SSE ----------------
function testEndToEnd() {
  return new Promise((resolve, reject) => {
    console.log('J. End-to-end over HTTP (enroll + ingest + registry + SSE)');
    process.env.AITHENA_ADMIN_TOKEN = 'test-token-e2e';
    process.env.PORT = '0'; // ephemeral
    process.env.AITHENA_REGISTRY = ''; // no persistence
    delete require.cache[require.resolve('../server/aithena-server.js')];
    const srv = require('../server/aithena-server.js');
    const server = http.createServer(srv.handler).listen(0, '127.0.0.1', async () => {
      const port = server.address().port;
      const base = 'http://127.0.0.1:' + port;
      const admin = { 'Authorization': 'Bearer test-token-e2e', 'Content-Type': 'application/json' };

      function req(method, path, headers, body) {
        return new Promise((res, rej) => {
          const data = body ? Buffer.from(JSON.stringify(body)) : null;
          const r = http.request(base + path, { method, headers: Object.assign({}, headers, data ? { 'Content-Length': data.length } : {}) }, resp => {
            let b = ''; resp.on('data', c => b += c); resp.on('end', () => res({ code: resp.statusCode, json: b ? JSON.parse(b) : null }));
          });
          r.on('error', rej); if (data) r.write(data); r.end();
        });
      }

      try {
        // SSE subscriber
        let sseGotTelemetry = false;
        const sse = http.get(base + '/api/v1/stream?token=test-token-e2e', resp => {
          resp.on('data', chunk => { if (chunk.toString().indexOf('event: telemetry') >= 0) sseGotTelemetry = true; });
        });
        await new Promise(r => setTimeout(r, 150));

        // enroll without admin token -> 401
        const unauth = await req('POST', '/api/v1/enroll', { 'Content-Type': 'application/json' }, { label: 'X' });
        assert(unauth.code === 401, 'enroll without admin token -> 401');

        // enroll device
        const en = await req('POST', '/api/v1/enroll', admin, { label: 'E2E-Laptop', assignedUser: 'Tester' });
        assert(en.code === 201 && en.json.deviceId && en.json.agentSecret, 'enroll -> 201 with id+secret');
        const dev = en.json.deviceId, secret = en.json.agentSecret;

        // telemetry with bad secret -> 403
        const bad = await req('POST', '/api/v1/telemetry?device=' + dev, { 'Authorization': 'Bearer nope', 'Content-Type': 'application/json' }, { flows: [] });
        assert(bad.code === 403, 'telemetry with bad secret -> 403');

        // real telemetry
        const tel = await req('POST', '/api/v1/telemetry?device=' + dev,
          { 'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json' },
          { hostname: 'tester-pc', reportedIp: '192.0.2.50', flows: [{ dest: '198.51.100.7', destPort: 443, protocol: 'HTTPS/TLS', connectionCount: 1, durationSec: 5 }] });
        assert(tel.code === 200 && tel.json.accepted === 1, 'telemetry accepted');
        assert(tel.json.device.connStatus === 'LIVE', 'device reports LIVE after telemetry');
        assert(tel.json.risk && typeof tel.json.risk.score === 'number', 'risk computed on ingest');

        // registry reflects the device
        const reg = await req('GET', '/api/v1/devices', admin);
        assert(reg.code === 200 && reg.json.devices.length === 1, 'registry lists the device');
        assert(reg.json.devices[0].lastIp === '192.0.2.50' && reg.json.devices[0].hostname === 'tester-pc', 'registry shows reported host/ip');

        // isolation: flows endpoint returns only this device
        const fl = await req('GET', '/api/v1/devices/' + dev + '/flows', admin);
        assert(fl.json.flows.length === 1 && fl.json.flows[0].dest === '198.51.100.7', 'per-device flows endpoint isolated');

        await new Promise(r => setTimeout(r, 100));
        assert(sseGotTelemetry === true, 'SSE pushed a telemetry event to the admin stream');

        // revoke over HTTP
        const rev = await req('POST', '/api/v1/devices/' + dev + '/revoke', admin);
        assert(rev.code === 200, 'revoke -> 200');
        const after = await req('POST', '/api/v1/telemetry?device=' + dev,
          { 'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json' }, { flows: [] });
        assert(after.code === 403, 'revoked secret rejected afterwards');

        sse.destroy();
        server.close(() => { ok('HTTP enroll/auth/ingest/registry/isolation/SSE/revoke all pass'); resolve(); });
      } catch (e) { server.close(); reject(e); }
    });
  });
}

async function main() {
  console.log('Running AITHENA Live Telemetry tests\n');
  const ctx = testEnroll();
  testAuth(ctx);
  testValidation();
  testIsolationAndNovelty(ctx);
  testRetention();
  testStatus();
  testScoring();
  testRevoke();
  await testEndToEnd();
  console.log('\nAll ' + passed + ' live-telemetry test groups passed ✔');
  process.exit(0);
}

main().catch(e => { console.error('\nTEST FAILED:', e.message); process.exit(1); });
