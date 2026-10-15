#!/usr/bin/env node
// AITHENA enrollment helper (admin-side, 0 dependencies)
// Registers one device against the running AITHENA server and writes a ready-to-use
// agent-config.json. Run this on a machine that has the admin token; hand the
// generated config to the participating laptop over a secure channel.
//
// Usage:
//   AITHENA_ADMIN_TOKEN=... node enroll.js \
//      --server https://admin.example:8443 \
//      --label "Rahul-Laptop" --user "Rahul" --dept "Friends" \
//      --out ./agent-config.rahul.json
'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
function flag(name) { return process.argv.indexOf(name) >= 0; }

const server = (arg('--server', process.env.AITHENA_SERVER || 'http://localhost:8443')).replace(/\/$/, '');
const adminToken = arg('--token', process.env.AITHENA_ADMIN_TOKEN);
const label = arg('--label');
const user = arg('--user', label);
const dept = arg('--dept', 'Friends');
const trusted = (arg('--trusted', 'home,corp_wifi')).split(',').map(s => s.trim()).filter(Boolean);
const out = arg('--out', label ? `./agent-config.${label.replace(/[^\w.-]/g, '_')}.json` : './agent-config.json');
const intervalSec = parseInt(arg('--interval', '10'), 10);
const caCertPath = arg('--ca', '');
const allowSelfSigned = flag('--allow-self-signed');

if (!adminToken) { console.error('Set AITHENA_ADMIN_TOKEN or pass --token.'); process.exit(2); }
if (!label) { console.error('Pass --label "<device label>".'); process.exit(2); }

const body = JSON.stringify({ label, assignedUser: user, department: dept, trustedNetworks: trusted });
const url = new URL(server + '/api/v1/enroll');
const isHttps = url.protocol === 'https:';
const lib = isHttps ? https : http;
const opts = {
  method: 'POST', hostname: url.hostname, port: url.port || (isHttps ? 443 : 80),
  path: url.pathname,
  headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), 'Authorization': 'Bearer ' + adminToken }
};
if (isHttps) {
  if (caCertPath && fs.existsSync(caCertPath)) opts.ca = fs.readFileSync(caCertPath);
  else if (allowSelfSigned) opts.rejectUnauthorized = false;
}

const req = lib.request(opts, res => {
  let data = ''; res.on('data', d => data += d);
  res.on('end', () => {
    let json; try { json = JSON.parse(data); } catch (e) { console.error('Bad response:', data); process.exit(1); }
    if (res.statusCode !== 201) { console.error('Enroll failed (' + res.statusCode + '):', json.error || data); process.exit(1); }
    const agentConfig = {
      serverUrl: server,
      deviceId: json.deviceId,
      agentSecret: json.agentSecret,
      label,
      intervalSec,
      consent: false,                 // the device owner must set this to true (informed consent)
      caCertPath: caCertPath || undefined,
      allowSelfSigned: allowSelfSigned || undefined,
      deleteConfigOnUninstall: true
    };
    fs.writeFileSync(out, JSON.stringify(agentConfig, null, 2));
    console.log('\n✓ Enrolled ' + json.deviceId + ' (' + label + ')');
    console.log('✓ Wrote agent config: ' + out);
    console.log('\nNext:');
    console.log('  1. Send ' + out + ' to the device owner over a secure channel.');
    console.log('  2. The owner reviews it, sets  "consent": true, and runs:');
    console.log('        node aithena-agent.js --config ' + out);
    console.log('\nThe agent secret is shown only once and is stored hashed on the server.');
  });
});
req.on('error', e => { console.error('Request error:', e.message); process.exit(1); });
req.write(body); req.end();
