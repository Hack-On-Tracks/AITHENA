LeakLens - UI prototype, multi-page version (Home, Dashboard, Traffic Analysis, Knowledge Graph, Alerts, Incidents, Developer Console)
Hero wordmark uses the TechText component from React Bits (ported to vanilla JS, no build step needed).

How to run: double-click index.html (open in Chrome/Edge/Firefox). Use the top nav or the Prev/Next buttons in the footer to move between pages.
Needs internet only for Google Fonts; it still works offline with fallback fonts.

Files
  index.html        Home (hero + intro story)
  dashboard.html    01 Dashboard
  traffic.html      02 Traffic analysis
  graph.html        03 Knowledge graph
  alerts.html       04 Alerts
  incidents.html    05 Incidents
  developer.html    06 Developer console
  assets/css/style.css   shared styles (unchanged from the single-page version, plus pager styles at the end)
  assets/js/techtext.js  TechText wordmark component
  assets/js/app.js       background scene, nav, sample data and all page logic

All data is generated sample data (see assets/js/app.js). Events, incidents, notes, the alert threshold,
false positives and allowlists are kept in sessionStorage, so they carry over between pages in the same browser tab.
"Open investigation" on the Alerts page takes you to the Incidents page with that incident selected.
To connect a real backend, replace the mk() event generator and the setInterval stream with fetch() calls to your API.

--------------------------------------------------------------------------------
Isolated Insider Data-Transfer Simulation
--------------------------------------------------------------------------------

Open graph.html and use "Start Simulation" to generate labeled SIMULATED transfer
events in the Knowledge Graph. The stream animates DEV-003 (Sameera, Insider)
transfers to DEV-004 (Keona, Outsider), mixed with normal background transfers.
Pause stops generation, Start resumes a paused stream, and Reset clears only the
simulation events and returns the graph risk scores to their baseline.

To serve the project locally, run `node local-server.js` from the project folder
and open http://localhost:8080/graph.html. The simulation is browser-only: it
does not open network connections, inspect files, or collect device telemetry.
Its anomaly thresholds are defined in
`assets/js/device-risk-engine.js` under `DEFAULT_CONFIG.transferDetection`.
Run the checks with `node tests/device-risk.test.js` and
`node tests/transfer-simulation.test.js`.

--------------------------------------------------------------------------------
Adaptive Device Risk Detection & Response Module
--------------------------------------------------------------------------------

1. New Files
   assets/js/device-risk-engine.js  Pure detection & scoring engine (testable in Node/browser via UMD).
   assets/js/device-response.js     Response layer adapters, safeguards, roles & append-only audit log.
   assets/js/device-risk-ui.js      Multi-page UI integration for Dashboard, Traffic, Alerts, Incidents, Developer Console.
   assets/js/device-risk-data.js    Synthetic device inventory, telemetry events & reviewer demo scenarios.
   tests/device-risk.test.js        Test suite verifying acceptance criteria a through f via plain Node.

2. How to Run the Tests
   Run in terminal:
     node tests/device-risk.test.js
   Output confirms all six acceptance criteria (a to f) pass cleanly with 0 dependencies.

3. How to Run the Web Application Locally
   Option A: Double-click index.html or open it in any web browser.
   Option B: Start a local HTTP server with:
     npx -y serve . -p 8080
   Navigate across pages via the top nav bar (Dashboard, Traffic, Alerts, Incidents, Developer Console).

4. Scoring & De-duplication Architecture
   - Correlation Groups: Signals are classified into groups (network, traffic, identity, status).
   - Within each group, only the strongest signal is taken at full weight; duplicate/subsequent signals receive a bounded diminishing factor (damping = 0.3) to avoid double counting.
   - Corroboration Bonus: When two or more independent signal groups corroborate an anomaly, a modest corroboration bonus (+10%) is applied.
   - Bounded Combiner: Total device risk score is capped between 0 and 100.
   - Missing Telemetry: Unseen sources (e.g. absent VPN logs) are treated as UNKNOWN, never safe. They never deduct risk points; instead, they lower the assessment confidence to Low or Medium and are surfaced in the explanation.
   - Stolen Status Rule: Reported stolen status acts as a multiplier only when accompanied by unfamiliar network or flow anomalies. Stolen status alone is capped below Critical.

5. Honesty Rules & Response Labelling
   Every response action carries an explicit honesty status label:
   - "SIMULATED": Default demonstration mode. Indicates isolation/step-up would be requested.
   - "REQUESTED, awaiting confirmation from <system>": Action sent to external adapter, awaiting confirmation.
   - "CONFIRMED by <system>": Explicit confirmation received from a configured external provider.
   No misleading wording (such as "frozen", "isolated", or "credentials revoked") is ever displayed unless verified CONFIRMED. A persistent "DEMO MODE" banner is displayed on all response surfaces.

6. Safeguards & Role Permissions
   - Roles: viewer, analyst, responder, admin.
   - Only responder and admin can trigger destructive containment (endpoint isolation).
   - Destructive actions enforce a two-step confirmation dialog requiring the user to type the exact device ID (e.g. DEV-001).
   - Protected Devices: Infrastructure servers (e.g. SRV-PROD-01) cannot be isolated from this UI.
   - Cooldown: 5-minute guard prevents accidental duplicate actions on the same device.
   - Audit Trail: All actions, notes, acknowledgements, and simulated results are stored under sessionStorage key "lldr_audit".

7. Plugging in a Real Adapter (IdP / MDM)
   Implement the Adapter interface in assets/js/device-response.js:
     class OktaIdentityAdapter extends Adapter {
       constructor(apiKey) { super('OktaIdP', ['stepup', 'revoke_sessions']); this.key = apiKey; }
       isConfigured() { return Boolean(this.key); }
       async execute(action, device, context) {
         const resp = await fetch('https://your-domain.okta.com/api/v1/users/' + device.assignedUser + '/lifecycle/suspend', {
           method: 'POST',
           headers: { Authorization: 'SSWS ' + this.key }
         });
         return { confirmed: resp.ok, externalRef: 'OKTA-' + Date.now(), message: 'Confirmed by Okta API' };
       }
     }

8. Live Reviewer Demo Scenarios (Developer Console)
   Open developer.html (06 Developer console) to test scenarios:
   - "Run Stolen-Laptop Scenario" (Criterion c): Triggers stolen status + untrusted network + 2.5 GB flow anomaly + admin portal auth on DEV-001. Score elevates to Critical.
   - "Run Network-Change-Only" (Criterion a): Demonstrates that network transition alone stays Low/Medium and never reaches Critical.
   - "Run Telemetry Gap" (Criterion d): Marks VPN telemetry missing. Confirms confidence drops to Low while score is not deducted.
   - "Reset Demo State": Clears injected events and restores baseline state.

--------------------------------------------------------------------------------
Live Multi-Laptop Monitoring (centralized admin server) — NEW
--------------------------------------------------------------------------------
The UI can now show LIVE telemetry from multiple AUTHORIZED laptops, each running a
consent-gated agent that reports only its own outbound connection metadata to one
admin server. DEMO (simulated) and LIVE (real) data are kept strictly separate via
the Live bar at the bottom of every page.

  Quick start:
    export AITHENA_ADMIN_TOKEN="$(node -e "console.log(require('crypto').randomBytes(24).toString('hex'))")"
    node server/aithena-server.js
    node agent/enroll.js --server http://localhost:8443 --label "Laptop-1" --out ./agent-config.1.json
    # set "consent": true in agent-config.1.json, then on that laptop:
    node agent/aithena-agent.js --config ./agent-config.1.json
    # open http://localhost:8443/dashboard.html -> Live bar -> Connection -> go Live

  Tests:   node tests/live-telemetry.test.js
  Full guide, Windows + TLS/VPN + acceptance test:  see LIVE-SETUP.md

New files: server/ (admin server + libs), agent/ (agent + enroll helper),
assets/js/live-client.js, tests/live-telemetry.test.js. Original prototype is
unchanged except each page also loads live-client.js and style.css has an appended
live-layer section.
