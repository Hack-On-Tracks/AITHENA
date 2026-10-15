# AITHENA / LeakLens — Live Multi-Laptop Monitoring

This adds **centralized, live monitoring of multiple *authorized* laptops** to the
existing LeakLens UI, without changing the original prototype. Each participating
laptop runs a small **consent-gated agent** that reports **only its own** outbound
connection *metadata* (destination IP/port, protocol, connection counts, duration,
and byte counts where the OS exposes them) to one **admin server**. The existing
Dashboard, Traffic, Alerts and Incident pages update in near real time over
Server-Sent Events, and a new **Admin Device Registry** shows every laptop with
honest `LIVE` / `STALE` / `OFFLINE` status.

> **Scope & ethics.** The agent reads the local host's own socket table (the same
> list the owner sees with `netstat`/`ss`). It does **not** capture packet payloads
> and **cannot** monitor any other machine's traffic, including other devices on the
> same Wi‑Fi. Sharing a network grants no visibility — each laptop must run its own
> agent, with the owner's informed consent. No blocking/quarantine is performed;
> this is monitoring and scoring only.

---

## 0. What was added

```
server/
  aithena-server.js         Central admin server (0-dependency Node)
  lib/auth.js               Token generation, hashing, constant-time compare
  lib/validate.js           Strict telemetry input validation
  lib/store.js              Device registry + per-device bounded flow store
  lib/risk-adapter.js       Bridges live flows into the existing risk engine
agent/
  aithena-agent.js          Endpoint agent (runs on each participating laptop)
  enroll.js                 Admin helper: registers a device, writes its config
  agent-config.example.json Template config
assets/js/live-client.js    Browser live layer (SSE, DEMO/LIVE, registry, inspector)
tests/live-telemetry.test.js  0-dependency test suite (9 groups)
```

The original files are unchanged except: each HTML page now also loads
`assets/js/live-client.js`, and `assets/css/style.css` has an appended
"AITHENA live layer" section. Everything still runs by opening the pages directly
(DEMO mode); the live layer only activates when you connect it to a server.

**Requirements:** Node.js 16+ on the server. The agent needs Node.js 16+ on each
laptop (Linux also works with zero external tools via `/proc/net`).

---

## 1. Server setup (the admin machine)

Pick one machine to be the collector/admin server. All laptops must be able to
reach it over the network (same LAN, or over a VPN, or a public host with HTTPS).

### 1a. Choose an admin token

The admin token protects enrollment, the registry, and the live stream. Generate one:

```bash
node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"
```

### 1b. (Recommended) Create a TLS certificate

Telemetry should travel over HTTPS or an already-encrypted VPN. For a lab, a
self-signed cert is fine — generate a CA + server cert so agents can verify it
properly:

```bash
# server key + self-signed cert (valid 365 days). Replace CN with the server's
# hostname or IP that laptops will connect to.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server/tls/key.pem -out server/tls/cert.pem \
  -days 365 -subj "/CN=YOUR-SERVER-HOSTNAME-OR-IP" \
  -addext "subjectAltName=IP:YOUR.SERVER.IP,DNS:YOUR-SERVER-HOSTNAME"
```

Give `server/tls/cert.pem` to each laptop later as the CA to trust (`caCertPath`).

### 1c. Start the server

Linux/macOS:

```bash
cd aithena
export AITHENA_ADMIN_TOKEN="<the token from 1a>"
export PORT=8443
export AITHENA_TLS_KEY="server/tls/key.pem"      # omit both TLS vars for plain HTTP
export AITHENA_TLS_CERT="server/tls/cert.pem"
node server/aithena-server.js
```

Windows (PowerShell):

```powershell
cd aithena
$env:AITHENA_ADMIN_TOKEN="<the token from 1a>"
$env:PORT="8443"
$env:AITHENA_TLS_KEY="server\tls\key.pem"
$env:AITHENA_TLS_CERT="server\tls\cert.pem"
node server\aithena-server.js
```

You should see `Admin server on https://0.0.0.0:8443/`. Open
`https://<server>:8443/` in a browser — the LeakLens UI loads in **DEMO mode**.

> If you run plain HTTP (no TLS vars), the server prints a warning. Only do that on
> a trusted LAN or **inside a VPN** (e.g. WireGuard/Tailscale), because agent
> secrets and metadata would otherwise cross the network in the clear.

**Config file (optional):** instead of env vars, copy `server/config.example.json`
to `server/config.json`. Env vars win over the file.

### 1d. Open the firewall

Allow inbound TCP on your chosen `PORT` (e.g. 8443). On Windows:

```powershell
New-NetFirewallRule -DisplayName "AITHENA 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

---

## 2. Enroll a laptop (once per friend, on the admin side)

For each participating laptop, register it and generate its agent config:

```bash
export AITHENA_ADMIN_TOKEN="<your token>"
node agent/enroll.js \
  --server https://YOUR-SERVER:8443 \
  --label "Rahul-Laptop" --user "Rahul" --dept "Friends" \
  --ca server/tls/cert.pem \
  --out ./agent-config.rahul.json
```

This calls the server, assigns a unique **device ID** (e.g. `DEV-001`), and writes
`agent-config.rahul.json` containing the server URL, device ID, and a **one-time
agent secret** (the secret is stored only as a salted hash on the server).

Send `agent-config.rahul.json` **and** `server/tls/cert.pem` to that friend over a
secure channel (encrypted chat, password manager, etc.). Repeat with a different
`--label`/`--out` for each laptop.

> No network between the enrollment machine and server? You can also `curl` the
> enroll endpoint directly; see §7.

---

## 3. Agent setup (on each friend's laptop, with their consent)

The friend installs Node.js (https://nodejs.org, LTS) if they don't have it, then:

1. Copies `aithena-agent.js` and their `agent-config.rahul.json` (and the CA
   `cert.pem`) into one folder.
2. **Reads and consents.** Opens the config and sets `"consent": true` (this is the
   informed-consent switch — the agent refuses to run until the owner sets it, or
   passes `--i-consent`). Points `caCertPath` at the `cert.pem` they received.
3. Runs it:

   ```bash
   node aithena-agent.js --config ./agent-config.rahul.json
   ```

   Windows (PowerShell), from the folder:

   ```powershell
   node .\aithena-agent.js --config .\agent-config.rahul.json
   ```

The agent prints what it's doing and sends a report every `intervalSec` seconds
(default 10). It appears on the admin dashboard within a few seconds.

**Useful flags**

| Flag | Effect |
|------|--------|
| `--once` | Send a single report and exit |
| `--dry-run` | Print what *would* be sent; send nothing (good for the owner to inspect) |
| `--i-consent` | Consent for this run without editing the config |
| `--uninstall` | Stop and remove the local config (opt-out) |

### Keep it running (optional)

- **Windows (Task Scheduler):**
  ```powershell
  schtasks /Create /TN AithenaAgent /SC ONLOGON /TR "node C:\path\aithena-agent.js --config C:\path\agent-config.rahul.json"
  ```
  Remove later with `schtasks /Delete /TN AithenaAgent /F`.
- **Linux (systemd --user):** create a unit running the same command; `systemctl --user enable --now aithena-agent`.

### Opt-out / uninstall

```bash
node aithena-agent.js --uninstall --config ./agent-config.rahul.json
```

This stops the agent and deletes the local config. Then the **admin revokes** the
device (Registry → **Revoke**, or §7) so its secret can never be reused. Also delete
any scheduled task/service created above.

---

## 4. Connect the dashboard to the live server

1. Open `https://<server>:8443/dashboard.html` in a browser.
2. In the bottom **Live bar**, click **⚙ Connection**.
3. Enter the **Server URL** (`https://<server>:8443`) and the **admin token**, then
   **Connect & go Live**.
4. The banner switches to `LIVE — N/N device(s) online`. The admin token is kept
   only in that browser tab's `sessionStorage` and sent only to that server.

Use **Switch to Demo / Switch to Live** on the Live bar to move between the
simulated prototype and real telemetry. The two are never mixed: DEMO shows the
original sample data under a clear DEMO banner; LIVE shows only real device data.

**Where live data shows up**

- **Traffic → Encrypted Flow Anomaly Inspector:** all connected laptops, a device
  filter, per-row `LIVE/STALE/OFFLINE` status, metadata-only findings.
- **Dashboard:** Fleet Overview tiles + the Admin Device Registry (ID, owner/host,
  status, last-seen, telemetry health, independent risk score, source IP, Revoke).
- **Developer console:** the full registry again for admin actions.
- **Alerts / Incidents:** live per-device risk with contributing factors and honest
  missing-telemetry notes. No automatic containment is taken.

---

## 5. Secure-connection checklist

- [ ] Server reached over **HTTPS** (TLS cert configured) **or** inside a VPN.
- [ ] Agents trust the server via `caCertPath` (don't rely on `allowSelfSigned`
      outside a quick lab test).
- [ ] `AITHENA_ADMIN_TOKEN` set from the environment (not left to the ephemeral
      auto-generated one) and kept secret.
- [ ] Per-device secrets delivered over a secure channel; never committed to git
      (`agent/.gitignore` already excludes `agent-config.*.json`).
- [ ] Firewall allows only the server port; retention bounded (default 6 h /
      2000 flows per device — tune in `config.json`).
- [ ] Each device owner has genuinely consented and can opt out any time.

---

## 6. End-to-end acceptance test (two laptops, no page refresh)

**Goal:** register at least two laptops, generate ordinary network activity on both,
and watch their real telemetry appear under the correct device IDs on the same admin
dashboard **without reloading the page**.

1. **Server:** start it (§1) and open `…/dashboard.html`; connect it Live (§4).
2. **Enroll two devices** (§2), e.g. `Rahul-Laptop` → `DEV-001`,
   `Meera-Laptop` → `DEV-002`.
3. **On each laptop**, set `consent: true` and run the agent (§3).
4. **Generate activity:** on each laptop just browse a few sites / open an app that
   uses the network.
5. **Verify (no refresh):**
   - Both `DEV-001` and `DEV-002` appear in the **Admin Device Registry**, each
     `LIVE`, with their own host name and source IP.
   - **Traffic → Inspector** shows rows for **both** device IDs; the device filter
     lists both; new rows and timestamps update on their own every few seconds.
   - Stopping one agent flips that device to `STALE` then `OFFLINE` on its own,
     while the other stays `LIVE` — and their flows never appear under each other.

### Automated proof (on the server machine)

A self-contained suite verifies enrollment, authentication, strict validation,
per-device isolation, per-device novelty, bounded retention, honest status
derivation, independent scoring, revoke, and a full HTTP + SSE round-trip:

```bash
node tests/live-telemetry.test.js     # 9 groups, exits 0 on success
node tests/device-risk.test.js        # original engine suite, still green
```

---

## 7. Admin API reference (for scripts / curl)

All admin calls need `Authorization: Bearer <AITHENA_ADMIN_TOKEN>` (the SSE stream
also accepts `?token=` because browsers can't set headers on `EventSource`).

| Method & path | Auth | Purpose |
|---|---|---|
| `GET  /api/v1/health` | none | Liveness + device count |
| `POST /api/v1/enroll` | admin | Register a device → `{deviceId, agentSecret}` |
| `POST /api/v1/telemetry?device=<id>` | agent bearer | Ingest a validated flow batch |
| `GET  /api/v1/devices` | admin | Device registry (status, risk, health) |
| `GET  /api/v1/devices/<id>/flows?limit=N` | admin | That device's recent flows only |
| `POST /api/v1/devices/<id>/revoke` | admin | Disable a device's secret |
| `GET  /api/v1/stream?token=<admin>` | admin | SSE: `snapshot`, `telemetry`, `registry`, `device` |

Enroll with curl:

```bash
curl -sk -X POST https://YOUR-SERVER:8443/api/v1/enroll \
  -H "Authorization: Bearer $AITHENA_ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"label":"Rahul-Laptop","assignedUser":"Rahul","department":"Friends"}'
```

Revoke with curl:

```bash
curl -sk -X POST https://YOUR-SERVER:8443/api/v1/devices/DEV-001/revoke \
  -H "Authorization: Bearer $AITHENA_ADMIN_TOKEN"
```

---

## 8. Tuning (`server/config.json`)

| Key | Default | Meaning |
|---|---|---|
| `port` / `host` | `8443` / `0.0.0.0` | Listen address |
| `liveMs` / `staleMs` | `30000` / `120000` | LIVE ≤30 s, STALE ≤2 min, else OFFLINE |
| `maxFlowsPerDevice` | `2000` | Per-device ring-buffer size |
| `retentionMs` | `21600000` | Flow age bound (6 h) |
| `maxBodyBytes` | `524288` | Max telemetry request size |
| `allowOrigins` | `null` | CORS allowlist if the UI is served from another origin |

Notes on honesty built into the engine: missing telemetry (e.g. no per-flow byte
counts on Windows) is treated as **unknown**, never "safe" — it lowers confidence,
never the score. Byte counts show as `n/a` rather than `0` when the OS doesn't
expose them per connection.
