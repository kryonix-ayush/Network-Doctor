# Network Doctor

Network Doctor is a local-plus-cloud monitor for HTTPS services. A local
Windows agent performs DNS, TCP, HTTPS, and TLS certificate checks and keeps a
durable SQLite history and delivery outbox. An independent cloud agent performs
the same checks from a separate network location. An authenticated API accepts
agent results, correlates observations, tracks incidents, and serves a
Streamlit dashboard. SQLite is used by default; PostgreSQL is supported for the
API deployment.

Only add targets you own or are explicitly authorized to monitor.

## Requirements

- Python 3.12 or newer for local development.
- Docker Compose v2 and a public DNS name pointing at the deployment host for
  the bundled public HTTPS deployment.
- The cloud agent requires API HTTPS. Local development may use loopback HTTP.

## Windows PowerShell setup

From the project directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If activation is blocked for the current PowerShell process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Run a one-off diagnostic against an authorized HTTPS URL:

```powershell
python .\network_doctor.py https://example.com/
python .\network_doctor.py https://example.com/ --dns-timeout 2 --tcp-timeout 3 --https-timeout 5
python .\network_doctor.py https://example.com/ --ping
python .\network_doctor.py https://example.com/ --traceroute
```

DNS, TCP, HTTPS, and TLS results are reported separately. ICMP and traceroute
are opt-in; ICMP can be blocked independently of HTTPS. HTTPS certificate
verification remains enabled and redirects are not followed. Each request has
a finite timeout. The command exits with `0` for an HTTPS success, `1` for a
failed measurement, and `2` for an invalid URL or command-line argument.

## Local continuous monitoring

Run the local agent from the project root. It saves results to
`network_doctor.sqlite3` and keeps checking without requiring the API or cloud
worker to be available:

```powershell
python -m agents.local_agent https://example.com/ https://www.python.org/
```

Stop with `Ctrl+C`. A single finite cycle is useful for testing:

```powershell
python -m agents.local_agent https://example.com/ --cycles 1
```

Tune its cadence, concurrency, and local database:

```powershell
python -m agents.local_agent https://example.com/ `
  --interval 10 `
  --max-concurrent-checks 20 `
  --database .\data\network_doctor.sqlite3
```

Show saved measurements:

```powershell
python .\network_doctor_history.py --limit 30
python .\network_doctor_history.py --database .\data\network_doctor.sqlite3 --url https://example.com/
```

The scheduler does not overlap cycles. If a cycle exceeds its interval, the
next begins after the current one finishes. Local checks and result persistence
are independent of remote API delivery; results are kept in a durable outbox
and retried with bounded exponential backoff.

## Local API and dashboard

Create independent random secrets for the API and each agent. Keep them private,
do not commit them, and use at least 32 characters for each. Example PowerShell
environment setup (replace the example values with randomly generated secrets):

```powershell
$env:API_TOKEN = "replace-with-a-random-secret-of-at-least-32-characters"
$env:LOCAL_AGENT_TOKEN = "use-a-different-random-secret-of-at-least-32-characters"
$env:CLOUD_AGENT_TOKEN = "use-another-random-secret-of-at-least-32-characters"
$env:AGENT_TOKENS = "{`"network-doctor-local`":`"$env:LOCAL_AGENT_TOKEN`",`"network-doctor-cloud`":`"$env:CLOUD_AGENT_TOKEN`"}"
$env:DATABASE_PATH = ".\network_doctor.sqlite3"
$env:DATABASE_URL = ""
$env:API_BASE_URL = "http://127.0.0.1:8000"
```

PowerShell environment variables are scoped to one terminal. Apply this block
in each terminal that will start one of the processes below.

In three PowerShell terminals (activate the virtual environment in each), start
the API, dashboard, and local agent. The API and dashboard use `API_TOKEN`; the
local agent sends its distinct `AGENT_TOKEN` and `AGENT_ID`:

```powershell
# Terminal 1: API
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# Terminal 2: dashboard
python -m streamlit run dashboard/app.py

# Terminal 3: local agent
$env:AGENT_ID = "network-doctor-local"
$env:AGENT_TOKEN = $env:LOCAL_AGENT_TOKEN
python -m agents.local_agent https://example.com/
```

Open the Streamlit URL printed by the dashboard (normally
`http://localhost:8501`) and enter the API token in its sidebar. The dashboard
shows target status, local/cloud observations, response-time and rolling
failure-rate charts, incidents, agents, and monitoring policy. Acknowledge
incidents and update policy in the dashboard.

Add an authorized HTTPS target with the authenticated API. For example:

```powershell
$headers = @{ Authorization = "Bearer $env:API_TOKEN" }
$body = @{
  name = "Example"
  url = "https://example.com/"
  expected_status_codes = @(200, 301, 302)
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/targets" `
  -Headers $headers -ContentType "application/json" -Body $body
```

The API also provides authenticated target listing/enablement, agent heartbeat,
result ingestion, current status, history, incidents, and monitoring settings.
Health and readiness endpoints are available at `/health` and `/ready`.

## Alerts

Alerts are optional. Configure Telegram using `TELEGRAM_BOT_TOKEN` and
`TELEGRAM_CHAT_ID`; configure email using `SMTP_HOST`, `SMTP_PORT`,
`SMTP_USERNAME`, `SMTP_PASSWORD`, `ALERT_FROM_EMAIL`, and `ALERT_TO_EMAIL`.
Missing channel configuration disables that channel. Incident transitions are
deduplicated per channel, persisted, and retried a bounded number of times.
Never put alert credentials in source code or target URLs.

## Public cloud deployment with Docker Compose

1. Copy `.env.example` to `.env`.
2. Replace every placeholder with fresh random credentials; ensure
   `LOCAL_AGENT_TOKEN` and `CLOUD_AGENT_TOKEN` are distinct from `API_TOKEN`.
   The `AGENT_TOKENS` JSON map must use IDs matching `AGENT_ID` for each agent.
3. Set `NETWORK_DOCTOR_DOMAIN` to a DNS name whose A/AAAA records point to the
   host. Allow inbound TCP ports 80 and 443 for Caddy certificate issuance and
   HTTPS traffic.
4. Start the API, PostgreSQL, cloud worker, dashboard, and TLS proxy:

```powershell
docker compose up --build -d
docker compose ps
docker compose logs -f api cloud-agent
```

The proxy automatically provisions HTTPS certificates for the configured
domain. The API uses PostgreSQL. The cloud worker has a separate persistent
SQLite volume for its local result history, cached target list, and durable
outbox, so it can continue probing while the API is temporarily unavailable.
The API and dashboard are exposed through the HTTPS proxy; do not expose the
API on plain public HTTP.

Stop the deployment without deleting its data:

```powershell
docker compose down
```

Private, loopback, link-local, and metadata IP destinations are blocked by the
cloud probe by default. Leave `ALLOW_PRIVATE_CLOUD_TARGETS=false` unless private
network monitoring is an explicit, reviewed requirement. Enabling it requires
the exact acknowledgement shown in `.env.example`; it bypasses the cloud
destination restriction and can expose internal services.

## Security and data behavior

- Cloud DNS results are checked against the public-destination policy, and
  cloud TCP/HTTPS connections are pinned to the validated IP to reduce
  DNS-rebinding risk. TLS certificate and hostname verification remain on.
- URLs must be HTTPS, cannot contain credentials, and redirects are not
  followed. Logs and alerts redact query strings.
- API access requires bearer authentication. Agent credentials are separately
  bound to agent IDs; result targets must be enabled and authorized in the API.
- The API applies request-size and rate limits, validates request schemas,
  stores idempotent agent results, and uses bounded result retention.
- Do not store secrets in Git, dashboard-visible target URLs, or logs. Keep
  `.env` private and rotate credentials if exposed.
- Optional ping/traceroute may need OS permissions or be blocked by firewalls;
  neither is required to establish HTTPS availability.

## Tests

From the project root with the virtual environment active:

```powershell
python -m pytest -q
```

The automated suite uses mocked HTTP/DNS and local socket fixtures and does not
require access to external websites. Docker/PostgreSQL deployment and
internet-dependent live probes are separate integration checks.

## Separate UI addon

A separate additive UI addon is available in `ui_addon/` for a modern network
operations dashboard without changing the existing project dashboard, CLI, API,
agent behavior, or persistence model.

Launch the addon from the project root:

```powershell
python -m streamlit run ui_addon/app.py
```

The addon is designed to:

- connect to the existing authenticated read APIs (`/health`, `/ready`,
  `/api/v1/targets`, `/api/v1/status`, `/api/v1/agents`, `/api/v1/history`,
  `/api/v1/incidents`, `/api/v1/settings`)
- show the same terminal diagnostic output captured from the existing CLI without
  modifying CLI behavior or output formatting
- display evidence-based remediation guidance from `diagnosis/remediation.py`
  with read-only steps, risk/admin warnings, and verification instructions
- present overview, run-diagnostic, issues-and-solutions, history, and agent
  connection views in a dark diagnostics-console aesthetic

Security requirements for the addon:

- keep `API_TOKEN` and all agent secrets server-side; never expose them in UI,
  browser code, logs, URLs, or error messages
- do not execute arbitrary shell commands; the addon runs the existing
  `network_doctor.py` entry point with `subprocess` and `shell=False`
- do not disable certificate verification or loosen cloud destination
  protections
- do not create a parallel database or modify existing project files; the addon
  is intentionally additive and read-only for existing system state

If a required capability is not available through the verified existing
interfaces, the addon should report the limitation instead of altering the core
project.
