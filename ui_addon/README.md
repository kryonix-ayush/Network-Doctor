# Network Doctor UI Addon

This directory contains a separate, additive Streamlit UI for Network Doctor. It is designed to work with the existing project without modifying the original CLI, API routes, agent behavior, or persistence model.

## Launch

From the project root:

```powershell
python -m streamlit run ui_addon/app.py
```

The addon reads `API_TOKEN` and `API_BASE_URL` from the server environment. Do not expose tokens in browser-visible UI or logs.

## What it does

- shows current target health from the existing API status endpoint
- shows connection health for agents and the API
- runs the existing CLI entry point (`network_doctor.py`) using `subprocess` and `shell=False`
- presents captured stdout/stderr, exit code, and runtime without modifying CLI output
- displays evidence-based remediation guidance from `diagnosis/remediation.py` when current data supports a recommendation

## Safety constraints

- no automatic changes to DNS, firewall, certificate, or server configuration
- no token leakage or secret exposure
- no modifications to core files or schemas
- no shell injection; the CLI is launched with a fixed argument list

## Requirements

- Python 3.12+
- the project virtual environment or equivalent runtime
- a running API with a valid `API_TOKEN`
