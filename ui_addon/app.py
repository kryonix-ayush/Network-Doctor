"""Additive Streamlit UI for Network Doctor diagnostics and recommendations."""

from __future__ import annotations

import os

import pandas as pd
import streamlit as st

from ui_addon.services.api_client import UIAPIClient
from ui_addon.services.result_adapter import (
    history_rows,
    incident_issue_rows,
    observed_target_rows,
    recommendations_for_target,
    status_metrics,
)
from ui_addon.services.terminal_runner import run_diagnostic

st.set_page_config(page_title="Network Doctor UI Addon", page_icon="🩺", layout="wide")
st.markdown(
    """
    <style>
    .stApp { background: #0b1220; color: #e5ecf8; }
    .block-container { padding-top: 1rem; }
    .stMetric { background: #101a2b; border: 1px solid #20314d; border-radius: 0.75rem; }
    div[data-testid="stExpander"] > div { background: #101a2b; }
    code { background: #0a0f18; }
    </style>
    """,
    unsafe_allow_html=True,
)

if "API_TOKEN" not in os.environ:
    st.warning("API_TOKEN is not configured in the environment for the addon. Set it before launching the UI.")
    st.stop()

api_base_url = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")

try:
    client = UIAPIClient(api_base_url)
except ValueError as exc:
    st.warning(str(exc))
    st.stop()

try:
    health = client.get("/health")
    status = client.get("/api/v1/status")
    incidents = client.get("/api/v1/incidents", {"limit": 25})
    agents = client.get("/api/v1/agents")
    history = client.get("/api/v1/history", {"limit": 50})
except Exception as exc:  # pragma: no cover - UI error branch
    st.error(f"API unavailable: {type(exc).__name__}. The addon will continue in read-only disconnected mode.")
    health = {"status": "disconnected"}
    status = []
    incidents = []
    agents = []
    history = []

overview_tab, run_tab, issues_tab, history_tab, agents_tab = st.tabs(
    ["Overview", "Run Diagnostic", "Issues & Solutions", "History", "Agents & Connection"]
)

with overview_tab:
    st.title("Network Doctor UI Addon")
    st.caption(f"Connected API: {api_base_url}  •  API health: {health.get('status', 'unknown')}")

    metrics = status_metrics(status)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Healthy targets", metrics["healthy"])
    col2.metric("Failing targets", metrics["failing"])
    col3.metric("Unknown", metrics["unknown"])
    col4.metric("Active incidents", len([item for item in incidents if item.get("status") in {"open", "acknowledged"}]))

    rows = observed_target_rows(status)
    if rows:
        st.subheader("Current target status")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No target status is available yet from the API.")

    if incidents:
        st.subheader("Recent incidents")
        st.dataframe(pd.DataFrame(incident_issue_rows(incidents)), use_container_width=True, hide_index=True)

with run_tab:
    st.subheader("Run a one-off diagnostic")
    url = st.text_input("Authorized HTTPS URL", value="https://example.com/")
    include_ping = st.checkbox("Include ICMP ping", value=False)
    include_traceroute = st.checkbox("Include traceroute", value=False)
    run_clicked = st.button("Run Diagnostic")
    if run_clicked:
        with st.spinner("Running the existing Network Doctor CLI..."):
            result = run_diagnostic(
                url,
                include_ping=include_ping,
                include_traceroute=include_traceroute,
            )
        st.code(result.stdout, language="text")
        if result.stderr:
            st.code(result.stderr, language="text")
        st.caption(
            f"Exit code: {result.exit_code} • Elapsed: {result.elapsed_seconds:.2f}s • Started: {result.started_at} • Completed: {result.completed_at}"
        )

with issues_tab:
    st.subheader("Detected issues and recommended actions")
    if not incidents:
        st.info("No incidents are currently available from the API.")
    else:
        for incident in incidents:
            target_key = incident.get("target_url") or "unknown"
            target_info = next((item for item in status if item.get("url") == target_key), None)
            recommendations = []
            if target_info and target_info.get("observations"):
                recommendations = recommendations_for_target(target_info)
            st.markdown(f"### {target_key}")
            st.write(f"Diagnosis: {incident.get('summary') or 'No summary available.'}")
            st.write(f"Confidence: {incident.get('confidence') or 'unknown'} | Status: {incident.get('status') or 'open'}")
            if incident.get("evidence"):
                st.write("Evidence:")
                for item in incident["evidence"]:
                    st.write(f"- {item}")
            if recommendations:
                for recommendation in recommendations:
                    st.markdown(f"**{recommendation['priority'].upper()}** — {recommendation['title']}")
                    st.write(recommendation["reason"])
                    st.write("Steps:")
                    for idx, step in enumerate(recommendation["steps"], start=1):
                        st.write(f"{idx}. {step}")
                    st.write(f"Verification: {recommendation['verification']}")
                    st.write(f"Risk: {recommendation['risk']}")
                    st.caption(f"Confidence: {recommendation['confidence']} | Source check: {recommendation['source_check']}")
            else:
                st.info("No verified remediation recommendation is available for this incident from the current evidence set.")
            st.divider()

with history_tab:
    st.subheader("Recent diagnostic history")
    if history:
        frame = pd.DataFrame(history_rows(history))
        st.dataframe(frame, use_container_width=True, hide_index=True)
    else:
        st.info("No recent history is available from the API yet.")

with agents_tab:
    st.subheader("Agent and connection status")
    if not agents:
        st.info("No agent records are available yet.")
    else:
        st.dataframe(pd.DataFrame(agents), use_container_width=True, hide_index=True)

    st.write("Connection check")
    st.success("API reachable." if client.ping() else "API is not reachable from the addon runtime.")
