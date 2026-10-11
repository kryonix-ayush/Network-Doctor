"""Streamlit dashboard for target, agent, history, and incident status."""

from __future__ import annotations

import os
from datetime import datetime

import httpx
import pandas as pd
import streamlit as st

from checks.models import CheckResult
from dashboard.api_client import DashboardAPI
from diagnosis.remediation import recommend_solutions


def _target_observations_by_location(
    target: dict,
    agent_locations: dict[str, str],
) -> dict[str, tuple[CheckResult, ...]]:
    grouped: dict[str, list[CheckResult]] = {}
    for agent_id, checks in target.get("observations", {}).items():
        if not isinstance(checks, dict):
            continue
        if agent_id in agent_locations:
            location = agent_locations[agent_id]
        elif str(agent_id).lower() == "local":
            location = "local"
        else:
            location = "cloud" if agent_id else "local"
        grouped.setdefault(location, [])
        for check_type, result in checks.items():
            if not isinstance(result, dict):
                continue
            grouped[location].append(
                CheckResult(
                    check_type,
                    result.get("success"),
                    float(result.get("duration_ms") or 0.0),
                    result.get("error_code"),
                    result.get("error_message"),
                    result.get("status_code"),
                    tuple(result.get("addresses") or ()),
                )
            )
    return {location: tuple(results) for location, results in grouped.items()}


st.set_page_config(page_title="Network Doctor", page_icon="🩺", layout="wide")
st.title("Network Doctor")

if st.sidebar.button("Refresh now"):
    st.rerun()

api_url = st.sidebar.text_input(
    "API URL",
    value=os.getenv("API_BASE_URL", "http://127.0.0.1:8000"),
)
api_token = st.sidebar.text_input(
    "API token",
    value=os.getenv("API_TOKEN", ""),
    type="password",
)
refresh_seconds = st.sidebar.number_input(
    "Auto-refresh interval (seconds)",
    min_value=5,
    max_value=300,
    value=10,
)
st.sidebar.caption("Use Refresh now to reload immediately.")

if not api_token:
    st.info("Set API_TOKEN in the environment or enter it in the sidebar.")
    st.stop()

try:
    api = DashboardAPI(api_url, api_token)
    overview = api.get("/api/v1/status")
    incidents = api.get("/api/v1/incidents", {"limit": 100})
    history = api.get("/api/v1/history", {"limit": 500})
    monitoring_settings = api.get("/api/v1/settings")
except (httpx.HTTPError, ValueError) as exc:
    st.error(f"Could not load authenticated API data: {type(exc).__name__}")
    st.stop()

if (
    not isinstance(overview, list)
    or not isinstance(incidents, list)
    or not isinstance(history, list)
    or not isinstance(monitoring_settings, dict)
):
    st.error("The API returned an unexpected response shape.")
    st.stop()

overview_tab, compare_tab, performance_tab, incidents_tab, settings_tab = st.tabs(
    ["Overview", "Local vs Cloud", "Performance", "Incidents", "Settings"]
)
with overview_tab:
    st.subheader("Current status by target")
    st.dataframe(pd.DataFrame(overview), use_container_width=True, hide_index=True)
    st.subheader("Agents")
    try:
        agents = api.get("/api/v1/agents")
        agent_locations = {
            str(agent.get("id")): str(agent.get("location_type") or "local")
            for agent in agents
            if isinstance(agent, dict)
        }
        st.dataframe(pd.DataFrame(agents), use_container_width=True, hide_index=True)
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        st.warning(f"Agent status unavailable: {type(exc).__name__}")
        agent_locations = {}
    for target in overview:
        if not isinstance(target, dict):
            continue
        created = []
        for recommendation in recommend_solutions(
            _target_observations_by_location(target, agent_locations),
            diagnosis=None,
        ):
            created.append(recommendation)
        if created:
            with st.expander(f"Recommended solutions for {target.get('name', target.get('url'))}", expanded=False):
                for recommendation in created:
                    st.markdown(f"**{recommendation['priority'].upper()} priority** — {recommendation['title']}")
                    st.write(recommendation["reason"])
                    st.caption(f"Evidence: { ' | '.join(recommendation['evidence']) if recommendation['evidence'] else 'No direct evidence recorded.' }")
                    st.write("Steps:")
                    for idx, step in enumerate(recommendation["steps"], start=1):
                        st.write(f"{idx}. {step}")
                    st.write(f"Verification: {recommendation['verification']}")
                    st.write(f"Risk/admin approval: {recommendation['risk']}")
                    if recommendation.get("requires_admin"):
                        st.caption("This step requires explicit administrator approval before any configuration change.")
                    st.caption(f"Confidence: {recommendation['confidence']} | Source check: {recommendation['source_check']}")

with compare_tab:
    st.subheader("Side-by-side latest observations")
    rows = []
    for target in overview:
        observations = target.get("observations", {})
        for agent, checks in observations.items():
            for check_type, result in checks.items():
                rows.append(
                    {
                        "target": target.get("name", target.get("url")),
                        "agent": agent,
                        "check": check_type,
                        "success": result.get("success"),
                        "duration_ms": result.get("duration_ms"),
                        "status_code": result.get("status_code"),
                        "checked_at": result.get("timestamp_utc"),
                    }
                )
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

with performance_tab:
    st.subheader("Response time history")
    if history:
        frame = pd.DataFrame(history)
        frame["timestamp_utc"] = pd.to_datetime(frame["timestamp_utc"], utc=True)
        frame["duration_ms"] = pd.to_numeric(frame["duration_ms"])
        target_options = sorted(frame["target_url"].unique())
        selected_target = st.selectbox("Target", target_options)
        selected = frame[
            (frame["target_url"] == selected_target)
            & (frame["check_type"].isin(["https", "tcp"]))
        ]
        if not selected.empty:
            chart = selected.pivot_table(
                index="timestamp_utc",
                columns="check_type",
                values="duration_ms",
                aggfunc="last",
            ).sort_index()
            st.line_chart(chart)
            selected = selected.sort_values(["check_type", "timestamp_utc"]).copy()
            selected["failure"] = (~selected["success"].fillna(False)).astype(float)
            selected["failure_rate"] = selected.groupby("check_type")["failure"].transform(
                lambda values: values.rolling(10, min_periods=1).mean()
            )
            failure_rate = selected.pivot_table(
                index="timestamp_utc",
                columns="check_type",
                values="failure_rate",
                aggfunc="last",
            )
            st.subheader("Failure rate (rolling 10 checks)")
            st.line_chart(failure_rate)
            st.subheader("Recent failures")
            st.dataframe(
                selected[selected["success"].eq(False)].sort_values("timestamp_utc", ascending=False),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No performance measurements exist for this target.")
    else:
        st.info("No result history is available yet.")

with incidents_tab:
    st.subheader("Active and resolved incidents")
    if incidents:
        st.dataframe(pd.DataFrame(incidents), use_container_width=True, hide_index=True)
        active_incidents = [incident for incident in incidents if incident["status"] == "open"]
        if active_incidents:
            incident_to_ack = st.selectbox(
                "Active incident to acknowledge",
                options=[incident["id"] for incident in active_incidents],
            )
            if st.button("Acknowledge incident"):
                try:
                    response = httpx.post(
                        f"{api.base_url}/api/v1/incidents/{incident_to_ack}/acknowledge",
                        headers=api.headers,
                        timeout=api.timeout,
                    )
                    response.raise_for_status()
                    st.success("Incident acknowledged.")
                except httpx.HTTPError as exc:
                    st.error(f"Could not acknowledge incident: {type(exc).__name__}")
    else:
        st.success("There are no incidents.")

with settings_tab:
    st.subheader("Monitoring policy")
    with st.form("monitoring_policy"):
        interval = st.number_input(
            "Monitoring interval (seconds)",
            min_value=1.0,
            max_value=3600.0,
            value=float(monitoring_settings["interval_seconds"]),
        )
        dns_timeout = st.number_input(
            "DNS timeout (seconds)",
            min_value=0.1,
            max_value=120.0,
            value=float(monitoring_settings["dns_timeout_seconds"]),
        )
        tcp_timeout = st.number_input(
            "TCP timeout (seconds)",
            min_value=0.1,
            max_value=120.0,
            value=float(monitoring_settings["tcp_timeout_seconds"]),
        )
        http_timeout = st.number_input(
            "HTTPS timeout (seconds)",
            min_value=0.1,
            max_value=120.0,
            value=float(monitoring_settings["http_timeout_seconds"]),
        )
        failures_to_open = st.number_input(
            "Consecutive failures to open incident",
            min_value=1,
            max_value=100,
            value=int(monitoring_settings["failures_to_open_incident"]),
        )
        successes_to_resolve = st.number_input(
            "Consecutive successes to resolve incident",
            min_value=1,
            max_value=100,
            value=int(monitoring_settings["successes_to_resolve_incident"]),
        )
        max_concurrent_checks = st.number_input(
            "Maximum concurrent checks",
            min_value=1,
            max_value=1000,
            value=int(monitoring_settings["max_concurrent_checks"]),
        )
        retention_days = st.number_input(
            "History retention (days)",
            min_value=1,
            max_value=3650,
            value=int(monitoring_settings["retention_days"]),
        )
        submitted_settings = st.form_submit_button("Save monitoring policy")
    if submitted_settings:
        try:
            response = httpx.patch(
                f"{api.base_url}/api/v1/settings",
                headers=api.headers,
                json={
                    "interval_seconds": interval,
                    "dns_timeout_seconds": dns_timeout,
                    "tcp_timeout_seconds": tcp_timeout,
                    "http_timeout_seconds": http_timeout,
                    "failures_to_open_incident": failures_to_open,
                    "successes_to_resolve_incident": successes_to_resolve,
                    "max_concurrent_checks": max_concurrent_checks,
                    "retention_days": retention_days,
                },
                timeout=api.timeout,
            )
            response.raise_for_status()
            st.success("Monitoring policy saved; agents apply it on their next cycle.")
        except httpx.HTTPError as exc:
            st.error(f"Could not save monitoring settings: {type(exc).__name__}")

    st.subheader("Manage authorized targets")
    with st.form("add_target"):
        target_name = st.text_input("Target name")
        target_url = st.text_input("HTTPS URL")
        target_enabled = st.checkbox("Enabled", value=True)
        submitted = st.form_submit_button("Add or update target")
    if submitted:
        try:
            response = httpx.post(
                f"{api.base_url}/api/v1/targets",
                headers=api.headers,
                json={"name": target_name, "url": target_url, "enabled": target_enabled},
                timeout=api.timeout,
            )
            response.raise_for_status()
            st.success("Authorized target saved.")
        except (httpx.HTTPError, ValueError) as exc:
            st.error(f"Target was not saved: {type(exc).__name__}")
    try:
        targets = api.get("/api/v1/targets")
        st.dataframe(pd.DataFrame(targets), use_container_width=True, hide_index=True)
    except httpx.HTTPError as exc:
        st.error(f"Could not load target settings: {type(exc).__name__}")

st.caption(f"Dashboard refreshed {datetime.now().astimezone().isoformat(timespec='seconds')}")
st.markdown(
    f"<meta http-equiv='refresh' content='{int(refresh_seconds)}'>",
    unsafe_allow_html=True,
)
