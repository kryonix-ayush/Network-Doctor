"""Safe subprocess wrapper for the existing Network Doctor CLI."""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DiagnosticRun:
    """Captured output for a single CLI diagnostic run."""

    url: str
    stdout: str
    stderr: str
    exit_code: int
    elapsed_seconds: float
    started_at: str
    completed_at: str


def run_diagnostic(
    target_url: str,
    *,
    dns_timeout: float = 2.0,
    tcp_timeout: float = 3.0,
    https_timeout: float = 5.0,
    include_ping: bool = False,
    include_traceroute: bool = False,
    timeout_seconds: float = 30.0,
) -> DiagnosticRun:
    """Run the existing one-off diagnostic in a controlled subprocess."""

    project_root = Path(__file__).resolve().parents[2]
    command = [
        os.environ.get("PYTHON_EXECUTABLE", "python"),
        str(project_root / "network_doctor.py"),
        target_url,
        "--dns-timeout",
        str(dns_timeout),
        "--tcp-timeout",
        str(tcp_timeout),
        "--https-timeout",
        str(https_timeout),
    ]
    if include_ping:
        command.append("--ping")
    if include_traceroute:
        command.append("--traceroute")

    started = time.time()
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started))
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=False,
        cwd=str(project_root),
        timeout=timeout_seconds,
    )
    elapsed = time.time() - started
    completed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
    return DiagnosticRun(
        url=target_url,
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
        elapsed_seconds=elapsed,
        started_at=started_at,
        completed_at=completed_at,
    )
