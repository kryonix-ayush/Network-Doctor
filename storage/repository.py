"""SQLite persistence for local diagnostic history."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from collections.abc import Generator, Iterable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from checks.models import CheckResult


class _PostgresResult:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def fetchall(self) -> list[Any]:
        return self._rows


class _PostgresConnection:
    """Adapt this repository's small SQL subset to PostgreSQL/psycopg."""

    def __init__(self, connection: Any) -> None:
        self.connection = connection

    @staticmethod
    def _translate(query: str) -> str:
        query = re.sub(
            r"INTEGER PRIMARY KEY AUTOINCREMENT",
            "BIGSERIAL PRIMARY KEY",
            query,
            flags=re.IGNORECASE,
        )
        query = query.replace("?", "%s")
        return query

    def execute(self, query: str, parameters: Any = ()) -> Any:
        match = re.search(r"PRAGMA table_info\((\w+)\)", query, re.IGNORECASE)
        if match:
            rows = self.connection.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
                (match.group(1),),
            ).fetchall()
            return _PostgresResult([(0, row["column_name"]) for row in rows])
        if query.lstrip().upper().startswith("PRAGMA"):
            return _PostgresResult([])
        return self.connection.execute(self._translate(query), parameters)

    def executemany(self, query: str, parameters: Any) -> Any:
        with self.connection.cursor() as cursor:
            cursor.executemany(self._translate(query), parameters)
            return cursor

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        self.connection.close()

    @property
    def row_factory(self) -> Any:
        return None

    @row_factory.setter
    def row_factory(self, _value: Any) -> None:
        pass


def _row_value(row: Any, key: str, index: int) -> Any:
    return row[key] if isinstance(row, dict) else row[index]


class ResultRepository:
    """Store and query completed local diagnostic measurements."""

    def __init__(
        self,
        database_path: str | Path = "network_doctor.sqlite3",
        database_url: str | None = None,
    ) -> None:
        detected_url = str(database_path) if str(database_path).startswith(
            ("postgresql://", "postgres://")
        ) else None
        self.database_url = database_url or detected_url
        if self.database_url is None:
            self.database_path = Path(database_path)
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.database_path = Path(":postgresql:")
        with self._connection() as connection:
            if self.database_url is None:
                connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS check_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp_utc TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    check_type TEXT NOT NULL,
                    success INTEGER,
                    duration_ms REAL NOT NULL,
                    status_code INTEGER,
                    error_code TEXT,
                    error_message TEXT,
                    addresses_json TEXT NOT NULL,
                    result_key TEXT,
                    agent_id TEXT
                )
                """
            )
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(check_results)")
            }
            if "result_key" not in columns:
                connection.execute("ALTER TABLE check_results ADD COLUMN result_key TEXT")
            if "agent_id" not in columns:
                connection.execute("ALTER TABLE check_results ADD COLUMN agent_id TEXT")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_check_results_result_key "
                "ON check_results (result_key) WHERE result_key IS NOT NULL"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    expected_status_codes_json TEXT NOT NULL DEFAULT '[200]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_counters (
                    target_url TEXT PRIMARY KEY,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    success_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    resolved_at TEXT,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    diagnosis_code TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            incident_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(incidents)")
            }
            if "acknowledged" not in incident_columns:
                connection.execute(
                    "ALTER TABLE incidents ADD COLUMN acknowledged INTEGER NOT NULL DEFAULT 0"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS notification_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    attempted_at TEXT NOT NULL,
                    delivery_status TEXT NOT NULL,
                    error_summary TEXT,
                    UNIQUE (incident_id, event_type, channel)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    location_type TEXT NOT NULL,
                    last_heartbeat_at TEXT,
                    agent_version TEXT,
                    status TEXT NOT NULL DEFAULT 'unknown'
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS result_outbox (
                    result_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL DEFAULT ''
                )
                """
            )
            outbox_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(result_outbox)")
            }
            if "created_at" not in outbox_columns:
                connection.execute(
                    "ALTER TABLE result_outbox ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS application_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_check_results_target_time "
                "ON check_results (target_url, timestamp_utc DESC)"
            )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_one_open_per_target "
                "ON incidents (target_url) WHERE status = 'open'"
            )

    @contextmanager
    def _connection(self) -> Generator[Any, None, None]:
        if self.database_url is None:
            connection: Any = sqlite3.connect(self.database_path, timeout=5.0)
        else:
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:
                raise RuntimeError(
                    "PostgreSQL DATABASE_URL requires psycopg[binary]."
                ) from exc
            connection = _PostgresConnection(
                psycopg.connect(self.database_url, row_factory=dict_row)
            )
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def save_report(self, target_url: str, results: Iterable[CheckResult]) -> int:
        """Persist all check outcomes from one target cycle in a single transaction."""
        timestamp = datetime.now(UTC).isoformat()
        rows = [
            (
                timestamp,
                target_url,
                result.check_type,
                None if result.success is None else int(result.success),
                result.duration_ms,
                result.status_code,
                result.error_code,
                result.error_message,
                json.dumps(result.addresses),
            )
            for result in results
        ]
        if not rows:
            return 0
        with self._connection() as connection:
            connection.executemany(
                """
                INSERT INTO check_results (
                    timestamp_utc, target_url, check_type, success, duration_ms,
                    status_code, error_code, error_message, addresses_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        return len(rows)

    def get_recent(
        self,
        limit: int = 100,
        target_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return recent measurements, optionally filtered to one target URL."""
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be a positive integer.")

        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            if target_url is None:
                rows = connection.execute(
                    "SELECT * FROM check_results ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM check_results WHERE target_url = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (target_url, limit),
                ).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["addresses"] = json.loads(item.pop("addresses_json"))
            if item["success"] is not None:
                item["success"] = bool(item["success"])
            results.append(item)
        return results

    def record_observation(self, target_url: str, success: bool) -> None:
        """Update consecutive result counters transactionally."""
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO incident_counters (target_url, failure_count, success_count)
                VALUES (?, ?, ?)
                ON CONFLICT(target_url) DO UPDATE SET
                    failure_count = CASE WHEN excluded.failure_count = 1
                        THEN incident_counters.failure_count + 1 ELSE 0 END,
                    success_count = CASE WHEN excluded.success_count = 1
                        THEN incident_counters.success_count + 1 ELSE 0 END
                """,
                (target_url, 0 if success else 1, 1 if success else 0),
            )

    def get_incident_state(self, target_url: str) -> dict[str, int]:
        """Return the consecutive counters for a target."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT failure_count, success_count FROM incident_counters WHERE target_url = ?",
                (target_url,),
            ).fetchone()
        if row is None:
            return {"failure_count": 0, "success_count": 0}
        return {
            "failure_count": _row_value(row, "failure_count", 0),
            "success_count": _row_value(row, "success_count", 1),
        }

    def open_incident(self, target_url: str, diagnosis: Any, severity: str = "warning") -> int:
        """Create one active incident for a target if none exists."""
        now = datetime.now(UTC).isoformat()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT id FROM incidents WHERE target_url = ? AND status = 'open'",
                (target_url,),
            ).fetchone()
            if row is not None:
                return int(_row_value(row, "id", 0))
            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    target_url, started_at, status, severity, diagnosis_code,
                    summary, evidence_json, confidence
                ) VALUES (?, ?, 'open', ?, ?, ?, ?, ?)
                ON CONFLICT (target_url) WHERE status = 'open' DO NOTHING
                RETURNING id
                """,
                (
                    target_url,
                    now,
                    severity,
                    diagnosis.code,
                    diagnosis.summary,
                    json.dumps(diagnosis.evidence),
                    diagnosis.confidence,
                ),
            )
            created = cursor.fetchone()
            if created is not None:
                return int(_row_value(created, "id", 0))
            existing = connection.execute(
                "SELECT id FROM incidents WHERE target_url = ? AND status = 'open'",
                (target_url,),
            ).fetchone()
            if existing is None:
                raise RuntimeError("The incident could not be created or retrieved.")
            return int(_row_value(existing, "id", 0))

    def resolve_incident(self, incident_id: int) -> bool:
        """Resolve an open incident once; return whether it transitioned."""
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE incidents SET status = 'resolved', resolved_at = ? "
                "WHERE id = ? AND status = 'open'",
                (datetime.now(UTC).isoformat(), incident_id),
            )
            return cursor.rowcount == 1

    def get_active_incident(self, target_url: str) -> dict[str, Any] | None:
        """Return the active incident for a target."""
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM incidents WHERE target_url = ? AND status = 'open' "
                "ORDER BY id DESC LIMIT 1",
                (target_url,),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        return item

    def list_incidents(self, limit: int = 100, active_only: bool = False) -> list[dict[str, Any]]:
        """Return incidents ordered newest first."""
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be a positive integer.")
        query = "SELECT * FROM incidents"
        if active_only:
            query += " WHERE status = 'open'"
        query += " ORDER BY id DESC LIMIT ?"
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(query, (limit,)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["evidence"] = json.loads(item.pop("evidence_json"))
            items.append(item)
        return items

    def acknowledge_incident(self, incident_id: int) -> bool:
        """Mark one incident acknowledged."""
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE incidents SET acknowledged = 1 WHERE id = ?",
                (incident_id,),
            )
            return cursor.rowcount == 1

    def claim_notification(self, incident_id: int, event_type: str, channel: str) -> bool:
        """Reserve one event/channel pair so retries cannot duplicate alerts."""
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO notification_log (
                    incident_id, event_type, channel, attempted_at, delivery_status
                ) VALUES (?, ?, ?, ?, 'pending')
                ON CONFLICT (incident_id, event_type, channel) DO NOTHING
                """,
                (incident_id, event_type, channel, datetime.now(UTC).isoformat()),
            )
            return cursor.rowcount == 1

    def finish_notification(
        self,
        incident_id: int,
        event_type: str,
        channel: str,
        success: bool,
        error_summary: str | None = None,
    ) -> None:
        """Record the final status of a delivery reservation."""
        with self._connection() as connection:
            connection.execute(
                """
                UPDATE notification_log
                SET attempted_at = ?, delivery_status = ?, error_summary = ?
                WHERE incident_id = ? AND event_type = ? AND channel = ?
                """,
                (
                    datetime.now(UTC).isoformat(),
                    "delivered" if success else "failed",
                    error_summary,
                    incident_id,
                    event_type,
                    channel,
                ),
            )

    def notification_status(self, incident_id: int) -> list[dict[str, Any]]:
        """Return delivery outcomes for an incident."""
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT * FROM notification_log WHERE incident_id = ? ORDER BY id",
                (incident_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def record_heartbeat(
        self,
        agent_id: str,
        name: str,
        location_type: str,
        version: str,
    ) -> int | None:
        """Create or refresh an agent heartbeat."""
        existing = next(
            (agent for agent in self.list_agents() if agent["id"] == agent_id),
            None,
        )
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO agents (id, name, location_type, last_heartbeat_at, agent_version, status)
                VALUES (?, ?, ?, ?, ?, 'online')
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    location_type = excluded.location_type,
                    last_heartbeat_at = excluded.last_heartbeat_at,
                    agent_version = excluded.agent_version,
                    status = 'online'
                """,
                (agent_id, name, location_type, datetime.now(UTC).isoformat(), version),
            )
            if existing is not None and existing["status"] == "stale":
                incident = connection.execute(
                    "SELECT id FROM incidents WHERE target_url = ? "
                    "AND diagnosis_code = 'local_agent_stale' AND status = 'open'",
                    (f"agent://{agent_id}",),
                ).fetchone()
                connection.execute(
                    "UPDATE incidents SET status = 'resolved', resolved_at = ? "
                    "WHERE target_url = ? AND diagnosis_code = 'local_agent_stale' "
                    "AND status = 'open'",
                    (datetime.now(UTC).isoformat(), f"agent://{agent_id}"),
                )
                return (
                    int(_row_value(incident, "id", 0))
                    if incident is not None
                    else None
                )
        return None

    def list_agents(self) -> list[dict[str, Any]]:
        """List agents, marking stale heartbeats offline."""
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute("SELECT * FROM agents ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def get_agent_location(self, agent_id: str) -> str | None:
        """Return the registered location assigned to one authenticated agent."""
        with self._connection() as connection:
            row = connection.execute(
                "SELECT location_type FROM agents WHERE id = ?",
                (agent_id,),
            ).fetchone()
        if row is None:
            return None
        return str(_row_value(row, "location_type", 0))

    def retention_cleanup(self, retention_days: int = 30) -> int:
        """Remove old raw measurements while preserving incidents and agent state."""
        if type(retention_days) is not int or retention_days < 1:
            raise ValueError("retention_days must be a positive integer.")
        from datetime import timedelta

        cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM check_results WHERE timestamp_utc < ?",
                (cutoff,),
            )
            return cursor.rowcount

    def upsert_target(
        self,
        name: str,
        url: str,
        expected_status_codes: list[int] | None = None,
        enabled: bool = True,
    ) -> int:
        """Create or update one explicitly authorized monitoring target."""
        from checks.url_validation import validate_url

        normalized_url = validate_url(url).url
        expected = expected_status_codes or [200, 201, 202, 204, 301, 302, 304]
        if not name.strip() or not expected or any(not 100 <= code <= 599 for code in expected):
            raise ValueError("Target name and valid expected HTTP status codes are required.")
        now = datetime.now(UTC).isoformat()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO targets (
                    name, url, enabled, expected_status_codes_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    name = excluded.name,
                    enabled = excluded.enabled,
                    expected_status_codes_json = excluded.expected_status_codes_json,
                    updated_at = excluded.updated_at
                """,
                (name.strip(), normalized_url, int(enabled), json.dumps(expected), now, now),
            )
            row = connection.execute(
                "SELECT id FROM targets WHERE url = ?",
                (normalized_url,),
            ).fetchone()
            return int(_row_value(row, "id", 0))

    def list_targets(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        """List configured targets with parsed status-code expectations."""
        query = "SELECT * FROM targets"
        if enabled_only:
            query += " WHERE enabled = 1"
        query += " ORDER BY id"
        with self._connection() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(query).fetchall()
        targets = []
        for row in rows:
            item = dict(row)
            item["enabled"] = bool(item["enabled"])
            item["expected_status_codes"] = json.loads(
                item.pop("expected_status_codes_json")
            )
            targets.append(item)
        return targets

    def get_target_by_url(self, url: str) -> dict[str, Any] | None:
        """Find a configured target by its normalized URL."""
        return next((item for item in self.list_targets() if item["url"] == url), None)

    def set_target_enabled(self, target_id: int, enabled: bool) -> bool:
        """Enable or disable a configured target."""
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE targets SET enabled = ?, updated_at = ? WHERE id = ?",
                (int(enabled), datetime.now(UTC).isoformat(), target_id),
            )
            return cursor.rowcount == 1

    def disable_all_targets(self) -> None:
        """Disable cached targets before applying an authoritative API target list."""
        with self._connection() as connection:
            connection.execute(
                "UPDATE targets SET enabled = 0, updated_at = ? WHERE enabled = 1",
                (datetime.now(UTC).isoformat(),),
            )

    def save_agent_results(
        self,
        agent_id: str,
        records: Iterable[dict[str, Any]],
    ) -> int:
        """Persist authenticated agent results idempotently."""
        now = datetime.now(UTC).isoformat()
        inserted = 0
        with self._connection() as connection:
            for record in records:
                cursor = connection.execute(
                    """
                    INSERT INTO check_results (
                        timestamp_utc, target_url, check_type, success, duration_ms,
                        status_code, error_code, error_message, addresses_json,
                        result_key, agent_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT DO NOTHING
                    """,
                    (
                        record.get("timestamp_utc", now),
                        record["target_url"],
                        record["check_type"],
                        None if record["success"] is None else int(record["success"]),
                        record["duration_ms"],
                        record.get("status_code"),
                        record.get("error_code"),
                        record.get("error_message"),
                        json.dumps(record.get("addresses", [])),
                        record["result_id"],
                        agent_id,
                    ),
                )
                inserted += cursor.rowcount
        return inserted

    def new_result_id(self) -> str:
        """Create a stable externally supplied result identifier."""
        return str(uuid.uuid4())

    def recent_target_status(self) -> list[dict[str, Any]]:
        """Join configured targets to each agent's most recent measurements."""
        targets = self.list_targets()
        for target in targets:
            target["observations"] = {}
            with self._connection() as connection:
                connection.row_factory = sqlite3.Row
                agents = connection.execute(
                    """
                    SELECT r.agent_id, r.timestamp_utc, r.check_type, r.success,
                           r.duration_ms, r.status_code, r.error_code
                    FROM check_results r
                    JOIN (
                        SELECT agent_id, check_type, MAX(id) AS max_id
                        FROM check_results WHERE target_url = ?
                        GROUP BY agent_id, check_type
                    ) latest ON latest.max_id = r.id
                    WHERE r.target_url = ?
                    """,
                    (target["url"], target["url"]),
                ).fetchall()
            for row in agents:
                observation = target["observations"].setdefault(
                    row["agent_id"] or "local",
                    {},
                )
                item = dict(row)
                if item["success"] is not None:
                    item["success"] = bool(item["success"])
                observation[item["check_type"]] = item
        return targets

    def latest_results_by_location(
        self,
        target_url: str,
    ) -> dict[str, tuple[CheckResult, ...]]:
        """Load the latest stored check of each type grouped by agent location."""
        query = """
            SELECT r.agent_id, a.location_type, r.check_type, r.success, r.duration_ms,
                   r.error_code, r.error_message, r.status_code, r.addresses_json
            FROM check_results r
            LEFT JOIN agents a ON a.id = r.agent_id
            JOIN (
                SELECT agent_id, check_type, MAX(id) AS latest_id
                FROM check_results
                WHERE target_url = ?
                GROUP BY agent_id, check_type
            ) latest ON latest.latest_id = r.id
            WHERE r.target_url = ?
        """
        with self._connection() as connection:
            rows = connection.execute(query, (target_url, target_url)).fetchall()

        grouped: dict[str, list[CheckResult]] = {}
        for row in rows:
            if isinstance(row, dict):
                location = row["location_type"] or "local"
                check_type = row["check_type"]
                success_value = row["success"]
                duration_ms = row["duration_ms"]
                error_code = row["error_code"]
                error_message = row["error_message"]
                status_code = row["status_code"]
                addresses_json = row["addresses_json"]
            else:
                location = row[1] or "local"
                check_type = row[2]
                success_value = row[3]
                duration_ms = row[4]
                error_code = row[5]
                error_message = row[6]
                status_code = row[7]
                addresses_json = row[8]
            grouped.setdefault(location, []).append(
                CheckResult(
                    check_type,
                    None if success_value is None else bool(success_value),
                    duration_ms,
                    error_code,
                    error_message,
                    status_code,
                    tuple(json.loads(addresses_json)),
                )
            )
        return {location: tuple(results) for location, results in grouped.items()}

    def mark_stale_agents(self, stale_after_seconds: int = 90) -> list[str]:
        """Set heartbeat status based on last contact and return stale agent IDs."""
        from datetime import timedelta

        cutoff = (datetime.now(UTC) - timedelta(seconds=stale_after_seconds)).isoformat()
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id FROM agents WHERE status != 'stale' AND "
                "(last_heartbeat_at IS NULL OR last_heartbeat_at < ?)",
                (cutoff,),
            ).fetchall()
            connection.execute(
                "UPDATE agents SET status = 'stale' "
                "WHERE last_heartbeat_at IS NULL OR last_heartbeat_at < ?",
                (cutoff,),
            )
            connection.execute(
                "UPDATE agents SET status = 'online' WHERE last_heartbeat_at >= ?",
                (cutoff,),
            )
        stale_ids = [str(_row_value(row, "id", 0)) for row in rows]
        from diagnosis.rules import Diagnosis

        for agent_id in stale_ids:
            self.open_incident(
                f"agent://{agent_id}",
                Diagnosis(
                    "local_agent_stale",
                    "The agent heartbeat is stale; the agent may be offline or its reporting path unavailable.",
                    "medium",
                    (f"No heartbeat received in {stale_after_seconds} seconds.",),
                ),
                severity="warning",
            )
        return stale_ids

    def enqueue_result(self, agent_id: str, record: dict[str, Any]) -> None:
        """Persist one idempotent pending API delivery for restart-safe retries."""
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO result_outbox (
                    result_id, agent_id, target_url, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (result_id) DO NOTHING
                """,
                (
                    record["result_id"],
                    agent_id,
                    record["target_url"],
                    json.dumps(record),
                    datetime.now(UTC).isoformat(),
                ),
            )

    def outbox_due(self, now: float, limit: int = 100) -> list[dict[str, Any]]:
        """Load due outbox records in enqueue order."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT result_id, agent_id, payload_json, attempt_count "
                "FROM result_outbox WHERE next_attempt_at <= ? "
                "ORDER BY created_at, result_id LIMIT ?",
                (now, limit),
            ).fetchall()
        return [
            {
                "result_id": _row_value(row, "result_id", 0),
                "agent_id": _row_value(row, "agent_id", 1),
                "payload": json.loads(_row_value(row, "payload_json", 2)),
                "attempt_count": _row_value(row, "attempt_count", 3),
            }
            for row in rows
        ]

    def remove_outbox(self, result_ids: Iterable[str]) -> None:
        """Remove results confirmed accepted by the API."""
        ids = tuple(result_ids)
        if not ids:
            return
        with self._connection() as connection:
            connection.executemany(
                "DELETE FROM result_outbox WHERE result_id = ?",
                ((result_id,) for result_id in ids),
            )

    def defer_outbox(
        self,
        result_ids: Iterable[str],
        next_attempt_at: float,
        error_code: str,
    ) -> None:
        """Record failure and schedule bounded exponential retry."""
        ids = tuple(result_ids)
        if not ids:
            return
        with self._connection() as connection:
            connection.executemany(
                "UPDATE result_outbox SET attempt_count = attempt_count + 1, "
                "next_attempt_at = ?, last_error = ? WHERE result_id = ?",
                ((next_attempt_at, error_code, result_id) for result_id in ids),
            )

    def discard_exhausted_outbox(self, maximum_attempts: int) -> int:
        """Discard pending API records after the configured bounded retry count."""
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM result_outbox WHERE attempt_count >= ?",
                (maximum_attempts,),
            )
            return cursor.rowcount

    def outbox_size(self) -> int:
        """Return number of pending cloud deliveries."""
        with self._connection() as connection:
            row = connection.execute("SELECT COUNT(*) FROM result_outbox").fetchone()
        return int(_row_value(row, "count", 0))

    def get_application_settings(self) -> dict[str, Any]:
        """Load centrally configurable monitoring defaults."""
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT setting_key, setting_value FROM application_settings"
            ).fetchall()
        return {
            _row_value(row, "setting_key", 0): json.loads(
                _row_value(row, "setting_value", 1)
            )
            for row in rows
        }

    def update_application_settings(self, values: dict[str, Any]) -> None:
        """Persist a validated settings update atomically."""
        now = datetime.now(UTC).isoformat()
        with self._connection() as connection:
            connection.executemany(
                """
                INSERT INTO application_settings (setting_key, setting_value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    updated_at = excluded.updated_at
                """,
                (
                    (key, json.dumps(value), now)
                    for key, value in values.items()
                ),
            )
