import importlib

from fastapi.testclient import TestClient


def test_authenticated_api_authorization_idempotency_and_payload_validation(
    tmp_path,
    monkeypatch,
) -> None:
    token = "test-only-network-doctor-token-with-32-chars"
    agent_token = "test-agent-only-token-with-at-least-32-chars"
    monkeypatch.setenv("API_TOKEN", token)
    monkeypatch.setenv("AGENT_TOKENS", f'{{"test-agent":"{agent_token}"}}')
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "api.sqlite3"))
    monkeypatch.setenv("API_RATE_LIMIT_PER_MINUTE", "1000")
    from backend import main

    app_module = importlib.reload(main)
    with TestClient(app_module.app, base_url="https://testserver") as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/v1/targets").status_code == 401
        headers = {"Authorization": f"Bearer {token}"}
        agent_headers = {"Authorization": f"Bearer {agent_token}"}

        created = client.post(
            "/api/v1/targets",
            headers=headers,
            json={"name": "Example", "url": "https://example.com/"},
        )
        assert created.status_code == 201
        target = created.json()
        assert target["url"] == "https://example.com/"
        updated_settings = client.patch(
            "/api/v1/settings",
            headers=headers,
            json={"interval_seconds": 15, "failures_to_open_incident": 4},
        )
        assert updated_settings.status_code == 200
        assert updated_settings.json()["interval_seconds"] == 15
        assert updated_settings.json()["failures_to_open_incident"] == 4
        invalid_settings = client.patch(
            "/api/v1/settings",
            headers=headers,
            json={"interval_seconds": 0},
        )
        assert invalid_settings.status_code == 422

        heartbeat = client.post(
            "/api/v1/agents/heartbeat",
            headers=agent_headers,
            json={
                "agent_id": "test-agent",
                "name": "Test",
                "location_type": "local",
                "agent_version": "1.0.0",
            },
        )
        assert heartbeat.status_code == 200

        unauthorized_result = {
            "result_id": "result-unauthorized",
            "target_url": "https://not-authorized.example/",
            "check_type": "https",
            "success": True,
            "duration_ms": 10,
            "status_code": 200,
        }
        denied = client.post(
            "/api/v1/results/batch",
            headers=agent_headers,
            json={"agent_id": "test-agent", "results": [unauthorized_result]},
        )
        assert denied.status_code == 403

        result = {
            **unauthorized_result,
            "result_id": "stable-result-key",
            "target_url": target["url"],
        }
        payload = {"agent_id": "test-agent", "results": [result]}
        accepted = client.post("/api/v1/results/batch", headers=agent_headers, json=payload)
        duplicate = client.post("/api/v1/results/batch", headers=agent_headers, json=payload)
        assert accepted.status_code == duplicate.status_code == 200
        assert accepted.json() == {"accepted": 1, "inserted": 1}
        assert duplicate.json() == {"accepted": 1, "inserted": 0}
        assert len(client.get("/api/v1/history", headers=headers).json()) == 1

        assert client.get("/api/v1/agents", headers=headers).json()[0]["status"] == "online"

        incident_id = app_module.repository.open_incident(
            target["url"],
            type(
                "Diagnosis",
                (),
                {
                    "code": "test",
                    "summary": "Evidence-based test incident",
                    "evidence": ("simulated",),
                    "confidence": "low",
                },
            )(),
        )
        assert client.post(
            f"/api/v1/incidents/{incident_id}/acknowledge",
            headers=headers,
        ).json() == {"acknowledged": True}

        malformed = client.post(
            "/api/v1/results/batch",
            headers=agent_headers,
            json={"agent_id": "test-agent", "results": [{"unexpected": "field"}]},
        )
        assert malformed.status_code == 422
