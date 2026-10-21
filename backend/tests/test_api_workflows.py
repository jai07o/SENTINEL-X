import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_check_endpoint(client: AsyncClient):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"
    assert data["database_connected"] is True


@pytest.mark.asyncio
async def test_auth_login_workflow(client: AsyncClient):
    # Login with seeded test admin
    res = await client.post(
        "/api/v1/auth/login",
        data={"username": "test_admin", "password": "AdminPass123!"},
    )
    assert res.status_code == 200
    token_data = res.json()
    assert "access_token" == token_data["token_type"].lower() or "bearer" in token_data["token_type"].lower()
    assert token_data["user"]["username"] == "test_admin"


@pytest.mark.asyncio
async def test_end_to_end_event_to_incident_workflow(
    client: AsyncClient, admin_token: str
):
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Register Host
    host_payload = {
        "hostname": "ubuntu-target-01",
        "ip_address": "192.168.10.50",
        "os_distro": "ubuntu",
        "os_version": "24.04",
        "architecture": "x86_64",
    }
    h_res = await client.post("/api/v1/hosts/register", json=host_payload, headers=headers)
    assert h_res.status_code == 200
    host_data = h_res.json()
    assert host_data["hostname"] == "ubuntu-target-01"

    # 2. Ingest 5 SSH auth failure events to trigger SX-R-AUTH-001 (Threshold: 5 in 60s)
    events_payload = []
    for i in range(5):
        events_payload.append({
            "event_id": f"test_wf_ssh_{i}",
            "hostname": "ubuntu-target-01",
            "source": "auth_log",
            "event_category": "AUTH_FAILURE",
            "severity": "LOW",
            "account_user": "root",
            "process_name": "sshd",
            "src_ip": "203.0.113.10",
            "raw_payload": {"attempt": i + 1, "service": "sshd"},
        })

    ingest_res = await client.post("/api/v1/events/ingest", json=events_payload, headers=headers)
    assert ingest_res.status_code == 200
    ingest_data = ingest_res.json()
    assert ingest_data["ingested"] == 5
    assert ingest_data["incidents_created"] >= 1

    # 3. Retrieve Incidents List
    inc_res = await client.get("/api/v1/incidents/", headers=headers)
    assert inc_res.status_code == 200
    inc_list = inc_res.json()["items"]
    assert len(inc_list) >= 1
    target_inc = inc_list[0]
    incident_id = target_inc["id"]

    # 4. Request Response Action
    action_res = await client.post(
        f"/api/v1/incidents/{incident_id}/actions",
        json={"action_type": "ISOLATE_HOST", "parameters": {"reason": "Brute force detected"}},
        headers=headers,
    )
    assert action_res.status_code == 200
    action_data = action_res.json()
    assert action_data["status"] == "PENDING_APPROVAL"
    action_id = action_data["id"]

    # 5. Approve Response Action
    approve_res = await client.post(
        f"/api/v1/incidents/{incident_id}/actions/{action_id}/approve",
        headers=headers,
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "EXECUTED"

    # 6. Request AI-Assisted Explanation
    ai_res = await client.post(
        "/api/v1/ai/explain-incident",
        json={"incident_id": incident_id, "target_audience": "security_analyst"},
        headers=headers,
    )
    assert ai_res.status_code == 200
    ai_data = ai_res.json()
    assert len(ai_data["cited_event_ids"]) >= 1
    assert len(ai_data["safe_investigative_steps"]) >= 1

    # 7. Export Incident Dossier Report
    export_res = await client.get(
        f"/api/v1/incidents/{incident_id}/export",
        headers=headers,
    )
    assert export_res.status_code == 200
    report_data = export_res.json()
    assert "content_markdown" in report_data
    assert "SENTINEL-X SECURITY INCIDENT DOSSIER" in report_data["content_markdown"]
