from datetime import datetime, timedelta
from backend.app.engine.rules_engine import DetectionRulesEngine


def test_rules_loading():
    engine = DetectionRulesEngine()
    assert len(engine.rules) >= 4
    rule_ids = [r["rule_id"] for r in engine.rules]
    assert "SX-R-AUTH-001" in rule_ids
    assert "SX-R-PRIV-001" in rule_ids
    assert "SX-R-FIM-001" in rule_ids


def test_ssh_brute_force_correlation_threshold():
    engine = DetectionRulesEngine()
    host_id = "test-host-ubuntu"
    now = datetime.utcnow()

    # SSH brute-force threshold is 5 failures within 60s
    triggered = []
    for i in range(5):
        ev = {
            "event_id": f"evt_ssh_test_{i}",
            "timestamp": now + timedelta(seconds=i * 2),
            "event_category": "AUTH_FAILURE",
            "process_name": "sshd",
            "account_user": "root",
            "raw_payload": "{}",
        }
        res = engine.process_event(host_id, ev)
        if res:
            triggered.extend(res)

    assert len(triggered) >= 1
    inc = triggered[0]
    assert inc["rule_id"] == "SX-R-AUTH-001"
    assert inc["severity"] == "HIGH"
    assert len(inc["event_ids"]) >= 5


def test_privilege_escalation_single_trigger():
    engine = DetectionRulesEngine()
    host_id = "test-host-fedora"
    now = datetime.utcnow()

    # Sudo privilege escalation threshold is 1
    ev = {
        "event_id": "evt_priv_test_01",
        "timestamp": now,
        "event_category": "PRIVILEGE_ESCALATION",
        "account_uid": 0,
        "process_name": "sudo",
        "account_user": "developer",
        "raw_payload": "{}",
    }
    res = engine.process_event(host_id, ev)
    assert len(res) == 1
    assert res[0]["rule_id"] == "SX-R-PRIV-001"
