from datetime import datetime, timedelta
from backend.app.engine.ewcc_engine import EWCCEngine


def test_source_reliability_calculation():
    ewcc = EWCCEngine()
    audit_events = [{"source": "auditd"}, {"source": "fim"}]
    log_events = [{"source": "auth_log"}, {"source": "proc_watcher"}]

    audit_score = ewcc.calculate_source_reliability(audit_events)
    log_score = ewcc.calculate_source_reliability(log_events)

    assert audit_score == 0.95
    assert log_score == 0.80
    assert audit_score > log_score


def test_identity_consistency_flagging():
    ewcc = EWCCEngine()
    # Normal user root uid 0
    normal = [{"account_user": "root", "account_uid": 0}]
    assert ewcc.calculate_identity_consistency(normal, "ubuntu") == 1.0

    # Masquerading: non-root user name with UID 0
    anomalous = [{"account_user": "guest", "account_uid": 0}]
    score = ewcc.calculate_identity_consistency(anomalous, "ubuntu")
    assert score < 1.0


def test_evidence_completeness_scoring():
    ewcc = EWCCEngine()
    # Sparse event (only event_id)
    sparse = [{"event_id": "1"}]
    # Complete event
    complete = [{
        "event_id": "1",
        "evidence_hash": "a1b2c3",
        "account_user": "admin",
        "process_name": "bash",
        "file_path": "/etc/passwd",
    }]

    assert ewcc.calculate_evidence_completeness(sparse) == 0.0
    assert ewcc.calculate_evidence_completeness(complete) == 1.0


def test_temporal_clustering_decay():
    ewcc = EWCCEngine()
    now = datetime.utcnow()
    
    # Tight cluster (5 events in 2 seconds)
    tight = [{"timestamp": now + timedelta(seconds=i*0.5)} for i in range(5)]
    # Spread out cluster (5 events across 58 seconds of a 60s window)
    spread = [{"timestamp": now + timedelta(seconds=i*14)} for i in range(5)]

    score_tight = ewcc.calculate_temporal_clustering(tight, window_seconds=60)
    score_spread = ewcc.calculate_temporal_clustering(spread, window_seconds=60)

    assert score_tight > score_spread
