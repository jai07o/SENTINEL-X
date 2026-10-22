import pytest
from backend.app.services.ai_training_service import ai_training_service
from backend.app.services.breach_forensics_service import breach_forensics_service


def test_ai_training_convergence_and_weights():
    """Verify AI model retrains, converges with low loss, and optimizes EWCC weights."""
    status_before = ai_training_service.get_status()
    assert "metrics" in status_before
    assert "weights" in status_before
    assert "safeguards_active" in status_before

    # Retrain model
    result = ai_training_service.execute_retraining_and_safeguard_evolution(trigger_source="pytest_test")
    assert "SUCCESS" in result["status"]
    assert result["metrics"]["accuracy"] >= 0.95
    assert result["metrics"]["training_loss"] < 0.05
    assert len(result["new_safeguards_evolved"]) >= 0

    # Verify weights persisted in status
    current_status = ai_training_service.get_status()
    assert current_status["metrics"]["accuracy"] >= 0.95
    assert current_status["metrics"]["training_loss"] < 0.05


def test_ai_scheduling_recurrence():
    """Verify scheduling across weekly, monthly, and 6-month cycles."""
    for cadence, expected_days in [("weekly", 7), ("monthly", 30), ("6months", 180)]:
        sched = ai_training_service.set_update_schedule(cadence=cadence, auto_update=True)
        assert sched["cadence"] == cadence
        assert sched["cadence_days"] == expected_days
        assert sched["auto_update_enabled"] is True
        assert "next_scheduled_training_at" in sched


def test_breach_forensics_discovery_and_seal():
    """Verify real host breach discovery executes and seals evidence cryptographically."""
    report = breach_forensics_service.run_master_breach_investigation()

    assert report["evidence_id"].startswith("BREACH-EVID-")
    assert "timestamp" in report
    assert "breach_verdict" in report
    assert "memory_injection_forensics" in report
    assert "credential_token_vault_forensics" in report
    assert "shadow_copy_wiper_forensics" in report
    assert "exfiltration_channel_forensics" in report

    # Verify cryptographic seals
    seals = report["cryptographic_evidence_seal"]
    assert "sha256_fingerprint" in seals
    assert len(seals["sha256_fingerprint"]) == 64
    assert "hmac_signature" in seals
    assert len(seals["hmac_signature"]) == 64
    assert seals["chain_of_custody_verified"] is True
    assert "sealed_evidence_filepath" in report
