from datetime import datetime, timedelta
from backend.app.engine.normalization import EventNormalizer
from backend.app.schemas.event import RawEventIngest


def test_timestamp_parsing():
    normalizer = EventNormalizer()
    # ISO string
    iso_str = "2026-10-21T14:30:00Z"
    dt = normalizer.parse_timestamp(iso_str)
    assert dt.year == 2026
    assert dt.month == 10
    assert dt.day == 21

    # Unix epoch
    epoch = 1792679400.0
    dt_epoch = normalizer.parse_timestamp(epoch)
    assert isinstance(dt_epoch, datetime)


def test_category_normalization():
    normalizer = EventNormalizer()
    raw = RawEventIngest(
        hostname="srv01",
        source="auth_log",
        event_category="auth_failure",
        raw_payload={"test": "val"},
    )
    norm, is_dup = normalizer.normalize(raw)
    assert norm["event_category"] == "AUTH_FAILURE"
    assert is_dup is False
    assert norm["evidence_hash"] is not None


def test_duplicate_suppression():
    normalizer = EventNormalizer(dedup_window_seconds=10)
    raw1 = RawEventIngest(
        hostname="srv01",
        source="auth_log",
        event_category="AUTH_FAILURE",
        raw_payload={"attempt": 1, "user": "root"},
    )
    raw2 = RawEventIngest(
        hostname="srv01",
        source="auth_log",
        event_category="AUTH_FAILURE",
        raw_payload={"attempt": 1, "user": "root"},
    )

    norm1, is_dup1 = normalizer.normalize(raw1)
    norm2, is_dup2 = normalizer.normalize(raw2)

    assert is_dup1 is False
    assert is_dup2 is True  # Second identical event suppressed within window!
