import json
from datetime import UTC, datetime

from app.services.access.lifecycle import _json_safe


def test_state_snapshots_are_json_serialisable():
    naive = datetime(2026, 11, 20, 9, 30)
    out = _json_safe({"created": naive, "nested": [{"at": datetime(2026, 1, 1, tzinfo=UTC)}], "enabled": True, "n": None})
    json.dumps(out)  # must not raise
    assert out["created"] == "2026-11-20T09:30:00+00:00"
    assert out["nested"][0]["at"] == "2026-01-01T00:00:00+00:00"
    assert out["enabled"] is True and out["n"] is None
    assert _json_safe(None) is None
