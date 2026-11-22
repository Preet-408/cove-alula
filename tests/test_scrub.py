"""The diagnostics scrubber must never keep names, PINs or codes, at any depth."""

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "scrub", Path(__file__).parents[1] / "custom_components/cove_alula/scrub.py"
)
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)


def test_drops_sensitive_keys_at_any_depth():
    out = sc.scrub({"pin": "1234", "zoneType": 7, "metadata": {"zoneName": "BACK DOOR", "x": 1}})
    assert out == {"zoneType": 7, "metadata": {"x": 1}}


def test_drops_records_that_name_a_sensitive_field():
    data = {"fields": [{"name": "pin", "value": "1234"}, {"name": "profile", "value": 9}]}
    assert sc.scrub(data) == {"fields": [{"value": 9}]}
    nested = [[{"field": "userCode", "value": "9999"}], {"key": "zoneType", "value": 3}]
    assert sc.scrub(nested) == [[], {"key": "zoneType", "value": 3}]


def test_scalars_and_truncation():
    assert sc.scrub(42) == 42
    assert sc.scrub(None) is None
    assert sc.scrub("x" * 100) == "x" * 40
    assert "1234" not in repr(sc.scrub({"a": [{"name": "Pin code", "value": "1234"}]}))
