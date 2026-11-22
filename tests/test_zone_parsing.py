"""zoneConfiguration type strings must survive zoneStatus's numeric deviceType, in any order.

Loads covealula.py as part of a stub package so the integration's __init__ (which needs
Home Assistant) is not executed. Skipped if aiohttp isn't installed.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip("aiohttp")

_DIR = Path(__file__).parents[1] / "custom_components/cove_alula"
_pkg = types.ModuleType("cove_alula_stub")
_pkg.__path__ = [str(_DIR)]
sys.modules.setdefault("cove_alula_stub", _pkg)
_spec = importlib.util.spec_from_file_location("cove_alula_stub.covealula", _DIR / "covealula.py")
cv = importlib.util.module_from_spec(_spec)
sys.modules["cove_alula_stub.covealula"] = cv
_spec.loader.exec_module(cv)

CONFIG = {"name": "zoneConfiguration", "value": [
    {"index": 3, "value": {"deviceType": "PIR", "alarmType": "Intrusion", "zoneSourceEnum": "daughter board"}},
    {"index": 30, "value": {"deviceType": "DWS", "alarmType": "No Alarm", "zoneSourceEnum": "disabled"}},
]}
STATUS = {"name": "zoneStatus", "value": [
    {"index": 3, "value": {"open": False, "deviceType": 0}},
    {"index": 30, "value": {"open": False, "deviceType": 0}},
]}


def _parse(entries):
    client = cv.CoveAlulaClient.__new__(cv.CoveAlulaClient)
    client.raw_zone_config = {}
    attrs, zones = {}, {}
    for e in entries:
        client._extract_mfd_entry(e, attrs, zones)
    return zones


@pytest.mark.parametrize("order", [(CONFIG, STATUS), (STATUS, CONFIG)])
def test_type_strings_survive_status_in_either_order(order):
    zones = _parse(order)
    assert zones[3]["device_type"] == "PIR"
    assert zones[3]["alarm_type"] == "Intrusion"
    assert zones[30]["zone_source"] == "disabled"
    z = cv.Zone(index=3)
    z.apply(zones[3])
    assert z.device_type == "PIR"


def test_disabled_slot_is_not_a_configured_zone():
    ps = cv.PanelState.__new__(cv.PanelState)
    ps.highest_zone_index = 30
    ps.zones = {3: cv.Zone(index=3, zone_source="daughter board"), 30: cv.Zone(index=30, zone_source="disabled")}
    assert [z.index for z in ps._configured_zones()] == [3]
