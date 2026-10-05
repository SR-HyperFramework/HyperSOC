import importlib.util
from pathlib import Path

import pytest

path = Path(__file__).parents[2] / 'integrations/wazuh/hub-collector.py'
if not path.exists():
    path = Path('/integrations/wazuh/hub-collector.py')
spec = importlib.util.spec_from_file_location('hub_collector', path)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def test_process_export_retains_scan_time_and_is_idempotent():
    agent = {'id': '003', 'name': 'lab-endpoint', 'ip': '192.0.2.3'}
    row = {'scan': {'time': '2026-10-05T12:00:00Z'}, 'pid': 101, 'ppid': 1,
           'name': '/usr/bin/backup', 'cmd': 'backup', 'euser': 'root', 'start_time': 123}
    event = collector.process_event(agent, row)
    assert event == collector.process_event(agent, row)
    assert event['timestamp'] == '2026-10-05T12:00:00+00:00'
    assert event['data']['process']['guid'] == '003:101:123'
    assert event['data']['user'] == 'root'
    assert 'rule' not in event  # inventory snapshots do not invent detections


def test_missing_source_scan_time_is_rejected_instead_of_fabricating_freshness():
    with pytest.raises(ValueError):
        collector.process_event({'id': '003', 'name': 'lab-endpoint'}, {'pid': 101})
