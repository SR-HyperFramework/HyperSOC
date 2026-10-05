#!/usr/bin/env python3
"""Read-only Wazuh inventory, process snapshots and SCA export into the Hub."""
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

CONFIG = Path(os.environ.get('HUB_COLLECTOR_CONFIG', '/config/collector.json'))

def internal_open(req, *, context=None):
    # Both endpoints are internal Docker services. Host proxy environment must
    # not route authentication or evidence outside the lab network.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    return opener.open(req, timeout=20)

def request(url, *, payload=None, headers=None, context=None):
    body = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode() if payload is not None else None
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', **(headers or {})})
    with internal_open(req, context=context) as response:
        return json.load(response)

def observed(value):
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    if isinstance(value, str) and value:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00').replace('+0000', '+00:00'))
        if stamp.tzinfo is None: stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp.isoformat()
    raise ValueError('Missing source observation timestamp')

def scan_time(row):
    return observed((row.get('scan') or {}).get('time') or row.get('scan_time'))

def process_event(agent, row):
    stamp = scan_time(row)
    process = {k: v for k, v in {'name': row.get('name'), 'pid': row.get('pid'),
        'parent_pid': row.get('ppid'), 'command_line': row.get('cmd'),
        'guid': f"{agent['id']}:{row.get('pid')}:{row.get('start_time')}" if row.get('start_time') else None}.items() if v is not None}
    native = {'timestamp': stamp, 'agent': {k: agent[k] for k in ('id', 'name', 'ip') if k in agent},
        'data': {'process': process, 'user': row.get('euser'), 'syscollector_scan': row.get('scan')}}
    native['id'] = 'syscollector:' + hashlib.sha256(json.dumps(native, sort_keys=True).encode()).hexdigest()
    return native

def cycle(config):
    tls = ssl.create_default_context(cafile=config['ca_file'])
    # Trust the exact certificate exported from this manager; its default CN may
    # differ from its Docker service name. CA validation remains enabled.
    tls.check_hostname = False
    basic = base64.b64encode((config['wazuh_username'] + ':' + config['wazuh_password']).encode()).decode()
    auth = urllib.request.Request(config['wazuh_url'] + '/security/user/authenticate', method='POST', headers={'Authorization': 'Basic ' + basic})
    with internal_open(auth, context=tls) as response:
        wazuh_token = json.load(response)['data']['token']
    wazuh_headers = {'Authorization': 'Bearer ' + wazuh_token}
    def items(path):
        return request(config['wazuh_url'] + path, headers=wazuh_headers, context=tls)['data']['affected_items']
    soc_login = request(config['soc_url'] + '/api/v1/auth/login', payload={'username': config['soc_username'], 'password': config['soc_password']})
    soc_headers = {'Authorization': 'Bearer ' + soc_login['access_token']}
    agents = items('/agents?limit=200')
    now = datetime.now(timezone.utc).isoformat()
    entities = [{'kind': 'asset', 'external_key': a['name'], 'label': a['name'], 'source': 'wazuh-api', 'observed_at': now,
        'attributes': {'wazuh_agent_id': a['id'], 'status': a['status'], 'ip': a.get('ip'), 'os': a.get('os'),
            'last_keep_alive': a.get('lastKeepAlive'), 'inventory': True}} for a in agents if a.get('name')]
    if entities:
        request(config['soc_url'] + '/api/v1/hub/inventory', payload={'entities': entities, 'relationships': []}, headers=soc_headers)
    counts = {'assets': len(entities), 'behavior': 0, 'posture': 0, 'skipped': 0}
    def ingest(event):
        body = json.dumps({'format': 'wazuh', 'source': 'wazuh', 'event': event}, separators=(',', ':'), ensure_ascii=False).encode()
        timestamp = str(time.time())
        signature = hmac.new(config['ingest_secret'].encode(), timestamp.encode() + b'.' + body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(config['soc_url'] + '/api/v1/hub/native-events', data=body,
            headers={'Content-Type': 'application/json', 'X-SOC-Timestamp': timestamp, 'X-SOC-Signature': signature})
        with internal_open(req) as response: response.read()
    for agent in agents:
        if agent.get('status') != 'active': continue
        try:
            for row in items('/syscollector/' + agent['id'] + '/processes?limit=100'):
                try:
                    ingest(process_event(agent, row)); counts['behavior'] += 1
                except (ValueError, urllib.error.HTTPError): counts['skipped'] += 1
            for policy in items('/sca/' + agent['id'] + '?limit=100'):
                try:
                    stamp = observed(policy.get('end_scan'))
                    event = {'timestamp': stamp, 'agent': {k: agent[k] for k in ('id', 'name', 'ip') if k in agent}, 'data': {'sca': policy}}
                    event['id'] = 'sca:' + hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()
                    ingest(event); counts['posture'] += 1
                except (ValueError, urllib.error.HTTPError): counts['skipped'] += 1
        except urllib.error.HTTPError as exc:
            counts['skipped'] += 1
            print('Wazuh read endpoint unavailable, HTTP', exc.code, flush=True)
    print(json.dumps({'observed_at': now, **counts, 'agent_limit': 200, 'process_limit_per_agent': 100}), flush=True)
    return counts

if __name__ == '__main__':
    config = json.loads(CONFIG.read_text())
    while True:
        try: cycle(config)
        except urllib.error.HTTPError as exc:
            print('Collector HTTP failed:', exc.code, 'endpoint=', urllib.parse.urlsplit(exc.url).path, flush=True)
        except urllib.error.URLError as exc:
            reason = exc.reason
            print('Collector transport failed:', type(reason).__name__,
                  'errno=', getattr(reason, 'errno', None), 'certificate_code=', getattr(reason, 'verify_code', None), flush=True)
        except Exception as exc: print('Collector cycle failed:', type(exc).__name__, flush=True)
        if os.environ.get('HUB_COLLECTOR_ONCE') == '1': break
        time.sleep(300)
