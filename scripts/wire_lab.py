"""Wire this checkout to the existing Wazuh Docker lab; never print secrets."""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
STATE = Path.home() / '.config' / 'hypersoc-lab'
MANAGER = 'single-node-wazuh.manager-1'

def command(args, *, capture=True, input=None):
    result = subprocess.run(args, input=input, text=True, capture_output=capture)
    if result.returncode:
        raise RuntimeError(f'Command failed: {args[0]} (exit {result.returncode})')
    return result.stdout if capture else None

def manager_info():
    return json.loads(command(['docker', 'inspect', MANAGER]))[0]

def container_read(path):
    return command(['docker', 'exec', '-u', 'root', MANAGER, 'cat', path])

def inspect():
    data = manager_info()
    config = container_read('/var/ossec/etc/ossec.conf')
    tree = ET.fromstring('<root>' + config + '</root>')
    print(json.dumps({'shared_root': str(ROOT), 'wazuh_networks': list(data['NetworkSettings']['Networks']),
        'configuration_mounts': [(m['Source'], m['Destination']) for m in data['Mounts'] if m['Type'] == 'bind' and ('ossec.conf' in m['Destination'] or 'integration' in m['Destination'])],
        'integration_blocks': [{'name': n.findtext('name'), 'hook_url': n.findtext('hook_url'), 'key_present': bool(n.findtext('api_key')), 'level': n.findtext('level')} for n in tree.findall('.//integration')],
        'manager_env_names': [v.split('=', 1)[0] for v in data['Config']['Env']],
        'existing_env_present': (ROOT / '.env').exists()}, indent=2))
    for mount in data['Mounts']:
        if mount['Destination'].startswith('/entrypoint-scripts/'):
            script = Path(mount['Source']).read_text()
            print('Startup integration script (secret-bearing lines omitted):')
            for line in script.splitlines():
                if any(word in line.lower() for word in ('key', 'secret', 'password', 'token')):
                    print('[secret-bearing line omitted]')
                else:
                    print(line)

def provision():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    envfile = STATE / 'lab.env'
    if not envfile.exists():
        secret = secrets.token_hex(32)
        password = secrets.token_hex(24)
        values = {'APP_SECRET_KEY': secret, 'POSTGRES_USER': 'soc', 'POSTGRES_PASSWORD': password,
            'POSTGRES_DB': 'soc', 'DATABASE_URL': f'postgresql+asyncpg://soc:{password}@postgres:5432/soc',
            'ENV_FILE': str(envfile), 'BACKEND_BIND_HOST': '127.0.0.1', 'BACKEND_PORT': '8000',
            'AUTH_ENABLED': 'true', 'AUTOMATION_ENABLED': 'true', 'BEHAVIOR_AUTO_TRAIN': 'true',
            'CORS_ALLOWED_ORIGINS': 'http://localhost:8000,http://127.0.0.1:8021,http://localhost:8021',
            'AI_TRIAGE_PROVIDER_MODE': 'offline', 'INVESTIGATOR_PROVIDER_MODE': 'offline',
            'ALERT_UNDERSTANDING_PROVIDER_MODE': 'offline', 'THREAT_INTEL_PROVIDER_MODE': 'offline',
            'THREAT_INTEL_ENABLE_EXTERNAL_PROVIDERS': 'false', 'WAZUH_ACTIVE_RESPONSE_PROVIDER_MODE': 'offline',
            'HUB_SOURCE_KEYS': json.dumps({'wazuh': secret}, separators=(',', ':')),
            'RESPONSE_EVIDENCE_SOURCES': 'wazuh', 'SECURITY_RATE_LIMIT_PER_MINUTE': '600'}
        envfile.write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
        os.chmod(envfile, 0o600)
    network = next(iter(manager_info()['NetworkSettings']['Networks']))
    override = {'services': {
        'backend': {'mem_limit': '384m', 'restart': 'unless-stopped', 'networks': {'default': {}, 'wazuh_ingest': {'aliases': ['hypersoc-backend']}}},
        'worker': {'mem_limit': '384m'},
        'postgres': {'mem_limit': '256m', 'restart': 'unless-stopped', 'command': ['postgres', '-c', 'shared_buffers=32MB', '-c', 'max_connections=40']},
        'redis': {'profiles': ['reserved']}},
        'networks': {'wazuh_ingest': {'external': True, 'name': network}}}
    (STATE / 'compose.json').write_text(json.dumps(override, indent=2))
    print('Private lab configuration created; provider modes offline; Wazuh network:', network)

def compose(arguments):
    return command(['docker', 'compose', '-p', 'hypersoc-lab', '--env-file', str(STATE / 'lab.env'),
        '-f', str(ROOT / 'docker-compose.yml'), '-f', str(STATE / 'compose.json'), *arguments], capture=False)

def start():
    override = json.loads((STATE / 'compose.json').read_text())
    for service in ('migrate', 'backend', 'worker'):
        override['services'].setdefault(service, {})['image'] = 'hypersoc-lab-migrate:latest'
    (STATE / 'compose.json').write_text(json.dumps(override, indent=2))
    compose(['build', 'migrate'])
    compose(['up', '-d', '--no-build', '--wait', '--wait-timeout', '180', 'backend', 'worker'])

def values():
    return dict(line.split('=', 1) for line in (STATE / 'lab.env').read_text().splitlines() if '=' in line)

def manager_write(path, data, mode=0o640):
    script = 'import json,sys,base64,os; d=json.load(sys.stdin); p=d["path"]; open(p,"wb").write(base64.b64decode(d["data"])); os.chmod(p,d["mode"])'
    command(['docker', 'exec', '-i', '-u', 'root', MANAGER, 'python3', '-c', script],
        input=json.dumps({'path': path, 'data': base64.b64encode(data).decode(), 'mode': mode}))

def wire():
    data = manager_info()
    source = Path(next(m['Source'] for m in data['Mounts'] if m['Destination'] == '/wazuh-config-mount/etc/ossec.conf'))
    startup = Path(next(m['Source'] for m in data['Mounts'] if m['Destination'].startswith('/entrypoint-scripts/')))
    secret = values()['APP_SECRET_KEY']
    import re
    def update(text):
        matches = [m for m in re.finditer(r'<integration>.*?</integration>', text, flags=re.S)
            if ET.fromstring(m.group()).findtext('name') == 'custom-ai-soc']
        if len(matches) != 1:
            raise RuntimeError('Expected exactly one existing custom-ai-soc integration; refusing ambiguous edits')
        match = matches[0]
        node = ET.fromstring(match.group())
        for key, value in {'hook_url': 'http://hypersoc-backend:8000/api/v1/hub/native-events', 'api_key': secret, 'alert_format': 'json'}.items():
            field = node.find(key)
            if field is None: field = ET.SubElement(node, key)
            field.text = value
        result = text[:match.start()] + ET.tostring(node, encoding='unicode') + text[match.end():]
        if '/var/ossec/logs/hypersoc-wiring.log' not in result:
            collector = '\n  <localfile><log_format>syslog</log_format><location>/var/ossec/logs/hypersoc-wiring.log</location></localfile>\n'
            result = result.replace('</ossec_config>', collector + '</ossec_config>', 1)
        return result
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    for name, content in [('source-ossec', source.read_bytes()), ('runtime-ossec', container_read('/var/ossec/etc/ossec.conf').encode()), ('startup', startup.read_bytes()), ('adapter', container_read('/var/ossec/integrations/custom-ai-soc').encode())]:
        backup = STATE / (name + '-' + stamp + '.bak')
        backup.write_bytes(content)
        os.chmod(backup, 0o600)
    source.write_text(update(source.read_text()))
    manager_write('/var/ossec/etc/ossec.conf', update(container_read('/var/ossec/etc/ossec.conf')).encode(), 0o660)
    adapter = (ROOT / 'integrations/wazuh/custom-ai-soc.py').read_bytes().replace(b'\r\n', b'\n')
    manager_write('/var/ossec/integrations/custom-ai-soc', adapter, 0o750)
    probe_rule = b'<group name="hypersoc_lab,"><rule id="110901" level="5"><program_name>^hypersoc-lab$</program_name><match>HyperSOC wiring probe</match><description>HyperSOC controlled wiring probe (not an attack)</description></rule></group>\n'
    existing_rules = command(['docker', 'exec', '-u', 'root', MANAGER, 'sh', '-c', 'grep -rl \'id="110901"\' /var/ossec/etc/rules || true']).splitlines()
    if any(path != '/var/ossec/etc/rules/hypersoc_lab_rules.xml' for path in existing_rules):
        raise RuntimeError('Probe rule ID conflicts with existing rules')
    manager_write('/var/ossec/etc/rules/hypersoc_lab_rules.xml', probe_rule, 0o640)
    command(['docker', 'exec', '-u', 'root', MANAGER, 'touch', '/var/ossec/logs/hypersoc-wiring.log'])
    command(['docker', 'exec', '-u', 'root', MANAGER, 'chown', 'root:wazuh', '/var/ossec/integrations/custom-ai-soc', '/var/ossec/etc/rules/hypersoc_lab_rules.xml'])
    script = startup.read_text()
    if '# HyperSOC: normalize shared Windows adapter line endings' not in script:
        script += '\n# HyperSOC: normalize shared Windows adapter line endings\nsed -i \'s/\\r$//\' "$adapter"\n'
        startup.write_text(script)
    command(['docker', 'exec', '-u', 'root', MANAGER, '/var/ossec/bin/wazuh-integratord', '-t'])
    command(['docker', 'restart', MANAGER])
    print('Updated existing integration, preserved its level filter, backed up private configuration and restarted only the manager.')

def account():
    credentials = STATE / 'admin-credentials.json'
    if not credentials.exists():
        credentials.write_text(json.dumps({'username': 'h26v', 'password': secrets.token_urlsafe(24)}))
        os.chmod(credentials, 0o600)
    params = json.loads(credentials.read_text())
    script = 'import asyncio,json,sys; from app.workers.create_user import create; p=json.load(sys.stdin); asyncio.run(create(p["username"],"admin",p["password"])); print("Lab admin provisioned")'
    backend = json.loads(command(['docker', 'ps', '--filter', 'label=com.docker.compose.project=hypersoc-lab', '--filter', 'label=com.docker.compose.service=backend', '--format', '{{json .}}']))['ID']
    print(command(['docker', 'exec', '-i', backend, 'python', '-c', script], input=json.dumps(params)).strip())
    print('Credentials stored only in', credentials)

def collector():
    data = manager_info()
    environment = dict(v.split('=', 1) for v in data['Config']['Env'] if '=' in v)
    params = json.loads((STATE / 'admin-credentials.json').read_text())
    certificate = container_read('/var/ossec/api/configuration/ssl/server.crt')
    (STATE / 'wazuh-api.crt').write_text(certificate)
    settings = {'wazuh_url': 'https://' + MANAGER + ':55000', 'wazuh_username': environment['API_USERNAME'],
        'wazuh_password': environment['API_PASSWORD'], 'ca_file': '/config/wazuh-api.crt',
        'soc_url': 'http://backend:8000', 'soc_username': params['username'], 'soc_password': params['password'],
        'ingest_secret': values()['APP_SECRET_KEY']}
    path = STATE / 'collector.json'
    path.write_text(json.dumps(settings))
    os.chmod(path, 0o600)
    override = json.loads((STATE / 'compose.json').read_text())
    override['services']['hub-collector'] = {'image': 'python:3.12-slim', 'user': f'{os.getuid()}:{os.getgid()}',
        'command': ['python', '/adapter/hub-collector.py'], 'restart': 'unless-stopped', 'mem_limit': '96m',
        'volumes': [f'{STATE}:/config:ro', f'{ROOT}/integrations/wazuh:/adapter:ro'],
        'networks': ['default', 'wazuh_ingest'], 'depends_on': {'backend': {'condition': 'service_healthy'}}}
    (STATE / 'compose.json').write_text(json.dumps(override, indent=2))
    compose(['up', '-d', '--no-build', '--no-deps', 'hub-collector'])

def fast_start():
    import signal
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        try: args = (entry / 'cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError, PermissionError, ProcessLookupError): continue
        if b'hypersoc-lab' in args and b'compose' in args and b'up' in args:
            os.kill(int(entry.name), signal.SIGTERM)
    override = json.loads((STATE / 'compose.json').read_text())
    for service in ('migrate', 'backend', 'worker'):
        override['services'].setdefault(service, {})['image'] = 'hypersoc-lab-migrate:latest'
    (STATE / 'compose.json').write_text(json.dumps(override, indent=2))
    compose(['up', '-d', '--no-build', 'backend', 'worker'])

def soc_request(path, payload=None):
    params = json.loads((STATE / 'admin-credentials.json').read_text())
    def request(url, payload=None, headers=None):
        raw = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request('http://127.0.0.1:8000' + url, data=raw,
            headers={'Content-Type': 'application/json', **(headers or {})})
        with urllib.request.urlopen(req, timeout=20) as response: return json.load(response)
    token = request('/api/v1/auth/login', params)['access_token']
    return request(path, payload, {'Authorization': 'Bearer ' + token})

def probe():
    deadline = time.monotonic() + 180
    while True:
        try:
            with urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=5) as response:
                if json.load(response).get('status') == 'ready': break
        except (urllib.error.URLError, OSError):
            pass
        if time.monotonic() >= deadline: raise RuntimeError('Backend is not ready; no probe emitted')
        time.sleep(3)
    marker = secrets.token_hex(8)
    line = time.strftime('%b %d %H:%M:%S') + ' wazuh.manager hypersoc-lab: HyperSOC wiring probe ' + marker + '\n'
    script = 'import sys; open("/var/ossec/logs/hypersoc-wiring.log","a").write(sys.stdin.read())'
    command(['docker', 'exec', '-i', '-u', 'root', MANAGER, 'python3', '-c', script], input=line)
    (STATE / 'probe.json').write_text(json.dumps({'marker': marker, 'created_at': time.time()}))
    print('Controlled local log emitted; waiting for Wazuh analysis and Integrator delivery.')

def retry_probes():
    probes = {row['id'] for row in soc_request('/api/v1/alerts?limit=100') if row['rule_id'] == '110901'}
    for job in soc_request('/api/v1/workflows?limit=200'):
        if job['alert_id'] in probes and job['status'] in {'FAILED', 'RETRY'}:
            result = soc_request('/api/v1/workflows/' + job['id'] + '/retry', {})
            print(json.dumps({'workflow_id': result['id'], 'status': result['status']}))

def verify():
    saved = json.loads((STATE / 'probe.json').read_text())
    script = '''import json,sys
from pathlib import Path
marker = sys.stdin.read().strip()
with open('/var/ossec/logs/alerts/alerts.json','rb') as f:
 f.seek(0,2); size=f.tell(); f.seek(max(0,size-1048576)); lines=f.read().splitlines()
for line in reversed(lines):
 try: alert=json.loads(line)
 except ValueError: continue
 if marker in alert.get('full_log',''):
  print(json.dumps({'external_id':alert['id'],'rule_id':alert['rule']['id']})); break
else: print('{}')
'''
    result = {}
    for _ in range(45):
        native = json.loads(command(['docker', 'exec', '-i', '-u', 'root', MANAGER, 'python3', '-c', script], input=saved['marker']))
        if native:
            rows = soc_request('/api/v1/alerts?limit=100')
            matching = [r for r in rows if r['external_id'] == native['external_id']]
            if matching:
                alert = matching[0]
                jobs = soc_request('/api/v1/workflows?limit=100')
                job = next((j for j in jobs if j['alert_id'] == alert['id']), None)
                if job and job['status'] == 'AWAITING_REVIEW':
                    result = {'wazuh_rule': native['rule_id'], 'native_alert_id': native['external_id'],
                        'soc_alert_id': alert['id'], 'workflow_id': job['id'], 'status': job['status'],
                        'investigations': job['output']['investigations'],
                        'provider_modes': {k: v for k, v in values().items() if k.endswith('_PROVIDER_MODE')},
                        'context_gaps': job['output'].get('context_gaps', [])}
                    break
                if job and job['status'] == 'FAILED': raise RuntimeError(job['error'])
        time.sleep(2)
    if not result: raise RuntimeError('Wazuh → Hub → worker probe did not reach review within the verification window')
    result['inventory_entities'] = len(soc_request('/api/v1/hub/entities?kind=asset&limit=200'))
    (STATE / 'wiring-result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

def provider_settings():
    source = {}
    for line in (ROOT / '.env').read_text().splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            key, value = line.split('=', 1)
            source[key.strip()] = value.strip().strip('"').strip("'")
    config = values()
    allowed = ['AI_TRIAGE_PROVIDER_MODE', 'TYPESAFE_API_KEY', 'TYPESAFE_BASE_URL', 'TYPESAFE_MODEL',
        'AI_TRIAGE_TIMEOUT_SECONDS', 'INVESTIGATOR_PROVIDER_MODE', 'INVESTIGATOR_OPENROUTER_API_KEY',
        'INVESTIGATOR_MODEL', 'INVESTIGATOR_TIMEOUT_SECONDS', 'ALERT_UNDERSTANDING_PROVIDER_MODE',
        'THREAT_INTEL_PROVIDER_MODE', 'THREAT_INTEL_ENABLE_EXTERNAL_PROVIDERS', 'VIRUSTOTAL_API_KEY',
        'ABUSEIPDB_API_KEY', 'URLHAUS_API_URL', 'URLHAUS_AUTH_KEY']
    for key in allowed:
        if source.get(key): config[key] = source[key]
    if config.get('INVESTIGATOR_PROVIDER_MODE') == 'openrouter' and 'ALERT_UNDERSTANDING_PROVIDER_MODE' not in source:
        config['ALERT_UNDERSTANDING_PROVIDER_MODE'] = 'openrouter'
    config['WAZUH_ACTIVE_RESPONSE_PROVIDER_MODE'] = 'offline'
    backend = json.loads(command(['docker', 'ps', '--filter', 'label=com.docker.compose.project=hypersoc-lab', '--filter', 'label=com.docker.compose.service=backend', '--format', '{{json .}}']))['ID']
    script = 'import json,sys; from app.core.config import Settings; values=json.load(sys.stdin); s=Settings(_env_file=None,**{k.lower():v for k,v in values.items()}); s.validate_runtime_settings(); print("Provider configuration validated")'
    print(command(['docker', 'exec', '-i', backend, 'python', '-c', script], input=json.dumps(config)).strip())
    path = STATE / 'lab.env'
    path.write_text(''.join(f'{k}={v}\n' for k, v in config.items()))
    os.chmod(path, 0o600)
    compose(['up', '-d', '--no-build', 'backend', 'worker'])
    print(json.dumps({k: config.get(k) for k in ['AI_TRIAGE_PROVIDER_MODE', 'INVESTIGATOR_PROVIDER_MODE', 'ALERT_UNDERSTANDING_PROVIDER_MODE', 'THREAT_INTEL_PROVIDER_MODE', 'WAZUH_ACTIVE_RESPONSE_PROVIDER_MODE']}, indent=2))

def snapshot():
    script = '''import asyncio,json
from sqlalchemy import select,func
from app.core.database import async_session_factory
from app.models.hub import HubEvidence,HubEntity
from app.models.workflow import WorkflowJob
from app.models.investigation import Investigation
from app.models.behavior import BehaviorModel
from app.models.incident import Incident
async def main():
 async with async_session_factory() as db:
  counts=dict((await db.execute(select(HubEvidence.category,func.count()).group_by(HubEvidence.category))).all())
  jobs=(await db.scalars(select(WorkflowJob).order_by(WorkflowJob.created_at.desc()).limit(20))).all()
  reports=(await db.scalars(select(Investigation).order_by(Investigation.created_at.desc()).limit(5))).all()
  models=(await db.scalars(select(BehaviorModel).order_by(BehaviorModel.created_at.desc()).limit(5))).all()
  result={'evidence':counts,'entities':await db.scalar(select(func.count()).select_from(HubEntity)), 'models':await db.scalar(select(func.count()).select_from(BehaviorModel)),
   'model_details':[{'id':str(m.id),'algorithm':m.algorithm,'sample_count':m.sample_count,'trained_until':m.trained_until.isoformat()} for m in models],
   'stored_triage_count':await db.scalar(select(func.count()).select_from(Incident).where(Incident.ai_analysis.is_not(None))),
   'workflows':[{'id':str(j.id),'status':j.status,'stage':j.stage,'attempts':j.attempts,'error':j.error} for j in jobs],
   'reports':[{'id':str(r.id),'provider':r.provider_mode,'model':r.model_name,'status':r.status,'classification':r.report.get('classification')} for r in reports]}
  print(json.dumps(result,indent=2))
asyncio.run(main())
'''
    result = command(['docker', 'exec', 'hypersoc-lab-backend-1', 'python', '-c', script])
    (STATE / 'snapshot.json').write_text(result)
    print(result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['inspect', 'provision', 'start', 'wire', 'account', 'collector', 'fast-start', 'probe', 'verify', 'providers', 'snapshot', 'retry-probes'])
    args = parser.parse_args()
    if args.operation == 'inspect': inspect()
    elif args.operation == 'provision': provision()
    elif args.operation == 'start': start()
    elif args.operation == 'wire': wire()
    elif args.operation == 'account': account()
    elif args.operation == 'collector': collector()
    elif args.operation == 'fast-start': fast_start()
    elif args.operation == 'probe': probe()
    elif args.operation == 'verify': verify()
    elif args.operation == 'providers': provider_settings()
    elif args.operation == 'snapshot': snapshot()
    elif args.operation == 'retry-probes': retry_probes()
