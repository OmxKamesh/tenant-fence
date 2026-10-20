"""Read-only HTTP probes. No SDK/admin bypass, redirects, cookies or body logs."""
import base64
from datetime import datetime, timezone
import json
import http.client
import os
import re
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 65536

class ConfigError(ValueError):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def claims(token):
    try:
        value = token.split('.')[1]
        decoded = json.loads(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4)))
        return decoded if isinstance(decoded, dict) else {}
    except (ValueError, IndexError, UnicodeDecodeError):
        return {}

def credential(value, session=False):
    if not isinstance(value, str) or not value or '\n' in value or '\r' in value:
        raise ConfigError('Missing or invalid credential environment variable')
    payload = claims(value)
    if value.startswith('sb_secret_') or payload.get('role') == 'service_role':
        raise ConfigError('Elevated credentials are forbidden; use public API key and user sessions')
    if session and payload.get('role') != 'authenticated':
        raise ConfigError('Session must be an authenticated user JWT, not an API key')
    if not session and not (value.startswith('sb_publishable_') or payload.get('role') == 'anon'):
        raise ConfigError('API key must be publishable or legacy anon')
    return value

def prepare(config, authorized=False, allowed_origin=None, env=None):
    if not authorized:
        raise ConfigError('Explicit --authorized-synthetic-staging acknowledgement required')
    env = os.environ if env is None else env
    if not isinstance(config, dict):
        raise ConfigError('Config must be a JSON object')
    if config.get('synthetic_only') is not True:
        raise ConfigError('Config must explicitly declare synthetic_only: true')
    base = config.get('base_url', '')
    if not isinstance(base, str):
        raise ConfigError('base_url must be a string')
    try:
        u = urllib.parse.urlsplit(base)
        u.port  # Validate malformed/out-of-range ports before any request.
    except ValueError:
        raise ConfigError('base_url contains an invalid host or port') from None
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
        raise ConfigError('base_url must be a bare HTTP(S) origin without credentials')
    origin = base.rstrip('/')
    local = u.hostname in ('127.0.0.1', 'localhost', '::1')
    if not local and (u.scheme != 'https' or allowed_origin != origin):
        raise ConfigError('Non-loopback requires HTTPS and exact --allow-origin matching base_url')
    table = config.get('table', '')
    if not isinstance(table, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', table):
        raise ConfigError('table must be a simple public table name')
    def read_env(name):
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
            raise ConfigError('Credential environment variable names must be nonempty identifiers')
        return env.get(name, '')
    api = credential(read_env(config.get('api_key_env')))
    accounts = config.get('accounts', [])
    if not isinstance(accounts, list) or len(accounts) != 2:
        raise ConfigError('Exactly two synthetic accounts required')
    result = []
    for account in accounts:
        if not isinstance(account, dict):
            raise ConfigError('Each account must be a JSON object')
        token = credential(read_env(account.get('token_env')), session=True)
        sub = claims(token).get('sub')
        record = account.get('record_id')
        marker = account.get('marker')
        if not sub or not isinstance(record, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', record):
            raise ConfigError('Each account needs a session subject and simple synthetic record_id')
        if not isinstance(marker, str) or not marker.startswith('tenant-fence-') or len(marker) > 128:
            raise ConfigError('Use unique synthetic marker strings beginning tenant-fence-')
        result.append({'token': token, 'sub': sub, 'record': record, 'marker': marker})
    if any(result[0][k] == result[1][k] for k in ('token', 'sub', 'record', 'marker')):
        raise ConfigError('Accounts, subjects, record IDs and markers must be distinct')
    return origin, table, api, result

def request(url, api, token):
    # Disable ambient proxies: credentials go only to the configured origin.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(url, headers={'apikey': api, 'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}, method='GET')
    try:
        with opener.open(req, timeout=10) as response:
            raw = response.read(MAX_BODY + 1)
            status = response.status
    except urllib.error.HTTPError as exc:
        # Never retain error bodies (they can contain secrets or application data).
        return exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
        return None, None
    if len(raw) > MAX_BODY:
        return status, None
    try:
        return status, json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return status, None

def run(config, authorized=False, allowed_origin=None, env=None):
    origin, table, api, accounts = prepare(config, authorized, allowed_origin, env)
    checks = []
    # All URLs select only synthetic fixture columns and exact known IDs.
    for actor, owner in ((0, 0), (1, 1), (0, 1), (1, 0)):
        fixture = accounts[owner]
        query = urllib.parse.urlencode({'select': 'id,marker', 'id': 'eq.' + fixture['record']})
        url = origin + '/rest/v1/' + table + '?' + query
        status, data = request(url, api, accounts[actor]['token'])
        own = actor == owner
        matched = isinstance(data, list) and any(isinstance(row, dict) and row.get('id') == fixture['record'] and row.get('marker') == fixture['marker'] for row in data)
        if own:
            outcome = 'PASS' if status == 200 and matched and len(data) == 1 else 'ERROR'
            reason = 'own fixture readable' if outcome == 'PASS' else 'positive control failed; identity, fixture or endpoint must be fixed'
        elif status == 200 and isinstance(data, list) and len(data) > 0:
            outcome, reason = 'FAIL', 'cross-account query returned rows'
        elif status == 200 and data == []:
            outcome, reason = 'PASS', 'cross-account query returned no rows'
        elif status in (403, 404):
            outcome, reason = 'PASS', 'cross-account request denied'
        else:
            outcome, reason = 'ERROR', 'unexpected response; cannot establish isolation'
        checks.append({'actor': 'AB'[actor], 'fixture_owner': 'AB'[owner], 'kind': 'own-read' if own else 'cross-read', 'http_status': status, 'outcome': outcome, 'reason': reason, 'synthetic_marker_matched': matched})
    # A visible leak is still a failure even if another probe is inconclusive.
    overall = 'FAIL' if any(c['outcome'] == 'FAIL' for c in checks) else 'ERROR' if any(c['outcome'] == 'ERROR' for c in checks) else 'PASS'
    return {'schema_version': 1, 'created_at': datetime.now(timezone.utc).isoformat(), 'result': overall, 'scope': 'two synthetic users; exact-ID REST reads only', 'checks': checks, 'notice': 'Regression evidence, not a security audit or certification. Tokens, URLs and response bodies omitted.'}

def human(report):
    lines = ['Tenant Fence | ' + report['result']]
    for c in report['checks']:
        lines.append(f"  {c['outcome']:5} {c['actor']} -> {c['fixture_owner']}  HTTP {c['http_status']}  {c['reason']}")
    return '\n'.join(lines + [report['notice']])
