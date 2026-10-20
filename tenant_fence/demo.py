"""Intentionally insecure and corrected toy REST services, loopback only."""
import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from urllib.parse import urlsplit, parse_qs
from .core import run

def token(sub, role='authenticated'):
    # Synthetic demo token, not accepted by Supabase or any real auth system.
    payload = base64.urlsafe_b64encode(json.dumps({'sub': sub, 'role': role}).encode()).decode().rstrip('=')
    return 'demo.' + payload + '.not-a-signature'

@contextmanager
def server(broken=False):
    tokens = {token('alice'): 'a', token('bob'): 'b'}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            parsed = urlsplit(self.path)
            identity = tokens.get(self.headers.get('Authorization', '').removeprefix('Bearer '))
            if parsed.path != '/rest/v1/fixtures':
                self.send_error(404)
                return
            if not identity:
                self.send_error(401)
                return
            record = parse_qs(parsed.query).get('id', [''])[0].removeprefix('eq.')
            visible = record in ('a', 'b') and (broken or record == identity)
            body = json.dumps([{'id': record, 'marker': 'tenant-fence-' + record}] if visible else []).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{http.server_port}'
    finally:
        http.shutdown()
        http.server_close()
        thread.join()

def config(origin):
    return {'base_url': origin, 'synthetic_only': True, 'table': 'fixtures', 'api_key_env': 'DEMO_KEY', 'accounts': [{'token_env': 'DEMO_A', 'record_id': 'a', 'marker': 'tenant-fence-a'}, {'token_env': 'DEMO_B', 'record_id': 'b', 'marker': 'tenant-fence-b'}]}

def environment():
    return {'DEMO_KEY': token('demo', 'anon'), 'DEMO_A': token('alice'), 'DEMO_B': token('bob')}

def demo():
    reports = {}
    for name, broken in [('broken', True), ('fixed', False)]:
        with server(broken) as origin:
            reports[name] = run(config(origin), authorized=True, env=environment())
    return reports
