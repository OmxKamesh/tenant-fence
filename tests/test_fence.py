import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tenant_fence import core
from tenant_fence.demo import config, environment, server, token
from tenant_fence.__main__ import main

class FenceTests(unittest.TestCase):
    def test_actual_broken_server_leaks_both_directions(self):
        with server(True) as origin:
            report = core.run(config(origin), True, env=environment())
        self.assertEqual(report['result'], 'FAIL')
        self.assertEqual([c['outcome'] for c in report['checks']], ['PASS', 'PASS', 'FAIL', 'FAIL'])

    def test_actual_fixed_server_passes(self):
        with server() as origin:
            report = core.run(config(origin), True, env=environment())
        self.assertEqual(report['result'], 'PASS')
        self.assertEqual(len(report['checks']), 4)

    def test_auth_failures_are_inconclusive_not_pass(self):
        with patch.object(core, 'request', return_value=(401, None)):
            report = core.run(config('http://127.0.0.1:1234'), True, env=environment())
        self.assertEqual(report['result'], 'ERROR')

    def test_positive_control_required_even_if_cross_read_is_empty(self):
        with patch.object(core, 'request', return_value=(200, [])):
            report = core.run(config('http://localhost:1234'), True, env=environment())
        self.assertEqual(report['result'], 'ERROR')

    def test_empty_and_explicit_denial_supported(self):
        responses = [(200, [{'id':'a', 'marker':'tenant-fence-a'}]), (200, [{'id':'b', 'marker':'tenant-fence-b'}]), (403, None), (404, None)]
        with patch.object(core, 'request', side_effect=responses):
            self.assertEqual(core.run(config('http://localhost'), True, env=environment())['result'], 'PASS')

    def test_redirect_is_not_followed(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                seen.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/should-not-be-requested')
                self.end_headers()
        http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=http.serve_forever)
        thread.start()
        try:
            status, _ = core.request(f'http://127.0.0.1:{http.server_port}/original', 'public', 'secret')
            self.assertEqual(status, 302)
            self.assertEqual(seen, ['/original'])
        finally:
            http.shutdown(); http.server_close(); thread.join()

    def test_malformed_config_is_controlled_error(self):
        for cfg in [[], {'synthetic_only': True, 'base_url': 123}, dict(config('http://localhost'), accounts=[None, None]), dict(config('http://localhost'), table=None)]:
            with self.subTest(cfg=cfg), self.assertRaises(core.ConfigError):
                core.prepare(cfg, True, env=environment())

    def test_malformed_env_names_and_url_fail_cleanly(self):
        for field in ['api_key_env', 'token_env']:
            for value in [{}, [], '', None]:
                cfg = config('http://localhost')
                if field == 'api_key_env': cfg[field] = value
                else: cfg['accounts'][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(core.ConfigError):
                    core.prepare(cfg, True, env=environment())
        for url in ['https://[bad', 'http://localhost:999999', 'http://localhost:nope']:
            with self.subTest(url=url), self.assertRaises(core.ConfigError):
                core.prepare(config(url), True, env=environment())

    def test_invalid_jwt_claim_shape_rejected(self):
        import base64
        malformed = 'x.' + base64.urlsafe_b64encode(b'[]').decode() + '.x'
        with self.assertRaises(core.ConfigError): core.credential(malformed, session=True)

    def test_observed_leak_overrides_other_inconclusive_checks(self):
        responses = [(401, None), (200, [{'id':'b', 'marker':'tenant-fence-b'}]), (200, [{'id':'b', 'marker':'tenant-fence-b'}]), (200, [])]
        with patch.object(core, 'request', side_effect=responses):
            self.assertEqual(core.run(config('http://localhost'), True, env=environment())['result'], 'FAIL')

    def test_requires_authorization(self):
        with self.assertRaises(core.ConfigError):
            core.prepare(config('http://localhost'), env=environment())

    def test_remote_requires_https_exact_allowlist(self):
        for origin, allowed in [('https://example.com', None), ('https://example.com', 'https://different.com'), ('http://example.com', 'http://example.com')]:
            with self.subTest(origin=origin, allowed=allowed), self.assertRaises(core.ConfigError):
                core.prepare(config(origin), True, allowed, environment())
        core.prepare(config('https://example.com'), True, 'https://example.com', environment())

    def test_rejects_unsafe_origins_and_table_injection(self):
        for origin in ['https://user:pass@example.com', 'https://example.com/?token=secret', 'file:///tmp/test', 'https://example.com/path']:
            with self.subTest(origin=origin), self.assertRaises(core.ConfigError):
                core.prepare(config(origin), True, origin, environment())
        cfg = config('http://localhost'); cfg['table'] = '../auth'
        with self.assertRaises(core.ConfigError): core.prepare(cfg, True, env=environment())

    def test_rejects_elevated_keys(self):
        for key in ['sb_secret_forbidden', token('admin', 'service_role')]:
            for variable in ['DEMO_KEY', 'DEMO_A']:
                env = environment(); env[variable] = key
                with self.subTest(variable=variable), self.assertRaises(core.ConfigError):
                    core.prepare(config('http://localhost'), True, env=env)

    def test_rejects_same_account(self):
        env = environment(); env['DEMO_B'] = env['DEMO_A']
        with self.assertRaises(core.ConfigError): core.prepare(config('http://localhost'), True, env=env)

    def test_no_tokens_or_bodies_in_reports(self):
        with server(True) as origin:
            report = core.run(config(origin), True, env=environment())
        output = json.dumps(report)
        for value in environment().values(): self.assertNotIn(value, output)
        self.assertNotIn('tenant-fence-a', output)
        self.assertNotIn(origin, output)

    def test_unexpected_responses_are_errors(self):
        for response in [(500,None), (302,None), (None,None), (200,{'error':'bad'}), (200,None)]:
            with self.subTest(response=response), patch.object(core, 'request', return_value=response):
                self.assertEqual(core.run(config('http://localhost'), True, env=environment())['result'], 'ERROR')

    def test_cli_real_exit_codes_and_json_file(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict('os.environ', environment()):
            path = Path(directory) / 'config.json'; report_path = Path(directory) / 'report.json'
            for broken, expected in [(True, 1), (False, 0)]:
                with server(broken) as origin:
                    path.write_text(json.dumps(config(origin)))
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        code = main(['check', str(path), '--authorized-synthetic-staging', '--json', '--report', str(report_path)])
                    self.assertEqual(code, expected)
                    self.assertEqual(json.loads(output.getvalue()), json.loads(report_path.read_text()))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['check', str(path)]), 2)

    def test_demo_is_verified_and_json_only(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output): code = main(['demo', '--json'])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())['demo_verified'])

if __name__ == '__main__': unittest.main()
