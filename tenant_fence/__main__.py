import argparse
import json
from pathlib import Path
from .core import ConfigError, run, human
from .demo import demo

EXIT = {'PASS': 0, 'FAIL': 1, 'ERROR': 2}

def main(argv=None):
    parser = argparse.ArgumentParser(description='Two synthetic accounts. Four real HTTP reads. Clear isolation evidence.')
    sub = parser.add_subparsers(dest='command', required=True)
    demo_parser = sub.add_parser('demo', help='Run intentionally broken and fixed local examples')
    check = sub.add_parser('check', help='Read-only probes against your authorized synthetic local/staging fixtures')
    check.add_argument('config', type=Path)
    check.add_argument('--authorized-synthetic-staging', action='store_true')
    check.add_argument('--allow-origin', help='Exact HTTPS origin required for non-loopback targets')
    for p in (demo_parser, check):
        p.add_argument('--json', action='store_true', help='Machine-readable stdout only')
        p.add_argument('--report', type=Path, help='Write sanitized JSON evidence')
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            reports = demo()
            result = {'demo_verified': reports['broken']['result'] == 'FAIL' and reports['fixed']['result'] == 'PASS', 'reports': reports}
            code = 0 if result['demo_verified'] else 2
            text = '\n\n'.join(name.upper() + '\n' + human(report) for name, report in reports.items())
        else:
            config = json.loads(args.config.read_text())
            result = run(config, args.authorized_synthetic_staging, args.allow_origin)
            code = EXIT[result['result']]
            text = human(result)
        serialized = json.dumps(result, indent=2) + '\n'
        if args.report:
            args.report.write_text(serialized)
        print(serialized if args.json else text, end='' if args.json else '\n')
        return code
    except (ConfigError, OSError, ValueError, TypeError, KeyError) as exc:
        # Deliberately avoid reflecting config contents or filesystem exception details.
        result = {'result': 'ERROR', 'reason': str(exc) if isinstance(exc, ConfigError) else 'Invalid config or report path; check format and permissions'}
        print(json.dumps(result) if args.json else 'Tenant Fence | ERROR\n' + result['reason'])
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
