# Tenant Fence

**Can account A read account B’s record? Prove the answer with real requests.**

Tenant Fence is a tiny, zero-runtime-dependency CLI for repeatable tenant-isolation read checks. Give it two synthetic users and two known fixtures in your authorized local or staging app. It checks that each user can read their own fixture, then tries the other user's fixture.

**Not a scanner. Not a security certification. A small regression test you can understand.**

## See a leak, then see the fix

Python 3.10+ is the only prerequisite. From this repository:

```sh
python -m tenant_fence demo
```

No accounts, Docker, keys, installation or external traffic required. The demo starts two temporary loopback HTTP servers and sends real requests through the same probe engine used by the Supabase adapter.

```text
BROKEN
Tenant Fence | FAIL
  PASS  A -> A  HTTP 200  own fixture readable
  PASS  B -> B  HTTP 200  own fixture readable
  FAIL  A -> B  HTTP 200  cross-account query returned rows
  FAIL  B -> A  HTTP 200  cross-account query returned rows

FIXED
Tenant Fence | PASS
  PASS  A -> A  HTTP 200  own fixture readable
  PASS  B -> B  HTTP 200  own fixture readable
  PASS  A -> B  HTTP 200  cross-account query returned no rows
  PASS  B -> A  HTTP 200  cross-account query returned no rows
```

The vulnerable server looks up a record without checking its owner. The fixed server additionally matches the owner to the authenticated synthetic user. See [the entire demo](tenant_fence/demo.py). Its toy tokens are intentionally not real JWT signatures and cannot authenticate to Supabase.

```sh
python -m tenant_fence demo --json --report demo-evidence.json
python -m unittest discover -s tests -v
```

The demo exits 0 only when it observes both the expected broken failure and fixed pass. That does NOT mean the broken app passed.

## Your local/staging Supabase project

1. Use a disposable project or isolated staging dataset you own or are explicitly authorized to test. Never use production customer records.
2. Create two synthetic Auth users with different user IDs and different tenant memberships, using your actual authorization model. Sign each in normally and obtain its current access token. Tenant Fence does not create users or manage credentials.
3. Seed two synthetic rows in your target table. Each needs an `id` and `marker` column visible through the public REST API. Markers must start with `tenant-fence-`. Use distinct fixture IDs and markers. The CLI only reads; it never seeds, edits or deletes data.
4. Copy [examples/supabase.json](examples/supabase.json), replacing the project origin, table and fixture values. Environment-variable names, not token values, belong in configuration.
5. Set `SUPABASE_PUBLIC_KEY` to your publishable key or legacy anon key, and `TENANT_A_ACCESS_TOKEN` / `TENANT_B_ACCESS_TOKEN` to the two user sessions through your shell or CI secret manager. Do not paste secrets into shell commands saved in shared history or commit them.
6. Run:

```sh
python -m tenant_fence check examples/supabase.json \
  --authorized-synthetic-staging \
  --allow-origin https://YOUR-STAGING-PROJECT.supabase.co \
  --report evidence.json
```

`--allow-origin` must exactly match the configured HTTPS origin for any non-loopback target. This is an explicit safety acknowledgement, not proof of ownership. Localhost/127.0.0.1/::1 may use HTTP, but still require `--authorized-synthetic-staging`.

For a first experiment, [examples/setup.sql](examples/setup.sql) shows a dedicated fixture table and owner policy. Run it manually only in a disposable project after replacing the UUIDs. **Passing on that example table does not test your application's tables.** To test an existing table, seed your synthetic fixtures there and point the config at it. This version requires `id`/`marker` columns and a simple public table name; it does not alter your schema automatically.

### Why two kinds of credentials?

The public API key identifies the application; the per-user access token identifies the user. Requests send the public key as `apikey` and the session as `Authorization: Bearer …`. Elevated secret/service-role keys can bypass RLS and invalidate the test, so known elevated key formats are rejected. JWT claims are decoded only for defensive configuration checks, not trusted as authentication; your server must verify signatures and authorization.

Reference: [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys), [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security). Tenant Fence does not need an administrative database connection.

## What the result means

| Exit | Result | Meaning |
| --- | --- | --- |
| 0 | PASS | Both own reads worked; both exact-ID cross reads returned no rows or HTTP 403/404. |
| 1 | FAIL | At least one cross-account exact-ID request returned rows. Investigate the policy/path. |
| 2 | ERROR | Configuration, network, auth or unexpected response prevented a reliable result. |

An empty database or two expired sessions must not produce a reassuring PASS. HTTP 401, redirects, server errors, malformed/oversized responses, and failed positive controls produce ERROR. An observed cross-account disclosure remains FAIL even if another probe errors. Nonempty cross-read results are treated conservatively as failures even if the synthetic marker is missing.

JSON output contains a versioned schema, UTC timestamp, actor/fixture aliases, HTTP status, marker-match boolean, reason and result. It does **not** retain tokens, full URLs, fixture values, headers or response bodies. Keep the matching config and git commit privately alongside the report for reproducibility. Reports demonstrate client-observed behavior, not operator attribution or cryptographically attested evidence.

## Fit this into CI

After provisioning your synthetic fixtures and injecting fresh user sessions, run `check` as a required step. Only exit 0 is a pass. Do not use `|| true` or treat exit 2 as a pass. Do not expose staging tokens to untrusted pull requests. This repository's CI runs only synthetic loopback tests and needs no secrets.

Optional local installation:

```sh
python -m pip install .
tenant-fence demo
```

This is a source release; no claim is made that the package name is available on PyPI. Running directly from the checkout requires no package downloads.

## Boundaries, honestly

- Four GET requests against known IDs, not discovery, enumeration or arbitrary scans.
- Tests two chosen user sessions and fixture records at one moment, not every tenant or permission.
- Does not test writes/deletes, bulk queries, joins, views, RPCs, storage, realtime, exports, caching, browser sessions, role changes or service-key misuse inside your backend.
- The Supabase adapter reads PostgREST directly. It does not test your app's custom server routes. The local demo is Supabase-shaped, not a full Supabase emulator.
- Passing a policy test is not a penetration test, compliance claim, guarantee of security or proof that all tenant boundaries are correct.
- Tokens go only to the configured origin. Redirects are not followed; ambient HTTP proxies are disabled. No telemetry. No browser history. No credential persistence.
- Only use on explicitly authorized local/staging systems with synthetic data. The safety options are not permission to probe others.

For SQL-level RLS tests, consider [Supabase's testing tools](https://supabase.com/docs/guides/local-development/testing/overview) and [Basejump's test helpers](https://github.com/usebasejump/supabase-test-helpers). Tenant Fence complements those with a small, real-client regression and readable evidence; it does not replace them.

## Contributing

Keep the demo runnable without network access and add a failing regression test before a fix. Good next adapters include explicit write-isolation fixtures with cleanup and richer membership models; these are **not implemented yet**. Report vulnerabilities privately using the process in [SECURITY.md](SECURITY.md). See [LICENSE](LICENSE) for MIT terms.
