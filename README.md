# Service Configuration Scanner

Finds Dynatrace configurations that hardcode service entity IDs (`SERVICE-*`).

Those configurations stop resolving once the `dt.entity.service` dimension is no longer written
to span and metric data: the SLO evaluates nothing, the dashboard tile goes blank, the metric
event never fires. This scanner produces the list of what breaks, so it can be fixed before the
change lands rather than discovered afterwards.

**Every detected service is in scope** — database, third-party, opaque, and internal
OneAgent-detected services alike. The dimension retires for all of them, so restricting the scan
to external services only would under-report the impact.

The scanner is read-only. It never writes to the tenant.

## ⚠️ Work in progress — not production ready
> This tool is under development.
> Contributions and bug reports are welcome — open an issue or submit a pull request.

## What gets scanned

| Source | Read from |
| --- | --- |
| Classic SLOs | `builtin:monitoring.slo` |
| Metric events | `builtin:anomaly-detection.metric-events` |
| Davis anomaly detectors | `builtin:davis.anomaly-detectors` |
| Site Reliability Guardians | `app:dynatrace.site.reliability.guardian:guardians` |
| Service-Level Objectives app | `/platform/slo/v1/slos` |
| Dashboards | Document API |
| Notebooks | Document API |

A notebook or dashboard tile stores its last query *result* next to the query *definition*. Only
the definition is scanned: a service ID that merely appeared in a cached result is not a
configuration that needs changing, and reporting it would be a false positive.

## Prerequisites

- Python 3.7 or later. No packages to install — the scripts use only the standard library.
- A Python that can verify TLS certificates. Check it in one command:

  ```bash
  python3 -c "import ssl; print(len(ssl.create_default_context().get_ca_certs()))"
  ```

  A `0` means your interpreter has no trust store and **every** request will fail with
  `CERTIFICATE_VERIFY_FAILED`. This is common with python.org builds on macOS, where the
  bundled certificate installer was never run. See [Troubleshooting](#troubleshooting).

- A Dynatrace **platform** token — the prefix must be `dt0s16.`

  > A classic API token (`dt0c01.` prefix) is **not** interchangeable. It works against the
  > classic settings API, so settings-based configs still get scanned, but every platform
  > API — Grail queries, dashboards, notebooks, the SLO app — rejects it with
  > `401 An error occurred during SSO authentication`. The practical effect is that no
  > dashboard or notebook is scanned at all and no service can be categorised. The scanner
  > warns about this on startup.

  Required scopes:

| Needed for | API surface | Scope |
| --- | --- | --- |
| Service census and ID lookup (DQL) | platform | Storage / `storage:entities:read` |
| Dashboard and notebook content | platform | `document:documents:read` |
| **Tenant-wide** document visibility | platform | `document:documents:admin` |
| Service-Level Objectives app | platform | `slo:slos:read` |
| Classic settings objects (SLOs, metric events, Davis detectors, SRGs) | classic | `settings.read` |

`document:documents:admin` is the one most often missed. Without it a token sees only the
documents its own user can see, which on most tenants is a small fraction of the total. The scan
detects this, reports itself as `partial`, and says so in the output — it will not present a
partial view as a clean bill of health.

Only the last row is served by the classic API. That is why a classic token gets you four of the
seven sources and nothing else. Scope names vary a little between Dynatrace versions — the API
column is the part that matters: anything marked *platform* needs a platform token.

If you already hold a classic token with `settings.read`, the quickest complete setup is to use
both, each on the surface it is valid for:

```bash
export DT_PLATFORM_TOKEN=dt0s16.XXXX   # platform APIs
export DT_CLASSIC_TOKEN=dt0c01.XXXX    # classic settings API only
```

Prefer environment variables over `--token` / `--classic-token`: a credential given on the
command line is visible to other users via `ps` and is written to your shell history.

## Step 1 — Scan

```bash
python3 scan_service_configs.py --tenant https://<env>.apps.dynatrace.com
```

Writes, next to the script:

- `report_<env>.json` — the machine-readable scan result
- `report_<env>_details/` — one file per affected dashboard, notebook, and settings schema,
  containing the exact tiles, sections, and setting values that carry the reference

Useful options:

| Option | Default | Notes |
| --- | --- | --- |
| `--output PATH` | `report_<env>.json` next to the script | the details directory follows the same path |
| `--lookback 30d` | `30d` | how far back to look for services (see below) |
| `--timeout 60` | `60` | HTTP socket timeout in seconds; `0` disables it |
| `--token` | `$DT_PLATFORM_TOKEN` | must be a platform token (`dt0s16.*`) |
| `--classic-token` | `$DT_CLASSIC_TOKEN` | optional; classic token used only for the classic settings API |

About `--lookback`: the service list is an event-lookback view, so it only contains services
*seen in the window*. Widen it if a service that stopped reporting three months ago still matters
to you; the trade-off is a slower query.

The console prints a summary and the affected configurations as it goes. Exit code `0` means the
scan completed — it does **not** mean nothing was found; check the counts.

## Step 2 — Build the report

```bash
python3 service_config_report.py --tenant https://<env>.apps.dynatrace.com
```

Writes, next to the scan report:

- `service_config_report_<env>.json` — consolidated result
- `service_config_report_<env>.html` — self-contained page, openable in any browser, with deep
  links back into the tenant for every setting, notebook, dashboard, objective, and service

Add `--report-dir PATH` if the scan wrote somewhere other than the script's own directory.

## Reading the output

The HTML report opens with an **Overview** table: how many services exist on the tenant per
category, and how many of them are referenced by a configuration. The rest of the page lists the
affected configurations grouped by type, then the referenced services grouped by category.

### Service categories

| Category | What it means | Typical fix |
| --- | --- | --- |
| `database` | `serviceType == DATABASE_SERVICE` | re-point at the database entity in the Services app |
| `third_party` | `serviceSubType == WEB_REQUEST_WATCHED` — an outbound call to something you do not run | re-point at the third-party service in the Services app |
| `opaque` | external, but neither of the above | re-point at the service in the Services app |
| `detected` | an internal service OneAgent detected — your own code | rewrite the query to filter on a service attribute instead of the entity ID |
| `unresolved` | the ID is referenced by a configuration but no service with that ID exists on the tenant | the configuration is already broken; delete it or re-point it |
| `unknown` | the lookup itself failed, so the category could not be determined | not a finding about the service — fix the scan (usually the token) and re-run |

`unresolved` is worth acting on first. It costs nothing to clean up and it is usually a sign that
the configuration has been silently returning nothing for a while.

### Scan completeness

Every report carries a status.

| Status | Meaning |
| --- | --- |
| `complete` | every configuration source was read in full |
| `partial` | at least one source could not be read, so an affected configuration may be missing |

A `partial` scan is refused by the report script, because a report that quietly omits findings is
worse than no report. Fix the cause and re-run, or override deliberately:

```bash
python3 service_config_report.py --tenant https://<env>.apps.dynatrace.com --allow-incomplete
```

The generated page then carries a warning banner listing exactly what was missed.

Some failures produce a warning without downgrading the status — a failed service census, or a
failure to resolve IDs to names. Those cost labelling, not coverage: every affected configuration
is still listed, just with `unresolved` in place of a name.

## Troubleshooting

### `CERTIFICATE_VERIFY_FAILED` / "cannot verify the TLS certificate"

Your Python has no CA certificates. It is not a tenant, token, or network problem, and it
affects every Python tool on the machine, not just this one. Confirm it:

```bash
python3 -c "import ssl; print(len(ssl.create_default_context().get_ca_certs()))"
```

`0` confirms it. Fix it with any one of these:

```bash
# 1. Permanent, for python.org builds on macOS — run once, fixes every tool
"/Applications/Python 3.12/Install Certificates.command"

# 2. This shell only, no install
export SSL_CERT_FILE=/etc/ssl/cert.pem

# 3. Via certifi
pip install certifi
export SSL_CERT_FILE=$(python3 -c 'import certifi; print(certifi.where())')
```

Note that a virtualenv inherits the base interpreter's trust store, so fixing the base
interpreter fixes the venv too.

### Everything else

| Symptom | Cause |
| --- | --- |
| `Scan aborted: every configuration source failed` | nothing on the tenant could be read, so there is nothing to report. Usually a token with no scopes, or the wrong tenant URL. The scan deliberately refuses to write a report here, because "0 affected configs" would look like a clean tenant |
| `401 An error occurred during SSO authentication` on platform APIs only, while settings schemas succeed | you are using a classic token (`dt0c01.*`) where a platform token (`dt0s16.*`) is required. Dashboards, notebooks, the SLO app and Grail queries are all platform APIs |
| "but the same URL shows data in my browser" | the browser authenticates with your **SSO session cookie**, carrying your user's permissions. The scanner authenticates with a **token**. A URL working in the browser says nothing about whether a token can read it — confirm with `curl -H "Authorization: Api-Token $DT_PLATFORM_TOKEN" '<url>'` |
| Every service reported as `unknown` | the service lookup (a Grail query) failed — almost always the same token problem as above |
| `Fatal API error: HTTP 401` | token missing, expired, or not a platform (`dt0s16.*`) token |
| Every API returns **403** (not 401) | authenticated but not authorised — an under-scoped credential. 401 means the credential was rejected; 403 means it was accepted and lacks permission |
| `HTTP 403` on settings | missing `settings.read` |
| Status `partial`, "tenant-wide document access unavailable" | missing `document:documents:admin`; only your own documents were scanned |
| `Service census could not be read` | missing Storage read scope; affected configs are still correct, counts are not |
| Suspiciously few services on the tenant | widen `--lookback` |
| Document content fetches failed | missing `document:read`, or the tenant rate-limited the run — re-run, or raise `--timeout` |

## Verifying the scripts

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test -v
```

122 tests, no tenant and no network required.
