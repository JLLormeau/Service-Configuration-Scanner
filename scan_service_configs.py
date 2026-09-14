#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Service Configuration Scanner

Finds Dynatrace configuration artifacts that hardcode service entity IDs
(SERVICE-*). Those configurations stop resolving once the dt.entity.service
dimension is no longer written to span and metric data: the SLO evaluates
nothing, the dashboard tile goes blank, the metric event never fires.

Every detected service is in scope -- database, third-party, opaque, and
internal OneAgent-detected services alike -- because the dimension retires for
all of them, not only for external ones.

Scanned configuration sources:
    Classic SLOs                 builtin:monitoring.slo
    Metric events                builtin:anomaly-detection.metric-events
    Davis anomaly detectors      builtin:davis.anomaly-detectors
    Site Reliability Guardians   app:dynatrace.site.reliability.guardian:guardians
    Service-Level Objectives app /platform/slo/v1/slos
    Dashboards
    Notebooks

Usage:
    export DT_PLATFORM_TOKEN=dt0s16.XXXXXX
    python3 scan_service_configs.py --tenant https://abc.apps.dynatrace.com

    python3 scan_service_configs.py --tenant https://abc.dev.apps.dynatracelabs.com \
        --output /custom/path/report.json --lookback 90d

Required token scopes (a platform token -- dt0s16.* prefix -- is sufficient):
    Storage read              DQL entity queries (built into platform tokens)
    settings.read             classic settings objects
    document:read             dashboard and notebook content
    document:documents:admin  tenant-wide document visibility; without it only the
                              documents the token owner can see are scanned and the
                              scan is reported as partial
    slo:slos:read             Service-Level Objectives app

Exit codes:
    0  completed successfully (check the report for affected configs)
    1  fatal error (auth failure, unreachable tenant, ...)
"""
import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

if sys.version_info < (3, 7):
    sys.exit("Python 3.7 or later is required.")

_SCRIPT_DIR = Path(__file__).parent

_SETTINGS_SCHEMAS = [
    "builtin:monitoring.slo",                               # classic, settings-based SLOs
    "builtin:anomaly-detection.metric-events",              # custom metric events
    "builtin:davis.anomaly-detectors",                      # Davis anomaly detectors
    "app:dynatrace.site.reliability.guardian:guardians",    # Site Reliability Guardians
]

_SLO_API_PATH = "/platform/slo/v1/slos"

# A Dynatrace service entity ID is the literal prefix plus 16 hex digits. The
# surrounding look-arounds stop SERVICE-<16 hex> from matching inside a longer
# token, which a plain substring test would do.
_SERVICE_ID_RE = re.compile(
    r"(?<![A-Za-z0-9_-])SERVICE-[0-9A-Fa-f]{16}(?![A-Za-z0-9_-])"
)

# Services are resolved in batches so the DQL filter list stays a sane length.
_RESOLVE_CHUNK = 500

# Third-party services are enumerated in full regardless of config references, so
# this one query is capped. There are orders of magnitude fewer of them than of
# detected services, so the cap is a guard rail rather than a working limit.
_THIRD_PARTY_CAP = 100000

#: Categories a service entity can actually carry. The census can only ever
#: produce these, because every one is derived from the entity's own fields.
_TENANT_CATEGORIES = ["database", "third_party", "opaque", "detected"]

#: The two bookkeeping categories, which describe the lookup rather than the
#: service: `unresolved` (looked up, no such service) and `unknown` (lookup
#: failed). Only referenced IDs can land in these.
_CATEGORY_ORDER = _TENANT_CATEGORIES + ["unresolved", "unknown"]

_Cfg = namedtuple("_Cfg", ["platform", "classic", "hdrs", "timeout", "lookback", "classic_hdrs"],
                  defaults=[None])

_CLASSIC_SETTINGS_PATH = "/api/v2/settings/objects"


def _token_kind(token):
    """Classify a Dynatrace token by its prefix.

    Platform APIs (Grail queries, documents, the SLO app) only accept a platform
    token; a classic token reaches them and is rejected with an SSO error that
    reads like a tenant problem rather than a token problem.
    """
    if token.startswith("dt0s16."):
        return "platform"
    if token.startswith("dt0c01."):
        return "classic"
    return "unknown"


def _hdrs_for(cfg, url):
    """Headers for a URL, honouring a separate classic token when one was given."""
    if cfg.classic_hdrs and cfg.platform != cfg.classic and url.startswith(cfg.classic):
        return dict(cfg.classic_hdrs)
    return dict(cfg.hdrs)


def _derive_bases(url):
    """Return (platform_base, classic_base) for a tenant URL."""
    url = url.rstrip("/")
    if ".apps.dynatrace.com" in url:                              # production SaaS
        return url, url.replace(".apps.dynatrace.com", ".live.dynatrace.com", 1)
    if ".apps." in url:                                           # dev/staging
        return url, url.replace(".apps.", ".", 1)
    return url, url


class _ApiError(Exception):
    def __init__(self, url, code, body):
        self.code = code
        super().__init__("HTTP {} -- {}: {}".format(code, url, body[:300]))


class _ScanAborted(Exception):
    """Raised when the scan cannot produce a meaningful result at all.

    Reporting "0 affected configs" after every source failed would read as a
    clean tenant, so that outcome is an error rather than an empty report.
    """


class _TrustStoreError(Exception):
    """Raised when this machine's Python cannot verify any TLS certificate."""

    def __init__(self, host, cause):
        super().__init__(
            "cannot verify the TLS certificate of {}: {}\n\n{}".format(
                host, cause, _cert_hint()))


def _cert_hint():
    version = "{}.{}".format(sys.version_info[0], sys.version_info[1])
    return (
        "Python has no CA certificates to verify the tenant's certificate with. This is a\n"
        "local Python setup problem, not a tenant, token, or network problem.\n"
        "\n"
        "Confirm it:\n"
        "    python3 -c \"import ssl; print(len(ssl.create_default_context().get_ca_certs()))\"\n"
        "A result of 0 is this problem.\n"
        "\n"
        "Fix it with any one of these:\n"
        "  1. Run the certificate installer shipped with python.org builds:\n"
        "       \"/Applications/Python {v}/Install Certificates.command\"\n"
        "  2. Point Python at the macOS system bundle, for this shell only:\n"
        "       export SSL_CERT_FILE=/etc/ssl/cert.pem\n"
        "  3. Install certifi and use its bundle:\n"
        "       pip install certifi\n"
        "       export SSL_CERT_FILE=$(python3 -c 'import certifi; print(certifi.where())')\n"
    ).format(v=version)


def _is_cert_error(exc):
    """Whether exc is a certificate-verification failure, however it is wrapped.

    urllib buries the ssl exception inside URLError, so the cause chain and the
    message are both worth checking.
    """
    seen, depth = exc, 0
    while isinstance(seen, BaseException) and depth < 5:
        if isinstance(seen, ssl.SSLCertVerificationError):
            return True
        seen = getattr(seen, "reason", None) or seen.__cause__
        depth += 1
    return "CERTIFICATE_VERIFY_FAILED" in str(exc)


def _preflight(cfg):
    """Verify TLS to each API base before doing any work.

    A Python without a CA bundle fails every request with the same certificate
    error. Catching that once, up front, is the difference between one
    actionable message and one per configuration source followed by an empty
    report.
    """
    ctx = ssl.create_default_context()
    for base in dict.fromkeys([cfg.platform, cfg.classic]):
        parsed = urllib.parse.urlparse(base)
        if parsed.scheme != "https":
            continue
        host, port = parsed.hostname, parsed.port or 443
        try:
            with socket.create_connection((host, port), timeout=cfg.timeout or 30) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass
        except ssl.SSLCertVerificationError as exc:
            raise _TrustStoreError(host, exc) from exc
        except OSError as exc:
            if _is_cert_error(exc):
                raise _TrustStoreError(host, exc) from exc
            raise _ApiError(base, 0, "cannot reach {}: {}".format(host, exc)) from exc

def _get(cfg, url, params=None, timeout=None):
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=_hdrs_for(cfg, url))
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(req, timeout=timeout or cfg.timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            if e.code == 429 and attempt < 3:
                time.sleep(attempt * 10)
                continue
            raise _ApiError(url, e.code, body) from e
        except urllib.error.URLError as e:
            # A broken trust store is permanent; retrying only multiplies the wait.
            if _is_cert_error(e):
                raise _TrustStoreError(urllib.parse.urlparse(url).hostname, e.reason) from e
            raise
    raise _ApiError(url, 0, "no response after retries")


def _pages(cfg, url, items_key, params):
    current, items = dict(params), []
    while True:
        data = _get(cfg, url, current)
        items.extend(data.get(items_key, []))
        nk = data.get("nextPageKey")
        if not nk:
            break
        current = {"nextPageKey": nk}
    return items


def _dql_execute(cfg, query):
    """Execute a DQL query and return the records list."""
    url = cfg.platform + "/platform/storage/query/v1/query:execute"
    # Grail can be slow on large tenants, so the socket waits longer than the
    # default. The server-side budget is derived from the same number instead of
    # being pinned, so raising --timeout actually buys a longer query.
    budget = min(max(60, cfg.timeout or 60), 300)
    dql_timeout = None if cfg.timeout is None else budget + 30
    hdrs = _hdrs_for(cfg, url)
    hdrs["Content-Type"] = "application/json"
    payload = json.dumps({
        "query": query,
        "requestTimeoutMilliseconds": budget * 1000,
    }).encode()
    req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(req, timeout=dql_timeout) as r:
                resp = json.loads(r.read())
            if resp.get("state") != "SUCCEEDED":
                raise _ApiError(url, 0, "DQL state={}: {}".format(
                    resp.get("state"), json.dumps(resp)[:200]))
            return resp.get("result", {}).get("records", [])
        except (_ApiError, _TrustStoreError):
            raise
        except urllib.error.HTTPError as e:
            body_text = e.read().decode(errors="replace")
            if e.code == 429 and attempt < 3:
                time.sleep(attempt * 10)
                continue
            raise _ApiError(url, e.code, body_text) from e
        except Exception as exc:
            # A broken trust store is permanent; retrying only multiplies the wait.
            if _is_cert_error(exc):
                raise _TrustStoreError(urllib.parse.urlparse(url).hostname, exc) from exc
            if attempt < 3:
                time.sleep(attempt * 5)
                continue
            raise _ApiError(url, 0, str(exc)) from exc
    raise _ApiError(url, 0, "no response after retries")


# --------------------------------------------------------------------------
# Service taxonomy
# --------------------------------------------------------------------------

def _categorise(service_type, service_sub_type, is_external):
    """Bucket a service by its type fields. Order matters: database wins over
    third-party, which wins over the generic external (opaque) case.

    isExternalService is null on entities that never reported the flag, so the
    test is an explicit `is True` rather than a truthiness or != comparison --
    a null must fall through to `detected`, not be guessed either way.
    """
    if service_type == "DATABASE_SERVICE":
        return "database"
    if service_sub_type == "WEB_REQUEST_WATCHED":
        return "third_party"
    if is_external is True:
        return "opaque"
    return "detected"


def _entity_source(cfg):
    """The fetch clause shared by every entity query.

    dt.entity.service is an event-lookback view: it lists the services seen in
    the query window, so the window has to be stated or the census silently
    depends on whatever the API happens to default to.
    """
    return "fetch dt.entity.service, from: now()-{}".format(cfg.lookback)


def _fetch_census(cfg):
    """Return ({category: count}, total) for every service on the tenant.

    A summarize is used rather than pulling the entity rows: the counts are all
    that is wanted, and an aggregation has no result-size ceiling to trip over.
    Bucketing happens in Python so the query itself stays trivial.
    """
    records = _dql_execute(cfg, _entity_source(cfg) + (
        " | summarize count = count(), by: {serviceType, serviceSubType, isExternalService}"
    ))
    counts = {c: 0 for c in _TENANT_CATEGORIES}
    total = 0
    for r in records:
        n = r.get("count") or 0
        category = _categorise(r.get("serviceType"), r.get("serviceSubType"),
                               r.get("isExternalService"))
        counts[category] = counts.get(category, 0) + n
        total += n
    return counts, total


def _resolve_services(cfg, service_ids):
    """Resolve referenced service IDs to names, types, and a category.

    Only the IDs actually found in configuration are looked up, in batches, so
    the cost of this scan tracks the number of configurations rather than the
    number of services on the tenant.

    An ID the lookup returned nothing for is categorised `unresolved`: the
    configuration points at a service that no longer exists, which is a finding
    in its own right rather than something to drop on the floor.

    An ID whose lookup never ran -- because the query itself failed -- is
    categorised `unknown`. The two must not be conflated: "this service is gone"
    and "I could not check" lead to opposite conclusions.
    """
    resolved, warnings, unqueried = {}, [], set()
    ordered = sorted(service_ids)
    for start in range(0, len(ordered), _RESOLVE_CHUNK):
        chunk = ordered[start:start + _RESOLVE_CHUNK]
        id_list = ", ".join('"{}"'.format(sid) for sid in chunk)
        query = _entity_source(cfg) + (
            " | filter in(id, {})"
            " | fields id, entity.name, entity.type, serviceType, serviceSubType,"
            " isExternalService"
            " | limit {}".format(id_list, len(chunk))
        )
        try:
            records = _dql_execute(cfg, query)
        except Exception as exc:
            warnings.append(
                "Could not look up {} referenced service ID(s); their category is "
                "reported as 'unknown', not as missing: {}".format(len(chunk), exc))
            unqueried.update(chunk)
            continue
        for r in records:
            sid = r.get("id")
            if not sid:
                continue
            resolved[sid] = {
                "name":             r.get("entity.name") or sid,
                "entity_type":      r.get("entity.type"),
                "service_type":     r.get("serviceType"),
                "service_sub_type": r.get("serviceSubType"),
                "category":         _categorise(r.get("serviceType"),
                                                r.get("serviceSubType"),
                                                r.get("isExternalService")),
            }

    for sid in ordered:
        if sid not in resolved:
            resolved[sid] = {
                "name":             sid,
                "entity_type":      None,
                "service_type":     None,
                "service_sub_type": None,
                "category":         "unknown" if sid in unqueried else "unresolved",
            }
    return resolved, warnings


def _fetch_third_party(cfg):
    """List every third-party (WEB_REQUEST_WATCHED) service on the tenant.

    These are reported whether or not a scanned configuration references them,
    because they need attention in their own right.
    """
    records = _dql_execute(cfg, _entity_source(cfg) + (
        ' | filter serviceSubType == "WEB_REQUEST_WATCHED"'
        " | fields id, entity.name, entity.type, serviceType, serviceSubType"
        " | limit {}".format(_THIRD_PARTY_CAP)
    ))
    services = [{
        "id":               r.get("id"),
        "name":             r.get("entity.name") or r.get("id"),
        "entity_type":      r.get("entity.type"),
        "service_type":     r.get("serviceType"),
        "service_sub_type": r.get("serviceSubType"),
    } for r in records if r.get("id")]
    truncated = len(records) >= _THIRD_PARTY_CAP
    return services, truncated


# --------------------------------------------------------------------------
# Reference detection
# --------------------------------------------------------------------------

def _strip_cached_results(obj):
    """
    Recursively remove cached query results from notebook/dashboard document bodies.

    Each notebook tile stores its last-run query output in state.result alongside the
    query definition in state.input. The cached data is irrelevant for finding entity
    ID references and can be megabytes of records. Removing it also avoids false
    positives: a service ID that appears only as a query result value (not hardcoded
    in the query definition) is not a config that needs migration.
    """
    if isinstance(obj, dict):
        cleaned = {k: _strip_cached_results(v) for k, v in obj.items()}
        if isinstance(cleaned.get("state"), dict):
            cleaned["state"] = {k: v for k, v in cleaned["state"].items() if k != "result"}
        return cleaned
    if isinstance(obj, list):
        return [_strip_cached_results(v) for v in obj]
    return obj


def _service_ids_in(obj):
    """Return the set of service IDs referenced anywhere in obj, upper-cased."""
    try:
        text = json.dumps(obj, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(obj)
    if "SERVICE-" not in text.upper():
        return set()
    return {m.upper() for m in _SERVICE_ID_RE.findall(text)}


def _filter_body(body, matched_ids, doc_type):
    """Return a copy of body containing only the sections/tiles that reference a matched ID.

    Notebooks store content in sections[] (list); dashboards store it in tiles{} (dict).
    Keeping only matching parts makes the detail file focused and readable, and ensures
    line numbers from _find_hits (computed on the filtered body) match the file exactly.

    Settings objects and SLO app objects are small and flat, so they pass through whole.
    """
    wanted = {sid.upper() for sid in matched_ids}
    if doc_type == "NOTEBOOK":
        kept = [s for s in body.get("sections", []) if _service_ids_in(s) & wanted]
        return dict(body, sections=kept)
    if doc_type == "DASHBOARD":
        tiles = body.get("tiles") or {}
        kept = {tid: t for tid, t in tiles.items() if _service_ids_in(t) & wanted}
        return dict(body, tiles=kept)
    return body


def _find_hits(body):
    """Return {service_id: [line_number, ...]} for every service ID found in the body.

    Line numbers are 1-indexed relative to the body serialised with two-space
    indentation, so they address the detail file that gets written.
    """
    text = json.dumps(body, indent=2, ensure_ascii=False)
    if "SERVICE-" not in text.upper():
        return {}
    hits = {}
    for i, line in enumerate(text.splitlines(), 1):
        for sid in set(_SERVICE_ID_RE.findall(line)):
            hits.setdefault(sid.upper(), []).append(i)
    return hits


# --------------------------------------------------------------------------
# Configuration sources
# --------------------------------------------------------------------------

def _fetch_settings(cfg, schema_id):
    rows = _pages(cfg, cfg.classic + _CLASSIC_SETTINGS_PATH, "items",
                  {"schemaIds": schema_id, "pageSize": 500})
    return [{"type": "SETTINGS/" + schema_id,
             "id": r.get("objectId"),
             "name": (r.get("value") or {}).get("name")
                     or (r.get("value") or {}).get("summary")
                     or r.get("objectId"),
             "body": r}
            for r in rows]


def _fetch_slos(cfg):
    """Read every objective of the Service-Level Objectives app.

    This API paginates with its own page-key parameter rather than the settings
    API's nextPageKey, so _pages does not apply. Classic builtin:monitoring.slo
    objects are a separate source; the two never overlap, so both are scanned.
    """
    url = cfg.platform + _SLO_API_PATH
    params, rows = {"page-size": 500}, []
    while True:
        page = _get(cfg, url, params)
        rows.extend(r for r in (page.get("slos") or []) if isinstance(r, dict))
        next_key = page.get("nextPageKey")
        if not next_key:
            break
        params = {"page-key": next_key}
    return [{"type": "SLO",
             "id": r.get("id"),
             "name": r.get("name") or r.get("id"),
             "body": r}
            for r in rows]


def _fetch_documents(cfg):
    """
    Fetch dashboards and notebooks, strip cached query results, and detect
    service references inline. Only affected documents are retained in memory.

    Listing asks for tenant-wide visibility first. Without that permission a
    token sees only its own documents, which would present a fraction of the
    tenant as if it were the whole of it, so the fallback degrades the scan to
    partial rather than reporting the smaller set as complete.
    """
    doc_base = cfg.platform + "/platform/document/v1/documents"
    listing_failed, access_warnings = [], []

    def _list_pages(dtype):
        docs, page_key, admin = [], "", True
        while True:
            params = {"page-size": 1000, "filter": "type=='{}'".format(dtype)}
            if page_key:
                params["page-key"] = page_key
            if admin:
                params["admin-access"] = "true"
            try:
                data = _get(cfg, doc_base, params)
            except _ApiError as exc:
                if page_key or admin is False or exc.code not in (401, 403):
                    raise
                # No tenant-wide document permission; retry with whatever the token
                # can see. The warning is only recorded once that retry succeeds --
                # if it fails too, nothing was scanned and the listing failure is
                # the honest description, not "only your own documents".
                admin = False
                data = _get(cfg, doc_base,
                            {"page-size": 1000, "filter": "type=='{}'".format(dtype)})
                access_warnings.append(
                    "tenant-wide {} access unavailable; only documents visible to the "
                    "token were scanned (add the document:documents:admin scope)".format(dtype))
            batch = data.get("documents") or []
            docs.extend(batch)
            page_key = str(data.get("nextPageKey") or "")
            if not page_key:
                break
        return docs, admin

    targets, admin_by_type = [], {}
    for dtype in ("dashboard", "notebook"):
        try:
            docs, admin = _list_pages(dtype)
            admin_by_type[dtype] = admin
            targets.extend((d["id"], d.get("name"), dtype) for d in docs if d.get("id"))
        except Exception as exc:
            listing_failed.append("{}s: {}".format(dtype, exc))
            print("  WARNING: failed to list {}s: {}".format(dtype, exc), flush=True)

    if not targets:
        return 0, [], listing_failed, 0, access_warnings

    print("  Fetching content for {} dashboards/notebooks...".format(len(targets)), flush=True)

    def _content(doc_id, dtype):
        url = doc_base + "/{}/content".format(doc_id)
        params = {"admin-access": "true"} if admin_by_type.get(dtype) else None
        # 30s is generous for a single doc; cfg.timeout (default 60s) would let
        # failing docs block a worker slot for twice as long, collapsing throughput
        # in the tail end of the fetch where slow/erroring docs accumulate.
        timeout = min(cfg.timeout, 30) if cfg.timeout else 30
        return _get(cfg, url, params, timeout=timeout)

    affected, failed, done = [], [], 0
    total = len(targets)
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {pool.submit(_content, doc_id, dtype): (doc_id, name, dtype)
                for doc_id, name, dtype in targets}
        for fut in as_completed(futs):
            doc_id, name, dtype = futs[fut]
            done += 1
            try:
                stripped = _strip_cached_results(fut.result())
                matched_ids = _service_ids_in(stripped)
                if matched_ids:
                    kind = "DASHBOARD" if dtype == "dashboard" else "NOTEBOOK"
                    filtered = _filter_body(stripped, matched_ids, kind)
                    hits = _find_hits(filtered)
                    if hits:
                        affected.append({"type": kind, "id": doc_id, "name": name,
                                         "body": filtered, "hits": hits})
            except Exception:
                failed.append(doc_id)
            if done % 200 == 0 or done == total:
                print("  Content fetch: {}/{} done{}".format(
                    done, total, ", {} failed".format(len(failed)) if failed else ""), flush=True)
    if failed:
        print("  ({}/{} document fetches failed -- check token document:read scope)".format(
            len(failed), total), flush=True)
    return total, affected, listing_failed, len(failed), access_warnings


# --------------------------------------------------------------------------
# Detail files
# --------------------------------------------------------------------------

def _sanitise(text):
    seg = "".join(c if c.isalnum() else "_" for c in text)
    while "__" in seg:
        seg = seg.replace("__", "_")
    return seg.strip("_")


def _write_json(detail_dir, filename, payload):
    os.makedirs(detail_dir, exist_ok=True)
    with open(os.path.join(detail_dir, filename), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return filename


def _write_settings_detail(detail_dir, schema, entries, tenant_name=""):
    """Write a SETTINGS detail file as a JSON array, one file per schema."""
    parts = ["SETTINGS", _sanitise(schema)] + ([tenant_name] if tenant_name else [])
    return _write_json(detail_dir, "_".join(parts) + ".json", entries)


def _write_slo_detail(detail_dir, entries, tenant_name=""):
    """Write the Service-Level Objectives app detail file as a JSON array."""
    parts = ["SLO"] + ([tenant_name] if tenant_name else [])
    return _write_json(detail_dir, "_".join(parts) + ".json", entries)


def _write_dashboard_detail(detail_dir, doc_id, entries, tenant_name=""):
    """Write a DASHBOARD detail file as a JSON array, one file per dashboard."""
    parts = ["DASHBOARD", doc_id] + ([tenant_name] if tenant_name else [])
    return _write_json(detail_dir, "_".join(parts) + ".json", entries)


def _write_notebook_detail(detail_dir, doc_id, entries, tenant_name=""):
    """Write a NOTEBOOK detail file as a JSON array, one file per notebook."""
    parts = ["NOTEBOOK", doc_id] + ([tenant_name] if tenant_name else [])
    return _write_json(detail_dir, "_".join(parts) + ".json", entries)


def _write_category_summary(detail_dir, payload, tenant_name=""):
    """Write the tenant-wide service census and the third-party inventory."""
    parts = ["CATEGORY", "SUMMARY"] + ([tenant_name] if tenant_name else [])
    return _write_json(detail_dir, "_".join(parts) + ".json", payload)


# --------------------------------------------------------------------------
# Report assembly
# --------------------------------------------------------------------------

def _completeness(failed_schemas, listing_failed, fetch_failed_count,
                  access_warnings=(), soft_warnings=()):
    """Grade the scan.

    `partial` is reserved for the case that makes a report misleading: a
    configuration source that could not be read, so an affected config may
    silently be missing. Failures that only cost labelling -- the census, or
    resolving IDs to names -- are reported as warnings without downgrading the
    status, because every affected config is still listed.
    """
    warnings = []
    for s in failed_schemas:
        warnings.append(
            "Configuration source {} could not be read; those configs were not "
            "scanned.".format(s))
    for desc in listing_failed:
        warnings.append("Failed to list {}.".format(desc))
    if fetch_failed_count:
        warnings.append(
            "{} document content fetch(es) failed; those configs were not scanned.".format(
                fetch_failed_count))
    warnings.extend(access_warnings)
    warnings.extend(soft_warnings)

    if failed_schemas or listing_failed or fetch_failed_count or access_warnings:
        status = "partial"
    else:
        status = "complete"
    return {"status": status, "warnings": warnings}


def _make_affected_entry(item_type, item_id, item_name, hits, services):
    return {
        "type":    item_type,
        "id":      item_id,
        "name":    item_name,
        "matches": [{"service_id": sid,
                     "service_name": services.get(sid, {}).get("name", sid),
                     "service_category": services.get(sid, {}).get("category", "unresolved"),
                     "occurrence_count": len(lines)}
                    for sid, lines in hits.items()],
    }


def _build_report(tenant, services, census, census_total, scanned, affected, completeness):
    referenced = {m["service_id"] for c in affected for m in c["matches"]}
    referenced_by_category = {c: 0 for c in _CATEGORY_ORDER}
    for sid in referenced:
        category = services.get(sid, {}).get("category", "unresolved")
        referenced_by_category[category] = referenced_by_category.get(category, 0) + 1
    return {
        "scanned_at":              datetime.now(timezone.utc).isoformat(),
        "tenant":                  tenant,
        "scan_completeness":       completeness,
        "services_on_tenant":      census_total,
        "services_by_category":    census,
        "configs_scanned":         scanned,
        "affected_config_count":   len(affected),
        "affected_service_count":  len(referenced),
        "affected_services_by_category": referenced_by_category,
        "affected_services": [
            {
                "id":               sid,
                "name":             meta["name"],
                "category":         meta["category"],
                "entity_type":      meta.get("entity_type"),
                "service_type":     meta.get("service_type"),
                "service_sub_type": meta.get("service_sub_type"),
            }
            for sid, meta in sorted(services.items()) if sid in referenced
        ],
        "affected_configs":        affected,
    }


def _service_fields(sid, services):
    meta = services.get(sid, {})
    return {
        "service_id":       sid,
        "service_name":     meta.get("name", sid),
        "service_category": meta.get("category", "unresolved"),
        "service_type":     meta.get("service_type"),
        "service_sub_type": meta.get("service_sub_type"),
    }


def _auth(token):
    return {"Authorization": "Api-Token " + token, "Accept": "application/json"}


def run(tenant_url, token, timeout=60, detail_dir=None, lookback="30d", classic_token=None):
    platform, classic = _derive_bases(tenant_url)
    tenant_name = tenant_url.split("//")[-1].split(".")[0]
    cfg = _Cfg(platform, classic, _auth(token), timeout, lookback,
               _auth(classic_token) if classic_token else None)

    if platform != classic:
        print("Platform API : {}".format(platform), flush=True)
        print("Classic  API : {}\n".format(classic), flush=True)

    if _token_kind(token) == "classic":
        print("WARNING: the token supplied for the platform APIs starts with 'dt0c01.', which is\n"
              "         a classic API token. Grail queries, dashboards, notebooks and the SLO app\n"
              "         are platform APIs and will reject it with an SSO error. Create a platform\n"
              "         token (dt0s16.*) instead, or pass this one as --classic-token alongside\n"
              "         a platform token.\n", file=sys.stderr, flush=True)

    _preflight(cfg)

    soft_warnings = []

    # Census first: it is cheap, and the totals frame everything the scan finds.
    print("Counting services on the tenant (lookback {})...".format(lookback), flush=True)
    try:
        census, census_total = _fetch_census(cfg)
        print("  {:,} service(s): {}".format(census_total, ", ".join(
            "{} {}".format(census.get(c, 0), c) for c in _CATEGORY_ORDER if census.get(c))),
            flush=True)
    except Exception as exc:
        census, census_total = {}, None
        soft_warnings.append("Service census could not be read: {}".format(exc))
        print("  WARNING: service census failed: {}".format(exc), file=sys.stderr, flush=True)

    print("\nScanning configurations for SERVICE-* references...", flush=True)

    # Settings and SLO app objects are small, so all are kept in memory.
    failed_schemas = []
    source_tasks = [(s, lambda s=s: _fetch_settings(cfg, s)) for s in _SETTINGS_SCHEMAS]
    source_tasks.append(("Service-Level Objectives app", lambda: _fetch_slos(cfg)))
    config_items = []
    with ThreadPoolExecutor(max_workers=len(source_tasks)) as pool:
        futs = {pool.submit(fn): label for label, fn in source_tasks}
        for fut in as_completed(futs):
            label = futs[fut]
            try:
                items = fut.result()
                config_items.extend(items)
                print("  {:<58} {:>4} item(s)".format(label, len(items)), flush=True)
            except _TrustStoreError:
                raise      # permanent and identical for every source; report it once
            except Exception as exc:
                failed_schemas.append(label)
                print("  {:<58}  ERROR -- {}".format(label, exc), file=sys.stderr, flush=True)

    # Documents: content is stripped and checked inline; only affected docs are kept.
    doc_count, doc_hits, listing_failed, fetch_failed_count, access_warnings = 0, [], [], 0, []
    try:
        doc_count, doc_hits, listing_failed, fetch_failed_count, access_warnings = \
            _fetch_documents(cfg)
        print("  {:<58} {:>4} item(s)".format("Dashboards + Notebooks", doc_count), flush=True)
    except Exception as exc:
        listing_failed = ["all documents: {}".format(exc)]
        print("  {:<58}  ERROR -- {}".format("Dashboards + Notebooks", exc),
              file=sys.stderr, flush=True)

    # Nothing readable means nothing can be concluded. Reporting zero affected
    # configs here would be indistinguishable from a genuinely clean tenant.
    if not config_items and doc_count == 0 and (failed_schemas or listing_failed):
        raise _ScanAborted(
            "every configuration source failed; no part of the tenant could be read.\n"
            "The scan produced nothing to report -- this is not a clean result.\n"
            "Check the errors above: the usual causes are a token missing the required "
            "scopes, or a wrong tenant URL.")

    # Detect references, then resolve only the IDs that were actually found.
    config_hits = [(item, _find_hits(item["body"])) for item in config_items]
    config_hits = [(item, hits) for item, hits in config_hits if hits]

    referenced_ids = set()
    for _, hits in config_hits:
        referenced_ids.update(hits)
    for item in doc_hits:
        referenced_ids.update(item["hits"])

    services = {}
    if referenced_ids:
        print("\nResolving {} referenced service ID(s)...".format(len(referenced_ids)), flush=True)
        services, resolve_warnings = _resolve_services(cfg, referenced_ids)
        soft_warnings.extend(resolve_warnings)
        unresolved = sum(1 for m in services.values() if m["category"] == "unresolved")
        unknown = sum(1 for m in services.values() if m["category"] == "unknown")
        if unresolved:
            print("  {} referenced service(s) no longer exist on the tenant.".format(unresolved),
                  flush=True)
        if unknown:
            print("  {} referenced service(s) could not be looked up; their category is "
                  "unknown.".format(unknown), file=sys.stderr, flush=True)

    affected = []
    settings_entries, slo_entries = {}, []

    for item, hits in config_hits:
        affected.append(_make_affected_entry(item["type"], item["id"], item["name"],
                                             hits, services))
        if not detail_dir:
            continue
        if item["type"] == "SLO":
            for sid in hits:
                entry = {"_slo_id": item["id"], "name": item["name"], "value": item["body"]}
                entry.update(_service_fields(sid, services))
                slo_entries.append(entry)
        else:
            schema = item["type"][len("SETTINGS/"):]
            for sid in hits:
                entry = {"_schema_id": schema, "objectId": item["id"],
                         "value": item["body"].get("value")}
                entry.update(_service_fields(sid, services))
                settings_entries.setdefault(schema, []).append(entry)

    notebook_entries, dashboard_entries = {}, {}
    for item in doc_hits:
        affected.append(_make_affected_entry(item["type"], item["id"], item["name"],
                                             item["hits"], services))
        if not detail_dir:
            continue
        bucket = notebook_entries if item["type"] == "NOTEBOOK" else dashboard_entries
        content_key = "sections" if item["type"] == "NOTEBOOK" else "tiles"
        for sid in item["hits"]:
            filtered = _filter_body(item["body"], {sid}, item["type"])
            entry = {"_doc_id": item["id"]}
            entry.update(_service_fields(sid, services))
            entry[content_key] = filtered.get(content_key, [] if content_key == "sections" else {})
            bucket.setdefault(item["id"], []).append(entry)

    if detail_dir:
        for schema, entries in settings_entries.items():
            _write_settings_detail(detail_dir, schema, entries, tenant_name)
        if slo_entries:
            _write_slo_detail(detail_dir, slo_entries, tenant_name)
        for doc_id, entries in notebook_entries.items():
            _write_notebook_detail(detail_dir, doc_id, entries, tenant_name)
        for doc_id, entries in dashboard_entries.items():
            _write_dashboard_detail(detail_dir, doc_id, entries, tenant_name)

        third_party, tp_truncated = [], False
        try:
            third_party, tp_truncated = _fetch_third_party(cfg)
        except Exception as exc:
            soft_warnings.append("Third-party service inventory could not be read: {}".format(exc))
        if tp_truncated:
            soft_warnings.append(
                "Third-party service inventory hit the {:,}-record cap.".format(_THIRD_PARTY_CAP))
        _write_category_summary(detail_dir, {
            "lookback":              lookback,
            "services_on_tenant":    census_total,
            "services_by_category":  census,
            "third_party_services":  third_party,
        }, tenant_name)
        if third_party:
            print("  Third-party (WEB_REQUEST_WATCHED) services written: {:>4}".format(
                len(third_party)), flush=True)

    completeness = _completeness(failed_schemas, listing_failed, fetch_failed_count,
                                 access_warnings, soft_warnings)
    return _build_report(tenant_url, services, census, census_total,
                         len(config_items) + doc_count, affected, completeness)


def _lookback(value):
    if not re.fullmatch(r"\d+[mhd]", value or ""):
        raise argparse.ArgumentTypeError(
            "lookback must be a number followed by m, h, or d (e.g. 30d), got: {!r}".format(value))
    return value


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description="Scan Dynatrace configurations for hardcoded service entity IDs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--tenant",   required=True, help="Tenant URL (.apps. or classic domain)")
    ap.add_argument("--token",    default=None,
                    help="Platform API token (dt0s16.XXX); overrides DT_PLATFORM_TOKEN")
    ap.add_argument("--classic-token", default=None,
                    help="Optional classic API token (dt0c01.XXX) used only for the classic "
                         "settings API; overrides DT_CLASSIC_TOKEN. Use when your platform "
                         "token lacks settings.read")
    ap.add_argument("--output",   default=None,
                    help="Output JSON report (default: <script-dir>/report_<tenant>.json)")
    ap.add_argument("--timeout",  type=int, default=60,
                    help="HTTP socket timeout in seconds (default: 60; 0 = no timeout)")
    ap.add_argument("--lookback", type=_lookback, default="30d",
                    help="Entity lookback window for the service census and ID resolution "
                         "(default: 30d)")
    args = ap.parse_args()

    token = args.token or os.environ.get("DT_PLATFORM_TOKEN")
    if not token:
        ap.error("provide --token or set the DT_PLATFORM_TOKEN environment variable")
    classic_token = args.classic_token or os.environ.get("DT_CLASSIC_TOKEN")

    sock_timeout = args.timeout if args.timeout > 0 else None

    tenant_name = args.tenant.split("//")[-1].split(".")[0]
    output = args.output or str(_SCRIPT_DIR / "report_{}.json".format(tenant_name))
    base, _ = os.path.splitext(os.path.abspath(output))
    detail_dir = base + "_details"

    try:
        t0 = time.monotonic()
        report = run(args.tenant, token, timeout=sock_timeout, detail_dir=detail_dir,
                     lookback=args.lookback, classic_token=classic_token)
        elapsed = time.monotonic() - t0
    except _TrustStoreError as exc:
        print("\nFatal: {}".format(exc), file=sys.stderr)
        sys.exit(1)
    except _ScanAborted as exc:
        print("\nScan aborted: {}".format(exc), file=sys.stderr)
        sys.exit(1)
    except _ApiError as exc:
        print("\nFatal API error: {}".format(exc), file=sys.stderr)
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as exc:
        print("\nFatal: {}".format(exc), file=sys.stderr)
        sys.exit(1)

    with open(output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    n = report["affected_config_count"]
    total = report["services_on_tenant"]
    sep = "-" * 62
    print("\n" + sep)
    print("Services on tenant      : {}".format("unknown" if total is None else total))
    print("Configs scanned         : {}".format(report["configs_scanned"]))
    print("Affected configs        : {}".format(n))
    print("Affected services       : {}".format(report["affected_service_count"]))
    by_cat = report["affected_services_by_category"]
    for category in _CATEGORY_ORDER:
        if by_cat.get(category):
            print("  {:<22}: {}".format(category, by_cat[category]))
    print("Scan completeness       : {}".format(report["scan_completeness"]["status"]))
    print("Duration                : {:.1f}s".format(elapsed))
    print("Report written to       : {}".format(output))
    if n > 0:
        print("Detail files written to : {}/".format(detail_dir))
    print(sep)

    if report["affected_configs"]:
        print("\nAffected configs:")
        for c in report["affected_configs"]:
            print("  [{}] {}".format(c["type"], c["name"]))
            matches = c["matches"]
            for m in matches[:5]:
                print("    -> {} ({}, {}) -- {} occurrence(s)".format(
                    m["service_name"], m["service_id"], m["service_category"],
                    m["occurrence_count"]))
            if len(matches) > 5:
                print("    ... and {} more service reference(s) -- see detail file".format(
                    len(matches) - 5))

    sys.exit(0)


if __name__ == "__main__":
    main()
