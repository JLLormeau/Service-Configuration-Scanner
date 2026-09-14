#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Service Configuration Report

Reads the JSON report and detail files produced by scan_service_configs.py and
generates a consolidated JSON + HTML report, grouped by configuration type and
by service category.

Usage:
    python3 service_config_report.py --tenant https://abc.apps.dynatrace.com
    python3 service_config_report.py --tenant https://abc.apps.dynatrace.com --report-dir /path/to/reports

Output is written next to the scan report:
    service_config_report_{tenant_name}.json
    service_config_report_{tenant_name}.html

Exit codes:
    0  completed successfully
    1  error (missing scan report, or a partial scan without --allow-incomplete)
"""
import argparse
import base64
import hashlib
import html
import json
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

if sys.version_info < (3, 7):
    sys.exit("Python 3.7 or later is required.")

_CATEGORY_ORDER = ["database", "third_party", "opaque", "detected", "unresolved", "unknown"]

_CATEGORY_LABELS = {
    "database":    "Database services",
    "third_party": "Third-party services",
    "opaque":      "Opaque services",
    "detected":    "Detected (internal) services",
    "unresolved":  "Unresolved -- referenced but no longer on the tenant",
    "unknown":     "Unknown -- lookup failed, category could not be determined",
}

_STYLE_CSS = (
    "  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }\n"
    "  h1   { font-size: 1.4rem; margin-bottom: 0.25rem; }\n"
    "  .meta { color: #666; font-size: 0.85rem; margin-bottom: 2rem; }\n"
    "  section { border: 1px solid #ddd; border-radius: 6px; padding: 1rem 1.25rem;\n"
    "             margin-bottom: 1.5rem; }\n"
    "  h2   { font-size: 1.1rem; margin: 0 0 0.75rem; }\n"
    "  .svc-id { font-weight: normal; color: #555; font-size: 0.9rem; margin-left: 0.5rem; }\n"
    "  table.refs { border-collapse: collapse; width: 100%; font-size: 0.875rem; }\n"
    "  table.refs th { background: #f4f4f4; text-align: left; padding: 0.4rem 0.6rem;\n"
    "                   border-bottom: 2px solid #ccc; white-space: nowrap; }\n"
    "  table.refs td { padding: 0.35rem 0.6rem; border-bottom: 1px solid #eee;\n"
    "                   vertical-align: top; }\n"
    "  table.refs tr:last-child td { border-bottom: none; }\n"
    "  .schema { font-family: monospace; color: #0055aa; white-space: nowrap; }\n"
    "  .none      { color: #888; font-style: italic; }\n"
    "  .sub-title { font-size: 0.95rem; font-weight: 600; margin: 1rem 0 0.4rem; color: #333; }\n"
    "  .banner    { background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px;\n"
    "               padding: 0.75rem 1rem; margin-bottom: 1.5rem; font-size: 0.875rem; }\n"
    "  .banner b  { color: #856404; }\n"
    "  .cat       { font-family: monospace; color: #444; white-space: nowrap; }"
)

_NONE = "<p class='none'>None found.</p>"


def _style_csp_hash():
    content = "\n" + _STYLE_CSS + "\n"
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def _normalize_tenant_url(url):
    """Strip the 'apps' subdomain from a Dynatrace platform URL.

    https://abc.apps.dynatrace.com         -> https://abc.dynatrace.com
    https://abc.dev.apps.dynatracelabs.com -> https://abc.dev.dynatracelabs.com
    """
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.replace(".apps.", ".")
    return parsed._replace(netloc=netloc).geturl()


def _settings_url(base_url, object_id):
    if not object_id:
        return None
    return f"{base_url.rstrip('/')}/ui/settings?objectId={object_id}"


def _notebook_url(base_url, doc_id):
    if not doc_id:
        return None
    return f"{base_url.rstrip('/')}/ui/apps/dynatrace.notebooks/notebook/{doc_id}"


def _dashboard_url(base_url, doc_id):
    if not doc_id:
        return None
    return f"{base_url.rstrip('/')}/ui/apps/dynatrace.dashboards/dashboard/{doc_id}"


def _service_url(base_url, service_id):
    if not service_id:
        return None
    return f"{base_url.rstrip('/')}/ui/apps/dynatrace.classic.services/ui/entity/{service_id}"


def _slo_url(base_url, slo_id):
    """The Service-Level Objectives app opens an objective through an intent URL
    rather than a path segment, so the id travels in the encoded fragment."""
    if not slo_id:
        return None
    payload = json.dumps({"dt.slo.id": slo_id}, separators=(",", ":"))
    fragment = urllib.parse.quote(payload, safe="")
    return (f"{base_url.rstrip('/')}/ui/intent/dynatrace.service.level.objectives"
            f"/view-slo#{fragment}")


def _load_report(report_dir, tenant_name):
    path = report_dir / f"report_{tenant_name}.json"
    if not path.exists():
        print(f"Error: scan report not found: {path}", file=sys.stderr)
        print("Run scan_service_configs.py first.", file=sys.stderr)
        sys.exit(1)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _load_details(details_dir, tenant_name):
    """Return (settings_by_schema, slo_by_id, nb_by_id, dash_by_id, category_summary)."""
    settings_by_schema: dict = {}
    slo_by_id: dict = {}
    nb_by_id: dict = {}
    dash_by_id: dict = {}
    category_summary: dict = {}

    if not details_dir.exists():
        return settings_by_schema, slo_by_id, nb_by_id, dash_by_id, category_summary

    def _read(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def _service_ref(entry):
        return {
            "service_id":       entry.get("service_id"),
            "service_name":     entry.get("service_name"),
            "service_category": entry.get("service_category"),
        }

    suffix = f"_{tenant_name}.json"
    for detail_file in sorted(details_dir.iterdir()):
        if detail_file.suffix != ".json":
            continue
        name = detail_file.name

        if name == f"CATEGORY_SUMMARY_{tenant_name}.json":
            category_summary = _read(detail_file) or {}
            continue

        if not name.endswith(suffix):
            continue
        raw = _read(detail_file)
        if not isinstance(raw, list):
            continue

        if name.startswith("SETTINGS_"):
            for entry in raw:
                schema_id = entry.get("_schema_id") or ""
                record = {"objectId": entry.get("objectId"), "value": entry.get("value")}
                record.update(_service_ref(entry))
                record["service_type"] = entry.get("service_type")
                record["service_sub_type"] = entry.get("service_sub_type")
                settings_by_schema.setdefault(schema_id, []).append(record)

        elif name.startswith("SLO_"):
            for entry in raw:
                slo_id = entry.get("_slo_id") or ""
                slot = slo_by_id.setdefault(slo_id, {"name": entry.get("name"), "services": []})
                slot["services"].append(_service_ref(entry))

        elif name.startswith("NOTEBOOK_"):
            for entry in raw:
                doc_id = entry.get("_doc_id") or ""
                nb_by_id.setdefault(doc_id, {"services": []})["services"].append(
                    _service_ref(entry))

        elif name.startswith("DASHBOARD_"):
            for entry in raw:
                doc_id = entry.get("_doc_id") or ""
                dash_by_id.setdefault(doc_id, {"services": []})["services"].append(
                    _service_ref(entry))

    return settings_by_schema, slo_by_id, nb_by_id, dash_by_id, category_summary


def _setting_name(entry):
    value = entry.get("value") or {}
    return value.get("name") or value.get("summary") or entry.get("objectId") or ""


# --------------------------------------------------------------------------
# HTML rendering
# --------------------------------------------------------------------------

def _link(url, label):
    if not url:
        return html.escape(label)
    return f"<a href='{html.escape(url)}'>{html.escape(label)}</a>"


def _table(headers, rows):
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    return (f"<table class='refs'><thead><tr>{head}</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>")


def _section(title, inner):
    return f"<section><h2>{html.escape(title)}</h2>{inner or _NONE}</section>"


def _service_names(services):
    return ", ".join(s.get("service_name") or s.get("service_id") or "" for s in services)


def _overview_inner(out, _urls):
    summary = out.get("scan_summary") or {}
    total = summary.get("services_on_tenant")
    by_cat = summary.get("services_by_category") or {}
    affected_by_cat = summary.get("affected_services_by_category") or {}
    rows = []
    for category in _CATEGORY_ORDER:
        on_tenant = by_cat.get(category)
        affected = affected_by_cat.get(category) or 0
        if not on_tenant and not affected:
            continue
        rows.append(
            f"<tr><td>{html.escape(_CATEGORY_LABELS.get(category, category))}</td>"
            f"<td class='cat'>{html.escape(category)}</td>"
            f"<td>{'--' if on_tenant is None else on_tenant}</td>"
            f"<td>{affected}</td></tr>"
        )
    if not rows:
        return ""
    table = _table(["Category", "Key", "On tenant", "Referenced by configs"], rows)
    total_text = "unknown" if total is None else f"{total:,}"
    return (f"<p class='meta'>{html.escape(str(summary.get('configs_scanned', 0)))} configuration(s) "
            f"scanned &middot; {html.escape(total_text)} service(s) on the tenant &middot; "
            f"{html.escape(str(summary.get('affected_config_count', 0)))} affected configuration(s)"
            f"</p>{table}")


def _settings_inner(out, urls):
    blocks = []
    for schema_id, entries in (out.get("settings_by_schema") or {}).items():
        rows = []
        for entry in entries:
            url = _settings_url(urls["settings"], entry.get("objectId"))
            rows.append(
                f"<tr><td>{_link(url, _setting_name(entry))}</td>"
                f"<td>{html.escape(entry.get('service_name') or '')}</td>"
                f"<td class='cat'>{html.escape(entry.get('service_category') or '')}</td>"
                f"<td class='svc-id'>{html.escape(entry.get('service_id') or '')}</td></tr>"
            )
        blocks.append(
            f"<h3 class='sub-title'>{html.escape(schema_id)}</h3>"
            + _table(["Setting name / summary", "Service", "Category", "Service ID"], rows)
        )
    return "".join(blocks)


def _slos_inner(out, urls):
    rows = []
    for slo in out.get("slos") or []:
        url = _slo_url(urls["tenant"], slo.get("id"))
        rows.append(
            f"<tr><td>{_link(url, slo.get('name') or slo.get('id') or '')}</td>"
            f"<td>{html.escape(_service_names(slo.get('services', [])))}</td></tr>"
        )
    return _table(["Name", "Services"], rows) if rows else ""


def _documents_inner(key, url_builder):
    def build(out, urls):
        rows = []
        for doc in out.get(key) or []:
            url = url_builder(urls["tenant"], doc.get("id"))
            rows.append(
                f"<tr><td>{_link(url, doc.get('name') or doc.get('id') or '')}</td>"
                f"<td>{html.escape(_service_names(doc.get('services', [])))}</td></tr>"
            )
        return _table(["Name", "Services"], rows) if rows else ""
    return build


def _affected_services_inner(out, urls):
    services = out.get("affected_services") or []
    by_category = {}
    for svc in services:
        by_category.setdefault(svc.get("category") or "unresolved", []).append(svc)
    blocks = []
    for category in _CATEGORY_ORDER:
        entries = by_category.get(category)
        if not entries:
            continue
        rows = []
        for svc in entries:
            url = _service_url(urls["tenant"], svc.get("id"))
            rows.append(
                f"<tr><td>{_link(url, svc.get('name') or svc.get('id') or '')}</td>"
                f"<td class='svc-id'>{html.escape(svc.get('id') or '')}</td>"
                f"<td>{html.escape(svc.get('service_type') or '')}</td></tr>"
            )
        blocks.append(
            f"<h3 class='sub-title'>{html.escape(_CATEGORY_LABELS.get(category, category))} "
            f"({len(entries)})</h3>"
            + _table(["Name", "Service ID", "Service type"], rows)
        )
    return "".join(blocks)


def _third_party_inner(out, urls):
    rows = []
    for svc in out.get("third_party_services") or []:
        url = _service_url(urls["tenant"], svc.get("id"))
        rows.append(
            f"<tr><td class='svc-id'>{_link(url, svc.get('id') or '')}</td>"
            f"<td>{html.escape(svc.get('name') or '')}</td></tr>"
        )
    return _table(["Service ID", "Name"], rows) if rows else ""


#: Ordered registry of report sections. Adding a section is one entry here; the
#: page body is a loop rather than a hand-unrolled block per section.
_SECTIONS = [
    ("Overview",                                      _overview_inner),
    ("Settings",                                      _settings_inner),
    ("Service-Level Objectives app",                  _slos_inner),
    ("Notebooks",                                     _documents_inner("notebooks", _notebook_url)),
    ("Dashboards",                                    _documents_inner("dashboards", _dashboard_url)),
    ("Referenced services by category",               _affected_services_inner),
    ("Third-party services on the tenant (WEB_REQUEST_WATCHED)", _third_party_inner),
]


def _write_html_report(out, output_file):
    tenant     = html.escape(out["tenant"])
    scanned_at = html.escape(out["scanned_at"])
    csp = (
        f"default-src 'none'; "
        f"style-src 'sha256-{_style_csp_hash()}'; "
        f"base-uri 'none'"
    )

    urls = {
        "tenant":   out["tenant"],
        "settings": out.get("settings_base_url", out["tenant"]),
    }

    completeness = out.get("scan_completeness", {})
    status   = completeness.get("status", "complete")
    warnings = completeness.get("warnings", [])
    if status != "complete":
        items = "".join(f"<li>{html.escape(w)}</li>" for w in warnings)
        banner = (
            f"<div class='banner'><b>Warning: scan completeness is '{html.escape(status)}'."
            f" This report may be missing affected configs.</b><ul>{items}</ul></div>"
        )
    else:
        banner = ""

    body = "\n".join(_section(title, builder(out, urls)) for title, builder in _SECTIONS)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{html.escape(csp)}">
<title>Service Configuration Report — {tenant}</title>
<style>
{_STYLE_CSS}
</style>
</head>
<body>
<h1>Service Configuration Report — {tenant}</h1>
<p class="meta">Scanned at {scanned_at}</p>
{banner}
{body}
</body>
</html>
"""
    output_file.write_text(page, encoding="utf-8")


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description="Build a consolidated JSON + HTML report from a scan_service_configs run.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--tenant",     required=True,
                    help="Tenant URL (e.g. https://abc.apps.dynatrace.com)")
    ap.add_argument("--report-dir", default=None,
                    help="Directory holding the scan report (default: script's own directory)")
    ap.add_argument("--allow-incomplete", action="store_true",
                    help="Process the report even if scan_completeness is not 'complete'. "
                         "Results may be missing affected configs.")
    args = ap.parse_args()

    tenant_url = args.tenant.rstrip("/")
    parsed = urllib.parse.urlparse(tenant_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        ap.error(f"--tenant must be a valid URL (e.g. https://abc.apps.dynatrace.com), "
                 f"got: {args.tenant!r}")
    tenant_name       = parsed.netloc.split(".")[0]
    settings_base_url = _normalize_tenant_url(tenant_url)

    report_dir  = Path(args.report_dir) if args.report_dir else Path(__file__).parent
    details_dir = report_dir / f"report_{tenant_name}_details"

    report = _load_report(report_dir, tenant_name)

    completeness  = report.get("scan_completeness", {})
    scan_status   = completeness.get("status", "complete")
    scan_warnings = completeness.get("warnings", [])
    if scan_status != "complete":
        print(f"\nWARNING: source scan completeness is '{scan_status}':", file=sys.stderr)
        for w in scan_warnings:
            print(f"  - {w}", file=sys.stderr)
        if scan_status == "partial" and not args.allow_incomplete:
            print(
                "\nError: refusing to generate a report from a partial scan — results may silently"
                " omit affected configs. Fix the scan errors and re-run, or pass"
                " --allow-incomplete to override.", file=sys.stderr)
            sys.exit(1)

    doc_names = {c["id"]: c.get("name") for c in report.get("affected_configs", [])}

    print(f"Loading detail files from: {details_dir}")
    settings_by_schema, slo_by_id, nb_by_id, dash_by_id, category_summary = \
        _load_details(details_dir, tenant_name)

    setting_count = sum(len(v) for v in settings_by_schema.values())
    print(f"  Settings: {setting_count} reference(s) across {len(settings_by_schema)} schema(s).")
    print(f"  SLO app objectives: {len(slo_by_id)}.")
    print(f"  Notebooks: {len(nb_by_id)}.")
    print(f"  Dashboards: {len(dash_by_id)}.")
    print(f"  Third-party services on tenant: "
          f"{len(category_summary.get('third_party_services') or [])}.")

    def _docs(by_id, url_builder):
        return [{
            "id":       doc_id,
            "name":     doc_names.get(doc_id),
            "url":      url_builder(tenant_url, doc_id),
            "services": data["services"],
        } for doc_id, data in by_id.items()]

    slos = [{
        "id":       slo_id,
        "name":     data.get("name") or doc_names.get(slo_id),
        "url":      _slo_url(tenant_url, slo_id),
        "services": data["services"],
    } for slo_id, data in slo_by_id.items()]

    out = {
        "scanned_at":    datetime.now(timezone.utc).isoformat(),
        "tenant":        tenant_url,
        "source_report": str(report_dir / f"report_{tenant_name}.json"),
        "scan_summary": {
            "lookback":                      category_summary.get("lookback"),
            "services_on_tenant":            report.get("services_on_tenant"),
            "services_by_category":          report.get("services_by_category") or {},
            "configs_scanned":               report.get("configs_scanned", 0),
            "affected_config_count":         report.get("affected_config_count", 0),
            "affected_service_count":        report.get("affected_service_count", 0),
            "affected_services_by_category": report.get("affected_services_by_category") or {},
        },
        "settings_by_schema":   settings_by_schema,
        "slos":                 slos,
        "notebooks":            _docs(nb_by_id, _notebook_url),
        "dashboards":           _docs(dash_by_id, _dashboard_url),
        "affected_services":    report.get("affected_services") or [],
        "third_party_services": category_summary.get("third_party_services") or [],
    }

    json_file = report_dir / f"service_config_report_{tenant_name}.json"
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)

    html_file = json_file.with_suffix(".html")
    _write_html_report({**out, "settings_base_url": settings_base_url,
                        "scan_completeness": completeness}, html_file)

    print(f"\nJSON report : {json_file}")
    print(f"HTML report : {html_file}")
    sys.exit(0)


if __name__ == "__main__":
    main()
