#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for service_config_report.py."""
import json
import shutil
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import service_config_report as reporter  # noqa: E402

_FIXTURES = Path(__file__).parent / "fixtures"

TENANT = "https://abc.apps.dynatrace.com"
DB = "SERVICE-1111111111111111"
TP = "SERVICE-2222222222222222"
DET = "SERVICE-4444444444444444"
GONE = "SERVICE-5555555555555555"


class TestNormalizeTenantUrl(unittest.TestCase):
    def test_production_saas(self):
        self.assertEqual(reporter._normalize_tenant_url(TENANT), "https://abc.dynatrace.com")

    def test_dev_staging(self):
        self.assertEqual(
            reporter._normalize_tenant_url("https://abc.dev.apps.dynatracelabs.com"),
            "https://abc.dev.dynatracelabs.com")

    def test_classic_domain_unchanged(self):
        self.assertEqual(reporter._normalize_tenant_url("https://abc.live.dynatrace.com"),
                         "https://abc.live.dynatrace.com")


class TestUrlBuilders(unittest.TestCase):
    def test_settings_url(self):
        self.assertEqual(reporter._settings_url("https://abc.dynatrace.com", "obj-1"),
                         "https://abc.dynatrace.com/ui/settings?objectId=obj-1")

    def test_notebook_url(self):
        self.assertEqual(reporter._notebook_url(TENANT, "nb-1"),
                         f"{TENANT}/ui/apps/dynatrace.notebooks/notebook/nb-1")

    def test_dashboard_url(self):
        self.assertEqual(reporter._dashboard_url(TENANT, "d-1"),
                         f"{TENANT}/ui/apps/dynatrace.dashboards/dashboard/d-1")

    def test_service_url(self):
        self.assertEqual(reporter._service_url(TENANT, DB),
                         f"{TENANT}/ui/apps/dynatrace.classic.services/ui/entity/{DB}")

    def test_slo_url_encodes_the_id_in_the_fragment(self):
        url = reporter._slo_url(TENANT, "slo-1")
        self.assertTrue(url.startswith(
            f"{TENANT}/ui/intent/dynatrace.service.level.objectives/view-slo#"))
        fragment = urllib.parse.unquote(url.split("#", 1)[1])
        self.assertEqual(json.loads(fragment), {"dt.slo.id": "slo-1"})

    def test_builders_return_none_without_an_id(self):
        for builder in (reporter._settings_url, reporter._notebook_url,
                        reporter._dashboard_url, reporter._service_url, reporter._slo_url):
            self.assertIsNone(builder(TENANT, ""))

    def test_trailing_slash_is_not_doubled(self):
        self.assertEqual(reporter._notebook_url(TENANT + "/", "nb-1"),
                         f"{TENANT}/ui/apps/dynatrace.notebooks/notebook/nb-1")


class TestSettingName(unittest.TestCase):
    def test_prefers_name(self):
        self.assertEqual(reporter._setting_name({"value": {"name": "N", "summary": "S"}}), "N")

    def test_falls_back_to_summary(self):
        self.assertEqual(reporter._setting_name({"value": {"summary": "S"}}), "S")

    def test_falls_back_to_object_id(self):
        self.assertEqual(reporter._setting_name({"value": {}, "objectId": "obj-1"}), "obj-1")

    def test_empty_when_nothing_available(self):
        self.assertEqual(reporter._setting_name({}), "")


class TestLoadReport(unittest.TestCase):
    def test_loads_existing_report(self):
        report = reporter._load_report(_FIXTURES, "abc")
        self.assertEqual(report["services_on_tenant"], 48)

    def test_exits_when_missing(self):
        with tempfile.TemporaryDirectory() as tmp, patch("sys.stderr", new_callable=MagicMock):
            with self.assertRaises(SystemExit) as ctx:
                reporter._load_report(Path(tmp), "abc")
        self.assertEqual(ctx.exception.code, 1)


class TestLoadDetails(unittest.TestCase):
    def setUp(self):
        self.details = _FIXTURES / "report_abc_details"
        (self.settings, self.slos, self.notebooks,
         self.dashboards, self.summary) = reporter._load_details(self.details, "abc")

    def test_settings_grouped_by_schema(self):
        self.assertEqual(list(self.settings), ["builtin:monitoring.slo"])
        entry = self.settings["builtin:monitoring.slo"][0]
        self.assertEqual(entry["service_id"], DET)
        self.assertEqual(entry["service_category"], "detected")

    def test_slo_app_objectives(self):
        self.assertEqual(list(self.slos), ["slo-app-1"])
        self.assertEqual(self.slos["slo-app-1"]["name"], "Orders latency")
        self.assertEqual(self.slos["slo-app-1"]["services"][0]["service_id"], DB)

    def test_notebook_entries_are_aggregated_per_document(self):
        self.assertEqual(list(self.notebooks), ["nb-uuid-1"])
        ids = {s["service_id"] for s in self.notebooks["nb-uuid-1"]["services"]}
        self.assertEqual(ids, {DB, TP})

    def test_dashboard_entries(self):
        self.assertEqual(self.dashboards["dash-uuid-1"]["services"][0]["service_category"],
                         "unresolved")

    def test_category_summary(self):
        self.assertEqual(self.summary["services_on_tenant"], 48)
        self.assertEqual(len(self.summary["third_party_services"]), 2)

    def test_missing_directory_returns_empties(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = reporter._load_details(Path(tmp) / "nope", "abc")
        self.assertEqual(result, ({}, {}, {}, {}, {}))

    def test_ignores_details_for_another_tenant(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "details"
            shutil.copytree(self.details, target)
            result = reporter._load_details(target, "other")
        self.assertEqual(result, ({}, {}, {}, {}, {}))


def _out(**overrides):
    base = {
        "scanned_at": "2026-09-14T09:00:00+00:00",
        "tenant": TENANT,
        "settings_base_url": "https://abc.dynatrace.com",
        "scan_completeness": {"status": "complete", "warnings": []},
        "scan_summary": {
            "services_on_tenant": 48,
            "services_by_category": {"database": 2, "detected": 40},
            "configs_scanned": 25,
            "affected_config_count": 4,
            "affected_service_count": 4,
            "affected_services_by_category": {"database": 1, "detected": 1, "unresolved": 1},
        },
        "settings_by_schema": {},
        "slos": [],
        "notebooks": [],
        "dashboards": [],
        "affected_services": [],
        "third_party_services": [],
    }
    base.update(overrides)
    return base


class TestWriteHtmlReport(unittest.TestCase):
    def _render(self, out):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "r.html"
            reporter._write_html_report(out, target)
            return target.read_text(encoding="utf-8")

    def test_renders_every_registered_section(self):
        content = self._render(_out())
        for title, _ in reporter._SECTIONS:
            self.assertIn(title.split("(")[0].strip(), content)

    def test_title_and_heading(self):
        content = self._render(_out())
        self.assertIn("Service Configuration Report", content)
        self.assertIn(TENANT, content)

    def test_empty_sections_say_none_found(self):
        self.assertIn("None found.", self._render(_out()))

    def test_overview_counts(self):
        content = self._render(_out())
        self.assertIn("25 configuration(s) scanned", content)
        self.assertIn("Detected (internal) services", content)

    def test_categories_section_groups_services(self):
        out = _out(affected_services=[
            {"id": DB, "name": "orders-db", "category": "database",
             "service_type": "DATABASE_SERVICE"},
            {"id": GONE, "name": GONE, "category": "unresolved", "service_type": None},
        ])
        content = self._render(out)
        self.assertIn("Database services (1)", content)
        self.assertIn("Unresolved", content)

    def test_settings_rows_link_to_the_classic_domain(self):
        out = _out(settings_by_schema={"builtin:monitoring.slo": [
            {"objectId": "obj-1", "value": {"name": "My SLO"}, "service_id": DET,
             "service_name": "checkout", "service_category": "detected"}]})
        content = self._render(out)
        self.assertIn("https://abc.dynatrace.com/ui/settings?objectId=obj-1", content)
        self.assertIn("My SLO", content)

    def test_slo_section_links_through_an_intent_url(self):
        out = _out(slos=[{"id": "slo-1", "name": "Orders latency",
                          "services": [{"service_id": DB, "service_name": "orders-db"}]}])
        self.assertIn("/ui/intent/dynatrace.service.level.objectives/view-slo#",
                      self._render(out))

    def test_documents_list_their_services(self):
        out = _out(
            notebooks=[{"id": "nb-1", "name": "NB", "url": reporter._notebook_url(TENANT, "nb-1"),
                        "services": [{"service_id": DB, "service_name": "orders-db"}]}],
            dashboards=[{"id": "d-1", "name": "Dash", "url": None,
                         "services": [{"service_id": TP, "service_name": "api.stripe.com"}]}])
        content = self._render(out)
        self.assertIn("orders-db", content)
        self.assertIn("api.stripe.com", content)

    def test_third_party_inventory(self):
        out = _out(third_party_services=[{"id": TP, "name": "api.stripe.com"}])
        self.assertIn("api.stripe.com", self._render(out))

    def test_banner_shown_for_partial_scan(self):
        out = _out(scan_completeness={"status": "partial", "warnings": ["a source failed"]})
        content = self._render(out)
        self.assertIn("scan completeness is 'partial'", content)
        self.assertIn("a source failed", content)

    def test_no_banner_when_complete(self):
        self.assertNotIn("class='banner'", self._render(_out()))

    def test_escapes_html_in_names(self):
        out = _out(affected_services=[
            {"id": DB, "name": "<script>alert(1)</script>", "category": "database",
             "service_type": None}])
        content = self._render(out)
        self.assertNotIn("<script>alert(1)</script>", content)
        self.assertIn("&lt;script&gt;", content)

    def test_handles_non_ascii(self):
        out = _out(affected_services=[
            {"id": DB, "name": "café-服务", "category": "database", "service_type": None}])
        self.assertIn("café-服务", self._render(out))

    def test_csp_hash_matches_the_inline_style(self):
        content = self._render(_out())
        self.assertIn(f"style-src &#x27;sha256-{reporter._style_csp_hash()}&#x27;", content)


class TestStyleCspHash(unittest.TestCase):
    def test_is_stable(self):
        self.assertEqual(reporter._style_csp_hash(), reporter._style_csp_hash())

    def test_tracks_the_stylesheet(self):
        original = reporter._STYLE_CSS
        before = reporter._style_csp_hash()
        try:
            reporter._STYLE_CSS = original + "\n  .x { color: red; }"
            self.assertNotEqual(before, reporter._style_csp_hash())
        finally:
            reporter._STYLE_CSS = original


class TestMain(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        shutil.copy(_FIXTURES / "report_abc.json", self.dir / "report_abc.json")
        shutil.copytree(_FIXTURES / "report_abc_details", self.dir / "report_abc_details")
        self.addCleanup(self._tmp.cleanup)

    def _run(self, *extra):
        argv = ["service_config_report.py", "--tenant", TENANT,
                "--report-dir", str(self.dir)] + list(extra)
        with patch("sys.argv", argv), \
             patch("sys.stdout", new_callable=MagicMock), \
             patch("sys.stderr", new_callable=MagicMock):
            with self.assertRaises(SystemExit) as ctx:
                reporter.main()
        return ctx.exception.code

    def _patch_status(self, status, warnings=("something failed",)):
        path = self.dir / "report_abc.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        report["scan_completeness"] = {"status": status, "warnings": list(warnings)}
        path.write_text(json.dumps(report), encoding="utf-8")

    def test_exits_zero_and_writes_both_outputs(self):
        self.assertEqual(self._run(), 0)
        self.assertTrue((self.dir / "service_config_report_abc.json").exists())
        self.assertTrue((self.dir / "service_config_report_abc.html").exists())

    def test_consolidated_json_shape(self):
        self._run()
        out = json.loads((self.dir / "service_config_report_abc.json").read_text(encoding="utf-8"))
        self.assertEqual(out["tenant"], TENANT)
        self.assertEqual(out["scan_summary"]["services_on_tenant"], 48)
        self.assertEqual(out["scan_summary"]["lookback"], "30d")
        self.assertEqual(len(out["affected_services"]), 4)
        self.assertEqual(len(out["third_party_services"]), 2)
        self.assertEqual([s["id"] for s in out["slos"]], ["slo-app-1"])

    def test_document_names_come_from_the_scan_report(self):
        self._run()
        out = json.loads((self.dir / "service_config_report_abc.json").read_text(encoding="utf-8"))
        self.assertEqual(out["notebooks"][0]["name"], "Payments investigation")
        self.assertEqual(out["dashboards"][0]["name"], "Service overview")

    def test_html_lists_all_four_config_types(self):
        self._run()
        content = (self.dir / "service_config_report_abc.html").read_text(encoding="utf-8")
        for expected in ("Checkout availability", "Orders latency",
                         "Payments investigation", "Service overview"):
            self.assertIn(expected, content)

    def test_partial_scan_is_refused_by_default(self):
        self._patch_status("partial")
        self.assertEqual(self._run(), 1)
        self.assertFalse((self.dir / "service_config_report_abc.json").exists())

    def test_partial_scan_proceeds_with_allow_incomplete(self):
        self._patch_status("partial")
        self.assertEqual(self._run("--allow-incomplete"), 0)
        content = (self.dir / "service_config_report_abc.html").read_text(encoding="utf-8")
        self.assertIn("something failed", content)

    def test_rejects_a_non_url_tenant(self):
        argv = ["service_config_report.py", "--tenant", "abc", "--report-dir", str(self.dir)]
        with patch("sys.argv", argv), patch("sys.stderr", new_callable=MagicMock):
            with self.assertRaises(SystemExit) as ctx:
                reporter.main()
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_scan_report_exits_one(self):
        (self.dir / "report_abc.json").unlink()
        self.assertEqual(self._run(), 1)


if __name__ == "__main__":
    unittest.main()
