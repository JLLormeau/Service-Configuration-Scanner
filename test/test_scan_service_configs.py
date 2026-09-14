#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for scan_service_configs.py."""
import argparse
import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))
import scan_service_configs as scanner  # noqa: E402

DB = "SERVICE-1111111111111111"
TP = "SERVICE-2222222222222222"
OP = "SERVICE-3333333333333333"
DET = "SERVICE-4444444444444444"
GONE = "SERVICE-5555555555555555"

_SERVICES = {
    DB:  {"name": "orders-db", "entity_type": "SERVICE", "service_type": "DATABASE_SERVICE",
          "service_sub_type": None, "category": "database"},
    TP:  {"name": "api.stripe.com", "entity_type": "SERVICE",
          "service_type": "WEB_REQUEST_SERVICE", "service_sub_type": "WEB_REQUEST_WATCHED",
          "category": "third_party"},
    DET: {"name": "checkout", "entity_type": "SERVICE", "service_type": "WEB_REQUEST_SERVICE",
          "service_sub_type": None, "category": "detected"},
    GONE: {"name": GONE, "entity_type": None, "service_type": None,
           "service_sub_type": None, "category": "unresolved"},
}


def _cfg(timeout=60, lookback="30d"):
    return scanner._Cfg("https://abc.apps.dynatrace.com", "https://abc.live.dynatrace.com",
                        {"Authorization": "Api-Token t"}, timeout, lookback)


class TestServiceIdRegex(unittest.TestCase):
    def test_matches_canonical_id(self):
        self.assertEqual(scanner._SERVICE_ID_RE.findall(f"id={DB}"), [DB])

    def test_matches_lowercase_hex(self):
        self.assertEqual(
            scanner._SERVICE_ID_RE.findall("SERVICE-00000000000000ab"),
            ["SERVICE-00000000000000ab"])

    def test_rejects_short_id(self):
        self.assertEqual(scanner._SERVICE_ID_RE.findall("SERVICE-DB001"), [])

    def test_rejects_non_hex(self):
        self.assertEqual(scanner._SERVICE_ID_RE.findall("SERVICE-ZZZZZZZZZZZZZZZZ"), [])

    def test_rejects_longer_id_with_same_prefix(self):
        """The old substring match reported SERVICE-<16hex> inside a 17-char id."""
        self.assertEqual(scanner._SERVICE_ID_RE.findall(DB + "0"), [])

    def test_rejects_embedded_in_larger_token(self):
        self.assertEqual(scanner._SERVICE_ID_RE.findall("XSERVICE-1111111111111111"), [])

    def test_matches_inside_json_quoting(self):
        self.assertEqual(scanner._service_ids_in({"entity": DB}), {DB})


class TestCategorise(unittest.TestCase):
    def test_database_wins_over_everything(self):
        self.assertEqual(
            scanner._categorise("DATABASE_SERVICE", "WEB_REQUEST_WATCHED", True), "database")

    def test_third_party(self):
        self.assertEqual(
            scanner._categorise("WEB_REQUEST_SERVICE", "WEB_REQUEST_WATCHED", True),
            "third_party")

    def test_opaque(self):
        self.assertEqual(scanner._categorise("WEB_REQUEST_SERVICE", None, True), "opaque")

    def test_detected_when_flag_false(self):
        self.assertEqual(scanner._categorise("WEB_REQUEST_SERVICE", None, False), "detected")

    def test_detected_when_flag_null(self):
        """A null isExternalService must fall through to detected, not be guessed."""
        self.assertEqual(scanner._categorise("WEB_REQUEST_SERVICE", None, None), "detected")


class TestFindHits(unittest.TestCase):
    def test_returns_line_numbers(self):
        hits = scanner._find_hits({"a": DB, "b": {"c": TP}})
        self.assertEqual(set(hits), {DB, TP})
        self.assertTrue(all(isinstance(n, int) and n > 0 for n in hits[DB]))

    def test_counts_repeated_occurrences(self):
        hits = scanner._find_hits({"a": DB, "b": DB})
        self.assertEqual(len(hits[DB]), 2)

    def test_empty_when_no_service_reference(self):
        self.assertEqual(scanner._find_hits({"a": "no ids here"}), {})

    def test_uppercases_the_key(self):
        hits = scanner._find_hits({"a": "SERVICE-00000000000000ab"})
        self.assertIn("SERVICE-00000000000000AB", hits)


class TestFilterBody(unittest.TestCase):
    def test_notebook_keeps_only_matching_sections(self):
        body = {"sections": [{"q": DB}, {"q": "unrelated"}], "other": 1}
        out = scanner._filter_body(body, {DB}, "NOTEBOOK")
        self.assertEqual(out["sections"], [{"q": DB}])
        self.assertEqual(out["other"], 1)

    def test_dashboard_keeps_only_matching_tiles(self):
        body = {"tiles": {"0": {"q": DB}, "1": {"q": "unrelated"}}}
        out = scanner._filter_body(body, {DB}, "DASHBOARD")
        self.assertEqual(list(out["tiles"]), ["0"])

    def test_dashboard_without_tiles(self):
        self.assertEqual(scanner._filter_body({}, {DB}, "DASHBOARD")["tiles"], {})

    def test_settings_pass_through(self):
        body = {"value": {"filter": DB}}
        self.assertEqual(scanner._filter_body(body, {DB}, "SETTINGS/x"), body)


class TestStripCachedResults(unittest.TestCase):
    def test_removes_state_result_but_keeps_input(self):
        body = {"sections": [{"state": {"input": {"q": DB}, "result": {"records": [{"id": TP}]}}}]}
        out = scanner._strip_cached_results(body)
        state = out["sections"][0]["state"]
        self.assertIn("input", state)
        self.assertNotIn("result", state)

    def test_cached_result_id_is_not_reported(self):
        body = {"sections": [{"state": {"input": {"q": "fetch spans"},
                                        "result": {"records": [{"id": TP}]}}}]}
        self.assertEqual(scanner._find_hits(scanner._strip_cached_results(body)), {})


class TestCompleteness(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(scanner._completeness([], [], 0)["status"], "complete")

    def test_failed_schema_is_partial(self):
        result = scanner._completeness(["builtin:monitoring.slo"], [], 0)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["warnings"]), 1)

    def test_failed_document_fetch_is_partial(self):
        self.assertEqual(scanner._completeness([], [], 3)["status"], "partial")

    def test_limited_document_access_is_partial(self):
        result = scanner._completeness([], [], 0, access_warnings=["only own documents"])
        self.assertEqual(result["status"], "partial")

    def test_soft_warning_does_not_downgrade(self):
        """A census or name-resolution failure costs labelling, not coverage."""
        result = scanner._completeness([], [], 0, soft_warnings=["census failed"])
        self.assertEqual(result["status"], "complete")
        self.assertIn("census failed", result["warnings"])


class TestReportSchema(unittest.TestCase):
    def _report(self):
        affected = [scanner._make_affected_entry(
            "SETTINGS/builtin:monitoring.slo", "obj-1", "My SLO",
            {DB: [3], GONE: [7, 9]}, _SERVICES)]
        census = {"database": 2, "third_party": 1, "opaque": 0, "detected": 40}
        return scanner._build_report("https://abc.apps.dynatrace.com", _SERVICES, census, 43,
                                     25, affected, scanner._completeness([], [], 0))

    def test_top_level_keys(self):
        report = self._report()
        for key in ("scanned_at", "tenant", "scan_completeness", "services_on_tenant",
                    "services_by_category", "configs_scanned", "affected_config_count",
                    "affected_service_count", "affected_services_by_category",
                    "affected_services", "affected_configs"):
            self.assertIn(key, report)

    def test_counts(self):
        report = self._report()
        self.assertEqual(report["services_on_tenant"], 43)
        self.assertEqual(report["configs_scanned"], 25)
        self.assertEqual(report["affected_config_count"], 1)
        self.assertEqual(report["affected_service_count"], 2)

    def test_only_referenced_services_are_listed(self):
        ids = {s["id"] for s in self._report()["affected_services"]}
        self.assertEqual(ids, {DB, GONE})

    def test_affected_services_carry_category(self):
        by_id = {s["id"]: s for s in self._report()["affected_services"]}
        self.assertEqual(by_id[DB]["category"], "database")
        self.assertEqual(by_id[GONE]["category"], "unresolved")

    def test_affected_services_by_category(self):
        counts = self._report()["affected_services_by_category"]
        self.assertEqual(counts["database"], 1)
        self.assertEqual(counts["unresolved"], 1)
        self.assertEqual(counts["detected"], 0)

    def test_match_occurrence_count(self):
        matches = {m["service_id"]: m for m in self._report()["affected_configs"][0]["matches"]}
        self.assertEqual(matches[DB]["occurrence_count"], 1)
        self.assertEqual(matches[GONE]["occurrence_count"], 2)
        self.assertEqual(matches[GONE]["service_category"], "unresolved")


class TestCensus(unittest.TestCase):
    def test_buckets_and_totals(self):
        records = [
            {"serviceType": "DATABASE_SERVICE", "serviceSubType": None,
             "isExternalService": True, "count": 2},
            {"serviceType": "WEB_REQUEST_SERVICE", "serviceSubType": "WEB_REQUEST_WATCHED",
             "isExternalService": True, "count": 5},
            {"serviceType": "WEB_REQUEST_SERVICE", "serviceSubType": None,
             "isExternalService": True, "count": 1},
            {"serviceType": "WEB_REQUEST_SERVICE", "serviceSubType": None,
             "isExternalService": None, "count": 40},
        ]
        with patch.object(scanner, "_dql_execute", return_value=records):
            counts, total = scanner._fetch_census(_cfg())
        self.assertEqual(counts, {"database": 2, "third_party": 5, "opaque": 1, "detected": 40})
        self.assertEqual(total, 48)

    def test_query_states_the_lookback_window(self):
        seen = {}

        def _capture(cfg, query):
            seen["query"] = query
            return []

        with patch.object(scanner, "_dql_execute", side_effect=_capture):
            scanner._fetch_census(_cfg(lookback="90d"))
        self.assertIn("from: now()-90d", seen["query"])
        self.assertIn("summarize", seen["query"])


class TestResolveServices(unittest.TestCase):
    def test_resolves_and_categorises(self):
        records = [{"id": DB, "entity.name": "orders-db", "entity.type": "SERVICE",
                    "serviceType": "DATABASE_SERVICE", "serviceSubType": None,
                    "isExternalService": True}]
        with patch.object(scanner, "_dql_execute", return_value=records):
            resolved, warnings = scanner._resolve_services(_cfg(), {DB})
        self.assertEqual(warnings, [])
        self.assertEqual(resolved[DB]["name"], "orders-db")
        self.assertEqual(resolved[DB]["category"], "database")

    def test_missing_id_becomes_unresolved(self):
        with patch.object(scanner, "_dql_execute", return_value=[]):
            resolved, _ = scanner._resolve_services(_cfg(), {GONE})
        self.assertEqual(resolved[GONE]["category"], "unresolved")
        self.assertEqual(resolved[GONE]["name"], GONE)

    def test_failed_lookup_is_unknown_not_unresolved(self):
        """"I could not check" and "the service is gone" lead to opposite conclusions."""
        with patch.object(scanner, "_dql_execute", side_effect=RuntimeError("boom")):
            resolved, warnings = scanner._resolve_services(_cfg(), {DB})
        self.assertEqual(resolved[DB]["category"], "unknown")
        self.assertEqual(len(warnings), 1)
        self.assertIn("not as missing", warnings[0])

    def test_missing_and_failed_are_distinguished_in_one_run(self):
        """One batch resolves, one comes back empty, one errors -- three outcomes."""
        record = {"id": DB, "entity.name": "orders-db", "entity.type": "SERVICE",
                  "serviceType": "DATABASE_SERVICE", "serviceSubType": None,
                  "isExternalService": True}

        def _per_id(cfg, query):
            if DB in query:
                return [record]       # found
            if OP in query:
                return []             # looked up, genuinely absent
            raise RuntimeError("boom")  # lookup never completed

        # One ID per batch, so each takes an independent path.
        with patch.object(scanner, "_RESOLVE_CHUNK", 1), \
             patch.object(scanner, "_dql_execute", side_effect=_per_id):
            resolved, warnings = scanner._resolve_services(_cfg(), {DB, OP, GONE})

        self.assertEqual(resolved[DB]["category"], "database")
        self.assertEqual(resolved[OP]["category"], "unresolved")
        self.assertEqual(resolved[GONE]["category"], "unknown")
        self.assertEqual(len(warnings), 1)

    def test_batches_large_id_sets(self):
        ids = {"SERVICE-{:016X}".format(i) for i in range(scanner._RESOLVE_CHUNK + 10)}
        calls = []

        def _capture(cfg, query):
            calls.append(query)
            return []

        with patch.object(scanner, "_dql_execute", side_effect=_capture):
            scanner._resolve_services(_cfg(), ids)
        self.assertEqual(len(calls), 2)
        self.assertIn("filter in(id,", calls[0])


class TestThirdParty(unittest.TestCase):
    def test_returns_inventory(self):
        records = [{"id": TP, "entity.name": "api.stripe.com", "entity.type": "SERVICE",
                    "serviceType": "WEB_REQUEST_SERVICE",
                    "serviceSubType": "WEB_REQUEST_WATCHED"}]
        with patch.object(scanner, "_dql_execute", return_value=records):
            services, truncated = scanner._fetch_third_party(_cfg())
        self.assertFalse(truncated)
        self.assertEqual(services[0]["name"], "api.stripe.com")


class TestHttpLayer(unittest.TestCase):
    """The network half, which the scan depends on and which is otherwise unexercised."""

    def _response(self, payload):
        stream = MagicMock()
        stream.read.return_value = json.dumps(payload).encode()
        stream.__enter__ = lambda s: s
        stream.__exit__ = lambda s, *a: False
        return stream

    def test_get_returns_parsed_json(self):
        with patch.object(scanner.urllib.request, "urlopen",
                          return_value=self._response({"ok": True})):
            self.assertEqual(scanner._get(_cfg(), "https://x/y"), {"ok": True})

    def test_get_retries_on_429(self):
        import urllib.error
        err = urllib.error.HTTPError("https://x/y", 429, "slow down", {}, io.BytesIO(b"rate"))
        with patch.object(scanner.time, "sleep"), \
             patch.object(scanner.urllib.request, "urlopen",
                          side_effect=[err, self._response({"ok": 1})]) as opener:
            self.assertEqual(scanner._get(_cfg(), "https://x/y"), {"ok": 1})
        self.assertEqual(opener.call_count, 2)

    def test_get_raises_api_error_with_code(self):
        import urllib.error
        err = urllib.error.HTTPError("https://x/y", 403, "denied", {}, io.BytesIO(b"nope"))
        with patch.object(scanner.urllib.request, "urlopen", side_effect=err):
            with self.assertRaises(scanner._ApiError) as ctx:
                scanner._get(_cfg(), "https://x/y")
        self.assertEqual(ctx.exception.code, 403)

    def test_dql_execute_returns_records(self):
        payload = {"state": "SUCCEEDED", "result": {"records": [{"id": DB}]}}
        with patch.object(scanner.urllib.request, "urlopen",
                          return_value=self._response(payload)):
            self.assertEqual(scanner._dql_execute(_cfg(), "fetch x"), [{"id": DB}])

    def test_dql_execute_rejects_non_succeeded_state(self):
        with patch.object(scanner.time, "sleep"), \
             patch.object(scanner.urllib.request, "urlopen",
                          return_value=self._response({"state": "FAILED"})):
            with self.assertRaises(scanner._ApiError):
                scanner._dql_execute(_cfg(), "fetch x")

    def test_dql_server_budget_follows_timeout(self):
        captured = {}

        def _open(req, timeout=None):
            captured["body"] = json.loads(req.data.decode())
            return self._response({"state": "SUCCEEDED", "result": {"records": []}})

        with patch.object(scanner.urllib.request, "urlopen", side_effect=_open):
            scanner._dql_execute(_cfg(timeout=120), "fetch x")
        self.assertEqual(captured["body"]["requestTimeoutMilliseconds"], 120000)


class TestAuthRouting(unittest.TestCase):
    def test_platform_headers_by_default(self):
        self.assertEqual(scanner._hdrs_for(_cfg(), "https://abc.apps.dynatrace.com/x"),
                         {"Authorization": "Api-Token t"})

    def test_classic_token_used_for_the_classic_host_only(self):
        cfg = _cfg()._replace(hdrs=scanner._auth("plat"),
                              classic_hdrs=scanner._auth("clsc"))
        self.assertEqual(
            scanner._hdrs_for(cfg, "https://abc.live.dynatrace.com/api/v2/settings/objects"
                              )["Authorization"], "Api-Token clsc")
        self.assertEqual(
            scanner._hdrs_for(cfg, "https://abc.apps.dynatrace.com/platform/x"
                              )["Authorization"], "Api-Token plat")

    def test_returns_a_copy_so_callers_cannot_mutate_config(self):
        cfg = _cfg()
        scanner._hdrs_for(cfg, "https://abc.apps.dynatrace.com/x")["Content-Type"] = "x"
        self.assertNotIn("Content-Type", cfg.hdrs)


class TestTrustStoreHandling(unittest.TestCase):
    """A machine whose Python has no CA bundle fails every request identically."""

    def _url_error(self):
        import ssl as _ssl
        import urllib.error
        cause = _ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
               "unable to get local issuer certificate (_ssl.c:1000)")
        return urllib.error.URLError(cause)

    def test_recognises_a_wrapped_certificate_error(self):
        self.assertTrue(scanner._is_cert_error(self._url_error()))

    def test_recognises_it_by_message_alone(self):
        self.assertTrue(scanner._is_cert_error(
            RuntimeError("[SSL: CERTIFICATE_VERIFY_FAILED] nope")))

    def test_ignores_unrelated_errors(self):
        self.assertFalse(scanner._is_cert_error(RuntimeError("connection reset")))

    def test_get_does_not_retry_a_certificate_error(self):
        with patch.object(scanner.time, "sleep") as slept, \
             patch.object(scanner.urllib.request, "urlopen",
                          side_effect=self._url_error()) as opener:
            with self.assertRaises(scanner._TrustStoreError):
                scanner._get(_cfg(), "https://abc.apps.dynatrace.com/x")
        self.assertEqual(opener.call_count, 1)
        slept.assert_not_called()

    def test_dql_does_not_retry_a_certificate_error(self):
        with patch.object(scanner.time, "sleep") as slept, \
             patch.object(scanner.urllib.request, "urlopen",
                          side_effect=self._url_error()) as opener:
            with self.assertRaises(scanner._TrustStoreError):
                scanner._dql_execute(_cfg(), "fetch x")
        self.assertEqual(opener.call_count, 1)
        slept.assert_not_called()

    def test_error_message_carries_actionable_guidance(self):
        message = str(scanner._TrustStoreError("abc.apps.dynatrace.com", "verify failed"))
        self.assertIn("SSL_CERT_FILE=/etc/ssl/cert.pem", message)
        self.assertIn("Install Certificates.command", message)
        self.assertIn("certifi", message)

    def test_preflight_translates_a_handshake_failure(self):
        import ssl as _ssl
        with patch.object(scanner.socket, "create_connection",
                          side_effect=_ssl.SSLCertVerificationError("verify failed")):
            with self.assertRaises(scanner._TrustStoreError):
                scanner._preflight(_cfg())

    def test_preflight_reports_an_unreachable_host_as_an_api_error(self):
        with patch.object(scanner.socket, "create_connection",
                          side_effect=OSError("Name or service not known")):
            with self.assertRaises(scanner._ApiError):
                scanner._preflight(_cfg())

    def test_preflight_passes_when_the_handshake_succeeds(self):
        with patch.object(scanner.socket, "create_connection", return_value=MagicMock()), \
             patch.object(scanner.ssl, "create_default_context", return_value=MagicMock()):
            self.assertIsNone(scanner._preflight(_cfg()))


class TestScanAborted(unittest.TestCase):
    def test_aborts_when_no_source_could_be_read(self):
        """Zero affected configs after total failure must not read as a clean tenant."""
        with patch.object(scanner, "_preflight"), \
             patch.object(scanner, "_fetch_census", side_effect=RuntimeError("no")), \
             patch.object(scanner, "_fetch_settings", side_effect=RuntimeError("denied")), \
             patch.object(scanner, "_fetch_slos", side_effect=RuntimeError("denied")), \
             patch.object(scanner, "_fetch_documents",
                          return_value=(0, [], ["dashboards: denied"], 0, [])), \
             patch("sys.stdout", new_callable=MagicMock), \
             patch("sys.stderr", new_callable=MagicMock):
            with self.assertRaises(scanner._ScanAborted):
                scanner.run("https://abc.apps.dynatrace.com", "tok")

    def test_empty_tenant_without_failures_still_reports(self):
        with patch.object(scanner, "_preflight"), \
             patch.object(scanner, "_fetch_census", return_value=({}, 0)), \
             patch.object(scanner, "_fetch_settings", return_value=[]), \
             patch.object(scanner, "_fetch_slos", return_value=[]), \
             patch.object(scanner, "_fetch_documents", return_value=(0, [], [], 0, [])), \
             patch("sys.stdout", new_callable=MagicMock):
            report = scanner.run("https://abc.apps.dynatrace.com", "tok")
        self.assertEqual(report["affected_config_count"], 0)
        self.assertEqual(report["scan_completeness"]["status"], "complete")


class TestFetchDocuments(unittest.TestCase):
    def setUp(self):
        """The fetch narrates progress on stdout; the assertions are on its return value."""
        patcher = patch("sys.stdout", new_callable=MagicMock)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _responses(self, admin_ok=True):
        """Return a _get stand-in serving two document types and their content."""
        def _get(cfg, url, params=None, timeout=None):
            params = params or {}
            if url.endswith("/documents"):
                if params.get("admin-access") and not admin_ok:
                    raise scanner._ApiError(url, 403, "forbidden")
                dtype = "dashboard" if "dashboard" in params.get("filter", "") else "notebook"
                return {"documents": [{"id": f"{dtype}-1", "name": f"my {dtype}"}]}
            if url.endswith("dashboard-1/content"):
                return {"tiles": {"0": {"q": DB}, "1": {"q": "none"}}}
            return {"sections": [{"q": TP}]}
        return _get

    def test_finds_references_in_both_document_types(self):
        with patch.object(scanner, "_get", side_effect=self._responses()):
            total, affected, listing_failed, failed, access = scanner._fetch_documents(_cfg())
        self.assertEqual(total, 2)
        self.assertEqual(listing_failed, [])
        self.assertEqual(failed, 0)
        self.assertEqual(access, [])
        by_kind = {a["type"]: a for a in affected}
        self.assertEqual(set(by_kind), {"DASHBOARD", "NOTEBOOK"})
        self.assertEqual(list(by_kind["DASHBOARD"]["body"]["tiles"]), ["0"])
        self.assertIn(TP, by_kind["NOTEBOOK"]["hits"])

    def test_falls_back_and_warns_without_tenant_wide_access(self):
        with patch.object(scanner, "_get", side_effect=self._responses(admin_ok=False)):
            _, _, _, _, access = scanner._fetch_documents(_cfg())
        self.assertEqual(len(access), 2)
        self.assertIn("document:documents:admin", access[0])

    def test_no_access_warning_when_the_fallback_also_fails(self):
        """Nothing was scanned, so "only your own documents" would be misleading."""
        def _always_denied(cfg, url, params=None, timeout=None):
            raise scanner._ApiError(url, 403, "forbidden")

        with patch.object(scanner, "_get", side_effect=_always_denied):
            total, _, listing_failed, _, access = scanner._fetch_documents(_cfg())
        self.assertEqual(total, 0)
        self.assertEqual(access, [])
        self.assertEqual(len(listing_failed), 2)

    def test_listing_failure_is_recorded(self):
        def _boom(cfg, url, params=None, timeout=None):
            raise scanner._ApiError(url, 500, "server error")

        with patch.object(scanner, "_get", side_effect=_boom):
            total, affected, listing_failed, _, _ = scanner._fetch_documents(_cfg())
        self.assertEqual(total, 0)
        self.assertEqual(affected, [])
        self.assertEqual(len(listing_failed), 2)


class TestDetailFileWriting(unittest.TestCase):
    def test_settings_filename_is_sanitised(self):
        with tempfile.TemporaryDirectory() as tmp:
            name = scanner._write_settings_detail(tmp, "builtin:monitoring.slo", [], "abc")
        self.assertEqual(name, "SETTINGS_builtin_monitoring_slo_abc.json")

    def test_settings_filename_matches_checked_in_fixture(self):
        """Guards the fixture against drifting from what the writer emits."""
        fixture_dir = Path(__file__).parent / "fixtures" / "report_abc_details"
        with tempfile.TemporaryDirectory() as tmp:
            name = scanner._write_settings_detail(tmp, "builtin:monitoring.slo", [], "abc")
        self.assertTrue((fixture_dir / name).exists(), f"missing fixture {name}")

    def test_writers_produce_expected_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(scanner._write_slo_detail(tmp, [], "abc"), "SLO_abc.json")
            self.assertEqual(scanner._write_notebook_detail(tmp, "nb-1", [], "abc"),
                             "NOTEBOOK_nb-1_abc.json")
            self.assertEqual(scanner._write_dashboard_detail(tmp, "d-1", [], "abc"),
                             "DASHBOARD_d-1_abc.json")
            self.assertEqual(scanner._write_category_summary(tmp, {}, "abc"),
                             "CATEGORY_SUMMARY_abc.json")

    def test_detail_content_round_trips(self):
        entries = [{"_doc_id": "nb-1", "service_id": DB, "service_name": "orders-db",
                    "service_category": "database", "sections": [{"q": DB}]}]
        with tempfile.TemporaryDirectory() as tmp:
            scanner._write_notebook_detail(tmp, "nb-1", entries, "abc")
            with open(os.path.join(tmp, "NOTEBOOK_nb-1_abc.json"), encoding="utf-8") as fh:
                loaded = json.load(fh)
        self.assertEqual(loaded, entries)

    def test_creates_the_detail_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "nested", "details")
            scanner._write_category_summary(target, {"a": 1}, "abc")
            self.assertTrue(os.path.isdir(target))


class TestLookbackArgument(unittest.TestCase):
    def test_accepts_valid_durations(self):
        for value in ("30d", "12h", "90m", "1d"):
            self.assertEqual(scanner._lookback(value), value)

    def test_rejects_invalid(self):
        for value in ("30", "d30", "30w", "", "1d; drop"):
            with self.assertRaises(argparse.ArgumentTypeError):
                scanner._lookback(value)


class TestDeriveBases(unittest.TestCase):
    def test_production_saas(self):
        self.assertEqual(scanner._derive_bases("https://abc.apps.dynatrace.com"),
                         ("https://abc.apps.dynatrace.com", "https://abc.live.dynatrace.com"))

    def test_dev_staging(self):
        self.assertEqual(scanner._derive_bases("https://abc.dev.apps.dynatracelabs.com/"),
                         ("https://abc.dev.apps.dynatracelabs.com",
                          "https://abc.dev.dynatracelabs.com"))

    def test_classic_domain_unchanged(self):
        self.assertEqual(scanner._derive_bases("https://abc.live.dynatrace.com"),
                         ("https://abc.live.dynatrace.com", "https://abc.live.dynatrace.com"))


if __name__ == "__main__":
    unittest.main()
