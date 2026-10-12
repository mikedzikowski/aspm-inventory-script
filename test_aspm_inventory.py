#!/usr/bin/env python3
"""
Offline tests for the ASPM inventory parsing layer.

No credentials or network access required: these exercise
build_application_view / build_interfaces_and_flows against synthetic assets,
so a refactor is caught without a live tenant. The live-data invariant checks
in aspm_fleet_report.py are complementary, not a substitute.

Run: python3 test_aspm_inventory.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

from aspm_application_inventory import (
    FETCH_ALL,
    MAX_IDS_PER_REQUEST,
    RETRYABLE_STATUS,
    AuthError,
    FalconClient,
    ScopeError,
    build_application_view,
    build_interfaces_and_flows,
    parse_configuration,
    print_report,
    truncation_status,
)
from aspm_fleet_report import app_label, validate


def make_asset(findings=None, summary=None, relationships=None, insights=None,
               deployment=None, technologies=None):
    config = {
        "deployment": deployment if deployment is not None else {
            "deploymentProvider": "aws",
            "deploymentType": "AWS Lambda Function",
            "cloudAssetResourceId": "arn:aws:lambda:us-east-1:1:function:f",
            "cloudAccount": "1",
            "cloudRegion": "us-east-1",
        },
        "technologies": technologies if technologies is not None else ["Python"],
        "embeddedFindings": findings or {},
    }
    if summary is not None:
        config["summary"] = summary
    return {
        "id": "CID|aspm|1|us-east-1|ASPM::Application|abc",
        "resource_id": "abc",
        "resource_name": "unit-test-app",
        "resource_type": "ASPM::Application",
        "account_id": "1",
        "region": "us-east-1",
        "active": True,
        "first_seen": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "tags": {},
        "relationships": relationships or [],
        "cloud_context": {"insights": {"external": insights or []}},
        "configuration": json.dumps(config),
    }


class PackageCveJoin(unittest.TestCase):
    def test_joins_packages_to_cve_details(self):
        view = build_application_view(make_asset({
            "vulnerable_packages": [
                {"name": "urllib3", "version": "1.26.4",
                 "vulnerabilities": [{"cve_id": "CVE-1"}, {"cve_id": "CVE-2"}]},
            ],
            "vulnerabilities": [
                {"cve_id": "CVE-1", "reachable": True, "severity": "HIGH",
                 "exprt_rating": "LOW", "cvss_v3_score": {"base_score": 7.5}},
                {"cve_id": "CVE-2", "reachable": True, "severity": "LOW",
                 "exprt_rating": "LOW", "cvss_v3_score": {"base_score": 3.1}},
            ],
        }, summary={"vulnerabilities": 2}))
        pkg = view["packages_with_reachable_cves"][0]
        self.assertEqual(pkg["cve_count"], 2)
        self.assertEqual(view["summary"]["reachable_cve_count"], 2)
        self.assertEqual(pkg["cves"][0]["severity"], "HIGH")
        self.assertTrue(view["summary"]["integrity_summary_count_matches"])

    def test_one_cve_across_two_versions_counts_once(self):
        """Shared CVEs make pair count exceed unique count; summary must be unique."""
        view = build_application_view(make_asset({
            "vulnerable_packages": [
                {"name": "urllib3", "version": "1.26.4", "vulnerabilities": [{"cve_id": "CVE-1"}]},
                {"name": "urllib3", "version": "2.7.0", "vulnerabilities": [{"cve_id": "CVE-1"}]},
            ],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True, "severity": "HIGH"}],
        }, summary={"vulnerabilities": 1}))
        pairs = sum(p["cve_count"] for p in view["packages_with_reachable_cves"])
        self.assertEqual(pairs, 2)
        self.assertEqual(view["summary"]["reachable_cve_count"], 1)
        self.assertEqual(view["summary"]["packages_with_reachable_cves"], 2)
        self.assertEqual(view["summary"]["distinct_package_names"], 1)

    def test_orphaned_package_cve_is_flagged(self):
        view = build_application_view(make_asset({
            "vulnerable_packages": [
                {"name": "p", "version": "1", "vulnerabilities": [{"cve_id": "CVE-MISSING"}]},
            ],
            "vulnerabilities": [],
        }))
        self.assertEqual(
            view["summary"]["integrity_orphaned_package_cves"],
            [{"package": "p", "cve_id": "CVE-MISSING"}],
        )
        self.assertFalse(view["packages_with_reachable_cves"][0]["cves"][0]["detail_available"])

    def test_unreachable_record_is_flagged(self):
        view = build_application_view(make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": False}],
        }, summary={"vulnerabilities": 1}))
        self.assertEqual(view["summary"]["integrity_unreachable_records"], ["CVE-1"])


class SummaryCounting(unittest.TestCase):
    def test_absent_vendor_count_with_no_findings_is_agreement(self):
        """Vendor omits summary.vulnerabilities when an app has no findings."""
        view = build_application_view(make_asset({}))
        self.assertTrue(view["summary"]["integrity_summary_count_matches"])

    def test_absent_vendor_count_with_findings_is_disagreement(self):
        view = build_application_view(make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True}],
        }))
        self.assertFalse(view["summary"]["integrity_summary_count_matches"])

    def test_missing_rating_is_absent_not_unknown(self):
        """UNKNOWN is a real vendor exprt_rating, so it must not be the fallback."""
        view = build_application_view(make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [
                {"cve_id": "CVE-1", "reachable": True, "exprt_rating": "UNKNOWN"},
                {"cve_id": "CVE-2", "reachable": True},
            ],
        }, summary={"vulnerabilities": 2}))
        counts = view["summary"]["cve_by_exprt_rating"]
        self.assertEqual(counts.get("UNKNOWN"), 1, "vendor UNKNOWN must stay distinct")
        self.assertEqual(counts.get("ABSENT"), 1, "missing rating must not merge into UNKNOWN")


class HostCorrelation(unittest.TestCase):
    def test_relationship_becomes_hosting_asset(self):
        view = build_application_view(make_asset(relationships=[{
            "crn": "aws|1|us-east-1|AWS::Lambda::Function|arn:x",
            "resource_id": "arn:x",
            "resource_type": "AWS::Lambda::Function",
            "relationship_name": "is deployed by",
        }]))
        self.assertTrue(view["summary"]["has_hosting_asset"])
        self.assertEqual(view["deployment"]["hosting_assets"][0]["resource_id"], "arn:x")

    def test_no_relationship_reports_gap(self):
        view = build_application_view(make_asset())
        self.assertFalse(view["summary"]["has_hosting_asset"])
        self.assertEqual(view["deployment"]["hosting_assets"], [])

    def test_accesses_edge_is_not_a_hosting_asset(self):
        """relationships[] mixes edge types; only 'is deployed by' is a host."""
        view = build_application_view(make_asset(relationships=[{
            "crn": "aws|1|global|global|AWS::S3::Bucket|b",
            "resource_id": "b",
            "resource_type": "AWS::S3::Bucket",
            "relationship_name": "accesses",
        }]))
        self.assertFalse(view["summary"]["has_hosting_asset"],
                         "an 'accesses' edge must not count as host correlation")
        self.assertEqual(view["deployment"]["hosting_assets"], [])
        self.assertEqual(len(view["deployment"]["other_relationships"]), 1)
        self.assertEqual(view["summary"]["other_relationship_count"], 1)

    def test_mixed_edges_separate_cleanly(self):
        view = build_application_view(make_asset(relationships=[
            {"resource_id": "arn:lambda", "resource_type": "AWS::Lambda::Function",
             "relationship_name": "is deployed by", "crn": "c1"},
            {"resource_id": "bucket", "resource_type": "AWS::S3::Bucket",
             "relationship_name": "accesses", "crn": "c2"},
        ]))
        hosts = view["deployment"]["hosting_assets"]
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["resource_id"], "arn:lambda")
        self.assertEqual(
            [e["resource_id"] for e in view["deployment"]["other_relationships"]],
            ["bucket"],
        )


class InterfacesAndFlows(unittest.TestCase):
    def test_rest_inbound_and_outbound(self):
        flows = build_interfaces_and_flows({
            "rest_inbound": [{"method": "GET", "pathPattern": "/health", "port": 8080}],
            "rest_outbound": [{"method": "POST", "path": "/v1/x",
                               "host": {"address": "api.example.com", "port": 443},
                               "areTargetEntityIdentifiersStatic": False}],
        })
        self.assertEqual(flows["rest_inbound"][0],
                         {"method": "GET", "path_pattern": "/health", "port": 8080})
        out = flows["rest_outbound"][0]
        self.assertEqual((out["host"], out["port"], out["targets_static"]),
                         ("api.example.com", 443, False))

    def test_datastore_detail_read_from_category_key(self):
        flows = build_interfaces_and_flows({"datastore_access": [{
            "category": "objectStorage",
            "objectStorage": {"operation": "PUT", "technology": "awsS3",
                              "filePath": "", "accessType": ""},
            "asset": {"gcrn": "CID|aws|global|global|AWS::S3::Bucket|b"},
            "sensitiveDataTags": ["pii"],
        }]})
        d = flows["datastore_access"][0]
        self.assertEqual(d["technology"], "awsS3")
        self.assertEqual(d["operation"], "PUT")
        self.assertEqual(d["asset_gcrn"], "CID|aws|global|global|AWS::S3::Bucket|b")
        self.assertEqual(d["sensitive_data_tags"], ["pii"])
        self.assertIsNone(d["file_path"], "empty string should normalise to None")

    def test_broker_target_is_never_a_dict(self):
        flows = build_interfaces_and_flows({"message_broker_producer": [
            {"technology": "sns", "sns": {"topicName": "t", "accountId": "1", "region": "r"}},
            {"technology": "sqs", "sqs": {"queueName": "q", "accountId": "1", "region": "r"}},
            {"technology": "sqs", "sqs": {"accountId": "1"}},
        ]})
        targets = [b["target"] for b in flows["message_broker_producer"]]
        self.assertEqual(targets, ["t", "q", None])
        for b in flows["message_broker_producer"]:
            self.assertIsInstance(b["target"], (str, type(None)))

    def test_absent_finding_types_yield_empty_lists(self):
        flows = build_interfaces_and_flows({})
        self.assertEqual(flows, {"rest_inbound": [], "rest_outbound": [],
                                 "datastore_access": [], "message_broker_producer": []})


class Robustness(unittest.TestCase):
    def test_all_null_fields_do_not_raise(self):
        """format(None, '<5') raises TypeError; vendor fields must be guarded."""
        view = build_application_view(make_asset(
            findings={
                "vulnerable_packages": [{"name": None, "version": None,
                                         "vulnerabilities": [{"cve_id": "CVE-0"}]}],
                "vulnerabilities": [{"cve_id": "CVE-0"}],
                "datastore_access": [{"category": None, "asset": {}}],
                "message_broker_producer": [{"technology": None}],
            },
            deployment={}, technologies=[],
        ))
        self.assertEqual(view["summary"]["cve_by_nvd_severity"], {"ABSENT": 1})

    def test_empty_configuration_is_handled(self):
        asset = make_asset()
        asset["configuration"] = None
        view = build_application_view(asset)
        self.assertEqual(view["summary"]["reachable_cve_count"], 0)
        self.assertEqual(view["packages_with_reachable_cves"], [])

    def test_insights_only_include_true_booleans(self):
        view = build_application_view(make_asset(insights=[
            {"id": "reachableRceVulnerabilities", "booleanValue": True},
            {"id": "publiclyExposedToTheInternet", "booleanValue": False},
        ]))
        self.assertEqual(view["summary"]["asset_insights"], ["reachableRceVulnerabilities"])


class ClientBehaviour(unittest.TestCase):
    def test_single_quote_in_name_is_rejected(self):
        """FQL delimits values with single quotes, so one would alter the query."""
        client = FalconClient("id", "secret", "https://example.com")
        with self.assertRaises(ValueError):
            client.query_aspm_applications("o'brien")

    def test_base_url_trailing_slash_stripped(self):
        self.assertEqual(
            FalconClient("i", "s", "https://example.com/").base_url,
            "https://example.com",
        )

    def test_get_assets_batches_and_preserves_order(self):
        calls = []

        class Stub(FalconClient):
            def _send(self, url):
                import urllib.parse as up
                ids = up.parse_qs(up.urlparse(url).query)["ids"]
                calls.append(len(ids))
                # Return out of order and drop one to test both behaviours.
                return {"resources": [{"id": i} for i in reversed(ids) if i != "drop-me"]}

        client = Stub("i", "s", "https://example.com")
        requested = [f"id-{n}" for n in range(MAX_IDS_PER_REQUEST + 5)] + ["drop-me"]
        got = client.get_assets(requested)

        self.assertEqual(calls, [MAX_IDS_PER_REQUEST, 6], "should chunk by MAX_IDS_PER_REQUEST")
        self.assertEqual([a["id"] for a in got], requested[:-1],
                         "order must follow the request, and misses are omitted")

    def test_retry_policy_covers_rate_limit_and_server_errors(self):
        self.assertIn(429, RETRYABLE_STATUS)
        for code in (500, 502, 503, 504):
            self.assertIn(code, RETRYABLE_STATUS)
        self.assertNotIn(404, RETRYABLE_STATUS)
        self.assertNotIn(400, RETRYABLE_STATUS)


class ErrorMessages(unittest.TestCase):
    """Misconfiguration must produce an actionable line, never a traceback."""

    def test_wrong_cloud_names_the_correct_host(self):
        import urllib.error
        import urllib.request

        real = urllib.request.urlopen

        def fake(req, *a, **k):
            raise urllib.error.HTTPError(
                "https://api.eu-1.crowdstrike.com/oauth2/token", 308, "Permanent Redirect",
                {"Location": "https://api.crowdstrike.com:443/oauth2/token"}, None,
            )

        urllib.request.urlopen = fake
        try:
            client = FalconClient("id", "secret", "https://api.eu-1.crowdstrike.com")
            with self.assertRaises(AuthError) as ctx:
                client.authenticate()
        finally:
            urllib.request.urlopen = real
        msg = str(ctx.exception)
        self.assertIn("wrong Falcon cloud", msg)
        self.assertIn("https://api.crowdstrike.com", msg)
        self.assertNotIn(":443", msg, "default port should be stripped so the hint is paste-ready")

    def test_rejected_credentials_mentions_both_env_vars(self):
        import urllib.error
        import urllib.request

        real = urllib.request.urlopen

        def fake(req, *a, **k):
            raise urllib.error.HTTPError("https://x/oauth2/token", 403, "Forbidden", {}, None)

        urllib.request.urlopen = fake
        try:
            with self.assertRaises(AuthError) as ctx:
                FalconClient("id", "secret").authenticate()
        finally:
            urllib.request.urlopen = real
        msg = str(ctx.exception)
        self.assertIn("FALCON_CLIENT_ID", msg)
        self.assertIn("FALCON_CLIENT_SECRET", msg)

    def test_unreachable_host_is_reported(self):
        import urllib.error
        import urllib.request

        real = urllib.request.urlopen

        def fake(req, *a, **k):
            raise urllib.error.URLError("nodename nor servname provided")

        urllib.request.urlopen = fake
        try:
            with self.assertRaises(AuthError) as ctx:
                FalconClient("id", "secret", "https://api.invalid.example").authenticate()
        finally:
            urllib.request.urlopen = real
        self.assertIn("api.invalid.example", str(ctx.exception))

    def test_403_on_data_call_is_a_scope_error(self):
        import urllib.error

        class Stub(FalconClient):
            def __init__(self):
                super().__init__("i", "s", "https://example.com")
                self._token = "t"

        client = Stub()
        import urllib.request
        real = urllib.request.urlopen

        def fake(req, *a, **k):
            raise urllib.error.HTTPError("https://example.com/x", 403, "Forbidden", {}, None)

        urllib.request.urlopen = fake
        try:
            with self.assertRaises(ScopeError) as ctx:
                client.get("/cloud-security-assets/queries/resources/v1")
        finally:
            urllib.request.urlopen = real
        self.assertIn("scope", str(ctx.exception).lower())


class ReviewRegressions(unittest.TestCase):
    """Defects found by code review of 75215bd..HEAD; each must stay fixed."""

    def test_orphan_cve_without_id_does_not_crash_the_report(self):
        """A package CVE ref with no cve_id reached an f-string format spec."""
        view = build_application_view(make_asset({
            "vulnerable_packages": [{"name": "p", "version": "1",
                                     "vulnerabilities": [{}]}],
            "vulnerabilities": [],
        }))
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            print_report(view)  # must not raise TypeError

    def test_vulnerability_record_without_id_is_counted_not_hidden(self):
        view = build_application_view(make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [{"reachable": True, "severity": "HIGH"}],
        }))
        self.assertEqual(view["summary"]["integrity_records_without_cve_id"], 1)

    def test_severity_buckets_are_case_normalised(self):
        """Mixed vendor casing would silently zero the critical/high ranking."""
        view = build_application_view(make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [
                {"cve_id": "CVE-1", "reachable": True, "severity": "Critical"},
                {"cve_id": "CVE-2", "reachable": True, "severity": "CRITICAL"},
            ],
        }, summary={"vulnerabilities": 2}))
        self.assertEqual(view["summary"]["cve_by_nvd_severity"], {"CRITICAL": 2})

    def test_malformed_configuration_is_recorded_not_raised(self):
        asset = make_asset()
        asset["configuration"] = "{not json"
        view = build_application_view(asset)
        self.assertIsNotNone(view["summary"]["integrity_config_parse_error"])
        self.assertEqual(view["summary"]["reachable_cve_count"], 0)

    def test_already_decoded_configuration_is_tolerated(self):
        asset = make_asset()
        asset["configuration"] = {"embeddedFindings": {
            "vulnerable_packages": [],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True}],
        }, "summary": {"vulnerabilities": 1}}
        view = build_application_view(asset)
        self.assertEqual(view["summary"]["reachable_cve_count"], 1)
        self.assertIsNone(view["summary"]["integrity_config_parse_error"])

    def test_null_resource_name_is_printable(self):
        asset = make_asset()
        asset["resource_name"] = None
        view = build_application_view(asset)
        self.assertEqual(app_label(view), "(unnamed)")

    def test_missing_ids_are_not_reported_as_duplicates(self):
        """Two id-less records are not a dedup loss -- neither was indexed."""
        raw = {"embeddedFindings": {"vulnerable_packages": [],
                                    "vulnerabilities": [{}, {}]}}
        asset = make_asset(raw["embeddedFindings"])
        view = build_application_view(asset)
        failures = validate(view, json.loads(asset["configuration"]))
        self.assertFalse([f for f in failures if "duplicate cve_ids" in f],
                         "absent ids must not be counted as duplicates")

    def test_real_duplicate_ids_are_still_caught(self):
        asset = make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True},
                                {"cve_id": "CVE-1", "reachable": True}],
        })
        view = build_application_view(asset)
        failures = validate(view, json.loads(asset["configuration"]))
        self.assertTrue([f for f in failures if "duplicate cve_ids" in f])

    def test_truncation_is_detectable_via_last_query_total(self):
        class Stub(FalconClient):
            def get(self, path, params=None):
                return {"resources": [f"id{n}" for n in range(params["limit"])],
                        "meta": {"pagination": {"total": 9999}}}

        c = Stub("i", "s", "https://example.com")
        ids = c.query_aspm_applications(limit=10)
        self.assertEqual(len(ids), 10)
        self.assertEqual(c.last_query_total, 9999)
        self.assertGreater(c.last_query_total, len(ids), "caller can detect a subset")


class SingleAppReporting(unittest.TestCase):
    def test_parse_failure_is_visible_in_the_report(self):
        """A non-fatal parse must not read as 'this application is clean'."""
        import io
        import contextlib
        asset = make_asset()
        asset["configuration"] = "{not json"
        view = build_application_view(asset)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            print_report(view)
        text = buf.getvalue()
        self.assertIn("configuration did not parse", text)
        self.assertIn("not because the application is clean", text)

    def test_json_null_configuration_is_not_an_error(self):
        asset = make_asset()
        asset["configuration"] = "null"
        view = build_application_view(asset)
        self.assertIsNone(view["summary"]["integrity_config_parse_error"],
                          "a JSON null means absent, not malformed")

    def test_parsed_config_can_be_passed_in_to_avoid_a_second_decode(self):
        asset = make_asset({"vulnerable_packages": [],
                            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True}]},
                           summary={"vulnerabilities": 1})
        parsed = parse_configuration(asset)
        view = build_application_view(asset, parsed)
        self.assertEqual(view["summary"]["reachable_cve_count"], 1)


class TruncationJudgement(unittest.TestCase):
    """Both entry points route through truncation_status, so they must agree."""

    def test_below_cap_with_matching_total_is_complete(self):
        self.assertEqual(truncation_status(5, 5), (False, None))

    def test_below_cap_with_no_total_is_complete(self):
        self.assertEqual(truncation_status(5, None), (False, None))

    def test_below_cap_with_larger_total_is_truncated(self):
        truncated, detail = truncation_status(5, 500)
        self.assertTrue(truncated)
        self.assertIn("500", detail)

    def test_at_cap_with_no_total_is_truncated(self):
        truncated, detail = truncation_status(FETCH_ALL, None)
        self.assertTrue(truncated)
        self.assertIn("no total", detail)

    def test_at_cap_with_equal_total_is_unconfirmable(self):
        truncated, detail = truncation_status(FETCH_ALL, FETCH_ALL)
        self.assertTrue(truncated, "a clamped total is indistinguishable from completeness")
        self.assertIn("cannot be confirmed", detail)

    def test_at_cap_with_larger_total_is_truncated(self):
        truncated, detail = truncation_status(FETCH_ALL, 50000)
        self.assertTrue(truncated)
        self.assertIn("50000", detail)


class VendorCountReconciliation(unittest.TestCase):
    """One accounting, shared by the summary field and the invariant."""

    def _view_and_failures(self, vulns, vendor_count):
        asset = make_asset({"vulnerable_packages": [], "vulnerabilities": vulns},
                           summary={"vulnerabilities": vendor_count})
        parsed = parse_configuration(asset)
        view = build_application_view(asset, parsed)
        return view, validate(view, parsed[0])

    def test_duplicates_are_accounted_not_double_reported(self):
        """A collapsed duplicate explains the shortfall; only one check fires."""
        view, failures = self._view_and_failures(
            [{"cve_id": "CVE-1", "reachable": True},
             {"cve_id": "CVE-1", "reachable": True}], 2)
        self.assertEqual(view["summary"]["integrity_duplicate_ids_collapsed"], 1)
        self.assertTrue(view["summary"]["integrity_summary_count_matches"])
        self.assertTrue([f for f in failures if "duplicate cve_ids" in f])
        self.assertFalse([f for f in failures if "vendor count agreement" in f],
                         "the duplicate already explains the gap")

    def test_summary_field_and_invariant_never_disagree(self):
        """The single-app NOTE and the fleet invariant read the same field."""
        for vulns, vendor in (
            ([{"cve_id": "CVE-1", "reachable": True}, {}], 2),
            ([{"cve_id": "CVE-1", "reachable": True}], 1),
            ([{"cve_id": "CVE-1", "reachable": True},
              {"cve_id": "CVE-1", "reachable": True}], 2),
            ([{"cve_id": "CVE-1", "reachable": True}, {}], 100),
        ):
            view, failures = self._view_and_failures(vulns, vendor)
            flagged = bool([f for f in failures if "vendor count agreement" in f])
            self.assertEqual(
                flagged, not view["summary"]["integrity_summary_count_matches"],
                f"disagreement for vendor={vendor} vulns={vulns}")

    def test_unexplained_gap_still_reported(self):
        view, failures = self._view_and_failures(
            [{"cve_id": "CVE-1", "reachable": True}, {}], 100)
        self.assertFalse(view["summary"]["integrity_summary_count_matches"])
        self.assertTrue([f for f in failures if "=100" in f])

    def test_absent_vendor_count_message_reports_the_raw_array(self):
        asset = make_asset({"vulnerable_packages": [], "vulnerabilities": [{}]})
        parsed = parse_configuration(asset)
        view = build_application_view(asset, parsed)
        failures = validate(view, parsed[0])
        msg = [f for f in failures if "absent" in f]
        self.assertTrue(msg)
        self.assertIn("1 record", msg[0], "must report the array size, not the deduped index")


class SeverityBandReporting(unittest.TestCase):
    def test_each_mismatch_counts_as_its_own_violation(self):
        vulns = [{"cve_id": f"CVE-{n}", "reachable": True, "severity": "LOW",
                  "cvss_v3_score": {"base_score": 9.9}} for n in range(12)]
        asset = make_asset({"vulnerable_packages": [], "vulnerabilities": vulns},
                           summary={"vulnerabilities": 12})
        parsed = parse_configuration(asset)
        failures = validate(build_application_view(asset, parsed), parsed[0])
        bands = [f for f in failures if "severity matches CVSS band" in f]
        self.assertGreater(len(bands), 1, "12 mismatches must not collapse into one entry")
        self.assertLessEqual(len(bands), 6, "evidence must stay bounded")
        self.assertTrue([f for f in bands if "more band mismatch" in f])
        for f in failures:
            self.assertLess(len(f), 300, "no unbounded multi-kilobyte line")


class FleetIntegration(unittest.TestCase):
    """Drive aspm_fleet_report.main() end-to-end against synthetic assets.

    The earlier malformed-configuration test only exercised
    build_application_view, so it stayed green while main() still did its own
    unguarded json.loads and aborted the walk. These tests run the real entry
    point so that class of defect cannot hide again.
    """

    NO_TOTAL = object()  # distinct from None, which means "use len(ids)"

    def _run_fleet(self, assets, total=None, ids=None):
        import io
        import contextlib
        import aspm_fleet_report as fleet

        ids = list(ids) if ids is not None else [a["id"] for a in assets]
        outer = self

        class Stub(FalconClient):
            def __init__(self):
                super().__init__("i", "s", "https://example.com")
                self._token = "t"
                if total is outer.NO_TOTAL:
                    self.last_query_total = None
                elif total is not None:
                    self.last_query_total = total
                else:
                    self.last_query_total = len(ids)

            def authenticate(self):
                self._token = "t"

            def query_aspm_applications(self, resource_name=None, limit=None):
                return list(ids)

            def get_assets(self, asset_ids):
                return list(assets)

        real_client, real_env = fleet.FalconClient, dict(os.environ)
        fleet.FalconClient = lambda *a, **k: Stub()
        os.environ["FALCON_CLIENT_ID"] = "i"
        os.environ["FALCON_CLIENT_SECRET"] = "s"
        os.environ.pop("ASPM_REGRESSION_BASELINE", None)
        cwd = os.getcwd()
        tmp = tempfile.mkdtemp()
        try:
            os.chdir(tmp)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = fleet.main()
            return code, out.getvalue(), err.getvalue()
        finally:
            os.chdir(cwd)
            shutil.rmtree(tmp, ignore_errors=True)
            fleet.FalconClient = real_client
            os.environ.clear()
            os.environ.update(real_env)

    def test_malformed_configuration_does_not_abort_the_walk(self):
        good = make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True, "severity": "HIGH"}],
        }, summary={"vulnerabilities": 1})
        bad = make_asset()
        bad["id"] = "CID|aspm|1|us-east-1|ASPM::Application|bad"
        bad["configuration"] = "{not json"
        code, out, _ = self._run_fleet([bad, good])
        self.assertIn("assets fetched           2/2", out,
                      "the good asset must still be processed")
        self.assertIn("did not parse", out)
        self.assertEqual(code, 1, "a parse failure is an invariant violation")

    def test_configuration_of_literal_null_does_not_abort(self):
        a = make_asset()
        a["configuration"] = "null"
        code, out, _ = self._run_fleet([a])
        self.assertIn("assets fetched           1/1", out)

    def test_non_string_severity_does_not_abort(self):
        a = make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True,
                                 "severity": 9, "exprt_rating": 3}],
        }, summary={"vulnerabilities": 1})
        code, out, _ = self._run_fleet([a])
        self.assertIn("assets fetched           1/1", out)

    def test_null_resource_name_does_not_abort(self):
        a = make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True, "severity": "CRITICAL"}],
        }, summary={"vulnerabilities": 1})
        a["resource_name"] = None
        code, out, _ = self._run_fleet([a])
        self.assertIn("(unnamed)", out)

    def test_complete_fleet_is_not_called_truncated(self):
        a = make_asset()
        _, out, err = self._run_fleet([a])
        self.assertNotIn("SUBSET", out)
        self.assertNotIn("SUBSET", err)

    def test_known_total_above_retrieved_warns(self):
        a = make_asset()
        _, out, err = self._run_fleet([a], total=500)
        self.assertIn("SUBSET", err)
        self.assertIn("500", err)
        self.assertIn("SUBSET ONLY -- 1 of 500", out)

    def test_total_equal_to_cap_is_reported_as_unconfirmable(self):
        """total == retrieved == cap is ambiguous, not complete.

        An API that clamps meta.pagination.total to the same ceiling as the
        result limit is indistinguishable from a tenant holding exactly that
        many applications, so completeness must not be asserted either way.
        """
        from aspm_application_inventory import FETCH_ALL
        a = make_asset()
        ids = [f"id{n}" for n in range(FETCH_ALL)]
        _, out, err = self._run_fleet([a], total=FETCH_ALL, ids=ids)
        self.assertIn("cannot be confirmed", err)
        self.assertIn("may clamp", err)

    def test_absent_total_at_the_cap_warns_without_printing_none(self):
        from aspm_application_inventory import FETCH_ALL
        a = make_asset()
        ids = [f"id{n}" for n in range(FETCH_ALL)]
        _, out, err = self._run_fleet([a], total=self.NO_TOTAL, ids=ids)
        self.assertIn("SUBSET", err)
        self.assertIn("no total was reported", err)
        self.assertNotIn("of None", out, "the COVERAGE line must not print 'of None'")
        self.assertIn("total unknown", out)

    def test_absent_total_below_the_cap_does_not_warn(self):
        a = make_asset()
        _, out, err = self._run_fleet([a], total=self.NO_TOTAL)
        self.assertNotIn("SUBSET", err)

    def test_coverage_table_prints_even_when_fully_correlated(self):
        a = make_asset(relationships=[{
            "resource_id": "arn:x", "resource_type": "AWS::Lambda::Function",
            "relationship_name": "is deployed by", "crn": "c"}])
        _, out, _ = self._run_fleet([a])
        self.assertIn("HOST CORRELATION COVERAGE", out,
                      "an absent table must not be mistaken for full coverage")

    def test_invariant_count_in_output_matches_implementation(self):
        import aspm_fleet_report as fleet
        a = make_asset()
        _, out, _ = self._run_fleet([a])
        self.assertIn(f"all {fleet.INVARIANT_COUNT} invariants hold", out)

    def test_id_less_record_reports_one_cause_not_two(self):
        """Indexed + id-less == vendor total, so only the id-less check fires."""
        a = make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True}, {}],
        }, summary={"vulnerabilities": 2})
        _, out, _ = self._run_fleet([a])
        self.assertIn("have no cve_id", out)
        self.assertNotIn("vendor summary.vulnerabilities", out,
                         "the dropped record fully explains the shortfall")

    def test_dropped_record_does_not_mask_a_large_mismatch(self):
        """One id-less record must not suppress 98 unaccounted-for CVEs."""
        a = make_asset({
            "vulnerable_packages": [],
            "vulnerabilities": [{"cve_id": "CVE-1", "reachable": True},
                                {"cve_id": "CVE-2", "reachable": True}, {}],
        }, summary={"vulnerabilities": 100})
        _, out, _ = self._run_fleet([a])
        self.assertIn("have no cve_id", out)
        self.assertIn("vendor summary.vulnerabilities=100", out,
                      "the count check must still fire for the unexplained gap")


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    sys.exit(0 if result.wasSuccessful() else 1)
