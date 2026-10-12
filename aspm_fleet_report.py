#!/usr/bin/env python3
"""
Fleet-wide ASPM reachable-CVE report with validation.

Walks every ASPM::Application asset, builds the same per-app view as
aspm_application_inventory.py, then asserts a set of invariants across the
whole fleet. Validation failures are reported loudly -- the point is to
detect the vendor data (or our assumptions about it) drifting, not to
produce a reassuring summary.

Supports an optional regression check pinning one application to a
known-good package set and CVE count.
"""

import collections
import json
import os
import sys
import time

from aspm_application_inventory import (
    FETCH_ALL,
    AuthError,
    FalconClient,
    ScopeError,
    build_application_view,
    parse_configuration,
    resolve_base_url,
    truncation_status,
)

# Optional regression baseline. Tenant-specific, so it is not shipped in this
# repo -- point ASPM_REGRESSION_BASELINE at a JSON file to enable the check:
#
#   {"name": "my-app", "reachable_cves": 21,
#    "packages": [{"name": "urllib3", "version": "1.26.4", "cve_count": 11}]}
#
# Generate one from a known-good run, ideally after confirming the figures
# against the Application Explorer console. Without it the check is skipped.
BASELINE_ENV = "ASPM_REGRESSION_BASELINE"


def load_baseline():
    path = os.getenv(BASELINE_ENV)
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    return {
        "name": raw["name"],
        "reachable_cves": raw["reachable_cves"],
        "packages": {(p["name"], p["version"]): p["cve_count"] for p in raw["packages"]},
    }

# NVD severity -> inclusive CVSS v3 base score band.
SEVERITY_BANDS = {
    "NONE": (0.0, 0.0),
    "LOW": (0.1, 3.9),
    "MEDIUM": (4.0, 6.9),
    "HIGH": (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}


EVIDENCE_LIMIT = 5


def _check_reachable_only(view, s, raw_vulns, raw_config):
    if s["integrity_unreachable_records"]:
        return [f"{len(s['integrity_unreachable_records'])} record(s) reachable!=true "
                f"-> findings array is NOT reachable-only: "
                f"{s['integrity_unreachable_records'][:EVIDENCE_LIMIT]}"]
    return []


def _check_join_complete(view, s, raw_vulns, raw_config):
    if s["integrity_orphaned_package_cves"]:
        return [f"{len(s['integrity_orphaned_package_cves'])} orphaned package CVE(s): "
                f"{s['integrity_orphaned_package_cves'][:EVIDENCE_LIMIT]}"]
    return []


def _check_vendor_count(view, s, raw_vulns, raw_config):
    """Vendor's own total agrees with every record we can account for.

    build_application_view does this reconciliation and exposes the result;
    recomputing it here is what let the two paths disagree. Records dropped
    for lacking an id, and duplicates the index collapsed, are added back --
    each has its own check, so only an unexplained gap is drift.
    """
    if s["integrity_summary_count_matches"]:
        return []
    vendor = s["integrity_vendor_reported_count"]
    if vendor is None:
        return [f"vendor summary.vulnerabilities absent but the array holds "
                f"{s['integrity_raw_record_count']} record(s)"]
    return [f"vendor summary.vulnerabilities={vendor} but "
            f"{s['reachable_cve_count']} indexed + "
            f"{s['integrity_records_without_cve_id']} id-less + "
            f"{s['integrity_duplicate_ids_collapsed']} duplicate = "
            f"{s['integrity_accounted_count']}"]


def _check_no_duplicate_ids(view, s, raw_vulns, raw_config):
    # Records without an id are reported by their own check; counting them
    # here would claim a dedup loss that never happened.
    ids = [v.get("cve_id") for v in raw_vulns if v.get("cve_id")]
    if len(ids) != len(set(ids)):
        dupes = [c for c, n in collections.Counter(ids).items() if n > 1]
        return [f"duplicate cve_ids in array, dedup may be lossy: "
                f"{dupes[:EVIDENCE_LIMIT]}"]
    return []


def _check_severity_bands(view, s, raw_vulns, raw_config):
    problems = []
    for v in raw_vulns:
        # str() because the vendor field is not guaranteed to be a string.
        sev = str(v.get("severity") or "").upper()
        score = (v.get("cvss_v3_score") or {}).get("base_score")
        if sev in SEVERITY_BANDS and isinstance(score, (int, float)):
            lo, hi = SEVERITY_BANDS[sev]
            if not (lo <= score <= hi):
                problems.append(f"{v.get('cve_id')} severity={sev} but "
                                f"CVSSv3={score} (band {lo}-{hi})")
    # One entry per mis-banded CVE so the violation count is truthful, but
    # bounded so a badly drifted application cannot flood the output.
    if len(problems) > EVIDENCE_LIMIT:
        extra = len(problems) - EVIDENCE_LIMIT
        return problems[:EVIDENCE_LIMIT] + [f"... and {extra} more band mismatch(es)"]
    return problems


def _check_pairs_cover_uniques(view, s, raw_vulns, raw_config):
    pairs = sum(p["cve_count"] for p in view["packages_with_reachable_cves"])
    if pairs < s["reachable_cve_count"]:
        return [f"{pairs} package-CVE pairs < {s['reachable_cve_count']} unique CVEs"]
    return []


def _check_config_parsed(view, s, raw_vulns, raw_config):
    if s["integrity_config_parse_error"]:
        return [f"configuration did not parse: {s['integrity_config_parse_error']}"]
    return []


def _check_records_have_ids(view, s, raw_vulns, raw_config):
    if s["integrity_records_without_cve_id"]:
        return [f"{s['integrity_records_without_cve_id']} vulnerability record(s) "
                f"have no cve_id and were skipped"]
    return []


# Ordered so the printed numbering matches the README's enumerated list, and
# so INVARIANT_COUNT is derived rather than hand-maintained.
INVARIANTS = (
    ("reachable-only findings", _check_reachable_only),
    ("package->CVE join completeness", _check_join_complete),
    ("vendor count agreement", _check_vendor_count),
    ("no duplicate CVE ids", _check_no_duplicate_ids),
    ("severity matches CVSS band", _check_severity_bands),
    ("pairs cover unique CVEs", _check_pairs_cover_uniques),
    ("configuration parsed", _check_config_parsed),
    ("every record has a cve_id", _check_records_have_ids),
)
INVARIANT_COUNT = len(INVARIANTS)


def app_label(view):
    """resource_name is vendor-supplied and may be absent; printing needs a str."""
    return str(view["application"]["name"] or "(unnamed)")


def validate(view, raw_config):
    """Return a list of invariant-violation strings for one application."""
    name = app_label(view)
    s = view["summary"]
    raw_vulns = (raw_config.get("embeddedFindings") or {}).get("vulnerabilities") or []
    failures = []
    for label, check in INVARIANTS:
        for problem in check(view, s, raw_vulns, raw_config):
            failures.append(f"{name}: [{label}] {problem}")
    return failures


def check_regression(views, baseline):
    if not baseline:
        return []
    match = [v for v in views if app_label(v) == baseline["name"]]
    if not match:
        return [f"REGRESSION: {baseline['name']} not found in fleet"]
    view = match[0]
    got = {(p["name"], p["version"]): p["cve_count"]
           for p in view["packages_with_reachable_cves"]}
    problems = []
    if got != baseline["packages"]:
        problems.append(f"REGRESSION: {baseline['name']} package set changed")
        for k in sorted(set(got) | set(baseline["packages"])):
            exp, act = baseline["packages"].get(k), got.get(k)
            if exp != act:
                problems.append(f"    {k[0]}@{k[1]}: baseline {exp}, got {act}")
    actual = view["summary"]["reachable_cve_count"]
    if actual != baseline["reachable_cves"]:
        problems.append(
            f"REGRESSION: {baseline['name']} reachable CVEs "
            f"baseline {baseline['reachable_cves']}, got {actual}"
        )
    return problems


def main():
    client_id = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    if not client_id or not client_secret:
        sys.exit("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")

    client = FalconClient(client_id, client_secret, resolve_base_url())
    try:
        client.authenticate()
    except AuthError as err:
        sys.exit(str(err))

    baseline = load_baseline()

    ids = client.query_aspm_applications(limit=FETCH_ALL)
    total = client.last_query_total
    print(f"ASPM::Application assets: {len(ids)}")

    # A tenant larger than FETCH_ALL would otherwise print a complete-looking
    # count and have the invariants certify only the retrieved subset.
    truncated, detail = truncation_status(len(ids), total)
    if truncated:
        print(f"  WARNING: {detail}; this report may cover a SUBSET, not the "
              f"whole fleet", file=sys.stderr)

    assets = client.get_assets(ids)
    fetch_failed = len(ids) - len(assets)

    views, failures, no_findings = [], [], 0
    for asset in assets:
        parsed = parse_configuration(asset)
        raw_config = parsed[0]
        view = build_application_view(asset, parsed)
        if not view["summary"]["reachable_cve_count"]:
            no_findings += 1
        views.append(view)
        failures.extend(validate(view, raw_config))

    failures = check_regression(views, baseline) + failures

    with_findings = [v for v in views if v["summary"]["reachable_cve_count"]]

    print(f"\n{'=' * 78}")
    print("  VALIDATION")
    print(f"{'=' * 78}")
    print(f"  assets fetched           {len(views)}/{len(ids)}"
          + (f"  ({fetch_failed} fetch failures)" if fetch_failed else ""))
    print(f"  with reachable CVEs      {len(with_findings)}")
    print(f"  with none                {no_findings}")
    if truncated:
        scope = f"{len(ids)} of {total}" if total is not None \
            else f"{len(ids)}, total unknown"
        print(f"  COVERAGE                 SUBSET ONLY -- {scope}")
    if failures:
        print(f"\n  {len(failures)} INVARIANT VIOLATION(S):")
        for f in failures[:40]:
            print(f"    {f}")
        if len(failures) > 40:
            print(f"    ... and {len(failures) - 40} more")
    else:
        print(f"\n  all {INVARIANT_COUNT} invariants hold across the fleet")
        if baseline:
            print(f"  {baseline['name']} matches regression baseline")
        else:
            print(f"  regression check skipped (set {BASELINE_ENV} to enable)")

    # Coverage gaps are incomplete vendor data, not a parsing failure, so they
    # are reported separately from invariant violations.
    by_type = collections.defaultdict(lambda: [0, 0])
    for v in views:
        slot = 0 if v["summary"]["has_hosting_asset"] else 1
        by_type[v["deployment"]["type"] or "(no deployment type)"][slot] += 1
    # Printed unconditionally: if it only appeared on failure, an operator
    # could not tell "fully correlated" from "the table did not run".
    if by_type:
        print(f"\n  HOST CORRELATION COVERAGE")
        print("  (an application with no 'is deployed by' edge cannot be tied")
        print("   to the resource running it; other edge types such as")
        print("   'accesses' describe data flow, not hosting)")
        print(f"    {'deployment type':<26}{'correlated':>11}{'missing':>9}")
        for dep_type, (have, missing) in sorted(by_type.items()):
            flag = "  <-- gap" if missing else ""
            print(f"    {dep_type:<26}{have:>11}{missing:>9}{flag}")

    orphan_apps = [v for v in with_findings if not v["deployment"]["hosting_assets"]]
    if orphan_apps:
        print(f"\n  {len(orphan_apps)} of those also carry reachable CVEs:")
        for v in orphan_apps:
            print(f"    {app_label(v):<34}"
                  f"{v['summary']['reachable_cve_count']:>4} CVEs   "
                  f"{v['deployment']['type'] or 'unknown deployment type'}")

    # ---- prioritisation ----
    def sev(v, s):
        return v["summary"]["cve_by_nvd_severity"].get(s, 0)

    ranked = sorted(
        with_findings,
        key=lambda v: (-sev(v, "CRITICAL"), -sev(v, "HIGH"), -v["summary"]["reachable_cve_count"]),
    )

    print(f"\n{'=' * 78}")
    print("  TOP APPLICATIONS BY REACHABLE CRITICAL/HIGH (NVD)")
    print(f"{'=' * 78}")
    print(f"  {'application':<34}{'CRIT':>5}{'HIGH':>5}{'CVEs':>6}{'pkgs':>6}  deployment")
    for v in ranked[:20]:
        s = v["summary"]
        print(f"  {app_label(v)[:33]:<34}"
              f"{sev(v, 'CRITICAL'):>5}{sev(v, 'HIGH'):>5}"
              f"{s['reachable_cve_count']:>6}{s['packages_with_reachable_cves']:>6}"
              f"  {v['deployment']['type'] or '-'}")

    # ---- blast radius ----
    pkg_apps = collections.defaultdict(set)
    pkg_cves = collections.defaultdict(set)
    for v in with_findings:
        for p in v["packages_with_reachable_cves"]:
            key = f"{p['name']}@{p['version']}"
            pkg_apps[key].add(app_label(v))
            for c in p["cves"]:
                if c.get("cve_id"):
                    pkg_cves[key].add(c["cve_id"])

    print(f"\n{'=' * 78}")
    print("  SHARED PACKAGE BLAST RADIUS (one upgrade, N applications)")
    print(f"{'=' * 78}")
    print(f"  {'package@version':<34}{'apps':>6}{'CVEs':>6}")
    for key, apps in sorted(pkg_apps.items(), key=lambda kv: -len(kv[1]))[:20]:
        print(f"  {key[:33]:<34}{len(apps):>6}{len(pkg_cves[key]):>6}")

    # ---- NVD vs ExPRT divergence ----
    nvd = collections.Counter()
    exprt = collections.Counter()
    for v in with_findings:
        nvd.update(v["summary"]["cve_by_nvd_severity"])
        exprt.update(v["summary"]["cve_by_exprt_rating"])
    print(f"\n{'=' * 78}")
    print("  SEVERITY MODEL DIVERGENCE (same CVE population, both models)")
    print(f"{'=' * 78}")
    print(f"  NVD severity : {dict(nvd)}")
    print(f"  ExPRT rating : {dict(exprt)}")

    # ---- attack surface / data flows ----
    exposed = [v for v in views if v["summary"]["rest_inbound_count"]]
    outbound = [v for v in views if v["summary"]["rest_outbound_count"]]
    stores = [v for v in views if v["summary"]["datastore_access_count"]]
    brokers = [v for v in views if v["summary"]["message_broker_count"]]
    internet = [v for v in views
                if "publiclyExposedToTheInternet" in v["summary"]["asset_insights"]]
    sensitive = [v for v in views
                 if "accessesSensitiveDataSource" in v["summary"]["asset_insights"]]

    print(f"\n{'=' * 78}")
    print("  ATTACK SURFACE AND DATA FLOWS")
    print(f"{'=' * 78}")
    print(f"  apps with exposed endpoints     {len(exposed):>4}"
          f"   ({sum(v['summary']['rest_inbound_count'] for v in exposed)} endpoints)")
    print(f"  apps making outbound calls      {len(outbound):>4}"
          f"   ({sum(v['summary']['rest_outbound_count'] for v in outbound)} calls)")
    print(f"  apps touching datastores        {len(stores):>4}")
    print(f"  apps writing to brokers         {len(brokers):>4}")
    print(f"  apps publicly exposed           {len(internet):>4}")
    print(f"  apps accessing sensitive data   {len(sensitive):>4}")

    # Internet-exposed AND carrying reachable critical/high is the pointy end.
    pointy = [v for v in internet if sev(v, "CRITICAL") or sev(v, "HIGH")]
    if pointy:
        print(f"\n  PUBLICLY EXPOSED *AND* REACHABLE CRITICAL/HIGH ({len(pointy)}):")
        print(f"    {'application':<34}{'CRIT':>5}{'HIGH':>5}{'in':>4}{'out':>5}")
        for v in sorted(pointy, key=lambda v: (-sev(v, "CRITICAL"), -sev(v, "HIGH"))):
            print(f"    {app_label(v)[:33]:<34}"
                  f"{sev(v, 'CRITICAL'):>5}{sev(v, 'HIGH'):>5}"
                  f"{v['summary']['rest_inbound_count']:>4}"
                  f"{v['summary']['rest_outbound_count']:>5}")

    # Outbound hosts are third-party dependencies worth inventorying.
    hosts_seen = collections.Counter()
    for v in outbound:
        for o in v["interfaces_and_flows"]["rest_outbound"]:
            if o["host"]:
                hosts_seen[o["host"]] += 1
    if hosts_seen:
        print(f"\n  TOP OUTBOUND DEPENDENCIES ({len(hosts_seen)} distinct hosts):")
        for host, n in hosts_seen.most_common(12):
            print(f"    {host[:54]:<56}{n:>4} calls")

    out = f"aspm_fleet_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "scope": "code-reachable findings only; not a full dependency inventory",
            "validation": {
                "tenant_reported_total": total,
                "truncated": bool(truncated),
                "assets_total": len(ids),
                "assets_fetched": len(views),
                "fetch_failures": fetch_failed,
                "invariant_violations": failures,
                "regression_app": baseline["name"] if baseline else None,
            },
            "applications": views,
        }, fh, indent=2, ensure_ascii=False)
    print(f"\nJSON written to {out}")
    return 1 if failures else 0


def _cli():
    """Keep sys.exit outside the try so SystemExit is not caught here."""
    try:
        return main()
    except (AuthError, ScopeError) as err:
        print(err, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(_cli())
