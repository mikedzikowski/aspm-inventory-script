#!/usr/bin/env python3
"""
ASPM Application Inventory (Falcon Cloud Security asset API)

Emits a JSON view of an ASPM application: its deployment (host) correlation,
the packages that carry code-reachable CVEs, and those CVEs.

Data source: /cloud-security-assets/{queries,entities}/resources/v1 with
resource_type ASPM::Application. Package and CVE data live in the asset's
`configuration` field under `embeddedFindings`.

SCOPE NOTE:

`embeddedFindings` returns code-reachable findings only, so
`vulnerable_packages` lists the packages carrying a reachable CVE rather than
the application's full dependency list. The console's Packages panel shows the
complete list and will report a higher number.

Severity is reported two ways: `severity` / `cvss_v3_score` are NVD-derived,
while `exprt_rating` is CrowdStrike's own model. They can differ
substantially. Both are passed through rather than one being chosen.

Requires an API client with read access to cloud security assets
(see README; the exact console label varies by version).
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

RESOURCE_TYPE = "ASPM::Application"

# Override with FALCON_BASE_URL for EU / gov / other clouds.
DEFAULT_BASE_URL = "https://api.crowdstrike.com"
BASE_URL_ENV = "FALCON_BASE_URL"

# The queries endpoint caps page size at 1000.
MAX_PAGE_SIZE = 1000

# Sentinel meaning "retrieve every match"; the endpoint caps results at 10k.
FETCH_ALL = 10000

# The entities endpoint accepts repeated ids= params. Verified: 100 ids
# succeed (~13 KB URL) and 149 fails with HTTP 400, so the ceiling is URL
# length. 50 keeps requests near 6 KB, well clear of proxy limits.
MAX_IDS_PER_REQUEST = 50

# Retry policy for transient failures (429 and 5xx).
MAX_RETRIES = 4
BACKOFF_BASE_SECONDS = 1.5
RETRYABLE_STATUS = {429, 500, 502, 503, 504}

# relationships[] mixes edge types. Only this one identifies the resource
# running the application; "accesses" points at things the application talks
# to, so counting it as a host would claim correlation that does not exist.
DEPLOYMENT_RELATIONSHIP = "is deployed by"


def resolve_base_url():
    return os.getenv(BASE_URL_ENV, DEFAULT_BASE_URL)


def truncation_status(retrieved, total):
    """Return (is_truncated, detail) for a result set against its server total.

    Both entry points call this so they cannot disagree about the same tenant.
    A reported total equal to the retrieved count *at the cap* is ambiguous --
    the API may clamp `total` to the same ceiling -- so it is reported as
    possibly truncated rather than silently assumed complete.
    """
    if retrieved >= FETCH_ALL:
        if total is None:
            return True, (f"no total was reported and {retrieved} were retrieved, "
                          f"which is the {FETCH_ALL} cap")
        if total > retrieved:
            return True, f"tenant reports {total} but only {retrieved} were retrieved"
        return True, (f"retrieved {retrieved}, the {FETCH_ALL} cap, and the reported "
                      f"total is also {total} -- the API may clamp the total, so "
                      f"completeness cannot be confirmed")
    if total is not None and total > retrieved:
        return True, f"tenant reports {total} but only {retrieved} were retrieved"
    return False, None


class AuthError(Exception):
    """Authentication failed in a way the operator needs to act on."""


class ScopeError(Exception):
    """The token is valid but lacks the scope this endpoint needs."""


class FalconClient:
    def __init__(self, client_id, client_secret, base_url=None):
        self.base_url = (base_url or resolve_base_url()).rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._token = None
        # Server-reported match count from the last query, for truncation checks.
        self.last_query_total = None

    def authenticate(self):
        data = urllib.parse.urlencode({
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
        }).encode()
        req = urllib.request.Request(f"{self.base_url}/oauth2/token", data=data)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with urllib.request.urlopen(req) as resp:
                self._token = json.loads(resp.read().decode())["access_token"]
        except urllib.error.HTTPError as err:
            # A tenant on another cloud answers with a redirect whose Location
            # names the correct host, which is the most useful hint available.
            if err.code in (301, 302, 307, 308):
                target = (err.headers or {}).get("Location") or ""
                split = urllib.parse.urlsplit(target)
                # Strip the default port so the hint is paste-ready.
                host = split.hostname or ""
                if split.port and split.port != 443:
                    host = f"{host}:{split.port}"
                hint = f" Your tenant appears to be at https://{host}." if host else ""
                raise AuthError(
                    f"{self.base_url} redirected ({err.code}): wrong Falcon cloud."
                    f"{hint} Set {BASE_URL_ENV} accordingly."
                ) from err
            if err.code in (400, 401, 403):
                raise AuthError(
                    f"Credentials rejected (HTTP {err.code}). Check "
                    f"FALCON_CLIENT_ID and FALCON_CLIENT_SECRET, that the API "
                    f"client is still active, and that {self.base_url} is the "
                    f"right cloud for your tenant."
                ) from err
            raise AuthError(
                f"Authentication failed against {self.base_url}: HTTP {err.code}"
            ) from err
        except urllib.error.URLError as err:
            raise AuthError(
                f"Cannot reach {self.base_url}: {err.reason}"
            ) from err

    def _send(self, url):
        """GET with retry on rate limits and transient server errors.

        Re-authenticates once on 401 so long fleet walks survive token expiry.
        """
        last_error = None
        for attempt in range(MAX_RETRIES + 1):
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Bearer {self._token}")
            req.add_header("Accept", "application/json")
            try:
                with urllib.request.urlopen(req) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as err:
                last_error = err
                if err.code == 401 and attempt == 0:
                    self.authenticate()
                    continue
                if err.code == 403:
                    raise ScopeError(
                        "HTTP 403 from the Cloud Security assets API. The token "
                        "is valid but the API client lacks read access to cloud "
                        "security assets; add that scope and retry."
                    ) from err
                if err.code not in RETRYABLE_STATUS or attempt == MAX_RETRIES:
                    raise
                # Honour Retry-After when the server sends it.
                retry_after = err.headers.get("Retry-After") if err.headers else None
                try:
                    delay = float(retry_after)
                except (TypeError, ValueError):
                    delay = BACKOFF_BASE_SECONDS * (2 ** attempt)
                print(f"  HTTP {err.code}, retrying in {delay:.1f}s "
                      f"(attempt {attempt + 1}/{MAX_RETRIES})", file=sys.stderr)
                time.sleep(delay)
            except urllib.error.URLError as err:
                last_error = err
                if attempt == MAX_RETRIES:
                    raise
                delay = BACKOFF_BASE_SECONDS * (2 ** attempt)
                print(f"  network error ({err.reason}), retrying in {delay:.1f}s "
                      f"(attempt {attempt + 1}/{MAX_RETRIES})", file=sys.stderr)
                time.sleep(delay)
        raise last_error

    def get(self, path, params=None):
        url = f"{self.base_url}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._send(url)

    def query_aspm_applications(self, resource_name=None, limit=MAX_PAGE_SIZE):
        """Return asset IDs for ASPM::Application resources.

        Sets self.last_query_total to the server's reported match count so a
        caller can tell a complete walk from one truncated by `limit`.
        """
        fql = f"resource_type:'{RESOURCE_TYPE}'"
        if resource_name:
            # Single quotes delimit FQL values, so an embedded quote would
            # change the query's meaning.
            if "'" in resource_name:
                raise ValueError("resource_name may not contain a single quote")
            fql += f"+resource_name:'{resource_name}'"

        ids, offset = [], 0
        self.last_query_total = None
        while True:
            page = self.get(
                "/cloud-security-assets/queries/resources/v1",
                {"filter": fql, "limit": min(limit, MAX_PAGE_SIZE), "offset": offset},
            )
            batch = page.get("resources") or []
            ids.extend(batch)
            total = (page.get("meta", {}).get("pagination", {}) or {}).get("total")
            if total is not None:
                self.last_query_total = total
            offset += len(batch)
            if not batch or len(ids) >= limit or (total is not None and offset >= total):
                break
        return ids[:limit]

    def get_assets(self, asset_ids):
        """Fetch asset entities in batches, preserving the requested order.

        The endpoint takes repeated ids= params; asset ids contain pipes and
        colons, so each is passed through urlencode rather than joined.
        Ids the API does not return are omitted, so the caller can detect
        misses by comparing lengths.
        """
        found = {}
        for start in range(0, len(asset_ids), MAX_IDS_PER_REQUEST):
            chunk = asset_ids[start:start + MAX_IDS_PER_REQUEST]
            query = urllib.parse.urlencode([("ids", i) for i in chunk])
            page = self._send(
                f"{self.base_url}/cloud-security-assets/entities/resources/v1?{query}"
            )
            for asset in page.get("resources") or []:
                found[asset.get("id")] = asset
        return [found[i] for i in asset_ids if i in found]

    def get_asset(self, asset_id):
        assets = self.get_assets([asset_id])
        return assets[0] if assets else None


def build_interfaces_and_flows(findings):
    """Extract the non-vulnerability finding types.

    Field shapes observed across the fleet (all keys present on every item
    of their type, so these are stable rather than optional):
      rest_inbound            method, pathPattern, port
      rest_outbound           method, path, host{address,port}, areTargetEntityIdentifiersStatic
      datastore_access        category, <category-specific obj>, asset{gcrn}, sensitiveDataTags?
      message_broker_producer technology, <technology-specific obj>, areTargetEntityIdentifiersStatic
    """
    inbound = [
        {
            "method": i.get("method"),
            "path_pattern": i.get("pathPattern"),
            "port": i.get("port"),
        }
        for i in findings.get("rest_inbound") or []
    ]

    outbound = [
        {
            "method": o.get("method"),
            "path": o.get("path"),
            "host": (o.get("host") or {}).get("address"),
            "port": (o.get("host") or {}).get("port"),
            "targets_static": o.get("areTargetEntityIdentifiersStatic"),
        }
        for o in findings.get("rest_outbound") or []
    ]

    datastores = []
    for d in findings.get("datastore_access") or []:
        category = d.get("category")
        # The category names the sibling key holding the detail.
        detail = d.get(category) or {}
        datastores.append({
            "category": category,
            "technology": detail.get("technology"),
            "operation": detail.get("operation"),
            "file_path": detail.get("filePath") or None,
            "access_type": detail.get("accessType") or None,
            # gcrn points at the actual cloud asset, enabling cross-asset join
            "asset_gcrn": (d.get("asset") or {}).get("gcrn"),
            "sensitive_data_tags": d.get("sensitiveDataTags") or [],
        })

    brokers = []
    for b in findings.get("message_broker_producer") or []:
        tech = b.get("technology")
        detail = b.get(tech) or {}
        brokers.append({
            "technology": tech,
            "target": detail.get("topicName") or detail.get("queueName") or None,
            "account_id": detail.get("accountId"),
            "region": detail.get("region"),
            "targets_static": b.get("areTargetEntityIdentifiersStatic"),
        })

    return {
        "rest_inbound": inbound,
        "rest_outbound": outbound,
        "datastore_access": datastores,
        "message_broker_producer": brokers,
    }


def parse_configuration(asset):
    """Decode an asset's `configuration` blob into (config, error).

    Every caller must use this rather than calling json.loads directly: a
    second, unguarded parse elsewhere reintroduces the fleet-wide abort this
    exists to prevent. `error` is None on success, otherwise a short string.
    """
    raw = asset.get("configuration")
    if raw is None or raw == "":
        return {}, None
    if isinstance(raw, dict):
        # Tolerate the field arriving already decoded.
        return raw, None
    try:
        config = json.loads(raw)
    except (ValueError, TypeError) as err:
        return {}, f"{type(err).__name__}: {err}"
    if config is None:
        # A JSON null is the vendor saying "no configuration", not a fault.
        # Note "null" is truthy as a string, so the default above misses it.
        return {}, None
    if not isinstance(config, dict):
        return {}, f"configuration decoded to {type(config).__name__}, expected object"
    return config, None


def build_application_view(asset, parsed=None):
    """Join the asset's reachable-CVE package list against its CVE findings.

    `parsed` is an existing (config, error) pair from parse_configuration;
    pass it to avoid decoding the same blob twice on a fleet walk.
    """
    config, config_error = parsed if parsed is not None else parse_configuration(asset)
    findings = config.get("embeddedFindings") or {}

    # cve_id -> full finding record (carries CVSS, exprt_rating, remediation).
    # This array is pre-filtered to reachable findings; see module docstring.
    raw_vulns = findings.get("vulnerabilities") or []
    cve_index = {}
    records_without_id = 0
    for v in raw_vulns:
        if v.get("cve_id"):
            cve_index[v["cve_id"]] = v
        else:
            # Dropping these silently would surface only as a vendor-count
            # mismatch, which points at the wrong cause.
            records_without_id += 1
    # Records the dict collapsed. Counted so the vendor-count reconciliation
    # below has one explanation per discrepancy.
    duplicates_collapsed = (
        len(raw_vulns) - records_without_id - len(cve_index)
    )

    packages = []
    orphaned = []
    for pkg in findings.get("vulnerable_packages") or []:
        cves = []
        for ref in pkg.get("vulnerabilities") or []:
            cve_id = ref.get("cve_id")
            detail = cve_index.get(cve_id)
            if detail:
                cves.append(detail)
            else:
                # Referenced by the package list but absent from the findings
                # array -- would indicate the two are scoped differently.
                orphaned.append({"package": pkg.get("name"), "cve_id": cve_id})
                cves.append({"cve_id": cve_id, "detail_available": False})

        packages.append({
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "cve_count": len(cves),
            "cves": cves,
        })

    # An ASPM application links to the cloud asset that runs it.
    deployment = config.get("deployment") or {}
    def as_edge(rel):
        return {
            "resource_id": rel.get("resource_id"),
            "resource_type": rel.get("resource_type"),
            "relationship": rel.get("relationship_name"),
            "crn": rel.get("crn"),
        }

    relationships = asset.get("relationships") or []
    # Only the deployment edge identifies what runs the application. Other
    # edges (e.g. "accesses") describe what it talks to and are kept apart so
    # they cannot be mistaken for host correlation.
    hosts = [as_edge(r) for r in relationships
             if r.get("relationship_name") == DEPLOYMENT_RELATIONSHIP]
    other_edges = [as_edge(r) for r in relationships
                   if r.get("relationship_name") != DEPLOYMENT_RELATIONSHIP]

    insights = ((asset.get("cloud_context") or {}).get("insights") or {}).get("external") or []

    all_cves = list(cve_index.values())
    not_reachable = [c["cve_id"] for c in all_cves if not c.get("reachable")]
    flows = build_interfaces_and_flows(findings)

    def by_severity(records, key="severity"):
        # Upper-cased so a vendor switch to "Critical" cannot silently zero the
        # risk ranking, which keys on these buckets. "ABSENT" rather than
        # "UNKNOWN": the vendor emits a real UNKNOWN exprt_rating, so reusing
        # it would conflate missing with unrated.
        counts = {}
        for c in records:
            bucket = str(c.get(key) or "ABSENT").upper()
            counts[bucket] = counts.get(bucket, 0) + 1
        return counts

    # Same package may appear at multiple versions; count distinct names too.
    distinct_names = {p["name"] for p in packages}

    # The vendor omits summary.vulnerabilities for applications with no
    # findings, so absent-and-zero is agreement. Records we dropped or
    # collapsed are added back: the index being smaller than the vendor total
    # is expected when we know why, and only an unexplained gap is drift.
    vendor_count = (config.get("summary") or {}).get("vulnerabilities")
    accounted = len(all_cves) + records_without_id + duplicates_collapsed
    if vendor_count is None:
        count_matches = not raw_vulns
    else:
        count_matches = accounted == vendor_count

    return {
        "application": {
            "asset_id": asset.get("id"),
            "resource_id": asset.get("resource_id"),
            "name": asset.get("resource_name"),
            "resource_type": asset.get("resource_type"),
            "account_id": asset.get("account_id"),
            "region": asset.get("region"),
            "active": asset.get("active"),
            "first_seen": asset.get("first_seen"),
            "updated_at": asset.get("updated_at"),
            "technologies": config.get("technologies") or [],
            "tags": asset.get("tags") or {},
        },
        "deployment": {
            "provider": deployment.get("deploymentProvider"),
            "type": deployment.get("deploymentType"),
            "cloud_asset_resource_id": deployment.get("cloudAssetResourceId"),
            "cloud_account": deployment.get("cloudAccount"),
            "cloud_region": deployment.get("cloudRegion"),
            "hosting_assets": hosts,
            "other_relationships": other_edges,
        },
        "packages_with_reachable_cves": sorted(packages, key=lambda p: -p["cve_count"]),
        "reachable_vulnerabilities": sorted(all_cves, key=lambda c: c.get("cve_id") or ""),
        "excessive_permissions": findings.get("admin_action") or [],
        "interfaces_and_flows": flows,
        "summary": {
            "scope": "code-reachable findings only; not a full dependency inventory",
            "packages_with_reachable_cves": len(packages),
            "distinct_package_names": len(distinct_names),
            "reachable_cve_count": len(all_cves),
            "cve_by_nvd_severity": by_severity(all_cves),
            "cve_by_exprt_rating": by_severity(all_cves, "exprt_rating"),
            "reachable_exprt_rating_reported": (config.get("summary") or {}).get(
                "reachableVulnerabilitiesExprtRating"
            ),
            "asset_insights": [i.get("id") for i in insights if i.get("booleanValue")],
            "rest_inbound_count": len(flows["rest_inbound"]),
            "rest_outbound_count": len(flows["rest_outbound"]),
            "datastore_access_count": len(flows["datastore_access"]),
            "message_broker_count": len(flows["message_broker_producer"]),
            "has_hosting_asset": bool(hosts),
            "other_relationship_count": len(other_edges),
            # Both should be empty. Non-empty means an assumption above broke.
            "integrity_config_parse_error": config_error,
            "integrity_records_without_cve_id": records_without_id,
            "integrity_duplicate_ids_collapsed": duplicates_collapsed,
            "integrity_raw_record_count": len(raw_vulns),
            "integrity_vendor_reported_count": vendor_count,
            "integrity_accounted_count": accounted,
            "integrity_unreachable_records": not_reachable,
            "integrity_orphaned_package_cves": orphaned,
            "integrity_summary_count_matches": count_matches,
        },
    }


def print_report(view):
    app = view["application"]
    dep = view["deployment"]
    s = view["summary"]

    print(f"\n{'=' * 72}")
    print(f"  {app['name'] or '(unnamed)'}   [{app['resource_type']}]")
    print(f"{'=' * 72}")
    print(f"  account {app['account_id']}  region {app['region']}  "
          f"tech {', '.join(app['technologies']) or 'n/a'}")
    print(f"  deployed on: {dep['type']} -> {dep['cloud_asset_resource_id']}")
    for h in dep["hosting_assets"]:
        print(f"      {h['relationship']}: {h['resource_type']}  {h['resource_id']}")
    if not dep["hosting_assets"]:
        print("      WARNING: no 'is deployed by' edge -- cannot correlate to a host")
    for e in dep["other_relationships"]:
        print(f"      (also {e['relationship']}: {e['resource_type']}  {e['resource_id']})")

    print(f"\n  SCOPE: {s['scope']}")
    print(f"  packages carrying reachable CVEs: {s['packages_with_reachable_cves']}"
          f"  ({s['distinct_package_names']} distinct names)")
    print(f"  reachable CVEs: {s['reachable_cve_count']}")
    print(f"      by NVD severity:  {s['cve_by_nvd_severity']}")
    print(f"      by ExPRT rating:  {s['cve_by_exprt_rating']}")
    if s["asset_insights"]:
        print(f"  insights: {', '.join(s['asset_insights'])}")
    for act in view["excessive_permissions"]:
        print(f"  excessive permission: {act.get('provider')}:{act.get('service')}:"
              f"{act.get('action')} ({act.get('category')})")

    # Surface any broken assumption rather than hiding it.
    if s["integrity_config_parse_error"]:
        print(f"  NOTE: configuration did not parse ({s['integrity_config_parse_error']}) "
              f"-- findings below are EMPTY because nothing could be read, "
              f"not because the application is clean")
    if s["integrity_records_without_cve_id"]:
        print(f"  NOTE: {s['integrity_records_without_cve_id']} vulnerability "
              f"record(s) have no cve_id and are excluded from the counts above")
    if s["integrity_unreachable_records"]:
        print(f"  NOTE: {len(s['integrity_unreachable_records'])} record(s) NOT reachable -- "
              f"findings array is no longer reachable-only: "
              f"{s['integrity_unreachable_records']}")
    if s["integrity_orphaned_package_cves"]:
        print(f"  NOTE: {len(s['integrity_orphaned_package_cves'])} package CVE(s) have no "
              f"detail record: {s['integrity_orphaned_package_cves']}")
    if not s["integrity_summary_count_matches"]:
        print("  NOTE: vendor summary.vulnerabilities disagrees with the findings array length")

    print(f"\n  {'-' * 68}")
    print("  PACKAGE -> REACHABLE CVE MAPPING")
    print(f"  {'-' * 68}")
    for pkg in view["packages_with_reachable_cves"]:
        print(f"\n  {pkg['name']}@{pkg['version']}  ({pkg['cve_count']} reachable CVEs)")
        for cve in pkg["cves"]:
            if cve.get("detail_available") is False:
                print(f"      {cve['cve_id'] or '(no cve id)':<20} (no detail in findings)")
                continue
            v3 = cve.get("cvss_v3_score") or {}
            score = v3.get("base_score")
            # format(None, '<5') raises TypeError, so every vendor-supplied
            # field below is coerced -- including cve_id, which is absent on
            # records the vendor returns without one.
            print(f"      {cve['cve_id'] or '(no cve id)':<20} "
                  f"NVD {cve.get('severity') or '-':<8} "
                  f"CVSSv3 {'-' if score is None else score:<5} "
                  f"ExPRT {cve.get('exprt_rating') or '-'}")
            if cve.get("remediation"):
                print(f"          fix: {cve['remediation']}")

    flows = view["interfaces_and_flows"]
    if any(flows.values()):
        print(f"\n  {'-' * 68}")
        print("  INTERFACES AND DATA FLOWS")
        print(f"  {'-' * 68}")

        if flows["rest_inbound"]:
            print(f"\n  exposed endpoints ({len(flows['rest_inbound'])}):")
            for i in flows["rest_inbound"]:
                print(f"      {i['method'] or '?':<7} {i['path_pattern'] or '/'} "
                      f"  :{i['port']}")

        if flows["rest_outbound"]:
            print(f"\n  outbound calls ({len(flows['rest_outbound'])}):")
            for o in flows["rest_outbound"]:
                dyn = "" if o["targets_static"] else "  [dynamic target]"
                print(f"      {o['method'] or '?':<7} {o['host']}:{o['port']}"
                      f"{o['path'] or ''}{dyn}")

        if flows["datastore_access"]:
            print(f"\n  datastore access ({len(flows['datastore_access'])}):")
            for d in flows["datastore_access"]:
                tags = f"  sensitive: {d['sensitive_data_tags']}" if d["sensitive_data_tags"] else ""
                label = d["technology"] or d["category"] or "?"
                print(f"      {label:<12} {d['operation'] or '?':<6} "
                      f"{d['asset_gcrn'] or '-'}{tags}")

        if flows["message_broker_producer"]:
            print(f"\n  message broker writes ({len(flows['message_broker_producer'])}):")
            for b in flows["message_broker_producer"]:
                loc = " ".join(str(x) for x in (b["account_id"], b["region"]) if x)
                print(f"      {b['technology'] or '?':<8} {b['target'] or '-'}  {loc}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Inventory ASPM applications with package and reachable-CVE correlation",
        epilog="One of --name, --list or --limit is required. "
               "For every application at once, use aspm_fleet_report.py.",
    )
    parser.add_argument("--name", help="exact application resource_name")
    parser.add_argument("--limit", type=int,
                        help="report on the first N applications; ignored when "
                             "--name is given, since all matches are reported")
    parser.add_argument("--list", action="store_true", help="list application names and exit")
    parser.add_argument("--output", help="write JSON here (default: auto-named file)")
    parser.add_argument("--base-url", default=resolve_base_url(),
                        help=f"API base URL (default: {BASE_URL_ENV} or {DEFAULT_BASE_URL})")
    args = parser.parse_args()

    # Without this, a bare invocation would silently report on one arbitrary
    # application, which reads as a complete inventory but is not one.
    if not args.name and not args.list and args.limit is None:
        parser.error("specify --name NAME, --list, or --limit N "
                     "(for the whole fleet use aspm_fleet_report.py)")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be 1 or greater")

    client_id = os.getenv("FALCON_CLIENT_ID")
    client_secret = os.getenv("FALCON_CLIENT_SECRET")
    if not client_id or not client_secret:
        sys.exit("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET")

    client = FalconClient(client_id, client_secret, args.base_url)
    try:
        client.authenticate()
    except AuthError as err:
        sys.exit(str(err))

    # When a name is given, fetch every match so ambiguity is detectable --
    # truncating to --limit first would hide it.
    fetch_limit = FETCH_ALL if (args.name or args.list) else args.limit
    ids = client.query_aspm_applications(args.name, limit=fetch_limit)

    if not ids:
        sys.exit(f"No {RESOURCE_TYPE} assets found"
                 + (f" named '{args.name}'" if args.name else ""))

    if args.list:
        incomplete, detail = truncation_status(len(ids), client.last_query_total)
        if incomplete:
            print(f"WARNING: this list may be incomplete -- {detail}",
                  file=sys.stderr)
        print(f"{len(ids)} ASPM applications:")
        for asset in client.get_assets(ids):
            print(f"  {str(asset.get('resource_name')):<40} "
                  f"{asset.get('account_id')}  {asset.get('region')}")
        return

    # resource_name is not unique -- distinct assets can share one. Process
    # every match rather than silently reporting on an arbitrary one.
    if args.name and len(ids) > 1:
        print(f"NOTE: '{args.name}' matches {len(ids)} distinct assets; "
              f"reporting on all of them", file=sys.stderr)
        selected = ids
    elif args.limit is not None:
        selected = ids[:args.limit]
    else:
        selected = ids

    views = []
    for asset in client.get_assets(selected):
        view = build_application_view(asset)
        views.append(view)
        print_report(view)
    if len(views) < len(selected):
        print(f"warning: {len(selected) - len(views)} asset(s) returned no entity",
              file=sys.stderr)

    payload = views[0] if len(views) == 1 else {"applications": views}
    out = args.output or f"aspm_application_{time.strftime('%Y%m%d_%H%M%S')}.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    print(f"JSON written to {out}")


def _cli():
    """Keep sys.exit outside the try so SystemExit is not caught here."""
    try:
        main()
    except (AuthError, ScopeError) as err:
        print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
