# ASPM Application Inventory

Inventory CrowdStrike ASPM applications via the Falcon Cloud Security asset
API: their code-reachable CVEs, the packages carrying them, the cloud resource
running each application, and the interfaces and data flows ASPM observed.

Python 3.7+, standard library only. No `pip install` required.

## Prerequisites

- Falcon Cloud Security with ASPM enabled, and applications already discovered
  (check **Cloud security → Application explorer** in the console; if it is
  empty these scripts will report nothing)
- An API client with read access to Cloud Security assets — see
  [Required API scope](#required-api-scope)
- Python 3.7 or newer

## Scripts

| Script | Purpose |
|---|---|
| `aspm_application_inventory.py` | Report on one application (or all matches for a name) |
| `aspm_fleet_report.py` | Walk every application, validate invariants, rank by risk |
| `test_aspm_inventory.py` | Offline tests for the parsing layer (no credentials needed) |

## Data source

```
GET /cloud-security-assets/queries/resources/v1?filter=resource_type:'ASPM::Application'
GET /cloud-security-assets/entities/resources/v1?ids=<asset id>
```

Asset IDs are pipe-delimited:

```
<CID>|aspm|<aws-account>|<region>|ASPM::Application|<resource-id>
```

If you copy an ID out of an Application Explorer console URL, **drop the
trailing `|<name>` segment** — that part is for display and the entities
endpoint returns 404 with it attached.

Package, CVE, interface and data-flow data all live inside the asset's
`configuration` field, which is a **JSON string** that must be parsed
separately. Under `configuration.embeddedFindings`:

| Key | Contents |
|---|---|
| `vulnerable_packages` | package name, version, and its CVE ids |
| `vulnerabilities` | per-CVE detail: CVSS v2/v3, NVD severity, ExPRT rating, remediation |
| `admin_action` | excessive IAM actions |
| `rest_inbound` | exposed endpoints (method, path pattern, port) |
| `rest_outbound` | outbound calls (method, path, host, port) |
| `datastore_access` | datastore reads/writes, with a `gcrn` to the target cloud asset |
| `message_broker_producer` | queue/topic writes |

Host correlation comes from the asset's `relationships[]`. That array mixes
edge types, and only **`is deployed by`** identifies the cloud resource running
the application (`AWS::Lambda::Function`, `AWS::ECS::Task`, and so on). An
`accesses` edge points at something the application talks to — an S3 bucket, a
database — so it is reported separately under `other_relationships` rather than
being counted as host correlation.

### Required API scope

Create an API client in the Falcon console under **Support and resources → API
clients and keys**, and grant it read access to Cloud Security assets. In the
scope list this is the entry covering `cloud-security-assets` — CrowdStrike has
labelled it **Cloud security API assets: Read**, though the exact wording varies
between console versions. If a request returns `403`, the client is missing that
scope.

The OAuth token response does not report granted scopes, so the script cannot
check this for you up front.

This does *not* use the legacy `/aspm-api-gateway/` API, which addresses a
different dataset and does not contain these applications. An ASPM read-only
scope alone is **not** sufficient.

## Severity models

`severity` and `cvss_v3_score` are NVD-derived; `exprt_rating` is
CrowdStrike's own model. They can differ substantially for the same CVE, so
both are reported rather than one being chosen for you.

## Usage

### 1. Set credentials

```bash
export FALCON_CLIENT_ID="your-client-id"
export FALCON_CLIENT_SECRET="your-client-secret"
```

Both scripts exit immediately with a message if either is unset.

### 2. Set your cloud, if it is not US-1

`FALCON_BASE_URL` defaults to `https://api.crowdstrike.com` (US-1). Use the
host matching your Falcon tenant:

| Cloud | Base URL |
|---|---|
| US-1 (default) | `https://api.crowdstrike.com` |
| US-2 | `https://api.us-2.crowdstrike.com` |
| EU-1 | `https://api.eu-1.crowdstrike.com` |
| US-GOV-1 | `https://api.laggar.gcw.crowdstrike.com` |

On any other cloud, take the base URL from your own API client page in the
console rather than guessing — these four are the ones verified against this
script.

```bash
export FALCON_BASE_URL="https://api.eu-1.crowdstrike.com"
```

`--base-url` overrides the variable for a single run. Pointing at the wrong
cloud produces a redirect rather than an auth error; the script reports it and
names the correct host, for example:

```
https://api.eu-1.crowdstrike.com redirected (308): wrong Falcon cloud.
Your tenant appears to be at https://api.crowdstrike.com. Set
FALCON_BASE_URL accordingly.
```

### 3. Run

Start by listing what ASPM has discovered:

```bash
python3 aspm_application_inventory.py --list
```

Then report on one application by its exact name:

```bash
python3 aspm_application_inventory.py --name my-app
```

Or the first N applications, writing JSON to a path you choose:

```bash
python3 aspm_application_inventory.py --limit 5 --output out.json
```

For every application at once, with validation, use the fleet report:

```bash
python3 aspm_fleet_report.py
```

`aspm_application_inventory.py` **requires one of `--name`, `--list` or
`--limit`** and errors out otherwise, rather than guessing. Without `--output`
it writes `aspm_application_<timestamp>.json`; the fleet report writes
`aspm_fleet_<timestamp>.json`. Both print a human-readable report to stdout as
well, so piping stdout to a file loses nothing.

Misconfiguration is reported as a single line, not a traceback: rejected
credentials, an unreachable host, the wrong cloud, and a missing API scope each
produce a message naming what to change.

Exit codes: `0` on success; `1` for missing credentials, an authentication or
scope failure, or no matching application; `2` for a bad argument combination.
`aspm_fleet_report.py` additionally exits `1` when a validation invariant
fails, which makes it usable as a CI drift check.

### Notes on matching and requests

`resource_name` is **not unique** — distinct assets can share a name. When
`--name` matches more than one, every match is reported and a note is written to
stderr, rather than an arbitrary one being picked. `--limit` does not apply in
that case; all matches are reported so none is silently hidden.

Asset entities are fetched in batches of 50 repeated `ids=` params, so a
149-application fleet is 3 requests rather than 149. Requests retry with
exponential backoff on 429 and 5xx, honour `Retry-After`, and re-authenticate
once on 401 so long walks survive token expiry.

## Tests

```bash
python3 test_aspm_inventory.py
```

Runs offline against synthetic assets — no credentials, no network. Covers the
package↔CVE join, shared-CVE deduplication, the absent-vendor-count case,
`ABSENT` vs the vendor's real `UNKNOWN`, null-field handling, id batching and
ordering, and FQL quote rejection. The live invariant checks in
`aspm_fleet_report.py` are complementary, not a substitute.

## Validation

`aspm_fleet_report.py` asserts eight invariants per application and exits
non-zero on any failure, so it is safe to run in CI as a drift detector
against vendor-side changes:

1. **reachable-only findings** — `reachable` is true on every record
2. **package→CVE join completeness** — every package-referenced CVE has a
   detail record
3. **vendor count agreement** — indexed CVEs plus records dropped for lacking
   an id equal the vendor's `summary.vulnerabilities`
4. **no duplicate CVE ids** — the internal index is keyed by id, so duplicates
   would be silently dropped
5. **severity matches CVSS band** — each NVD severity label agrees with its own
   CVSS v3 base score
6. **pairs cover unique CVEs** — package→CVE pairs ≥ unique CVEs
7. **configuration parsed** — the `configuration` blob decoded to an object
8. **every record has a cve_id** — nothing was excluded from the counts

Each failure is prefixed with the bracketed name above so the output says which
invariant broke. `INVARIANT_COUNT` is `len(INVARIANTS)`, the same table
`validate()` iterates, so adding a check updates the printed count — but this
list is prose and still has to be edited by hand.

An optional regression check pins one application to a known-good package set
and CVE count. The baseline is tenant-specific and therefore not shipped here;
point `ASPM_REGRESSION_BASELINE` at a JSON file to enable it:

```json
{"name": "my-app", "reachable_cves": 21,
 "packages": [{"name": "urllib3", "version": "1.26.4", "cve_count": 11}]}
```

Coverage gaps are reported separately from invariant failures, broken down by
deployment type. An application with no `is deployed by` edge cannot be tied to
the resource running it; it may still carry other edges such as `accesses`,
which describe data flow rather than hosting. The coverage table prints on
every run, so an absent table never has to be read as full coverage.

Host correlation is not uniform across deployment types. In the reference
tenant every Lambda, ECS task and Azure Function App carried an `is deployed
by` edge (139/139), while **no** Kubernetes deployment did (0/7) — so do not
rely on Kubernetes host correlation, and check the coverage table the fleet
report prints before trusting it anywhere.

Note that counting package→CVE pairs overstates findings where one CVE affects
two versions of the same package; the unique-CVE count is the figure to use.

## License

MIT — see [LICENSE](LICENSE).
