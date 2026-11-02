# Tenable integration

SecOps Autopilot reads Tenable; it does not scan. The connector interface lives
in `secops_autopilot/connectors/`.

## Authentication

### Vulnerability Management (cloud.tenable.com)

```http
X-ApiKeys: accessKey=<access>; secretKey=<secret>;
User-Agent: SecOps-Autopilot/0.1.0 (SWARM-Tenable-Hackathon; security-team@example.com)
Accept: application/json
```

The header is built once in `connectors/http.py` and every request goes through
that transport. Tenable requires a descriptive `User-Agent` identifying the
integration and a contact for support; the integration name, version, and
contact are recorded in every run snapshot.

Credentials are read from `.env` or the process environment. They are never
written to `run.json`, stage records, reports, or request logs. Tests assert the
access and secret keys do not appear anywhere under `runs/`.

### Security Center

The adapter sends the same `X-ApiKeys` header to the appliance's `/rest` API.
Authentication methods vary by SC version; if an installation requires a
username/password session, put a small session adapter in front of
`connectors/http.py` rather than weakening the key handling.

## Endpoints used

### Vulnerability Management

| Endpoint | Purpose | Notes |
|---|---|---|
| `GET /session` | Credential and account check | Also returns the account's permission list |
| `GET /workbenches/vulnerabilities` | CVE → plugin mapping | Filter `plugin.attributes.cve.raw`, quality `eq`; `date_range` scopes the window |
| `POST /vulns/export` | Queue a per-asset findings export | Body `{"filters":{"plugin_id":[...]},"num_assets":5000}` |
| `GET /vulns/export/{uuid}/status` | Export progress | Poll until `FINISHED`, then read `chunks_available` |
| `GET /vulns/export/{uuid}/chunks/{n}` | Findings records | Each record carries asset, plugin metadata, output, CVEs, exploit flags |
| `GET /assets/{uuid}` | Asset posture | `has_agent`, ACR, AES, last scan, MAC/OS |
| `GET /workbenches/assets/{uuid}/info` | Fallback asset detail | Used if `/assets/{uuid}` is unavailable |
| `GET /scanners/agents` | Agent inventory | May return HTTP 403 when the key lacks scope; recorded as unknown, not fatal |

A nuance worth knowing: `/workbenches/vulnerabilities` responds with a
`total_asset_count` that can be `0` even when per-plugin asset counts are
non-zero. The engine derives affected asset counts from the exported findings,
not that aggregate field, and records the observation in intake notes.

Export filters are an object, not the workbench's indexed filter syntax:

```json
{"filters": {"plugin_id": [900001]}, "num_assets": 5000}
```

The CVE filter itself is a workbench filter:

```text
filter.0.filter=plugin.attributes.cve.raw
filter.0.quality=eq
filter.0.value=CVE-2017-0144
```

Only one export can run per tenant at a time. On HTTP 409 the client reads the
`active_job_id`, waits for that export to finish, and retries its own request.

### Security Center

| Endpoint | Purpose |
|---|---|
| `GET /rest/currentUser` | Credential check |
| `POST /rest/analysis` | CVE/plugin query, `tool=vulndetails`, `filterName=cveID` |
| `GET /rest/asset/{id}` | Asset detail |
| `GET /rest/agent` | Agent inventory where the SC version exposes it |

The analysis payload follows the shape used by pyTenable:

```json
{
  "type": "vuln",
  "sourceType": "cumulative",
  "query": {
    "type": "vuln",
    "tool": "vulndetails",
    "startOffset": 0,
    "endOffset": 5000,
    "filters": [
      {"filterName": "cveID", "operator": "=", "value": "CVE-2017-0144"}
    ]
  },
  "sortField": "severity",
  "sortDir": "DESC"
}
```

SC column names vary by version and tool. The parser maps the documented
`vulndetails` fields and degrades unmapped fields to `unknown`.

**Validation status:** the SC adapter was written against the documented API and
pyTenable's payload construction. No SC appliance was available in the lab, so it
is marked `live_validated: false` in every run snapshot.

## Data freshness and verification

A Tenable finding is point-in-time. The engine treats the *disappearance* of a
finding after a new scan as remediation evidence. It does not treat an old
`last_found` timestamp, a missing asset record, or a failed query as a fix.
Verification records the query method, window, and per-asset last scan.

## Rate limits and retries

- HTTP 429: honor `Retry-After` (capped at 60s), then retry.
- HTTP 500/502/503/504: exponential backoff with jitter, up to four retries.
- HTTP 401/403: fail with a typed error. `Insufficient scope` becomes a
  `ScopeError` used for optional endpoints such as agent inventory.
- Network errors: retried; the run records the final failure and does not claim
  a result.

## Scope observed on the lab tenant

On the SWARM lab key, `GET /scanners/agents` returned:

```text
HTTP 403 {"statusCode":403,"error":"Forbidden","message":"Insufficient scope"}
```

The engine records agent version, status, and feed age as `unknown` with that
reason. It still uses the asset's `has_agent` flag, which is a different signal.
The export also carries an `agent_uuid` field on scanner-only assets in this
tenant, so that field alone is not treated as proof of an endpoint agent. A
conflict is recorded only when the asset's source type indicates an agent and
`has_agent` is false.

## Extending to another Tenable product

Implement the `VulnerabilitySource` protocol in `connectors/base.py`:

```python
cve_plugin_hits(cve, date_range) -> list[PluginHit]
findings_for_plugins(plugin_ids, date_range) -> list[Finding]
asset_detail(asset_uuid) -> dict
agent_inventory() -> (list[dict] | None, str | None)
public_snapshot() -> dict
```

The pipeline, scoring, remediation, approval, and evidence layers do not change.
