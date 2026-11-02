# Example inventories

Tenable answers "what did the scanner see?" It does not know who owns an asset
or whether the EDR agent is healthy. These two optional CSVs fill that gap.

## Matching

The `match` column is compared, case-insensitively, against the asset's:

1. Tenable asset UUID
2. hostname
3. FQDN
4. NetBIOS name
5. IPv4 address
6. MAC address (normalized to `aa:bb:cc:dd:ee:ff`)

The first matching row wins. One row per asset (or per identifier) is simplest.

## Owners

```csv
match,owner,team,email
```

A missing row is recorded as `owner: unknown` with the reason
`no CMDB owner mapping configured`. It is never filled from a guess.

## Controls

```csv
match,edr_present,edr_vendor,edr_version,edr_baseline_version,edr_last_seen,edr_feed_age_hours,edr_mode,av_present,av_vendor,av_version,av_baseline_version,av_signature_age_hours,av_mode,app_control_mode,nac_compliant,nac_policy,patch_agent_present,source,updated_at
```

- Boolean fields accept `true/false`, `yes/no`, `1/0`.
- A blank field is **unknown**, not false. The report records the reason.
- `*_mode` is a free-text label from your control plane, for example `prevent`,
  `monitor`, `audit`, or `disabled`.
- `nac_compliant` (or `nac_posture`) accepts true/false, `compliant`/`noncompliant`,
  `pass`/`fail`, or `permit`/`deny`.
- `source` and `updated_at` make the evidence defensible: a reader can see which
  inventory supplied the value and when.

### Which fields drive which KRI

| KRI | Fields |
|---|---|
| KRI-01 Missing security agent | `edr_present`, `av_present`, plus Tenable `has_agent` |
| KRI-02 Stale control version | `edr_version`/`edr_baseline_version`, `av_version`/`av_baseline_version` |
| KRI-03 Stale threat feeds | `edr_feed_age_hours`, `av_signature_age_hours` (24h SLA) |
| KRI-04 Detect-only mode | `edr_mode`, `av_mode`, `app_control_mode` |
| KRI-05 Unpatched exploitable host | Tenable findings for MS17-010/CVE-2017-0144 |
| KRI-06 NAC non-compliant posture | `nac_compliant` / `nac_posture`, `nac_policy` |
| KRI-07 Active compromise | EDR `infection_status`, `behavioral_matches` |

The example rows intentionally include DC01, WS-FIN-042, and WS-MKT-011 so the
seven-KRI catalog can be demonstrated without changing a real control plane.

## EDR status fixture

`edr_status.example.json` exercises the infection branch without an EDR tenant.
Copy it to `.state/edr_status.json` before `secops verify`:

```json
{
  "assets": {
    "srv-01": {
      "present": true,
      "vendor": "ExampleEDR",
      "version": "7.2.0",
      "feed_age_hours": 6,
      "infection_status": "infected"
    }
  }
}
```

The engine will create a simulated SOC case and refuse to restore that asset.
With no fixture and no EDR connector, infection status remains `unknown`; it is
never treated as clean.

## Try it

```bash
python -m secops_autopilot run --cve CVE-2017-0144 \
  --owners examples/owners.example.csv \
  --controls examples/controls.example.csv
```
