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
match,edr_present,edr_vendor,edr_version,edr_last_seen,edr_feed_age_hours,av_present,av_vendor,av_signature_age_hours,app_control_mode,patch_agent_present,source,updated_at
```

- Boolean fields accept `true/false`, `yes/no`, `1/0`.
- A blank field is **unknown**, not false. The report records the reason.
- `app_control_mode` is a free-text label from your control plane, for example
  `enforce`, `audit`, or `disabled`.
- `source` and `updated_at` make the evidence defensible: a reader can see which
  inventory supplied the value and when.

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
