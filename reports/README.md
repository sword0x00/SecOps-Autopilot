# Reports

Generated artifacts from the live all-CVE scan: the 56 discovered PHP/Node.js
CVEs plus the five added high-profile CVEs (61 runs total).

| File | Audience | Contents |
|---|---|---|
| `Executive-Summary-For-All-CVE.md` | Management | One consolidated report for all 61 CVE runs: assets, KRI coverage, numbers, insights, decisions |
| `Executive-Summary-For-All-CVE.html` | Management (browser) | The same consolidated report as styled HTML |
| `Executive-Summary-For-All-CVE.pdf` | Management (print/share) | The same consolidated report as PDF |
| `Phase-Validation-For-All-CVE.md` | SecOps / engineering | Per-CVE results, phase matrix, evidence paths for all 61 CVE runs |
| `Phase-Validation-For-All-CVE.json` | SecOps / engineering / automation | Machine-readable per-CVE results and run IDs for all 61 CVE runs |
| `cve-list.md` | SecOps / engineering | The scanned CVE set with Tenable finding names, CVSS, and exposure |
| `cve-list.csv` | SecOps / engineering / automation | The same list with status and run IDs |

Every new `secops run` writes its own management summary inside
`runs/<run-id>/executive-summary.md` (and `.html`), alongside `report.md`,
`report.html`, and the SHA-256 manifest. The full per-run evidence stays under
`runs/<run-id>/`.

The live batches are read-only. They did not create a ticket, contain an asset,
submit a patch job, or restore a host. The management summaries are generated from the
run records; they never turn an unknown into a clear result.
