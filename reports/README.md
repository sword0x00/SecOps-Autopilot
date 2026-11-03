# Reports

Generated artifacts from the live PHP/Node.js batch.

| File | Audience | Contents |
|---|---|---|
| `live-php-node-executive-summary.md` | Management | One consolidated report: all CVEs, all assets, KRI coverage, numbers, insights, decisions |
| `live-php-node-executive-summary.html` | Management (browser) | The same consolidated report as styled HTML |
| `live-php-node-executive-summary.pdf` | Management (print/share) | The same consolidated report as a 5-page PDF |
| `live-php-node-phase-validation.md` | SecOps / engineering | Per-CVE results, phase matrix, evidence paths |
| `live-php-node-assessment.md` | SecOps / architecture | Issues, priority classification, recommended actions |
| `not-running-inventory.md` | Engineering / audit | Functions, scripts, skills, and Markdown not executed by the final batch |
| `executive-summaries/<run-id>.md` | Management | One management summary per live run |

Every new `secops run` writes its own `executive-summary.md` inside
`runs/<run-id>/`, alongside `report.md`, `report.html`, and the SHA-256 manifest.

The live batch is read-only. It did not create a ticket, contain an asset, submit
a patch job, or restore a host. The management summaries are generated from the
run records; they never turn an unknown into a clear result.
