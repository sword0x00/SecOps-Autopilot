#!/usr/bin/env bash
# Read-only demo. The state-changing gates are printed for a human to execute.
set -euo pipefail
cd "$(dirname "$0")/.."

CVE="${1:-CVE-2017-0144}"

echo "== 1. Tenable connectivity and scope =="
python3 -m secops_autopilot doctor || true

echo
echo "== 2. Tenant overview =="
python3 -m secops_autopilot inventory --limit 2000 || true

echo
echo "== 3. Read-only pipeline: intake -> exposure -> controls -> KRI -> plan =="
RUN=$(python3 -m secops_autopilot run --cve "$CVE" --json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["run_id"])')

python3 -m secops_autopilot status --run "$RUN"

cat <<EOF

== 4. Human approval gates (state-changing, simulated control plane) ==

The run stopped before the first state change. Execute these one at a time:

  python3 -m secops_autopilot approve --run $RUN --gate ticket \\
    --approver "Your Name"

  python3 -m secops_autopilot approve --run $RUN --gate remediation \\
    --approver "Infosec Approver" --note "Approved for containment pending patch"

  python3 -m secops_autopilot approve --run $RUN --gate containment \\
    --approver "SecOps Lead"

  python3 -m secops_autopilot verify --run $RUN

  python3 -m secops_autopilot report --run $RUN --format html --verify

Evidence: runs/$RUN/
EOF
