# CyberAgents Exchange submission

This directory contains a **draft** listing for the Tenable CyberAgents Exchange.
It is not submitted automatically. The competition rules require a contribution
to the Exchange and a notification through Tenable's Discord.

## One-time decisions

1. **Confirm the GitHub username.** The listing uses `sword0x00` because that is
   the clone URL in this repository's README. If your account differs, change
   `author` and `github_url` in `secops-autopilot.md`.
2. **Accept the Contribution Agreement.** The agreement is linked from
   `tenable/cyberagents-exchange`. Set `contribution_agreement_date` to the actual
   ISO 8601 acceptance time. The draft deliberately contains
   `REPLACE_WITH_ACTUAL_ISO8601_ACCEPTANCE_TIME` so it cannot pass validation
   until a human has accepted the agreement.
3. **Confirm the repository is public**, owned by a personal GitHub account (not
   an EMU account), and MIT licensed. This repository already contains `LICENSE`.
4. **Confirm no secrets are in git history.** The local `.env`, `runs/`, and
   `.state/` are ignored. Check before the first push:

```bash
git status --short
git grep -nE 'accessKey=|secretKey=|TENABLE_(ACCESS|SECRET)_KEY=.+' || true
```

## Publish the repository first

The Exchange validator does not check URL reachability, but reviewers do. The
repository must be public at the URL declared in the listing:

```text
https://github.com/sword0x00/SecOps-Autopilot
```

If it is not yet published:

```bash
cd /path/to/SecOps-Autopilot
git status --short          # must not list .env, runs/, or .state/
git add .
git commit -m "SecOps Autopilot: Tenable vulnerability-to-evidence pipeline"
# create the empty public repository in the GitHub UI, or with gh:
# gh repo create sword0x00/SecOps-Autopilot --public --source=. --remote=origin --push
git remote add origin https://github.com/sword0x00/SecOps-Autopilot.git
git push -u origin main
git ls-remote https://github.com/sword0x00/SecOps-Autopilot.git HEAD
```

Do not upload a zip that contains `.env`, `runs/`, or `.state/`; those hold local
credentials and lab asset evidence.

## Submit

```bash
# Fork tenable/cyberagents-exchange, then:
git clone https://github.com/<your-user>/cyberagents-exchange.git
cd cyberagents-exchange
git checkout -b add-secops-autopilot
cp /path/to/SecOps-Autopilot/submission/secops-autopilot.md \
   skills/secops-autopilot.md
uv sync
uv run ./validator.py
```

Fix any validator errors, then commit and open a pull request titled:

```text
Add listing: SecOps Autopilot
```

The PR description must include:

```text
I have reviewed and accept the CyberAgents Contribution Agreement.
```

The agreement is at:
`https://github.com/tenable/cyberagents-exchange/blob/main/docs/CyberAgents_Contribution_Agreement`

## After the PR

- The automated validator checks required fields, controlled vocabularies, and
  file placement. Two maintainers review the repository and the listing body.
- Notify Tenable through the method specified on Discord, as required by the
  SWARM Global rules.
- Register for the event at `https://info.tenable.com/2026-SWARM-GLOBAL.html` if
  you have not already.
- SWARM Global 2026 runs November 2–6, 2026; the official rules do not publish a
  separate submission deadline beyond the event window.

## Why this listing is a skill

The project is a Claude Code skill backed by a Python engine. The reusable
capability is the vulnerability-to-evidence workflow, not a single script. The
skill listing points at the repository; the agent, playbook, and CLI live there.
