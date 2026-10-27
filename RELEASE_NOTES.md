# Initial release (v1.1.0) — working build

Enterprise Cisco IOS-XE Upgrade Orchestrator — a single-file Python tool that plans and
executes bulk firmware upgrades for Cisco Catalyst fleets (9200 / 9200L / 9200CX / 9300 /
9500) to IOS-XE 17.18.04.

> **Supersedes v1.0.0**, whose `orchestrator.py` was a truncated merge that failed on
> start-up with `NameError: name 'sys' is not defined`. This build runs.

## Verification

Run from the repository root (`pip install -r requirements.txt` first):

```text
python orchestrator.py --version    -> orchestrator.py v1.0.0 (target IOS-XE 17.18.04)
python orchestrator.py --help       -> full CLI
python orchestrator.py --validate   -> Passed: 20/20
```

Verified on Python 3.14 with paramiko 5.1.0 and netmiko 4.8.0. CI runs the same gates on
Python 3.10, 3.11 and 3.12.

## Highlights

* **Fleet discovery** from `locations/<site>.txt` or `--hosts`, with `--limit` / `--exclude`.
* **Pre-flight validation** — running version, model/firmware consistency, free-flash
  arithmetic (`insufficient_space`), boot-mode detection (bundle vs install).
* **Crash-resistant transfer** — SCP via pscp with stall detection (`SCP_STALL_TIMEOUT`),
  retry, host-key retry and a tuned paramiko fallback; MD5 verification of the image.
* **State-driven install** — `install add` → `activate` → `commit`, one command per state
  read, with installer-lock clearing and `packages.conf` repair.
* **Reboot monitoring** — ICMP down/up/stable, SSH readiness, boot-loop detection.
* **Post-upgrade verification** — version, stack members, interfaces, running-config drift.
* **Temporary-change ledger** — every temp config change recorded and reverted (with
  verification); `--recover` / `--revert-only` / `--dry-run-revert`.
* **Checkpoint and resume** per location and per device.
* **Reporting** — per-location CSV **and** JSON, a rollback document per location, master and
  per-device logs.
* **Safety rails** — `--validate`, `--check`, `--dry-run`, and a confirmation prompt unless
  `--yes` is given.

## Getting started

```bash
git clone https://github.com/rainykarthick-crypto/cisco-xe-upgrade-orchestrator.git
cd cisco-xe-upgrade-orchestrator
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python orchestrator.py --version
python orchestrator.py --validate          # offline self-test, no switches touched
python orchestrator.py --help
```

Working directories (`firmware/`, `locations/`, `logs/`, `reports/`, `state/`, `backups/`)
live in the base directory — pass `--base-dir .` to keep them next to the script. Sample
inventories are in `examples/`; copy one to `locations/HQ.txt` and edit it.

Optional: put `pscp.exe` (PuTTY) in the base directory for the fastest transfer path; without
it the orchestrator falls back to a tuned paramiko SFTP transfer.

## What is in this release

| Path | Contents |
|---|---|
| `orchestrator.py` | 4,338-line single-file orchestrator |
| `requirements.txt` | `paramiko`, `netmiko` |
| `config.example.json` | tuning overrides (`config.json`) |
| `docs/architecture_workflow.md` | phase model, state machine, failure taxonomy |
| `docs/PROJECT_STATUS.md` | verification recipe and what the self-test covers |
| `examples/` | sample inventories (documentation-range addresses) |
| `.github/` | CI, Dependabot, issue and PR templates |

## Safety notice

This tool logs into network devices and changes boot images. Test in a lab against your exact
models and IOS-XE versions, run `--dry-run` first, and keep a configuration backup before the
first wave. Never commit real inventories, firmware images or credentials — they are
git-ignored by design.
