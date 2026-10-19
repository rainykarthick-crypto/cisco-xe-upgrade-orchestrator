# Initial release

Enterprise Cisco IOS-XE Upgrade Orchestrator — a single-file Python tool that plans and
executes bulk firmware upgrades for Cisco Catalyst fleets (9200 / 9200L / 9200CX / 9300 /
9500) to IOS-XE 17.18.04.

## Highlights

* **Fleet discovery** from `locations/<site>.txt` or `--hosts`, with `--limit` / `--exclude`.
* **Pre-flight validation** — running version, model/firmware consistency, free-flash
  arithmetic (`insufficient_space`), boot-mode detection (bundle vs install).
* **Crash-resistant transfer** — SCP via pscp with stall detection, retry, host-key retry and
  a tuned paramiko fallback; MD5 verification of the transferred image.
* **State-driven install** — `install add` → `activate` → `commit`, one command per state
  read, with installer-lock clearing and `packages.conf` repair.
* **Reboot monitoring** — ICMP down/up/stable, SSH readiness, boot-loop detection.
* **Post-upgrade verification** — version, stack members, interfaces, running-config drift.
* **Temporary-change ledger** — every temp config change recorded and reverted (with
  verification); `--recover` / `--revert-only` / `--dry-run-revert`.
* **Checkpoint and resume** per location and per device.
* **Reporting** — per-location CSV, per-location rollback document, master and per-device
  logs, optional HTML dashboard.
* **Safety rails** — `--validate`, `--check`, `--dry-run`, and a confirmation prompt unless
  `--yes` is given.

## Getting started

```bash
git clone https://github.com/rainykarthick-crypto/cisco-xe-upgrade-orchestrator.git
cd cisco-xe-upgrade-orchestrator
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python orchestrator.py --validate
python orchestrator.py --help
```

Working directories (`firmware/`, `locations/`, `logs/`, `reports/`, `state/`, `backups/`)
live in the base directory — pass `--base-dir .` to keep them next to the script.
Sample inventories are in `examples/`; copy them to `locations/HQ.txt` and edit.

## What is in this release

| Path | Contents |
|---|---|
| `orchestrator.py` | the single-file orchestrator |
| `requirements.txt` | `paramiko`, `netmiko` |
| `config.example.json` | tuning overrides (`config.json`) |
| `docs/architecture_workflow.md` | phase model, state machine, failure taxonomy |
| `docs/PROJECT_STATUS.md` | current module state and what remains |
| `examples/` | sample inventories (documentation-range addresses) |
| `.github/` | CI, Dependabot, issue and PR templates |

## Known gap

The module in this tree is still being assembled: its header (imports, constants) and helper
block are not present yet, so the CLI exits immediately with `NameError`. `py_compile` passes.

`docs/PROJECT_STATUS.md` lists the missing definitions (226 undefined names: 14 stdlib
imports, 57 helpers/constants from an earlier build, 155 engine definitions) and the two
steps needed to finish it. Once the header is added and the duplicated tail removed, CI's
`--validate` step can be re-enabled as a gate.

## Safety notice

This tool logs into network devices and changes boot images. Test in a lab against your exact
models and IOS-XE versions, run `--dry-run` first, and keep a configuration backup before the
first wave. Never commit real inventories, firmware images or credentials — they are
git-ignored by design.
