# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

* `docs/PROJECT_STATUS.md`: verification recipe, the last recorded self-test result, and what
  the `--validate` suite actually covers.
* `docs/architecture_workflow.md`: phase model, per-device state machine, concurrency,
  failure taxonomy, checkpoints and artefacts.
* `examples/`: two sample inventories with documentation-range addresses plus the accepted
  line formats.
* `config.example.json`: the supported `config.json` tuning overrides.
* CI (syntax, static analysis, self-test, documentation and repository hygiene), Dependabot,
  issue and pull-request templates.

### Changed

* `orchestrator.py` rebuilt from the complete engine: `VERSION = "1.0.0"`,
  `SCRIPT_NAME = "orchestrator.py"`, and every build/version label removed from comments,
  self-test names and the version assertion (now a non-empty-string check).
* README: quality-gate table with verified results; the HTML-report claim removed (the module
  writes a CSV and a JSON per location, a rollback document and logs).

### Fixed

* The module runs again. `--version`, `--help` and `--validate` (**20/20**) all pass under
  Python 3.14 with paramiko 5.1.0 and netmiko 4.8.0. The previous revision was a truncated
  merge that raised `NameError: name 'sys' is not defined` on start-up.

## [Initial import] - 2026-10-19

### Added

* Single-file orchestrator for bulk Cisco Catalyst (9200 / 9200L / 9200CX / 9300 / 9500)
  upgrades to IOS-XE **17.18.04**.
* Fleet discovery from `locations/<site>.txt` or `--hosts`, with `--limit` / `--exclude`.
* Pre-flight validation: running version, model/firmware consistency, free-flash arithmetic
  (`insufficient_space`), boot-mode detection (bundle vs install).
* SCP transfer via pscp with stall detection, retry, host-key retry and a tuned paramiko
  fallback; MD5 verification of the transferred image.
* State-driven `install add` → `activate` → `commit`, one command per state read, with
  installer-lock clearing and `packages.conf` repair.
* Reboot monitoring (ICMP down/up/stable, SSH ready, boot-loop detection) and post-upgrade
  verification (version, stack, interfaces, running-config drift).
* Temporary-change ledger (`state/temp_changes_<RUN_ID>.json`) with revert and verification;
  `--recover` / `--revert-only` / `--dry-run-revert`.
* Checkpoint and resume per location and per device.
* CSV reports per location, rollback documents per location, master and per-device logs.
* Safety rails: `--validate`, `--check`, `--dry-run`, and a confirmation prompt unless
  `--yes` is given.
