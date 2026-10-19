# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

* `docs/PROJECT_STATUS.md`: precise state of the module — 1,160 `pyflakes` diagnostics,
  226 undefined names (14 stdlib imports · 57 helpers/constants from the earlier build ·
  155 engine definitions absent everywhere), the duplicated tail, and the exact section
  required to finish it.
* `docs/architecture_workflow.md`: phase model, per-device state machine, concurrency,
  failure taxonomy, checkpoints and artefacts.
* `examples/`: two sample inventories with documentation-range addresses plus the accepted
  line formats.
* `config.example.json`: the supported `config.json` tuning overrides.
* CI (syntax gate, informational `pyflakes`, documentation and repository hygiene checks),
  Dependabot, issue and pull-request templates.

### Changed

* Removed build/version labels from the module and documentation: comments, self-test names
  and the hard-coded version assertion are gone; the self-test now checks that
  `VERSION_STRING` is a non-empty string instead of matching a specific number.

### Known gaps

* The module's header (imports, constants) and helper block are not in the tree yet, so the
  CLI exits immediately. See [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md).

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
