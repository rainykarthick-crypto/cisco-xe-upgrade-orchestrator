# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), project versioning follows
the tool's own `v<major>.<minor>.<build>` scheme.

## [Unreleased] — v35.9.43 (incomplete)

### Added

* `docs/PROJECT_STATUS.md`: precise status of the v35.9.43 merge — 226 undefined names
  (14 stdlib imports, 57 present in v35.9.34, 155 missing everywhere), the duplicated tail,
  and the exact section required to finish it.
* `docs/architecture_workflow.md`: phase model, per-device state machine, concurrency,
  failure taxonomy, checkpoints and artefacts.
* `examples/`: two sample inventories with documentation-range addresses and the accepted
  line formats.
* `config.example.json`: the supported `config.json` tuning overrides.
* CI (`py_compile` + `pyflakes` + the v35.9.34 self-test), Dependabot, issue/PR templates.

### Changed

* `orchestrator.py` now holds the v35.9.43 development merge (imported verbatim). It is
  **not runnable** until its header/helper block is restored — the complete build remains
  available at tag [`v35.9.34`](https://github.com/rainykarthick-crypto/cisco-xe-upgrade-orchestrator/releases/tag/v35.9.34).

### Removed

* The duplicate second half of the imported file is documented (not silently dropped) so the
  original content can be diffed when the header is supplied.

## [v35.9.34] - 2026-10-19

### Added

* Initial public release: single-file orchestrator for bulk Cisco Catalyst
  (9200/9200L/9200CX/9300/9500) upgrades to IOS-XE **17.18.04**.
* Fleet discovery from `locations/<site>.txt` or `--hosts`, with `--limit` / `--exclude`.
* Pre-flight validation: running version, model/firmware consistency, free-flash arithmetic
  (`insufficient_space`), boot-mode detection (bundle vs install).
* SCP transfer via pscp with stall detection, retry, host-key retry and a tuned paramiko
  fallback; MD5 verification of the transferred image.
* State-driven `install add` → `activate` → `commit`, one command per state read, with
  installer-lock clearing and `packages.conf` repair.
* Reboot monitoring (ICMP down/up/stable, SSH ready, boot-loop detection) and post-upgrade
  verification (version, stack, interfaces, running-config drift).
* Temporary-change ledger (`state/temp_changes_<RUN_ID>.json`) with revert and
  verification; `--recover` / `--revert-only` / `--dry-run-revert`.
* Checkpoint & resume per location and per device.
* CSV reports per location, rollback documents per location, master and per-device logs.
* Safety rails: `--validate`, `--check`, `--dry-run`, confirmation prompt unless `--yes`.
