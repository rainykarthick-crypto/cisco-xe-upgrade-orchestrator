# Security Policy

## Supported builds

The repository tracks a single verified build on `main` (`orchestrator.py` v1.0.0). Its
verification status and the checks to reproduce it are recorded in
[docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md).

## Reporting a vulnerability

Please do **not** disclose security issues in public issues or pull requests.

Use GitHub's private reporting:
**Security → Advisories → Report a vulnerability**
(`https://github.com/rainykarthick-crypto/cisco-xe-upgrade-orchestrator/security/advisories/new`)

Include: affected version/commit, impact, reproduction steps (on a lab device), and any
suggested fix. Expect an acknowledgement within 3 working days.

## What is security-relevant here

This tool logs into network devices and changes boot images, so these areas are especially
sensitive:

* **Credential handling.** Passwords come from `--enable-pass` or `$CISCO_ENABLE`; the tool
  writes a short-lived password file (`_pscp_pw*`) for pscp and is expected to remove it.
  Any path where credentials leak into logs, process arguments visible to other users, or
  files that outlive the run is a vulnerability. `.gitignore` excludes those files; treat a
  committed one as a leak.
* **Command injection.** Hostnames, IPs and firmware filenames are interpolated into device
  CLI commands and into `pscp` invocations. Inventory files are therefore trusted input —
  document any change that loosens validation.
* **Transport.** SCP/SSH host keys are not pinned in this version; a man-in-the-middle on
  the management network can impersonate a switch. Report any suggestion that host-key
  verification is silently skipped.
* **Log contents.** Per-device logs contain full command output, which may include
  configuration. Never attach real logs to an issue; redact in this repository.

## Hardening checklist for operators

* Run from a dedicated automation host, not a user workstation.
* Keep inventory, logs, reports, state and backups off any public share or repo.
* Use a dedicated privilege-15 account scoped to the maintenance window.
* Take a configuration backup before the first wave (`--check` / `--dry-run` first).
* Rotate the account's secret after the campaign.
