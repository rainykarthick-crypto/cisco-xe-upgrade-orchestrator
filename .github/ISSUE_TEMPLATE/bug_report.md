---
name: Bug report
about: Something is not working as documented
title: '[Bug] '
labels: bug
assignees: ''
---

## What happened

<!-- Actual behaviour, and what you expected instead. -->

## Steps to reproduce

1.
2.
3.

## Environment

| | |
|---|---|
| Commit (`git rev-parse --short HEAD`) | |
| Python version (`python -V`) | |
| OS | |
| Switch models | <!-- e.g. C9300-48P, C9200L-24P --> |
| IOS-XE from → to | |
| pscp.exe present? | <!-- yes/no; paramiko fallback used? --> |

## Output

```text
# Relevant lines from logs/master_*.log or logs/<host>_*.log
# REDACT hostnames, IPs, serial numbers, passwords and configuration.
```

## Result files (optional)

- [ ] `reports/<location>_<RUN_ID>.csv` (redacted)
- [ ] `logs/ROLLBACK_<location>_<RUN_ID>.txt` (redacted)

## Checklist

- [ ] I ran `--validate` and `--help` on this build
- [ ] I can reproduce with `--dry-run`
- [ ] I searched existing issues for a duplicate
- [ ] No secrets or customer data are included above
