# Project status

## Summary

| | |
|---|---|
| Module | single file, `orchestrator.py` (4,338 lines) |
| Version | `1.0.0` (`python orchestrator.py --version` → `orchestrator.py v1.0.0 (target IOS-XE 17.18.04)`) |
| State | **complete and verified** |
| Requires | Python 3.10+, `paramiko`, `netmiko`, optional `pscp.exe` |

## Verification (reproducible)

Run from the repository root, in a virtual environment with `requirements.txt` installed:

```bash
python -m py_compile orchestrator.py        # syntax            -> exit 0
python -m pyflakes orchestrator.py          # no undefined names (2 unused-import notices)
python orchestrator.py --version            # orchestrator.py v1.0.0 (target IOS-XE 17.18.04)
python orchestrator.py --help               # full CLI
python orchestrator.py --validate           # built-in self-test -> 20/20 pass
```

Last verified result (Python 3.14.0, paramiko 5.1.0, netmiko 4.8.0):

```text
self-test suite for orchestrator.py v1.0.0
  ✓ VERSION_STRING            ✓ classify 17.6.4            ✓ classify 17.18.4
  ✓ build file-arg activate   ✓ apply_service_locks        ✓ revert handles services
  ✓ verify_no_temp_changes    ✓ locks before precheck      ✓ run_location no per-loc
  ✓ pscp reader thread        ✓ keepalive get_transport    ✓ escalation cap top
  ✓ update_paths from main    ✓ session_is_alive loops     ✓ SIGBREAK registered
  ✓ settle shutdown-aware     ✓ normalise_status           ✓ remote_size retries
  ✓ NTP socket cleanup        ✓ summary parser rows
Passed: 20/20
```

CI (`.github/workflows/ci.yml`) runs the same gates on Python 3.10, 3.11 and 3.12, plus
repository hygiene checks (no inventory files, firmware images or logs committed; balanced
markdown fences).

## What the self-test covers

The `--validate` suite checks the parts that are easy to break and expensive to get wrong:

* request classification and activate-command construction per IOS-XE version,
* service-lock application and reversion of temporary changes,
* the temp-change ledger and its verification,
* location/run wiring and `update_paths`,
* the pscp reader thread, stall timeout and remote-size retries,
* keepalive/session liveness and reconnect behaviour,
* signal handling (SIGBREAK), shutdown-aware waits and status normalisation,
* the install-summary parser.

It does not touch a switch: it exercises the helpers in isolation, so it runs in CI without a
lab.

## History note

An earlier revision of this file in the repository history is an incomplete merge (only the
program tail, with no imports, constants or helpers). It is preserved in commit `cfaf961` for
reference; `orchestrator.py` on `main` is the complete, verified module.

If you have a newer build of the module, replace `orchestrator.py` and re-run the five
commands above — `--validate` is the fastest way to know whether it is intact.
