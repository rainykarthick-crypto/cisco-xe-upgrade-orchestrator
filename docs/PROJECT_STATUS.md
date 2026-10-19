# Project status

## Summary

| | |
|---|---|
| Branch `main` | **v35.9.43** development merge — imported verbatim, **incomplete** |
| Tag `v35.9.34` | **Complete, tested build** — 20/20 self-tests pass |
| Runnable today | `git checkout v35.9.34` (or `git show v35.9.34:orchestrator.py > orchestrator.py`) |
| Blocking issue | the v35.9.43 file is missing its header (imports, constants) and helper block |

## What exactly is wrong with the v35.9.43 file

`orchestrator.py` on `main` is 9,779 lines / 421 KB and starts at
`def _run_install_commit_only(...)` — the middle of the program. It contains the program
**tail twice**:

| Lines | Content |
|---|---|
| 1 – 4,889 | tail copy A, ends with `if __name__ == "__main__": sys.exit(main())` |
| 4,890 – 9,779 | identical tail copy B, ends the same way |

Both copies are missing everything that came **before** `_run_install_commit_only`, i.e. the
module docstring, the imports, ~40 module constants and the helper functions.

Running it fails immediately:

```text
File "orchestrator.py", line 4889, in <module>
    sys.exit(main())
NameError: name 'sys' is not defined
```

### Static analysis (pyflakes)

1,160 diagnostics, **226 undefined names**:

| Category | Count | Examples |
|---|---|---|
| stdlib imports | 14 | `os`, `sys`, `time`, `re`, `json`, `argparse`, `threading`, `csv`, `signal`, `subprocess` |
| present in v35.9.34 (could be spliced) | 57 | `robust_reconnect`, `parse_running_version`, `do_connect`, `track_temp_change`, `update_paths`, `PSCP_EXE`, `RUN_ID`, … |
| **absent from every source on the machine** | **155** | `wlog`, `set_state`, `_classify_connect_error`, `_force_wipe_flash`, `_delete_firmware_from_flash`, `_get_all_member_free_bytes`, `_ensure_device_clock_correct`, `_acquire_instance_lock`, `_SWITCH_ROW_RE`, `_ACTIVATE_FORMS`, `_PROMPT_MARKERS`, `FIRMWARE_SHA256`, `EXTRACTION_OVERHEAD_FACTOR`, … |

The 155 cannot be grepped from `cisco_upgrade_v35_9_34.py`: `_run_install_commit_only` itself
does not exist there, i.e. v35.9.43 refactored the engine. Inventing timeouts, retry budgets
and Cisco prompt/state markers would change upgrade behaviour on production switches, so
that was deliberately not done.

## How to finish v35.9.43

1. Supply the **top section** of the original file: everything from line 1 down to the line
   before `def _run_install_commit_only(...)`.
2. Remove the duplicate half (keep either 1–4,889 or 4,890–9,779, not both) so there is a
   single `main()` and a single `__main__` block.
3. Validate:

   ```bash
   python -m py_compile orchestrator.py
   python -m pyflakes orchestrator.py      # expect 0 undefined names
   python orchestrator.py --validate       # expect the self-test suite to pass
   python orchestrator.py --help
   ```

4. Commit and retag (`v35.9.43`), and drop the work-in-progress note from `README.md`.

## What already works in the v35.9.43 tail

The imported content is not useless: it carries the newer implementation of

* the **pscp stall detector** (`v35.9.43 FIX-PSCP-STALL`),
* the **HTML report** (`write_html_report`),
* the v35.9.43 self-test entries.

So once the header is restored, the diff against v35.9.34 is exactly those improvements.

## What works today (tag `v35.9.34`)

Verified in a clean virtualenv (Python 3.14, paramiko 5.1.0, netmiko 4.8.0):

```text
self-test suite for cisco_upgrade_v35_9_34.py v35.9.34
  ✓ VERSION_STRING  ✓ classify 17.6.4  ✓ classify 17.18.4  ✓ build file-arg activate
  ✓ apply_service_locks  ✓ revert handles services  ✓ verify_no_temp_changes
  ✓ locks before precheck  ✓ run_location no per-loc  ✓ pscp reader thread
  ✓ keepalive get_transport  ✓ escalation cap top  ✓ update_paths from main
  ✓ session_is_alive loops  ✓ SIGBREAK registered  ✓ settle shutdown-aware
  ✓ normalise_status  ✓ remote_size retries  ✓ NTP socket cleanup  ✓ summary parser rows
Passed: 20/20
```

## How CI treats this

`.github/workflows/ci.yml` (Python 3.10 / 3.11 / 3.12):

* **gating** — syntax check of the working tree; syntax, an undefined-name gate
  (`pyflakes`, unused-import notices tolerated) and `--validate` of the tagged v35.9.34
  build; documentation/repository hygiene checks;
* **informational** (`continue-on-error`) — pyflakes on the incomplete merge, so the missing
  header is visible in the CI log without turning every push red.

When the header is restored, remove the `continue-on-error` flag so the working tree gates
the build.
