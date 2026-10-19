# Project status

## Summary

| | |
|---|---|
| Module | single file, `orchestrator.py` |
| State | **in progress** — the header (imports, constants) and helper block are not in the tree yet |
| Runnable | **no** — the CLI exits before it can parse arguments |
| Tracked in | [`../CHANGELOG.md`](../CHANGELOG.md) · [`../README.md`](../README.md) |

## What is in the file

The module currently starts at `def _run_install_commit_only(...)` — the middle of the
program — and holds the program **tail twice**:

| Lines | Content |
|---|---|
| 1 – 4,889 | tail copy A, ends with `if __name__ == "__main__": sys.exit(main())` |
| 4,890 – 9,779 | identical tail copy B, ends the same way |

Everything that came **before** `_run_install_commit_only` is absent: the docstring, the
imports, roughly forty module constants, and the helper functions.

Running it fails immediately:

```text
File "orchestrator.py", line 4889, in <module>
    sys.exit(main())
NameError: name 'sys' is not defined
```

## What is missing (static analysis)

`pyflakes`: 1,160 diagnostics, **226 undefined names**:

| Category | Count | Examples |
|---|---|---|
| stdlib imports | 14 | `os`, `sys`, `time`, `re`, `json`, `argparse`, `threading`, `csv`, `signal`, `subprocess` |
| helpers/constants from the earlier build | 57 | `robust_reconnect`, `parse_running_version`, `do_connect`, `track_temp_change`, `update_paths`, `PSCP_EXE`, `RUN_ID`, … |
| engine definitions absent from every source | **155** | `wlog`, `set_state`, `_classify_connect_error`, `_force_wipe_flash`, `_delete_firmware_from_flash`, `_get_all_member_free_bytes`, `_ensure_device_clock_correct`, `_acquire_instance_lock`, `_SWITCH_ROW_RE`, `_ACTIVATE_FORMS`, `_PROMPT_MARKERS`, `FIRMWARE_SHA256`, `EXTRACTION_OVERHEAD_FACTOR`, … |

The last group cannot be copied from the earlier build: its engine is structured differently
(`_run_install_commit_only` does not exist there). Inventing timeouts, retry budgets and
Cisco prompt/state markers would silently change upgrade behaviour on production switches,
so it was deliberately left undone.

## How to finish it

1. Add the **top section**: everything from line 1 down to the line before
   `def _run_install_commit_only(...)`.
2. Remove one of the two duplicated halves so there is a single `main()` and a single
   `__main__` block.
3. Validate:

   ```bash
   python -m py_compile orchestrator.py
   python -m pyflakes orchestrator.py      # expect 0 undefined names
   python orchestrator.py --validate       # self-test suite
   python orchestrator.py --help
   ```

4. Update `CHANGELOG.md` and drop the development note from `README.md`.

## What the imported tail already carries

The content is not wasted: it holds

* the **pscp stall detector** (kills a transfer that stops emitting progress),
* the **HTML report** (`write_html_report`),
* the self-test entries for the features above.

## What CI covers today

`.github/workflows/ci.yml` (Python 3.10 / 3.11 / 3.12):

* **gating** — syntax check of the module; documentation and repository hygiene checks
  (required files, no runtime artefacts or binaries, balanced markdown fences);
* **informational** (`continue-on-error`) — `pyflakes`, so the missing header is visible in
  the log without turning every push red.

When the header lands, make the `pyflakes` step gating and re-enable the `--validate` step.
