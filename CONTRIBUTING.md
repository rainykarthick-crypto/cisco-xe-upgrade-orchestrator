# Contributing

Thanks for your interest. This project automates firmware upgrades on production network
gear, so correctness and safety matter far more than speed of delivery.

## Ground rules for changes

The orchestrator is built on five invariants (detailed in
[`docs/architecture_workflow.md`](docs/architecture_workflow.md)). A change that breaks one
of them is a regression even if it "works":

1. **State driven, never timer driven** — read the device, classify, issue one command.
2. **Session continuity** — the session that ran `install add` runs activate/commit.
3. **Version-aware dispatch** — the activate form comes from the running IOS-XE version.
4. **Service locks on every device**, including devices already on target.
5. **Temporary changes are recorded before they are made** and reverted afterwards.

Also:

* Never run destructive operations against a device without `--dry-run` first.
* Never commit real inventory files, firmware images, credentials or logs. `locations/`,
  `firmware/`, `logs/`, `reports/`, `state/`, `backups/` and `pscp.exe` are git-ignored.
* `examples/` must only ever contain documentation-range placeholder addresses.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install pyflakes                # static analysis used by CI
```

## Checks to run before opening a pull request

```bash
python -m py_compile orchestrator.py        # syntax
python -m pyflakes orchestrator.py          # undefined names / dead code
python orchestrator.py --validate           # built-in self-test
python orchestrator.py --help               # CLI surface
```

The self-test (`--validate`) is the minimum bar: it exercises the internal helpers without
touching a switch.

## Pull requests

1. Branch from `main` (`feat/…`, `fix/…`, `docs/…`).
2. Keep commits focused; use [Conventional Commits](https://www.conventionalcommits.org/)
   (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `ci:`).
3. Update `README.md` / `CHANGELOG.md` when behaviour or usage changes.
4. Fill in the pull request template, including **how you verified** the change (lab device
   model + IOS-XE version, or "self-test only").
5. Never include customer hostnames, IPs, serial numbers or configurations in a PR.

## Reporting bugs and security issues

* Bugs / features: use the issue templates.
* Security: **do not** open a public issue — see [SECURITY.md](SECURITY.md).

## License

By contributing you agree your work is licensed under the MIT License (see [LICENSE](LICENSE)).
