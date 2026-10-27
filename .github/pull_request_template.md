## What does this change?

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / internal cleanup
- [ ] Documentation
- [ ] CI / tooling

## How was it verified?

<!-- Be specific: lab device model + IOS-XE version, or "self-test only". -->

- [ ] `python -m py_compile orchestrator.py`
- [ ] `python -m pyflakes orchestrator.py` (no new undefined names)
- [ ] `python orchestrator.py --validate`
- [ ] `python orchestrator.py --help` (CLI unchanged or intentionally changed)
- [ ] Lab-tested on: <!-- e.g. C9300-48P, IOS-XE 17.12.4 -> 17.18.04 -->

## Safety checklist

- [ ] No invariant broken (state-driven, session continuity, version-aware dispatch,
      service locks, temp-change ledger) - see `docs/architecture_workflow.md`
- [ ] Destructive paths still require `--yes`; `--dry-run` remains read-only
- [ ] New/changed device commands are issued through the same guarded helpers
- [ ] Timeouts and retries have bounded values (no unbounded wait)
- [ ] Logs never contain credentials or the `_pscp_pw*` file contents
- [ ] No real hostnames, IPs, serials, configurations or firmware images added

## Documentation

- [ ] `README.md` updated (usage/behaviour)
- [ ] `CHANGELOG.md` updated
- [ ] `docs/architecture_workflow.md` updated if the phase/state model changed
