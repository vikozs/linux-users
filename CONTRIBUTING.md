# Contributing

Bug reports and pull requests are welcome.

- Keep `ssh_exec.py` and `xlsx_safe.py` in sync with the rest of the family.
- The collector never returns password hashes; keep it that way. Account model
  and checks are pure functions. Add a fixture under `tests/fixtures/` for any
  new input shape rather than testing over SSH.
- apply must never delete an account, remove a key, or edit sudoers in this
  release. Protected accounts must never enter the apply set.
- Run `pytest -q` before opening a PR. CI runs on Python 3.9 through 3.12.
- Plain, direct writing in docs and messages.
