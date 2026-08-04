# linux-users

Account and access lifecycle audit and remediation for a RHEL 9 fleet. SSH in,
audit local accounts, sudoers, and SSH keys, then lock or expire the stale ones
with per-host confirmation and live re-validation. Output is a formatted Excel
report and a machine-readable plan.

It never deletes an account. apply only ever locks or expires, and it
re-validates last login before acting so an account that logged in since the
audit drops out. SSH keys and sudoers are reported, not modified.

Part of a family with [linux-audit](https://github.com/vikozs/linux-audit),
[linux-harden](https://github.com/vikozs/linux-harden),
[linux-diskspace](https://github.com/vikozs/linux-diskspace),
[linux-patch](https://github.com/vikozs/linux-patch), and
[linux-certs](https://github.com/vikozs/linux-certs). It shares their transport
(`ssh_exec.py`) and Excel safety layer (`xlsx_safe.py`).

## What it does

Discover:

- Enumerates accounts from `passwd`, joins password status and aging from
  `shadow` (hashes are never collected), and last-login age from `lastlog`.
- Reads sudoers (`/etc/sudoers` and `sudoers.d`) and per-user
  `authorized_keys`.
- Flags duplicate UID 0, empty passwords, never-expiring passwords, accounts
  that have never logged in, NOPASSWD sudo grants, and weak (`ssh-dss`) keys.
- Marks stale accounts: a login account (UID >= 1000, real shell) whose last
  login is older than the threshold and that is not protected.

Apply:

- Locks (`usermod -L`) and, with `--expire`, expires (`chage -E`) the stale
  accounts a plan proposes.
- Re-runs discovery first and only acts on accounts that are still stale, so
  anyone who logged in since the audit is skipped.
- Never runs `userdel`, never removes keys, never edits sudoers.

## Protection

These are never touched, and are re-checked at apply time as a second guard:

- `root` and every account with UID < 1000.
- The account you connect as (`-u`), so you never lock yourself out.
- Anything named with `--protect NAME` (repeatable).

Accounts whose last login is unknown or "never" are never auto-locked.

## Requirements

- Python 3.9+ and `openpyxl` on the machine you run it from.
- `sshpass` on that machine if you use password SSH login.
- RHEL 9 targets. Sudo is needed to read `shadow` and other users'
  `authorized_keys`.

```
pip install -r requirements.txt
```

## Usage

Audit the fleet, writing `users_plan.json` and `users_report.xlsx`:

```
python3 linux_users.py discover -H hosts.txt -u local.user \
    --ask-ssh-pass --sudo-pass-same-as-ssh
```

Review the report, then lock the stale accounts, confirming per host:

```
python3 linux_users.py apply --plan users_plan.json -H hosts.txt -u local.user \
    --ask-ssh-pass --sudo-pass-same-as-ssh
```

Lock and expire, with a longer stale window and an extra protected name:

```
python3 linux_users.py discover -H hosts.txt -u local.user --ask-ssh-pass \
    --sudo-pass-same-as-ssh --stale-days 120 --protect deploybot
python3 linux_users.py apply --plan users_plan.json -H hosts.txt -u local.user \
    --ask-ssh-pass --sudo-pass-same-as-ssh --expire
```

Re-render an existing plan to Excel without touching the fleet:

```
python3 linux_users.py report --plan users_plan.json -o report.xlsx
```

Passwords travel via stdin or the `SSHPASS` env var, never on the command line.

## Output

`users_report.xlsx` sheets:

- Summary: per host, account count, stale count, issue count, weak-key count.
- Accounts: every account, with UID, shell, password status, never-expires
  flag, last-login age, sudo capability, and flags.
- Stale Candidates: the accounts apply would lock.
- Sudoers: grant entries, with NOPASSWD highlighted.
- SSH Keys: per-user key inventory, with weak types highlighted.
- Issues: duplicate UID 0, duplicate UIDs, empty passwords.
- Errors: hosts that could not be reached.
- About: tool version, build stamp, threshold, protected accounts, totals.

`users_plan.json` is the same data as structured input for `apply`, which
writes `users_results.json` recording what was locked per host.

## Development

```
pip install -r requirements.txt pytest
pytest -q
```

The account model and checks are pure functions. Fixtures cover stale accounts,
duplicate UID 0, empty passwords, weak keys, protected accounts, and the apply
re-validation path.

## Landing page

A lightweight static landing page lives in [`docs/`](docs/) for GitHub
Pages-friendly publishing without affecting the CLI package. Open
`docs/index.html` locally in a browser to preview it, or publish the repository
from the `docs/` folder on `main` in GitHub Pages settings.

## License

MIT. See [LICENSE](LICENSE).
