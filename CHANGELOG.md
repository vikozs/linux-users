# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
semantic versioning.

## [1.0.0] - 2026-07-31

Initial release.

### Added
- `discover` mode: enumerate local accounts (passwd, shadow password status and
  aging, last login), sudoers, and per-user authorized_keys. Flag duplicate
  UID 0, empty passwords, never-expiring passwords, never-logged-in accounts,
  and stale accounts. Write a plan (JSON) and an Excel report.
- `apply` mode: lock (and optionally expire, `--expire`) the stale accounts a
  plan proposes, re-validating each host against live last-login first so an
  account that logged in since discover drops out.
- Protected accounts are never touched: root, every UID < 1000, the connecting
  service account, and `--protect` names.
- Stale threshold via `--stale-days` (default 90). Accounts whose last login is
  unknown or "never" are never auto-locked.
- Report-only sudoers and SSH-key inventory, with NOPASSWD and weak-key
  (ssh-dss) flags.
- `report` mode: re-render an existing plan to Excel with no SSH.
- Shadow password hashes are never collected or written.
- Shared `ssh_exec.py` transport and `xlsx_safe.py` Excel safety layer from the
  linux-audit family. Test suite and GitHub Actions CI on Python 3.9-3.12.

### Not in this release (report-only for now)
- Deleting accounts (`userdel`). apply only ever locks or expires.
- Removing SSH keys or editing sudoers.
