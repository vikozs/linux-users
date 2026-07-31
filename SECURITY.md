# Security

## Reporting

Report vulnerabilities privately through GitHub Security Advisories on this
repository. Please do not disclose details publicly until a fix is released.

## Handling of credentials and run artifacts

- SSH and sudo passwords are passed over stdin or the `SSHPASS` environment
  variable, never as command-line arguments.
- Shadow password hashes are never collected. The collector derives only a
  status (set, locked, empty) and aging fields.
- apply only locks (`usermod -L`) and optionally expires (`chage -E`). It never
  runs `userdel`, never removes SSH keys, and never edits sudoers.
- Protected accounts (root, UID < 1000, the connecting service account, and
  `--protect` names) are excluded from the apply set, and re-checked at apply
  time as a second guard.
- The plan and report list account names, sudoers entries, and key metadata.
  They are gitignored. Do not commit them.
- Values written into the Excel report are neutralised against spreadsheet
  formula injection.
