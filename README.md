[![Python CI](https://github.com/elliottkennedy52-ux/ssh-log-auditor/actions/workflows/python-ci.yml/badge.svg)](https://github.com/elliottkennedy52-ux/ssh-log-auditor/actions/workflows/python-ci.yml)

# Linux SSH Authentication & Brute-Force Log Auditor

A Python CLI security monitoring tool that parses Linux authentication logs (`/var/log/auth.log`, `/var/log/secure`, or `systemd` `journalctl`) to detect SSH brute-force attempts, credential stuffing patterns, and potential post-brute-force compromises.

## Features
- **Multi-Source Log Ingestion:** Automatically reads Debian/Ubuntu `auth.log`, RHEL/Fedora `secure`, or live `journalctl -u sshd` output.
- **Threshold-Based Brute-Force Detection:** Flags source IPs exceeding configurable failed-login thresholds and enumerates targeted accounts.
- **Compromise Correlation:** Alerts when an IP with repeated failed authentication attempts subsequently achieves a successful SSH login.
- **JSON SIEM Export:** Outputs structured JSON reports ready for SIEM ingestion or incident response documentation.

## Usage

### Run Built-In Demo Mode
```bash
python3 auditor.py --demo
```

### Audit Live System Logs & Export JSON Report
```bash
sudo python3 auditor.py -t 5 -o ssh_audit_report.json
```

### Audit an Archived Log File
```bash
python3 auditor.py -f /path/to/auth.log -t 3
```
