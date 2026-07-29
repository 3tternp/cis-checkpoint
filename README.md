# Check Point CIS Audit GUI

A local Flask GUI that scans Check Point Gaia backup/support archives, evaluates evidence-driven CIS-aligned technical checks, suppresses false positives, and generates a standalone HTML report.

## Key behavior

- Explicit authoritative settings produce Compliant or Non-Compliant results.
- Missing evidence becomes Not Assessed.
- Ambiguous evidence becomes Manual Review Required.
- Gateway backups are not used to guess centrally managed firewall policy state.
- Secrets, hashes, community strings, tokens, passwords, and IP addresses are redacted from report evidence.
- Archive extraction includes traversal, link, file-count, and expanded-size controls.

## Run on Windows

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000`.

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.venv\Scripts\Activate.ps1
```

## Run on Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

## Current automated checks

Telnet, IPv6, GRUB protection, expert-mode protection, inactivity timeout, centralized AAA indicators, scheduled backup, insecure backup transport, management interface, SNMP, NTP evidence, and hotfix inventory. Management-policy checks are included as evidence requirements and remain Not Assessed until authoritative exports are provided.

## Recommended management exports

Add parsers for `mgmt_cli` JSON exports for access rulebase, NAT rulebase, gateways and servers, administrators, and threat profiles. Do not infer these controls from gateway logs.

## Important

This tool is CIS-aligned and does not redistribute licensed CIS benchmark text. Validate control mappings against your authorized benchmark copy and Check Point version documentation.

## Large Check Point archives

The scanner permits up to **10 GiB** of expanded regular-file content and **200,000 files** by default. These protections reduce archive-bomb and disk-exhaustion risk while accommodating normal Check Point backup and CPInfo archives.

For a larger archive that you trust, configure the limits before starting the application.

### Windows PowerShell

```powershell
$env:CHECKPOINT_AUDIT_MAX_EXPANDED_BYTES = "21474836480"  # 20 GiB
$env:CHECKPOINT_AUDIT_MAX_FILES = "300000"
python run.py
```

### Linux

```bash
export CHECKPOINT_AUDIT_MAX_EXPANDED_BYTES=21474836480  # 20 GiB
export CHECKPOINT_AUDIT_MAX_FILES=300000
python run.py
```

Do not remove the limits entirely. Increase them only for an archive obtained from a trusted Check Point system and ensure adequate free disk space in the operating system temporary directory.

## Version 0.2.0 checks

The extended scanner includes 45 evidence-driven checks covering:

- Gaia management services and session timeout
- Password length, history, expiry, complexity, and account lockout
- SSH root access, password authentication, idle timeout, login grace time, ciphers, MACs, and key exchange
- Gaia Portal SSLv3, session timeout, and HTTP listener review
- Remote syslog and Gaia audit forwarding
- SNMPv3-only mode and authPriv user enforcement
- NTP configuration and protocol-version review
- Scheduled backups, encrypted transport, and retention
- GRUB and expert-mode protection
- IPv6, management-interface, timezone, hotfix inventory, and centralized AAA
- Management policy checks held as Not Assessed unless authoritative API/rulebase exports are supplied

A control becomes Non-Compliant only when an explicit active insecure setting is present and confidence is high. Ambiguous settings are classified as Manual Review Required.
