# Changelog

## 0.1.0
- Added local GUI archive upload and scanning.
- Added secure archive extraction controls.
- Added normalized Gaia configuration parser.
- Added evidence redaction and source attribution.
- Added confidence-based result classification.
- Added standalone HTML report generation.
- Added explicit Not Assessed handling for management policy checks.

## 0.1.1 - 2026-07-29
- Increased the default trusted archive expansion limit from 2 GB to 10 GiB.
- Count only regular files when calculating expanded archive size.
- Added configurable `CHECKPOINT_AUDIT_MAX_EXPANDED_BYTES` and `CHECKPOINT_AUDIT_MAX_FILES` limits.
- Improved extraction errors to display actual and permitted archive sizes.

## 0.2.0 - 2026-07-29

- Expanded the evidence-driven rule pack from 20 to 45 checks.
- Added password policy, account lockout, SSH hardening, web-management, remote logging, SNMPv3, NTP version, backup retention, and timezone checks.
- Added detection for enabled CBC ciphers, SHA-1/64-bit MACs, and legacy SSH key exchange.
- Improved secret redaction to cover cryptographic keys and hashes.
- Treated ambiguous HTTP listener and backup-retention semantics as manual-review results rather than definite failures.
- Maintained authoritative-evidence-only failure logic and policy-export requirements.
