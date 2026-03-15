# AD Hardening Baseline 🛡️

**PowerShell toolkit for Active Directory security hardening — CIS Benchmark aligned**

## Purpose

A collection of ready-to-use PowerShell scripts for auditing and hardening Active Directory environments. Each script addresses a specific attack vector documented in real-world penetration testing scenarios, with remediation aligned to CIS Benchmark, NIST SP 800-53, and ISO 27001 controls.

Built from hands-on offensive security experience — every hardening action directly counters a proven attack technique.

## Scripts

| Script | Purpose | Counters |
|---|---|---|
| `01-audit-ad-passwords.ps1` | Find passwords in LDAP descriptions and SYSVOL scripts | Credential harvesting (AS-REP, SYSVOL mining) |
| `02-disable-llmnr-nbtns.ps1` | Disable LLMNR and NBT-NS via registry | NTLM relay, Responder poisoning |
| `03-enforce-smb-signing.ps1` | Enforce SMB signing and disable SMBv1 | NTLM relay, SMB attacks |
| `04-deploy-laps.ps1` | Deploy LAPS for local admin password rotation | Pass-the-Hash, lateral movement |
| `05-harden-kerberos.ps1` | Force AES256, disable RC4, audit SPNs and PreAuth | Kerberoasting, AS-REP Roasting |
| `06-audit-acl-delegations.ps1` | Audit dangerous ACLs and delegations on AD objects | ACL abuse chains, privilege escalation |
| `07-harden-ldap.ps1` | Disable anonymous LDAP bind, enforce channel binding | LDAP enumeration, reconnaissance |
| `08-audit-gpo-security.ps1` | Audit GPO permissions and settings for misconfigurations | GPO abuse, privilege escalation |
| `09-protected-users.ps1` | Add sensitive accounts to Protected Users group | Credential theft, delegation abuse |
| `10-generate-report.ps1` | Generate HTML audit report from all checks | Compliance reporting |

## Quick Start

```powershell
# Clone the repository
git clone https://github.com/hikenroot/ad-hardening-baseline.git
cd ad-hardening-baseline

# Run full audit (read-only, no changes)
.\10-generate-report.ps1

# Run individual checks
.\01-audit-ad-passwords.ps1
.\05-harden-kerberos.ps1 -AuditOnly
```

## Compliance Mapping

| Control | CIS Benchmark | NIST 800-53 | ISO 27001 | Script |
|---|---|---|---|---|
| Disable LLMNR/NBT-NS | CIS 18.5.4.1 | SC-7 | A.13.1.1 | 02 |
| Enforce SMB signing | CIS 2.3.8.1 | SC-8 | A.13.1.1 | 03 |
| LAPS deployment | CIS 18.2.1 | AC-2 | A.9.2.3 | 04 |
| AES256 Kerberos | CIS 2.3.6.1 | SC-12 | A.10.1.1 | 05 |
| Disable anonymous LDAP | CIS 2.3.10.2 | AC-3 | A.9.4.1 | 07 |
| Protected Users group | CIS 1.1.6 | AC-6 | A.9.2.3 | 09 |

## Attack → Defense Mapping

Each script is linked to the offensive technique it mitigates:

| Attack Technique | MITRE ATT&CK | Defensive Script |
|---|---|---|
| Credentials in LDAP/SYSVOL | T1552.001, T1552.006 | `01-audit-ad-passwords.ps1` |
| LLMNR/NBT-NS Poisoning | T1557.001 | `02-disable-llmnr-nbtns.ps1` |
| NTLM Relay | T1557.001 | `03-enforce-smb-signing.ps1` |
| Pass-the-Hash | T1550.002 | `04-deploy-laps.ps1` |
| Kerberoasting | T1558.003 | `05-harden-kerberos.ps1` |
| AS-REP Roasting | T1558.004 | `05-harden-kerberos.ps1` |
| ACL Abuse | T1222.001 | `06-audit-acl-delegations.ps1` |
| LDAP Reconnaissance | T1087.002 | `07-harden-ldap.ps1` |
| GPO Abuse | T1484.001 | `08-audit-gpo-security.ps1` |
| Credential Theft | T1003 | `09-protected-users.ps1` |

## Requirements

- Windows Server 2016+ with RSAT-AD-PowerShell
- Domain Admin or equivalent for remediation scripts
- Read-only Domain access for audit scripts
- PowerShell 5.1+

## Disclaimer

These scripts are provided for legitimate security hardening purposes. Always test in a non-production environment first. The author is not responsible for any impact caused by running these scripts in production without proper testing and change management.

## Author

**hik3nR00t** — [HikenRoot Forge](https://github.com/hikenroot/hikenroot-forge)

## License

MIT
