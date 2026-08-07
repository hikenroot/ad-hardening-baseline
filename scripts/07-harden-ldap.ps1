#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disable anonymous LDAP bind and enforce LDAP signing/channel binding.

.DESCRIPTION
    Counters: T1087.002 (LDAP Enumeration), T1069.002 (Domain Groups Discovery)
    CIS Benchmark: 2.3.10.2 — Ensure anonymous LDAP access is restricted

.PARAMETER AuditOnly
    Only check current state without making changes.

.EXAMPLE
    .\07-harden-ldap.ps1 -AuditOnly
    .\07-harden-ldap.ps1
#>

param([switch]$AuditOnly)

Write-Host "`n[*] LDAP Hardening — $(Get-Date)" -ForegroundColor Cyan

# ============================================================
# CHECK 1: Anonymous LDAP Bind
# ============================================================
Write-Host "`n[1/3] Anonymous LDAP access..." -ForegroundColor Yellow

$domainDN = (Get-ADDomain).DistinguishedName
$dsHeuristics = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$domainDN" -Properties dsHeuristics).dsHeuristics

if ($dsHeuristics -and $dsHeuristics.Length -ge 7 -and $dsHeuristics[6] -eq '2') {
    # 7th char (fLDAPBlockAnonOps) = 2 => anonymous LDAP operations ALLOWED (vulnerable)
    Write-Host "  [!] Anonymous LDAP bind: ALLOWED (dsHeuristics 7th char = 2) — enumeration possible" -ForegroundColor Red
    if (-not $AuditOnly) {
        Write-Host "  [*] Setting dsHeuristics to disable anonymous LDAP..." -ForegroundColor Yellow
        $chars = $dsHeuristics.ToCharArray()
        while ($chars.Length -lt 7) { $chars += '0' }
        $chars[6] = '0'   # 0 = block anonymous LDAP operations
        $newValue = -join $chars
        Set-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$domainDN" -Replace @{dsHeuristics=$newValue}
        Write-Host "  [+] Anonymous LDAP bind: DISABLED (7th char set to 0)" -ForegroundColor Green
    }
} else {
    # 7th char absent or != 2 => anonymous operations blocked (default, secure)
    Write-Host "  [+] Anonymous LDAP bind: RESTRICTED (default / 7th char != 2)" -ForegroundColor Green
}

# ============================================================
# CHECK 2: LDAP Signing
# ============================================================
Write-Host "`n[2/3] LDAP Signing requirement..." -ForegroundColor Yellow

$ldapSigning = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
$signingLevel = $ldapSigning.LDAPServerIntegrity

switch ($signingLevel) {
    2 { Write-Host "  [+] LDAP Signing: REQUIRED" -ForegroundColor Green }
    1 { Write-Host "  [!] LDAP Signing: NEGOTIATED (not enforced)" -ForegroundColor DarkYellow }
    default { Write-Host "  [!] LDAP Signing: NONE — man-in-the-middle risk" -ForegroundColor Red }
}

if ($signingLevel -ne 2 -and -not $AuditOnly) {
    Write-Host "  [*] Enforcing LDAP signing..." -ForegroundColor Yellow
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord
    Write-Host "  [+] LDAP Signing: REQUIRED (reboot may be needed)" -ForegroundColor Green
}

# ============================================================
# CHECK 3: LDAP Channel Binding
# ============================================================
Write-Host "`n[3/3] LDAP Channel Binding..." -ForegroundColor Yellow

$channelBinding = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
$cbLevel = $channelBinding.LdapEnforceChannelBinding

switch ($cbLevel) {
    2 { Write-Host "  [+] Channel Binding: ALWAYS (strongest)" -ForegroundColor Green }
    1 { Write-Host "  [!] Channel Binding: WHEN SUPPORTED" -ForegroundColor DarkYellow }
    default { Write-Host "  [!] Channel Binding: NEVER — LDAP relay risk" -ForegroundColor Red }
}

# Summary
Write-Host "`n[*] Summary" -ForegroundColor Cyan
Write-Host "  Anonymous LDAP  : $(if($dsHeuristics -and $dsHeuristics.Length -ge 7 -and $dsHeuristics[6] -eq '2'){'Allowed'}else{'Restricted'})"
Write-Host "  LDAP Signing    : $(switch($signingLevel){2{'Required'}1{'Negotiated'}default{'None'}})"
Write-Host "  Channel Binding : $(switch($cbLevel){2{'Always'}1{'When Supported'}default{'Never'}})"
if ($AuditOnly) {
    Write-Host "`n  [i] Audit mode — no changes made." -ForegroundColor DarkYellow
}
