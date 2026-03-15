#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Harden Kerberos: enforce AES256, audit SPNs and PreAuth-disabled accounts.

.DESCRIPTION
    Counters: T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting)
    CIS Benchmark: 2.3.6.1 — Ensure Kerberos encryption types are configured

.PARAMETER AuditOnly
    Only check current state without making changes.

.PARAMETER ExportPath
    Path for CSV export.

.EXAMPLE
    .\05-harden-kerberos.ps1 -AuditOnly
    .\05-harden-kerberos.ps1
#>

param(
    [switch]$AuditOnly,
    [string]$ExportPath = ".\audit-results"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }

Write-Host "`n[*] Kerberos Hardening Audit — $(Get-Date)" -ForegroundColor Cyan

# ============================================================
# CHECK 1: AS-REP Roastable accounts (DoNotRequirePreAuth)
# ============================================================
Write-Host "`n[1/4] AS-REP Roastable accounts (PreAuth disabled)..." -ForegroundColor Yellow

$asrepUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, SamAccountName, Enabled
if ($asrepUsers) {
    Write-Host "  [!] $($asrepUsers.Count) accounts with PreAuth DISABLED:" -ForegroundColor Red
    foreach ($u in $asrepUsers) {
        Write-Host "    - $($u.SamAccountName) (Enabled: $($u.Enabled))" -ForegroundColor Red
    }
    $asrepUsers | Select-Object SamAccountName, Enabled | Export-Csv "$ExportPath\asrep-roastable-$timestamp.csv" -NoTypeInformation
    
    if (-not $AuditOnly) {
        Write-Host "  [*] Enabling PreAuth on all accounts..." -ForegroundColor Yellow
        $asrepUsers | Set-ADAccountControl -DoesNotRequirePreAuth $false
        Write-Host "  [+] PreAuth ENABLED on $($asrepUsers.Count) accounts" -ForegroundColor Green
    }
} else {
    Write-Host "  [+] No AS-REP Roastable accounts found." -ForegroundColor Green
}

# ============================================================
# CHECK 2: Kerberoastable accounts (SPNs)
# ============================================================
Write-Host "`n[2/4] Kerberoastable accounts (users with SPNs)..." -ForegroundColor Yellow

$spnUsers = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, SamAccountName, PasswordLastSet, Enabled |
    Where-Object { $_.SamAccountName -ne "krbtgt" }

if ($spnUsers) {
    Write-Host "  [!] $($spnUsers.Count) user accounts with SPNs:" -ForegroundColor Red
    foreach ($u in $spnUsers) {
        $daysSinceChange = (New-TimeSpan -Start $u.PasswordLastSet -End (Get-Date)).Days
        $risk = if ($daysSinceChange -gt 365) { "HIGH (>365 days)" } elseif ($daysSinceChange -gt 90) { "MEDIUM" } else { "LOW" }
        Write-Host "    - $($u.SamAccountName) | SPN: $($u.ServicePrincipalName -join ', ') | Password age: ${daysSinceChange}d ($risk)" -ForegroundColor $(if($risk -match "HIGH"){"Red"}elseif($risk -match "MEDIUM"){"DarkYellow"}else{"Green"})
    }
    $spnUsers | Select-Object SamAccountName, @{N='SPNs';E={$_.ServicePrincipalName -join ';'}}, PasswordLastSet, Enabled |
        Export-Csv "$ExportPath\kerberoastable-accounts-$timestamp.csv" -NoTypeInformation
} else {
    Write-Host "  [+] No Kerberoastable user accounts found." -ForegroundColor Green
}

# ============================================================
# CHECK 3: RC4 encryption usage
# ============================================================
Write-Host "`n[3/4] Accounts using RC4 encryption (vulnerable to offline cracking)..." -ForegroundColor Yellow

$rc4Users = Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes, SamAccountName |
    Where-Object {
        $_.'msDS-SupportedEncryptionTypes' -band 0x4  # RC4_HMAC_MD5
    }

if ($rc4Users) {
    Write-Host "  [!] $($rc4Users.Count) accounts support RC4 encryption" -ForegroundColor Red
    if (-not $AuditOnly) {
        Write-Host "  [*] Forcing AES256 on Kerberoastable accounts..." -ForegroundColor Yellow
        foreach ($u in $spnUsers) {
            Set-ADUser -Identity $u -KerberosEncryptionType AES256
            Write-Host "    [+] $($u.SamAccountName) → AES256 only" -ForegroundColor Green
        }
    }
} else {
    Write-Host "  [+] No accounts with RC4-only encryption." -ForegroundColor Green
}

# ============================================================
# CHECK 4: Fine-Grained Password Policy for service accounts
# ============================================================
Write-Host "`n[4/4] Fine-Grained Password Policies..." -ForegroundColor Yellow

$fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
if ($fgpp) {
    Write-Host "  [+] $($fgpp.Count) Fine-Grained Password Policies found:" -ForegroundColor Green
    foreach ($p in $fgpp) {
        Write-Host "    - $($p.Name) | MinLength: $($p.MinPasswordLength) | MaxAge: $($p.MaxPasswordAge)" -ForegroundColor Green
    }
} else {
    Write-Host "  [!] No Fine-Grained Password Policies — service accounts use default domain policy" -ForegroundColor Red
    Write-Host "  [i] Recommendation: Create a PSO with 25+ char minimum for service accounts" -ForegroundColor DarkYellow
}

# Summary
Write-Host "`n[*] Summary" -ForegroundColor Cyan
Write-Host "  AS-REP Roastable    : $(if($asrepUsers){$asrepUsers.Count}else{0})"
Write-Host "  Kerberoastable SPNs : $(if($spnUsers){$spnUsers.Count}else{0})"
Write-Host "  RC4 accounts        : $(if($rc4Users){$rc4Users.Count}else{0})"
Write-Host "  FGPP policies       : $(if($fgpp){$fgpp.Count}else{0})"
Write-Host "  Results exported to : $ExportPath" -ForegroundColor Cyan
