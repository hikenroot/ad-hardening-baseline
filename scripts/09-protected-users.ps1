#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audit and manage Protected Users security group membership.

.DESCRIPTION
    Protected Users group prevents: NTLM auth, DES/RC4 Kerberos, delegation,
    credential caching. Essential for privileged accounts.
    
    Counters: T1003 (Credential Dumping), T1550 (Use Alternate Authentication Material)
    CIS Benchmark: 1.1.6 — Ensure sensitive accounts are in Protected Users

.PARAMETER AuditOnly
    Only check current membership without making changes.

.PARAMETER AddPrivileged
    Automatically add Domain Admins and Enterprise Admins to Protected Users.

.PARAMETER ExportPath
    Path for CSV export.

.EXAMPLE
    .\09-protected-users.ps1 -AuditOnly
    .\09-protected-users.ps1 -AddPrivileged
#>

param(
    [switch]$AuditOnly,
    [switch]$AddPrivileged,
    [string]$ExportPath = ".\audit-results"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }

Write-Host "`n[*] Protected Users Audit — $(Get-Date)" -ForegroundColor Cyan

# ============================================================
# CHECK 1: Current Protected Users membership
# ============================================================
Write-Host "`n[1/4] Current Protected Users members..." -ForegroundColor Yellow

$protectedMembers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue
if ($protectedMembers) {
    Write-Host "  [+] $($protectedMembers.Count) members in Protected Users:" -ForegroundColor Green
    foreach ($m in $protectedMembers) {
        Write-Host "    - $($m.SamAccountName) ($($m.objectClass))" -ForegroundColor Green
    }
} else {
    Write-Host "  [!] Protected Users group is EMPTY — no privileged accounts protected" -ForegroundColor Red
}

# ============================================================
# CHECK 2: Privileged accounts NOT in Protected Users
# ============================================================
Write-Host "`n[2/4] Privileged accounts NOT in Protected Users..." -ForegroundColor Yellow

$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
$protectedSAMs = @()
if ($protectedMembers) { $protectedSAMs = $protectedMembers.SamAccountName }

$unprotected = @()
foreach ($group in $privilegedGroups) {
    $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
    foreach ($m in $members) {
        if ($m.objectClass -eq "user" -and $m.SamAccountName -notin $protectedSAMs) {
            $alreadyListed = $unprotected | Where-Object { $_.SamAccountName -eq $m.SamAccountName }
            if (-not $alreadyListed) {
                $userDetails = Get-ADUser -Identity $m.SamAccountName -Properties Enabled, LastLogonDate, PasswordLastSet
                $unprotected += [PSCustomObject]@{
                    SamAccountName  = $m.SamAccountName
                    PrivilegedGroup = $group
                    Enabled         = $userDetails.Enabled
                    LastLogon       = $userDetails.LastLogonDate
                    PasswordLastSet = $userDetails.PasswordLastSet
                }
            }
        }
    }
}

if ($unprotected.Count -gt 0) {
    Write-Host "  [!] $($unprotected.Count) privileged accounts NOT in Protected Users:" -ForegroundColor Red
    foreach ($u in $unprotected) {
        Write-Host "    - $($u.SamAccountName) (member of $($u.PrivilegedGroup), Enabled: $($u.Enabled))" -ForegroundColor Red
    }
    $unprotected | Export-Csv "$ExportPath\unprotected-privileged-$timestamp.csv" -NoTypeInformation

    if ($AddPrivileged -and -not $AuditOnly) {
        Write-Host "`n  [*] Adding privileged accounts to Protected Users..." -ForegroundColor Yellow
        foreach ($u in $unprotected | Where-Object { $_.Enabled -eq $true }) {
            try {
                Add-ADGroupMember -Identity "Protected Users" -Members $u.SamAccountName
                Write-Host "    [+] Added: $($u.SamAccountName)" -ForegroundColor Green
            } catch {
                Write-Host "    [-] Failed: $($u.SamAccountName) — $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "  [+] All privileged accounts are in Protected Users." -ForegroundColor Green
}

# ============================================================
# CHECK 3: Service accounts in Protected Users (warning)
# ============================================================
Write-Host "`n[3/4] Service accounts in Protected Users (compatibility check)..." -ForegroundColor Yellow

if ($protectedMembers) {
    foreach ($m in $protectedMembers) {
        if ($m.objectClass -eq "user") {
            $user = Get-ADUser -Identity $m.SamAccountName -Properties ServicePrincipalName
            if ($user.ServicePrincipalName) {
                Write-Host "  [!] WARNING: $($m.SamAccountName) has SPNs and is in Protected Users" -ForegroundColor DarkYellow
                Write-Host "      SPNs: $($user.ServicePrincipalName -join ', ')" -ForegroundColor DarkYellow
                Write-Host "      Protected Users blocks delegation — this may break services" -ForegroundColor DarkYellow
            }
        }
    }
}

# ============================================================
# CHECK 4: Accounts with AdminCount=1 not in Protected Users
# ============================================================
Write-Host "`n[4/4] AdminCount=1 accounts not in Protected Users..." -ForegroundColor Yellow

$adminCountUsers = Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, Enabled |
    Where-Object { $_.Enabled -eq $true -and $_.SamAccountName -notin $protectedSAMs }

if ($adminCountUsers) {
    Write-Host "  [!] $($adminCountUsers.Count) accounts with AdminCount=1 NOT in Protected Users:" -ForegroundColor Red
    foreach ($a in $adminCountUsers) {
        Write-Host "    - $($a.SamAccountName)" -ForegroundColor Red
    }
} else {
    Write-Host "  [+] All AdminCount=1 accounts are in Protected Users." -ForegroundColor Green
}

# Summary
Write-Host "`n[*] Summary" -ForegroundColor Cyan
Write-Host "  Protected Users members   : $(if($protectedMembers){$protectedMembers.Count}else{0})"
Write-Host "  Unprotected privileged    : $($unprotected.Count)"
Write-Host "  AdminCount=1 unprotected  : $(if($adminCountUsers){$adminCountUsers.Count}else{0})"
Write-Host "  Results exported to       : $ExportPath" -ForegroundColor Cyan
if ($AuditOnly) {
    Write-Host "`n  [i] Audit mode — run with -AddPrivileged to auto-add." -ForegroundColor DarkYellow
}
