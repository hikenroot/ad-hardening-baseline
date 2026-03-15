#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audit dangerous ACLs and delegations on Active Directory objects.

.DESCRIPTION
    Identifies risky permissions: GenericAll, GenericWrite, WriteDACL, WriteOwner,
    ForceChangePassword on sensitive objects.
    
    Counters: T1222.001 (ACL Abuse), T1098 (Account Manipulation)
    CIS Benchmark: Privileged access review

.PARAMETER ExportPath
    Path for CSV export.

.EXAMPLE
    .\06-audit-acl-delegations.ps1
#>

param(
    [string]$ExportPath = ".\audit-results"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }

Write-Host "`n[*] ACL & Delegation Audit — $(Get-Date)" -ForegroundColor Cyan

$dangerousRights = @(
    "GenericAll",
    "GenericWrite", 
    "WriteDacl",
    "WriteOwner",
    "WriteProperty"
)

$builtinSIDs = @(
    "S-1-5-18",      # SYSTEM
    "S-1-5-32-544",  # Administrators
    "S-1-5-9",       # Enterprise DCs
    "S-1-5-10"       # Self
)

$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$results = @()

# ============================================================
# CHECK 1: Dangerous ACLs on Domain Root
# ============================================================
Write-Host "`n[1/4] Auditing ACLs on domain root..." -ForegroundColor Yellow

$domainACL = Get-Acl "AD:\$domainDN"
foreach ($ace in $domainACL.Access) {
    $rights = $ace.ActiveDirectoryRights.ToString()
    foreach ($dr in $dangerousRights) {
        if ($rights -match $dr -and $ace.IdentityReference -notmatch "BUILTIN|NT AUTHORITY|Domain Admins|Enterprise Admins") {
            $results += [PSCustomObject]@{
                Object    = "Domain Root"
                Identity  = $ace.IdentityReference.ToString()
                Rights    = $rights
                Type      = $ace.AccessControlType.ToString()
                Inherited = $ace.IsInherited
            }
            Write-Host "  [!] $($ace.IdentityReference) has $dr on Domain Root" -ForegroundColor Red
        }
    }
}

# ============================================================
# CHECK 2: Dangerous ACLs on AdminSDHolder
# ============================================================
Write-Host "`n[2/4] Auditing ACLs on AdminSDHolder..." -ForegroundColor Yellow

$adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
$adminACL = Get-Acl "AD:\$adminSDHolderDN" -ErrorAction SilentlyContinue
if ($adminACL) {
    foreach ($ace in $adminACL.Access) {
        $rights = $ace.ActiveDirectoryRights.ToString()
        foreach ($dr in $dangerousRights) {
            if ($rights -match $dr -and $ace.IdentityReference -notmatch "BUILTIN|NT AUTHORITY|Domain Admins|Enterprise Admins|Administrators") {
                $results += [PSCustomObject]@{
                    Object    = "AdminSDHolder"
                    Identity  = $ace.IdentityReference.ToString()
                    Rights    = $rights
                    Type      = $ace.AccessControlType.ToString()
                    Inherited = $ace.IsInherited
                }
                Write-Host "  [!] $($ace.IdentityReference) has $dr on AdminSDHolder" -ForegroundColor Red
            }
        }
    }
}

# ============================================================
# CHECK 3: Users with delegation rights
# ============================================================
Write-Host "`n[3/4] Accounts with unconstrained delegation..." -ForegroundColor Yellow

$unconstrainedDelegation = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Where-Object { $_.Name -notmatch "DC" }

if ($unconstrainedDelegation) {
    foreach ($c in $unconstrainedDelegation) {
        Write-Host "  [!] $($c.Name) — Unconstrained delegation (non-DC)" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Object    = $c.Name
            Identity  = "COMPUTER"
            Rights    = "TrustedForDelegation (Unconstrained)"
            Type      = "Delegation"
            Inherited = $false
        }
    }
} else {
    Write-Host "  [+] No non-DC computers with unconstrained delegation." -ForegroundColor Green
}

# ============================================================
# CHECK 4: Users who can DCSync
# ============================================================
Write-Host "`n[4/4] Accounts with DCSync rights..." -ForegroundColor Yellow

$replicationGUIDs = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # DS-Replication-Get-Changes-All
)

foreach ($ace in $domainACL.Access) {
    if ($ace.ObjectType -in $replicationGUIDs) {
        if ($ace.IdentityReference -notmatch "BUILTIN|NT AUTHORITY|Domain Controllers|Enterprise Domain Controllers|Cloneable Domain Controllers") {
            Write-Host "  [!] $($ace.IdentityReference) has DCSync rights" -ForegroundColor Red
            $results += [PSCustomObject]@{
                Object    = "Domain Root"
                Identity  = $ace.IdentityReference.ToString()
                Rights    = "DCSync (Replication)"
                Type      = $ace.AccessControlType.ToString()
                Inherited = $ace.IsInherited
            }
        }
    }
}

# Export
if ($results.Count -gt 0) {
    $results | Export-Csv "$ExportPath\dangerous-acls-$timestamp.csv" -NoTypeInformation
    Write-Host "`n[!] $($results.Count) dangerous ACL entries found." -ForegroundColor Red
} else {
    Write-Host "`n[+] No dangerous ACL entries found." -ForegroundColor Green
}

Write-Host "  Results exported to: $ExportPath`n" -ForegroundColor Cyan
