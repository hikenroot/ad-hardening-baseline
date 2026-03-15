#Requires -Modules ActiveDirectory, GroupPolicy
<#
.SYNOPSIS
    Audit GPO permissions and settings for security misconfigurations.

.DESCRIPTION
    Checks for: overprivileged GPO editors, GPOs linked to sensitive OUs,
    unlinked GPOs, and dangerous settings.
    
    Counters: T1484.001 (Group Policy Modification)
    CIS Benchmark: GPO management best practices

.PARAMETER ExportPath
    Path for CSV export.

.EXAMPLE
    .\08-audit-gpo-security.ps1
#>

param(
    [string]$ExportPath = ".\audit-results"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }

Write-Host "`n[*] GPO Security Audit — $(Get-Date)" -ForegroundColor Cyan

# ============================================================
# CHECK 1: GPO Edit Permissions
# ============================================================
Write-Host "`n[1/5] Users with GPO edit permissions..." -ForegroundColor Yellow

$allGPOs = Get-GPO -All
$riskyEditors = @()

foreach ($gpo in $allGPOs) {
    $perms = Get-GPPermissions -Guid $gpo.Id -All
    foreach ($perm in $perms) {
        if ($perm.Permission -match "GpoEdit|GpoEditDeleteModifySecurity" -and
            $perm.Trustee.Name -notmatch "Domain Admins|Enterprise Admins|SYSTEM|Administrators") {
            $riskyEditors += [PSCustomObject]@{
                GPOName    = $gpo.DisplayName
                Trustee    = $perm.Trustee.Name
                Permission = $perm.Permission
                TrusteeType = $perm.Trustee.SidType
            }
            Write-Host "  [!] $($perm.Trustee.Name) can EDIT GPO '$($gpo.DisplayName)'" -ForegroundColor Red
        }
    }
}

if ($riskyEditors.Count -eq 0) {
    Write-Host "  [+] No non-admin GPO editors found." -ForegroundColor Green
} else {
    $riskyEditors | Export-Csv "$ExportPath\risky-gpo-editors-$timestamp.csv" -NoTypeInformation
}

# ============================================================
# CHECK 2: Unlinked GPOs
# ============================================================
Write-Host "`n[2/5] Unlinked GPOs..." -ForegroundColor Yellow

$unlinked = @()
foreach ($gpo in $allGPOs) {
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    if ($report -notmatch "<LinksTo>") {
        $unlinked += [PSCustomObject]@{
            GPOName      = $gpo.DisplayName
            Status       = $gpo.GpoStatus
            CreationTime = $gpo.CreationTime
            ModifiedTime = $gpo.ModificationTime
        }
    }
}

if ($unlinked.Count -gt 0) {
    Write-Host "  [!] $($unlinked.Count) unlinked GPOs (potential cleanup needed):" -ForegroundColor DarkYellow
    foreach ($u in $unlinked) {
        Write-Host "    - $($u.GPOName) (Modified: $($u.ModifiedTime))" -ForegroundColor DarkYellow
    }
    $unlinked | Export-Csv "$ExportPath\unlinked-gpos-$timestamp.csv" -NoTypeInformation
} else {
    Write-Host "  [+] All GPOs are linked." -ForegroundColor Green
}

# ============================================================
# CHECK 3: GPOs with Restricted Groups / Local Admin settings
# ============================================================
Write-Host "`n[3/5] GPOs modifying local admin groups..." -ForegroundColor Yellow

$adminGPOs = @()
foreach ($gpo in $allGPOs) {
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    if ($report -match "Restricted Groups|RestrictedGroups|Administrators" -and $report -match "Member") {
        $adminGPOs += $gpo.DisplayName
        Write-Host "  [i] $($gpo.DisplayName) — modifies local admin group membership" -ForegroundColor DarkYellow
    }
}

if ($adminGPOs.Count -eq 0) {
    Write-Host "  [+] No GPOs modifying local admin groups." -ForegroundColor Green
}

# ============================================================
# CHECK 4: GPOs with script execution
# ============================================================
Write-Host "`n[4/5] GPOs with startup/logon scripts..." -ForegroundColor Yellow

$scriptGPOs = @()
foreach ($gpo in $allGPOs) {
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    if ($report -match "<Script>|<Command>|\.ps1|\.bat|\.cmd|\.vbs") {
        $scriptGPOs += $gpo.DisplayName
        Write-Host "  [i] $($gpo.DisplayName) — contains scripts" -ForegroundColor DarkYellow
    }
}

if ($scriptGPOs.Count -eq 0) {
    Write-Host "  [+] No GPOs with embedded scripts." -ForegroundColor Green
} else {
    Write-Host "  [!] Review these GPO scripts for hardcoded credentials" -ForegroundColor Red
}

# ============================================================
# CHECK 5: GPO status (disabled/partially disabled)
# ============================================================
Write-Host "`n[5/5] GPO status check..." -ForegroundColor Yellow

$disabledGPOs = $allGPOs | Where-Object { $_.GpoStatus -ne "AllSettingsEnabled" }
if ($disabledGPOs) {
    Write-Host "  [i] $($disabledGPOs.Count) GPOs not fully enabled:" -ForegroundColor DarkYellow
    foreach ($d in $disabledGPOs) {
        Write-Host "    - $($d.DisplayName) — Status: $($d.GpoStatus)" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "  [+] All GPOs are fully enabled." -ForegroundColor Green
}

# Summary
Write-Host "`n[*] Summary" -ForegroundColor Cyan
Write-Host "  Total GPOs          : $($allGPOs.Count)"
Write-Host "  Risky editors       : $($riskyEditors.Count)"
Write-Host "  Unlinked GPOs       : $($unlinked.Count)"
Write-Host "  Admin-modifying GPOs: $($adminGPOs.Count)"
Write-Host "  Script GPOs         : $($scriptGPOs.Count)"
Write-Host "  Results exported to : $ExportPath" -ForegroundColor Cyan
