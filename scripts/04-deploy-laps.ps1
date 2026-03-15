#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deploy and audit Microsoft LAPS (Local Administrator Password Solution).

.DESCRIPTION
    Checks LAPS deployment status, configures AD schema extension, sets permissions,
    and enables automatic local admin password rotation.
    
    Counters: T1550.002 (Pass-the-Hash), T1078.003 (Local Accounts)
    CIS Benchmark: 18.2.1 — Ensure LAPS AdmPwd GPO Extension is enabled

.PARAMETER AuditOnly
    Only check LAPS deployment status without making changes.

.PARAMETER TargetOU
    OU to configure LAPS permissions on. Defaults to all computer OUs.

.PARAMETER ExportPath
    Path for CSV export.

.EXAMPLE
    .\04-deploy-laps.ps1 -AuditOnly
    .\04-deploy-laps.ps1 -TargetOU "OU=Servers,DC=contoso,DC=local"
#>

param(
    [switch]$AuditOnly,
    [string]$TargetOU,
    [string]$ExportPath = ".\audit-results"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }

Write-Host "`n[*] LAPS Deployment Audit — $(Get-Date)" -ForegroundColor Cyan

# ============================================================
# CHECK 1: LAPS Schema Extension
# ============================================================
Write-Host "`n[1/5] LAPS schema extension..." -ForegroundColor Yellow

$lapsSchema = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter {Name -eq "ms-Mcs-AdmPwd"} -ErrorAction SilentlyContinue
$windowsLaps = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Filter {Name -eq "msLAPS-Password"} -ErrorAction SilentlyContinue

if ($windowsLaps) {
    Write-Host "  [+] Windows LAPS schema detected (modern)" -ForegroundColor Green
} elseif ($lapsSchema) {
    Write-Host "  [+] Legacy LAPS schema detected (ms-Mcs-AdmPwd)" -ForegroundColor Green
} else {
    Write-Host "  [!] LAPS schema NOT extended — LAPS not deployed" -ForegroundColor Red
    if (-not $AuditOnly) {
        Write-Host "  [*] To extend schema, run: Update-LapsADSchema" -ForegroundColor Yellow
    }
}

# ============================================================
# CHECK 2: Computers with LAPS password set
# ============================================================
Write-Host "`n[2/5] Computers with LAPS passwords..." -ForegroundColor Yellow

$allComputers = Get-ADComputer -Filter {Enabled -eq $true} -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime, OperatingSystem
$withLaps = $allComputers | Where-Object { $_.'ms-Mcs-AdmPwd' }
$withoutLaps = $allComputers | Where-Object { -not $_.'ms-Mcs-AdmPwd' -and $_.OperatingSystem -notmatch "Domain Controller" }

$totalEnabled = ($allComputers | Measure-Object).Count
$lapsCount = ($withLaps | Measure-Object).Count
$noLapsCount = ($withoutLaps | Measure-Object).Count

Write-Host "  Total enabled computers : $totalEnabled" -ForegroundColor Cyan
Write-Host "  With LAPS password      : $lapsCount" -ForegroundColor $(if($lapsCount -gt 0){"Green"}else{"Red"})
Write-Host "  Without LAPS password   : $noLapsCount" -ForegroundColor $(if($noLapsCount -eq 0){"Green"}else{"Red"})

if ($noLapsCount -gt 0) {
    Write-Host "`n  Computers WITHOUT LAPS:" -ForegroundColor Red
    foreach ($c in $withoutLaps | Select-Object -First 20) {
        Write-Host "    - $($c.Name) ($($c.OperatingSystem))" -ForegroundColor Red
    }
    if ($noLapsCount -gt 20) { Write-Host "    ... and $($noLapsCount - 20) more" -ForegroundColor Red }
    $withoutLaps | Select-Object Name, OperatingSystem, DistinguishedName |
        Export-Csv "$ExportPath\computers-without-laps-$timestamp.csv" -NoTypeInformation
}

# ============================================================
# CHECK 3: LAPS password expiration
# ============================================================
Write-Host "`n[3/5] LAPS password expiration check..." -ForegroundColor Yellow

$expiredLaps = @()
foreach ($c in $withLaps) {
    $expTime = $c.'ms-Mcs-AdmPwdExpirationTime'
    if ($expTime) {
        $expDate = [DateTime]::FromFileTime($expTime)
        if ($expDate -lt (Get-Date)) {
            $expiredLaps += [PSCustomObject]@{
                Name = $c.Name
                ExpirationDate = $expDate
                DaysExpired = ((Get-Date) - $expDate).Days
            }
        }
    }
}

if ($expiredLaps.Count -gt 0) {
    Write-Host "  [!] $($expiredLaps.Count) computers with expired LAPS passwords:" -ForegroundColor Red
    foreach ($e in $expiredLaps | Select-Object -First 10) {
        Write-Host "    - $($e.Name) expired $($e.DaysExpired) days ago" -ForegroundColor Red
    }
} else {
    Write-Host "  [+] All LAPS passwords are current." -ForegroundColor Green
}

# ============================================================
# CHECK 4: LAPS GPO Configuration
# ============================================================
Write-Host "`n[4/5] LAPS GPO configuration..." -ForegroundColor Yellow

$lapsGPOs = Get-GPO -All | Where-Object {
    $_ | Get-GPOReport -ReportType Xml | Select-String -Pattern "LAPS|AdmPwd" -Quiet
} -ErrorAction SilentlyContinue

if ($lapsGPOs) {
    Write-Host "  [+] LAPS GPO(s) found:" -ForegroundColor Green
    foreach ($g in $lapsGPOs) {
        Write-Host "    - $($g.DisplayName) (Status: $($g.GpoStatus))" -ForegroundColor Green
    }
} else {
    Write-Host "  [!] No LAPS GPO found — LAPS not configured via Group Policy" -ForegroundColor Red
}

# ============================================================
# CHECK 5: Self-permission on target OUs
# ============================================================
Write-Host "`n[5/5] LAPS self-permission on OUs..." -ForegroundColor Yellow

if ($TargetOU) {
    $ous = @(Get-ADOrganizationalUnit -Identity $TargetOU)
} else {
    $ous = Get-ADOrganizationalUnit -Filter {Name -like "*Server*" -or Name -like "*Computer*" -or Name -like "*Workstation*"}
}

foreach ($ou in $ous) {
    Write-Host "  Checking: $($ou.DistinguishedName)" -ForegroundColor Cyan
    if (-not $AuditOnly) {
        try {
            Set-LapsADComputerSelfPermission -Identity $ou.DistinguishedName -ErrorAction Stop
            Write-Host "    [+] Self-permission set" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Could not set permission: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }
}

# Summary
Write-Host "`n[*] Summary" -ForegroundColor Cyan
Write-Host "  Schema extended     : $(if($windowsLaps -or $lapsSchema){'Yes'}else{'No'})"
Write-Host "  LAPS coverage       : $lapsCount / $totalEnabled ($(if($totalEnabled -gt 0){[math]::Round($lapsCount/$totalEnabled*100)}else{0})%)"
Write-Host "  Expired passwords   : $($expiredLaps.Count)"
Write-Host "  Without LAPS        : $noLapsCount"
Write-Host "  Results exported to : $ExportPath" -ForegroundColor Cyan
