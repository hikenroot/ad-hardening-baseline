#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Generate a consolidated HTML audit report from all AD hardening checks.

.DESCRIPTION
    Runs all audit scripts and generates a professional HTML report
    with pass/fail status, risk levels, and remediation recommendations.
    
    Suitable for ISO 27001 / CIS Benchmark compliance evidence.

.PARAMETER OutputFile
    Path for the HTML report. Defaults to .\audit-results\ad-hardening-report.html

.EXAMPLE
    .\10-generate-report.ps1
    .\10-generate-report.ps1 -OutputFile C:\Reports\ad-audit.html
#>

param(
    [string]$OutputFile = ".\audit-results\ad-hardening-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
)

$ErrorActionPreference = "Continue"
$ExportPath = Split-Path $OutputFile -Parent
if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }

Write-Host "`n[*] AD Hardening Consolidated Report — $(Get-Date)" -ForegroundColor Cyan
Write-Host "[*] Running all audit checks...`n" -ForegroundColor Cyan

$results = @()

# ============================================================
# Helper function: add result
# ============================================================
function Add-AuditResult {
    param($Category, $Check, $Status, $Risk, $Details, $Remediation, $CIS, $MITRE)
    $script:results += [PSCustomObject]@{
        Category     = $Category
        Check        = $Check
        Status       = $Status      # PASS, FAIL, WARNING
        Risk         = $Risk        # Critical, High, Medium, Low
        Details      = $Details
        Remediation  = $Remediation
        CISBenchmark = $CIS
        MITRE        = $MITRE
    }
}

# ============================================================
# AUDIT 1: LDAP Passwords
# ============================================================
Write-Host "[1/8] Auditing LDAP password exposure..." -ForegroundColor Yellow

$passwordPatterns = @("pass", "pwd", "mdp", "secret", "key", "cred")
$suspectCount = 0
$allUsers = Get-ADUser -Filter * -Properties Description
foreach ($user in $allUsers) {
    if ($user.Description) {
        foreach ($p in $passwordPatterns) {
            if ($user.Description -match $p) { $suspectCount++; break }
        }
    }
}
Add-AuditResult "Credential Exposure" "Passwords in LDAP descriptions" `
    $(if($suspectCount -eq 0){"PASS"}else{"FAIL"}) `
    $(if($suspectCount -eq 0){"Low"}else{"Critical"}) `
    "$suspectCount accounts with suspected passwords in description" `
    "Remove passwords from LDAP descriptions, implement password vault" `
    "1.1.x" "T1552.001"

# ============================================================
# AUDIT 2: LLMNR/NBT-NS
# ============================================================
Write-Host "[2/8] Auditing LLMNR/NBT-NS..." -ForegroundColor Yellow

$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$llmnrValue = Get-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
$llmnrDisabled = ($llmnrValue.EnableMulticast -eq 0)

Add-AuditResult "Network Protocols" "LLMNR disabled" `
    $(if($llmnrDisabled){"PASS"}else{"FAIL"}) `
    $(if($llmnrDisabled){"Low"}else{"High"}) `
    "LLMNR is $(if($llmnrDisabled){'disabled'}else{'enabled — vulnerable to Responder'})" `
    "Disable LLMNR via GPO (Computer Config > Admin Templates > Network > DNS Client)" `
    "18.5.4.1" "T1557.001"

# ============================================================
# AUDIT 3: SMB Signing
# ============================================================
Write-Host "[3/8] Auditing SMB signing..." -ForegroundColor Yellow

$smbConfig = Get-SmbServerConfiguration
Add-AuditResult "Network Protocols" "SMB signing required" `
    $(if($smbConfig.RequireSecuritySignature){"PASS"}else{"FAIL"}) `
    $(if($smbConfig.RequireSecuritySignature){"Low"}else{"Critical"}) `
    "SMB signing is $(if($smbConfig.RequireSecuritySignature){'required'}else{'not required — relay vulnerable'})" `
    "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force" `
    "2.3.8.1" "T1557.001"

Add-AuditResult "Network Protocols" "SMBv1 disabled" `
    $(if(-not $smbConfig.EnableSMB1Protocol){"PASS"}else{"FAIL"}) `
    $(if(-not $smbConfig.EnableSMB1Protocol){"Low"}else{"High"}) `
    "SMBv1 is $(if(-not $smbConfig.EnableSMB1Protocol){'disabled'}else{'enabled — EternalBlue surface'})" `
    "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" `
    "2.3.8.x" "T1210"

# ============================================================
# AUDIT 4: LAPS Coverage
# ============================================================
Write-Host "[4/8] Auditing LAPS coverage..." -ForegroundColor Yellow

$allComputers = Get-ADComputer -Filter {Enabled -eq $true} -Properties ms-Mcs-AdmPwd
$withLaps = ($allComputers | Where-Object { $_.'ms-Mcs-AdmPwd' } | Measure-Object).Count
$totalComputers = ($allComputers | Measure-Object).Count
$coverage = if($totalComputers -gt 0){[math]::Round($withLaps/$totalComputers*100)}else{0}

Add-AuditResult "Local Admin" "LAPS deployment coverage" `
    $(if($coverage -ge 90){"PASS"}elseif($coverage -ge 50){"WARNING"}else{"FAIL"}) `
    $(if($coverage -ge 90){"Low"}elseif($coverage -ge 50){"Medium"}else{"High"}) `
    "LAPS coverage: $withLaps/$totalComputers ($coverage%)" `
    "Deploy LAPS to all workstations and member servers" `
    "18.2.1" "T1550.002"

# ============================================================
# AUDIT 5: Kerberos (AS-REP Roastable)
# ============================================================
Write-Host "[5/8] Auditing Kerberos configuration..." -ForegroundColor Yellow

$asrepCount = (Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Measure-Object).Count
Add-AuditResult "Kerberos" "AS-REP Roastable accounts" `
    $(if($asrepCount -eq 0){"PASS"}else{"FAIL"}) `
    $(if($asrepCount -eq 0){"Low"}else{"High"}) `
    "$asrepCount accounts with PreAuth disabled" `
    "Enable Kerberos pre-authentication on all accounts" `
    "2.3.6.x" "T1558.004"

$spnCount = (Get-ADUser -Filter {ServicePrincipalName -like "*"} | Where-Object {$_.SamAccountName -ne "krbtgt"} | Measure-Object).Count
Add-AuditResult "Kerberos" "Kerberoastable accounts" `
    $(if($spnCount -eq 0){"PASS"}else{"WARNING"}) `
    $(if($spnCount -eq 0){"Low"}else{"Medium"}) `
    "$spnCount user accounts with SPNs (Kerberoastable)" `
    "Use gMSA, enforce 25+ char passwords, AES256 only" `
    "2.3.6.1" "T1558.003"

# ============================================================
# AUDIT 6: Protected Users
# ============================================================
Write-Host "[6/8] Auditing Protected Users..." -ForegroundColor Yellow

$protectedCount = (Get-ADGroupMember "Protected Users" -ErrorAction SilentlyContinue | Measure-Object).Count
Add-AuditResult "Privileged Access" "Protected Users membership" `
    $(if($protectedCount -gt 0){"PASS"}else{"FAIL"}) `
    $(if($protectedCount -gt 0){"Low"}else{"High"}) `
    "$protectedCount accounts in Protected Users" `
    "Add all DA/EA/SA accounts to Protected Users group" `
    "1.1.6" "T1003"

# ============================================================
# AUDIT 7: Anonymous LDAP
# ============================================================
Write-Host "[7/8] Auditing anonymous LDAP..." -ForegroundColor Yellow

$domainDN = (Get-ADDomain).DistinguishedName
$dsH = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$domainDN" -Properties dsHeuristics -ErrorAction SilentlyContinue).dsHeuristics
$anonBlocked = ($dsH -and $dsH.Length -ge 7 -and $dsH[6] -eq '2')

Add-AuditResult "LDAP" "Anonymous LDAP bind" `
    $(if($anonBlocked){"PASS"}else{"FAIL"}) `
    $(if($anonBlocked){"Low"}else{"High"}) `
    "Anonymous LDAP is $(if($anonBlocked){'restricted'}else{'allowed — enumeration possible'})" `
    "Set dsHeuristics bit 7 to 2" `
    "2.3.10.2" "T1087.002"

# ============================================================
# AUDIT 8: GPO Count
# ============================================================
Write-Host "[8/8] Auditing GPO inventory..." -ForegroundColor Yellow

$gpoCount = (Get-GPO -All | Measure-Object).Count
Add-AuditResult "Group Policy" "GPO inventory" `
    "INFO" "Info" "$gpoCount GPOs in domain" "" "" ""

# ============================================================
# GENERATE HTML REPORT
# ============================================================
Write-Host "`n[*] Generating HTML report..." -ForegroundColor Cyan

$passCount = ($results | Where-Object { $_.Status -eq "PASS" } | Measure-Object).Count
$failCount = ($results | Where-Object { $_.Status -eq "FAIL" } | Measure-Object).Count
$warnCount = ($results | Where-Object { $_.Status -eq "WARNING" } | Measure-Object).Count
$totalChecks = $results.Count

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AD Hardening Audit Report</title>
<style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; color: #1a1a1a; }
    h1 { color: #0D47A1; border-bottom: 3px solid #1565C0; padding-bottom: 10px; }
    h2 { color: #1565C0; margin-top: 30px; }
    .summary { display: flex; gap: 20px; margin: 20px 0; }
    .card { padding: 20px; border-radius: 8px; color: white; min-width: 120px; text-align: center; }
    .card-pass { background: #2e7d32; }
    .card-fail { background: #c62828; }
    .card-warn { background: #f57f17; }
    .card h3 { margin: 0; font-size: 36px; }
    .card p { margin: 5px 0 0; }
    table { border-collapse: collapse; width: 100%; margin-top: 15px; background: white; }
    th { background: #0D47A1; color: white; padding: 10px; text-align: left; }
    td { padding: 8px 10px; border-bottom: 1px solid #e0e0e0; }
    tr:hover { background: #e3f2fd; }
    .pass { color: #2e7d32; font-weight: bold; }
    .fail { color: #c62828; font-weight: bold; }
    .warning { color: #f57f17; font-weight: bold; }
    .info { color: #1565C0; font-weight: bold; }
    .footer { margin-top: 40px; color: #757575; font-size: 12px; border-top: 1px solid #e0e0e0; padding-top: 10px; }
</style>
</head>
<body>
<h1>Active Directory Hardening Audit Report</h1>
<p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | <strong>Domain:</strong> $((Get-ADDomain).DNSRoot) | <strong>DC:</strong> $((Get-ADDomainController).HostName)</p>

<div class="summary">
    <div class="card card-pass"><h3>$passCount</h3><p>PASS</p></div>
    <div class="card card-fail"><h3>$failCount</h3><p>FAIL</p></div>
    <div class="card card-warn"><h3>$warnCount</h3><p>WARNING</p></div>
</div>

<h2>Detailed Results</h2>
<table>
<tr><th>Category</th><th>Check</th><th>Status</th><th>Risk</th><th>Details</th><th>CIS</th><th>MITRE</th></tr>
"@

foreach ($r in $results) {
    $statusClass = switch($r.Status) { "PASS" {"pass"} "FAIL" {"fail"} "WARNING" {"warning"} default {"info"} }
    $html += "<tr><td>$($r.Category)</td><td>$($r.Check)</td><td class='$statusClass'>$($r.Status)</td><td>$($r.Risk)</td><td>$($r.Details)</td><td>$($r.CISBenchmark)</td><td>$($r.MITRE)</td></tr>`n"
}

$html += @"
</table>

<h2>Remediation Priority</h2>
<table>
<tr><th>Priority</th><th>Check</th><th>Remediation</th></tr>
"@

$failedChecks = $results | Where-Object { $_.Status -eq "FAIL" } | Sort-Object { switch($_.Risk) { "Critical" {0} "High" {1} "Medium" {2} default {3} } }
$priority = 1
foreach ($f in $failedChecks) {
    $html += "<tr><td><strong>$priority</strong></td><td>$($f.Check)</td><td>$($f.Remediation)</td></tr>`n"
    $priority++
}

$html += @"
</table>

<div class="footer">
    <p>Generated by <strong>ad-hardening-baseline</strong> — <a href="https://github.com/hikenroot/ad-hardening-baseline">github.com/hikenroot/ad-hardening-baseline</a></p>
    <p>hik3nR00t | CIS Benchmark / NIST SP 800-53 / ISO 27001 aligned</p>
</div>
</body>
</html>
"@

$html | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "[+] Report generated: $OutputFile" -ForegroundColor Green
Write-Host "    PASS: $passCount | FAIL: $failCount | WARNING: $warnCount | Total: $totalChecks" -ForegroundColor Cyan

# Open report
if (Test-Path $OutputFile) {
    Write-Host "[*] Opening report in browser..." -ForegroundColor Cyan
    Start-Process $OutputFile
}
