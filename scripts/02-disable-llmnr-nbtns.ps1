#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disable LLMNR and NBT-NS to prevent NTLM relay attacks.

.DESCRIPTION
    Counters: T1557.001 (LLMNR/NBT-NS Poisoning)
    CIS Benchmark: 18.5.4.1 — Ensure Turn off multicast name resolution is Enabled

.PARAMETER AuditOnly
    Only check current state without making changes.

.EXAMPLE
    .\02-disable-llmnr-nbtns.ps1 -AuditOnly
    .\02-disable-llmnr-nbtns.ps1
#>

param([switch]$AuditOnly)

Write-Host "`n[*] LLMNR / NBT-NS Hardening — $(Get-Date)" -ForegroundColor Cyan

# ============================================================
# CHECK 1: LLMNR Status
# ============================================================
Write-Host "`n[1/2] LLMNR Status..." -ForegroundColor Yellow

$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$llmnrValue = Get-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue

if ($llmnrValue.EnableMulticast -eq 0) {
    Write-Host "  [+] LLMNR is DISABLED (registry)" -ForegroundColor Green
} else {
    Write-Host "  [!] LLMNR is ENABLED — vulnerable to poisoning" -ForegroundColor Red
    if (-not $AuditOnly) {
        Write-Host "  [*] Disabling LLMNR..." -ForegroundColor Yellow
        if (-not (Test-Path $llmnrPath)) {
            New-Item -Path $llmnrPath -Force | Out-Null
        }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord
        Write-Host "  [+] LLMNR DISABLED" -ForegroundColor Green
    }
}

# ============================================================
# CHECK 2: NBT-NS Status
# ============================================================
Write-Host "`n[2/2] NBT-NS Status..." -ForegroundColor Yellow

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
$nbtnsVulnerable = 0

foreach ($adapter in $adapters) {
    $tcpipNetbios = $adapter.TcpipNetbiosOptions
    # 0 = Default (enabled), 1 = Enabled, 2 = Disabled
    if ($tcpipNetbios -ne 2) {
        $nbtnsVulnerable++
        Write-Host "  [!] $($adapter.Description) — NBT-NS ENABLED (value: $tcpipNetbios)" -ForegroundColor Red
        if (-not $AuditOnly) {
            Write-Host "  [*] Disabling NBT-NS on $($adapter.Description)..." -ForegroundColor Yellow
            $adapter.SetTcpipNetbios(2) | Out-Null
            Write-Host "  [+] NBT-NS DISABLED on $($adapter.Description)" -ForegroundColor Green
        }
    } else {
        Write-Host "  [+] $($adapter.Description) — NBT-NS DISABLED" -ForegroundColor Green
    }
}

# Summary
Write-Host "`n[*] Summary" -ForegroundColor Cyan
Write-Host "  LLMNR : $(if($llmnrValue.EnableMulticast -eq 0){'DISABLED (OK)'}else{'ENABLED (VULNERABLE)'})"
Write-Host "  NBT-NS vulnerable adapters : $nbtnsVulnerable"
if ($AuditOnly) {
    Write-Host "`n  [i] Audit mode — no changes made. Run without -AuditOnly to remediate." -ForegroundColor DarkYellow
}
