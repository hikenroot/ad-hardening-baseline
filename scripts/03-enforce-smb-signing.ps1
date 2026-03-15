#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enforce SMB signing and disable SMBv1.

.DESCRIPTION
    Counters: T1557.001 (NTLM Relay via unsigned SMB)
    CIS Benchmark: 2.3.8.1/2.3.8.2 — Ensure SMB signing is required
    
.PARAMETER AuditOnly
    Only check current state without making changes.

.EXAMPLE
    .\03-enforce-smb-signing.ps1 -AuditOnly
    .\03-enforce-smb-signing.ps1
#>

param([switch]$AuditOnly)

Write-Host "`n[*] SMB Hardening — $(Get-Date)" -ForegroundColor Cyan

# ============================================================
# CHECK 1: SMB Server Signing
# ============================================================
Write-Host "`n[1/3] SMB Server Signing..." -ForegroundColor Yellow

$smbServer = Get-SmbServerConfiguration
if ($smbServer.RequireSecuritySignature) {
    Write-Host "  [+] SMB Server signing: REQUIRED" -ForegroundColor Green
} else {
    Write-Host "  [!] SMB Server signing: NOT required — relay vulnerable" -ForegroundColor Red
    if (-not $AuditOnly) {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Write-Host "  [+] SMB Server signing: ENFORCED" -ForegroundColor Green
    }
}

# ============================================================
# CHECK 2: SMB Client Signing
# ============================================================
Write-Host "`n[2/3] SMB Client Signing..." -ForegroundColor Yellow

$smbClient = Get-SmbClientConfiguration
if ($smbClient.RequireSecuritySignature) {
    Write-Host "  [+] SMB Client signing: REQUIRED" -ForegroundColor Green
} else {
    Write-Host "  [!] SMB Client signing: NOT required" -ForegroundColor Red
    if (-not $AuditOnly) {
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
        Write-Host "  [+] SMB Client signing: ENFORCED" -ForegroundColor Green
    }
}

# ============================================================
# CHECK 3: SMBv1 Status
# ============================================================
Write-Host "`n[3/3] SMBv1 Status..." -ForegroundColor Yellow

if ($smbServer.EnableSMB1Protocol) {
    Write-Host "  [!] SMBv1: ENABLED — EternalBlue/WannaCry attack surface" -ForegroundColor Red
    if (-not $AuditOnly) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-Host "  [+] SMBv1: DISABLED" -ForegroundColor Green
    }
} else {
    Write-Host "  [+] SMBv1: DISABLED" -ForegroundColor Green
}

# Summary
Write-Host "`n[*] Summary" -ForegroundColor Cyan
Write-Host "  Server signing required : $($smbServer.RequireSecuritySignature)"
Write-Host "  Client signing required : $($smbClient.RequireSecuritySignature)"
Write-Host "  SMBv1 enabled           : $($smbServer.EnableSMB1Protocol)"
if ($AuditOnly) {
    Write-Host "`n  [i] Audit mode — no changes made." -ForegroundColor DarkYellow
}
