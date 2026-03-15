#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Audit Active Directory for exposed passwords in LDAP descriptions and SYSVOL scripts.

.DESCRIPTION
    Searches for credentials stored in:
    - User/computer description fields (LDAP attributes)
    - SYSVOL login scripts (.ps1, .bat, .cmd, .vbs)
    - Group Policy Preferences (GPP) XML files (cpassword)
    
    Counters: T1552.001 (Credentials in Files), T1552.006 (Group Policy Preferences)
    CIS Benchmark: 1.1.x — Ensure passwords are not stored in reversible encryption

.PARAMETER DomainController
    Target Domain Controller FQDN. Defaults to current domain.

.PARAMETER ExportPath
    Path for CSV export. Defaults to .\audit-results\

.EXAMPLE
    .\01-audit-ad-passwords.ps1
    .\01-audit-ad-passwords.ps1 -DomainController dc01.contoso.local -ExportPath C:\Audits\
#>

param(
    [string]$DomainController = (Get-ADDomainController).HostName,
    [string]$ExportPath = ".\audit-results"
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

if (-not (Test-Path $ExportPath)) { New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null }

Write-Host "`n[*] AD Password Exposure Audit — $(Get-Date)" -ForegroundColor Cyan
Write-Host "[*] Target DC: $DomainController`n" -ForegroundColor Cyan

# ============================================================
# CHECK 1: Passwords in LDAP Description fields
# ============================================================
Write-Host "[1/4] Checking LDAP descriptions for password patterns..." -ForegroundColor Yellow

$passwordPatterns = @("pass", "pwd", "mdp", "secret", "key", "cred", "motdepasse")
$suspectUsers = @()

$allUsers = Get-ADUser -Filter * -Properties Description, SamAccountName -Server $DomainController
foreach ($user in $allUsers) {
    if ($user.Description) {
        foreach ($pattern in $passwordPatterns) {
            if ($user.Description -match $pattern) {
                $suspectUsers += [PSCustomObject]@{
                    SamAccountName = $user.SamAccountName
                    Description    = $user.Description
                    MatchedPattern = $pattern
                    ObjectType     = "User"
                }
                Write-Host "  [!] FOUND: $($user.SamAccountName) — Description contains '$pattern'" -ForegroundColor Red
                break
            }
        }
    }
}

$allComputers = Get-ADComputer -Filter * -Properties Description -Server $DomainController
foreach ($computer in $allComputers) {
    if ($computer.Description) {
        foreach ($pattern in $passwordPatterns) {
            if ($computer.Description -match $pattern) {
                $suspectUsers += [PSCustomObject]@{
                    SamAccountName = $computer.Name
                    Description    = $computer.Description
                    MatchedPattern = $pattern
                    ObjectType     = "Computer"
                }
                Write-Host "  [!] FOUND: $($computer.Name) — Description contains '$pattern'" -ForegroundColor Red
                break
            }
        }
    }
}

if ($suspectUsers.Count -eq 0) {
    Write-Host "  [+] No passwords found in LDAP descriptions." -ForegroundColor Green
} else {
    Write-Host "  [!] $($suspectUsers.Count) objects with suspected passwords in description." -ForegroundColor Red
    $suspectUsers | Export-Csv "$ExportPath\ldap-password-exposure-$timestamp.csv" -NoTypeInformation
}

# ============================================================
# CHECK 2: Credentials in SYSVOL scripts
# ============================================================
Write-Host "`n[2/4] Scanning SYSVOL scripts for credentials..." -ForegroundColor Yellow

$domain = (Get-ADDomain -Server $DomainController).DNSRoot
$sysvolPath = "\\$domain\SYSVOL\$domain"
$scriptPatterns = @("password", "pass=", "pwd=", "net user", "SecureString", "ConvertTo-SecureString", "credentials")
$suspectScripts = @()

if (Test-Path $sysvolPath) {
    $scripts = Get-ChildItem -Path $sysvolPath -Recurse -Include *.ps1, *.bat, *.cmd, *.vbs -ErrorAction SilentlyContinue
    foreach ($script in $scripts) {
        $content = Get-Content $script.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            foreach ($pattern in $scriptPatterns) {
                if ($content -match $pattern) {
                    $suspectScripts += [PSCustomObject]@{
                        FilePath       = $script.FullName
                        MatchedPattern = $pattern
                        LastModified   = $script.LastWriteTime
                    }
                    Write-Host "  [!] FOUND: $($script.FullName) — contains '$pattern'" -ForegroundColor Red
                    break
                }
            }
        }
    }
    if ($suspectScripts.Count -eq 0) {
        Write-Host "  [+] No credentials found in SYSVOL scripts." -ForegroundColor Green
    } else {
        $suspectScripts | Export-Csv "$ExportPath\sysvol-credential-exposure-$timestamp.csv" -NoTypeInformation
    }
} else {
    Write-Host "  [-] Cannot access SYSVOL at $sysvolPath" -ForegroundColor DarkYellow
}

# ============================================================
# CHECK 3: GPP cpassword (MS14-025)
# ============================================================
Write-Host "`n[3/4] Scanning for GPP cpassword (MS14-025)..." -ForegroundColor Yellow

$gppFiles = @()
$policiesPath = "\\$domain\SYSVOL\$domain\Policies"
if (Test-Path $policiesPath) {
    $xmlFiles = Get-ChildItem -Path $policiesPath -Recurse -Include *.xml -ErrorAction SilentlyContinue
    foreach ($xml in $xmlFiles) {
        $content = Get-Content $xml.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match "cpassword") {
            $gppFiles += [PSCustomObject]@{
                FilePath     = $xml.FullName
                LastModified = $xml.LastWriteTime
            }
            Write-Host "  [!] CRITICAL: GPP cpassword found in $($xml.FullName)" -ForegroundColor Red
        }
    }
    if ($gppFiles.Count -eq 0) {
        Write-Host "  [+] No GPP cpassword found." -ForegroundColor Green
    } else {
        $gppFiles | Export-Csv "$ExportPath\gpp-cpassword-$timestamp.csv" -NoTypeInformation
    }
}

# ============================================================
# CHECK 4: Summary
# ============================================================
Write-Host "`n[4/4] Summary" -ForegroundColor Cyan
Write-Host "  LDAP descriptions with passwords : $($suspectUsers.Count)" -ForegroundColor $(if($suspectUsers.Count -gt 0){"Red"}else{"Green"})
Write-Host "  SYSVOL scripts with credentials  : $($suspectScripts.Count)" -ForegroundColor $(if($suspectScripts.Count -gt 0){"Red"}else{"Green"})
Write-Host "  GPP cpassword (MS14-025)         : $($gppFiles.Count)" -ForegroundColor $(if($gppFiles.Count -gt 0){"Red"}else{"Green"})
Write-Host "`n  Results exported to: $ExportPath" -ForegroundColor Cyan

# Return object for pipeline
[PSCustomObject]@{
    Timestamp            = $timestamp
    LDAPPasswordExposure = $suspectUsers.Count
    SYSVOLCredentials    = $suspectScripts.Count
    GPPcpassword         = $gppFiles.Count
    ExportPath           = $ExportPath
}
