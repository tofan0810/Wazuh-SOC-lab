# ==============================================================================
# Setup Deception Canary Files, Windows SACL Auditing & Honey-Account
# MITRE ATT&CK: T1083 (File Discovery), T1005 (Data from Local System), T1078 (Valid Accounts)
# ==============================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "[*] Configuring Windows Object Access Auditing..."
# Enable File System auditing (Success and Failure)
auditpol /set /subcategory:"File System" /success:enable /failure:enable
if ($LASTEXITCODE -ne 0) {
    Write-Warning "auditpol command returned code $LASTEXITCODE"
}

# ------------------------------------------------------------------------------
# 1. Setup Canary File at C:\Users\Public\IT_Admin_Credentials.xlsx
# ------------------------------------------------------------------------------
$canaryPath = "C:\Users\Public\IT_Admin_Credentials.xlsx"
Write-Host "[*] Creating Canary File at $canaryPath..."

$canaryContent = @"
SERVER_NAME,IP_ADDRESS,ADMIN_USER,PASSWORD,NOTES
DC-01.corp.local,192.168.71.10,administrator,P@ssw0rd2026!Prod,Primary Active Directory Domain Controller
SQL-PROD-01,192.168.71.20,sa,SuperSecretSQL_DB_Pass!,Financial Database Instance
VPN-GATEWAY,192.168.71.1,vpn_admin,VpnToken#Secure2026,Core Cisco ASA VPN
BACKUP-SRV,192.168.71.50,backup_admin,H0neyP0t_Tr1pw1re_2026!,Veeam Backup Repository
"@

[IO.File]::WriteAllText($canaryPath, $canaryContent, [System.Text.Encoding]::UTF8)

# ------------------------------------------------------------------------------
# 2. Configure SACL (System Access Control List) for Read Access Auditing
# ------------------------------------------------------------------------------
Write-Host "[*] Configuring SACL on $canaryPath to trigger Event ID 4663 on READ..."
try {
    $fileItem = Get-Item $canaryPath
    $acl = $fileItem.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
    
    $identity = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null) # Everyone
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        $identity,
        [System.Security.AccessControl.FileSystemRights]::ReadData,
        [System.Security.AccessControl.AuditFlags]::Success
    )
    
    $acl.SetAuditRule($auditRule)
    $fileItem.SetAccessControl($acl)
    Write-Host "[+] SACL successfully set on $canaryPath!" -ForegroundColor Green
} catch {
    Write-Warning "Failed setting SACL via .NET API: $_"
}

# ------------------------------------------------------------------------------
# 3. Setup Honey-Account (backup_admin) as a Login Tripwire
# ------------------------------------------------------------------------------
Write-Host "[*] Checking Honey-Account 'backup_admin'..."
$honeyUser = Get-LocalUser -Name "backup_admin" -ErrorAction SilentlyContinue

if (-not $honeyUser) {
    Write-Host "[*] Creating local Honey-Account 'backup_admin'..."
    # High-entropy dynamically generated password, user is disabled from real privileges or set to non-interactive
    $generatedPass = [System.Guid]::NewGuid().ToString("N") + "!Aa1"
    $securePass = ConvertTo-SecureString $generatedPass -AsPlainText -Force
    New-LocalUser -Name "backup_admin" -Password $securePass -FullName "Enterprise Backup Administrator (Decoy)" -Description "Decoy Honey-Account for Tripwire Detection (Zero False Positive)" -PasswordNeverExpires:$true
    Write-Host "[+] Honey-Account 'backup_admin' created successfully!" -ForegroundColor Green
} else {
    Write-Host "[i] Honey-Account 'backup_admin' already exists." -ForegroundColor Cyan
}

Write-Host "=== DECEPTION SETUP VERIFICATION ==="
Get-Item $canaryPath | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize
auditpol /get /subcategory:"File System"
Get-LocalUser -Name "backup_admin" | Select-Object Name, Enabled, Description | Format-Table -AutoSize
Write-Host "[+] All Deception artifacts deployed successfully." -ForegroundColor Green
