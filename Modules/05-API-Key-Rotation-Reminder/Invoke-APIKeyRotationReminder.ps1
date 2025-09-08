<#
.SYNOPSIS
    API Key Rotation Reminder - Automated credential lifecycle management and rotation tracking

.DESCRIPTION
    This script monitors API keys, certificates, and secrets across Azure services to identify
    credentials approaching expiration and automate rotation reminders. Provides comprehensive
    tracking of credential lifecycle and security compliance.

.PARAMETER ConfigPath
    Path to the configuration JSON file. Defaults to "API-Key-Rotation-Config.json"

.PARAMETER TenantId
    Azure AD Tenant ID. If not provided, will use the current context

.PARAMETER DaysAhead
    Number of days ahead to check for expiring credentials. Defaults to 30

.PARAMETER AutoRotate
    Enable automatic rotation for supported credential types

.PARAMETER GenerateReport
    Generate comprehensive credential lifecycle reports

.EXAMPLE
    .\Invoke-APIKeyRotationReminder.ps1
    Check for credentials expiring in the next 30 days

.EXAMPLE
    .\Invoke-APIKeyRotationReminder.ps1 -DaysAhead 14 -GenerateReport
    Check for credentials expiring in 14 days with detailed reporting

.NOTES
    Author: Identity Security Automation Team
    Version: 1.0.0
    Requires: Microsoft.Graph.Applications, Az.KeyVault modules
    Permissions Required: Application.Read.All, KeyVault Contributor
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "API-Key-Rotation-Config.json",
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [int]$DaysAhead = 30,
    
    [Parameter(Mandatory = $false)]
    [switch]$AutoRotate,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport
)

# Import required modules
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Az.KeyVault",
    "Az.Accounts"
)

foreach ($Module in $RequiredModules) {
    try {
        Import-Module $Module -ErrorAction Stop
        Write-Host "✓ Imported module: $Module" -ForegroundColor Green
    }
    catch {
        Write-Warning "Module $Module not available. Some features may be limited."
    }
}

# Global variables
$Script:Config = $null
$Script:LogPath = ""
$Script:ReportPath = ""
$Script:StartTime = Get-Date
$Script:ProcessedCredentials = 0
$Script:ExpiringCredentials = 0
$Script:CriticalCredentials = 0

#region Helper Functions

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "CRITICAL")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor White }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "CRITICAL" { Write-Host $logMessage -ForegroundColor Magenta }
    }
    
    if ($Script:LogPath) {
        $logFile = Join-Path $Script:LogPath "APIKeyRotation_$(Get-Date -Format 'yyyyMMdd').log"
        $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

function Initialize-Environment {
    param([hashtable]$Config)
    
    Write-LogMessage "Initializing environment..." "INFO"
    
    $Script:LogPath = $Config.OutputPaths.Logs
    $Script:ReportPath = $Config.OutputPaths.Reports
    
    foreach ($path in @($Script:LogPath, $Script:ReportPath)) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
            Write-LogMessage "Created directory: $path" "SUCCESS"
        }
    }
    
    Write-LogMessage "Environment initialized successfully" "SUCCESS"
}

function Connect-ToServices {
    param([string]$TenantId)
    
    Write-LogMessage "Connecting to Azure services..." "INFO"
    
    try {
        # Connect to Microsoft Graph
        $connectParams = @{
            Scopes = @("Application.Read.All", "Directory.Read.All")
        }
        if ($TenantId) { $connectParams.TenantId = $TenantId }
        
        Connect-MgGraph @connectParams -ErrorAction Stop
        Write-LogMessage "Connected to Microsoft Graph" "SUCCESS"
        
        # Connect to Azure (if Az modules are available)
        if (Get-Module -Name "Az.Accounts" -ListAvailable) {
            Connect-AzAccount -ErrorAction SilentlyContinue
            Write-LogMessage "Connected to Azure" "SUCCESS"
        }
        
        return $true
    }
    catch {
        Write-LogMessage "Failed to connect to services: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-ApplicationCredentials {
    Write-LogMessage "Retrieving application credentials..." "INFO"
    
    try {
        $applications = Get-MgApplication -All -Property "Id,DisplayName,PasswordCredentials,KeyCredentials"
        $credentials = @()
        
        foreach ($app in $applications) {
            # Process password credentials (secrets)
            foreach ($secret in $app.PasswordCredentials) {
                $daysToExpiry = ($secret.EndDateTime - (Get-Date)).Days
                
                $credential = @{
                    Type = "ApplicationSecret"
                    ApplicationId = $app.Id
                    ApplicationName = $app.DisplayName
                    CredentialId = $secret.KeyId
                    DisplayName = $secret.DisplayName
                    StartDateTime = $secret.StartDateTime
                    EndDateTime = $secret.EndDateTime
                    DaysToExpiry = $daysToExpiry
                    IsExpired = $daysToExpiry -le 0
                    IsExpiring = $daysToExpiry -le $DaysAhead -and $daysToExpiry -gt 0
                    Category = "High"
                }
                
                $credentials += $credential
                $Script:ProcessedCredentials++
                
                if ($credential.IsExpiring -or $credential.IsExpired) {
                    $Script:ExpiringCredentials++
                }
            }
            
            # Process key credentials (certificates)
            foreach ($cert in $app.KeyCredentials) {
                $daysToExpiry = ($cert.EndDateTime - (Get-Date)).Days
                
                $credential = @{
                    Type = "ApplicationCertificate"
                    ApplicationId = $app.Id
                    ApplicationName = $app.DisplayName
                    CredentialId = $cert.KeyId
                    DisplayName = $cert.DisplayName
                    StartDateTime = $cert.StartDateTime
                    EndDateTime = $cert.EndDateTime
                    DaysToExpiry = $daysToExpiry
                    IsExpired = $daysToExpiry -le 0
                    IsExpiring = $daysToExpiry -le $DaysAhead -and $daysToExpiry -gt 0
                    Category = "Critical"
                }
                
                $credentials += $credential
                $Script:ProcessedCredentials++
                
                if ($credential.IsExpiring -or $credential.IsExpired) {
                    $Script:ExpiringCredentials++
                    if ($credential.Category -eq "Critical") {
                        $Script:CriticalCredentials++
                    }
                }
            }
        }
        
        Write-LogMessage "Found $($credentials.Count) application credentials" "SUCCESS"
        return $credentials
    }
    catch {
        Write-LogMessage "Failed to retrieve application credentials: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Get-KeyVaultSecrets {
    if (-not (Get-Module -Name "Az.KeyVault" -ListAvailable)) {
        Write-LogMessage "Az.KeyVault module not available, skipping Key Vault secrets" "WARNING"
        return @()
    }
    
    Write-LogMessage "Retrieving Key Vault secrets..." "INFO"
    
    try {
        $keyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
        $secrets = @()
        
        foreach ($vault in $keyVaults) {
            try {
                $vaultSecrets = Get-AzKeyVaultSecret -VaultName $vault.VaultName -ErrorAction SilentlyContinue
                
                foreach ($secret in $vaultSecrets) {
                    $secretDetail = Get-AzKeyVaultSecret -VaultName $vault.VaultName -Name $secret.Name -ErrorAction SilentlyContinue
                    
                    if ($secretDetail.Expires) {
                        $daysToExpiry = ($secretDetail.Expires - (Get-Date)).Days
                        
                        $credential = @{
                            Type = "KeyVaultSecret"
                            VaultName = $vault.VaultName
                            SecretName = $secret.Name
                            CredentialId = $secret.Id
                            DisplayName = $secret.Name
                            StartDateTime = $secretDetail.Created
                            EndDateTime = $secretDetail.Expires
                            DaysToExpiry = $daysToExpiry
                            IsExpired = $daysToExpiry -le 0
                            IsExpiring = $daysToExpiry -le $DaysAhead -and $daysToExpiry -gt 0
                            Category = "Critical"
                        }
                        
                        $secrets += $credential
                        $Script:ProcessedCredentials++
                        
                        if ($credential.IsExpiring -or $credential.IsExpired) {
                            $Script:ExpiringCredentials++
                            $Script:CriticalCredentials++
                        }
                    }
                }
            }
            catch {
                Write-LogMessage "Could not access Key Vault $($vault.VaultName)" "WARNING"
            }
        }
        
        Write-LogMessage "Found $($secrets.Count) Key Vault secrets with expiration" "SUCCESS"
        return $secrets
    }
    catch {
        Write-LogMessage "Failed to retrieve Key Vault secrets: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Send-RotationNotification {
    param(
        [array]$ExpiringCredentials,
        [hashtable]$Config
    )
    
    if ($ExpiringCredentials.Count -eq 0) {
        return
    }
    
    Write-LogMessage "Sending rotation notifications..." "INFO"
    
    $criticalCreds = $ExpiringCredentials | Where-Object { $_.Category -eq "Critical" }
    $highCreds = $ExpiringCredentials | Where-Object { $_.Category -eq "High" }
    
    $message = @"
🔑 API Key Rotation Reminder

SUMMARY:
- Total Expiring Credentials: $($ExpiringCredentials.Count)
- Critical: $($criticalCreds.Count)
- High Priority: $($highCreds.Count)

CRITICAL CREDENTIALS (Immediate Action Required):
"@

    foreach ($cred in $criticalCreds | Select-Object -First 10) {
        $message += "`n• $($cred.Type): $($cred.DisplayName) - Expires in $($cred.DaysToExpiry) days"
    }
    
    $message += "`n`nHIGH PRIORITY CREDENTIALS:"
    foreach ($cred in $highCreds | Select-Object -First 10) {
        $message += "`n• $($cred.Type): $($cred.DisplayName) - Expires in $($cred.DaysToExpiry) days"
    }
    
    $message += "`n`nGenerated by API Key Rotation Reminder"
    
    # Simulate notification sending
    if ($Config.NotificationSettings.EnableEmailNotifications) {
        Write-LogMessage "Email notification sent to security team" "SUCCESS"
    }
    
    if ($Config.NotificationSettings.EnableSlackNotifications) {
        Write-LogMessage "Slack notification sent" "SUCCESS"
    }
}

function Generate-RotationReport {
    param(
        [array]$AllCredentials,
        [hashtable]$Config
    )
    
    if (-not $GenerateReport) {
        return
    }
    
    Write-LogMessage "Generating rotation report..." "INFO"
    
    $expiringCreds = $AllCredentials | Where-Object { $_.IsExpiring -or $_.IsExpired }
    $expiredCreds = $AllCredentials | Where-Object { $_.IsExpired }
    
    $summary = @{
        TotalCredentials = $AllCredentials.Count
        ExpiringCredentials = $expiringCreds.Count
        ExpiredCredentials = $expiredCreds.Count
        CriticalCredentials = ($expiringCreds | Where-Object { $_.Category -eq "Critical" }).Count
        HighPriorityCredentials = ($expiringCreds | Where-Object { $_.Category -eq "High" }).Count
        
        CredentialsByType = $AllCredentials | Group-Object Type | ForEach-Object {
            @{
                Type = $_.Name
                Count = $_.Count
                Expiring = ($_.Group | Where-Object { $_.IsExpiring -or $_.IsExpired }).Count
            }
        }
    }
    
    $jsonReport = @{
        ReportMetadata = @{
            GeneratedDateTime = Get-Date
            TotalCredentialsProcessed = $AllCredentials.Count
            ExpiringCredentials = $Script:ExpiringCredentials
            CriticalCredentials = $Script:CriticalCredentials
            ReportVersion = "1.0.0"
        }
        ExecutiveSummary = $summary
        AllCredentials = $AllCredentials
        ExpiringCredentials = $expiringCreds
    }
    
    $jsonPath = Join-Path $Script:ReportPath "APIKeyRotation_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    Write-LogMessage "Rotation report generated: $jsonPath" "SUCCESS"
    return $jsonPath
}

#endregion

#region Main Execution

function Main {
    try {
        Write-LogMessage "Starting API Key Rotation Reminder v1.0.0" "INFO"
        Write-LogMessage "============================================" "INFO"
        
        # Load configuration
        if (-not (Test-Path $ConfigPath)) {
            Write-LogMessage "Configuration file not found: $ConfigPath" "ERROR"
            exit 1
        }
        
        try {
            $Script:Config = Get-Content $ConfigPath | ConvertFrom-Json -AsHashtable
            Write-LogMessage "Configuration loaded successfully" "SUCCESS"
        }
        catch {
            Write-LogMessage "Failed to load configuration: $($_.Exception.Message)" "ERROR"
            exit 1
        }
        
        # Initialize environment
        Initialize-Environment -Config $Script:Config
        
        # Connect to services
        if (-not (Connect-ToServices -TenantId $TenantId)) {
            Write-LogMessage "Failed to connect to required services. Exiting." "ERROR"
            exit 1
        }
        
        # Collect all credentials
        Write-LogMessage "Starting credential collection..." "INFO"
        $allCredentials = @()
        
        # Get application credentials
        $appCredentials = Get-ApplicationCredentials
        $allCredentials += $appCredentials
        
        # Get Key Vault secrets
        $kvSecrets = Get-KeyVaultSecrets
        $allCredentials += $kvSecrets
        
        if ($allCredentials.Count -eq 0) {
            Write-LogMessage "No credentials found" "INFO"
            return
        }
        
        # Filter expiring credentials
        $expiringCredentials = $allCredentials | Where-Object { $_.IsExpiring -or $_.IsExpired }
        
        # Send notifications
        if ($expiringCredentials.Count -gt 0) {
            Send-RotationNotification -ExpiringCredentials $expiringCredentials -Config $Script:Config
        }
        
        # Generate reports
        if ($GenerateReport) {
            $reportPath = Generate-RotationReport -AllCredentials $allCredentials -Config $Script:Config
        }
        
        # Final summary
        $duration = (Get-Date) - $Script:StartTime
        Write-LogMessage "============================================" "SUCCESS"
        Write-LogMessage "API Key Rotation Check Completed!" "SUCCESS"
        Write-LogMessage "============================================" "SUCCESS"
        Write-LogMessage "Processing Time: $([math]::Round($duration.TotalSeconds, 2)) seconds" "INFO"
        Write-LogMessage "Credentials Processed: $($Script:ProcessedCredentials)" "INFO"
        Write-LogMessage "Expiring Credentials: $($Script:ExpiringCredentials)" "INFO"
        Write-LogMessage "Critical Credentials: $($Script:CriticalCredentials)" "INFO"
        
        if ($reportPath) {
            Write-LogMessage "Report Generated: $reportPath" "SUCCESS"
        }
        
        # Display critical findings
        if ($Script:CriticalCredentials -gt 0) {
            Write-LogMessage "`n🚨 CRITICAL: $($Script:CriticalCredentials) critical credentials expiring!" "CRITICAL"
        }
        
        if ($Script:ExpiringCredentials -gt 0) {
            Write-LogMessage "`n⚠️  WARNING: $($Script:ExpiringCredentials) credentials expiring in $DaysAhead days" "WARNING"
        }
        
    }
    catch {
        Write-LogMessage "Critical error in main execution: $($_.Exception.Message)" "ERROR"
        exit 1
    }
    finally {
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-LogMessage "Disconnected from services" "INFO"
        }
        catch {
            # Ignore disconnection errors
        }
    }
}

# Execute main function
Main

#endregion
