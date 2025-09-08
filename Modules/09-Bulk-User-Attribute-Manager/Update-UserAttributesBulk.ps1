<#
.SYNOPSIS
    Bulk update user attributes from CSV file for Active Directory and Entra ID
.DESCRIPTION
    Reads user data from CSV and performs bulk updates to user attributes.
    Supports both on-premises AD and cloud-based Entra ID operations.
.PARAMETER CsvPath
    Path to the CSV file containing user updates
.PARAMETER ConfigPath
    Path to the JSON configuration file
.PARAMETER WhatIf
    Show what would be changed without making actual changes
.PARAMETER TargetEnvironment
    Target environment: AD, EntraID, or Both
.PARAMETER LogLevel
    Logging level: INFO, WARNING, ERROR, DEBUG
.EXAMPLE
    .\Update-UserAttributesBulk.ps1 -CsvPath ".\UserUpdateTemplate.csv" -TargetEnvironment "Both"
.EXAMPLE
    .\Update-UserAttributesBulk.ps1 -CsvPath ".\users.csv" -TargetEnvironment "AD" -WhatIf
.NOTES
    Author: Identity Security Automation Project
    Version: 1.0
    Requires: PowerShell 5.1+, ActiveDirectory module, Microsoft.Graph modules
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to CSV file containing user updates")]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "CSV file not found: $_"
        }
        if (-not $_.EndsWith('.csv')) {
            throw "File must be a CSV file: $_"
        }
        return $true
    })]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false, HelpMessage = "Path to JSON configuration file")]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "Configuration file not found: $_"
        }
        return $true
    })]
    [string]$ConfigPath = ".\Update-UserAttributesBulk-Config.json",
    
    [Parameter(Mandatory = $false, HelpMessage = "Target environment for updates")]
    [ValidateSet("AD", "EntraID", "Both")]
    [string]$TargetEnvironment = "Both",
    
    [Parameter(Mandatory = $false, HelpMessage = "Logging level")]
    [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
    [string]$LogLevel = "INFO",
    
    [Parameter(Mandatory = $false, HelpMessage = "Preview changes without applying them")]
    [switch]$WhatIf
)

# Global variables
$script:Config = $null
$script:LogPath = $null
$script:StartTime = Get-Date

#region Helper Functions

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    # Check if we should log this level
    $levelPriority = @{
        "DEBUG" = 0
        "INFO" = 1
        "SUCCESS" = 1
        "WARNING" = 2
        "ERROR" = 3
    }
    
    if ($levelPriority[$Level] -lt $levelPriority[$LogLevel]) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file if path is set
    if ($script:LogPath) {
        Add-Content -Path $script:LogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    
    # Write to console with colors
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "DEBUG" { Write-Host $logEntry -ForegroundColor Cyan }
        default { Write-Host $logEntry }
    }
}

function Initialize-Logging {
    param([object]$Config)
    
    try {
        $logDir = $Config.LogPath
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-Log "Created log directory: $logDir" "DEBUG"
        }
        
        $script:LogPath = Join-Path $logDir "BulkUserUpdate_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Write-Log "Logging initialized. Log file: $script:LogPath" "INFO"
        return $true
    }
    catch {
        Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
        return $false
    }
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..." "INFO"
    
    $issues = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $issues += "PowerShell 5.1 or later is required"
    }
    
    # Check for required modules based on target environment
    if ($TargetEnvironment -in @("AD", "Both")) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Log "✅ ActiveDirectory module loaded" "SUCCESS"
        }
        catch {
            $issues += "ActiveDirectory PowerShell module is required for AD operations"
        }
    }
    
    if ($TargetEnvironment -in @("EntraID", "Both")) {
        $requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users")
        foreach ($module in $requiredModules) {
            try {
                Import-Module $module -ErrorAction Stop
                Write-Log "✅ $module module loaded" "SUCCESS"
            }
            catch {
                $issues += "$module PowerShell module is required for Entra ID operations"
            }
        }
    }
    
    if ($issues.Count -gt 0) {
        Write-Log "❌ Prerequisites check failed:" "ERROR"
        foreach ($issue in $issues) {
            Write-Log "  - $issue" "ERROR"
        }
        return $false
    }
    
    Write-Log "✅ All prerequisites met" "SUCCESS"
    return $true
}

function Test-UserData {
    param(
        [Parameter(Mandatory = $true)]
        [object]$UserData,
        
        [Parameter(Mandatory = $true)]
        [object]$Config
    )
    
    $errors = @()
    
    # Check required fields
    foreach ($field in $Config.RequiredFields) {
        if (-not $UserData.$field -or $UserData.$field.Trim() -eq "") {
            $errors += "Missing required field: $field"
        }
    }
    
    # Validate supported actions
    if ($UserData.Action -and $UserData.Action -notin $Config.SupportedActions) {
        $errors += "Unsupported action: $($UserData.Action). Supported: $($Config.SupportedActions -join ', ')"
    }
    
    # Validate data format using regex rules
    foreach ($field in $Config.ValidationRules.PSObject.Properties.Name) {
        if ($UserData.$field -and $UserData.$field -notmatch $Config.ValidationRules.$field) {
            $errors += "Invalid format for $field`: $($UserData.$field)"
        }
    }
    
    return $errors
}

function Connect-ToServices {
    Write-Log "Connecting to required services..." "INFO"
    
    if ($TargetEnvironment -in @("EntraID", "Both")) {
        try {
            # Connect to Microsoft Graph with required scopes
            $scopes = @("User.ReadWrite.All", "Directory.ReadWrite.All")
            Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
            Write-Log "✅ Connected to Microsoft Graph" "SUCCESS"
        }
        catch {
            Write-Log "❌ Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    
    if ($TargetEnvironment -in @("AD", "Both")) {
        try {
            # Test AD connectivity
            $domain = Get-ADDomain -ErrorAction Stop
            Write-Log "✅ Connected to Active Directory domain: $($domain.DNSRoot)" "SUCCESS"
        }
        catch {
            Write-Log "❌ Failed to connect to Active Directory: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    
    return $true
}

function Update-ADUserAttributes {
    param(
        [Parameter(Mandatory = $true)]
        [object]$UserData,
        
        [Parameter(Mandatory = $true)]
        [object]$Config
    )
    
    try {
        Write-Log "Processing AD user: $($UserData.UserPrincipalName)" "DEBUG"
        
        # Find the user
        $user = Get-ADUser -Filter "UserPrincipalName -eq '$($UserData.UserPrincipalName)'" -Properties * -ErrorAction Stop
        
        if (-not $user) {
            if ($UserData.Action -eq "CREATE") {
                Write-Log "User not found, CREATE action not implemented in this version" "WARNING"
                return $false
            }
            else {
                Write-Log "❌ User not found in AD: $($UserData.UserPrincipalName)" "ERROR"
                return $false
            }
        }
        
        # Build update parameters
        $updateParams = @{}
        foreach ($csvField in $Config.AttributeMapping.PSObject.Properties.Name) {
            $adField = $Config.AttributeMapping.$csvField
            if ($UserData.$csvField -and $UserData.$csvField.Trim() -ne "") {
                $updateParams[$adField] = $UserData.$csvField.Trim()
            }
        }
        
        # Handle manager separately (requires DN)
        if ($UserData.Manager -and $UserData.Manager.Trim() -ne "") {
            try {
                $manager = Get-ADUser -Filter "UserPrincipalName -eq '$($UserData.Manager)'" -ErrorAction Stop
                $updateParams["Manager"] = $manager.DistinguishedName
            }
            catch {
                Write-Log "⚠️ Manager not found: $($UserData.Manager)" "WARNING"
            }
        }
        
        if ($updateParams.Count -gt 0) {
            if ($WhatIf) {
                Write-Log "WHATIF: Would update AD user $($UserData.UserPrincipalName) with: $($updateParams.Keys -join ', ')" "INFO"
            }
            else {
                Set-ADUser -Identity $user.DistinguishedName @updateParams -ErrorAction Stop
                Write-Log "✅ Updated AD user: $($UserData.UserPrincipalName)" "SUCCESS"
            }
        }
        else {
            Write-Log "No AD attributes to update for: $($UserData.UserPrincipalName)" "DEBUG"
        }
        
        return $true
    }
    catch {
        Write-Log "❌ Failed to update AD user $($UserData.UserPrincipalName): $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Update-EntraIDUserAttributes {
    param(
        [Parameter(Mandatory = $true)]
        [object]$UserData,
        
        [Parameter(Mandatory = $true)]
        [object]$Config
    )
    
    try {
        Write-Log "Processing Entra ID user: $($UserData.UserPrincipalName)" "DEBUG"
        
        # Find the user
        $user = Get-MgUser -Filter "userPrincipalName eq '$($UserData.UserPrincipalName)'" -ErrorAction Stop
        
        if (-not $user) {
            if ($UserData.Action -eq "CREATE") {
                Write-Log "User not found, CREATE action not implemented in this version" "WARNING"
                return $false
            }
            else {
                Write-Log "❌ User not found in Entra ID: $($UserData.UserPrincipalName)" "ERROR"
                return $false
            }
        }
        
        # Build update parameters using Entra ID attribute mapping
        $updateParams = @{}
        foreach ($csvField in $Config.EntraIdAttributeMapping.PSObject.Properties.Name) {
            $entraField = $Config.EntraIdAttributeMapping.$csvField
            if ($UserData.$csvField -and $UserData.$csvField.Trim() -ne "") {
                if ($csvField -eq "PhoneNumber") {
                    # Handle phone numbers as array
                    $updateParams[$entraField] = @($UserData.$csvField.Trim())
                }
                else {
                    $updateParams[$entraField] = $UserData.$csvField.Trim()
                }
            }
        }
        
        # Handle manager separately
        if ($UserData.Manager -and $UserData.Manager.Trim() -ne "") {
            try {
                $manager = Get-MgUser -Filter "userPrincipalName eq '$($UserData.Manager)'" -ErrorAction Stop
                $updateParams["manager@odata.bind"] = "https://graph.microsoft.com/v1.0/users/$($manager.Id)"
            }
            catch {
                Write-Log "⚠️ Manager not found in Entra ID: $($UserData.Manager)" "WARNING"
            }
        }
        
        if ($updateParams.Count -gt 0) {
            if ($WhatIf) {
                Write-Log "WHATIF: Would update Entra ID user $($UserData.UserPrincipalName) with: $($updateParams.Keys -join ', ')" "INFO"
            }
            else {
                Update-MgUser -UserId $user.Id -BodyParameter $updateParams -ErrorAction Stop
                Write-Log "✅ Updated Entra ID user: $($UserData.UserPrincipalName)" "SUCCESS"
            }
        }
        else {
            Write-Log "No Entra ID attributes to update for: $($UserData.UserPrincipalName)" "DEBUG"
        }
        
        return $true
    }
    catch {
        Write-Log "❌ Failed to update Entra ID user $($UserData.UserPrincipalName): $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Disconnect-FromServices {
    Write-Log "Disconnecting from services..." "INFO"
    
    if ($TargetEnvironment -in @("EntraID", "Both")) {
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-Log "🔌 Disconnected from Microsoft Graph" "INFO"
        }
        catch {
            Write-Log "Warning: Could not cleanly disconnect from Microsoft Graph" "WARNING"
        }
    }
}

function Show-Summary {
    param(
        [int]$TotalUsers,
        [int]$SuccessCount,
        [int]$ErrorCount,
        [datetime]$StartTime
    )
    
    $duration = (Get-Date) - $StartTime
    
    Write-Log "" "INFO"
    Write-Log "═══════════════════════════════════════" "INFO"
    Write-Log "           BULK UPDATE SUMMARY          " "INFO"
    Write-Log "═══════════════════════════════════════" "INFO"
    Write-Log "📊 Total users processed: $TotalUsers" "INFO"
    Write-Log "✅ Successful updates: $SuccessCount" "SUCCESS"
    Write-Log "❌ Failed updates: $ErrorCount" "ERROR"
    Write-Log "⏱️ Total duration: $($duration.ToString('hh\:mm\:ss'))" "INFO"
    Write-Log "📄 Log file: $script:LogPath" "INFO"
    Write-Log "═══════════════════════════════════════" "INFO"
}

#endregion

#region Main Execution

try {
    Write-Log "🚀 Starting Identity Security Automation - Bulk User Update" "INFO"
    Write-Log "📁 CSV File: $CsvPath" "INFO"
    Write-Log "⚙️ Config File: $ConfigPath" "INFO"
    Write-Log "🎯 Target Environment: $TargetEnvironment" "INFO"
    Write-Log "🔍 WhatIf Mode: $WhatIf" "INFO"
    Write-Log "📝 Log Level: $LogLevel" "INFO"
    
    # Load configuration
    try {
        $script:Config = Get-Content $ConfigPath | ConvertFrom-Json
        Write-Log "✅ Configuration loaded successfully" "SUCCESS"
    }
    catch {
        Write-Log "❌ Failed to load configuration: $($_.Exception.Message)" "ERROR"
        exit 1
    }
    
    # Initialize logging
    if (-not (Initialize-Logging -Config $script:Config)) {
        Write-Warning "Continuing without file logging..."
    }
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-Log "❌ Prerequisites check failed. Exiting." "ERROR"
        exit 1
    }
    
    # Read and validate CSV data
    try {
        $userData = Import-Csv $CsvPath
        Write-Log "📊 Loaded $($userData.Count) user records from CSV" "INFO"
        
        if ($userData.Count -eq 0) {
            Write-Log "❌ No user data found in CSV file" "ERROR"
            exit 1
        }
    }
    catch {
        Write-Log "❌ Failed to read CSV file: $($_.Exception.Message)" "ERROR"
        exit 1
    }
    
    # Connect to services
    if (-not (Connect-ToServices)) {
        Write-Log "❌ Failed to connect to required services. Exiting." "ERROR"
        exit 1
    }
    
    # Process users in batches
    $successCount = 0
    $errorCount = 0
    $batchCount = 0
    $totalUsers = $userData.Count
    
    Write-Log "📦 Processing users in batches of $($script:Config.BatchSize)..." "INFO"
    
    for ($i = 0; $i -lt $userData.Count; $i += $script:Config.BatchSize) {
        $batchCount++
        $batchEnd = [Math]::Min($i + $script:Config.BatchSize - 1, $userData.Count - 1)
        $batch = $userData[$i..$batchEnd]
        
        Write-Log "📦 Processing batch $batchCount (Users $($i + 1)-$($batchEnd + 1) of $totalUsers)" "INFO"
        
        foreach ($user in $batch) {
            Write-Log "👤 Processing user: $($user.UserPrincipalName)" "DEBUG"
            
            # Validate user data
            $validationErrors = Test-UserData -UserData $user -Config $script:Config
            if ($validationErrors.Count -gt 0) {
                Write-Log "❌ Validation failed for $($user.UserPrincipalName):" "ERROR"
                foreach ($error in $validationErrors) {
                    Write-Log "  - $error" "ERROR"
                }
                $errorCount++
                continue
            }
            
            $userSuccess = $true
            
            # Update AD if required
            if ($TargetEnvironment -in @("AD", "Both")) {
                $userSuccess = $userSuccess -and (Update-ADUserAttributes -UserData $user -Config $script:Config)
            }
            
            # Update Entra ID if required
            if ($TargetEnvironment -in @("EntraID", "Both")) {
                $userSuccess = $userSuccess -and (Update-EntraIDUserAttributes -UserData $user -Config $script:Config)
            }
            
            if ($userSuccess) {
                $successCount++
            }
            else {
                $errorCount++
            }
        }
        
        # Throttle between batches
        if ($i + $script:Config.BatchSize -lt $userData.Count) {
            Write-Log "⏳ Waiting $($script:Config.ThrottleDelay)ms before next batch..." "DEBUG"
            Start-Sleep -Milliseconds $script:Config.ThrottleDelay
        }
    }
    
    # Show summary
    Show-Summary -TotalUsers $totalUsers -SuccessCount $successCount -ErrorCount $errorCount -StartTime $script:StartTime
    
    # Set exit code based on results
    if ($errorCount -gt 0) {
        exit 1
    }
    else {
        exit 0
    }
}
catch {
    Write-Log "❌ Unexpected error: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
    exit 1
}
finally {
    # Always disconnect from services
    Disconnect-FromServices
}

#endregion
