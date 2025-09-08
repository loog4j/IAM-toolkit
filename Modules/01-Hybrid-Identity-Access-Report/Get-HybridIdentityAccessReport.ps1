<#
.SYNOPSIS
    Generate comprehensive identity and access report across Active Directory and Entra ID
.DESCRIPTION
    Provides a unified 360-degree view of a user's identity, attributes, group memberships 
    (including nested), role assignments, and effective permissions across both on-premises 
    Active Directory and Entra ID environments.
.PARAMETER UserIdentifier
    User identifier (UPN, sAMAccountName, or employeeId)
.PARAMETER ConfigPath
    Path to the JSON configuration file
.PARAMETER OutputFormat
    Output format for the report: JSON, CSV, HTML, or All
.PARAMETER IncludeNestedGroups
    Include nested group membership analysis (default: true)
.PARAMETER LogLevel
    Logging level: INFO, WARNING, ERROR, DEBUG
.EXAMPLE
    .\Get-HybridIdentityAccessReport.ps1 -UserIdentifier "john.doe@contoso.com"
.EXAMPLE
    .\Get-HybridIdentityAccessReport.ps1 -UserIdentifier "jdoe" -OutputFormat "HTML"
.NOTES
    Author: Identity Security Automation Project
    Version: 1.0
    Requires: PowerShell 5.1+, ActiveDirectory module, Microsoft.Graph modules
    Permissions: User.Read.All, Group.Read.All, Directory.Read.All, RoleManagement.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "User identifier (UPN, sAMAccountName, or employeeId)")]
    [ValidateNotNullOrEmpty()]
    [string]$UserIdentifier,
    
    [Parameter(Mandatory = $false, HelpMessage = "Path to JSON configuration file")]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "Configuration file not found: $_"
        }
        return $true
    })]
    [string]$ConfigPath = ".\Hybrid-Identity-Config.json",
    
    [Parameter(Mandatory = $false, HelpMessage = "Output format for reports")]
    [ValidateSet("JSON", "CSV", "HTML", "All")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory = $false, HelpMessage = "Include nested group membership analysis")]
    [switch]$IncludeNestedGroups = $true,
    
    [Parameter(Mandatory = $false, HelpMessage = "Logging level")]
    [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
    [string]$LogLevel = "INFO"
)

# Global variables
$script:Config = $null
$script:LogPath = $null
$script:StartTime = Get-Date
$script:IdentityData = @{}
$script:AnalysisResults = @{}

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
        $logDir = $Config.OutputPath
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-Log "Created log directory: $logDir" "DEBUG"
        }
        
        $script:LogPath = Join-Path $logDir "HybridIdentityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
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
    
    # Check for Active Directory module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "✅ ActiveDirectory module loaded" "SUCCESS"
    }
    catch {
        $issues += "ActiveDirectory PowerShell module is required for AD operations"
    }
    
    # Check for Microsoft Graph modules
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )
    
    foreach ($module in $requiredModules) {
        try {
            Import-Module $module -ErrorAction Stop
            Write-Log "✅ $module module loaded" "SUCCESS"
        }
        catch {
            $issues += "$module PowerShell module is required"
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

function Connect-ToServices {
    Write-Log "Connecting to required services..." "INFO"
    
    # Connect to Microsoft Graph
    try {
        $scopes = @(
            "User.Read.All",
            "Group.Read.All", 
            "Directory.Read.All",
            "RoleManagement.Read.All",
            "Application.Read.All"
        )
        
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        Write-Log "✅ Connected to Microsoft Graph" "SUCCESS"
    }
    catch {
        Write-Log "❌ Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    # Test Active Directory connectivity
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Log "✅ Connected to Active Directory domain: $($domain.DNSRoot)" "SUCCESS"
    }
    catch {
        Write-Log "❌ Failed to connect to Active Directory: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    return $true
}

function Find-HybridUserIdentity {
    param([string]$UserIdentifier)
    
    Write-Log "🔍 Searching for user identity: $UserIdentifier" "INFO"
    
    $identityResult = @{
        ActiveDirectoryUser = $null
        EntraIDUser = $null
        CorrelationStatus = "NotFound"
        CorrelationConfidence = 0
        ConflictsDetected = @()
    }
    
    # Search Active Directory
    try {
        # Try different search methods
        $adUser = $null
        
        # Try UPN first
        if ($UserIdentifier -like "*@*") {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$UserIdentifier'" -Properties * -ErrorAction SilentlyContinue
        }
        
        # Try sAMAccountName if UPN failed
        if (-not $adUser) {
            $adUser = Get-ADUser -Filter "sAMAccountName -eq '$UserIdentifier'" -Properties * -ErrorAction SilentlyContinue
        }
        
        # Try employeeId if others failed
        if (-not $adUser) {
            $adUser = Get-ADUser -Filter "employeeId -eq '$UserIdentifier'" -Properties * -ErrorAction SilentlyContinue
        }
        
        if ($adUser) {
            $identityResult.ActiveDirectoryUser = $adUser
            Write-Log "✅ Found user in Active Directory: $($adUser.UserPrincipalName)" "SUCCESS"
        }
        else {
            Write-Log "⚠️ User not found in Active Directory" "WARNING"
        }
    }
    catch {
        Write-Log "❌ Error searching Active Directory: $($_.Exception.Message)" "ERROR"
    }
    
    # Search Entra ID
    try {
        $entraUser = $null
        
        # Try UPN first
        if ($UserIdentifier -like "*@*") {
            $entraUser = Get-MgUser -Filter "userPrincipalName eq '$UserIdentifier'" -ErrorAction SilentlyContinue
        }
        
        # Try mail if UPN failed
        if (-not $entraUser) {
            $entraUser = Get-MgUser -Filter "mail eq '$UserIdentifier'" -ErrorAction SilentlyContinue
        }
        
        # Try employeeId if others failed
        if (-not $entraUser) {
            $entraUser = Get-MgUser -Filter "employeeId eq '$UserIdentifier'" -ErrorAction SilentlyContinue
        }
        
        if ($entraUser) {
            $identityResult.EntraIDUser = $entraUser
            Write-Log "✅ Found user in Entra ID: $($entraUser.UserPrincipalName)" "SUCCESS"
        }
        else {
            Write-Log "⚠️ User not found in Entra ID" "WARNING"
        }
    }
    catch {
        Write-Log "❌ Error searching Entra ID: $($_.Exception.Message)" "ERROR"
    }
    
    # Validate correlation
    if ($identityResult.ActiveDirectoryUser -and $identityResult.EntraIDUser) {
        $adUpn = $identityResult.ActiveDirectoryUser.UserPrincipalName
        $entraUpn = $identityResult.EntraIDUser.UserPrincipalName
        
        if ($adUpn -eq $entraUpn) {
            $identityResult.CorrelationStatus = "Matched"
            $identityResult.CorrelationConfidence = 100
            Write-Log "✅ Identity correlation successful" "SUCCESS"
        }
        else {
            $identityResult.CorrelationStatus = "Conflict"
            $identityResult.CorrelationConfidence = 50
            $identityResult.ConflictsDetected += "UPN mismatch: AD=$adUpn, Entra=$entraUpn"
            Write-Log "⚠️ Identity correlation conflict detected" "WARNING"
        }
    }
    elseif ($identityResult.ActiveDirectoryUser -or $identityResult.EntraIDUser) {
        $identityResult.CorrelationStatus = "Partial"
        $identityResult.CorrelationConfidence = 75
        Write-Log "⚠️ User found in only one system" "WARNING"
    }
    
    return $identityResult
}

function Get-NestedGroupMembership {
    param(
        [Microsoft.ActiveDirectory.Management.ADUser]$User,
        [int]$MaxDepth = 10
    )
    
    Write-Log "🔍 Analyzing nested group memberships for: $($User.UserPrincipalName)" "DEBUG"
    
    $allGroups = @()
    $processedGroups = @()
    
    function Get-GroupsRecursive {
        param($Groups, $CurrentDepth)
        
        if ($CurrentDepth -gt $MaxDepth) { 
            Write-Log "⚠️ Maximum nesting depth reached: $MaxDepth" "WARNING"
            return 
        }
        
        foreach ($group in $Groups) {
            if ($group.DistinguishedName -in $processedGroups) { continue }
            
            $processedGroups += $group.DistinguishedName
            $groupInfo = @{
                Group = $group
                Depth = $CurrentDepth
                MembershipType = if ($CurrentDepth -eq 0) { "Direct" } else { "Nested" }
                IsPrivileged = $group.Name -in $script:Config.PrivilegedGroups.ActiveDirectory
            }
            
            $script:allGroups += $groupInfo
            
            # Get parent groups
            try {
                $parentGroups = Get-ADGroup -Filter "member -eq '$($group.DistinguishedName)'" -ErrorAction SilentlyContinue
                if ($parentGroups) {
                    Get-GroupsRecursive -Groups $parentGroups -CurrentDepth ($CurrentDepth + 1)
                }
            }
            catch {
                Write-Log "⚠️ Error getting parent groups for $($group.Name): $($_.Exception.Message)" "WARNING"
            }
        }
    }
    
    # Start with direct group memberships
    try {
        $directGroups = Get-ADGroup -Filter "member -eq '$($User.DistinguishedName)'" -ErrorAction Stop
        Get-GroupsRecursive -Groups $directGroups -CurrentDepth 0
        
        Write-Log "📊 Found $($script:allGroups.Count) total group memberships ($($directGroups.Count) direct)" "INFO"
    }
    catch {
        Write-Log "❌ Error getting group memberships: $($_.Exception.Message)" "ERROR"
    }
    
    return $script:allGroups
}

function Get-EntraIDUserAnalysis {
    param([object]$EntraUser)
    
    Write-Log "🔍 Analyzing Entra ID user: $($EntraUser.UserPrincipalName)" "DEBUG"
    
    $analysis = @{
        User = $EntraUser
        GroupMemberships = @()
        AdministrativeRoles = @()
        ApplicationRoles = @()
        RiskScore = 0
    }
    
    # Get group memberships
    try {
        $groups = Get-MgUserMemberOf -UserId $EntraUser.Id -ErrorAction Stop
        foreach ($group in $groups) {
            if ($group.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') {
                $groupInfo = @{
                    Id = $group.Id
                    DisplayName = $group.AdditionalProperties.displayName
                    IsPrivileged = $group.AdditionalProperties.displayName -in $script:Config.PrivilegedGroups.EntraID
                }
                $analysis.GroupMemberships += $groupInfo
                
                if ($groupInfo.IsPrivileged) {
                    $analysis.RiskScore += 5
                }
            }
        }
        Write-Log "📊 Found $($analysis.GroupMemberships.Count) Entra ID group memberships" "INFO"
    }
    catch {
        Write-Log "❌ Error getting Entra ID group memberships: $($_.Exception.Message)" "ERROR"
    }
    
    # Get administrative roles
    try {
        $roleAssignments = Get-MgUserAppRoleAssignment -UserId $EntraUser.Id -ErrorAction Stop
        foreach ($assignment in $roleAssignments) {
            $roleInfo = @{
                Id = $assignment.Id
                ResourceDisplayName = $assignment.ResourceDisplayName
                AppRoleDisplayName = $assignment.AppRoleDisplayName
                IsPrivileged = $assignment.AppRoleDisplayName -in $script:Config.PrivilegedGroups.EntraID
            }
            $analysis.ApplicationRoles += $roleInfo
            
            if ($roleInfo.IsPrivileged) {
                $analysis.RiskScore += 10
            }
        }
        Write-Log "📊 Found $($analysis.ApplicationRoles.Count) application role assignments" "INFO"
    }
    catch {
        Write-Log "❌ Error getting application roles: $($_.Exception.Message)" "ERROR"
    }
    
    return $analysis
}

function Calculate-RiskScore {
    param(
        [array]$ADGroups,
        [object]$EntraAnalysis
    )
    
    $riskScore = 0
    $riskFactors = @()
    
    # Analyze AD group risks
    foreach ($groupInfo in $ADGroups) {
        if ($groupInfo.IsPrivileged) {
            $riskScore += 10
            $riskFactors += "Privileged AD group: $($groupInfo.Group.Name)"
        }
    }
    
    # Add Entra ID risk score
    $riskScore += $EntraAnalysis.RiskScore
    
    # Determine risk level
    $riskLevel = switch ($riskScore) {
        { $_ -ge 25 } { "Critical" }
        { $_ -ge 15 } { "High" }
        { $_ -ge 8 } { "Medium" }
        default { "Low" }
    }
    
    return @{
        Score = $riskScore
        Level = $riskLevel
        Factors = $riskFactors
    }
}

function Export-IdentityReport {
    param(
        [string]$Format,
        [string]$OutputPath,
        [object]$IdentityData,
        [object]$AnalysisResults
    )
    
    Write-Log "📄 Exporting identity report in $Format format..." "INFO"
    
    try {
        switch ($Format.ToUpper()) {
            "JSON" {
                $jsonPath = Join-Path $OutputPath "IdentityReport_$($IdentityData.UserIdentifier)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $reportData = @{
                    ReportMetadata = @{
                        GeneratedDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
                        ReportVersion = "1.0"
                        UserIdentifier = $IdentityData.UserIdentifier
                    }
                    IdentityCorrelation = $IdentityData.IdentityCorrelation
                    ActiveDirectoryAnalysis = $AnalysisResults.ActiveDirectory
                    EntraIDAnalysis = $AnalysisResults.EntraID
                    RiskAssessment = $AnalysisResults.RiskAssessment
                }
                
                $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
                Write-Log "✅ JSON report saved: $jsonPath" "SUCCESS"
            }
            
            "CSV" {
                $csvPath = Join-Path $OutputPath "IdentityReport_$($IdentityData.UserIdentifier)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                
                # Create flattened data for CSV
                $csvData = @()
                
                # Add AD group memberships
                foreach ($groupInfo in $AnalysisResults.ActiveDirectory.GroupMemberships) {
                    $csvData += [PSCustomObject]@{
                        Source = "ActiveDirectory"
                        Type = "Group"
                        Name = $groupInfo.Group.Name
                        MembershipType = $groupInfo.MembershipType
                        IsPrivileged = $groupInfo.IsPrivileged
                        Depth = $groupInfo.Depth
                    }
                }
                
                # Add Entra ID group memberships
                foreach ($group in $AnalysisResults.EntraID.GroupMemberships) {
                    $csvData += [PSCustomObject]@{
                        Source = "EntraID"
                        Type = "Group"
                        Name = $group.DisplayName
                        MembershipType = "Direct"
                        IsPrivileged = $group.IsPrivileged
                        Depth = 0
                    }
                }
                
                $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Log "✅ CSV report saved: $csvPath" "SUCCESS"
            }
            
            "HTML" {
                $htmlPath = Join-Path $OutputPath "IdentityReport_$($IdentityData.UserIdentifier)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                Generate-HTMLReport -OutputPath $htmlPath -IdentityData $IdentityData -AnalysisResults $AnalysisResults
                Write-Log "✅ HTML report saved: $htmlPath" "SUCCESS"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "❌ Failed to export $Format report: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Generate-HTMLReport {
    param(
        [string]$OutputPath,
        [object]$IdentityData,
        [object]$AnalysisResults
    )
    
    $riskLevel = $AnalysisResults.RiskAssessment.Level
    $riskClass = switch ($riskLevel) {
        "Critical" { "risk-critical" }
        "High" { "risk-high" }
        "Medium" { "risk-medium" }
        default { "risk-low" }
    }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Hybrid Identity Access Report - $($IdentityData.UserIdentifier)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .section { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .risk-critical { background-color: #ff4444; color: white; }
        .risk-high { background-color: #ff8800; color: white; }
        .risk-medium { background-color: #ffaa00; }
        .risk-low { background-color: #88cc88; }
        .privileged { font-weight: bold; color: #cc0000; }
        .nested { font-style: italic; color: #666; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Hybrid Identity Access Report</h1>
        <p>User: $($IdentityData.UserIdentifier)</p>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <div class="$riskClass" style="padding: 10px; border-radius: 5px; margin: 10px 0;">
            <strong>Overall Risk Level: $($AnalysisResults.RiskAssessment.Level)</strong><br>
            Risk Score: $($AnalysisResults.RiskAssessment.Score)
        </div>
        <p><strong>Identity Correlation:</strong> $($IdentityData.IdentityCorrelation.CorrelationStatus)</p>
        <p><strong>Confidence:</strong> $($IdentityData.IdentityCorrelation.CorrelationConfidence)%</p>
    </div>
    
    <div class="section">
        <h2>🏢 Active Directory Analysis</h2>
"@
    
    if ($IdentityData.IdentityCorrelation.ActiveDirectoryUser) {
        $adUser = $IdentityData.IdentityCorrelation.ActiveDirectoryUser
        $html += @"
        <p><strong>User Principal Name:</strong> $($adUser.UserPrincipalName)</p>
        <p><strong>Display Name:</strong> $($adUser.DisplayName)</p>
        <p><strong>Department:</strong> $($adUser.Department)</p>
        <p><strong>Title:</strong> $($adUser.Title)</p>
        <p><strong>Last Logon:</strong> $($adUser.LastLogonDate)</p>
        
        <h3>Group Memberships</h3>
        <table>
            <tr><th>Group Name</th><th>Type</th><th>Depth</th><th>Privileged</th></tr>
"@
        
        foreach ($groupInfo in $AnalysisResults.ActiveDirectory.GroupMemberships) {
            $privilegedClass = if ($groupInfo.IsPrivileged) { "privileged" } else { "" }
            $nestedClass = if ($groupInfo.MembershipType -eq "Nested") { "nested" } else { "" }
            
            $html += @"
            <tr class="$privilegedClass $nestedClass">
                <td>$($groupInfo.Group.Name)</td>
                <td>$($groupInfo.MembershipType)</td>
                <td>$($groupInfo.Depth)</td>
                <td>$($groupInfo.IsPrivileged)</td>
            </tr>
"@
        }
        
        $html += "</table>"
    }
    else {
        $html += "<p><em>User not found in Active Directory</em></p>"
    }
    
    $html += @"
    </div>
    
    <div class="section">
        <h2>☁️ Entra ID Analysis</h2>
"@
    
    if ($IdentityData.IdentityCorrelation.EntraIDUser) {
        $entraUser = $IdentityData.IdentityCorrelation.EntraIDUser
        $html += @"
        <p><strong>User Principal Name:</strong> $($entraUser.UserPrincipalName)</p>
        <p><strong>Display Name:</strong> $($entraUser.DisplayName)</p>
        <p><strong>Department:</strong> $($entraUser.Department)</p>
        <p><strong>Job Title:</strong> $($entraUser.JobTitle)</p>
        <p><strong>Last Sign In:</strong> $($entraUser.SignInActivity.LastSignInDateTime)</p>
        
        <h3>Group Memberships</h3>
        <ul>
"@
        
        foreach ($group in $AnalysisResults.EntraID.GroupMemberships) {
            $privilegedClass = if ($group.IsPrivileged) { "privileged" } else { "" }
            $html += "<li class='$privilegedClass'>$($group.DisplayName)</li>"
        }
        
        $html += @"
        </ul>
        
        <h3>Application Roles</h3>
        <ul>
"@
        
        foreach ($role in $AnalysisResults.EntraID.ApplicationRoles) {
            $privilegedClass = if ($role.IsPrivileged) { "privileged" } else { "" }
            $html += "<li class='$privilegedClass'>$($role.ResourceDisplayName) - $($role.AppRoleDisplayName)</li>"
        }
        
        $html += "</ul>"
    }
    else {
        $html += "<p><em>User not found in Entra ID</em></p>"
    }
    
    $html += @"
    </div>
    
    <div class="section">
        <h2>⚠️ Risk Factors</h2>
        <ul>
"@
    
    foreach ($factor in $AnalysisResults.RiskAssessment.Factors) {
        $html += "<li>$factor</li>"
    }
    
    $html += @"
        </ul>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

function Show-Summary {
    param(
        [object]$IdentityData,
        [object]$AnalysisResults,
        [datetime]$StartTime
    )
    
    $duration = (Get-Date) - $StartTime
    
    Write-Log "" "INFO"
    Write-Log "═══════════════════════════════════════" "INFO"
    Write-Log "      HYBRID IDENTITY REPORT SUMMARY    " "INFO"
    Write-Log "═══════════════════════════════════════" "INFO"
    Write-Log "👤 User: $($IdentityData.UserIdentifier)" "INFO"
    Write-Log "🔗 Correlation: $($IdentityData.IdentityCorrelation.CorrelationStatus)" "INFO"
    Write-Log "📊 Risk Level: $($AnalysisResults.RiskAssessment.Level)" "INFO"
    Write-Log "🏢 AD Groups: $($AnalysisResults.ActiveDirectory.GroupMemberships.Count)" "INFO"
    Write-Log "☁️ Entra Groups: $($AnalysisResults.EntraID.GroupMemberships.Count)" "INFO"
    Write-Log "⏱️ Duration: $($duration.ToString('hh\:mm\:ss'))" "INFO"
    Write-Log "📄 Log file: $script:LogPath" "INFO"
    Write-Log "═══════════════════════════════════════" "INFO"
}

#endregion

#region Main Execution

try {
    Write-Log "🚀 Starting Hybrid Identity Access Report" "INFO"
    Write-Log "👤 User Identifier: $UserIdentifier" "INFO"
    Write-Log "⚙️ Config File: $ConfigPath" "INFO"
    Write-Log "📊 Output Format: $OutputFormat" "INFO"
    Write-Log "📝 Log Level: $LogLevel" "INFO"
    
    # Load configuration
    try {
        if (Test-Path $ConfigPath) {
            $script:Config = Get-Content $ConfigPath | ConvertFrom-Json
            Write-Log "✅ Configuration loaded successfully" "SUCCESS"
        }
        else {
            # Use default configuration
            $script:Config = @{
                OutputPath = "./IdentityReports"
                PrivilegedGroups = @{
                    ActiveDirectory = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
                    EntraID = @("Global Administrator", "Privileged Role Administrator", "Security Administrator")
                }
            }
            Write-Log "⚠️ Using default configuration" "WARNING"
        }
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
    
    # Connect to services
    if (-not (Connect-ToServices)) {
        Write-Log "❌ Failed to connect to required services. Exiting." "ERROR"
        exit 1
    }
    
    # Find user identity across systems
    $script:IdentityData.UserIdentifier = $UserIdentifier
    $script:IdentityData.IdentityCorrelation = Find-HybridUserIdentity -UserIdentifier $UserIdentifier
    
    if ($script:IdentityData.IdentityCorrelation.CorrelationStatus -eq "NotFound") {
        Write-Log "❌ User not found in either Active Directory or Entra ID. Exiting." "ERROR"
        exit 1
    }
    
    # Analyze Active Directory
    $script:AnalysisResults.ActiveDirectory = @{
        GroupMemberships = @()
        RiskScore = 0
    }
    
    if ($script:IdentityData.IdentityCorrelation.ActiveDirectoryUser) {
        Write-Log "🔍 Analyzing Active Directory access..." "INFO"
        
        if ($IncludeNestedGroups) {
            $script:AnalysisResults.ActiveDirectory.GroupMemberships = Get-NestedGroupMembership -User $script:IdentityData.IdentityCorrelation.ActiveDirectoryUser -MaxDepth $script:Config.AnalysisScope.MaxNestingDepth
        }
        else {
            # Get only direct group memberships
            try {
                $directGroups = Get-ADGroup -Filter "member -eq '$($script:IdentityData.IdentityCorrelation.ActiveDirectoryUser.DistinguishedName)'" -ErrorAction Stop
                foreach ($group in $directGroups) {
                    $script:AnalysisResults.ActiveDirectory.GroupMemberships += @{
                        Group = $group
                        Depth = 0
                        MembershipType = "Direct"
                        IsPrivileged = $group.Name -in $script:Config.PrivilegedGroups.ActiveDirectory
                    }
                }
            }
            catch {
                Write-Log "❌ Error getting direct group memberships: $($_.Exception.Message)" "ERROR"
            }
        }
    }
    
    # Analyze Entra ID
    $script:AnalysisResults.EntraID = @{
        GroupMemberships = @()
        ApplicationRoles = @()
        RiskScore = 0
    }
    
    if ($script:IdentityData.IdentityCorrelation.EntraIDUser) {
        Write-Log "🔍 Analyzing Entra ID access..." "INFO"
        $script:AnalysisResults.EntraID = Get-EntraIDUserAnalysis -EntraUser $script:IdentityData.IdentityCorrelation.EntraIDUser
    }
    
    # Calculate overall risk assessment
    $script:AnalysisResults.RiskAssessment = Calculate-RiskScore -ADGroups $script:AnalysisResults.ActiveDirectory.GroupMemberships -EntraAnalysis $script:AnalysisResults.EntraID
    
    # Create output directory
    $outputDir = $script:Config.OutputPath
    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        Write-Log "Created output directory: $outputDir" "DEBUG"
    }
    
    # Export reports based on format selection
    if ($OutputFormat -eq "All") {
        foreach ($format in @("JSON", "CSV", "HTML")) {
            Export-IdentityReport -Format $format -OutputPath $outputDir -IdentityData $script:IdentityData -AnalysisResults $script:AnalysisResults
        }
    }
    else {
        Export-IdentityReport -Format $OutputFormat -OutputPath $outputDir -IdentityData $script:IdentityData -AnalysisResults $script:AnalysisResults
    }
    
    # Show summary
    Show-Summary -IdentityData $script:IdentityData -AnalysisResults $script:AnalysisResults -StartTime $script:StartTime
    
    # Set exit code based on risk level
    if ($script:AnalysisResults.RiskAssessment.Level -in @("Critical", "High")) {
        Write-Log "⚠️ Analysis completed with high risk findings" "WARNING"
        exit 1
    }
    else {
        Write-Log "✅ Analysis completed successfully" "SUCCESS"
        exit 0
    }
}
catch {
    Write-Log "❌ Unexpected error: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
    exit 1
}
finally {
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Log "🔌 Disconnected from Microsoft Graph" "INFO"
    }
    catch {
        Write-Log "Warning: Could not cleanly disconnect from Microsoft Graph" "WARNING"
    }
}

#endregion
