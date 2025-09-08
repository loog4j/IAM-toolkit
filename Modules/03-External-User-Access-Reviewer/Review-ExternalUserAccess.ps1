<#
.SYNOPSIS
    External User Access Reviewer - Comprehensive guest user security and compliance analysis

.DESCRIPTION
    This script performs comprehensive security analysis of external/guest users in Entra ID to identify
    security risks, compliance violations, and access governance issues. It analyzes guest user permissions,
    activity patterns, risk factors, and generates actionable security reports for B2B collaboration governance.

.PARAMETER ConfigPath
    Path to the configuration JSON file. Defaults to "External-User-Review-Config.json"

.PARAMETER TenantId
    Azure AD Tenant ID. If not provided, will use the current context

.PARAMETER OutputPath
    Custom output path for reports. Overrides config file setting

.PARAMETER ExportFormat
    Export format(s): JSON, CSV, HTML, or ALL. Defaults to ALL

.PARAMETER RiskThreshold
    Minimum risk score for inclusion in reports (Critical, High, Medium, Low). Defaults to config setting

.PARAMETER IncludeDormantOnly
    Only analyze dormant/inactive guest users

.PARAMETER GenerateRemediationScript
    Generate PowerShell remediation scripts for identified issues

.EXAMPLE
    .\Review-ExternalUserAccess.ps1
    Run with default settings using config file

.EXAMPLE
    .\Review-ExternalUserAccess.ps1 -RiskThreshold "High" -ExportFormat "HTML" -GenerateRemediationScript
    Generate HTML report for high-risk users with remediation scripts

.EXAMPLE
    .\Review-ExternalUserAccess.ps1 -IncludeDormantOnly -OutputPath "C:\Reports"
    Analyze only dormant guest users with custom output path

.NOTES
    Author: Identity Security Automation Team
    Version: 1.0.0
    Requires: Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement modules
    Permissions Required: User.Read.All, Group.Read.All, Directory.Read.All, AuditLog.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "External-User-Review-Config.json",
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("JSON", "CSV", "HTML", "ALL")]
    [string]$ExportFormat = "ALL",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Critical", "High", "Medium", "Low")]
    [string]$RiskThreshold,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDormantOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateRemediationScript
)

# Import required modules
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Reports"
)

foreach ($Module in $RequiredModules) {
    try {
        Import-Module $Module -ErrorAction Stop
        Write-Host "✓ Imported module: $Module" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to import required module: $Module. Please install it using: Install-Module $Module"
        exit 1
    }
}

# Global variables
$Script:Config = $null
$Script:LogPath = ""
$Script:ReportPath = ""
$Script:RemediationPath = ""
$Script:StartTime = Get-Date
$Script:ProcessedUsers = 0
$Script:HighRiskUsers = 0
$Script:CriticalRiskUsers = 0

#region Helper Functions

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Console output with colors
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor White }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
    }
    
    # File logging
    if ($Script:LogPath) {
        $logFile = Join-Path $Script:LogPath "ExternalUserReview_$(Get-Date -Format 'yyyyMMdd').log"
        $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

function Initialize-Environment {
    param([hashtable]$Config)
    
    Write-LogMessage "Initializing environment..." "INFO"
    
    # Create directories
    $Script:LogPath = $Config.OutputPaths.Logs
    $Script:ReportPath = if ($OutputPath) { $OutputPath } else { $Config.OutputPaths.Reports }
    $Script:RemediationPath = $Config.OutputPaths.Remediation
    
    foreach ($path in @($Script:LogPath, $Script:ReportPath, $Script:RemediationPath)) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
            Write-LogMessage "Created directory: $path" "SUCCESS"
        }
    }
    
    Write-LogMessage "Environment initialized successfully" "SUCCESS"
}

function Connect-ToMicrosoftGraph {
    param([string]$TenantId)
    
    Write-LogMessage "Connecting to Microsoft Graph..." "INFO"
    
    try {
        $connectParams = @{
            Scopes = @(
                "User.Read.All",
                "Group.Read.All",
                "Directory.Read.All",
                "AuditLog.Read.All",
                "Policy.Read.All"
            )
        }
        
        if ($TenantId) {
            $connectParams.TenantId = $TenantId
        }
        
        Connect-MgGraph @connectParams -ErrorAction Stop
        
        $context = Get-MgContext
        Write-LogMessage "Connected to tenant: $($context.TenantId)" "SUCCESS"
        Write-LogMessage "Account: $($context.Account)" "INFO"
        
        return $true
    }
    catch {
        Write-LogMessage "Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-GuestUsers {
    Write-LogMessage "Retrieving guest users..." "INFO"
    
    try {
        $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -All -Property @(
            "Id", "DisplayName", "UserPrincipalName", "Mail", "UserType", 
            "AccountEnabled", "CreatedDateTime", "SignInActivity", "ExternalUserState",
            "ExternalUserStateChangeDateTime", "InvitedBy", "Country", "CompanyName"
        ) -ErrorAction Stop
        
        Write-LogMessage "Found $($guestUsers.Count) guest users" "SUCCESS"
        return $guestUsers
    }
    catch {
        Write-LogMessage "Failed to retrieve guest users: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Get-UserSignInActivity {
    param([string]$UserId)
    
    try {
        $signIns = Get-MgAuditLogSignIn -Filter "userId eq '$UserId'" -Top 1 -Sort "createdDateTime desc" -ErrorAction SilentlyContinue
        
        $activity = @{
            LastSignIn = $null
            DaysSinceLastSignIn = $null
            TotalSignIns = 0
            IsActive = $false
            HasNeverSignedIn = $true
        }
        
        if ($signIns -and $signIns.Count -gt 0) {
            $activity.LastSignIn = $signIns[0].CreatedDateTime
            $activity.DaysSinceLastSignIn = (Get-Date) - $activity.LastSignIn | Select-Object -ExpandProperty Days
            $activity.IsActive = $activity.DaysSinceLastSignIn -le 30
            $activity.HasNeverSignedIn = $false
        }
        
        return $activity
    }
    catch {
        Write-LogMessage "Could not retrieve sign-in activity for user $UserId" "WARNING"
        return @{
            LastSignIn = $null
            DaysSinceLastSignIn = $null
            TotalSignIns = 0
            IsActive = $false
            HasNeverSignedIn = $true
        }
    }
}

function Get-UserGroupMemberships {
    param([string]$UserId)
    
    try {
        $memberships = Get-MgUserMemberOf -UserId $UserId -All -ErrorAction SilentlyContinue
        
        $groups = @()
        $privilegedGroups = @()
        
        foreach ($membership in $memberships) {
            if ($membership.AdditionalProperties["@odata.type"] -eq "#microsoft.graph.group") {
                $groupName = $membership.AdditionalProperties["displayName"]
                $groups += $groupName
                
                # Check if it's a privileged group
                if ($Script:Config.RiskCriteria.SensitiveGroups -contains $groupName) {
                    $privilegedGroups += $groupName
                }
            }
        }
        
        return @{
            AllGroups = $groups
            PrivilegedGroups = $privilegedGroups
            GroupCount = $groups.Count
            PrivilegedGroupCount = $privilegedGroups.Count
        }
    }
    catch {
        Write-LogMessage "Could not retrieve group memberships for user $UserId" "WARNING"
        return @{
            AllGroups = @()
            PrivilegedGroups = @()
            GroupCount = 0
            PrivilegedGroupCount = 0
        }
    }
}

function Get-UserDirectoryRoles {
    param([string]$UserId)
    
    try {
        $roleAssignments = Get-MgUserAppRoleAssignment -UserId $UserId -All -ErrorAction SilentlyContinue
        
        $roles = @()
        $privilegedRoles = @()
        
        foreach ($assignment in $roleAssignments) {
            if ($assignment.ResourceDisplayName -eq "Microsoft Graph") {
                $roleName = $assignment.AppRoleDisplayName
                if ($roleName) {
                    $roles += $roleName
                    
                    # Check if it's a privileged role
                    if ($Script:Config.RiskCriteria.PrivilegedRoles -contains $roleName) {
                        $privilegedRoles += $roleName
                    }
                }
            }
        }
        
        return @{
            AllRoles = $roles
            PrivilegedRoles = $privilegedRoles
            RoleCount = $roles.Count
            PrivilegedRoleCount = $privilegedRoles.Count
        }
    }
    catch {
        Write-LogMessage "Could not retrieve directory roles for user $UserId" "WARNING"
        return @{
            AllRoles = @()
            PrivilegedRoles = @()
            RoleCount = 0
            PrivilegedRoleCount = 0
        }
    }
}

function Calculate-UserRiskScore {
    param(
        [object]$User,
        [object]$Activity,
        [object]$Groups,
        [object]$Roles,
        [hashtable]$Config
    )
    
    $riskScore = 0
    $riskFactors = @()
    
    # Dormant account risk
    if ($Activity.DaysSinceLastSignIn -gt $Config.ReviewSettings.DormantThresholdDays) {
        $riskScore += $Config.RiskScoring.Weights.DormantAccount
        $riskFactors += "Dormant account ($($Activity.DaysSinceLastSignIn) days since last sign-in)"
    }
    
    # Never signed in risk
    if ($Activity.HasNeverSignedIn) {
        $riskScore += $Config.RiskScoring.Weights.NeverSignedIn
        $riskFactors += "Never signed in"
    }
    
    # Privileged role risk
    if ($Roles.PrivilegedRoleCount -gt 0) {
        $riskScore += $Roles.PrivilegedRoleCount * $Config.RiskScoring.Weights.PrivilegedRole
        $riskFactors += "Privileged roles: $($Roles.PrivilegedRoles -join ', ')"
    }
    
    # High-risk domain
    $domain = ($User.UserPrincipalName -split '@')[1]
    if ($Config.RiskCriteria.HighRiskDomains -contains $domain) {
        $riskScore += $Config.RiskScoring.Weights.HighRiskDomain
        $riskFactors += "High-risk domain: $domain"
    }
    
    # Personal email domain
    $personalDomains = @("gmail.com", "yahoo.com", "hotmail.com", "outlook.com")
    if ($personalDomains -contains $domain) {
        $riskScore += $Config.RiskScoring.Weights.PersonalEmail
        $riskFactors += "Personal email domain: $domain"
    }
    
    # High-risk country
    if ($User.Country -and $Config.RiskCriteria.HighRiskCountries -contains $User.Country) {
        $riskScore += $Config.RiskScoring.Weights.HighRiskCountry
        $riskFactors += "High-risk country: $($User.Country)"
    }
    
    # Privileged group membership
    if ($Groups.PrivilegedGroupCount -gt 0) {
        $riskScore += $Groups.PrivilegedGroupCount * $Config.RiskScoring.Weights.OverPrivileged
        $riskFactors += "Privileged groups: $($Groups.PrivilegedGroups -join ', ')"
    }
    
    # Suspicious patterns in display name or UPN
    $userText = "$($User.DisplayName) $($User.UserPrincipalName)"
    foreach ($pattern in $Config.RiskCriteria.SuspiciousPatterns) {
        if ($userText -match $pattern) {
            $riskScore += $Config.RiskScoring.Weights.SuspiciousPattern
            $riskFactors += "Suspicious pattern detected: $pattern"
            break
        }
    }
    
    # Determine risk level
    $riskLevel = switch ($riskScore) {
        { $_ -ge $Config.RiskScoring.Thresholds.Critical } { "Critical" }
        { $_ -ge $Config.RiskScoring.Thresholds.High } { "High" }
        { $_ -ge $Config.RiskScoring.Thresholds.Medium } { "Medium" }
        { $_ -ge $Config.RiskScoring.Thresholds.Low } { "Low" }
        default { "Minimal" }
    }
    
    return @{
        Score = $riskScore
        Level = $riskLevel
        Factors = $riskFactors
    }
}

function Get-ExternalUserAnalysis {
    param([hashtable]$Config)
    
    Write-LogMessage "Starting external user analysis..." "INFO"
    
    $guestUsers = Get-GuestUsers
    if ($guestUsers.Count -eq 0) {
        Write-LogMessage "No guest users found" "WARNING"
        return @()
    }
    
    $userAnalysis = @()
    $totalUsers = $guestUsers.Count
    $currentUser = 0
    
    foreach ($user in $guestUsers) {
        $currentUser++
        $Script:ProcessedUsers++
        
        Write-Progress -Activity "Analyzing External Users" -Status "Processing $($user.DisplayName)" -PercentComplete (($currentUser / $totalUsers) * 100)
        
        try {
            # Get user activity
            $activity = Get-UserSignInActivity -UserId $user.Id
            
            # Skip non-dormant users if only analyzing dormant users
            if ($IncludeDormantOnly -and $activity.IsActive) {
                continue
            }
            
            # Get group memberships
            $groups = Get-UserGroupMemberships -UserId $user.Id
            
            # Get directory roles
            $roles = Get-UserDirectoryRoles -UserId $user.Id
            
            # Calculate risk score
            $risk = Calculate-UserRiskScore -User $user -Activity $activity -Groups $groups -Roles $roles -Config $Config
            
            # Skip low-risk users if threshold is set
            if ($RiskThreshold) {
                $thresholdOrder = @("Critical", "High", "Medium", "Low")
                $userRiskIndex = $thresholdOrder.IndexOf($risk.Level)
                $thresholdIndex = $thresholdOrder.IndexOf($RiskThreshold)
                
                if ($userRiskIndex -gt $thresholdIndex) {
                    continue
                }
            }
            
            # Track high-risk users
            if ($risk.Level -eq "Critical") {
                $Script:CriticalRiskUsers++
            }
            if ($risk.Level -in @("Critical", "High")) {
                $Script:HighRiskUsers++
            }
            
            $analysis = @{
                # User Information
                UserId = $user.Id
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                Mail = $user.Mail
                AccountEnabled = $user.AccountEnabled
                CreatedDateTime = $user.CreatedDateTime
                Country = $user.Country
                CompanyName = $user.CompanyName
                
                # External User Specific
                ExternalUserState = $user.ExternalUserState
                ExternalUserStateChangeDateTime = $user.ExternalUserStateChangeDateTime
                InvitedBy = $user.InvitedBy
                Domain = ($user.UserPrincipalName -split '@')[1]
                
                # Activity Analysis
                LastSignIn = $activity.LastSignIn
                DaysSinceLastSignIn = $activity.DaysSinceLastSignIn
                IsActive = $activity.IsActive
                HasNeverSignedIn = $activity.HasNeverSignedIn
                IsDormant = $activity.DaysSinceLastSignIn -gt $Config.ReviewSettings.DormantThresholdDays
                
                # Access Rights
                GroupMemberships = $groups.AllGroups
                PrivilegedGroups = $groups.PrivilegedGroups
                GroupCount = $groups.GroupCount
                PrivilegedGroupCount = $groups.PrivilegedGroupCount
                
                DirectoryRoles = $roles.AllRoles
                PrivilegedRoles = $roles.PrivilegedRoles
                RoleCount = $roles.RoleCount
                PrivilegedRoleCount = $roles.PrivilegedRoleCount
                
                # Risk Assessment
                RiskScore = $risk.Score
                RiskLevel = $risk.Level
                RiskFactors = $risk.Factors
                
                # Compliance Flags
                RequiresReview = ($risk.Level -in @("Critical", "High")) -or 
                                ($activity.DaysSinceLastSignIn -gt $Config.ReviewSettings.DormantThresholdDays) -or
                                ($roles.PrivilegedRoleCount -gt 0)
                
                AnalyzedDateTime = Get-Date
            }
            
            $userAnalysis += $analysis
            
        }
        catch {
            Write-LogMessage "Error analyzing user $($user.DisplayName): $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-Progress -Activity "Analyzing External Users" -Completed
    Write-LogMessage "External user analysis completed. Analyzed $($userAnalysis.Count) users" "SUCCESS"
    
    return $userAnalysis
}

function Generate-ExecutiveSummary {
    param([array]$Users, [hashtable]$Config)
    
    $summary = @{
        TotalGuestUsers = $Users.Count
        CriticalRiskUsers = ($Users | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        HighRiskUsers = ($Users | Where-Object { $_.RiskLevel -eq "High" }).Count
        MediumRiskUsers = ($Users | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        DormantUsers = ($Users | Where-Object { $_.IsDormant }).Count
        NeverSignedInUsers = ($Users | Where-Object { $_.HasNeverSignedIn }).Count
        PrivilegedGuestUsers = ($Users | Where-Object { $_.PrivilegedRoleCount -gt 0 -or $_.PrivilegedGroupCount -gt 0 }).Count
        PersonalEmailUsers = ($Users | Where-Object { $_.Domain -in @("gmail.com", "yahoo.com", "hotmail.com", "outlook.com") }).Count
        HighRiskDomainUsers = ($Users | Where-Object { $_.Domain -in $Config.RiskCriteria.HighRiskDomains }).Count
        
        TopRiskyUsers = $Users | 
            Sort-Object RiskScore -Descending | 
            Select-Object -First $Config.ReportSettings.MaxUsersInSummary |
            Select-Object DisplayName, UserPrincipalName, RiskScore, RiskLevel, Domain
        
        RecommendedActions = @()
    }
    
    # Generate recommendations
    if ($summary.CriticalRiskUsers -gt 0) {
        $summary.RecommendedActions += "URGENT: Review and potentially remove $($summary.CriticalRiskUsers) critical-risk guest users"
    }
    
    if ($summary.HighRiskUsers -gt 0) {
        $summary.RecommendedActions += "Review and validate business need for $($summary.HighRiskUsers) high-risk guest users"
    }
    
    if ($summary.PrivilegedGuestUsers -gt 0) {
        $summary.RecommendedActions += "Audit privileged access for $($summary.PrivilegedGuestUsers) guest users with elevated permissions"
    }
    
    if ($summary.DormantUsers -gt 0) {
        $summary.RecommendedActions += "Consider removing $($summary.DormantUsers) dormant guest users"
    }
    
    if ($summary.NeverSignedInUsers -gt 0) {
        $summary.RecommendedActions += "Review and clean up $($summary.NeverSignedInUsers) guest users who never signed in"
    }
    
    if ($summary.PersonalEmailUsers -gt 0) {
        $summary.RecommendedActions += "Review business justification for $($summary.PersonalEmailUsers) guests using personal email domains"
    }
    
    return $summary
}

function Export-ToJSON {
    param(
        [array]$Users,
        [hashtable]$Summary,
        [string]$OutputPath
    )
    
    $jsonReport = @{
        ReportMetadata = @{
            GeneratedDateTime = Get-Date
            TotalUsersAnalyzed = $Users.Count
            CriticalRiskUsers = $Script:CriticalRiskUsers
            HighRiskUsers = $Script:HighRiskUsers
            ReportVersion = "1.0.0"
        }
        ExecutiveSummary = $Summary
        GuestUsers = $Users
    }
    
    $jsonPath = Join-Path $OutputPath "ExternalUserReview_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    Write-LogMessage "JSON report exported to: $jsonPath" "SUCCESS"
    return $jsonPath
}

function Export-ToCSV {
    param(
        [array]$Users,
        [string]$OutputPath
    )
    
    $csvData = $Users | Select-Object @(
        'DisplayName',
        'UserPrincipalName',
        'Domain',
        'RiskScore',
        'RiskLevel',
        'AccountEnabled',
        'ExternalUserState',
        'Country',
        'CompanyName',
        'LastSignIn',
        'DaysSinceLastSignIn',
        'IsActive',
        'IsDormant',
        'HasNeverSignedIn',
        'GroupCount',
        'PrivilegedGroupCount',
        'RoleCount',
        'PrivilegedRoleCount',
        'RequiresReview',
        @{Name='GroupMemberships'; Expression={$_.GroupMemberships -join '; '}},
        @{Name='PrivilegedGroups'; Expression={$_.PrivilegedGroups -join '; '}},
        @{Name='DirectoryRoles'; Expression={$_.DirectoryRoles -join '; '}},
        @{Name='PrivilegedRoles'; Expression={$_.PrivilegedRoles -join '; '}},
        @{Name='RiskFactors'; Expression={$_.RiskFactors -join '; '}}
    )
    
    $csvPath = Join-Path $OutputPath "ExternalUserReview_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    
    Write-LogMessage "CSV report exported to: $csvPath" "SUCCESS"
    return $csvPath
}

function Export-ToHTML {
    param(
        [array]$Users,
        [hashtable]$Summary,
        [string]$OutputPath
    )
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>External User Access Review Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #0078d4; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .summary-card { background: linear-gradient(135deg, #0078d4, #106ebe); color: white; padding: 15px; border-radius: 8px; text-align: center; }
        .summary-card h3 { margin: 0 0 8px 0; font-size: 1.8em; }
        .summary-card p { margin: 0; opacity: 0.9; font-size: 0.9em; }
        .risk-critical { background: linear-gradient(135deg, #d13438, #b71c1c) !important; }
        .risk-high { background: linear-gradient(135deg, #ff6b35, #e65100) !important; }
        .risk-medium { background: linear-gradient(135deg, #ffb347, #f57c00) !important; }
        .risk-warning { background: linear-gradient(135deg, #ff9800, #f57c00) !important; }
        .users-table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 0.9em; }
        .users-table th, .users-table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        .users-table th { background-color: #0078d4; color: white; font-weight: 600; }
        .users-table tr:hover { background-color: #f5f5f5; }
        .risk-badge { padding: 3px 6px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.75em; }
        .risk-critical-badge { background-color: #d13438; }
        .risk-high-badge { background-color: #ff6b35; }
        .risk-medium-badge { background-color: #ffb347; color: #333; }
        .risk-low-badge { background-color: #4caf50; }
        .risk-minimal-badge { background-color: #9e9e9e; }
        .recommendations { background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .recommendations h3 { color: #856404; margin-top: 0; }
        .recommendations ul { margin: 10px 0; }
        .recommendations li { margin: 5px 0; }
        .timestamp { text-align: center; color: #666; font-size: 0.9em; margin-top: 30px; }
        .status-active { color: #4caf50; font-weight: bold; }
        .status-dormant { color: #ff6b35; font-weight: bold; }
        .status-never { color: #d13438; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 External User Access Review Report</h1>
            <p>Generated on $(Get-Date -Format 'MMMM dd, yyyy at HH:mm:ss')</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>$($Summary.TotalGuestUsers)</h3>
                <p>Total Guest Users</p>
            </div>
            <div class="summary-card risk-critical">
                <h3>$($Summary.CriticalRiskUsers)</h3>
                <p>Critical Risk</p>
            </div>
            <div class="summary-card risk-high">
                <h3>$($Summary.HighRiskUsers)</h3>
                <p>High Risk</p>
            </div>
            <div class="summary-card risk-warning">
                <h3>$($Summary.PrivilegedGuestUsers)</h3>
                <p>Privileged Access</p>
            </div>
            <div class="summary-card risk-medium">
                <h3>$($Summary.DormantUsers)</h3>
                <p>Dormant Users</p>
            </div>
            <div class="summary-card risk-warning">
                <h3>$($Summary.NeverSignedInUsers)</h3>
                <p>Never Signed In</p>
            </div>
        </div>
        
        <div class="recommendations">
            <h3>🎯 Recommended Actions</h3>
            <ul>
"@

    foreach ($action in $Summary.RecommendedActions) {
        $htmlContent += "                <li>$action</li>`n"
    }

    $htmlContent += @"
            </ul>
        </div>
        
        <h2>👥 Guest User Analysis Results</h2>
        <table class="users-table">
            <thead>
                <tr>
                    <th>User</th>
                    <th>Domain</th>
                    <th>Risk Level</th>
                    <th>Status</th>
                    <th>Last Sign-In</th>
                    <th>Privileged Access</th>
                    <th>Country</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($user in ($Users | Sort-Object RiskScore -Descending)) {
        $riskBadgeClass = switch ($user.RiskLevel) {
            "Critical" { "risk-critical-badge" }
            "High" { "risk-high-badge" }
            "Medium" { "risk-medium-badge" }
            "Low" { "risk-low-badge" }
            default { "risk-minimal-badge" }
        }
        
        $statusClass = if ($user.HasNeverSignedIn) { "status-never" } 
                      elseif ($user.IsDormant) { "status-dormant" } 
                      else { "status-active" }
        
        $statusText = if ($user.HasNeverSignedIn) { "Never Signed In" } 
                     elseif ($user.IsDormant) { "Dormant" } 
                     else { "Active" }
        
        $lastSignIn = if ($user.LastSignIn) { 
            (Get-Date $user.LastSignIn).ToString("yyyy-MM-dd") 
        } else { 
            "Never" 
        }
        
        $privilegedAccess = ""
        if ($user.PrivilegedRoleCount -gt 0) {
            $privilegedAccess += "Roles: $($user.PrivilegedRoleCount) "
        }
        if ($user.PrivilegedGroupCount -gt 0) {
            $privilegedAccess += "Groups: $($user.PrivilegedGroupCount)"
        }
        if (-not $privilegedAccess) {
            $privilegedAccess = "None"
        }
        
        $htmlContent += @"
                <tr>
                    <td><strong>$($user.DisplayName)</strong><br><small>$($user.UserPrincipalName)</small></td>
                    <td>$($user.Domain)</td>
                    <td><span class="risk-badge $riskBadgeClass">$($user.RiskLevel)</span></td>
                    <td><span class="$statusClass">$statusText</span></td>
                    <td>$lastSignIn</td>
                    <td>$privilegedAccess</td>
                    <td>$($user.Country)</td>
                </tr>
"@
    }

    $htmlContent += @"
            </tbody>
        </table>
        
        <div class="timestamp">
            Report generated by External User Access Reviewer v1.0.0<br>
            Processing completed in $([math]::Round((Get-Date) - $Script:StartTime).TotalSeconds, 2) seconds
        </div>
    </div>
</body>
</html>
"@

    $htmlPath = Join-Path $OutputPath "ExternalUserReview_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    
    Write-LogMessage "HTML report exported to: $htmlPath" "SUCCESS"
    return $htmlPath
}

function Generate-RemediationScript {
    param(
        [array]$Users,
        [string]$OutputPath
    )
    
    if (-not $GenerateRemediationScript) {
        return
    }
    
    Write-LogMessage "Generating remediation scripts..." "INFO"
    
    $criticalUsers = $Users | Where-Object { $_.RiskLevel -eq "Critical" }
    $dormantUsers = $Users | Where-Object { $_.IsDormant }
    $neverSignedInUsers = $Users | Where-Object { $_.HasNeverSignedIn }
    $privilegedUsers = $Users | Where-Object { $_.PrivilegedRoleCount -gt 0 -or $_.PrivilegedGroupCount -gt 0 }
    
    $remediationScript = @"
<#
.SYNOPSIS
    External User Remediation Script - Generated on $(Get-Date)

.DESCRIPTION
    This script contains remediation actions for identified external user security risks.
    Review each section carefully before execution.

.NOTES
    Generated by External User Access Reviewer
    Total Users Analyzed: $($Users.Count)
    Critical Risk Users: $($criticalUsers.Count)
    Dormant Users: $($dormantUsers.Count)
    Never Signed In: $($neverSignedInUsers.Count)
    Privileged Users: $($privilegedUsers.Count)
#>

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All"

Write-Host "External User Remediation Script" -ForegroundColor Yellow
Write-Host "=================================" -ForegroundColor Yellow
Write-Host ""

#region Critical Risk Users
Write-Host "CRITICAL RISK USERS - IMMEDIATE ATTENTION REQUIRED" -ForegroundColor Red
Write-Host "===================================================" -ForegroundColor Red

"@

    if ($criticalUsers.Count -gt 0) {
        $remediationScript += @"

# Critical risk users that should be reviewed immediately:
"@
        foreach ($user in $criticalUsers) {
            $remediationScript += @"

# User: $($user.DisplayName) ($($user.UserPrincipalName))
# Risk Score: $($user.RiskScore) | Risk Factors: $($user.RiskFactors -join '; ')
# Uncomment the line below to disable this user:
# Update-MgUser -UserId "$($user.UserId)" -AccountEnabled:`$false

"@
        }
    } else {
        $remediationScript += @"

# No critical risk users found.

"@
    }

    $remediationScript += @"

#endregion

#region Dormant Users Cleanup
Write-Host "DORMANT USERS CLEANUP" -ForegroundColor Yellow
Write-Host "=====================" -ForegroundColor Yellow

"@

    if ($dormantUsers.Count -gt 0) {
        $remediationScript += @"

# Users who haven't signed in for more than 90 days:
"@
        foreach ($user in $dormantUsers) {
            $remediationScript += @"

# User: $($user.DisplayName) | Last Sign-In: $($user.LastSignIn) | Days: $($user.DaysSinceLastSignIn)
# Uncomment to remove this dormant user:
# Remove-MgUser -UserId "$($user.UserId)"

"@
        }
    } else {
        $remediationScript += @"

# No dormant users found.

"@
    }

    $remediationScript += @"

#endregion

#region Never Signed In Users
Write-Host "NEVER SIGNED IN USERS" -ForegroundColor Yellow
Write-Host "=====================" -ForegroundColor Yellow

"@

    if ($neverSignedInUsers.Count -gt 0) {
        $remediationScript += @"

# Users who were invited but never signed in:
"@
        foreach ($user in $neverSignedInUsers) {
            $remediationScript += @"

# User: $($user.DisplayName) | Created: $($user.CreatedDateTime)
# Uncomment to remove this user who never signed in:
# Remove-MgUser -UserId "$($user.UserId)"

"@
        }
    } else {
        $remediationScript += @"

# No users found who never signed in.

"@
    }

    $remediationScript += @"

#endregion

#region Privileged Users Review
Write-Host "PRIVILEGED USERS REVIEW" -ForegroundColor Yellow
Write-Host "=======================" -ForegroundColor Yellow

"@

    if ($privilegedUsers.Count -gt 0) {
        $remediationScript += @"

# External users with privileged access - review carefully:
"@
        foreach ($user in $privilegedUsers) {
            $remediationScript += @"

# User: $($user.DisplayName)
# Privileged Roles: $($user.PrivilegedRoles -join ', ')
# Privileged Groups: $($user.PrivilegedGroups -join ', ')
# Review and remove unnecessary privileged access

"@
        }
    } else {
        $remediationScript += @"

# No external users with privileged access found.

"@
    }

    $remediationScript += @"

#endregion

Write-Host ""
Write-Host "Remediation script completed. Review all actions before uncommenting and executing." -ForegroundColor Green
Write-Host "Always test in a non-production environment first." -ForegroundColor Yellow

# Disconnect from Microsoft Graph
Disconnect-MgGraph
"@

    $scriptPath = Join-Path $OutputPath "ExternalUserRemediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
    $remediationScript | Out-File -FilePath $scriptPath -Encoding UTF8
    
    Write-LogMessage "Remediation script generated: $scriptPath" "SUCCESS"
    return $scriptPath
}

#endregion

#region Main Execution

function Main {
    try {
        Write-LogMessage "Starting External User Access Reviewer v1.0.0" "INFO"
        Write-LogMessage "================================================" "INFO"
        
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
        
        # Connect to Microsoft Graph
        if (-not (Connect-ToMicrosoftGraph -TenantId $TenantId)) {
            Write-LogMessage "Failed to connect to Microsoft Graph. Exiting." "ERROR"
            exit 1
        }
        
        # Perform external user analysis
        Write-LogMessage "Starting comprehensive external user analysis..." "INFO"
        $users = Get-ExternalUserAnalysis -Config $Script:Config
        
        if ($users.Count -eq 0) {
            Write-LogMessage "No external users found matching the criteria" "WARNING"
            return
        }
        
        # Generate executive summary
        Write-LogMessage "Generating executive summary..." "INFO"
        $summary = Generate-ExecutiveSummary -Users $users -Config $Script:Config
        
        # Export reports
        Write-LogMessage "Exporting reports..." "INFO"
        $exportedFiles = @()
        
        $formats = if ($ExportFormat -eq "ALL") { 
            $Script:Config.ReportSettings.Formats 
        } else { 
            @($ExportFormat) 
        }
        
        foreach ($format in $formats) {
            switch ($format) {
                "JSON" {
                    $exportedFiles += Export-ToJSON -Users $users -Summary $summary -OutputPath $Script:ReportPath
                }
                "CSV" {
                    $exportedFiles += Export-ToCSV -Users $users -OutputPath $Script:ReportPath
                }
                "HTML" {
                    $exportedFiles += Export-ToHTML -Users $users -Summary $summary -OutputPath $Script:ReportPath
                }
            }
        }
        
        # Generate remediation script if requested
        if ($GenerateRemediationScript) {
            $remediationFile = Generate-RemediationScript -Users $users -OutputPath $Script:RemediationPath
            if ($remediationFile) {
                $exportedFiles += $remediationFile
            }
        }
        
        # Final summary
        $duration = (Get-Date) - $Script:StartTime
        Write-LogMessage "================================================" "SUCCESS"
        Write-LogMessage "External User Access Review Completed Successfully!" "SUCCESS"
        Write-LogMessage "================================================" "SUCCESS"
        Write-LogMessage "Processing Time: $([math]::Round($duration.TotalSeconds, 2)) seconds" "INFO"
        Write-LogMessage "Users Processed: $($Script:ProcessedUsers)" "INFO"
        Write-LogMessage "Users Analyzed: $($users.Count)" "INFO"
        Write-LogMessage "Critical Risk Users: $($Script:CriticalRiskUsers)" "INFO"
        Write-LogMessage "High Risk Users: $($Script:HighRiskUsers)" "INFO"
        Write-LogMessage "Reports Generated: $($exportedFiles.Count)" "INFO"
        
        Write-LogMessage "`nGenerated Reports:" "INFO"
        foreach ($file in $exportedFiles) {
            Write-LogMessage "  • $file" "SUCCESS"
        }
        
        # Display key findings
        if ($summary.CriticalRiskUsers -gt 0) {
            Write-LogMessage "`n🚨 CRITICAL ALERT: $($summary.CriticalRiskUsers) critical-risk guest users detected!" "ERROR"
        }
        
        if ($summary.PrivilegedGuestUsers -gt 0) {
            Write-LogMessage "⚠️  WARNING: $($summary.PrivilegedGuestUsers) guest users have privileged access" "WARNING"
        }
        
        if ($summary.DormantUsers -gt 0) {
            Write-LogMessage "ℹ️  INFO: $($summary.DormantUsers) dormant guest users found" "INFO"
        }
        
        if ($summary.NeverSignedInUsers -gt 0) {
            Write-LogMessage "ℹ️  INFO: $($summary.NeverSignedInUsers) guest users never signed in" "INFO"
        }
        
        Write-LogMessage "`nRecommended Actions:" "INFO"
        foreach ($action in $summary.RecommendedActions) {
            Write-LogMessage "  • $action" "INFO"
        }
        
    }
    catch {
        Write-LogMessage "Critical error in main execution: $($_.Exception.Message)" "ERROR"
        Write-LogMessage "Stack trace: $($_.ScriptStackTrace)" "ERROR"
        exit 1
    }
    finally {
        # Disconnect from Microsoft Graph
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-LogMessage "Disconnected from Microsoft Graph" "INFO"
        }
        catch {
            # Ignore disconnection errors
        }
    }
}

# Execute main function
Main

#endregion
