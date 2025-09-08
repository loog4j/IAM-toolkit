<#
.SYNOPSIS
    Entra ID App Consent Auditor - Comprehensive analysis of application permissions and consent grants

.DESCRIPTION
    This script performs a comprehensive audit of all Entra ID app registrations and enterprise applications
    to identify high-risk permissions, suspicious consent grants, and potential security risks. It provides
    detailed analysis of application permissions, consent types, usage patterns, and generates actionable
    security reports.

.PARAMETER ConfigPath
    Path to the configuration JSON file. Defaults to "App-Consent-Audit-Config.json"

.PARAMETER TenantId
    Azure AD Tenant ID. If not provided, will use the current context

.PARAMETER OutputPath
    Custom output path for reports. Overrides config file setting

.PARAMETER ExportFormat
    Export format(s): JSON, CSV, HTML, or ALL. Defaults to ALL

.PARAMETER RiskThreshold
    Minimum risk score for inclusion in reports (1-10). Defaults to config setting

.PARAMETER IncludeSystemApps
    Include Microsoft system applications in the analysis

.PARAMETER Detailed
    Generate detailed analysis including permission descriptions and recommendations

.EXAMPLE
    .\Export-EntraIDAppConsent.ps1
    Run with default settings using config file

.EXAMPLE
    .\Export-EntraIDAppConsent.ps1 -RiskThreshold 8 -ExportFormat "HTML" -Detailed
    Generate detailed HTML report for high-risk applications only

.EXAMPLE
    .\Export-EntraIDAppConsent.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -OutputPath "C:\Reports"
    Run for specific tenant with custom output path

.NOTES
    Author: Identity Security Automation Team
    Version: 1.0.0
    Requires: Microsoft.Graph.Applications, Microsoft.Graph.Authentication modules
    Permissions Required: Application.Read.All, Directory.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "App-Consent-Audit-Config.json",
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("JSON", "CSV", "HTML", "ALL")]
    [string]$ExportFormat = "ALL",
    
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 10)]
    [int]$RiskThreshold,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSystemApps,
    
    [Parameter(Mandatory = $false)]
    [switch]$Detailed
)

# Import required modules
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.DirectoryObjects",
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
$Script:StartTime = Get-Date
$Script:ProcessedApps = 0
$Script:HighRiskApps = 0

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
        $logFile = Join-Path $Script:LogPath "AppConsentAudit_$(Get-Date -Format 'yyyyMMdd').log"
        $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

function Initialize-Environment {
    param([hashtable]$Config)
    
    Write-LogMessage "Initializing environment..." "INFO"
    
    # Create directories
    $Script:LogPath = $Config.LogPath
    $Script:ReportPath = if ($OutputPath) { $OutputPath } else { $Config.ReportPath }
    
    foreach ($path in @($Script:LogPath, $Script:ReportPath)) {
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
                "Application.Read.All",
                "Directory.Read.All",
                "AuditLog.Read.All"
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

function Get-ApplicationPermissions {
    param([object]$Application)
    
    $permissions = @{
        RequiredResourceAccess = @()
        DelegatedPermissions = @()
        ApplicationPermissions = @()
    }
    
    if ($Application.RequiredResourceAccess) {
        foreach ($resource in $Application.RequiredResourceAccess) {
            $resourceInfo = @{
                ResourceAppId = $resource.ResourceAppId
                ResourceAccess = @()
            }
            
            foreach ($access in $resource.ResourceAccess) {
                $accessInfo = @{
                    Id = $access.Id
                    Type = $access.Type
                    Permission = ""
                }
                
                # Try to resolve permission name
                try {
                    if ($resource.ResourceAppId -eq "00000003-0000-0000-c000-000000000000") {
                        # Microsoft Graph permissions
                        $accessInfo.Permission = Get-GraphPermissionName -PermissionId $access.Id -Type $access.Type
                    }
                }
                catch {
                    $accessInfo.Permission = "Unknown Permission"
                }
                
                $resourceInfo.ResourceAccess += $accessInfo
                
                if ($access.Type -eq "Scope") {
                    $permissions.DelegatedPermissions += $accessInfo.Permission
                }
                elseif ($access.Type -eq "Role") {
                    $permissions.ApplicationPermissions += $accessInfo.Permission
                }
            }
            
            $permissions.RequiredResourceAccess += $resourceInfo
        }
    }
    
    return $permissions
}

function Get-GraphPermissionName {
    param(
        [string]$PermissionId,
        [string]$Type
    )
    
    # Common Microsoft Graph permissions mapping
    $graphPermissions = @{
        # Application permissions (Role)
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Application.ReadWrite.All"
        "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" = "Application.Read.All"
        "62a82d76-70ea-41e2-9197-370581804d09" = "Group.ReadWrite.All"
        "5b567255-7703-4780-807c-7be8301ae99b" = "Group.Read.All"
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7" = "Directory.ReadWrite.All"
        "7ab1d382-f21e-4acd-a863-ba3e13f7da61" = "Directory.Read.All"
        "df021288-bdef-4463-88db-98f22de89214" = "User.Read.All"
        "741f803b-c850-494e-b5df-cde7c675a1ca" = "User.ReadWrite.All"
        "810c84a8-4a9e-49e6-bf7d-12d183f40d01" = "Mail.Read.All"
        "e2a3a72e-5f79-4c64-b1b1-878b674786d9" = "Mail.ReadWrite.All"
        
        # Delegated permissions (Scope)
        "e1fe6dd8-ba31-4d61-89e7-88639da4683d" = "User.Read"
        "b4e74841-8e56-480b-be8b-910348b18b4c" = "User.ReadWrite"
        "a154be20-db9c-4678-8ab7-66f6cc099a59" = "User.Read.All"
        "204e0828-b5ca-4ad8-b9f3-f32a958e7cc4" = "User.ReadWrite.All"
        "570282fd-fa5c-430d-a7fd-fc8dc98a9dca" = "Mail.Read"
        "024d486e-b451-40bb-833d-3e66d98c5c73" = "Mail.ReadWrite"
    }
    
    if ($graphPermissions.ContainsKey($PermissionId)) {
        return $graphPermissions[$PermissionId]
    }
    
    return "Unknown Permission ($PermissionId)"
}

function Calculate-ApplicationRiskScore {
    param(
        [object]$Application,
        [object]$ServicePrincipal,
        [array]$Permissions,
        [hashtable]$Config
    )
    
    $riskScore = 0
    $riskFactors = @()
    
    # High-risk permissions
    $highRiskCount = 0
    $mediumRiskCount = 0
    
    foreach ($permission in $Permissions.ApplicationPermissions + $Permissions.DelegatedPermissions) {
        if ($Config.HighRiskPermissions -contains $permission) {
            $highRiskCount++
            $riskFactors += "High-risk permission: $permission"
        }
        elseif ($Config.MediumRiskPermissions -contains $permission) {
            $mediumRiskCount++
        }
    }
    
    $riskScore += $highRiskCount * $Config.RiskScoring.HighRiskPermissionWeight
    $riskScore += $mediumRiskCount * $Config.RiskScoring.MediumRiskPermissionWeight
    
    # Publisher verification
    if ($ServicePrincipal -and -not $ServicePrincipal.VerifiedPublisher.VerifiedPublisherId) {
        $riskScore += $Config.RiskScoring.UnverifiedPublisherWeight
        $riskFactors += "Unverified publisher"
    }
    
    # External tenant
    if ($Application.PublisherDomain -and $Application.PublisherDomain -notlike "*microsoft*") {
        $context = Get-MgContext
        if ($Application.AppOwnerOrganizationId -ne $context.TenantId) {
            $riskScore += $Config.RiskScoring.ExternalTenantWeight
            $riskFactors += "External tenant application"
        }
    }
    
    # User consent
    if ($ServicePrincipal -and $ServicePrincipal.AppRoleAssignmentRequired -eq $false) {
        $riskScore += $Config.RiskScoring.UserConsentWeight
        $riskFactors += "User consent enabled"
    }
    
    # Suspicious patterns in app name or description
    $suspiciousText = "$($Application.DisplayName) $($Application.Description)"
    foreach ($pattern in $Config.SuspiciousPatterns) {
        if ($suspiciousText -match $pattern) {
            $riskScore += 2
            $riskFactors += "Suspicious pattern detected: $pattern"
            break
        }
    }
    
    # Cap risk score at 10
    $riskScore = [Math]::Min($riskScore, 10)
    
    return @{
        Score = $riskScore
        Factors = $riskFactors
        HighRiskPermissions = $highRiskCount
        MediumRiskPermissions = $mediumRiskCount
    }
}

function Get-ApplicationUsageData {
    param([string]$ApplicationId)
    
    try {
        # Get sign-in data (requires AuditLog.Read.All)
        $signIns = Get-MgAuditLogSignIn -Filter "appId eq '$ApplicationId'" -Top 1 -Sort "createdDateTime desc" -ErrorAction SilentlyContinue
        
        $usageData = @{
            LastSignIn = $null
            DaysSinceLastUse = $null
            TotalSignIns = 0
            IsActive = $false
        }
        
        if ($signIns) {
            $usageData.LastSignIn = $signIns[0].CreatedDateTime
            $usageData.DaysSinceLastUse = (Get-Date) - $usageData.LastSignIn | Select-Object -ExpandProperty Days
            $usageData.IsActive = $usageData.DaysSinceLastUse -le 30
        }
        
        return $usageData
    }
    catch {
        Write-LogMessage "Could not retrieve usage data for app $ApplicationId" "WARNING"
        return @{
            LastSignIn = $null
            DaysSinceLastUse = $null
            TotalSignIns = 0
            IsActive = $false
        }
    }
}

function Get-ApplicationAnalysis {
    param([hashtable]$Config)
    
    Write-LogMessage "Starting application analysis..." "INFO"
    
    $applications = @()
    $allApps = @()
    $allServicePrincipals = @()
    
    try {
        # Get all applications
        Write-LogMessage "Retrieving applications..." "INFO"
        $allApps = Get-MgApplication -All -ErrorAction Stop
        Write-LogMessage "Found $($allApps.Count) applications" "INFO"
        
        # Get all service principals
        Write-LogMessage "Retrieving service principals..." "INFO"
        $allServicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop
        Write-LogMessage "Found $($allServicePrincipals.Count) service principals" "INFO"
        
    }
    catch {
        Write-LogMessage "Failed to retrieve applications: $($_.Exception.Message)" "ERROR"
        return @()
    }
    
    $totalApps = $allApps.Count
    $currentApp = 0
    
    foreach ($app in $allApps) {
        $currentApp++
        $Script:ProcessedApps++
        
        Write-Progress -Activity "Analyzing Applications" -Status "Processing $($app.DisplayName)" -PercentComplete (($currentApp / $totalApps) * 100)
        
        try {
            # Skip Microsoft system apps unless explicitly included
            if (-not $IncludeSystemApps -and ($app.PublisherDomain -like "*microsoft*" -or $app.DisplayName -like "Microsoft*")) {
                continue
            }
            
            # Find corresponding service principal
            $servicePrincipal = $allServicePrincipals | Where-Object { $_.AppId -eq $app.AppId }
            
            # Get permissions
            $permissions = Get-ApplicationPermissions -Application $app
            
            # Calculate risk score
            $riskAnalysis = Calculate-ApplicationRiskScore -Application $app -ServicePrincipal $servicePrincipal -Permissions $permissions -Config $Config
            
            # Skip low-risk apps if threshold is set
            if ($RiskThreshold -and $riskAnalysis.Score -lt $RiskThreshold) {
                continue
            }
            
            # Get usage data
            $usageData = Get-ApplicationUsageData -ApplicationId $app.AppId
            
            # Track high-risk apps
            if ($riskAnalysis.Score -ge $Config.AlertThresholds.MinRiskScoreForAlert) {
                $Script:HighRiskApps++
            }
            
            $appAnalysis = @{
                ApplicationId = $app.Id
                AppId = $app.AppId
                DisplayName = $app.DisplayName
                Description = $app.Description
                PublisherDomain = $app.PublisherDomain
                CreatedDateTime = $app.CreatedDateTime
                SignInAudience = $app.SignInAudience
                
                # Service Principal Info
                ServicePrincipalId = if ($servicePrincipal) { $servicePrincipal.Id } else { $null }
                ServicePrincipalType = if ($servicePrincipal) { $servicePrincipal.ServicePrincipalType } else { "None" }
                AppRoleAssignmentRequired = if ($servicePrincipal) { $servicePrincipal.AppRoleAssignmentRequired } else { $null }
                
                # Publisher Verification
                VerifiedPublisher = if ($servicePrincipal -and $servicePrincipal.VerifiedPublisher) { 
                    $servicePrincipal.VerifiedPublisher.DisplayName 
                } else { 
                    "Not Verified" 
                }
                
                # Permissions
                TotalPermissions = ($permissions.ApplicationPermissions + $permissions.DelegatedPermissions).Count
                ApplicationPermissions = $permissions.ApplicationPermissions
                DelegatedPermissions = $permissions.DelegatedPermissions
                
                # Risk Analysis
                RiskScore = $riskAnalysis.Score
                RiskLevel = switch ($riskAnalysis.Score) {
                    { $_ -ge 8 } { "Critical" }
                    { $_ -ge 6 } { "High" }
                    { $_ -ge 4 } { "Medium" }
                    { $_ -ge 2 } { "Low" }
                    default { "Minimal" }
                }
                RiskFactors = $riskAnalysis.Factors
                HighRiskPermissions = $riskAnalysis.HighRiskPermissions
                MediumRiskPermissions = $riskAnalysis.MediumRiskPermissions
                
                # Usage Data
                LastSignIn = $usageData.LastSignIn
                DaysSinceLastUse = $usageData.DaysSinceLastUse
                IsActive = $usageData.IsActive
                
                # Compliance Flags
                RequiresReview = ($riskAnalysis.Score -ge $Config.AlertThresholds.MinRiskScoreForAlert) -or 
                                ($usageData.DaysSinceLastUse -gt $Config.AlertThresholds.DaysUnusedThreshold)
                
                AnalyzedDateTime = Get-Date
            }
            
            $applications += $appAnalysis
            
        }
        catch {
            Write-LogMessage "Error analyzing application $($app.DisplayName): $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-Progress -Activity "Analyzing Applications" -Completed
    Write-LogMessage "Application analysis completed. Analyzed $($applications.Count) applications" "SUCCESS"
    
    return $applications
}

function Generate-ExecutiveSummary {
    param([array]$Applications, [hashtable]$Config)
    
    $summary = @{
        TotalApplications = $Applications.Count
        HighRiskApplications = ($Applications | Where-Object { $_.RiskLevel -in @("Critical", "High") }).Count
        MediumRiskApplications = ($Applications | Where-Object { $_.RiskLevel -eq "Medium" }).Count
        UnverifiedPublishers = ($Applications | Where-Object { $_.VerifiedPublisher -eq "Not Verified" }).Count
        UnusedApplications = ($Applications | Where-Object { $_.DaysSinceLastUse -gt $Config.AlertThresholds.DaysUnusedThreshold }).Count
        ExternalApplications = ($Applications | Where-Object { $_.PublisherDomain -notlike "*microsoft*" }).Count
        
        TopRiskyApplications = $Applications | 
            Sort-Object RiskScore -Descending | 
            Select-Object -First $Config.ReportSettings.MaxAppsInSummary |
            Select-Object DisplayName, RiskScore, RiskLevel, HighRiskPermissions
        
        RecommendedActions = @()
    }
    
    # Generate recommendations
    if ($summary.HighRiskApplications -gt 0) {
        $summary.RecommendedActions += "Review and potentially revoke access for $($summary.HighRiskApplications) high-risk applications"
    }
    
    if ($summary.UnverifiedPublishers -gt 0) {
        $summary.RecommendedActions += "Verify publisher information for $($summary.UnverifiedPublishers) applications"
    }
    
    if ($summary.UnusedApplications -gt 0) {
        $summary.RecommendedActions += "Consider removing $($summary.UnusedApplications) unused applications"
    }
    
    return $summary
}

function Export-ToJSON {
    param(
        [array]$Applications,
        [hashtable]$Summary,
        [string]$OutputPath
    )
    
    $jsonReport = @{
        ReportMetadata = @{
            GeneratedDateTime = Get-Date
            TotalApplicationsAnalyzed = $Applications.Count
            HighRiskApplications = $Script:HighRiskApps
            ReportVersion = "1.0.0"
        }
        ExecutiveSummary = $Summary
        Applications = $Applications
    }
    
    $jsonPath = Join-Path $OutputPath "AppConsentAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    Write-LogMessage "JSON report exported to: $jsonPath" "SUCCESS"
    return $jsonPath
}

function Export-ToCSV {
    param(
        [array]$Applications,
        [string]$OutputPath
    )
    
    $csvData = $Applications | Select-Object @(
        'DisplayName',
        'AppId',
        'RiskScore',
        'RiskLevel',
        'HighRiskPermissions',
        'MediumRiskPermissions',
        'TotalPermissions',
        'VerifiedPublisher',
        'PublisherDomain',
        'LastSignIn',
        'DaysSinceLastUse',
        'IsActive',
        'RequiresReview',
        @{Name='ApplicationPermissions'; Expression={$_.ApplicationPermissions -join '; '}},
        @{Name='DelegatedPermissions'; Expression={$_.DelegatedPermissions -join '; '}},
        @{Name='RiskFactors'; Expression={$_.RiskFactors -join '; '}}
    )
    
    $csvPath = Join-Path $OutputPath "AppConsentAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    
    Write-LogMessage "CSV report exported to: $csvPath" "SUCCESS"
    return $csvPath
}

function Export-ToHTML {
    param(
        [array]$Applications,
        [hashtable]$Summary,
        [string]$OutputPath
    )
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Entra ID App Consent Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #0078d4; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: linear-gradient(135deg, #0078d4, #106ebe); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 2em; }
        .summary-card p { margin: 0; opacity: 0.9; }
        .risk-critical { background: linear-gradient(135deg, #d13438, #b71c1c) !important; }
        .risk-high { background: linear-gradient(135deg, #ff6b35, #e65100) !important; }
        .risk-medium { background: linear-gradient(135deg, #ffb347, #f57c00) !important; }
        .applications-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .applications-table th, .applications-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .applications-table th { background-color: #0078d4; color: white; font-weight: 600; }
        .applications-table tr:hover { background-color: #f5f5f5; }
        .risk-badge { padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8em; }
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Entra ID App Consent Audit Report</h1>
            <p>Generated on $(Get-Date -Format 'MMMM dd, yyyy at HH:mm:ss')</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>$($Summary.TotalApplications)</h3>
                <p>Total Applications</p>
            </div>
            <div class="summary-card risk-critical">
                <h3>$($Summary.HighRiskApplications)</h3>
                <p>High Risk Apps</p>
            </div>
            <div class="summary-card risk-medium">
                <h3>$($Summary.MediumRiskApplications)</h3>
                <p>Medium Risk Apps</p>
            </div>
            <div class="summary-card risk-high">
                <h3>$($Summary.UnverifiedPublishers)</h3>
                <p>Unverified Publishers</p>
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
        
        <h2>📊 Application Analysis Results</h2>
        <table class="applications-table">
            <thead>
                <tr>
                    <th>Application Name</th>
                    <th>Risk Level</th>
                    <th>Risk Score</th>
                    <th>High Risk Permissions</th>
                    <th>Publisher</th>
                    <th>Last Used</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($app in ($Applications | Sort-Object RiskScore -Descending)) {
        $riskBadgeClass = switch ($app.RiskLevel) {
            "Critical" { "risk-critical-badge" }
            "High" { "risk-high-badge" }
            "Medium" { "risk-medium-badge" }
            "Low" { "risk-low-badge" }
            default { "risk-minimal-badge" }
        }
        
        $lastUsed = if ($app.LastSignIn) { 
            (Get-Date $app.LastSignIn).ToString("yyyy-MM-dd") 
        } else { 
            "Never" 
        }
        
        $status = if ($app.RequiresReview) { "⚠️ Requires Review" } else { "✅ OK" }
        
        $htmlContent += @"
                <tr>
                    <td><strong>$($app.DisplayName)</strong><br><small>$($app.AppId)</small></td>
                    <td><span class="risk-badge $riskBadgeClass">$($app.RiskLevel)</span></td>
                    <td>$($app.RiskScore)/10</td>
                    <td>$($app.HighRiskPermissions)</td>
                    <td>$($app.VerifiedPublisher)</td>
                    <td>$lastUsed</td>
                    <td>$status</td>
                </tr>
"@
    }

    $htmlContent += @"
            </tbody>
        </table>
        
        <div class="timestamp">
            Report generated by Entra ID App Consent Auditor v1.0.0<br>
            Processing completed in $([math]::Round((Get-Date) - $Script:StartTime).TotalSeconds, 2) seconds
        </div>
    </div>
</body>
</html>
"@

    $htmlPath = Join-Path $OutputPath "AppConsentAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    
    Write-LogMessage "HTML report exported to: $htmlPath" "SUCCESS"
    return $htmlPath
}

#endregion

#region Main Execution

function Main {
    try {
        Write-LogMessage "Starting Entra ID App Consent Auditor v1.0.0" "INFO"
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
        
        # Override risk threshold if provided
        if ($RiskThreshold) {
            $Script:Config.AlertThresholds.MinRiskScoreForAlert = $RiskThreshold
        }
        
        # Initialize environment
        Initialize-Environment -Config $Script:Config
        
        # Connect to Microsoft Graph
        if (-not (Connect-ToMicrosoftGraph -TenantId $TenantId)) {
            Write-LogMessage "Failed to connect to Microsoft Graph. Exiting." "ERROR"
            exit 1
        }
        
        # Perform application analysis
        Write-LogMessage "Starting comprehensive application analysis..." "INFO"
        $applications = Get-ApplicationAnalysis -Config $Script:Config
        
        if ($applications.Count -eq 0) {
            Write-LogMessage "No applications found matching the criteria" "WARNING"
            return
        }
        
        # Generate executive summary
        Write-LogMessage "Generating executive summary..." "INFO"
        $summary = Generate-ExecutiveSummary -Applications $applications -Config $Script:Config
        
        # Export reports
        Write-LogMessage "Exporting reports..." "INFO"
        $exportedFiles = @()
        
        $formats = if ($ExportFormat -eq "ALL") { 
            $Script:Config.ExportFormats 
        } else { 
            @($ExportFormat) 
        }
        
        foreach ($format in $formats) {
            switch ($format) {
                "JSON" {
                    $exportedFiles += Export-ToJSON -Applications $applications -Summary $summary -OutputPath $Script:ReportPath
                }
                "CSV" {
                    $exportedFiles += Export-ToCSV -Applications $applications -OutputPath $Script:ReportPath
                }
                "HTML" {
                    $exportedFiles += Export-ToHTML -Applications $applications -Summary $summary -OutputPath $Script:ReportPath
                }
            }
        }
        
        # Final summary
        $duration = (Get-Date) - $Script:StartTime
        Write-LogMessage "================================================" "SUCCESS"
        Write-LogMessage "Entra ID App Consent Audit Completed Successfully!" "SUCCESS"
        Write-LogMessage "================================================" "SUCCESS"
        Write-LogMessage "Processing Time: $([math]::Round($duration.TotalSeconds, 2)) seconds" "INFO"
        Write-LogMessage "Applications Processed: $($Script:ProcessedApps)" "INFO"
        Write-LogMessage "Applications Analyzed: $($applications.Count)" "INFO"
        Write-LogMessage "High-Risk Applications: $($Script:HighRiskApps)" "INFO"
        Write-LogMessage "Reports Generated: $($exportedFiles.Count)" "INFO"
        
        Write-LogMessage "`nGenerated Reports:" "INFO"
        foreach ($file in $exportedFiles) {
            Write-LogMessage "  • $file" "SUCCESS"
        }
        
        # Display key findings
        if ($summary.HighRiskApplications -gt 0) {
            Write-LogMessage "`n⚠️  SECURITY ALERT: $($summary.HighRiskApplications) high-risk applications detected!" "WARNING"
        }
        
        if ($summary.UnverifiedPublishers -gt 0) {
            Write-LogMessage "⚠️  WARNING: $($summary.UnverifiedPublishers) applications from unverified publishers" "WARNING"
        }
        
        if ($summary.UnusedApplications -gt 0) {
            Write-LogMessage "ℹ️  INFO: $($summary.UnusedApplications) unused applications found" "INFO"
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
