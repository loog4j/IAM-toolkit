<#
.SYNOPSIS
    Export and audit Conditional Access policies from Entra ID
.DESCRIPTION
    Exports Conditional Access policies, analyzes them for security gaps, compliance issues,
    and generates comprehensive reports in multiple formats (JSON, CSV, HTML).
.PARAMETER ConfigPath
    Path to the JSON configuration file
.PARAMETER OutputFormat
    Output format for the report: JSON, CSV, HTML, or All
.PARAMETER IncludeDisabled
    Include disabled policies in the analysis
.PARAMETER AnalysisOnly
    Perform analysis only without exporting raw policy data
.PARAMETER LogLevel
    Logging level: INFO, WARNING, ERROR, DEBUG
.EXAMPLE
    .\Export-ConditionalAccessPolicies.ps1 -OutputFormat "HTML"
.EXAMPLE
    .\Export-ConditionalAccessPolicies.ps1 -OutputFormat "All" -IncludeDisabled
.NOTES
    Author: Identity Security Automation Project
    Version: 1.0
    Requires: PowerShell 5.1+, Microsoft.Graph.Identity.SignIns module
    Permissions: Policy.Read.All, Directory.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Path to JSON configuration file")]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "Configuration file not found: $_"
        }
        return $true
    })]
    [string]$ConfigPath = ".\CA-Policy-Audit-Config.json",
    
    [Parameter(Mandatory = $false, HelpMessage = "Output format for reports")]
    [ValidateSet("JSON", "CSV", "HTML", "All")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory = $false, HelpMessage = "Include disabled policies in analysis")]
    [switch]$IncludeDisabled,
    
    [Parameter(Mandatory = $false, HelpMessage = "Perform analysis only without raw export")]
    [switch]$AnalysisOnly,
    
    [Parameter(Mandatory = $false, HelpMessage = "Logging level")]
    [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
    [string]$LogLevel = "INFO"
)

# Global variables
$script:Config = $null
$script:LogPath = $null
$script:StartTime = Get-Date
$script:Policies = @()
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
        $logDir = $Config.LogPath
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            Write-Log "Created log directory: $logDir" "DEBUG"
        }
        
        $script:LogPath = Join-Path $logDir "CA-PolicyAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
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
    
    # Check for required modules
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Identity.SignIns"
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

function Connect-ToMicrosoftGraph {
    Write-Log "Connecting to Microsoft Graph..." "INFO"
    
    try {
        # Required scopes for Conditional Access policy reading
        $scopes = @(
            "Policy.Read.All",
            "Directory.Read.All",
            "Application.Read.All"
        )
        
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
        
        # Verify connection
        $context = Get-MgContext
        Write-Log "✅ Connected to Microsoft Graph" "SUCCESS"
        Write-Log "Tenant: $($context.TenantId)" "INFO"
        Write-Log "Account: $($context.Account)" "INFO"
        
        return $true
    }
    catch {
        Write-Log "❌ Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-ConditionalAccessPolicies {
    Write-Log "Retrieving Conditional Access policies..." "INFO"
    
    try {
        # Get all Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
        
        Write-Log "📊 Retrieved $($policies.Count) Conditional Access policies" "INFO"
        
        # Filter based on configuration
        if (-not $IncludeDisabled -and -not $script:Config.IncludeDisabledPolicies) {
            $enabledPolicies = $policies | Where-Object { $_.State -eq "enabled" }
            Write-Log "📊 Filtered to $($enabledPolicies.Count) enabled policies" "INFO"
            return $enabledPolicies
        }
        
        return $policies
    }
    catch {
        Write-Log "❌ Failed to retrieve Conditional Access policies: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Analyze-PolicyCompliance {
    param([array]$Policies)
    
    Write-Log "Analyzing policy compliance..." "INFO"
    
    $complianceResults = @{
        RequireMFAForAdmins = $false
        BlockLegacyAuth = $false
        RequireCompliantDevice = $false
        RequireApprovedApp = $false
        BlockHighRiskSignIns = $false
        RequirePasswordChange = $false
        BlockUnknownPlatforms = $false
        ComplianceScore = 0
        Issues = @()
        Recommendations = @()
    }
    
    # Check for MFA requirement for administrators
    $mfaAdminPolicies = $Policies | Where-Object {
        $_.Conditions.Users.IncludeRoles -and
        $_.GrantControls.BuiltInControls -contains "mfa" -and
        $_.State -eq "enabled"
    }
    
    if ($mfaAdminPolicies.Count -gt 0) {
        $complianceResults.RequireMFAForAdmins = $true
        $complianceResults.ComplianceScore += 20
        Write-Log "✅ MFA for administrators: COMPLIANT" "SUCCESS"
    } else {
        $complianceResults.Issues += "No MFA requirement found for administrator roles"
        $complianceResults.Recommendations += "Create policy to require MFA for all administrator roles"
        Write-Log "❌ MFA for administrators: NON-COMPLIANT" "WARNING"
    }
    
    # Check for legacy authentication blocking
    $legacyAuthPolicies = $Policies | Where-Object {
        $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
        $_.Conditions.ClientAppTypes -contains "other" -and
        $_.GrantControls.BuiltInControls -contains "block" -and
        $_.State -eq "enabled"
    }
    
    if ($legacyAuthPolicies.Count -gt 0) {
        $complianceResults.BlockLegacyAuth = $true
        $complianceResults.ComplianceScore += 25
        Write-Log "✅ Legacy authentication blocking: COMPLIANT" "SUCCESS"
    } else {
        $complianceResults.Issues += "Legacy authentication is not blocked"
        $complianceResults.Recommendations += "Create policy to block legacy authentication protocols"
        Write-Log "❌ Legacy authentication blocking: NON-COMPLIANT" "WARNING"
    }
    
    # Check for device compliance requirements
    $deviceCompliancePolicies = $Policies | Where-Object {
        $_.GrantControls.BuiltInControls -contains "compliantDevice" -and
        $_.State -eq "enabled"
    }
    
    if ($deviceCompliancePolicies.Count -gt 0) {
        $complianceResults.RequireCompliantDevice = $true
        $complianceResults.ComplianceScore += 15
        Write-Log "✅ Device compliance requirement: COMPLIANT" "SUCCESS"
    } else {
        $complianceResults.Issues += "No device compliance requirement found"
        $complianceResults.Recommendations += "Consider requiring compliant devices for sensitive applications"
        Write-Log "⚠️ Device compliance requirement: MISSING" "WARNING"
    }
    
    # Check for approved client app requirements
    $approvedAppPolicies = $Policies | Where-Object {
        $_.GrantControls.BuiltInControls -contains "approvedApplication" -and
        $_.State -eq "enabled"
    }
    
    if ($approvedAppPolicies.Count -gt 0) {
        $complianceResults.RequireApprovedApp = $true
        $complianceResults.ComplianceScore += 10
        Write-Log "✅ Approved client apps requirement: COMPLIANT" "SUCCESS"
    } else {
        $complianceResults.Recommendations += "Consider requiring approved client applications"
        Write-Log "⚠️ Approved client apps requirement: MISSING" "WARNING"
    }
    
    # Check for high-risk sign-in blocking
    $riskPolicies = $Policies | Where-Object {
        $_.Conditions.SignInRiskLevels -contains "high" -and
        $_.GrantControls.BuiltInControls -contains "block" -and
        $_.State -eq "enabled"
    }
    
    if ($riskPolicies.Count -gt 0) {
        $complianceResults.BlockHighRiskSignIns = $true
        $complianceResults.ComplianceScore += 20
        Write-Log "✅ High-risk sign-in blocking: COMPLIANT" "SUCCESS"
    } else {
        $complianceResults.Issues += "High-risk sign-ins are not blocked"
        $complianceResults.Recommendations += "Create policy to block high-risk sign-ins"
        Write-Log "❌ High-risk sign-in blocking: NON-COMPLIANT" "WARNING"
    }
    
    # Calculate final compliance percentage
    $maxScore = 90 # Total possible points
    $compliancePercentage = [math]::Round(($complianceResults.ComplianceScore / $maxScore) * 100, 2)
    
    Write-Log "📊 Overall compliance score: $compliancePercentage% ($($complianceResults.ComplianceScore)/$maxScore)" "INFO"
    
    return $complianceResults
}

function Analyze-PolicyRisks {
    param([array]$Policies)
    
    Write-Log "Analyzing policy risks..." "INFO"
    
    $riskResults = @{
        HighRiskPolicies = @()
        ConflictingPolicies = @()
        OverlyBroadPolicies = @()
        RiskScore = 0
        Warnings = @()
    }
    
    foreach ($policy in $Policies) {
        $policyRisk = @{
            PolicyName = $policy.DisplayName
            PolicyId = $policy.Id
            RiskLevel = "Low"
            RiskFactors = @()
        }
        
        # Check for overly broad user targeting
        if ($policy.Conditions.Users.IncludeUsers -contains "All") {
            $policyRisk.RiskFactors += "Targets all users"
            $policyRisk.RiskLevel = "High"
            $riskResults.RiskScore += 10
        }
        
        # Check for overly broad application targeting
        if ($policy.Conditions.Applications.IncludeApplications -contains "All") {
            $policyRisk.RiskFactors += "Targets all applications"
            $policyRisk.RiskLevel = "High"
            $riskResults.RiskScore += 10
        }
        
        # Check for any location (including untrusted)
        if ($policy.Conditions.Locations.IncludeLocations -contains "All") {
            $policyRisk.RiskFactors += "Allows access from any location"
            if ($policyRisk.RiskLevel -ne "High") {
                $policyRisk.RiskLevel = "Medium"
            }
            $riskResults.RiskScore += 5
        }
        
        # Check for block controls without proper conditions
        if ($policy.GrantControls.BuiltInControls -contains "block" -and 
            $policy.Conditions.Users.IncludeUsers -contains "All") {
            $policyRisk.RiskFactors += "Blocks all users - potential lockout risk"
            $policyRisk.RiskLevel = "Critical"
            $riskResults.RiskScore += 20
        }
        
        # Add to appropriate risk categories
        if ($policyRisk.RiskLevel -in @("High", "Critical")) {
            $riskResults.HighRiskPolicies += $policyRisk
        }
        
        if ($policyRisk.RiskFactors -contains "Targets all users" -or 
            $policyRisk.RiskFactors -contains "Targets all applications") {
            $riskResults.OverlyBroadPolicies += $policyRisk
        }
    }
    
    Write-Log "📊 Risk analysis complete. Risk score: $($riskResults.RiskScore)" "INFO"
    Write-Log "⚠️ High-risk policies found: $($riskResults.HighRiskPolicies.Count)" "WARNING"
    Write-Log "📢 Overly broad policies found: $($riskResults.OverlyBroadPolicies.Count)" "WARNING"
    
    return $riskResults
}

function Export-PolicyData {
    param(
        [array]$Policies,
        [string]$Format,
        [string]$OutputPath
    )
    
    Write-Log "Exporting policy data in $Format format..." "INFO"
    
    try {
        switch ($Format.ToUpper()) {
            "JSON" {
                $jsonPath = Join-Path $OutputPath "CA-Policies_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
                $Policies | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
                Write-Log "✅ JSON export saved: $jsonPath" "SUCCESS"
            }
            
            "CSV" {
                $csvPath = Join-Path $OutputPath "CA-Policies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                $simplifiedPolicies = $Policies | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime,
                    @{Name="TargetUsers"; Expression={($_.Conditions.Users.IncludeUsers -join "; ")}},
                    @{Name="TargetApps"; Expression={($_.Conditions.Applications.IncludeApplications -join "; ")}},
                    @{Name="GrantControls"; Expression={($_.GrantControls.BuiltInControls -join "; ")}}
                
                $simplifiedPolicies | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Log "✅ CSV export saved: $csvPath" "SUCCESS"
            }
            
            "HTML" {
                $htmlPath = Join-Path $OutputPath "CA-Policies-Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                Generate-HTMLReport -Policies $Policies -OutputPath $htmlPath
                Write-Log "✅ HTML report saved: $htmlPath" "SUCCESS"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "❌ Failed to export $Format data: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Generate-HTMLReport {
    param(
        [array]$Policies,
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Conditional Access Policy Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .policy { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .enabled { border-left: 5px solid #28a745; }
        .disabled { border-left: 5px solid #dc3545; }
        .risk-high { background-color: #f8d7da; }
        .risk-medium { background-color: #fff3cd; }
        .risk-low { background-color: #d1ecf1; }
        .compliance-good { color: #28a745; }
        .compliance-bad { color: #dc3545; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Conditional Access Policy Audit Report</h1>
        <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p>Total Policies: $($Policies.Count)</p>
    </div>
    
    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <p><strong>Enabled Policies:</strong> $(($Policies | Where-Object {$_.State -eq 'enabled'}).Count)</p>
        <p><strong>Disabled Policies:</strong> $(($Policies | Where-Object {$_.State -eq 'disabled'}).Count)</p>
        <p><strong>Report Only Policies:</strong> $(($Policies | Where-Object {$_.State -eq 'enabledForReportingButNotEnforced'}).Count)</p>
    </div>
    
    <div class="summary">
        <h2>🔍 Compliance Analysis</h2>
        <p class="compliance-good">✅ Compliant Areas: $($script:AnalysisResults.Compliance.ComplianceScore) points</p>
        <p class="compliance-bad">❌ Issues Found: $($script:AnalysisResults.Compliance.Issues.Count)</p>
        <p>📋 Recommendations: $($script:AnalysisResults.Compliance.Recommendations.Count)</p>
    </div>
    
    <h2>📋 Policy Details</h2>
"@
    
    foreach ($policy in $Policies) {
        $stateClass = if ($policy.State -eq "enabled") { "enabled" } else { "disabled" }
        $html += @"
    <div class="policy $stateClass">
        <h3>$($policy.DisplayName)</h3>
        <p><strong>State:</strong> $($policy.State)</p>
        <p><strong>Created:</strong> $($policy.CreatedDateTime)</p>
        <p><strong>Modified:</strong> $($policy.ModifiedDateTime)</p>
        <p><strong>Target Users:</strong> $($policy.Conditions.Users.IncludeUsers -join ', ')</p>
        <p><strong>Target Applications:</strong> $($policy.Conditions.Applications.IncludeApplications -join ', ')</p>
        <p><strong>Grant Controls:</strong> $($policy.GrantControls.BuiltInControls -join ', ')</p>
    </div>
"@
    }
    
    $html += @"
    <div class="summary">
        <h2>📈 Recommendations</h2>
        <ul>
"@
    
    foreach ($recommendation in $script:AnalysisResults.Compliance.Recommendations) {
        $html += "<li>$recommendation</li>"
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
        [int]$TotalPolicies,
        [int]$EnabledPolicies,
        [object]$ComplianceResults,
        [object]$RiskResults,
        [datetime]$StartTime
    )
    
    $duration = (Get-Date) - $StartTime
    
    Write-Log "" "INFO"
    Write-Log "═══════════════════════════════════════" "INFO"
    Write-Log "      CONDITIONAL ACCESS AUDIT SUMMARY  " "INFO"
    Write-Log "═══════════════════════════════════════" "INFO"
    Write-Log "📊 Total policies analyzed: $TotalPolicies" "INFO"
    Write-Log "✅ Enabled policies: $EnabledPolicies" "SUCCESS"
    Write-Log "🔒 Compliance score: $($ComplianceResults.ComplianceScore)%" "INFO"
    Write-Log "⚠️ Risk score: $($RiskResults.RiskScore)" "WARNING"
    Write-Log "❌ Issues found: $($ComplianceResults.Issues.Count)" "ERROR"
    Write-Log "💡 Recommendations: $($ComplianceResults.Recommendations.Count)" "INFO"
    Write-Log "⏱️ Analysis duration: $($duration.ToString('hh\:mm\:ss'))" "INFO"
    Write-Log "📄 Log file: $script:LogPath" "INFO"
    Write-Log "═══════════════════════════════════════" "INFO"
}

#endregion

#region Main Execution

try {
    Write-Log "🚀 Starting Conditional Access Policy Audit" "INFO"
    Write-Log "⚙️ Config File: $ConfigPath" "INFO"
    Write-Log "📊 Output Format: $OutputFormat" "INFO"
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
    
    # Connect to Microsoft Graph
    if (-not (Connect-ToMicrosoftGraph)) {
        Write-Log "❌ Failed to connect to Microsoft Graph. Exiting." "ERROR"
        exit 1
    }
    
    # Get Conditional Access policies
    $script:Policies = Get-ConditionalAccessPolicies
    if ($script:Policies.Count -eq 0) {
        Write-Log "❌ No Conditional Access policies found. Exiting." "ERROR"
        exit 1
    }
    
    # Perform analysis
    Write-Log "🔍 Starting policy analysis..." "INFO"
    $complianceResults = Analyze-PolicyCompliance -Policies $script:Policies
    $riskResults = Analyze-PolicyRisks -Policies $script:Policies
    
    # Store analysis results
    $script:AnalysisResults = @{
        Compliance = $complianceResults
        Risk = $riskResults
    }
    
    # Create output directory
    $outputDir = $script:Config.ReportPath
    if (-not (Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        Write-Log "Created output directory: $outputDir" "DEBUG"
    }
    
    # Export data based on format selection
    if (-not $AnalysisOnly) {
        if ($OutputFormat -eq "All") {
            foreach ($format in $script:Config.ExportFormats) {
                Export-PolicyData -Policies $script:Policies -Format $format -OutputPath $outputDir
            }
        }
        else {
            Export-PolicyData -Policies $script:Policies -Format $OutputFormat -OutputPath $outputDir
        }
    }
    
    # Show summary
    $enabledCount = ($script:Policies | Where-Object { $_.State -eq "enabled" }).Count
    Show-Summary -TotalPolicies $script:Policies.Count -EnabledPolicies $enabledCount -ComplianceResults $complianceResults -RiskResults $riskResults -StartTime $script:StartTime
    
    # Set exit code based on compliance
    if ($complianceResults.Issues.Count -gt 0 -or $riskResults.RiskScore -gt 50) {
        Write-Log "⚠️ Audit completed with issues or high risk score" "WARNING"
        exit 1
    }
    else {
        Write-Log "✅ Audit completed successfully" "SUCCESS"
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
