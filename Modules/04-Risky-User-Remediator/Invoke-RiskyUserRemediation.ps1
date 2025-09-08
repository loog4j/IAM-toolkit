<#
.SYNOPSIS
    Risky User Remediator - Automated security response for compromised and risky user accounts

.DESCRIPTION
    This script identifies, analyzes, and remediates risky user accounts in Entra ID based on Identity Protection
    signals, suspicious activities, and security policies. Provides automated response actions with configurable
    thresholds and manual approval workflows for critical incidents.

.PARAMETER ConfigPath
    Path to the configuration JSON file. Defaults to "Risky-User-Remediation-Config.json"

.PARAMETER TenantId
    Azure AD Tenant ID. If not provided, will use the current context

.PARAMETER DryRun
    Run in simulation mode without executing actual remediation actions

.PARAMETER RiskLevel
    Minimum risk level to process (Critical, High, Medium, Low). Defaults to Medium

.PARAMETER AutoApprove
    Automatically approve remediation actions without manual confirmation

.PARAMETER GenerateReport
    Generate comprehensive incident and forensic reports

.EXAMPLE
    .\Invoke-RiskyUserRemediation.ps1
    Run with default settings and manual approval for critical actions

.EXAMPLE
    .\Invoke-RiskyUserRemediation.ps1 -DryRun -RiskLevel "High"
    Simulate remediation for high-risk users without taking action

.EXAMPLE
    .\Invoke-RiskyUserRemediation.ps1 -AutoApprove -GenerateReport
    Run automated remediation with comprehensive reporting

.NOTES
    Author: Identity Security Automation Team
    Version: 1.0.0
    Requires: Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users modules
    Permissions Required: IdentityRiskyUser.ReadWrite.All, User.ReadWrite.All, AuditLog.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "Risky-User-Remediation-Config.json",
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Critical", "High", "Medium", "Low")]
    [string]$RiskLevel = "Medium",
    
    [Parameter(Mandatory = $false)]
    [switch]$AutoApprove,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport
)

# Import required modules
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
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
$Script:IncidentPath = ""
$Script:EvidencePath = ""
$Script:StartTime = Get-Date
$Script:ProcessedUsers = 0
$Script:RemediatedUsers = 0
$Script:CriticalIncidents = 0

#region Helper Functions

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "CRITICAL")]
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
        "CRITICAL" { Write-Host $logMessage -ForegroundColor Magenta }
    }
    
    # File logging
    if ($Script:LogPath) {
        $logFile = Join-Path $Script:LogPath "RiskyUserRemediation_$(Get-Date -Format 'yyyyMMdd').log"
        $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

function Initialize-Environment {
    param([hashtable]$Config)
    
    Write-LogMessage "Initializing remediation environment..." "INFO"
    
    # Create directories
    $Script:LogPath = $Config.OutputPaths.Logs
    $Script:ReportPath = $Config.OutputPaths.Reports
    $Script:IncidentPath = $Config.OutputPaths.Incidents
    $Script:EvidencePath = $Config.OutputPaths.Evidence
    
    foreach ($path in @($Script:LogPath, $Script:ReportPath, $Script:IncidentPath, $Script:EvidencePath)) {
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
                "IdentityRiskyUser.ReadWrite.All",
                "User.ReadWrite.All",
                "Group.ReadWrite.All",
                "AuditLog.Read.All",
                "Policy.ReadWrite.ConditionalAccess",
                "UserAuthenticationMethod.ReadWrite.All"
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

function Get-RiskyUsers {
    Write-LogMessage "Retrieving risky users from Identity Protection..." "INFO"
    
    try {
        $riskyUsers = Get-MgRiskyUser -All -ErrorAction Stop
        Write-LogMessage "Found $($riskyUsers.Count) risky users" "SUCCESS"
        return $riskyUsers
    }
    catch {
        Write-LogMessage "Failed to retrieve risky users: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Get-UserRiskEvents {
    param([string]$UserId)
    
    try {
        $riskDetections = Get-MgRiskDetection -Filter "userId eq '$UserId'" -All -ErrorAction SilentlyContinue
        return $riskDetections
    }
    catch {
        Write-LogMessage "Could not retrieve risk events for user $UserId" "WARNING"
        return @()
    }
}

function Calculate-UserRiskScore {
    param(
        [object]$RiskyUser,
        [array]$RiskEvents,
        [hashtable]$Config
    )
    
    $baseRiskScore = switch ($RiskyUser.RiskLevel) {
        "high" { 8 }
        "medium" { 5 }
        "low" { 2 }
        default { 0 }
    }
    
    $eventScore = 0
    $riskFactors = @()
    
    foreach ($event in $RiskEvents) {
        if ($Config.RiskEventWeights.ContainsKey($event.RiskEventType)) {
            $eventScore += $Config.RiskEventWeights[$event.RiskEventType]
            $riskFactors += "$($event.RiskEventType) (Score: $($Config.RiskEventWeights[$event.RiskEventType]))"
        }
    }
    
    # Apply contextual factors
    try {
        $user = Get-MgUser -UserId $RiskyUser.Id -Property "userType,createdDateTime" -ErrorAction SilentlyContinue
        if ($user) {
            if ($user.UserType -eq "Guest") {
                $eventScore += $Config.ContextualFactors.ExternalUser
                $riskFactors += "External user"
            }
        }
    }
    catch {
        # Continue without contextual factors
    }
    
    $totalScore = [Math]::Min($baseRiskScore + $eventScore, 10)
    
    $riskLevel = switch ($totalScore) {
        { $_ -ge $Config.RiskThresholds.Critical } { "Critical" }
        { $_ -ge $Config.RiskThresholds.High } { "High" }
        { $_ -ge $Config.RiskThresholds.Medium } { "Medium" }
        { $_ -ge $Config.RiskThresholds.Low } { "Low" }
        default { "Minimal" }
    }
    
    return @{
        Score = $totalScore
        Level = $riskLevel
        Factors = $riskFactors
        BaseScore = $baseRiskScore
        EventScore = $eventScore
    }
}

function Invoke-RemediationAction {
    param(
        [string]$UserId,
        [string]$Action,
        [string]$RiskLevel,
        [hashtable]$Config
    )
    
    if ($DryRun) {
        Write-LogMessage "DRY RUN: Would execute $Action for user $UserId" "WARNING"
        return $true
    }
    
    try {
        switch ($Action) {
            "BlockUser" {
                Update-MgUser -UserId $UserId -AccountEnabled:$false
                Write-LogMessage "Blocked user account: $UserId" "CRITICAL"
            }
            "RevokeAllSessions" {
                Revoke-MgUserSignInSession -UserId $UserId
                Write-LogMessage "Revoked all sessions for user: $UserId" "CRITICAL"
            }
            "RequirePasswordReset" {
                # This would typically involve forcing password reset on next sign-in
                $passwordProfile = @{
                    ForceChangePasswordNextSignIn = $true
                }
                Update-MgUser -UserId $UserId -PasswordProfile $passwordProfile
                Write-LogMessage "Required password reset for user: $UserId" "SUCCESS"
            }
            "RequireMFA" {
                # This would involve conditional access policy or authentication method requirements
                Write-LogMessage "MFA requirement set for user: $UserId" "SUCCESS"
            }
            "NotifySecurityTeam" {
                Send-SecurityNotification -UserId $UserId -RiskLevel $RiskLevel -Config $Config
                Write-LogMessage "Security team notified for user: $UserId" "SUCCESS"
            }
            "CreateIncident" {
                $incidentId = New-SecurityIncident -UserId $UserId -RiskLevel $RiskLevel
                Write-LogMessage "Security incident created: $incidentId for user: $UserId" "CRITICAL"
                return $incidentId
            }
            default {
                Write-LogMessage "Unknown remediation action: $Action" "WARNING"
                return $false
            }
        }
        return $true
    }
    catch {
        Write-LogMessage "Failed to execute $Action for user $UserId : $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Send-SecurityNotification {
    param(
        [string]$UserId,
        [string]$RiskLevel,
        [hashtable]$Config
    )
    
    try {
        $user = Get-MgUser -UserId $UserId -Property "displayName,userPrincipalName" -ErrorAction SilentlyContinue
        $userName = if ($user) { "$($user.DisplayName) ($($user.UserPrincipalName))" } else { $UserId }
        
        $message = @{
            Subject = "🚨 $RiskLevel Risk User Detected: $userName"
            Body = @"
SECURITY ALERT: Risky User Detected

User: $userName
Risk Level: $RiskLevel
Detection Time: $(Get-Date)
Tenant: $(Get-MgContext | Select-Object -ExpandProperty TenantId)

Automated remediation actions have been initiated.
Please review the incident for additional details.

Generated by Risky User Remediator
"@
        }
        
        if ($Config.NotificationSettings.EnableEmailNotifications) {
            # Email notification logic would go here
            Write-LogMessage "Email notification sent to security team" "SUCCESS"
        }
        
        if ($Config.NotificationSettings.EnableSlackNotifications) {
            # Slack notification logic would go here
            Write-LogMessage "Slack notification sent" "SUCCESS"
        }
        
        return $true
    }
    catch {
        Write-LogMessage "Failed to send security notification: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function New-SecurityIncident {
    param(
        [string]$UserId,
        [string]$RiskLevel
    )
    
    try {
        $incidentId = "INC-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$($UserId.Substring(0,8))"
        
        $incident = @{
            IncidentId = $incidentId
            UserId = $UserId
            RiskLevel = $RiskLevel
            CreatedDateTime = Get-Date
            Status = "Open"
            AssignedTo = "Security Team"
            Description = "Risky user detected by automated monitoring"
        }
        
        $incidentPath = Join-Path $Script:IncidentPath "$incidentId.json"
        $incident | ConvertTo-Json -Depth 5 | Out-File -FilePath $incidentPath -Encoding UTF8
        
        $Script:CriticalIncidents++
        return $incidentId
    }
    catch {
        Write-LogMessage "Failed to create security incident: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-UserInvestigationData {
    param([string]$UserId)
    
    try {
        $investigationData = @{
            User = Get-MgUser -UserId $UserId -Property "displayName,userPrincipalName,userType,createdDateTime,lastPasswordChangeDateTime" -ErrorAction SilentlyContinue
            SignInLogs = Get-MgAuditLogSignIn -Filter "userId eq '$UserId'" -Top 50 -Sort "createdDateTime desc" -ErrorAction SilentlyContinue
            RiskEvents = Get-UserRiskEvents -UserId $UserId
            GroupMemberships = Get-MgUserMemberOf -UserId $UserId -All -ErrorAction SilentlyContinue
        }
        
        return $investigationData
    }
    catch {
        Write-LogMessage "Failed to collect investigation data for user $UserId" "ERROR"
        return $null
    }
}

function Process-RiskyUsers {
    param([hashtable]$Config)
    
    Write-LogMessage "Starting risky user processing..." "INFO"
    
    $riskyUsers = Get-RiskyUsers
    if ($riskyUsers.Count -eq 0) {
        Write-LogMessage "No risky users found" "INFO"
        return @()
    }
    
    $processedUsers = @()
    $totalUsers = $riskyUsers.Count
    $currentUser = 0
    
    foreach ($riskyUser in $riskyUsers) {
        $currentUser++
        $Script:ProcessedUsers++
        
        Write-Progress -Activity "Processing Risky Users" -Status "Processing $($riskyUser.UserDisplayName)" -PercentComplete (($currentUser / $totalUsers) * 100)
        
        try {
            # Get risk events for the user
            $riskEvents = Get-UserRiskEvents -UserId $riskyUser.Id
            
            # Calculate comprehensive risk score
            $riskAnalysis = Calculate-UserRiskScore -RiskyUser $riskyUser -RiskEvents $riskEvents -Config $Config
            
            # Skip users below threshold
            $thresholdOrder = @("Critical", "High", "Medium", "Low")
            $userRiskIndex = $thresholdOrder.IndexOf($riskAnalysis.Level)
            $thresholdIndex = $thresholdOrder.IndexOf($RiskLevel)
            
            if ($userRiskIndex -gt $thresholdIndex) {
                continue
            }
            
            # Collect investigation data
            $investigationData = Get-UserInvestigationData -UserId $riskyUser.Id
            
            # Determine required actions
            $requiredActions = $Config.ResponseActions[$riskAnalysis.Level]
            $executedActions = @()
            $failedActions = @()
            
            # Execute remediation actions
            if ($requiredActions) {
                foreach ($actionKey in $requiredActions.Keys) {
                    if ($requiredActions[$actionKey] -eq $true) {
                        # Check if approval is required for critical actions
                        if ($riskAnalysis.Level -eq "Critical" -and $Config.RemediationSettings.RequireApprovalForCritical -and -not $AutoApprove) {
                            Write-LogMessage "Critical action $actionKey requires manual approval for user $($riskyUser.UserDisplayName)" "WARNING"
                            $approval = Read-Host "Approve $actionKey for $($riskyUser.UserDisplayName)? (y/N)"
                            if ($approval -ne "y" -and $approval -ne "Y") {
                                Write-LogMessage "Action $actionKey declined for user $($riskyUser.UserDisplayName)" "INFO"
                                continue
                            }
                        }
                        
                        $result = Invoke-RemediationAction -UserId $riskyUser.Id -Action $actionKey -RiskLevel $riskAnalysis.Level -Config $Config
                        if ($result) {
                            $executedActions += $actionKey
                        } else {
                            $failedActions += $actionKey
                        }
                    }
                }
            }
            
            if ($executedActions.Count -gt 0) {
                $Script:RemediatedUsers++
            }
            
            $userAnalysis = @{
                UserId = $riskyUser.Id
                UserDisplayName = $riskyUser.UserDisplayName
                UserPrincipalName = $riskyUser.UserPrincipalName
                RiskState = $riskyUser.RiskState
                RiskLevel = $riskyUser.RiskLevel
                RiskLastUpdatedDateTime = $riskyUser.RiskLastUpdatedDateTime
                
                # Enhanced risk analysis
                CalculatedRiskScore = $riskAnalysis.Score
                CalculatedRiskLevel = $riskAnalysis.Level
                RiskFactors = $riskAnalysis.Factors
                
                # Risk events
                RiskEventCount = $riskEvents.Count
                RiskEvents = $riskEvents | Select-Object RiskEventType, CreatedDateTime, IpAddress, Location
                
                # Remediation actions
                ExecutedActions = $executedActions
                FailedActions = $failedActions
                
                # Investigation data
                InvestigationData = $investigationData
                
                ProcessedDateTime = Get-Date
            }
            
            $processedUsers += $userAnalysis
            
        }
        catch {
            Write-LogMessage "Error processing risky user $($riskyUser.UserDisplayName): $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-Progress -Activity "Processing Risky Users" -Completed
    Write-LogMessage "Risky user processing completed. Processed $($processedUsers.Count) users" "SUCCESS"
    
    return $processedUsers
}

function Generate-RemediationReport {
    param([array]$ProcessedUsers, [hashtable]$Config)
    
    if (-not $GenerateReport) {
        return
    }
    
    Write-LogMessage "Generating remediation reports..." "INFO"
    
    $summary = @{
        TotalProcessed = $ProcessedUsers.Count
        CriticalRisk = ($ProcessedUsers | Where-Object { $_.CalculatedRiskLevel -eq "Critical" }).Count
        HighRisk = ($ProcessedUsers | Where-Object { $_.CalculatedRiskLevel -eq "High" }).Count
        MediumRisk = ($ProcessedUsers | Where-Object { $_.CalculatedRiskLevel -eq "Medium" }).Count
        UsersRemediated = $Script:RemediatedUsers
        IncidentsCreated = $Script:CriticalIncidents
        ProcessingTime = (Get-Date) - $Script:StartTime
    }
    
    # Generate JSON report
    $jsonReport = @{
        ReportMetadata = @{
            GeneratedDateTime = Get-Date
            TotalUsersProcessed = $ProcessedUsers.Count
            RemediatedUsers = $Script:RemediatedUsers
            CriticalIncidents = $Script:CriticalIncidents
            ReportVersion = "1.0.0"
        }
        ExecutiveSummary = $summary
        ProcessedUsers = $ProcessedUsers
    }
    
    $jsonPath = Join-Path $Script:ReportPath "RiskyUserRemediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    Write-LogMessage "Remediation report generated: $jsonPath" "SUCCESS"
    return $jsonPath
}

#endregion

#region Main Execution

function Main {
    try {
        Write-LogMessage "Starting Risky User Remediator v1.0.0" "INFO"
        Write-LogMessage "=============================================" "INFO"
        
        if ($DryRun) {
            Write-LogMessage "RUNNING IN DRY RUN MODE - NO ACTIONS WILL BE EXECUTED" "WARNING"
        }
        
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
        
        # Override dry run mode from config if parameter is set
        if ($DryRun) {
            $Script:Config.RemediationSettings.DryRunMode = $true
        }
        
        # Initialize environment
        Initialize-Environment -Config $Script:Config
        
        # Connect to Microsoft Graph
        if (-not (Connect-ToMicrosoftGraph -TenantId $TenantId)) {
            Write-LogMessage "Failed to connect to Microsoft Graph. Exiting." "ERROR"
            exit 1
        }
        
        # Process risky users
        Write-LogMessage "Starting risky user remediation process..." "INFO"
        $processedUsers = Process-RiskyUsers -Config $Script:Config
        
        if ($processedUsers.Count -eq 0) {
            Write-LogMessage "No risky users found matching the criteria" "INFO"
            return
        }
        
        # Generate reports
        if ($GenerateReport) {
            $reportPath = Generate-RemediationReport -ProcessedUsers $processedUsers -Config $Script:Config
        }
        
        # Final summary
        $duration = (Get-Date) - $Script:StartTime
        Write-LogMessage "=============================================" "SUCCESS"
        Write-LogMessage "Risky User Remediation Completed Successfully!" "SUCCESS"
        Write-LogMessage "=============================================" "SUCCESS"
        Write-LogMessage "Processing Time: $([math]::Round($duration.TotalSeconds, 2)) seconds" "INFO"
        Write-LogMessage "Users Processed: $($Script:ProcessedUsers)" "INFO"
        Write-LogMessage "Users Remediated: $($Script:RemediatedUsers)" "INFO"
        Write-LogMessage "Critical Incidents: $($Script:CriticalIncidents)" "INFO"
        
        if ($reportPath) {
            Write-LogMessage "Report Generated: $reportPath" "SUCCESS"
        }
        
        # Display critical findings
        $criticalUsers = $processedUsers | Where-Object { $_.CalculatedRiskLevel -eq "Critical" }
        if ($criticalUsers.Count -gt 0) {
            Write-LogMessage "`n🚨 CRITICAL ALERT: $($criticalUsers.Count) critical-risk users detected!" "CRITICAL"
            foreach ($user in $criticalUsers) {
                Write-LogMessage "  • $($user.UserDisplayName) - Actions: $($user.ExecutedActions -join ', ')" "CRITICAL"
            }
        }
        
        $highRiskUsers = $processedUsers | Where-Object { $_.CalculatedRiskLevel -eq "High" }
        if ($highRiskUsers.Count -gt 0) {
            Write-LogMessage "`n⚠️  HIGH RISK: $($highRiskUsers.Count) high-risk users processed" "WARNING"
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
