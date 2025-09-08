<#
.SYNOPSIS
    Dynamic Group Rule Validator - Validates and optimizes Entra ID dynamic group membership rules

.DESCRIPTION
    This script validates dynamic group membership rules for syntax, logic, performance, and security
    compliance. Provides recommendations for optimization and identifies potential security risks.

.PARAMETER ConfigPath
    Path to the configuration JSON file. Defaults to "Dynamic-Group-Validation-Config.json"

.PARAMETER GroupId
    Specific group ID to validate. If not provided, validates all dynamic groups

.PARAMETER RuleText
    Specific rule text to validate without applying to a group

.PARAMETER ValidationType
    Type of validation to perform: Syntax, Logic, Performance, Security, or All

.PARAMETER GenerateReport
    Generate comprehensive validation reports

.EXAMPLE
    .\Test-DynamicGroupRules.ps1
    Validate all dynamic groups with comprehensive checks

.EXAMPLE
    .\Test-DynamicGroupRules.ps1 -GroupId "12345678-1234-1234-1234-123456789012"
    Validate a specific dynamic group

.EXAMPLE
    .\Test-DynamicGroupRules.ps1 -RuleText "user.department -eq \"IT\""
    Validate a specific rule without applying it

.NOTES
    Author: Identity Security Automation Team
    Version: 1.0.0
    Requires: Microsoft.Graph.Groups module
    Permissions Required: Group.Read.All, Directory.Read.All
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "Dynamic-Group-Validation-Config.json",
    
    [Parameter(Mandatory = $false)]
    [string]$GroupId,
    
    [Parameter(Mandatory = $false)]
    [string]$RuleText,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Syntax", "Logic", "Performance", "Security", "All")]
    [string]$ValidationType = "All",
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport
)

# Import required modules
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.DirectoryObjects"
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
$Script:ProcessedGroups = 0
$Script:ValidationIssues = 0
$Script:SecurityRisks = 0

#region Helper Functions

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor White }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
    }
    
    if ($Script:LogPath) {
        $logFile = Join-Path $Script:LogPath "DynamicGroupValidation_$(Get-Date -Format 'yyyyMMdd').log"
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

function Test-RuleSyntax {
    param(
        [string]$Rule,
        [hashtable]$Config
    )
    
    $issues = @()
    
    # Basic syntax validation
    if ([string]::IsNullOrWhiteSpace($Rule)) {
        $issues += @{
            Type = "Syntax"
            Severity = "Error"
            Message = "Rule is empty or null"
        }
        return $issues
    }
    
    # Check for balanced parentheses
    $openParens = ($Rule.ToCharArray() | Where-Object { $_ -eq '(' }).Count
    $closeParens = ($Rule.ToCharArray() | Where-Object { $_ -eq ')' }).Count
    
    if ($openParens -ne $closeParens) {
        $issues += @{
            Type = "Syntax"
            Severity = "Error"
            Message = "Unbalanced parentheses in rule"
        }
    }
    
    # Check for valid operators
    $validOperators = @("-eq", "-ne", "-contains", "-notContains", "-in", "-notIn", "-startsWith", "-notStartsWith")
    $hasValidOperator = $false
    
    foreach ($operator in $validOperators) {
        if ($Rule -like "*$operator*") {
            $hasValidOperator = $true
            break
        }
    }
    
    if (-not $hasValidOperator) {
        $issues += @{
            Type = "Syntax"
            Severity = "Warning"
            Message = "No recognized comparison operators found"
        }
    }
    
    # Check for prohibited patterns
    foreach ($pattern in $Config.RulePatterns.ProhibitedPatterns) {
        if ($Rule -match $pattern) {
            $issues += @{
                Type = "Syntax"
                Severity = "Error"
                Message = "Rule contains prohibited pattern: $pattern"
            }
        }
    }
    
    return $issues
}

function Test-RuleLogic {
    param(
        [string]$Rule,
        [hashtable]$Config
    )
    
    $issues = @()
    
    # Check for logical contradictions
    if ($Rule -match "(\w+\.\w+)\s+-eq\s+(.+?)\s+and\s+\1\s+-ne\s+\2") {
        $issues += @{
            Type = "Logic"
            Severity = "Error"
            Message = "Logical contradiction detected (attribute equals and not equals same value)"
        }
    }
    
    # Check for redundant conditions
    if ($Rule -match "(\w+\.\w+\s+-eq\s+.+?)\s+and\s+\1") {
        $issues += @{
            Type = "Logic"
            Severity = "Warning"
            Message = "Redundant condition detected"
        }
    }
    
    # Check for overly broad conditions
    if ($Rule -match "user\.userPrincipalName\s+-contains\s+\"@\"") {
        $issues += @{
            Type = "Logic"
            Severity = "Warning"
            Message = "Overly broad condition - matches all users with email addresses"
        }
    }
    
    return $issues
}

function Test-RulePerformance {
    param(
        [string]$Rule,
        [hashtable]$Config
    )
    
    $issues = @()
    
    # Count logical operators
    $logicalOperators = @("and", "or", "not")
    $operatorCount = 0
    
    foreach ($operator in $logicalOperators) {
        $operatorCount += ([regex]::Matches($Rule, "\b$operator\b", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
    }
    
    if ($operatorCount -gt $Config.PerformanceThresholds.MaxLogicalOperators) {
        $issues += @{
            Type = "Performance"
            Severity = "Warning"
            Message = "High number of logical operators ($operatorCount) may impact performance"
        }
    }
    
    # Count attribute checks
    $attributeChecks = ([regex]::Matches($Rule, "\b(user|device)\.\w+", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
    
    if ($attributeChecks -gt $Config.PerformanceThresholds.MaxAttributeChecks) {
        $issues += @{
            Type = "Performance"
            Severity = "Warning"
            Message = "High number of attribute checks ($attributeChecks) may impact performance"
        }
    }
    
    # Check for expensive operations
    if ($Rule -match "-contains\s+\".*\*.*\"") {
        $issues += @{
            Type = "Performance"
            Severity = "Warning"
            Message = "Wildcard contains operations can be expensive"
        }
    }
    
    return $issues
}

function Test-RuleSecurity {
    param(
        [string]$Rule,
        [hashtable]$Config
    )
    
    $issues = @()
    
    # Check for security risk patterns
    foreach ($riskPattern in $Config.RulePatterns.SecurityRisks) {
        if ($Rule -like "*$riskPattern*") {
            $issues += @{
                Type = "Security"
                Severity = "Error"
                Message = "Security risk detected: $riskPattern"
            }
            $Script:SecurityRisks++
        }
    }
    
    # Check for sensitive attribute exposure
    $sensitiveAttributes = @("password", "secret", "key", "token", "credential")
    foreach ($attr in $sensitiveAttributes) {
        if ($Rule -match "\b$attr\b") {
            $issues += @{
                Type = "Security"
                Severity = "Error"
                Message = "Rule references sensitive attribute: $attr"
            }
            $Script:SecurityRisks++
        }
    }
    
    # Check for overly permissive rules
    if ($Rule -match "user\.\w+\s+-eq\s+\"\*\"") {
        $issues += @{
            Type = "Security"
            Severity = "Warning"
            Message = "Overly permissive rule using wildcard equality"
        }
    }
    
    return $issues
}

function Test-DynamicGroupRule {
    param(
        [string]$Rule,
        [hashtable]$Config,
        [string]$GroupName = "Unknown"
    )
    
    $allIssues = @()
    
    Write-LogMessage "Validating rule for group: $GroupName" "INFO"
    
    # Perform different types of validation based on configuration and parameters
    if ($ValidationType -eq "All" -or $ValidationType -eq "Syntax") {
        if ($Config.ValidationSettings.EnableSyntaxValidation) {
            $syntaxIssues = Test-RuleSyntax -Rule $Rule -Config $Config
            $allIssues += $syntaxIssues
        }
    }
    
    if ($ValidationType -eq "All" -or $ValidationType -eq "Logic") {
        if ($Config.ValidationSettings.EnableLogicValidation) {
            $logicIssues = Test-RuleLogic -Rule $Rule -Config $Config
            $allIssues += $logicIssues
        }
    }
    
    if ($ValidationType -eq "All" -or $ValidationType -eq "Performance") {
        if ($Config.ValidationSettings.EnablePerformanceValidation) {
            $performanceIssues = Test-RulePerformance -Rule $Rule -Config $Config
            $allIssues += $performanceIssues
        }
    }
    
    if ($ValidationType -eq "All" -or $ValidationType -eq "Security") {
        if ($Config.ValidationSettings.EnableSecurityValidation) {
            $securityIssues = Test-RuleSecurity -Rule $Rule -Config $Config
            $allIssues += $securityIssues
        }
    }
    
    $Script:ValidationIssues += $allIssues.Count
    
    return @{
        GroupName = $GroupName
        Rule = $Rule
        Issues = $allIssues
        ErrorCount = ($allIssues | Where-Object { $_.Severity -eq "Error" }).Count
        WarningCount = ($allIssues | Where-Object { $_.Severity -eq "Warning" }).Count
        IsValid = ($allIssues | Where-Object { $_.Severity -eq "Error" }).Count -eq 0
    }
}

function Get-DynamicGroups {
    Write-LogMessage "Retrieving dynamic groups..." "INFO"
    
    try {
        if ($GroupId) {
            $group = Get-MgGroup -GroupId $GroupId -Property "Id,DisplayName,GroupTypes,MembershipRule,MembershipRuleProcessingState"
            if ($group.GroupTypes -contains "DynamicMembership") {
                return @($group)
            } else {
                Write-LogMessage "Specified group is not a dynamic group" "WARNING"
                return @()
            }
        } else {
            $groups = Get-MgGroup -All -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -Property "Id,DisplayName,GroupTypes,MembershipRule,MembershipRuleProcessingState"
            Write-LogMessage "Found $($groups.Count) dynamic groups" "SUCCESS"
            return $groups
        }
    }
    catch {
        Write-LogMessage "Failed to retrieve dynamic groups: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Process-DynamicGroups {
    param([hashtable]$Config)
    
    if ($RuleText) {
        # Validate a specific rule text
        Write-LogMessage "Validating provided rule text..." "INFO"
        $result = Test-DynamicGroupRule -Rule $RuleText -Config $Config -GroupName "Custom Rule"
        return @($result)
    }
    
    $groups = Get-DynamicGroups
    if ($groups.Count -eq 0) {
        Write-LogMessage "No dynamic groups found" "INFO"
        return @()
    }
    
    $results = @()
    $totalGroups = $groups.Count
    $currentGroup = 0
    
    foreach ($group in $groups) {
        $currentGroup++
        $Script:ProcessedGroups++
        
        Write-Progress -Activity "Validating Dynamic Groups" -Status "Processing $($group.DisplayName)" -PercentComplete (($currentGroup / $totalGroups) * 100)
        
        try {
            if ([string]::IsNullOrWhiteSpace($group.MembershipRule)) {
                Write-LogMessage "Group $($group.DisplayName) has no membership rule" "WARNING"
                continue
            }
            
            $result = Test-DynamicGroupRule -Rule $group.MembershipRule -Config $Config -GroupName $group.DisplayName
            $result.GroupId = $group.Id
            $result.ProcessingState = $group.MembershipRuleProcessingState
            
            $results += $result
            
        }
        catch {
            Write-LogMessage "Error validating group $($group.DisplayName): $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-Progress -Activity "Validating Dynamic Groups" -Completed
    Write-LogMessage "Dynamic group validation completed. Processed $($results.Count) groups" "SUCCESS"
    
    return $results
}

function Generate-ValidationReport {
    param([array]$Results, [hashtable]$Config)
    
    if (-not $GenerateReport) {
        return
    }
    
    Write-LogMessage "Generating validation report..." "INFO"
    
    $summary = @{
        TotalGroups = $Results.Count
        ValidGroups = ($Results | Where-Object { $_.IsValid }).Count
        GroupsWithErrors = ($Results | Where-Object { $_.ErrorCount -gt 0 }).Count
        GroupsWithWarnings = ($Results | Where-Object { $_.WarningCount -gt 0 }).Count
        TotalIssues = $Script:ValidationIssues
        SecurityRisks = $Script:SecurityRisks
        
        IssuesByType = $Results | ForEach-Object { $_.Issues } | Group-Object Type | ForEach-Object {
            @{
                Type = $_.Name
                Count = $_.Count
            }
        }
    }
    
    $jsonReport = @{
        ReportMetadata = @{
            GeneratedDateTime = Get-Date
            TotalGroupsProcessed = $Results.Count
            ValidationIssues = $Script:ValidationIssues
            SecurityRisks = $Script:SecurityRisks
            ReportVersion = "1.0.0"
        }
        ExecutiveSummary = $summary
        ValidationResults = $Results
    }
    
    $jsonPath = Join-Path $Script:ReportPath "DynamicGroupValidation_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    Write-LogMessage "Validation report generated: $jsonPath" "SUCCESS"
    return $jsonPath
}

#endregion

#region Main Execution

function Main {
    try {
        Write-LogMessage "Starting Dynamic Group Rule Validator v1.0.0" "INFO"
        Write-LogMessage "===============================================" "INFO"
        
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
        try {
            Connect-MgGraph -Scopes @("Group.Read.All", "Directory.Read.All") -ErrorAction Stop
            Write-LogMessage "Connected to Microsoft Graph" "SUCCESS"
        }
        catch {
            Write-LogMessage "Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
            exit 1
        }
        
        # Process dynamic groups
        Write-LogMessage "Starting dynamic group rule validation..." "INFO"
        $results = Process-DynamicGroups -Config $Script:Config
        
        if ($results.Count -eq 0) {
            Write-LogMessage "No dynamic groups processed" "INFO"
            return
        }
        
        # Generate reports
        if ($GenerateReport) {
            $reportPath = Generate-ValidationReport -Results $results -Config $Script:Config
        }
        
        # Final summary
        $duration = (Get-Date) - $Script:StartTime
        Write-LogMessage "===============================================" "SUCCESS"
        Write-LogMessage "Dynamic Group Validation Completed!" "SUCCESS"
        Write-LogMessage "===============================================" "SUCCESS"
        Write-LogMessage "Processing Time: $([math]::Round($duration.TotalSeconds, 2)) seconds" "INFO"
        Write-LogMessage "Groups Processed: $($Script:ProcessedGroups)" "INFO"
        Write-LogMessage "Validation Issues: $($Script:ValidationIssues)" "INFO"
        Write-LogMessage "Security Risks: $($Script:SecurityRisks)" "INFO"
        
        if ($reportPath) {
            Write-LogMessage "Report Generated: $reportPath" "SUCCESS"
        }
        
        # Display key findings
        $errorGroups = $results | Where-Object { $_.ErrorCount -gt 0 }
        if ($errorGroups.Count -gt 0) {
            Write-LogMessage "`n🚨 ERROR: $($errorGroups.Count) groups have validation errors!" "ERROR"
            foreach ($group in $errorGroups | Select-Object -First 5) {
                Write-LogMessage "  • $($group.GroupName): $($group.ErrorCount) errors" "ERROR"
            }
        }
        
        if ($Script:SecurityRisks -gt 0) {
            Write-LogMessage "`n⚠️  SECURITY: $($Script:SecurityRisks) security risks detected!" "WARNING"
        }
        
        $warningGroups = $results | Where-Object { $_.WarningCount -gt 0 }
        if ($warningGroups.Count -gt 0) {
            Write-LogMessage "`nℹ️  INFO: $($warningGroups.Count) groups have warnings" "INFO"
        }
        
    }
    catch {
        Write-LogMessage "Critical error in main execution: $($_.Exception.Message)" "ERROR"
        exit 1
    }
    finally {
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
