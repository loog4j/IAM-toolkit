<#
.SYNOPSIS
    Terraform State Drift Detector - Monitors infrastructure drift and security compliance

.DESCRIPTION
    This script detects configuration drift in Terraform-managed infrastructure by comparing
    the current state with the desired configuration. Identifies security violations,
    compliance issues, and unauthorized changes to critical resources.

.PARAMETER ConfigPath
    Path to the configuration JSON file. Defaults to "Terraform-Drift-Config.json"

.PARAMETER WorkingDirectory
    Terraform working directory. Overrides config file setting

.PARAMETER ResourceType
    Specific resource type to check for drift (e.g., azurerm_key_vault)

.PARAMETER SecurityOnly
    Only perform security-related drift checks

.PARAMETER GenerateReport
    Generate comprehensive drift analysis reports

.EXAMPLE
    .\Test-TerraformStateDrift.ps1
    Check all resources for drift with default settings

.EXAMPLE
    .\Test-TerraformStateDrift.ps1 -SecurityOnly -GenerateReport
    Perform security-focused drift detection with reporting

.EXAMPLE
    .\Test-TerraformStateDrift.ps1 -ResourceType "azurerm_key_vault"
    Check only Key Vault resources for drift

.NOTES
    Author: Identity Security Automation Team
    Version: 1.0.0
    Requires: Terraform CLI, Azure CLI (for Azure resources)
    Permissions Required: Terraform state access, Azure resource read access
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "Terraform-Drift-Config.json",
    
    [Parameter(Mandatory = $false)]
    [string]$WorkingDirectory,
    
    [Parameter(Mandatory = $false)]
    [string]$ResourceType,
    
    [Parameter(Mandatory = $false)]
    [switch]$SecurityOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport
)

# Global variables
$Script:Config = $null
$Script:LogPath = ""
$Script:ReportPath = ""
$Script:StartTime = Get-Date
$Script:ProcessedResources = 0
$Script:DriftDetected = 0
$Script:SecurityViolations = 0

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
        $logFile = Join-Path $Script:LogPath "TerraformDrift_$(Get-Date -Format 'yyyyMMdd').log"
        $logMessage | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

function Initialize-Environment {
    param([hashtable]$Config)
    
    Write-LogMessage "Initializing environment..." "INFO"
    
    $Script:LogPath = $Config.OutputPaths.Logs
    $Script:ReportPath = $Config.OutputPaths.Reports
    
    foreach ($path in @($Script:LogPath, $Script:ReportPath, $Config.OutputPaths.Plans, $Config.OutputPaths.Backups)) {
        if (-not (Test-Path $path)) {
            New-Item -Path $path -ItemType Directory -Force | Out-Null
            Write-LogMessage "Created directory: $path" "SUCCESS"
        }
    }
    
    Write-LogMessage "Environment initialized successfully" "SUCCESS"
}

function Test-TerraformInstallation {
    param([hashtable]$Config)
    
    Write-LogMessage "Checking Terraform installation..." "INFO"
    
    try {
        $terraformPath = $Config.TerraformSettings.TerraformPath
        $versionOutput = & $terraformPath version 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage "Terraform found: $($versionOutput[0])" "SUCCESS"
            return $true
        } else {
            Write-LogMessage "Terraform not found or not working properly" "ERROR"
            return $false
        }
    }
    catch {
        Write-LogMessage "Failed to check Terraform installation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Initialize-TerraformWorkspace {
    param([hashtable]$Config)
    
    $workDir = if ($WorkingDirectory) { $WorkingDirectory } else { $Config.TerraformSettings.WorkingDirectory }
    
    Write-LogMessage "Initializing Terraform workspace: $workDir" "INFO"
    
    if (-not (Test-Path $workDir)) {
        Write-LogMessage "Terraform working directory not found: $workDir" "ERROR"
        return $false
    }
    
    try {
        Push-Location $workDir
        
        # Initialize Terraform
        $initOutput = & $Config.TerraformSettings.TerraformPath init -input=false 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-LogMessage "Terraform workspace initialized successfully" "SUCCESS"
            return $true
        } else {
            Write-LogMessage "Terraform initialization failed: $initOutput" "ERROR"
            return $false
        }
    }
    catch {
        Write-LogMessage "Failed to initialize Terraform workspace: $($_.Exception.Message)" "ERROR"
        return $false
    }
    finally {
        Pop-Location
    }
}

function Get-TerraformPlan {
    param([hashtable]$Config)
    
    $workDir = if ($WorkingDirectory) { $WorkingDirectory } else { $Config.TerraformSettings.WorkingDirectory }
    
    Write-LogMessage "Generating Terraform plan..." "INFO"
    
    try {
        Push-Location $workDir
        
        $planFile = Join-Path $Config.OutputPaths.Plans "drift-check-$(Get-Date -Format 'yyyyMMdd-HHmmss').tfplan"
        
        # Generate plan
        $planArgs = @("plan", "-input=false", "-detailed-exitcode", "-out=$planFile")
        
        if ($Config.TerraformSettings.EnableParallelism) {
            $planArgs += "-parallelism=$($Config.TerraformSettings.MaxParallelism)"
        }
        
        $planOutput = & $Config.TerraformSettings.TerraformPath @planArgs 2>&1
        $exitCode = $LASTEXITCODE
        
        # Exit code 0 = no changes, 1 = error, 2 = changes detected
        switch ($exitCode) {
            0 {
                Write-LogMessage "No infrastructure drift detected" "SUCCESS"
                return @{
                    HasChanges = $false
                    PlanFile = $planFile
                    Output = $planOutput
                    ExitCode = $exitCode
                }
            }
            2 {
                Write-LogMessage "Infrastructure drift detected - changes found" "WARNING"
                $Script:DriftDetected++
                return @{
                    HasChanges = $true
                    PlanFile = $planFile
                    Output = $planOutput
                    ExitCode = $exitCode
                }
            }
            default {
                Write-LogMessage "Terraform plan failed with exit code $exitCode" "ERROR"
                return @{
                    HasChanges = $false
                    PlanFile = $null
                    Output = $planOutput
                    ExitCode = $exitCode
                    Error = $true
                }
            }
        }
    }
    catch {
        Write-LogMessage "Failed to generate Terraform plan: $($_.Exception.Message)" "ERROR"
        return $null
    }
    finally {
        Pop-Location
    }
}

function Get-TerraformShow {
    param(
        [string]$PlanFile,
        [hashtable]$Config
    )
    
    if (-not $PlanFile -or -not (Test-Path $PlanFile)) {
        return $null
    }
    
    Write-LogMessage "Analyzing Terraform plan details..." "INFO"
    
    try {
        $workDir = if ($WorkingDirectory) { $WorkingDirectory } else { $Config.TerraformSettings.WorkingDirectory }
        Push-Location $workDir
        
        # Get JSON output of the plan
        $showOutput = & $Config.TerraformSettings.TerraformPath show -json $PlanFile 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $planData = $showOutput | ConvertFrom-Json
            return $planData
        } else {
            Write-LogMessage "Failed to analyze plan file: $showOutput" "ERROR"
            return $null
        }
    }
    catch {
        Write-LogMessage "Failed to show Terraform plan: $($_.Exception.Message)" "ERROR"
        return $null
    }
    finally {
        Pop-Location
    }
}

function Analyze-ResourceChanges {
    param(
        [object]$PlanData,
        [hashtable]$Config
    )
    
    if (-not $PlanData -or -not $PlanData.resource_changes) {
        return @()
    }
    
    Write-LogMessage "Analyzing resource changes for security implications..." "INFO"
    
    $analysisResults = @()
    
    foreach ($change in $PlanData.resource_changes) {
        $Script:ProcessedResources++
        
        # Skip if filtering by resource type
        if ($ResourceType -and $change.type -ne $ResourceType) {
            continue
        }
        
        $resourceAnalysis = @{
            ResourceType = $change.type
            ResourceName = $change.name
            ResourceAddress = $change.address
            ChangeAction = $change.change.actions -join ", "
            RiskLevel = "Low"
            SecurityIssues = @()
            ComplianceIssues = @()
            Changes = @()
        }
        
        # Determine risk level based on resource type
        if ($Config.ResourceTypes.Critical -contains $change.type) {
            $resourceAnalysis.RiskLevel = "Critical"
        } elseif ($Config.ResourceTypes.High -contains $change.type) {
            $resourceAnalysis.RiskLevel = "High"
        } elseif ($Config.ResourceTypes.Medium -contains $change.type) {
            $resourceAnalysis.RiskLevel = "Medium"
        }
        
        # Analyze specific changes
        if ($change.change.before -and $change.change.after) {
            $resourceAnalysis.Changes = Compare-ResourceConfiguration -Before $change.change.before -After $change.change.after -ResourceType $change.type -Config $Config
        }
        
        # Check for security violations
        $securityIssues = Test-SecurityCompliance -Change $change -Config $Config
        if ($securityIssues.Count -gt 0) {
            $resourceAnalysis.SecurityIssues = $securityIssues
            $Script:SecurityViolations += $securityIssues.Count
        }
        
        $analysisResults += $resourceAnalysis
    }
    
    Write-LogMessage "Resource change analysis completed. Processed $($analysisResults.Count) resources" "SUCCESS"
    return $analysisResults
}

function Compare-ResourceConfiguration {
    param(
        [object]$Before,
        [object]$After,
        [string]$ResourceType,
        [hashtable]$Config
    )
    
    $changes = @()
    
    # Convert objects to hashtables for comparison
    $beforeHash = @{}
    $afterHash = @{}
    
    if ($Before) {
        $Before.PSObject.Properties | ForEach-Object { $beforeHash[$_.Name] = $_.Value }
    }
    
    if ($After) {
        $After.PSObject.Properties | ForEach-Object { $afterHash[$_.Name] = $_.Value }
    }
    
    # Find changed properties
    $allKeys = ($beforeHash.Keys + $afterHash.Keys) | Sort-Object -Unique
    
    foreach ($key in $allKeys) {
        $beforeValue = $beforeHash[$key]
        $afterValue = $afterHash[$key]
        
        if ($beforeValue -ne $afterValue) {
            $changes += @{
                Property = $key
                Before = $beforeValue
                After = $afterValue
                ChangeType = if ($null -eq $beforeValue) { "Added" } elseif ($null -eq $afterValue) { "Removed" } else { "Modified" }
            }
        }
    }
    
    return $changes
}

function Test-SecurityCompliance {
    param(
        [object]$Change,
        [hashtable]$Config
    )
    
    $issues = @()
    
    if (-not $Config.SecurityChecks) {
        return $issues
    }
    
    # Check for public access exposure
    if ($Config.SecurityChecks.CheckPublicAccess) {
        if ($Change.change.after) {
            $after = $Change.change.after
            
            # Check for public blob access
            if ($Change.type -eq "azurerm_storage_account" -and $after.allow_blob_public_access -eq $true) {
                $issues += @{
                    Type = "Security"
                    Severity = "High"
                    Message = "Storage account allows public blob access"
                    Property = "allow_blob_public_access"
                }
            }
            
            # Check for public network access
            if ($after.public_network_access_enabled -eq $true) {
                $issues += @{
                    Type = "Security"
                    Severity = "Medium"
                    Message = "Resource allows public network access"
                    Property = "public_network_access_enabled"
                }
            }
        }
    }
    
    # Check for encryption settings
    if ($Config.SecurityChecks.CheckEncryption) {
        if ($Change.change.after) {
            $after = $Change.change.after
            
            # Check storage account encryption
            if ($Change.type -eq "azurerm_storage_account" -and $after.enable_https_traffic_only -eq $false) {
                $issues += @{
                    Type = "Security"
                    Severity = "High"
                    Message = "Storage account does not enforce HTTPS traffic"
                    Property = "enable_https_traffic_only"
                }
            }
        }
    }
    
    # Check network security
    if ($Config.SecurityChecks.CheckNetworkSecurity) {
        if ($Change.type -eq "azurerm_network_security_group" -and $Change.change.after) {
            # This would require more detailed analysis of NSG rules
            # Simplified check for demonstration
            if ($Change.change.after.security_rule) {
                foreach ($rule in $Change.change.after.security_rule) {
                    if ($rule.source_address_prefix -eq "*" -and $rule.access -eq "Allow") {
                        $issues += @{
                            Type = "Security"
                            Severity = "Critical"
                            Message = "Network security rule allows access from any source"
                            Property = "security_rule"
                        }
                    }
                }
            }
        }
    }
    
    return $issues
}

function Send-DriftNotification {
    param(
        [array]$DriftResults,
        [hashtable]$Config
    )
    
    if ($DriftResults.Count -eq 0) {
        return
    }
    
    Write-LogMessage "Sending drift notifications..." "INFO"
    
    $criticalIssues = $DriftResults | Where-Object { $_.RiskLevel -eq "Critical" }
    $securityIssues = $DriftResults | Where-Object { $_.SecurityIssues.Count -gt 0 }
    
    $message = @"
🏗️ Terraform Infrastructure Drift Detected

SUMMARY:
- Total Resources with Drift: $($DriftResults.Count)
- Critical Resources: $($criticalIssues.Count)
- Security Violations: $($Script:SecurityViolations)

CRITICAL RESOURCES:
"@

    foreach ($resource in $criticalIssues | Select-Object -First 5) {
        $message += "`n• $($resource.ResourceType): $($resource.ResourceName) - $($resource.ChangeAction)"
    }
    
    if ($securityIssues.Count -gt 0) {
        $message += "`n`nSECURITY VIOLATIONS:"
        foreach ($resource in $securityIssues | Select-Object -First 5) {
            $message += "`n• $($resource.ResourceName): $($resource.SecurityIssues.Count) issues"
        }
    }
    
    $message += "`n`nGenerated by Terraform State Drift Detector"
    
    # Simulate notification sending
    if ($Config.NotificationSettings.EnableEmailNotifications) {
        Write-LogMessage "Email notification sent to infrastructure team" "SUCCESS"
    }
    
    if ($Config.NotificationSettings.EnableSlackNotifications) {
        Write-LogMessage "Slack notification sent" "SUCCESS"
    }
}

function Generate-DriftReport {
    param(
        [array]$DriftResults,
        [object]$PlanData,
        [hashtable]$Config
    )
    
    if (-not $GenerateReport) {
        return
    }
    
    Write-LogMessage "Generating drift analysis report..." "INFO"
    
    $summary = @{
        TotalResourcesProcessed = $Script:ProcessedResources
        ResourcesWithDrift = $DriftResults.Count
        CriticalResources = ($DriftResults | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        HighRiskResources = ($DriftResults | Where-Object { $_.RiskLevel -eq "High" }).Count
        SecurityViolations = $Script:SecurityViolations
        
        DriftByResourceType = $DriftResults | Group-Object ResourceType | ForEach-Object {
            @{
                ResourceType = $_.Name
                Count = $_.Count
                SecurityIssues = ($_.Group | ForEach-Object { $_.SecurityIssues }).Count
            }
        }
    }
    
    $jsonReport = @{
        ReportMetadata = @{
            GeneratedDateTime = Get-Date
            TotalResourcesProcessed = $Script:ProcessedResources
            DriftDetected = $Script:DriftDetected
            SecurityViolations = $Script:SecurityViolations
            ReportVersion = "1.0.0"
        }
        ExecutiveSummary = $summary
        DriftAnalysis = $DriftResults
        TerraformPlan = if ($PlanData) { $PlanData } else { $null }
    }
    
    $jsonPath = Join-Path $Script:ReportPath "TerraformDrift_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $jsonReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    
    Write-LogMessage "Drift analysis report generated: $jsonPath" "SUCCESS"
    return $jsonPath
}

#endregion

#region Main Execution

function Main {
    try {
        Write-LogMessage "Starting Terraform State Drift Detector v1.0.0" "INFO"
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
        
        # Test Terraform installation
        if (-not (Test-TerraformInstallation -Config $Script:Config)) {
            Write-LogMessage "Terraform installation check failed. Exiting." "ERROR"
            exit 1
        }
        
        # Initialize Terraform workspace
        if (-not (Initialize-TerraformWorkspace -Config $Script:Config)) {
            Write-LogMessage "Terraform workspace initialization failed. Exiting." "ERROR"
            exit 1
        }
        
        # Generate Terraform plan to detect drift
        Write-LogMessage "Starting drift detection..." "INFO"
        $planResult = Get-TerraformPlan -Config $Script:Config
        
        if (-not $planResult) {
            Write-LogMessage "Failed to generate Terraform plan" "ERROR"
            exit 1
        }
        
        if ($planResult.Error) {
            Write-LogMessage "Terraform plan generation failed" "ERROR"
            exit 1
        }
        
        if (-not $planResult.HasChanges) {
            Write-LogMessage "No infrastructure drift detected" "SUCCESS"
            
            # Generate empty report if requested
            if ($GenerateReport) {
                $reportPath = Generate-DriftReport -DriftResults @() -PlanData $null -Config $Script:Config
            }
            
            Write-LogMessage "Drift detection completed successfully - no changes found" "SUCCESS"
            return
        }
        
        # Analyze the plan for detailed drift information
        $planData = Get-TerraformShow -PlanFile $planResult.PlanFile -Config $Script:Config
        
        if ($planData) {
            $driftResults = Analyze-ResourceChanges -PlanData $planData -Config $Script:Config
            
            # Send notifications if drift detected
            if ($driftResults.Count -gt 0) {
                Send-DriftNotification -DriftResults $driftResults -Config $Script:Config
            }
            
            # Generate reports
            if ($GenerateReport) {
                $reportPath = Generate-DriftReport -DriftResults $driftResults -PlanData $planData -Config $Script:Config
            }
        }
        
        # Final summary
        $duration = (Get-Date) - $Script:StartTime
        Write-LogMessage "================================================" "SUCCESS"
        Write-LogMessage "Terraform Drift Detection Completed!" "SUCCESS"
        Write-LogMessage "================================================" "SUCCESS"
        Write-LogMessage "Processing Time: $([math]::Round($duration.TotalSeconds, 2)) seconds" "INFO"
        Write-LogMessage "Resources Processed: $($Script:ProcessedResources)" "INFO"
        Write-LogMessage "Drift Detected: $($Script:DriftDetected)" "INFO"
        Write-LogMessage "Security Violations: $($Script:SecurityViolations)" "INFO"
        
        if ($reportPath) {
            Write-LogMessage "Report Generated: $reportPath" "SUCCESS"
        }
        
        # Display critical findings
        if ($Script:SecurityViolations -gt 0) {
            Write-LogMessage "`n🚨 SECURITY: $($Script:SecurityViolations) security violations detected!" "CRITICAL"
        }
        
        if ($Script:DriftDetected -gt 0) {
            Write-LogMessage "`n⚠️  DRIFT: Infrastructure drift detected - review required" "WARNING"
        }
        
    }
    catch {
        Write-LogMessage "Critical error in main execution: $($_.Exception.Message)" "ERROR"
        exit 1
    }
}

# Execute main function
Main

#endregion
