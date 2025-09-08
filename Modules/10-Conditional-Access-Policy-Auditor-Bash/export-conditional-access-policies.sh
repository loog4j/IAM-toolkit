#!/bin/bash

#
# Export and audit Conditional Access policies from Entra ID
# 
# Description:
#   Exports Conditional Access policies, analyzes them for security gaps, compliance issues,
#   and generates comprehensive reports in multiple formats (JSON, CSV, HTML).
#
# Requirements:
#   - Microsoft Graph CLI (mgc) installed and configured
#   - jq for JSON processing
#   - curl for API calls (fallback)
#   - Appropriate permissions: Policy.Read.All, Directory.Read.All
#
# Usage:
#   ./export-conditional-access-policies.sh [OPTIONS]
#
# Examples:
#   ./export-conditional-access-policies.sh --format html
#   ./export-conditional-access-policies.sh --format all --include-disabled
#
# Author: Identity Security Automation Project
# Version: 1.0
#

set -euo pipefail

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/CA-Policy-Audit-Config.json"
OUTPUT_FORMAT="HTML"
INCLUDE_DISABLED=false
ANALYSIS_ONLY=false
LOG_LEVEL="INFO"
START_TIME=$(date +%s)
LOG_PATH=""
POLICIES_JSON=""
ANALYSIS_RESULTS=""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Export and audit Conditional Access policies from Entra ID

OPTIONS:
    -c, --config PATH       Path to configuration file (default: ./CA-Policy-Audit-Config.json)
    -f, --format FORMAT     Output format: json, csv, html, all (default: html)
    -d, --include-disabled  Include disabled policies in analysis
    -a, --analysis-only     Perform analysis only without exporting raw policy data
    -l, --log-level LEVEL   Logging level: INFO, WARNING, ERROR, DEBUG (default: INFO)
    -h, --help             Display this help message

EXAMPLES:
    $0 --format html
    $0 --format all --include-disabled
    $0 --analysis-only --log-level DEBUG

REQUIREMENTS:
    - Microsoft Graph CLI (mgc) installed
    - jq for JSON processing
    - Appropriate Azure AD permissions

EOF
}

# Function to log messages with timestamps and colors
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] $message"
    
    # Check log level priority
    case "$LOG_LEVEL" in
        "DEBUG") level_priority=0 ;;
        "INFO") level_priority=1 ;;
        "WARNING") level_priority=2 ;;
        "ERROR") level_priority=3 ;;
        *) level_priority=1 ;;
    esac
    
    case "$level" in
        "DEBUG") current_priority=0 ;;
        "INFO"|"SUCCESS") current_priority=1 ;;
        "WARNING") current_priority=2 ;;
        "ERROR") current_priority=3 ;;
        *) current_priority=1 ;;
    esac
    
    # Only log if current level meets threshold
    if [ $current_priority -ge $level_priority ]; then
        # Write to log file if path is set
        if [ -n "$LOG_PATH" ]; then
            echo "$log_entry" >> "$LOG_PATH"
        fi
        
        # Write to console with colors
        case "$level" in
            "ERROR") echo -e "${RED}$log_entry${NC}" ;;
            "WARNING") echo -e "${YELLOW}$log_entry${NC}" ;;
            "SUCCESS") echo -e "${GREEN}$log_entry${NC}" ;;
            "DEBUG") echo -e "${CYAN}$log_entry${NC}" ;;
            *) echo "$log_entry" ;;
        esac
    fi
}

# Function to initialize logging
initialize_logging() {
    local config_file="$1"
    
    if [ -f "$config_file" ]; then
        local log_dir=$(jq -r '.LogPath // "./logs/"' "$config_file")
        
        # Create log directory if it doesn't exist
        mkdir -p "$log_dir"
        
        LOG_PATH="${log_dir}/CA-PolicyAudit_$(date +%Y%m%d_%H%M%S).log"
        log "INFO" "Logging initialized. Log file: $LOG_PATH"
        return 0
    else
        log "WARNING" "Configuration file not found. Continuing without file logging..."
        return 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    local issues=()
    
    # Check for required tools
    if ! command -v mgc &> /dev/null; then
        if ! command -v az &> /dev/null; then
            issues+=("Microsoft Graph CLI (mgc) or Azure CLI (az) is required")
        fi
    fi
    
    if ! command -v jq &> /dev/null; then
        issues+=("jq is required for JSON processing")
    fi
    
    if ! command -v curl &> /dev/null; then
        issues+=("curl is required for HTTP requests")
    fi
    
    if [ ${#issues[@]} -gt 0 ]; then
        log "ERROR" "Prerequisites check failed:"
        for issue in "${issues[@]}"; do
            log "ERROR" "  - $issue"
        done
        return 1
    fi
    
    log "SUCCESS" "All prerequisites met"
    return 0
}

# Function to connect to Microsoft Graph
connect_to_graph() {
    log "INFO" "Connecting to Microsoft Graph..."
    
    # Try Microsoft Graph CLI first
    if command -v mgc &> /dev/null; then
        if mgc auth status &> /dev/null; then
            log "SUCCESS" "Already authenticated with Microsoft Graph CLI"
            return 0
        else
            log "INFO" "Authenticating with Microsoft Graph CLI..."
            if mgc auth login --scopes "Policy.Read.All Directory.Read.All Application.Read.All"; then
                log "SUCCESS" "Connected to Microsoft Graph via mgc"
                return 0
            else
                log "ERROR" "Failed to authenticate with Microsoft Graph CLI"
                return 1
            fi
        fi
    fi
    
    # Fallback to Azure CLI
    if command -v az &> /dev/null; then
        if az account show &> /dev/null; then
            log "SUCCESS" "Already authenticated with Azure CLI"
            return 0
        else
            log "INFO" "Authenticating with Azure CLI..."
            if az login; then
                log "SUCCESS" "Connected to Microsoft Graph via Azure CLI"
                return 0
            else
                log "ERROR" "Failed to authenticate with Azure CLI"
                return 1
            fi
        fi
    fi
    
    log "ERROR" "No suitable authentication method available"
    return 1
}

# Function to get Conditional Access policies
get_conditional_access_policies() {
    log "INFO" "Retrieving Conditional Access policies..."
    
    local temp_file=$(mktemp)
    
    # Try Microsoft Graph CLI first
    if command -v mgc &> /dev/null && mgc auth status &> /dev/null; then
        if mgc identity conditional-access policies list --output json > "$temp_file" 2>/dev/null; then
            POLICIES_JSON=$(cat "$temp_file")
        else
            log "ERROR" "Failed to retrieve policies with Microsoft Graph CLI"
            rm -f "$temp_file"
            return 1
        fi
    # Fallback to Azure CLI
    elif command -v az &> /dev/null && az account show &> /dev/null; then
        if az rest --method GET --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" --output json > "$temp_file" 2>/dev/null; then
            POLICIES_JSON=$(jq '.value' "$temp_file")
        else
            log "ERROR" "Failed to retrieve policies with Azure CLI"
            rm -f "$temp_file"
            return 1
        fi
    else
        log "ERROR" "No authenticated Graph connection available"
        rm -f "$temp_file"
        return 1
    fi
    
    rm -f "$temp_file"
    
    local total_count=$(echo "$POLICIES_JSON" | jq 'length')
    log "INFO" "📊 Retrieved $total_count Conditional Access policies"
    
    # Filter based on configuration if needed
    if [ "$INCLUDE_DISABLED" = false ]; then
        local config_include_disabled=$(jq -r '.IncludeDisabledPolicies // false' "$CONFIG_FILE" 2>/dev/null || echo "false")
        if [ "$config_include_disabled" = "false" ]; then
            POLICIES_JSON=$(echo "$POLICIES_JSON" | jq '[.[] | select(.state == "enabled")]')
            local enabled_count=$(echo "$POLICIES_JSON" | jq 'length')
            log "INFO" "📊 Filtered to $enabled_count enabled policies"
        fi
    fi
    
    return 0
}

# Function to analyze policy compliance
analyze_policy_compliance() {
    log "INFO" "Analyzing policy compliance..."
    
    local compliance_score=0
    local issues=()
    local recommendations=()
    
    # Check for MFA requirement for administrators
    local mfa_admin_count=$(echo "$POLICIES_JSON" | jq '[.[] | select(.conditions.users.includeRoles != null and (.grantControls.builtInControls // []) | contains(["mfa"]) and .state == "enabled")] | length')
    
    if [ "$mfa_admin_count" -gt 0 ]; then
        compliance_score=$((compliance_score + 20))
        log "SUCCESS" "✅ MFA for administrators: COMPLIANT"
    else
        issues+=("No MFA requirement found for administrator roles")
        recommendations+=("Create policy to require MFA for all administrator roles")
        log "WARNING" "❌ MFA for administrators: NON-COMPLIANT"
    fi
    
    # Check for legacy authentication blocking
    local legacy_auth_count=$(echo "$POLICIES_JSON" | jq '[.[] | select((.conditions.clientAppTypes // []) | contains(["exchangeActiveSync", "other"]) and (.grantControls.builtInControls // []) | contains(["block"]) and .state == "enabled")] | length')
    
    if [ "$legacy_auth_count" -gt 0 ]; then
        compliance_score=$((compliance_score + 25))
        log "SUCCESS" "✅ Legacy authentication blocking: COMPLIANT"
    else
        issues+=("Legacy authentication is not blocked")
        recommendations+=("Create policy to block legacy authentication protocols")
        log "WARNING" "❌ Legacy authentication blocking: NON-COMPLIANT"
    fi
    
    # Check for device compliance requirements
    local device_compliance_count=$(echo "$POLICIES_JSON" | jq '[.[] | select((.grantControls.builtInControls // []) | contains(["compliantDevice"]) and .state == "enabled")] | length')
    
    if [ "$device_compliance_count" -gt 0 ]; then
        compliance_score=$((compliance_score + 15))
        log "SUCCESS" "✅ Device compliance requirement: COMPLIANT"
    else
        issues+=("No device compliance requirement found")
        recommendations+=("Consider requiring compliant devices for sensitive applications")
        log "WARNING" "⚠️ Device compliance requirement: MISSING"
    fi
    
    # Check for high-risk sign-in blocking
    local risk_policies_count=$(echo "$POLICIES_JSON" | jq '[.[] | select((.conditions.signInRiskLevels // []) | contains(["high"]) and (.grantControls.builtInControls // []) | contains(["block"]) and .state == "enabled")] | length')
    
    if [ "$risk_policies_count" -gt 0 ]; then
        compliance_score=$((compliance_score + 20))
        log "SUCCESS" "✅ High-risk sign-in blocking: COMPLIANT"
    else
        issues+=("High-risk sign-ins are not blocked")
        recommendations+=("Create policy to block high-risk sign-ins")
        log "WARNING" "❌ High-risk sign-in blocking: NON-COMPLIANT"
    fi
    
    # Calculate compliance percentage
    local max_score=80
    local compliance_percentage=$(echo "scale=2; ($compliance_score / $max_score) * 100" | bc -l 2>/dev/null || echo "0")
    
    log "INFO" "📊 Overall compliance score: ${compliance_percentage}% ($compliance_score/$max_score)"
    
    # Create analysis results JSON
    ANALYSIS_RESULTS=$(jq -n \
        --argjson score "$compliance_score" \
        --argjson percentage "$compliance_percentage" \
        --argjson issues "$(printf '%s\n' "${issues[@]}" | jq -R . | jq -s .)" \
        --argjson recommendations "$(printf '%s\n' "${recommendations[@]}" | jq -R . | jq -s .)" \
        '{
            complianceScore: $score,
            compliancePercentage: $percentage,
            issues: $issues,
            recommendations: $recommendations
        }')
    
    return 0
}

# Function to analyze policy risks
analyze_policy_risks() {
    log "INFO" "Analyzing policy risks..."
    
    local risk_score=0
    local high_risk_policies=()
    local overly_broad_policies=()
    
    # Analyze each policy for risk factors
    while IFS= read -r policy; do
        local policy_name=$(echo "$policy" | jq -r '.displayName')
        local policy_id=$(echo "$policy" | jq -r '.id')
        local risk_level="Low"
        local risk_factors=()
        
        # Check for overly broad user targeting
        if echo "$policy" | jq -e '.conditions.users.includeUsers // [] | contains(["All"])' > /dev/null; then
            risk_factors+=("Targets all users")
            risk_level="High"
            risk_score=$((risk_score + 10))
        fi
        
        # Check for overly broad application targeting
        if echo "$policy" | jq -e '.conditions.applications.includeApplications // [] | contains(["All"])' > /dev/null; then
            risk_factors+=("Targets all applications")
            risk_level="High"
            risk_score=$((risk_score + 10))
        fi
        
        # Check for any location access
        if echo "$policy" | jq -e '.conditions.locations.includeLocations // [] | contains(["All"])' > /dev/null; then
            risk_factors+=("Allows access from any location")
            if [ "$risk_level" != "High" ]; then
                risk_level="Medium"
            fi
            risk_score=$((risk_score + 5))
        fi
        
        # Check for potential lockout scenarios
        if echo "$policy" | jq -e '(.grantControls.builtInControls // []) | contains(["block"])' > /dev/null && \
           echo "$policy" | jq -e '.conditions.users.includeUsers // [] | contains(["All"])' > /dev/null; then
            risk_factors+=("Blocks all users - potential lockout risk")
            risk_level="Critical"
            risk_score=$((risk_score + 20))
        fi
        
        # Add to risk categories if applicable
        if [[ "$risk_level" == "High" || "$risk_level" == "Critical" ]]; then
            high_risk_policies+=("$policy_name")
        fi
        
        if [[ " ${risk_factors[*]} " =~ "Targets all users" ]] || [[ " ${risk_factors[*]} " =~ "Targets all applications" ]]; then
            overly_broad_policies+=("$policy_name")
        fi
        
    done < <(echo "$POLICIES_JSON" | jq -c '.[]')
    
    log "INFO" "📊 Risk analysis complete. Risk score: $risk_score"
    log "WARNING" "⚠️ High-risk policies found: ${#high_risk_policies[@]}"
    log "WARNING" "📢 Overly broad policies found: ${#overly_broad_policies[@]}"
    
    return 0
}

# Function to export policy data
export_policy_data() {
    local format="$1"
    local output_path="$2"
    
    log "INFO" "Exporting policy data in $format format..."
    
    case "${format^^}" in
        "JSON")
            local json_file="${output_path}/CA-Policies_$(date +%Y%m%d_%H%M%S).json"
            echo "$POLICIES_JSON" | jq '.' > "$json_file"
            log "SUCCESS" "✅ JSON export saved: $json_file"
            ;;
        "CSV")
            local csv_file="${output_path}/CA-Policies_$(date +%Y%m%d_%H%M%S).csv"
            echo "$POLICIES_JSON" | jq -r '
                ["DisplayName","State","CreatedDateTime","ModifiedDateTime","TargetUsers","TargetApps","GrantControls"],
                (.[] | [
                    .displayName,
                    .state,
                    .createdDateTime,
                    .modifiedDateTime,
                    (.conditions.users.includeUsers // [] | join("; ")),
                    (.conditions.applications.includeApplications // [] | join("; ")),
                    (.grantControls.builtInControls // [] | join("; "))
                ]) | @csv
            ' > "$csv_file"
            log "SUCCESS" "✅ CSV export saved: $csv_file"
            ;;
        "HTML")
            local html_file="${output_path}/CA-Policies-Report_$(date +%Y%m%d_%H%M%S).html"
            generate_html_report "$html_file"
            log "SUCCESS" "✅ HTML report saved: $html_file"
            ;;
    esac
    
    return 0
}

# Function to generate HTML report
generate_html_report() {
    local output_file="$1"
    
    local total_policies=$(echo "$POLICIES_JSON" | jq 'length')
    local enabled_policies=$(echo "$POLICIES_JSON" | jq '[.[] | select(.state == "enabled")] | length')
    local disabled_policies=$(echo "$POLICIES_JSON" | jq '[.[] | select(.state == "disabled")] | length')
    local report_only_policies=$(echo "$POLICIES_JSON" | jq '[.[] | select(.state == "enabledForReportingButNotEnforced")] | length')
    
    local compliance_score=$(echo "$ANALYSIS_RESULTS" | jq -r '.complianceScore // 0')
    local issues_count=$(echo "$ANALYSIS_RESULTS" | jq '.issues | length')
    local recommendations_count=$(echo "$ANALYSIS_RESULTS" | jq '.recommendations | length')
    
    cat > "$output_file" << EOF
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
        <p>Generated on: $(date '+%Y-%m-%d %H:%M:%S')</p>
        <p>Total Policies: $total_policies</p>
    </div>
    
    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <p><strong>Enabled Policies:</strong> $enabled_policies</p>
        <p><strong>Disabled Policies:</strong> $disabled_policies</p>
        <p><strong>Report Only Policies:</strong> $report_only_policies</p>
    </div>
    
    <div class="summary">
        <h2>🔍 Compliance Analysis</h2>
        <p class="compliance-good">✅ Compliance Score: $compliance_score points</p>
        <p class="compliance-bad">❌ Issues Found: $issues_count</p>
        <p>📋 Recommendations: $recommendations_count</p>
    </div>
    
    <h2>📋 Policy Details</h2>
EOF

    # Add policy details
    echo "$POLICIES_JSON" | jq -c '.[]' | while IFS= read -r policy; do
        local name=$(echo "$policy" | jq -r '.displayName')
        local state=$(echo "$policy" | jq -r '.state')
        local created=$(echo "$policy" | jq -r '.createdDateTime')
        local modified=$(echo "$policy" | jq -r '.modifiedDateTime')
        local users=$(echo "$policy" | jq -r '.conditions.users.includeUsers // [] | join(", ")')
        local apps=$(echo "$policy" | jq -r '.conditions.applications.includeApplications // [] | join(", ")')
        local controls=$(echo "$policy" | jq -r '.grantControls.builtInControls // [] | join(", ")')
        
        local state_class="enabled"
        if [ "$state" != "enabled" ]; then
            state_class="disabled"
        fi
        
        cat >> "$output_file" << EOF
    <div class="policy $state_class">
        <h3>$name</h3>
        <p><strong>State:</strong> $state</p>
        <p><strong>Created:</strong> $created</p>
        <p><strong>Modified:</strong> $modified</p>
        <p><strong>Target Users:</strong> $users</p>
        <p><strong>Target Applications:</strong> $apps</p>
        <p><strong>Grant Controls:</strong> $controls</p>
    </div>
EOF
    done
    
    # Add recommendations
    cat >> "$output_file" << EOF
    <div class="summary">
        <h2>📈 Recommendations</h2>
        <ul>
EOF
    
    echo "$ANALYSIS_RESULTS" | jq -r '.recommendations[]' | while IFS= read -r recommendation; do
        echo "            <li>$recommendation</li>" >> "$output_file"
    done
    
    cat >> "$output_file" << EOF
        </ul>
    </div>
</body>
</html>
EOF
}

# Function to show summary
show_summary() {
    local total_policies=$(echo "$POLICIES_JSON" | jq 'length')
    local enabled_policies=$(echo "$POLICIES_JSON" | jq '[.[] | select(.state == "enabled")] | length')
    local compliance_score=$(echo "$ANALYSIS_RESULTS" | jq -r '.complianceScore // 0')
    local issues_count=$(echo "$ANALYSIS_RESULTS" | jq '.issues | length')
    local recommendations_count=$(echo "$ANALYSIS_RESULTS" | jq '.recommendations | length')
    
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))
    
    echo
    log "INFO" "═══════════════════════════════════════"
    log "INFO" "      CONDITIONAL ACCESS AUDIT SUMMARY  "
    log "INFO" "═══════════════════════════════════════"
    log "INFO" "📊 Total policies analyzed: $total_policies"
    log "SUCCESS" "✅ Enabled policies: $enabled_policies"
    log "INFO" "🔒 Compliance score: $compliance_score points"
    log "ERROR" "❌ Issues found: $issues_count"
    log "INFO" "💡 Recommendations: $recommendations_count"
    log "INFO" "⏱️ Analysis duration: $duration_formatted"
    log "INFO" "📄 Log file: $LOG_PATH"
    log "INFO" "═══════════════════════════════════════"
}

# Function to cleanup on exit
cleanup() {
    log "INFO" "🔌 Cleaning up..."
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -f|--format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -d|--include-disabled)
            INCLUDE_DISABLED=true
            shift
            ;;
        -a|--analysis-only)
            ANALYSIS_ONLY=true
            shift
            ;;
        -l|--log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate output format
case "${OUTPUT_FORMAT^^}" in
    "JSON"|"CSV"|"HTML"|"ALL") ;;
    *)
        echo "Error: Invalid output format. Must be json, csv, html, or all"
        exit 1
        ;;
esac

# Set up cleanup trap
trap cleanup EXIT

# Main execution
main() {
    log "INFO" "🚀 Starting Conditional Access Policy Audit"
    log "INFO" "⚙️ Config File: $CONFIG_FILE"
    log "INFO" "📊 Output Format: $OUTPUT_FORMAT"
    log "INFO" "📝 Log Level: $LOG_LEVEL"
    
    # Load configuration and initialize logging
    if ! initialize_logging "$CONFIG_FILE"; then
        log "WARNING" "Continuing without file logging..."
    fi
    
    # Check prerequisites
    if ! check_prerequisites; then
        log "ERROR" "❌ Prerequisites check failed. Exiting."
        exit 1
    fi
    
    # Connect to Microsoft Graph
    if ! connect_to_graph; then
        log "ERROR" "❌ Failed to connect to Microsoft Graph. Exiting."
        exit 1
    fi
    
    # Get Conditional Access policies
    if ! get_conditional_access_policies; then
        log "ERROR" "❌ Failed to retrieve Conditional Access policies. Exiting."
        exit 1
    fi
    
    # Perform analysis
    log "INFO" "🔍 Starting policy analysis..."
    if ! analyze_policy_compliance; then
        log "ERROR" "❌ Policy compliance analysis failed."
        exit 1
    fi
    
    if ! analyze_policy_risks; then
        log "ERROR" "❌ Policy risk analysis failed."
        exit 1
    fi
    
    # Create output directory
    local output_dir
    if [ -f "$CONFIG_FILE" ]; then
        output_dir=$(jq -r '.ReportPath // "./reports/"' "$CONFIG_FILE")
    else
        output_dir="./reports/"
    fi
    
    mkdir -p "$output_dir"
    log "DEBUG" "Created output directory: $output_dir"
    
    # Export data based on format selection
    if [ "$ANALYSIS_ONLY" = false ]; then
        if [ "${OUTPUT_FORMAT^^}" = "ALL" ]; then
            for format in "JSON" "CSV" "HTML"; do
                export_policy_data "$format" "$output_dir"
            done
        else
            export_policy_data "$OUTPUT_FORMAT" "$output_dir"
        fi
    fi
    
    # Show summary
    show_summary
    
    # Set exit code based on compliance
    local issues_count=$(echo "$ANALYSIS_RESULTS" | jq '.issues | length')
    if [ "$issues_count" -gt 0 ]; then
        log "WARNING" "⚠️ Audit completed with issues"
        exit 1
    else
        log "SUCCESS" "✅ Audit completed successfully"
        exit 0
    fi
}

# Run main function
main "$@"
