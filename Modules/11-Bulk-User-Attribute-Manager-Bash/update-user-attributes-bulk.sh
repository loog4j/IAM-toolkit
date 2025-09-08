#!/bin/bash

#
# Bulk update user attributes for Entra ID from CSV file
# 
# Description:
#   Reads user data from CSV and performs bulk updates to user attributes in Entra ID.
#   This is the cross-platform equivalent of the PowerShell script, supporting Entra ID only.
#   For Active Directory operations, use the PowerShell version on Windows.
#
# Requirements:
#   - Microsoft Graph CLI (mgc) or Azure CLI (az) installed and configured
#   - jq for JSON processing
#   - Appropriate permissions: User.ReadWrite.All, Directory.ReadWrite.All
#
# Usage:
#   ./update-user-attributes-bulk.sh [OPTIONS]
#
# Examples:
#   ./update-user-attributes-bulk.sh --csv-file users.csv
#   ./update-user-attributes-bulk.sh --csv-file users.csv --whatif
#   ./update-user-attributes-bulk.sh --csv-file users.csv --log-level DEBUG
#
# Author: Identity Security Automation Project
# Version: 1.0
#

set -euo pipefail

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/Update-UserAttributesBulk-Config.json"
CSV_FILE=""
WHATIF=false
LOG_LEVEL="INFO"
START_TIME=$(date +%s)
LOG_PATH=""
USER_DATA=""
SUCCESS_COUNT=0
ERROR_COUNT=0

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

Bulk update user attributes for Entra ID from CSV file

OPTIONS:
    -c, --csv-file PATH     Path to CSV file containing user updates (required)
    -f, --config PATH       Path to configuration file (default: ./Update-UserAttributesBulk-Config.json)
    -w, --whatif           Preview changes without applying them
    -l, --log-level LEVEL   Logging level: INFO, WARNING, ERROR, DEBUG (default: INFO)
    -h, --help             Display this help message

EXAMPLES:
    $0 --csv-file users.csv
    $0 --csv-file users.csv --whatif
    $0 --csv-file users.csv --log-level DEBUG

REQUIREMENTS:
    - Microsoft Graph CLI (mgc) or Azure CLI (az) installed
    - jq for JSON processing
    - Appropriate Azure AD permissions

NOTE:
    This script only supports Entra ID operations. For Active Directory operations,
    use the PowerShell version on Windows.

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
        
        LOG_PATH="${log_dir}/BulkUserUpdate_$(date +%Y%m%d_%H%M%S).log"
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
    
    # Check CSV file
    if [ -z "$CSV_FILE" ]; then
        issues+=("CSV file path is required")
    elif [ ! -f "$CSV_FILE" ]; then
        issues+=("CSV file not found: $CSV_FILE")
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
            if mgc auth login --scopes "User.ReadWrite.All Directory.ReadWrite.All"; then
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

# Function to validate user data
validate_user_data() {
    local user_json="$1"
    local config_file="$2"
    
    local errors=()
    
    # Check required fields
    if [ -f "$config_file" ]; then
        local required_fields=$(jq -r '.RequiredFields[]' "$config_file" 2>/dev/null || echo "UserPrincipalName Action")
        
        while IFS= read -r field; do
            if [ -n "$field" ]; then
                local value=$(echo "$user_json" | jq -r ".$field // empty")
                if [ -z "$value" ] || [ "$value" = "null" ]; then
                    errors+=("Missing required field: $field")
                fi
            fi
        done <<< "$required_fields"
    else
        # Default required fields
        local upn=$(echo "$user_json" | jq -r '.UserPrincipalName // empty')
        local action=$(echo "$user_json" | jq -r '.Action // empty')
        
        if [ -z "$upn" ] || [ "$upn" = "null" ]; then
            errors+=("Missing required field: UserPrincipalName")
        fi
        
        if [ -z "$action" ] || [ "$action" = "null" ]; then
            errors+=("Missing required field: Action")
        fi
    fi
    
    # Validate email format for UserPrincipalName
    local upn=$(echo "$user_json" | jq -r '.UserPrincipalName // empty')
    if [ -n "$upn" ] && [ "$upn" != "null" ]; then
        if ! echo "$upn" | grep -qE '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; then
            errors+=("Invalid email format for UserPrincipalName: $upn")
        fi
    fi
    
    # Validate supported actions
    local action=$(echo "$user_json" | jq -r '.Action // empty')
    if [ -n "$action" ] && [ "$action" != "null" ]; then
        if [[ ! "$action" =~ ^(UPDATE|CREATE|DISABLE)$ ]]; then
            errors+=("Unsupported action: $action. Supported: UPDATE, CREATE, DISABLE")
        fi
    fi
    
    # Return validation results
    if [ ${#errors[@]} -gt 0 ]; then
        printf '%s\n' "${errors[@]}"
        return 1
    fi
    
    return 0
}

# Function to get user from Entra ID
get_entra_user() {
    local upn="$1"
    local temp_file=$(mktemp)
    
    # Try Microsoft Graph CLI first
    if command -v mgc &> /dev/null && mgc auth status &> /dev/null; then
        if mgc users get --user-id "$upn" --output json > "$temp_file" 2>/dev/null; then
            cat "$temp_file"
            rm -f "$temp_file"
            return 0
        fi
    # Fallback to Azure CLI
    elif command -v az &> /dev/null && az account show &> /dev/null; then
        if az rest --method GET --url "https://graph.microsoft.com/v1.0/users/$upn" --output json > "$temp_file" 2>/dev/null; then
            cat "$temp_file"
            rm -f "$temp_file"
            return 0
        fi
    fi
    
    rm -f "$temp_file"
    return 1
}

# Function to update Entra ID user attributes
update_entra_user() {
    local user_json="$1"
    local config_file="$2"
    
    local upn=$(echo "$user_json" | jq -r '.UserPrincipalName')
    local action=$(echo "$user_json" | jq -r '.Action')
    
    log "DEBUG" "Processing Entra ID user: $upn"
    
    # Get existing user
    local existing_user
    if ! existing_user=$(get_entra_user "$upn"); then
        if [ "$action" = "CREATE" ]; then
            log "WARNING" "User not found, CREATE action not implemented in this version"
            return 1
        else
            log "ERROR" "❌ User not found in Entra ID: $upn"
            return 1
        fi
    fi
    
    local user_id=$(echo "$existing_user" | jq -r '.id')
    
    # Build update parameters using Entra ID attribute mapping
    local update_params="{}"
    
    # Map attributes based on configuration or defaults
    local mapping
    if [ -f "$config_file" ]; then
        mapping=$(jq -r '.EntraIdAttributeMapping // {}' "$config_file")
    else
        mapping='{"DisplayName":"displayName","Department":"department","Title":"jobTitle","OfficeLocation":"officeLocation","PhoneNumber":"businessPhones"}'
    fi
    
    # Process each field in the mapping
    echo "$mapping" | jq -r 'to_entries[] | "\(.key):\(.value)"' | while IFS=: read -r csv_field entra_field; do
        local value=$(echo "$user_json" | jq -r ".$csv_field // empty")
        
        if [ -n "$value" ] && [ "$value" != "null" ] && [ "$value" != "" ]; then
            if [ "$csv_field" = "PhoneNumber" ]; then
                # Handle phone numbers as array
                update_params=$(echo "$update_params" | jq --arg field "$entra_field" --arg value "$value" '. + {($field): [$value]}')
            else
                update_params=$(echo "$update_params" | jq --arg field "$entra_field" --arg value "$value" '. + {($field): $value}')
            fi
        fi
    done
    
    # Handle manager separately
    local manager=$(echo "$user_json" | jq -r '.Manager // empty')
    if [ -n "$manager" ] && [ "$manager" != "null" ] && [ "$manager" != "" ]; then
        local manager_user
        if manager_user=$(get_entra_user "$manager"); then
            local manager_id=$(echo "$manager_user" | jq -r '.id')
            update_params=$(echo "$update_params" | jq --arg manager_id "$manager_id" '. + {"manager@odata.bind": "https://graph.microsoft.com/v1.0/users/\($manager_id)"}')
        else
            log "WARNING" "⚠️ Manager not found in Entra ID: $manager"
        fi
    fi
    
    # Check if there are any updates to apply
    local update_count=$(echo "$update_params" | jq 'keys | length')
    if [ "$update_count" -eq 0 ]; then
        log "DEBUG" "No Entra ID attributes to update for: $upn"
        return 0
    fi
    
    # Apply updates
    if [ "$WHATIF" = true ]; then
        local update_keys=$(echo "$update_params" | jq -r 'keys | join(", ")')
        log "INFO" "WHATIF: Would update Entra ID user $upn with: $update_keys"
        return 0
    else
        local temp_file=$(mktemp)
        echo "$update_params" > "$temp_file"
        
        local success=false
        
        # Try Microsoft Graph CLI first
        if command -v mgc &> /dev/null && mgc auth status &> /dev/null; then
            if mgc users patch --user-id "$user_id" --body "@$temp_file" &>/dev/null; then
                success=true
            fi
        # Fallback to Azure CLI
        elif command -v az &> /dev/null && az account show &> /dev/null; then
            if az rest --method PATCH --url "https://graph.microsoft.com/v1.0/users/$user_id" --body "@$temp_file" &>/dev/null; then
                success=true
            fi
        fi
        
        rm -f "$temp_file"
        
        if [ "$success" = true ]; then
            log "SUCCESS" "✅ Updated Entra ID user: $upn"
            return 0
        else
            log "ERROR" "❌ Failed to update Entra ID user: $upn"
            return 1
        fi
    fi
}

# Function to process CSV file
process_csv_file() {
    local csv_file="$1"
    local config_file="$2"
    
    log "INFO" "📊 Processing CSV file: $csv_file"
    
    # Convert CSV to JSON for easier processing
    local temp_json=$(mktemp)
    
    # Read CSV and convert to JSON array
    {
        # Read header
        IFS=',' read -r -a headers
        
        # Process each data row
        echo "["
        local first_row=true
        while IFS=',' read -r -a values; do
            if [ "$first_row" = false ]; then
                echo ","
            fi
            first_row=false
            
            echo -n "{"
            local first_field=true
            for i in "${!headers[@]}"; do
                if [ "$first_field" = false ]; then
                    echo -n ","
                fi
                first_field=false
                
                local header=$(echo "${headers[$i]}" | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                local value=$(echo "${values[$i]:-}" | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                
                echo -n "\"$header\":\"$value\""
            done
            echo -n "}"
        done
        echo "]"
    } < "$csv_file" > "$temp_json"
    
    USER_DATA=$(cat "$temp_json")
    rm -f "$temp_json"
    
    local total_users=$(echo "$USER_DATA" | jq 'length')
    log "INFO" "📊 Loaded $total_users user records from CSV"
    
    if [ "$total_users" -eq 0 ]; then
        log "ERROR" "❌ No user data found in CSV file"
        return 1
    fi
    
    return 0
}

# Function to process users in batches
process_users() {
    local config_file="$1"
    
    # Get batch size from config or use default
    local batch_size=100
    if [ -f "$config_file" ]; then
        batch_size=$(jq -r '.BatchSize // 100' "$config_file")
    fi
    
    # Get throttle delay from config or use default
    local throttle_delay=1000
    if [ -f "$config_file" ]; then
        throttle_delay=$(jq -r '.ThrottleDelay // 1000' "$config_file")
    fi
    
    local total_users=$(echo "$USER_DATA" | jq 'length')
    local batch_count=0
    
    log "INFO" "📦 Processing users in batches of $batch_size..."
    
    # Process users in batches
    for ((i=0; i<total_users; i+=batch_size)); do
        batch_count=$((batch_count + 1))
        local batch_end=$((i + batch_size - 1))
        if [ $batch_end -ge $total_users ]; then
            batch_end=$((total_users - 1))
        fi
        
        log "INFO" "📦 Processing batch $batch_count (Users $((i + 1))-$((batch_end + 1)) of $total_users)"
        
        # Process each user in the batch
        for ((j=i; j<=batch_end; j++)); do
            local user_json=$(echo "$USER_DATA" | jq ".[$j]")
            local upn=$(echo "$user_json" | jq -r '.UserPrincipalName')
            
            log "DEBUG" "👤 Processing user: $upn"
            
            # Validate user data
            local validation_errors
            if validation_errors=$(validate_user_data "$user_json" "$config_file"); then
                # Update user
                if update_entra_user "$user_json" "$config_file"; then
                    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
                else
                    ERROR_COUNT=$((ERROR_COUNT + 1))
                fi
            else
                log "ERROR" "❌ Validation failed for $upn:"
                while IFS= read -r error; do
                    log "ERROR" "  - $error"
                done <<< "$validation_errors"
                ERROR_COUNT=$((ERROR_COUNT + 1))
            fi
        done
        
        # Throttle between batches
        if [ $((batch_end + 1)) -lt $total_users ]; then
            log "DEBUG" "⏳ Waiting ${throttle_delay}ms before next batch..."
            sleep $(echo "scale=3; $throttle_delay / 1000" | bc -l 2>/dev/null || echo "1")
        fi
    done
}

# Function to show summary
show_summary() {
    local total_users=$(echo "$USER_DATA" | jq 'length')
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local duration_formatted=$(printf '%02d:%02d:%02d' $((duration/3600)) $((duration%3600/60)) $((duration%60)))
    
    echo
    log "INFO" "═══════════════════════════════════════"
    log "INFO" "           BULK UPDATE SUMMARY          "
    log "INFO" "═══════════════════════════════════════"
    log "INFO" "📊 Total users processed: $total_users"
    log "SUCCESS" "✅ Successful updates: $SUCCESS_COUNT"
    log "ERROR" "❌ Failed updates: $ERROR_COUNT"
    log "INFO" "⏱️ Total duration: $duration_formatted"
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
        -c|--csv-file)
            CSV_FILE="$2"
            shift 2
            ;;
        -f|--config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        -w|--whatif)
            WHATIF=true
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

# Set up cleanup trap
trap cleanup EXIT

# Main execution
main() {
    log "INFO" "🚀 Starting Identity Security Automation - Bulk User Update (Entra ID)"
    log "INFO" "📁 CSV File: $CSV_FILE"
    log "INFO" "⚙️ Config File: $CONFIG_FILE"
    log "INFO" "🔍 WhatIf Mode: $WHATIF"
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
    
    # Process CSV file
    if ! process_csv_file "$CSV_FILE" "$CONFIG_FILE"; then
        log "ERROR" "❌ Failed to process CSV file. Exiting."
        exit 1
    fi
    
    # Process users
    log "INFO" "🔍 Starting user processing..."
    process_users "$CONFIG_FILE"
    
    # Show summary
    show_summary
    
    # Set exit code based on results
    if [ $ERROR_COUNT -gt 0 ]; then
        log "WARNING" "⚠️ Bulk update completed with errors"
        exit 1
    else
        log "SUCCESS" "✅ Bulk update completed successfully"
        exit 0
    fi
}

# Run main function
main "$@"
