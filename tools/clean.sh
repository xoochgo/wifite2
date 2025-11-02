#!/bin/bash
#
# Wifite2 Cracked Database Cleaner
# Removes duplicate entries from cracked.json based on BSSID
#
# Usage: ./clean.sh [cracked.json]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default file location (relative to tools directory)
CRACKED_FILE="${1:-../cracked.json}"

# Check if file exists
if [ ! -f "$CRACKED_FILE" ]; then
    echo -e "${RED}[!]${NC} Error: File '$CRACKED_FILE' not found"
    echo -e "${BLUE}[?]${NC} Usage: $0 [cracked.json]"
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo -e "${RED}[!]${NC} Error: 'jq' is required but not installed"
    echo -e "${BLUE}[?]${NC} Install with: sudo apt install jq"
    exit 1
fi

# Validate JSON format
if ! jq empty "$CRACKED_FILE" 2>/dev/null; then
    echo -e "${RED}[!]${NC} Error: '$CRACKED_FILE' is not valid JSON"
    exit 1
fi

# Create backup
BACKUP_FILE="${CRACKED_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
cp "$CRACKED_FILE" "$BACKUP_FILE"
echo -e "${GREEN}[+]${NC} Created backup: $BACKUP_FILE"

# Count original entries
ORIGINAL_COUNT=$(jq 'length' "$CRACKED_FILE")
echo -e "${BLUE}[*]${NC} Original entries: $ORIGINAL_COUNT"

# Remove duplicates based on BSSID (keep the most recent entry)
# Sort by date descending, then use unique_by to keep first occurrence (most recent)
jq 'sort_by(.date) | reverse | unique_by(.bssid)' "$CRACKED_FILE" > "${CRACKED_FILE}.tmp"

# Count cleaned entries
CLEANED_COUNT=$(jq 'length' "${CRACKED_FILE}.tmp")
REMOVED_COUNT=$((ORIGINAL_COUNT - CLEANED_COUNT))

# Show results
echo -e "${BLUE}[*]${NC} Cleaned entries: $CLEANED_COUNT"

if [ $REMOVED_COUNT -gt 0 ]; then
    echo -e "${YELLOW}[!]${NC} Removed $REMOVED_COUNT duplicate(s)"
    
    # Show which BSSIDs had duplicates
    echo -e "${BLUE}[*]${NC} Duplicate BSSIDs removed:"
    jq -r '.[].bssid' "$CRACKED_FILE" | sort | uniq -d | while read -r bssid; do
        ESSID=$(jq -r ".[] | select(.bssid == \"$bssid\") | .essid" "$CRACKED_FILE" | head -1)
        echo -e "    ${YELLOW}→${NC} $bssid ($ESSID)"
    done
    
    # Replace original file
    mv "${CRACKED_FILE}.tmp" "$CRACKED_FILE"
    echo -e "${GREEN}[+]${NC} Successfully cleaned $CRACKED_FILE"
    echo -e "${GREEN}[+]${NC} Kept most recent entry for each BSSID"
else
    echo -e "${GREEN}[+]${NC} No duplicates found - file is already clean"
    rm "${CRACKED_FILE}.tmp"
fi

echo -e "${BLUE}[*]${NC} Done!"
