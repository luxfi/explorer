#!/bin/sh
# healthcheck.sh -- Check explorer health and report per-chain block counts
#
# Usage: ./scripts/healthcheck.sh [base_url]
#   base_url defaults to http://localhost:8090

set -e

BASE="${1:-http://localhost:8090}"

printf "Checking %s ...\n\n" "$BASE"

# Health endpoint
printf "%-20s " "/health"
status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/health" 2>/dev/null) || status="unreachable"
if [ "$status" = "200" ]; then
    printf "OK (200)\n"
else
    printf "FAIL (%s)\n" "$status"
    exit 1
fi

# Stats endpoint
printf "%-20s " "/v1/explorer/stats"
stats=$(curl -sf "$BASE/v1/explorer/stats" 2>/dev/null) || stats=""
if [ -z "$stats" ]; then
    printf "FAIL (no response)\n"
    exit 1
fi
printf "OK\n\n"

# Parse per-chain block counts from stats JSON
# Expected format: {"chains":[{"name":"...","chain_id":...,"block_count":...},...]}
printf "%-16s %-12s %s\n" "CHAIN" "CHAIN_ID" "BLOCKS"
printf "%-16s %-12s %s\n" "-----" "--------" "------"

echo "$stats" | \
    sed 's/},{/}\n{/g' | \
    sed -n 's/.*"name":"\([^"]*\)".*"chain_id":\([0-9]*\).*"block_count":\([0-9]*\).*/\1|\2|\3/p' | \
    while IFS='|' read -r name chain_id blocks; do
        printf "%-16s %-12s %s\n" "$name" "$chain_id" "$blocks"
    done

# If no chains parsed, show raw stats
if ! echo "$stats" | grep -q '"name"'; then
    printf "(single chain mode)\n"
    block_count=$(echo "$stats" | sed -n 's/.*"block_count":\([0-9]*\).*/\1/p')
    printf "%-16s %-12s %s\n" "default" "-" "${block_count:-unknown}"
fi

printf "\nDone.\n"
