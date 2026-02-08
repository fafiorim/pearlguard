#!/bin/bash
#
# Quick smoke test for FinGuard
# Tests basic functionality without exhaustive configuration testing
#

set -e

# Configuration
FINGUARD_URL="${FINGUARD_URL:-http://localhost:3000}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}FinGuard Quick Smoke Test${NC}"
echo ""

# Test 1: Health Check
echo -n "Testing health endpoint... "
HEALTH_RESPONSE=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASS}" "${FINGUARD_URL}/api/health")
if echo "$HEALTH_RESPONSE" | grep -q '"status":"healthy"'; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "Response: $HEALTH_RESPONSE"
    exit 1
fi

# Test 2: Authentication
echo -n "Testing authentication... "
AUTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -u "invalid:invalid" "${FINGUARD_URL}/api/health")
if [ "$AUTH_RESPONSE" = "401" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗ Expected 401, got $AUTH_RESPONSE${NC}"
    exit 1
fi

# Test 3: EICAR Upload
echo -n "Testing EICAR detection... "
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
UPLOAD_RESPONSE=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASS}" \
    -F "file=@-;filename=eicar.txt" \
    "${FINGUARD_URL}/api/upload" <<< "$EICAR")

if echo "$UPLOAD_RESPONSE" | grep -q '"isSafe":false'; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    echo "Response: $UPLOAD_RESPONSE"
    exit 1
fi

# Test 4: Scan Results
echo -n "Testing scan results API... "
RESULTS_RESPONSE=$(curl -s -u "${ADMIN_USER}:${ADMIN_PASS}" "${FINGUARD_URL}/api/scan-results")
if echo "$RESULTS_RESPONSE" | grep -q '\['; then
    echo -e "${GREEN}✓${NC}"
    SCAN_COUNT=$(echo "$RESULTS_RESPONSE" | grep -o '"scanId"' | wc -l)
    echo "  Found $SCAN_COUNT scan(s) in history"
else
    echo -e "${RED}✗${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}✓ All quick tests passed!${NC}"
