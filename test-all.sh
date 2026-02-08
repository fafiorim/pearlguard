#!/bin/bash
#
# FinGuard - Comprehensive Test Runner
# Runs all tests including configuration validation and file uploads
#

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
FINGUARD_URL="${FINGUARD_URL:-http://localhost:3000}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
USER_USER="${USER_USER:-user}"
USER_PASS="${USER_PASS:-user123}"

echo -e "${BOLD}============================================${NC}"
echo -e "${BOLD}FinGuard Comprehensive Test Suite${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""

# Check if server is running
echo -e "${BLUE}Checking if FinGuard is running...${NC}"
if ! curl -s -f "${FINGUARD_URL}/api/health" -u "${ADMIN_USER}:${ADMIN_PASS}" > /dev/null 2>&1; then
    echo -e "${RED}✗ FinGuard server is not accessible at ${FINGUARD_URL}${NC}"
    echo -e "${YELLOW}Please start the server first:${NC}"
    echo "  docker run -d --name finguard-test -p 3000:3000 -e SCANNER_EXTERNAL_ADDR=10.10.21.201:50051 finguard:latest"
    exit 1
fi
echo -e "${GREEN}✓ Server is accessible${NC}"
echo ""

# Check Python dependencies
echo -e "${BLUE}Checking Python dependencies...${NC}"
if ! python3 -c "import requests" 2>/dev/null; then
    echo -e "${YELLOW}Installing requests library...${NC}"
    pip3 install requests || {
        echo -e "${RED}✗ Failed to install requests. Please run: pip3 install requests${NC}"
        exit 1
    }
fi
echo -e "${GREEN}✓ Python dependencies satisfied${NC}"
echo ""

# Run Python test suite
echo -e "${BOLD}${BLUE}Running Python Test Suite...${NC}"
echo ""
python3 test-scanner.py
TEST_EXIT_CODE=$?

echo ""
echo -e "${BOLD}============================================${NC}"

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ All tests passed!${NC}"
    echo ""
    echo -e "Test Coverage:"
    echo -e "  ✓ Health checks"
    echo -e "  ✓ Authentication (admin & user)"
    echo -e "  ✓ Scanner configurations (PML, Verbose, Active Content)"
    echo -e "  ✓ Security modes (prevent, logOnly, disabled)"
    echo -e "  ✓ EICAR malware detection"
    echo -e "  ✓ Safe file scanning"
    echo -e "  ✓ Active content detection"
    echo -e "  ✓ Scan results API"
    exit 0
else
    echo -e "${RED}${BOLD}✗ Some tests failed${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo -e "  1. Check scanner logs: docker logs finguard-test"
    echo -e "  2. Verify external scanner is accessible: curl http://10.10.21.201:50051"
    echo -e "  3. Check configuration: curl ${FINGUARD_URL}/api/config -u ${ADMIN_USER}:${ADMIN_PASS}"
    echo -e "  4. Review test output above for specific failures"
    exit 1
fi
