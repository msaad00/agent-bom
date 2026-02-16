#!/bin/bash
# End-to-End Testing Script for agent-bom
# Tests all major workflows and identifies gaps

set -e  # Exit on error

echo "🧪 agent-bom End-to-End Test Suite"
echo "===================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

test_step() {
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "${BLUE}[TEST $TESTS_RUN]${NC} $1"
}

test_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}✓ PASS${NC}: $1"
    echo ""
}

test_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}✗ FAIL${NC}: $1"
    echo ""
}

test_skip() {
    echo -e "${YELLOW}⊘ SKIP${NC}: $1"
    echo ""
}

# Test 1: Check installation
test_step "Check agent-bom installation"
if command -v agent-bom &> /dev/null; then
    VERSION=$(agent-bom --version 2>&1 || echo "unknown")
    test_pass "agent-bom is installed: $VERSION"
else
    test_fail "agent-bom not found in PATH. Run: pip install -e ."
    exit 1
fi

# Test 2: Discover MCP configs
test_step "Discover MCP configurations"
DISCOVERY_OUTPUT=$(agent-bom where 2>&1)
if echo "$DISCOVERY_OUTPUT" | grep -q "claude-desktop\|cursor\|windsurf"; then
    test_pass "Discovery paths configured"
else
    test_fail "No discovery paths found"
fi

# Test 3: Run basic inventory (no vuln scan)
test_step "Run inventory scan (no vulnerabilities)"
if agent-bom inventory > /tmp/agent-bom-inventory.log 2>&1; then
    SERVERS=$(grep -c "MCP server(s)" /tmp/agent-bom-inventory.log || echo "0")
    if [ "$SERVERS" -gt 0 ]; then
        test_pass "Found MCP servers in inventory"
    else
        test_skip "No MCP servers found on this system"
    fi
else
    test_fail "Inventory scan failed. Check /tmp/agent-bom-inventory.log"
fi

# Test 4: Full scan with vulnerabilities
test_step "Full vulnerability scan"
if agent-bom scan > /tmp/agent-bom-scan.log 2>&1; then
    if grep -q "Scanning.*unique packages" /tmp/agent-bom-scan.log; then
        test_pass "Vulnerability scanning executed"
    else
        test_skip "No packages to scan"
    fi
else
    test_fail "Scan failed. Check /tmp/agent-bom-scan.log"
fi

# Test 5: Transitive dependency resolution
test_step "Test transitive dependency resolution"
if agent-bom scan --transitive --max-depth 2 > /tmp/agent-bom-transitive.log 2>&1; then
    if grep -q "Resolving transitive dependencies" /tmp/agent-bom-transitive.log; then
        test_pass "Transitive resolution attempted"
    else
        test_skip "No npx/uvx packages to resolve"
    fi
else
    test_fail "Transitive scan failed"
fi

# Test 6: JSON export
test_step "Export JSON report"
if agent-bom scan --format json --output /tmp/agent-bom-test.json 2>&1; then
    if [ -f /tmp/agent-bom-test.json ]; then
        if python3 -m json.tool /tmp/agent-bom-test.json > /dev/null 2>&1; then
            test_pass "Valid JSON export generated"
        else
            test_fail "JSON export is malformed"
        fi
    else
        test_fail "JSON file not created"
    fi
else
    test_fail "JSON export failed"
fi

# Test 7: CycloneDX export
test_step "Export CycloneDX BOM"
if agent-bom scan --format cyclonedx --output /tmp/agent-bom-test.cdx.json 2>&1; then
    if [ -f /tmp/agent-bom-test.cdx.json ]; then
        if python3 -m json.tool /tmp/agent-bom-test.cdx.json > /dev/null 2>&1; then
            if grep -q '"bomFormat": "CycloneDX"' /tmp/agent-bom-test.cdx.json; then
                test_pass "Valid CycloneDX BOM generated"
            else
                test_fail "CycloneDX format incorrect"
            fi
        else
            test_fail "CycloneDX JSON malformed"
        fi
    else
        test_fail "CycloneDX file not created"
    fi
else
    test_fail "CycloneDX export failed"
fi

# Test 8: Verify OSV.dev connectivity
test_step "Test OSV.dev API connectivity"
OSV_TEST=$(curl -s -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"package":{"name":"express","ecosystem":"npm"},"version":"4.18.2"}' 2>&1)

if echo "$OSV_TEST" | grep -q "vulns"; then
    test_pass "OSV.dev API is reachable and responding"
else
    test_fail "Cannot reach OSV.dev API"
fi

# Test 9: Check for known vulnerabilities in test package
test_step "Verify vulnerability detection (express@4.18.2 has known vulns)"
if echo "$OSV_TEST" | python3 -c "import sys, json; data=json.load(sys.stdin); print('✓' if data.get('vulns') else '✗')" 2>/dev/null | grep -q "✓"; then
    test_pass "OSV correctly identifies known vulnerabilities"
else
    test_fail "OSV not detecting known vulnerabilities"
fi

# Test 10: Package extraction accuracy
test_step "Verify package extraction from lock files"
# Create test package.json
mkdir -p /tmp/test-mcp-server
cat > /tmp/test-mcp-server/package.json << 'EOF'
{
  "name": "test-server",
  "dependencies": {
    "express": "4.18.2",
    "axios": "1.6.0"
  }
}
EOF

# Note: This would require actually running the parser on test data
test_skip "Package extraction accuracy (manual verification needed)"

# Summary
echo ""
echo "===================================="
echo "📊 Test Summary"
echo "===================================="
echo -e "Total:  $TESTS_RUN tests"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo -e "${YELLOW}Skipped: $((TESTS_RUN - TESTS_PASSED - TESTS_FAILED))${NC}"
echo ""

# Detailed logs
echo "📝 Detailed logs available:"
echo "  - /tmp/agent-bom-inventory.log"
echo "  - /tmp/agent-bom-scan.log"
echo "  - /tmp/agent-bom-transitive.log"
echo "  - /tmp/agent-bom-test.json"
echo "  - /tmp/agent-bom-test.cdx.json"
echo ""

# Known gaps
echo "🔍 Known Gaps (Not Yet Implemented):"
echo "  ❌ Snowflake Cortex scanning"
echo "  ❌ AWS Bedrock agent discovery"
echo "  ❌ Azure OpenAI agent inventory"
echo "  ❌ Google ADK scanning"
echo "  ❌ Direct NVD API integration"
echo "  ❌ EPSS score enrichment"
echo "  ❌ Live MCP server introspection"
echo "  ❌ Dependency graph visualization"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All critical tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed. Review logs above.${NC}"
    exit 1
fi
