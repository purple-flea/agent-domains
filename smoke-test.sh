#!/bin/bash
# Domains Smoke Test — checks all public endpoints return 200
# Usage: ./domains-smoke-test.sh [BASE_URL]
# Default BASE_URL: http://localhost:3004

BASE_URL="${1:-http://localhost:3004}"
PASS=0
FAIL=0
ERRORS=()

check() {
  local method="$1"
  local path="$2"
  local desc="$3"
  local body="$4"
  local expected="${5:-200}"

  if [ -n "$body" ]; then
    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
      -H "Content-Type: application/json" \
      -d "$body" \
      "${BASE_URL}${path}")
  else
    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "${BASE_URL}${path}")
  fi

  if [ "$status" = "$expected" ]; then
    echo "  ✓ $method $path ($desc) → $status"
    PASS=$((PASS + 1))
  else
    echo "  ✗ $method $path ($desc) → $status (expected $expected)"
    FAIL=$((FAIL + 1))
    ERRORS+=("$method $path: got $status, expected $expected")
  fi
}

echo "=== Domains Smoke Test ==="
echo "Target: $BASE_URL"
echo ""

echo "--- Public endpoints ---"
check GET /health "health check"
check GET /gossip "gossip"
check GET /public-stats "public stats"
check GET /tlds "TLD pricing table"
check GET "/search?name=example.com" "domain search"
check GET "/search?name=purpleflea&tlds=com,io,ai" "multi-TLD search"
check GET /network "network"
check GET /changelog "changelog"
check GET /robots.txt "robots.txt"
check GET /sitemap.xml "sitemap"
check GET /.well-known/agent.json "agent.json"
check GET /.well-known/purpleflea.json "purpleflea.json"
check GET /openapi.json "openapi spec"
check GET /llms.txt "llms.txt"
check GET /favicon.ico "favicon" "" 204
check GET /ping "ping"

echo ""
echo "--- Auth endpoints return 401 without token ---"
check GET /wallet/balance "balance (no auth)" "" 401
check POST /domains/purchase "purchase (no auth)" '{"domain":"test.com"}' 401
check GET /domains "my domains (no auth)" "" 401

echo ""
echo "--- 404 handling ---"
check GET /nonexistent-path "404 handler" "" 404

echo ""
echo "==========================="
echo "Results: $PASS passed, $FAIL failed"
if [ ${#ERRORS[@]} -gt 0 ]; then
  echo ""
  echo "FAILURES:"
  for err in "${ERRORS[@]}"; do
    echo "  - $err"
  done
  exit 1
else
  echo "All checks passed!"
  exit 0
fi
