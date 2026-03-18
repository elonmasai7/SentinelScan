#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${BASE_URL:-http://localhost:8000}
EMAIL=${EMAIL:-demo@sentinelscan.io}
PASSWORD=${PASSWORD:-DemoPass123!}

printf "Health check...\n"
curl -sS "$BASE_URL/healthz" | grep -q "ok"

printf "Readiness check...\n"
curl -sS "$BASE_URL/readyz" | grep -q "ready"

printf "Login...\n"
TOKEN=$(curl -sS "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | \
  python -c 'import sys, json; print(json.load(sys.stdin)["access_token"])')

printf "List projects...\n"
curl -sS "$BASE_URL/api/org/projects" -H "Authorization: Bearer $TOKEN" | grep -q "id"

printf "Smoke test passed.\n"
