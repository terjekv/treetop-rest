#!/bin/bash

# Matrix Example: Testing multiple principal/action combinations
# This script demonstrates the matrix expansion feature
#
# Matrix syntax:
# - Use pipe | for alternative values: alice|bob
# - Use square brackets [] for Cedar group entries: alice[admins|webmasters]
# - Combinations are expanded into separate queries with descriptive IDs

set -e

HOST="${1:-127.0.0.1}"
PORT="${2:-9999}"
BASE_URL="http://${HOST}:${PORT}"

echo "Matrix Query Examples"
echo "====================="
echo ""
echo "1. Simple alternatives (2 principals × 2 actions = 4 queries)"
echo "   Command: --principal alice|bob --action view|edit --resource-type Photo --resource-id VacationPhoto94.jpg"
./target/debug/treetop-cli \
  --host "$HOST" --port "$PORT" \
  check \
  --principal "alice|bob" \
  --action "view|edit" \
  --resource-type "Photo" \
  --resource-id "VacationPhoto94.jpg"

echo ""
echo "2. With group bracket notation (2 groups = 2 queries)"
echo "   Command: --principal User::admins[alice|bob] --action view --resource-type Photo --resource-id VacationPhoto94.jpg"
./target/debug/treetop-cli \
  --host "$HOST" --port "$PORT" \
  check \
  --principal "User::admins[alice|bob]" \
  --action "view" \
  --resource-type "Photo" \
  --resource-id "VacationPhoto94.jpg"

echo ""
echo "3. Large matrix (2 principals × 3 actions × 2 resources = 12 queries)"
./target/debug/treetop-cli \
  --host "$HOST" --port "$PORT" \
  check \
  --principal "alice|bob" \
  --action "view|edit|delete" \
  --resource-type "Photo" \
  --resource-id "VacationPhoto94.jpg|Photo123.jpg" \
  --table

echo ""
echo "Matrix expansion completed. All permutations were tested."
