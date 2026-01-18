#!/bin/bash
# Example script demonstrating batch API usage
# Usage: ./batch_example.sh [SERVER_URL]
# Example: ./batch_example.sh http://localhost:9090

SERVER_URL="${1:-${SERVER_URL:-http://localhost:9090}}"

echo "=== Batch Check Example ==="
echo

# Example 1: Batch check with multiple users and actions
echo "Example 1: Multiple authorization checks"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$SERVER_URL/api/v1/batch_check" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "principal": { "User": { "id": "alice", "namespace": ["DNS"], "groups": [{ "id": "admins", "namespace": ["DNS"] }] } },
        "action": { "id": "create_host", "namespace": ["DNS"] },
        "resource": {
          "kind": "Host",
          "id": "web01.example.com",
          "attrs": {
            "ip": { "type": "Ip", "value": "10.0.0.1" }
          }
        }
      },
      {
        "principal": { "User": { "id": "bob", "namespace": ["DNS"], "groups": [{ "id": "users", "namespace": ["DNS"] }] } },
        "action": { "id": "view_host", "namespace": ["DNS"] },
        "resource": {
          "kind": "Host",
          "id": "web01.example.com",
          "attrs": {
            "ip": { "type": "Ip", "value": "10.0.0.1" }
          }
        }
      },
      {
        "principal": { "User": { "id": "charlie", "namespace": ["DNS"], "groups": [{ "id": "users", "namespace": ["DNS"] }] } },
        "action": { "id": "delete_host", "namespace": ["DNS"] },
        "resource": {
          "kind": "Host",
          "id": "web01.example.com",
          "attrs": {
            "ip": { "type": "Ip", "value": "10.0.0.1" }
          }
        }
      },
      {
        "principal": { "User": { "id": "super", "namespace": [], "groups": [] } },
        "action": { "id": "create_label", "namespace": ["DNS"] },
        "resource": {
          "kind": "Label",
          "id": "label1"
        }
      }
    ]
  }')
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -eq 200 ]; then
  echo "$BODY" | jq '.'
else
  echo "HTTP $HTTP_CODE"
  echo "$BODY"
fi

echo
echo "=== Batch Check Detailed Example ==="
echo

# Example 2: Detailed batch check showing policy information
echo "Example 2: Detailed results with policy information"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$SERVER_URL/api/v1/batch_check_detailed" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {
        "principal": { "User": { "id": "alice", "namespace": ["DNS"], "groups": [{ "id": "admins", "namespace": ["DNS"] }] } },
        "action": { "id": "view_host", "namespace": ["DNS"] },
        "resource": {
          "kind": "Host",
          "id": "web01.example.com",
          "attrs": {
            "ip": { "type": "Ip", "value": "192.168.1.1" }
          }
        }
      },
      {
        "principal": { "User": { "id": "webadmin", "namespace": ["DNS"], "groups": [{ "id": "webadmins", "namespace": ["DNS"] }] } },
        "action": { "id": "delete_host", "namespace": ["DNS"] },
        "resource": {
          "kind": "Host",
          "id": "webserver-001.example.com",
          "attrs": {
            "ip": { "type": "Ip", "value": "192.168.1.50" }
          }
        }
      }
    ]
  }')
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -eq 200 ]; then
  echo "$BODY" | jq '.'
else
  echo "HTTP $HTTP_CODE"
  echo "$BODY"
fi

echo
echo "=== Performance Test ==="
echo

# Example 3: Large batch for performance testing
echo "Example 3: Processing 100 requests in a single batch"

# Generate batch payload using Python
BATCH_PAYLOAD=$(python3 << 'PYTHON_EOF'
import json
requests = []
for i in range(100):
    # Alternate between different user types
    if i % 3 == 0:
        principal = { "User": { "id": "alice", "namespace": ["DNS"], "groups": [{ "id": "admins", "namespace": ["DNS"] }] } }
    elif i % 3 == 1:
        principal = { "User": { "id": "bob", "namespace": ["DNS"], "groups": [{ "id": "users", "namespace": ["DNS"] }] } }
    else:
        principal = { "User": { "id": "super", "namespace": [], "groups": [] } }
    
    requests.append({
        "principal": principal,
        "action": { "id": "view_host", "namespace": ["DNS"] },
        "resource": {
            "kind": "Host",
            "id": f"host{i}.example.com",
            "attrs": {
                "ip": { "type": "Ip", "value": f"10.0.{i // 256}.{i % 256}" }
            }
        }
    })
print(json.dumps({"requests": requests}))
PYTHON_EOF
)

RESPONSE=$(time curl -s -w "\n%{http_code}" -X POST "$SERVER_URL/api/v1/batch_check" \
  -H "Content-Type: application/json" \
  -d "$BATCH_PAYLOAD")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -eq 200 ]; then
  echo "$BODY" | jq '.successful, .failed, .version.hash' | head -3
else
  echo "HTTP $HTTP_CODE"
  echo "$BODY"
fi

echo
echo "Done!"
