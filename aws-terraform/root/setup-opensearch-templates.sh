#!/bin/bash
# setup-opensearch-templates.sh
# Terraform 배포 후 Bastion에서 실행

OPENSEARCH_ENDPOINT="vpc-cloudpentagon-logs-x3mbpblueqymmklmlujzttgeuu.ap-northeast-2.es.amazonaws.com"
ADMIN_PASSWORD="Admin123!@#"

# App logs template
curl -k -u admin:"${ADMIN_PASSWORD}" -X PUT \
  "https://${OPENSEARCH_ENDPOINT}/_index_template/app-logs-template" \
  -H 'Content-Type: application/json' \
  -d '{
  "index_patterns": ["app-logs-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "timestamp": { "type": "date" },
        "logGroup": { "type": "keyword" },
        "logStream": { "type": "keyword" },
        "owner": { "type": "keyword" },
        "eventCount": { "type": "integer" },
        "messageType": { "type": "keyword" }
      }
    }
  },
  "priority": 100
}'

echo "App logs template created"

# Infra logs template  
curl -k -u admin:"${ADMIN_PASSWORD}" -X PUT \
  "https://${OPENSEARCH_ENDPOINT}/_index_template/infra-logs-template" \
  -H 'Content-Type: application/json' \
  -d '{
  "index_patterns": ["infra-logs-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "timestamp": { "type": "date" },
        "logGroup": { "type": "keyword" },
        "logStream": { "type": "keyword" },
        "owner": { "type": "keyword" },
        "eventCount": { "type": "integer" }
      }
    }
  },
  "priority": 100
}'

echo "Infra logs template created"

# Audit logs template
curl -k -u admin:"${ADMIN_PASSWORD}" -X PUT \
  "https://${OPENSEARCH_ENDPOINT}/_index_template/audit-logs-template" \
  -H 'Content-Type: application/json' \
  -d '{
  "index_patterns": ["audit-logs-*"],
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "timestamp": { "type": "date" },
        "logGroup": { "type": "keyword" },
        "logStream": { "type": "keyword" },
        "owner": { "type": "keyword" },
        "eventCount": { "type": "integer" }
      }
    }
  },
  "priority": 100
}'

echo "Audit logs template created"
echo "All templates created successfully!"