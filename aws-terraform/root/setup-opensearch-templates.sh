#!/bin/bash
#===============================================================================
# setup-opensearch.sh
# OpenSearch Index Template 설정 및 인덱스 재생성 스크립트
# Terraform 배포 후 Bastion에서 실행
#===============================================================================

set -e

# 설정
OPENSEARCH_ENDPOINT="${OPENSEARCH_ENDPOINT:-vpc-cloudpentagon-logs-x3mbpblueqymmklmlujzttgeuu.ap-northeast-2.es.amazonaws.com}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin123!@#}"
BASE_URL="https://${OPENSEARCH_ENDPOINT}"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 로깅 함수
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# OpenSearch API 호출 함수
opensearch_api() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    if [ -n "$data" ]; then
        curl -sk -X "$method" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
            -H "Content-Type: application/json" \
            "${BASE_URL}${endpoint}" \
            -d "$data"
    else
        curl -sk -X "$method" -u "${ADMIN_USER}:${ADMIN_PASSWORD}" \
            "${BASE_URL}${endpoint}"
    fi
}

# 연결 테스트
test_connection() {
    log_info "OpenSearch 연결 테스트 중..."
    
    if opensearch_api GET "/_cluster/health" | grep -q '"cluster_name"'; then
        log_success "OpenSearch 연결 성공"
        return 0
    else
        log_error "OpenSearch 연결 실패. 엔드포인트와 인증 정보를 확인하세요."
        exit 1
    fi
}

# Index Template 생성
create_templates() {
    log_info "Index Templates 생성 중..."
    
    # App logs template
    local app_template='{
        "index_patterns": ["app-logs-*"],
        "template": {
            "settings": {
                "number_of_shards": 5,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "@timestamp": { "type": "date" },
                    "timestamp": { "type": "date" },
                    "logGroup": { "type": "keyword" },
                    "logStream": { "type": "keyword" },
                    "owner": { "type": "keyword" },
                    "eventCount": { "type": "integer" },
                    "messageType": { "type": "keyword" },
                    "message": { "type": "text" },
                    "events": {
                        "type": "nested",
                        "properties": {
                            "@timestamp": { "type": "date" },
                            "timestamp": { "type": "date" },
                            "message": { "type": "text" },
                            "logGroup": { "type": "keyword" },
                            "logStream": { "type": "keyword" }
                        }
                    }
                }
            }
        },
        "priority": 100
    }'
    
    result=$(opensearch_api PUT "/_index_template/app-logs-template" "$app_template")
    if echo "$result" | grep -q '"acknowledged":true'; then
        log_success "App logs template 생성 완료"
    else
        log_warn "App logs template: $result"
    fi
    
    # Infra logs template
    local infra_template='{
        "index_patterns": ["infra-logs-*"],
        "template": {
            "settings": {
                "number_of_shards": 5,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "@timestamp": { "type": "date" },
                    "timestamp": { "type": "date" },
                    "logGroup": { "type": "keyword" },
                    "logStream": { "type": "keyword" },
                    "owner": { "type": "keyword" },
                    "eventCount": { "type": "integer" },
                    "messageType": { "type": "keyword" },
                    "message": { "type": "text" },
                    "events": {
                        "type": "nested",
                        "properties": {
                            "@timestamp": { "type": "date" },
                            "timestamp": { "type": "date" },
                            "message": { "type": "text" }
                        }
                    }
                }
            }
        },
        "priority": 100
    }'
    
    result=$(opensearch_api PUT "/_index_template/infra-logs-template" "$infra_template")
    if echo "$result" | grep -q '"acknowledged":true'; then
        log_success "Infra logs template 생성 완료"
    else
        log_warn "Infra logs template: $result"
    fi
    
    # Audit logs template
    local audit_template='{
        "index_patterns": ["audit-logs-*"],
        "template": {
            "settings": {
                "number_of_shards": 5,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "@timestamp": { "type": "date" },
                    "timestamp": { "type": "date" },
                    "logGroup": { "type": "keyword" },
                    "logStream": { "type": "keyword" },
                    "owner": { "type": "keyword" },
                    "eventCount": { "type": "integer" },
                    "messageType": { "type": "keyword" },
                    "message": { "type": "text" },
                    "parsed": {
                        "type": "object",
                        "properties": {
                            "eventSource": { "type": "keyword" },
                            "eventName": { "type": "keyword" },
                            "awsRegion": { "type": "keyword" },
                            "sourceIPAddress": { "type": "ip" },
                            "userAgent": { "type": "keyword" },
                            "eventType": { "type": "keyword" }
                        }
                    }
                }
            }
        },
        "priority": 100
    }'
    
    result=$(opensearch_api PUT "/_index_template/audit-logs-template" "$audit_template")
    if echo "$result" | grep -q '"acknowledged":true'; then
        log_success "Audit logs template 생성 완료"
    else
        log_warn "Audit logs template: $result"
    fi
    
    # Access logs template
    local access_template='{
        "index_patterns": ["access-logs-*"],
        "template": {
            "settings": {
                "number_of_shards": 5,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "@timestamp": { "type": "date" },
                    "timestamp": { "type": "date" },
                    "logGroup": { "type": "keyword" },
                    "logStream": { "type": "keyword" },
                    "owner": { "type": "keyword" },
                    "eventCount": { "type": "integer" },
                    "message": { "type": "text" }
                }
            }
        },
        "priority": 100
    }'
    
    result=$(opensearch_api PUT "/_index_template/access-logs-template" "$access_template")
    if echo "$result" | grep -q '"acknowledged":true'; then
        log_success "Access logs template 생성 완료"
    else
        log_warn "Access logs template: $result"
    fi
}

# Firehose IAM Role 매핑
setup_role_mapping() {
    log_info "Firehose IAM Role 매핑 설정 중..."
    
    local role_mapping='{
        "users": ["admin"],
        "backend_roles": [
            "arn:aws:iam::962698957678:role/cloudpentagon-firehose-application-role",
            "arn:aws:iam::962698957678:role/cloudpentagon-firehose-infrastructure-role",
            "arn:aws:iam::962698957678:role/cloudpentagon-firehose-audit-role",
            "arn:aws:iam::962698957678:role/cloudpentagon-firehose-access-role"
        ]
    }'
    
    result=$(opensearch_api PUT "/_plugins/_security/api/rolesmapping/all_access" "$role_mapping")
    if echo "$result" | grep -q '"status":"OK"' || echo "$result" | grep -q '"status":"CREATED"'; then
        log_success "Role mapping 설정 완료"
    else
        log_warn "Role mapping: $result"
    fi
}

# 기존 인덱스 삭제 (날짜 자동 감지)
delete_existing_indices() {
    log_info "기존 로그 인덱스 검색 중..."
    
    # 현재 존재하는 로그 인덱스 목록 가져오기
    local indices=$(opensearch_api GET "/_cat/indices?h=index" | grep -E "^(app|infra|audit|access)-logs-" || true)
    
    if [ -z "$indices" ]; then
        log_info "삭제할 로그 인덱스가 없습니다."
        return 0
    fi
    
    echo -e "${YELLOW}다음 인덱스가 삭제됩니다:${NC}"
    echo "$indices"
    echo ""
    
    read -p "정말 삭제하시겠습니까? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        log_info "인덱스 삭제를 취소했습니다."
        return 0
    fi
    
    for index in $indices; do
        log_info "삭제 중: $index"
        result=$(opensearch_api DELETE "/$index")
        if echo "$result" | grep -q '"acknowledged":true'; then
            log_success "$index 삭제 완료"
        else
            log_warn "$index 삭제 실패: $result"
        fi
    done
}

# 강제 인덱스 삭제 (확인 없이)
force_delete_indices() {
    log_info "기존 로그 인덱스 강제 삭제 중..."
    
    local indices=$(opensearch_api GET "/_cat/indices?h=index" | grep -E "^(app|infra|audit|access)-logs-" || true)
    
    if [ -z "$indices" ]; then
        log_info "삭제할 로그 인덱스가 없습니다."
        return 0
    fi
    
    for index in $indices; do
        log_info "삭제 중: $index"
        result=$(opensearch_api DELETE "/$index")
        if echo "$result" | grep -q '"acknowledged":true'; then
            log_success "$index 삭제 완료"
        else
            log_warn "$index 삭제: $result"
        fi
    done
}

# 인덱스 상태 확인
check_indices() {
    log_info "현재 인덱스 상태 확인 중..."
    echo ""
    echo "=== 인덱스 목록 ==="
    opensearch_api GET "/_cat/indices?v&s=index" | grep -E "(index|logs-)" || echo "로그 인덱스가 없습니다."
    echo ""
    
    echo "=== 템플릿 목록 ==="
    opensearch_api GET "/_index_template" | jq -r '.index_templates[].name' 2>/dev/null || \
        opensearch_api GET "/_index_template" | grep -o '"name":"[^"]*"' | cut -d'"' -f4
    echo ""
    
    echo "=== 문서 수 ==="
    for pattern in app-logs infra-logs audit-logs access-logs; do
        count=$(opensearch_api GET "/${pattern}-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2 || echo "0")
        echo "${pattern}-*: ${count:-0} documents"
    done
}

# 매핑 확인
check_mapping() {
    local index=$1
    log_info "$index 매핑 확인 중..."
    opensearch_api GET "/${index}/_mapping?pretty"
}

# 도움말
show_help() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  setup       전체 설정 (templates + role mapping)"
    echo "  templates   Index templates만 생성"
    echo "  roles       Role mapping만 설정"
    echo "  delete      기존 인덱스 삭제 (확인 후)"
    echo "  force-delete 기존 인덱스 강제 삭제"
    echo "  reset       전체 리셋 (templates + 인덱스 삭제)"
    echo "  status      현재 상태 확인"
    echo "  mapping     특정 인덱스 매핑 확인 (예: $0 mapping app-logs-2025-12-04)"
    echo "  help        이 도움말 표시"
    echo ""
    echo "Environment Variables:"
    echo "  OPENSEARCH_ENDPOINT  OpenSearch 엔드포인트"
    echo "  ADMIN_USER           관리자 사용자명 (기본값: admin)"
    echo "  ADMIN_PASSWORD       관리자 비밀번호"
    echo ""
    echo "Examples:"
    echo "  $0 setup              # 최초 설정 (Terraform 배포 후)"
    echo "  $0 reset              # 템플릿 재적용 + 인덱스 재생성"
    echo "  $0 status             # 현재 상태 확인"
}

# 메인 실행
main() {
    local command=${1:-help}
    
    case $command in
        setup)
            test_connection
            create_templates
            setup_role_mapping
            echo ""
            log_success "설정이 완료되었습니다!"
            echo ""
            check_indices
            ;;
        templates)
            test_connection
            create_templates
            ;;
        roles)
            test_connection
            setup_role_mapping
            ;;
        delete)
            test_connection
            delete_existing_indices
            ;;
        force-delete)
            test_connection
            force_delete_indices
            ;;
        reset)
            test_connection
            create_templates
            setup_role_mapping
            echo ""
            force_delete_indices
            echo ""
            log_info "새 로그가 들어오면 템플릿이 적용된 인덱스가 자동 생성됩니다."
            log_info "1-2분 후 'status' 명령으로 확인하세요."
            ;;
        status)
            test_connection
            check_indices
            ;;
        mapping)
            test_connection
            if [ -z "$2" ]; then
                log_error "인덱스 이름을 지정하세요. 예: $0 mapping app-logs-2025-12-04"
                exit 1
            fi
            check_mapping "$2"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "알 수 없는 명령: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"