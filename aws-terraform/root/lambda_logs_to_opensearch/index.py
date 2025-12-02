import json
import boto3
import gzip
import base64
import os
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

# 환경 변수
OPENSEARCH_ENDPOINT = os.environ['OPENSEARCH_ENDPOINT']
OPENSEARCH_INDEX = os.environ.get('OPENSEARCH_INDEX', 'aws-logs')
REGION = os.environ.get('AWS_REGION', 'ap-northeast-2')

# AWS 인증
credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(
    credentials.access_key,
    credentials.secret_key,
    REGION,
    'es',
    session_token=credentials.token
)

# OpenSearch 클라이언트
opensearch_client = OpenSearch(
    hosts=[{'host': OPENSEARCH_ENDPOINT, 'port': 443}],
    http_auth=awsauth,
    use_ssl=True,
    verify_certs=True,
    connection_class=RequestsHttpConnection
)

def handler(event, context):
    """
    CloudWatch Logs에서 전송된 로그를 OpenSearch로 전송
    """
    try:
        # CloudWatch Logs 데이터 디코딩
        compressed_payload = base64.b64decode(event['awslogs']['data'])
        uncompressed_payload = gzip.decompress(compressed_payload)
        log_data = json.loads(uncompressed_payload)
        
        # 로그 그룹 및 스트림 정보
        log_group = log_data['logGroup']
        log_stream = log_data['logStream']
        
        # 각 로그 이벤트를 OpenSearch에 인덱싱
        documents = []
        for log_event in log_data['logEvents']:
            # 로그 메시지 파싱 시도
            try:
                message = json.loads(log_event['message'])
            except (json.JSONDecodeError, TypeError):
                message = {'raw_message': log_event['message']}
            
            # OpenSearch 문서 생성
            document = {
                '@timestamp': datetime.fromtimestamp(log_event['timestamp'] / 1000).isoformat(),
                'log_group': log_group,
                'log_stream': log_stream,
                'log_id': log_event['id'],
                'message': message,
                'source_type': extract_source_type(log_group),
                'environment': extract_environment(log_group)
            }
            
            documents.append(document)
        
        # Bulk indexing
        if documents:
            bulk_index_documents(documents)
            
        return {
            'statusCode': 200,
            'body': json.dumps(f'Successfully indexed {len(documents)} log events')
        }
        
    except Exception as e:
        print(f"Error processing logs: {str(e)}")
        raise

def extract_source_type(log_group):
    """
    로그 그룹 이름에서 소스 타입 추출
    """
    if '/ecs/' in log_group:
        if 'frontend' in log_group:
            return 'ecs-frontend'
        elif 'backend' in log_group:
            return 'ecs-backend'
        return 'ecs'
    elif '/alb/' in log_group:
        if 'public' in log_group:
            return 'alb-public'
        elif 'internal' in log_group:
            return 'alb-internal'
        return 'alb'
    elif '/rds/' in log_group:
        if 'error' in log_group:
            return 'rds-error'
        elif 'slowquery' in log_group:
            return 'rds-slowquery'
        return 'rds'
    elif '/vpc/' in log_group:
        return 'vpc-flowlogs'
    elif '/cloudtrail/' in log_group:
        return 'cloudtrail'
    elif '/infrastructure/' in log_group:
        return 'infrastructure-syslog'
    elif '/lambda/' in log_group:
        return 'lambda'
    else:
        return 'unknown'

def extract_environment(log_group):
    """
    로그 그룹 이름에서 환경 추출
    """
    if 'prod' in log_group.lower():
        return 'production'
    elif 'dev' in log_group.lower():
        return 'development'
    elif 'staging' in log_group.lower():
        return 'staging'
    else:
        return 'unknown'

def bulk_index_documents(documents):
    """
    OpenSearch에 대량 문서 인덱싱
    """
    bulk_data = []
    
    for doc in documents:
        # Index 이름 (날짜별로 분리)
        index_name = f"{OPENSEARCH_INDEX}-{datetime.now().strftime('%Y.%m.%d')}"
        
        # Bulk API 형식
        bulk_data.append(json.dumps({"index": {"_index": index_name}}))
        bulk_data.append(json.dumps(doc))
    
    # OpenSearch Bulk API 호출
    if bulk_data:
        body = '\n'.join(bulk_data) + '\n'
        response = opensearch_client.bulk(body=body)
        
        if response.get('errors'):
            print(f"Bulk indexing had errors: {response}")
        else:
            print(f"Successfully indexed {len(documents)} documents")

def create_index_template():
    """
    OpenSearch 인덱스 템플릿 생성 (처음 실행 시)
    """
    template = {
        "index_patterns": [f"{OPENSEARCH_INDEX}-*"],
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,  # 단일 노드이므로 replica 0
            "index.mapping.total_fields.limit": 2000
        },
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "log_group": {"type": "keyword"},
                "log_stream": {"type": "keyword"},
                "log_id": {"type": "keyword"},
                "source_type": {"type": "keyword"},
                "environment": {"type": "keyword"},
                "message": {"type": "object", "enabled": True}
            }
        }
    }
    
    try:
        opensearch_client.indices.put_index_template(
            name=f"{OPENSEARCH_INDEX}-template",
            body=template
        )
        print(f"Index template created: {OPENSEARCH_INDEX}-template")
    except Exception as e:
        print(f"Error creating index template: {str(e)}")
