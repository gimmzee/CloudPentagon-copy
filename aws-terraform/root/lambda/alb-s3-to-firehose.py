import boto3
import gzip
import json
import os
import base64
from urllib.parse import unquote_plus
from datetime import datetime

firehose = boto3.client('firehose')
s3 = boto3.client('s3')

FIREHOSE_STREAM = os.environ.get('FIREHOSE_STREAM_NAME', 'cloudpentagon-access-logs')

def parse_alb_log_line(line):
    """ALB Access 로그 한 줄을 JSON으로 변환"""
    if line.startswith('#'):
        return None
    
    # ALB 로그 필드 순서
    # type timestamp elb client:port target:port request_processing_time target_processing_time 
    # response_processing_time elb_status_code target_status_code received_bytes sent_bytes 
    # "request" "user_agent" ssl_cipher ssl_protocol target_group_arn "trace_id" 
    # "domain_name" "chosen_cert_arn" matched_rule_priority request_creation_time 
    # "actions_executed" "redirect_url" "error_reason" "target:port_list" 
    # "target_status_code_list" "classification" "classification_reason"
    
    parts = line.split(' ')
    
    try:
        log_entry = {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'type': parts[0] if len(parts) > 0 else '',
            'timestamp': parts[1] if len(parts) > 1 else '',
            'elb': parts[2] if len(parts) > 2 else '',
            'client_ip': parts[3].split(':')[0] if len(parts) > 3 else '',
            'client_port': parts[3].split(':')[1] if len(parts) > 3 and ':' in parts[3] else '',
            'target_ip': parts[4].split(':')[0] if len(parts) > 4 else '',
            'target_port': parts[4].split(':')[1] if len(parts) > 4 and ':' in parts[4] else '',
            'request_processing_time': float(parts[5]) if len(parts) > 5 and parts[5] != '-1' else -1,
            'target_processing_time': float(parts[6]) if len(parts) > 6 and parts[6] != '-1' else -1,
            'response_processing_time': float(parts[7]) if len(parts) > 7 and parts[7] != '-1' else -1,
            'elb_status_code': int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 0,
            'target_status_code': int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0,
            'received_bytes': int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else 0,
            'sent_bytes': int(parts[11]) if len(parts) > 11 and parts[11].isdigit() else 0,
            'request': parts[12].strip('"') if len(parts) > 12 else '',
            'user_agent': parts[13].strip('"') if len(parts) > 13 else '',
            'ssl_cipher': parts[14] if len(parts) > 14 else '',
            'ssl_protocol': parts[15] if len(parts) > 15 else '',
            'target_group_arn': parts[16] if len(parts) > 16 else '',
            'trace_id': parts[17].strip('"') if len(parts) > 17 else '',
            'message': line.strip()
        }
        
        return log_entry
    except Exception as e:
        print(f"Error parsing line: {e}")
        return {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'message': line.strip(),
            'parse_error': str(e)
        }

def handler(event, context):
    """S3에 저장된 ALB Access 로그를 Firehose로 전송"""
    
    print(f"Received event: {json.dumps(event)}")
    
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = unquote_plus(record['s3']['object']['key'])
        
        print(f"Processing: s3://{bucket}/{key}")
        
        try:
            # S3에서 로그 파일 다운로드
            response = s3.get_object(Bucket=bucket, Key=key)
            
            # gzip 압축 해제
            with gzip.GzipFile(fileobj=response['Body']) as gzipfile:
                content = gzipfile.read().decode('utf-8')
            
            # 각 로그 라인을 파싱하고 Firehose로 전송
            records = []
            line_count = 0
            error_count = 0
            
            for line in content.strip().split('\n'):
                if not line or line.startswith('#'):
                    continue
                
                line_count += 1
                
                # 로그 라인을 JSON으로 변환
                log_entry = parse_alb_log_line(line)
                
                if log_entry:
                    # Firehose 레코드 형식으로 변환
                    records.append({
                        'Data': json.dumps(log_entry) + '\n'
                    })
                else:
                    error_count += 1
                
                # 배치 크기 제한 (500개)
                if len(records) >= 500:
                    response = firehose.put_record_batch(
                        DeliveryStreamName=FIREHOSE_STREAM,
                        Records=records
                    )
                    print(f"Sent batch: {len(records)} records, FailedPutCount: {response['FailedPutCount']}")
                    records = []
            
            # 남은 레코드 전송
            if records:
                response = firehose.put_record_batch(
                    DeliveryStreamName=FIREHOSE_STREAM,
                    Records=records
                )
                print(f"Sent final batch: {len(records)} records, FailedPutCount: {response['FailedPutCount']}")
            
            print(f"Successfully processed {line_count} lines from {key} (errors: {error_count})")
            
        except Exception as e:
            print(f"Error processing {key}: {str(e)}")
            raise e
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Successfully processed ALB logs',
            'files': len(event['Records']),
            'lines': line_count
        })
    }
