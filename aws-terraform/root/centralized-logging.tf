# ========================================
# 중앙 로그 시스템 - Kinesis Firehose 통합 아키텍처
# ========================================
# 
# 아키텍처 개요:
# 1. 로그 수집: CloudWatch Logs → Firehose → [Transform Lambda] → OpenSearch → S3 Backup
# 2. 알람 시스템: CloudWatch Logs → Metric Filter → CloudWatch Alarm → SNS → Slack Lambda → Slack
#
# 로그 타입별 Firehose 스트림:
# 1. Application Logs (ECS, RDS)
# 2. Access Logs (ALB)
# 3. Infrastructure Logs (VPC Flow Logs)
# 4. Audit Logs (CloudTrail)
# ========================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ========================================
# 1. CloudWatch Log Groups
# ========================================

# Application Logs
resource "aws_cloudwatch_log_group" "ecs_frontend" {
  name              = "/aws/ecs/${var.project_name}/frontend"
  retention_in_days = 7 # 비용 절감을 위해 7일

  tags = {
    Name        = "ECS-Frontend-Logs"
    Environment = var.environment
    LogType     = "application"
  }
}

resource "aws_cloudwatch_log_group" "ecs_backend" {
  name              = "/aws/ecs/${var.project_name}/backend"
  retention_in_days = 7

  tags = {
    Name        = "ECS-Backend-Logs"
    Environment = var.environment
    LogType     = "application"
  }
}

# RDS 로그 그룹 (자동 생성되지만 명시적으로 관리)
resource "aws_cloudwatch_log_group" "aurora_error" {
  name              = "/aws/rds/cluster/${var.project_name}-cluster/error"
  retention_in_days = 7

  tags = {
    Name        = "Aurora-Error-Logs"
    Environment = var.environment
    LogType     = "application"
  }
}

# 🔧 FIX 1: Aurora SlowQuery 로그 그룹 - 기존 리소스 import 필요
# 이미 Aurora에 의해 자동 생성된 로그 그룹을 import해야 합니다
# 터미널에서 실행:
# terraform import aws_cloudwatch_log_group.aurora_slowquery /aws/rds/cluster/cloudpentagon-cluster/slowquery
resource "aws_cloudwatch_log_group" "aurora_slowquery" {
  name              = "/aws/rds/cluster/${var.project_name}-cluster/slowquery"
  retention_in_days = 7

  tags = {
    Name        = "Aurora-SlowQuery-Logs"
    Environment = var.environment
    LogType     = "application"
  }
}

# Infrastructure Logs
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/${var.project_name}/flowlogs"
  retention_in_days = 3 # Flow 로그는 많으므로 3일

  tags = {
    Name        = "VPC-FlowLogs"
    Environment = var.environment
    LogType     = "infrastructure"
  }
}

# Audit Logs
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}"
  retention_in_days = 30  # 감사 로그는 장기 보관

  tags = {
    Name        = "CloudTrail-Logs"
    Environment = var.environment
    LogType     = "audit"
  }
}

# Firehose Log Groups
resource "aws_cloudwatch_log_group" "firehose_application" {
  name              = "/aws/kinesisfirehose/${var.project_name}-application"
  retention_in_days = 7
  
  tags = {
    Name        = "Firehose-Application-Logs"
    Environment = var.environment
    LogType     = "firehose"
  }
}

resource "aws_cloudwatch_log_group" "firehose_infrastructure" {
  name              = "/aws/kinesisfirehose/${var.project_name}-infrastructure"
  retention_in_days = 7
  
  tags = {
    Name        = "Firehose-Infrastructure-Logs"
    Environment = var.environment
    LogType     = "firehose"
  }
}

resource "aws_cloudwatch_log_group" "firehose_audit" {
  name              = "/aws/kinesisfirehose/${var.project_name}-audit"
  retention_in_days = 7
  
  tags = {
    Name        = "Firehose-Audit-Logs"
    Environment = var.environment
    LogType     = "firehose"
  }
}

resource "aws_cloudwatch_log_group" "firehose_access" {
  name              = "/aws/kinesisfirehose/${var.project_name}-access"
  retention_in_days = 7
  
  tags = {
    Name        = "Firehose-Access-Logs"
    Environment = var.environment
    LogType     = "firehose"
  }
}

# ALB Access Logs
resource "aws_cloudwatch_log_group" "alb_access" {
  name              = "/aws/alb/${var.project_name}/access"
  retention_in_days = 7

  tags = {
    Name        = "ALB-Access-Logs"
    Environment = var.environment
    LogType     = "access"
  }
}

# ========================================
# 2. S3 Buckets for Backup & Source
# ========================================

# Unified Backup Bucket
resource "aws_s3_bucket" "logs_backup" {
  bucket = "${var.project_name}-logs-backup-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "Centralized-Logs-Backup"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "logs_backup" {
  bucket = aws_s3_bucket.logs_backup.id

  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs_backup" {
  bucket = aws_s3_bucket.logs_backup.id

  # 1. Application Logs (ECS, RDS)
  rule {
    id     = "application-logs-lifecycle"
    status = "Enabled"
    filter { prefix = "application-logs/" }
    
    expiration { days = 7 }
  }

  # 2. Access Logs (ALB)
  rule {
    id     = "access-logs-lifecycle"
    status = "Enabled"
    filter { prefix = "access-logs/" }
    
    expiration { days = 14 }
  }

  # 3. Infrastructure Logs (VPC)
  rule {
    id     = "infrastructure-logs-lifecycle"
    status = "Enabled"
    filter { prefix = "infrastructure-logs/" }
    
    expiration { days = 3 }
  }

  # 4. Audit Logs (CloudTrail) - 장기 보관
  rule {
    id     = "audit-logs-lifecycle"
    status = "Enabled"
    filter { prefix = "audit-logs/" }
    
    transition {
      days          = 30
      storage_class = "GLACIER"
    }
    
    expiration { days = 90 }
  }
}

# ALB Access Logs Bucket (ALB는 S3 직접 전송)
resource "aws_s3_bucket" "alb_logs" {
  bucket = "${var.project_name}-alb-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "ALB-Access-Logs"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs.arn
      },
      {
        Sid    = "AWSELBLogDelivery"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::600734575887:root"  # ap-northeast-2 ELB account
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/*"
      }
    ]
  })
}

# CloudTrail S3 Bucket
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${var.project_name}-cloudtrail-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "CloudTrail-Logs"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# ========================================
# 3. OpenSearch Domain
# ========================================

resource "aws_security_group" "opensearch" {
  name        = "${var.project_name}-opensearch-sg"
  description = "Security group for OpenSearch"
  vpc_id      = aws_vpc.vpc1.id

  tags = {
    Name        = "OpenSearch-SecurityGroup"
    Environment = var.environment
  }
}

resource "aws_security_group" "firehose" {
  name        = "${var.project_name}-firehose-sg"
  description = "Security group for Firehose ENIs"
  vpc_id      = aws_vpc.vpc1.id

  egress {
    description = "HTTPS to OpenSearch"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.opensearch.id]
  }
  
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "Firehose-SecurityGroup"
    Environment = var.environment
  }
}

# OpenSearch: Firehose로부터의 접근 허용
resource "aws_security_group_rule" "opensearch_from_firehose" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.opensearch.id
  source_security_group_id = aws_security_group.firehose.id
  description              = "HTTPS from Firehose"
}

resource "aws_opensearch_domain" "logs" {
  domain_name    = "${var.project_name}-logs"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type            = "t3.small.search"
    instance_count           = 2
    zone_awareness_enabled   = true

    zone_awareness_config {
      availability_zone_count = 2
    }    
  }

  vpc_options {
    subnet_ids = [
      aws_subnet.vpc1_ecs_backend_aza.id,
      aws_subnet.vpc1_ecs_backend_azc.id
    ]
    security_group_ids = [aws_security_group.opensearch.id]
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
    volume_type = "gp3"
  }

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action   = "es:*"
        Resource = "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.project_name}-logs/*"
      }
    ]
  })

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "admin"
      master_user_password = "Admin123!@#"  # 실제로는 Secrets Manager 사용
    }
  }

  tags = {
    Name        = "Centralized-Logs-OpenSearch"
    Environment = var.environment
  }
}

# ========================================
# 4. Firehose Transform Lambda
# ========================================

# Lambda용 로그 그룹
resource "aws_cloudwatch_log_group" "firehose_transform_lambda" {
  name              = "/aws/lambda/${var.project_name}-firehose-transform"
  retention_in_days = 7

  tags = {
    Name        = "Firehose-Transform-Lambda-Logs"
    Environment = var.environment
  }
}

# Lambda IAM Role
resource "aws_iam_role" "firehose_transform_lambda" {
  name = "${var.project_name}-firehose-transform-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "Firehose-Transform-Lambda-Role"
  }
}

resource "aws_iam_role_policy" "firehose_transform_lambda" {
  name = "${var.project_name}-firehose-transform-lambda-policy"
  role = aws_iam_role.firehose_transform_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.firehose_transform_lambda.arn}:*"
      }
    ]
  })
}

# Lambda 함수 코드
data "archive_file" "firehose_transform" {
  type        = "zip"
  output_path = "${path.module}/lambda/firehose_transform.zip"

  source {
    content  = <<-EOF
import base64
import gzip
import json

def lambda_handler(event, context):
    output = []
    
    for record in event['records']:
        record_id = record['recordId']
        
        try:
            payload = base64.b64decode(record['data'])
            
            try:
                payload = gzip.decompress(payload)
            except:
                pass
            
            log_data = json.loads(payload)
            
            # Control message 무시
            if log_data.get('messageType') == 'CONTROL_MESSAGE':
                output.append({
                    'recordId': record_id,
                    'result': 'Dropped',
                    'data': record['data']
                })
                continue
            
            if 'logEvents' in log_data and log_data['logEvents']:
                # 첫 번째 이벤트만 사용하거나, 배치로 묶음
                first_event = log_data['logEvents'][0]
                
                document = {
                    '@timestamp': first_event.get('timestamp'),
                    'timestamp': first_event.get('timestamp'),
                    'message': first_event.get('message', ''),
                    'logGroup': log_data.get('logGroup', ''),
                    'logStream': log_data.get('logStream', ''),
                    'owner': log_data.get('owner', ''),
                    'messageType': log_data.get('messageType', ''),
                    'eventCount': len(log_data['logEvents'])
                }
                
                # 여러 이벤트가 있으면 messages 배열에 저장
                if len(log_data['logEvents']) > 1:
                    document['allMessages'] = [e.get('message', '') for e in log_data['logEvents']]
                
                try:
                    msg = json.loads(first_event.get('message', ''))
                    if isinstance(msg, dict):
                        document['parsed'] = msg
                except:
                    pass
                
                # 핵심: 단일 JSON 문서 + newline (Firehose OpenSearch 요구사항)
                result_data = json.dumps(document) + '\n'
                
                output.append({
                    'recordId': record_id,
                    'result': 'Ok',
                    'data': base64.b64encode(result_data.encode('utf-8')).decode('utf-8')
                })
            else:
                output.append({
                    'recordId': record_id,
                    'result': 'Dropped',
                    'data': record['data']
                })
                
        except Exception as e:
            output.append({
                'recordId': record_id,
                'result': 'ProcessingFailed',
                'data': record['data']
            })
    
    return {'records': output}
EOF
    filename = "index.py"
  }
}

resource "aws_lambda_function" "firehose_transform" {
  filename         = data.archive_file.firehose_transform.output_path
  function_name    = "${var.project_name}-firehose-transform"
  role             = aws_iam_role.firehose_transform_lambda.arn
  handler          = "index.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256
  source_code_hash = data.archive_file.firehose_transform.output_base64sha256

  depends_on = [aws_cloudwatch_log_group.firehose_transform_lambda]

  tags = {
    Name        = "Firehose-Transform-Lambda"
    Environment = var.environment
  }
}

# ========================================
# 5. Kinesis Firehose - Application Logs
# ========================================

resource "aws_iam_role" "firehose_application" {
  name = "${var.project_name}-firehose-application-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "firehose.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "Firehose-Application-Role"
  }
}

resource "aws_iam_role_policy" "firehose_application" {
  name = "${var.project_name}-firehose-application-policy"
  role = aws_iam_role.firehose_application.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "es:DescribeElasticsearchDomain",
          "es:DescribeElasticsearchDomains",
          "es:DescribeElasticsearchDomainConfig",
          "es:ESHttpHead",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet"
        ]
        Resource = [
          "${aws_opensearch_domain.logs.arn}",
          "${aws_opensearch_domain.logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.logs_backup.arn}",
          "${aws_s3_bucket.logs_backup.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/kinesisfirehose/*",
          "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/kinesisfirehose/*:log-stream:*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateNetworkInterface",
          "ec2:CreateNetworkInterfacePermission",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = "${aws_lambda_function.firehose_transform.arn}:*"
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "application_logs" {
  name        = "${var.project_name}-application-logs"
  destination = "opensearch"

  opensearch_configuration {
    domain_arn = aws_opensearch_domain.logs.arn
    role_arn   = aws_iam_role.firehose_application.arn
    index_name = "app-logs"
    
    index_rotation_period = "OneDay"
    
    buffering_interval = 60
    buffering_size     = 5
    
    retry_duration = 300
    
    s3_backup_mode = "AllDocuments"
    
    s3_configuration {
      role_arn           = aws_iam_role.firehose_application.arn
      bucket_arn         = aws_s3_bucket.logs_backup.arn
      prefix             = "application-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      error_output_prefix = "application-logs-errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      compression_format = "GZIP"
    }
    
    vpc_config {
      subnet_ids = [
        aws_subnet.vpc1_ecs_backend_aza.id,
        aws_subnet.vpc1_ecs_backend_azc.id
      ]
      security_group_ids = [aws_security_group.firehose.id]
      role_arn           = aws_iam_role.firehose_application.arn
    }
    
    # Transform Lambda 설정 추가
    processing_configuration {
      enabled = true

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.firehose_transform.arn}:$LATEST"
        }
        
        parameters {
          parameter_name  = "BufferSizeInMBs"
          parameter_value = "1"
        }
        
        parameters {
          parameter_name  = "BufferIntervalInSeconds"
          parameter_value = "60"
        }
      }
    }
    
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_application.name
      log_stream_name = "opensearch-delivery"
    }
  }
  
  depends_on = [
    aws_iam_role_policy.firehose_application,
    aws_cloudwatch_log_group.firehose_application,
    aws_lambda_function.firehose_transform
  ]

  tags = {
    Name    = "Application-Logs-Firehose"
    LogType = "application"
  }
}

# ========================================
# 6. Kinesis Firehose - Infrastructure Logs
# ========================================

resource "aws_iam_role" "firehose_infrastructure" {
  name = "${var.project_name}-firehose-infrastructure-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "firehose.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "Firehose-Infrastructure-Role"
  }
}

resource "aws_iam_role_policy" "firehose_infrastructure" {
  name = "${var.project_name}-firehose-infrastructure-policy"
  role = aws_iam_role.firehose_infrastructure.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "es:DescribeElasticsearchDomain",
          "es:DescribeElasticsearchDomains",
          "es:DescribeElasticsearchDomainConfig",
          "es:ESHttpHead",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet"
        ]
        Resource = [
          "${aws_opensearch_domain.logs.arn}",
          "${aws_opensearch_domain.logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.logs_backup.arn}",
          "${aws_s3_bucket.logs_backup.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/kinesisfirehose/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateNetworkInterface",
          "ec2:CreateNetworkInterfacePermission",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = "${aws_lambda_function.firehose_transform.arn}:*"
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "infrastructure_logs" {
  name        = "${var.project_name}-infrastructure-logs"
  destination = "opensearch"

  opensearch_configuration {
    domain_arn = aws_opensearch_domain.logs.arn
    role_arn   = aws_iam_role.firehose_infrastructure.arn
    index_name = "infra-logs"
    
    index_rotation_period = "OneDay"
    
    buffering_interval = 300
    buffering_size     = 5
    
    retry_duration = 300
    
    s3_backup_mode = "AllDocuments"
    
    s3_configuration {
      role_arn           = aws_iam_role.firehose_infrastructure.arn
      bucket_arn         = aws_s3_bucket.logs_backup.arn
      prefix             = "infrastructure-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      error_output_prefix = "infrastructure-logs-errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      compression_format = "GZIP"
    }
    
    vpc_config {
      subnet_ids = [
        aws_subnet.vpc1_ecs_backend_aza.id,
        aws_subnet.vpc1_ecs_backend_azc.id
      ]
      security_group_ids = [aws_security_group.firehose.id]
      role_arn           = aws_iam_role.firehose_infrastructure.arn
    }
    
    processing_configuration {
      enabled = true

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.firehose_transform.arn}:$LATEST"
        }
        
        parameters {
          parameter_name  = "BufferSizeInMBs"
          parameter_value = "1"
        }
        
        parameters {
          parameter_name  = "BufferIntervalInSeconds"
          parameter_value = "60"
        }
      }
    }
    
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_infrastructure.name
      log_stream_name = "opensearch-delivery"
    }
  }
  
  depends_on = [
    aws_iam_role_policy.firehose_infrastructure,
    aws_cloudwatch_log_group.firehose_infrastructure,
    aws_lambda_function.firehose_transform
  ]

  tags = {
    Name    = "Infrastructure-Logs-Firehose"
    LogType = "infrastructure"
  }
}

# ========================================
# 7. Kinesis Firehose - Audit Logs
# ========================================

resource "aws_iam_role" "firehose_audit" {
  name = "${var.project_name}-firehose-audit-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "firehose.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "Firehose-Audit-Role"
  }
}

resource "aws_iam_role_policy" "firehose_audit" {
  name = "${var.project_name}-firehose-audit-policy"
  role = aws_iam_role.firehose_audit.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "es:DescribeElasticsearchDomain",
          "es:DescribeElasticsearchDomains",
          "es:DescribeElasticsearchDomainConfig",
          "es:ESHttpHead",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet"
        ]
        Resource = [
          "${aws_opensearch_domain.logs.arn}",
          "${aws_opensearch_domain.logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.logs_backup.arn}",
          "${aws_s3_bucket.logs_backup.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/kinesisfirehose/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateNetworkInterface",
          "ec2:CreateNetworkInterfacePermission",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = "${aws_lambda_function.firehose_transform.arn}:*"
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "audit_logs" {
  name        = "${var.project_name}-audit-logs"
  destination = "opensearch"

  opensearch_configuration {
    domain_arn = aws_opensearch_domain.logs.arn
    role_arn   = aws_iam_role.firehose_audit.arn
    index_name = "audit-logs"
    
    index_rotation_period = "OneDay"
    
    buffering_interval = 60
    buffering_size     = 5
    
    retry_duration = 300
    
    s3_backup_mode = "AllDocuments"
    
    s3_configuration {
      role_arn           = aws_iam_role.firehose_audit.arn
      bucket_arn         = aws_s3_bucket.logs_backup.arn
      prefix             = "audit-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      error_output_prefix = "audit-logs-errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      compression_format = "GZIP"
    }
    
    vpc_config {
      subnet_ids = [
        aws_subnet.vpc1_ecs_backend_aza.id,
        aws_subnet.vpc1_ecs_backend_azc.id
      ]
      security_group_ids = [aws_security_group.firehose.id]
      role_arn           = aws_iam_role.firehose_audit.arn
    }
    
    processing_configuration {
      enabled = true

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.firehose_transform.arn}:$LATEST"
        }
        
        parameters {
          parameter_name  = "BufferSizeInMBs"
          parameter_value = "1"
        }
        
        parameters {
          parameter_name  = "BufferIntervalInSeconds"
          parameter_value = "60"
        }
      }
    }
    
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_audit.name
      log_stream_name = "opensearch-delivery"
    }
  }
  
  depends_on = [
    aws_iam_role_policy.firehose_audit,
    aws_cloudwatch_log_group.firehose_audit,
    aws_lambda_function.firehose_transform
  ]

  tags = {
    Name    = "Audit-Logs-Firehose"
    LogType = "audit"
  }
}

# ========================================
# 8. Kinesis Firehose - Access Logs (ALB)
# ========================================

resource "aws_iam_role" "firehose_access" {
  name = "${var.project_name}-firehose-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "firehose.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "Firehose-Access-Role"
  }
}

resource "aws_iam_role_policy" "firehose_access" {
  name = "${var.project_name}-firehose-access-policy"
  role = aws_iam_role.firehose_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "es:DescribeElasticsearchDomain",
          "es:DescribeElasticsearchDomains",
          "es:DescribeElasticsearchDomainConfig",
          "es:ESHttpHead",
          "es:ESHttpPost",
          "es:ESHttpPut",
          "es:ESHttpGet"
        ]
        Resource = [
          "${aws_opensearch_domain.logs.arn}",
          "${aws_opensearch_domain.logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.alb_logs.arn}",
          "${aws_s3_bucket.alb_logs.arn}/*",
          "${aws_s3_bucket.logs_backup.arn}",
          "${aws_s3_bucket.logs_backup.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/kinesisfirehose/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateNetworkInterface",
          "ec2:CreateNetworkInterfacePermission",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = "${aws_lambda_function.firehose_transform.arn}:*"
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "access_logs" {
  name        = "${var.project_name}-access-logs"
  destination = "opensearch"

  opensearch_configuration {
    domain_arn = aws_opensearch_domain.logs.arn
    role_arn   = aws_iam_role.firehose_access.arn
    index_name = "access-logs"
    
    index_rotation_period = "OneDay"
    
    buffering_interval = 60
    buffering_size     = 5
    
    retry_duration = 300
    
    s3_backup_mode = "AllDocuments"
    
    s3_configuration {
      role_arn           = aws_iam_role.firehose_access.arn
      bucket_arn         = aws_s3_bucket.logs_backup.arn
      prefix             = "access-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      error_output_prefix = "access-logs-errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      compression_format = "GZIP"
    }
    
    vpc_config {
      subnet_ids = [
        aws_subnet.vpc1_ecs_backend_aza.id,
        aws_subnet.vpc1_ecs_backend_azc.id
      ]
      security_group_ids = [aws_security_group.firehose.id]
      role_arn           = aws_iam_role.firehose_access.arn
    }
    
    processing_configuration {
      enabled = false
      # enabled = true

      # processors {
      #   type = "Lambda"

      #   parameters {
      #     parameter_name  = "LambdaArn"
      #     parameter_value = "${aws_lambda_function.firehose_transform.arn}:$LATEST"
      #   }
        
      #   parameters {
      #     parameter_name  = "BufferSizeInMBs"
      #     parameter_value = "1"
      #   }
        
      #   parameters {
      #     parameter_name  = "BufferIntervalInSeconds"
      #     parameter_value = "60"
      #   }
      # }
    }
    
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_access.name
      log_stream_name = "opensearch-delivery"
    }
  }
  
  depends_on = [
    aws_iam_role_policy.firehose_access,
    aws_s3_bucket_policy.alb_logs,
    aws_cloudwatch_log_group.firehose_access,
    aws_lambda_function.firehose_transform
  ]

  tags = {
    Name    = "Access-Logs-Firehose"
    LogType = "access"
  }
}

# ========================================
# 8.5 ALB Access Logs → Firehose 연결 (Lambda)
# ========================================
#
# ALB는 S3에만 로그를 쓸 수 있으므로 Lambda로 연결 필요
# 흐름: ALB → S3 → Lambda (S3 Event) → Firehose → OpenSearch
# ========================================

# Lambda 함수 코드 패키징
data "archive_file" "alb_s3_to_firehose" {
  type        = "zip"
  source_file = "${path.module}/lambda/alb-s3-to-firehose.py"
  output_path = "${path.module}/lambda/alb-s3-to-firehose.zip"
}

# Lambda IAM Role
resource "aws_iam_role" "alb_s3_to_firehose_lambda" {
  name = "${var.project_name}-alb-s3-to-firehose-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "ALB-S3-Firehose-Lambda-Role"
  }
}

# Lambda IAM Policy
resource "aws_iam_role_policy" "alb_s3_to_firehose_lambda" {
  name = "${var.project_name}-alb-s3-to-firehose-lambda-policy"
  role = aws_iam_role.alb_s3_to_firehose_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.alb_logs.arn,
          "${aws_s3_bucket.alb_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "firehose:PutRecord",
          "firehose:PutRecordBatch"
        ]
        Resource = aws_kinesis_firehose_delivery_stream.access_logs.arn
      }
    ]
  })
}

# Lambda 함수
resource "aws_lambda_function" "alb_s3_to_firehose" {
  filename      = data.archive_file.alb_s3_to_firehose.output_path
  function_name = "${var.project_name}-alb-s3-to-firehose"
  role          = aws_iam_role.alb_s3_to_firehose_lambda.arn
  handler       = "alb-s3-to-firehose.handler"
  runtime       = "python3.11"
  timeout       = 300  # 5분 (ALB 로그 파일이 클 수 있음)
  memory_size   = 512

  source_code_hash = data.archive_file.alb_s3_to_firehose.output_base64sha256

  environment {
    variables = {
      FIREHOSE_STREAM_NAME = aws_kinesis_firehose_delivery_stream.access_logs.name
    }
  }

  tags = {
    Name = "ALB-S3-Firehose-Lambda"
  }
}

# Lambda CloudWatch Log Group
resource "aws_cloudwatch_log_group" "alb_s3_to_firehose_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.alb_s3_to_firehose.function_name}"
  retention_in_days = 7

  tags = {
    Name = "ALB-S3-Firehose-Lambda-Logs"
  }
}

# S3 → Lambda 권한
resource "aws_lambda_permission" "allow_s3_alb_logs" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alb_s3_to_firehose.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.alb_logs.arn
}

# S3 버킷 이벤트 알림
resource "aws_s3_bucket_notification" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.alb_s3_to_firehose.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "alb-"  # alb-public/, alb-internal/
    filter_suffix       = ".gz"
  }

  depends_on = [aws_lambda_permission.allow_s3_alb_logs]
}

# ========================================
# 9. CloudWatch Logs Subscription Filters
# ========================================

# Application Logs Subscriptions
resource "aws_cloudwatch_log_subscription_filter" "ecs_frontend_to_firehose" {
  name            = "ecs-frontend-to-firehose"
  log_group_name  = aws_cloudwatch_log_group.ecs_frontend.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.application_logs.arn
  role_arn        = aws_iam_role.cloudwatch_to_firehose.arn
}

resource "aws_cloudwatch_log_subscription_filter" "ecs_backend_to_firehose" {
  name            = "ecs-backend-to-firehose"
  log_group_name  = aws_cloudwatch_log_group.ecs_backend.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.application_logs.arn
  role_arn        = aws_iam_role.cloudwatch_to_firehose.arn
}

resource "aws_cloudwatch_log_subscription_filter" "aurora_error_to_firehose" {
  name            = "aurora-error-to-firehose"
  log_group_name  = aws_cloudwatch_log_group.aurora_error.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.application_logs.arn
  role_arn        = aws_iam_role.cloudwatch_to_firehose.arn
}

resource "aws_cloudwatch_log_subscription_filter" "aurora_slowquery_to_firehose" {
  name            = "aurora-slowquery-to-firehose"
  log_group_name  = aws_cloudwatch_log_group.aurora_slowquery.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.application_logs.arn
  role_arn        = aws_iam_role.cloudwatch_to_firehose.arn
}

# Infrastructure Logs Subscription
resource "aws_cloudwatch_log_subscription_filter" "vpc_flowlogs_to_firehose" {
  name            = "vpc-flowlogs-to-firehose"
  log_group_name  = aws_cloudwatch_log_group.vpc_flow_logs.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.infrastructure_logs.arn
  role_arn        = aws_iam_role.cloudwatch_to_firehose.arn
}

# Audit Logs Subscription
resource "aws_cloudwatch_log_subscription_filter" "cloudtrail_to_firehose" {
  name            = "cloudtrail-to-firehose"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern  = ""
  destination_arn = aws_kinesis_firehose_delivery_stream.audit_logs.arn
  role_arn        = aws_iam_role.cloudwatch_to_firehose.arn
}

# IAM Role for CloudWatch Logs → Firehose
resource "aws_iam_role" "cloudwatch_to_firehose" {
  name = "${var.project_name}-cloudwatch-to-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "CloudWatch-to-Firehose-Role"
  }
}

resource "aws_iam_role_policy" "cloudwatch_to_firehose" {
  name = "${var.project_name}-cloudwatch-to-firehose-policy"
  role = aws_iam_role.cloudwatch_to_firehose.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "firehose:PutRecord",
          "firehose:PutRecordBatch"
        ]
        Resource = [
          aws_kinesis_firehose_delivery_stream.application_logs.arn,
          aws_kinesis_firehose_delivery_stream.infrastructure_logs.arn,
          aws_kinesis_firehose_delivery_stream.audit_logs.arn,
          aws_kinesis_firehose_delivery_stream.access_logs.arn
        ]
      }
    ]
  })
}

# ========================================
# 10. Slack 알람 시스템
# ========================================

# Slack Webhook URL 변수 (main.tf에서 정의 필요)
variable "slack_webhook_url" {
  description = "Slack Incoming Webhook URL for alerts"
  type        = string
  default     = "https://hooks.slack.com/services/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"  # terraform.tfvars에서 설정하거나 apply 시 입력
  sensitive   = true
}

# SNS Topic for Slack Alerts
resource "aws_sns_topic" "slack_alerts" {
  name = "${var.project_name}-slack-alerts"

  tags = {
    Name        = "Slack-Alerts-Topic"
    Environment = var.environment
  }
}

# CloudWatch Metric Filter - Backend ERROR 로그 감지
resource "aws_cloudwatch_log_metric_filter" "backend_error_logs" {
  name           = "${var.project_name}-backend-error-filter"
  pattern        = "?ERROR ?Error ?error ?CRITICAL ?Critical ?FATAL ?Fatal ?Exception ?exception"
  log_group_name = aws_cloudwatch_log_group.ecs_backend.name

  metric_transformation {
    name          = "BackendErrorCount"
    namespace     = "${var.project_name}/ApplicationLogs"
    value         = "1"
    default_value = "0"
  }
}

# CloudWatch Metric Filter - Frontend ERROR 로그 감지
resource "aws_cloudwatch_log_metric_filter" "frontend_error_logs" {
  name           = "${var.project_name}-frontend-error-filter"
  pattern        = "?ERROR ?Error ?error ?CRITICAL ?Critical ?FATAL ?Fatal ?Exception ?exception"
  log_group_name = aws_cloudwatch_log_group.ecs_frontend.name

  metric_transformation {
    name          = "FrontendErrorCount"
    namespace     = "${var.project_name}/ApplicationLogs"
    value         = "1"
    default_value = "0"
  }
}

# CloudWatch Alarm - Backend 에러
resource "aws_cloudwatch_metric_alarm" "backend_error_alarm" {
  alarm_name          = "${var.project_name}-backend-error-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BackendErrorCount"
  namespace           = "${var.project_name}/ApplicationLogs"
  period              = 300  # 5분
  statistic           = "Sum"
  threshold           = 5    # 5분간 5개 이상 에러 시 알람
  alarm_description   = "Backend 애플리케이션에서 에러 로그가 감지되었습니다."
  
  alarm_actions = [aws_sns_topic.slack_alerts.arn]
  ok_actions    = [aws_sns_topic.slack_alerts.arn]
  
  treat_missing_data = "notBreaching"

  tags = {
    Name        = "Backend-Error-Alarm"
    Category    = "Application"
    Environment = var.environment
  }
}

# CloudWatch Alarm - Frontend 에러
resource "aws_cloudwatch_metric_alarm" "frontend_error_alarm" {
  alarm_name          = "${var.project_name}-frontend-error-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FrontendErrorCount"
  namespace           = "${var.project_name}/ApplicationLogs"
  period              = 300
  statistic           = "Sum"
  threshold           = 10   # Frontend는 임계값 높게
  alarm_description   = "Frontend 애플리케이션에서 에러 로그가 감지되었습니다."
  
  alarm_actions = [aws_sns_topic.slack_alerts.arn]
  ok_actions    = [aws_sns_topic.slack_alerts.arn]
  
  treat_missing_data = "notBreaching"

  tags = {
    Name        = "Frontend-Error-Alarm"
    Category    = "Application"
    Environment = var.environment
  }
}

# ========================================
# Infrastructure 로그 알람 (VPC Flow Logs)
# ========================================

# VPC Flow Logs - REJECT 트래픽 감지
resource "aws_cloudwatch_log_metric_filter" "vpc_rejected_traffic" {
  name           = "${var.project_name}-vpc-rejected-filter"
  pattern        = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action=\"REJECT\", flowlogstatus]"
  log_group_name = aws_cloudwatch_log_group.vpc_flow_logs.name

  metric_transformation {
    name          = "VPCRejectedPackets"
    namespace     = "${var.project_name}/InfrastructureLogs"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "vpc_rejected_alarm" {
  alarm_name          = "${var.project_name}-vpc-rejected-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "VPCRejectedPackets"
  namespace           = "${var.project_name}/InfrastructureLogs"
  period              = 300
  statistic           = "Sum"
  threshold           = 100  # 5분간 100개 이상 거부된 패킷
  alarm_description   = "VPC에서 비정상적으로 많은 트래픽이 거부되었습니다. 보안 위협 가능성이 있습니다."

  alarm_actions = [aws_sns_topic.slack_alerts.arn]
  ok_actions    = [aws_sns_topic.slack_alerts.arn]

  treat_missing_data = "notBreaching"

  tags = {
    Name        = "VPC-Rejected-Traffic-Alarm"
    Category    = "Infrastructure"
    Environment = var.environment
  }
}

# ========================================
# Audit 로그 알람 (CloudTrail)
# ========================================

# CloudTrail - 보안 관련 이벤트 감지
resource "aws_cloudwatch_log_metric_filter" "security_events" {
  name           = "${var.project_name}-security-events-filter"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") || ($.eventName = \"StopInstances\") || ($.eventName = \"TerminateInstances\") || ($.eventName = \"DeleteBucket\") || ($.eventName = \"DeleteDBInstance\") || ($.eventName = \"AuthorizeSecurityGroupIngress\") || ($.eventName = \"CreateUser\") || ($.eventName = \"DeleteUser\") || ($.eventName = \"AttachRolePolicy\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name          = "SecurityEventCount"
    namespace     = "${var.project_name}/AuditLogs"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_events_alarm" {
  alarm_name          = "${var.project_name}-security-events-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "SecurityEventCount"
  namespace           = "${var.project_name}/AuditLogs"
  period              = 300
  statistic           = "Sum"
  threshold           = 10  # 5분간 10개 이상 보안 이벤트
  alarm_description   = "중요한 보안 이벤트가 다수 감지되었습니다. 즉시 확인이 필요합니다."

  alarm_actions = [aws_sns_topic.slack_alerts.arn]
  ok_actions    = [aws_sns_topic.slack_alerts.arn]

  treat_missing_data = "notBreaching"

  tags = {
    Name        = "Security-Events-Alarm"
    Category    = "Audit"
    Environment = var.environment
  }
}

# CloudTrail - 로그인 실패 감지
resource "aws_cloudwatch_log_metric_filter" "failed_login" {
  name           = "${var.project_name}-failed-login-filter"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name          = "FailedLoginCount"
    namespace     = "${var.project_name}/AuditLogs"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "failed_login_alarm" {
  alarm_name          = "${var.project_name}-failed-login-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FailedLoginCount"
  namespace           = "${var.project_name}/AuditLogs"
  period              = 300
  statistic           = "Sum"
  threshold           = 3  # 5분간 3회 이상 로그인 실패
  alarm_description   = "AWS 콘솔 로그인 실패가 반복되고 있습니다. 무차별 대입 공격 가능성이 있습니다."

  alarm_actions = [aws_sns_topic.slack_alerts.arn]
  ok_actions    = [aws_sns_topic.slack_alerts.arn]

  treat_missing_data = "notBreaching"

  tags = {
    Name        = "Failed-Login-Alarm"
    Category    = "Audit"
    Environment = var.environment
  }
}

# ========================================
# Access 로그 알람 (ALB)
# ========================================

# ALB Access Logs - 5xx 에러 감지
resource "aws_cloudwatch_log_metric_filter" "alb_5xx_errors" {
  name           = "${var.project_name}-alb-5xx-filter"
  pattern        = "[type, time, elb, client_ip, target_ip, request_processing_time, target_processing_time, response_processing_time, elb_status_code=5*, target_status_code, received_bytes, sent_bytes, ...]"
  log_group_name = aws_cloudwatch_log_group.alb_access.name

  metric_transformation {
    name          = "ALB5xxErrorCount"
    namespace     = "${var.project_name}/AccessLogs"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx_alarm" {
  alarm_name          = "${var.project_name}-alb-5xx-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ALB5xxErrorCount"
  namespace           = "${var.project_name}/AccessLogs"
  period              = 300
  statistic           = "Sum"
  threshold           = 10  # 5분간 10개 이상 5xx 에러
  alarm_description   = "ALB에서 5xx 서버 에러가 다수 발생했습니다. 백엔드 서비스 상태를 확인하세요."

  alarm_actions = [aws_sns_topic.slack_alerts.arn]
  ok_actions    = [aws_sns_topic.slack_alerts.arn]

  treat_missing_data = "notBreaching"

  tags = {
    Name        = "ALB-5xx-Error-Alarm"
    Category    = "Access"
    Environment = var.environment
  }
}

# ALB Access Logs - 4xx 에러 감지 (선택적)
resource "aws_cloudwatch_log_metric_filter" "alb_4xx_errors" {
  name           = "${var.project_name}-alb-4xx-filter"
  pattern        = "[type, time, elb, client_ip, target_ip, request_processing_time, target_processing_time, response_processing_time, elb_status_code=4*, target_status_code, received_bytes, sent_bytes, ...]"
  log_group_name = aws_cloudwatch_log_group.alb_access.name

  metric_transformation {
    name          = "ALB4xxErrorCount"
    namespace     = "${var.project_name}/AccessLogs"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_4xx_alarm" {
  alarm_name          = "${var.project_name}-alb-4xx-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ALB4xxErrorCount"
  namespace           = "${var.project_name}/AccessLogs"
  period              = 300
  statistic           = "Sum"
  threshold           = 50  # 5분간 50개 이상 4xx 에러
  alarm_description   = "ALB에서 4xx 클라이언트 에러가 다수 발생했습니다."

  alarm_actions = [aws_sns_topic.slack_alerts.arn]
  ok_actions    = [aws_sns_topic.slack_alerts.arn]

  treat_missing_data = "notBreaching"

  tags = {
    Name        = "ALB-4xx-Error-Alarm"
    Category    = "Access"
    Environment = var.environment
  }
}

# ========================================
# RDS 슬로우 쿼리 알람
# ========================================

resource "aws_cloudwatch_log_metric_filter" "rds_slow_query" {
  name           = "${var.project_name}-rds-slowquery-filter"
  pattern        = "Query_time"
  log_group_name = aws_cloudwatch_log_group.aurora_slowquery.name

  metric_transformation {
    name          = "RDSSlowQueryCount"
    namespace     = "${var.project_name}/ApplicationLogs"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_slow_query_alarm" {
  alarm_name          = "${var.project_name}-rds-slowquery-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "RDSSlowQueryCount"
  namespace           = "${var.project_name}/ApplicationLogs"
  period              = 300
  statistic           = "Sum"
  threshold           = 20  # 5분간 20개 이상 슬로우 쿼리
  alarm_description   = "RDS에서 슬로우 쿼리가 다수 발생했습니다. 데이터베이스 성능을 확인하세요."

  alarm_actions = [aws_sns_topic.slack_alerts.arn]
  ok_actions    = [aws_sns_topic.slack_alerts.arn]

  treat_missing_data = "notBreaching"

  tags = {
    Name        = "RDS-SlowQuery-Alarm"
    Category    = "Application"
    Environment = var.environment
  }
}

# Slack 알림 Lambda 로그 그룹
resource "aws_cloudwatch_log_group" "slack_notifier_lambda" {
  name              = "/aws/lambda/${var.project_name}-slack-notifier"
  retention_in_days = 7

  tags = {
    Name        = "Slack-Notifier-Lambda-Logs"
    Environment = var.environment
  }
}

# Slack Lambda IAM Role
resource "aws_iam_role" "slack_notifier_lambda" {
  name = "${var.project_name}-slack-notifier-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = {
    Name = "Slack-Notifier-Lambda-Role"
  }
}

resource "aws_iam_role_policy" "slack_notifier_lambda" {
  name = "${var.project_name}-slack-notifier-lambda-policy"
  role = aws_iam_role.slack_notifier_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.slack_notifier_lambda.arn}:*"
      }
    ]
  })
}

# Slack 알림 Lambda 함수 코드
data "archive_file" "slack_notifier" {
  type        = "zip"
  output_path = "${path.module}/lambda/slack_notifier.zip"

  source {
    content  = <<-EOF
import json
import os
import urllib.request
import urllib.error
from datetime import datetime

def lambda_handler(event, context):
    webhook_url = os.environ.get('SLACK_WEBHOOK_URL', '')
    
    if not webhook_url:
        print("SLACK_WEBHOOK_URL is not set")
        return {'statusCode': 400, 'body': 'Webhook URL not configured'}
    
    for record in event.get('Records', []):
        try:
            # SNS 메시지 파싱
            sns_message = json.loads(record['Sns']['Message'])
            
            # 알람 정보 추출
            alarm_name = sns_message.get('AlarmName', 'Unknown Alarm')
            new_state = sns_message.get('NewStateValue', 'Unknown')
            old_state = sns_message.get('OldStateValue', 'Unknown')
            reason = sns_message.get('NewStateReason', 'No reason provided')
            timestamp = sns_message.get('StateChangeTime', datetime.now().isoformat())
            region = sns_message.get('Region', 'Unknown')
            
            # 상태에 따른 색상 및 이모지 설정
            if new_state == 'ALARM':
                color = '#FF0000'  # 빨간색
                emoji = '🚨'
                status_text = 'ALARM 발생'
            elif new_state == 'OK':
                color = '#00FF00'  # 초록색
                emoji = '✅'
                status_text = '정상 복구'
            else:
                color = '#FFFF00'  # 노란색
                emoji = '⚠️'
                status_text = 'INSUFFICIENT_DATA'
            
            # Slack 메시지 구성
            slack_message = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"{emoji} [{status_text}] {alarm_name}",
                        "fields": [
                            {
                                "title": "상태 변경",
                                "value": f"{old_state} → {new_state}",
                                "short": True
                            },
                            {
                                "title": "리전",
                                "value": region,
                                "short": True
                            },
                            {
                                "title": "발생 시간",
                                "value": timestamp,
                                "short": True
                            },
                            {
                                "title": "원인",
                                "value": reason[:500] if len(reason) > 500 else reason,
                                "short": False
                            }
                        ],
                        "footer": "CloudPentagon Monitoring System",
                        "footer_icon": "https://a.slack-edge.com/80588/img/services/amazon_cloudwatch_512.png"
                    }
                ]
            }
            
            # Slack으로 전송
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(slack_message).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                print(f"Slack notification sent successfully: {response.status}")
                
        except urllib.error.URLError as e:
            print(f"Failed to send Slack notification: {e}")
            raise e
        except Exception as e:
            print(f"Error processing record: {e}")
            raise e
    
    return {'statusCode': 200, 'body': 'Notifications sent'}
EOF
    filename = "index.py"
  }
}

resource "aws_lambda_function" "slack_notifier" {
  filename         = data.archive_file.slack_notifier.output_path
  function_name    = "${var.project_name}-slack-notifier"
  role             = aws_iam_role.slack_notifier_lambda.arn
  handler          = "index.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30
  memory_size      = 128
  source_code_hash = data.archive_file.slack_notifier.output_base64sha256

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }

  depends_on = [aws_cloudwatch_log_group.slack_notifier_lambda]

  tags = {
    Name        = "Slack-Notifier-Lambda"
    Environment = var.environment
  }
}

# SNS → Lambda 연결
resource "aws_sns_topic_subscription" "slack_lambda_subscription" {
  topic_arn = aws_sns_topic.slack_alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.slack_notifier.arn
}

resource "aws_lambda_permission" "sns_invoke_slack_lambda" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_notifier.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.slack_alerts.arn
}

# ========================================
# 11. VPC Flow Logs & CloudTrail Configuration
# ========================================

resource "aws_iam_role" "vpc_flow_logs_role" {
  name = "${var.project_name}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "VPC-FlowLogs-Role"
  }
}

resource "aws_iam_role_policy" "vpc_flow_logs_policy" {
  name = "${var.project_name}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "vpc1_flow_log" {
  vpc_id          = aws_vpc.vpc1.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.vpc_flow_logs_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  tags = {
    Name = "VPC1-FlowLogs"
  }
}

resource "aws_iam_role" "cloudtrail_role" {
  name = "${var.project_name}-cloudtrail-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "CloudTrail-Role"
  }
}

resource "aws_iam_role_policy" "cloudtrail_policy" {
  name = "${var.project_name}-cloudtrail-policy"
  role = aws_iam_role.cloudtrail_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_role.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = {
    Name = "Main-CloudTrail"
  }
}

# ========================================
# 12. Bastion Host (OpenSearch 대시보드 접근용)
# ========================================

resource "aws_security_group" "bastion" {
  name        = "${var.project_name}-bastion-sg"
  description = "Security group for Bastion Host"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [
      "121.160.41.207/32",
      "222.112.195.117/32"
    ]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "Bastion-SecurityGroup"
    Environment = var.environment
  }
}

resource "aws_security_group_rule" "opensearch_from_bastion" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.opensearch.id
  source_security_group_id = aws_security_group.bastion.id
  description              = "HTTPS from Bastion"
}

resource "aws_instance" "bastion" {
  ami           = "ami-04fcc2023d6e37430"
  instance_type = "t3.micro"
  key_name      = "soldesk-507"

  subnet_id                   = aws_subnet.vpc1_public_aza.id
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  associate_public_ip_address = true

  tags = {
    Name        = "Bastion-Host"
    Environment = var.environment
  }
}

# ========================================
# 13. Outputs
# ========================================

output "opensearch_endpoint" {
  description = "OpenSearch domain endpoint"
  value       = aws_opensearch_domain.logs.endpoint
}

output "opensearch_dashboard_url" {
  description = "OpenSearch Dashboards URL"
  value       = "https://${aws_opensearch_domain.logs.endpoint}/_dashboards"
}

output "firehose_streams" {
  description = "Kinesis Firehose delivery streams"
  value = {
    application    = aws_kinesis_firehose_delivery_stream.application_logs.name
    infrastructure = aws_kinesis_firehose_delivery_stream.infrastructure_logs.name
    audit          = aws_kinesis_firehose_delivery_stream.audit_logs.name
    access         = aws_kinesis_firehose_delivery_stream.access_logs.name
  }
}

output "firehose_transform_lambda" {
  description = "Firehose Transform Lambda function"
  value       = aws_lambda_function.firehose_transform.function_name
}

output "slack_notifier_lambda" {
  description = "Slack Notifier Lambda function"
  value       = aws_lambda_function.slack_notifier.function_name
}

output "slack_alerts_topic" {
  description = "SNS Topic for Slack alerts"
  value       = aws_sns_topic.slack_alerts.arn
}

output "s3_backup_bucket" {
  description = "S3 bucket for log backups"
  value       = aws_s3_bucket.logs_backup.id
}

output "alb_logs_bucket" {
  description = "S3 bucket for ALB access logs"
  value       = aws_s3_bucket.alb_logs.id
}

output "aurora_log_groups" {
  description = "Aurora CloudWatch Log Groups"
  value = {
    error     = aws_cloudwatch_log_group.aurora_error.name
    slowquery = aws_cloudwatch_log_group.aurora_slowquery.name
  }
}

output "firehose_roles" {
  description = "Firehose IAM Role ARNs (for OpenSearch role mapping)"
  value = {
    application    = aws_iam_role.firehose_application.arn
    infrastructure = aws_iam_role.firehose_infrastructure.arn
    audit          = aws_iam_role.firehose_audit.arn
    access         = aws_iam_role.firehose_access.arn
  }
}

output "bastion_public_ip" {
  description = "Bastion Host Public IP (for OpenSearch Dashboard access)"
  value       = aws_instance.bastion.public_ip
}

output "opensearch_access_guide" {
  description = "How to access OpenSearch Dashboard"
  value       = <<-EOT
    1. SSH to Bastion: ssh -i soldesk-507.pem ec2-user@${aws_instance.bastion.public_ip}
    2. Port Forward: ssh -i soldesk-507.pem -N -L 9200:${aws_opensearch_domain.logs.endpoint}:443 ec2-user@${aws_instance.bastion.public_ip}
    3. Access Dashboard: https://localhost:9200/_dashboards
    4. Login: admin / Admin123!@#
  EOT
}

output "slack_setup_guide" {
  description = "How to set up Slack notifications"
  value       = <<-EOT
    1. Slack에서 Incoming Webhook 생성:
       - Slack 워크스페이스 → Apps → Incoming Webhooks
       - Add to Slack → 채널 선택 → Webhook URL 복사
    
    2. terraform.tfvars에 추가:
       slack_webhook_url = "https://hooks.slack.com/services/xxx/yyy/zzz"
    
    3. terraform apply 실행
    
    4. 테스트:
       aws sns publish --topic-arn ${aws_sns_topic.slack_alerts.arn} \
         --message '{"AlarmName":"Test","NewStateValue":"ALARM","OldStateValue":"OK","NewStateReason":"Test message","Region":"ap-northeast-2"}'
  EOT
}

output "alb_s3_to_firehose_lambda" {
  description = "ALB S3 to Firehose Lambda function name"
  value       = aws_lambda_function.alb_s3_to_firehose.function_name
}

output "alb_logs_flow" {
  description = "ALB Access Logs data flow"
  value       = <<-EOT
    ALB → S3 (${aws_s3_bucket.alb_logs.id})
      ↓ (S3 Event)
    Lambda (${aws_lambda_function.alb_s3_to_firehose.function_name})
      ↓
    Firehose (${aws_kinesis_firehose_delivery_stream.access_logs.name})
      ↓
    OpenSearch (access-logs-*)
  EOT
}
