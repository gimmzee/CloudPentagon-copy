# ========================================
# 중앙 로그 시스템 - OpenSearch & CloudWatch Logs
# ========================================
# 730, 762 변경 필요
# ========================================
# 1. CloudWatch Log Groups (각 서비스별)
# ========================================

# ECS 애플리케이션 로그 그룹
resource "aws_cloudwatch_log_group" "ecs_frontend" {
  name              = "/aws/ecs/${var.project_name}/frontend"
  retention_in_days = 7  # 비용 절감을 위해 7일

  tags = {
    Name        = "ECS-Frontend-Logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "ecs_backend" {
  name              = "/aws/ecs/${var.project_name}/backend"
  retention_in_days = 7

  tags = {
    Name        = "ECS-Backend-Logs"
    Environment = var.environment
  }
}

# ALB 액세스 로그 그룹
resource "aws_cloudwatch_log_group" "alb_public" {
  name              = "/aws/alb/${var.project_name}/public"
  retention_in_days = 3  # ALB 로그는 많으므로 3일

  tags = {
    Name        = "ALB-Public-Logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "alb_internal" {
  name              = "/aws/alb/${var.project_name}/internal"
  retention_in_days = 3

  tags = {
    Name        = "ALB-Internal-Logs"
    Environment = var.environment
  }
}

# RDS 로그 그룹 (자동 생성되지만 명시적으로 관리)
resource "aws_cloudwatch_log_group" "aurora_error" {
  name              = "/aws/rds/cluster/cloudpentagon-cluster/error"
  retention_in_days = 7

  tags = {
    Name        = "RDS-Error-Logs"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "aurora_slowquery" {
  name              = "/aws/rds/cluster/cloudpentagon-cluster/slowquery"
  retention_in_days = 7

  tags = {
    Name        = "RDS-SlowQuery-Logs"
    Environment = var.environment
  }
}

# VPC Flow Logs 그룹
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/${var.project_name}/flowlogs"
  retention_in_days = 3  # Flow 로그는 많으므로 3일

  tags = {
    Name        = "VPC-FlowLogs"
    Environment = var.environment
  }
}

# CloudTrail 로그 그룹
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.project_name}"
  retention_in_days = 30  # 감사 로그는 30일 보관

  tags = {
    Name        = "CloudTrail-Logs"
    Environment = var.environment
  }
}

# Lambda 로그 그룹들 (기존 Lambda 함수들)
resource "aws_cloudwatch_log_group" "lambda_notification" {
  name              = "/aws/lambda/${var.project_name}-notification-lambda"
  retention_in_days = 7

  tags = {
    Name        = "Lambda-Notification-Logs"
    Environment = var.environment
  }
}

# 인프라 로그 그룹 (syslog용 - EC2나 인프라 컴포넌트)
resource "aws_cloudwatch_log_group" "infrastructure" {
  name              = "/aws/infrastructure/${var.project_name}/syslog"
  retention_in_days = 7

  tags = {
    Name        = "Infrastructure-Syslog"
    Environment = var.environment
  }
}

# ========================================
# 2. VPC Flow Logs 활성화
# ========================================

resource "aws_flow_log" "vpc1_flow_log" {
  vpc_id          = aws_vpc.vpc1.id
  traffic_type    = "ALL"  # ACCEPT, REJECT, ALL
  iam_role_arn    = aws_iam_role.vpc_flow_logs_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  tags = {
    Name        = "VPC1-FlowLogs"
    Environment = var.environment
  }
}

# VPC Flow Logs IAM Role
resource "aws_iam_role" "vpc_flow_logs_role" {
  name = "${var.project_name}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "VPC-FlowLogs-Role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "vpc_flow_logs_policy" {
  name = "${var.project_name}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# ========================================
# 3. CloudTrail 설정
# ========================================

# CloudTrail S3 버킷 (필수)
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "${var.project_name}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "CloudTrail-Logs-Bucket"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudTrail S3 버킷 정책
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

# CloudTrail IAM Role for CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name = "${var.project_name}-cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "CloudTrail-CloudWatch-Role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_policy" {
  name = "${var.project_name}-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailCreateLogStream"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# CloudTrail
resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  # CloudWatch Logs 통합
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_role.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = {
    Name        = "Main-CloudTrail"
    Environment = var.environment
  }
}

# ========================================
# 4. OpenSearch Domain (비용 최적화 버전)
# ========================================

# OpenSearch용 보안 그룹
resource "aws_security_group" "opensearch" {
  name        = "${var.project_name}-opensearch-sg"
  description = "Security group for OpenSearch domain"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.vpc1.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "OpenSearch-SecurityGroup"
    Environment = var.environment
  }
}

# # OpenSearch Service-Linked Role 생성
# resource "aws_iam_service_linked_role" "opensearch" {
#   aws_service_name = "es.amazonaws.com"
#   description      = "Service-linked role for Amazon OpenSearch Service"

#   # 이미 존재할 수 있으므로 lifecycle 추가
#   lifecycle {
#     ignore_changes = [
#       aws_service_name,
#       description
#     ]
#   }
# }

# OpenSearch Domain (비용 최적화: 단일 노드)
resource "aws_opensearch_domain" "logs" {
  # depends_on = [aws_iam_service_linked_role.opensearch]
  domain_name    = "${var.project_name}-logs"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type  = "t3.small.search"  # 가장 저렴한 옵션
    instance_count = 1                  # 단일 노드 (개발/학습용)
    
    # 프로덕션에서는 다음을 활성화:
    # instance_count = 2
    # zone_awareness_enabled = true
    # zone_awareness_config {
    #   availability_zone_count = 2
    # }
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10  # 10GB (최소)
    volume_type = "gp3"
  }

  # VPC 내부 배치
  vpc_options {
    subnet_ids         = [aws_subnet.vpc1_ecs_backend_aza.id]
    security_group_ids = [aws_security_group.opensearch.id]
  }

  # 액세스 정책
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"  # 모두 허용
        }
        Action   = "es:*"
        Resource = "arn:aws:es:ap-northeast-2:${data.aws_caller_identity.current.account_id}:domain/${var.project_name}-logs/*"
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
      master_user_password = "Admin123!" # 실제로는 AWS Secrets Manager 사용 권장
    }
  }

  tags = {
    Name        = "OpenSearch-Logs-Domain"
    Environment = var.environment
  }
}

# ========================================
# 5. Lambda - CloudWatch Logs to OpenSearch
# ========================================

# Lambda IAM Role
resource "aws_iam_role" "logs_to_opensearch_lambda" {
  name = "${var.project_name}-logs-to-opensearch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "LogsToOpenSearch-Lambda-Role"
    Environment = var.environment
  }
}

# Lambda IAM Policy
resource "aws_iam_role_policy" "logs_to_opensearch_policy" {
  name = "${var.project_name}-logs-to-opensearch-policy"
  role = aws_iam_role.logs_to_opensearch_lambda.id

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
          "es:ESHttpPost",
          "es:ESHttpPut"
        ]
        Resource = "${aws_opensearch_domain.logs.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      }
    ]
  })
}

# Lambda Function
resource "aws_lambda_function" "logs_to_opensearch" {
  filename      = "${path.module}/lambda_logs_to_opensearch/logs_to_opensearch.zip"  # 별도로 생성 필요
  function_name = "${var.project_name}-logs-to-opensearch"
  role          = aws_iam_role.logs_to_opensearch_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 60
  memory_size   = 256

  vpc_config {
    subnet_ids         = [aws_subnet.vpc1_ecs_backend_aza.id]
    security_group_ids = [aws_security_group.opensearch.id]
  }

  environment {
    variables = {
      OPENSEARCH_ENDPOINT = aws_opensearch_domain.logs.endpoint
      OPENSEARCH_INDEX    = "aws-logs"
    }
  }

  tags = {
    Name        = "LogsToOpenSearch-Lambda"
    Environment = var.environment
  }
}

# ========================================
# 6. CloudWatch Logs Subscription Filters
# ========================================

# Aurora Error 로그 구독
resource "aws_cloudwatch_log_subscription_filter" "aurora_error_to_opensearch" {
  name            = "aurora-error-to-opensearch"
  log_group_name  = aws_cloudwatch_log_group.aurora_error.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.logs_to_opensearch.arn
  depends_on      = [aws_lambda_permission.aurora_error_allow_cloudwatch]
}

resource "aws_lambda_permission" "aurora_error_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchAuroraError"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs_to_opensearch.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.aurora_error.arn}:*"
}

# Aurora SlowQuery 로그 구독
resource "aws_cloudwatch_log_subscription_filter" "aurora_slowquery_to_opensearch" {
  name            = "aurora-slowquery-to-opensearch"
  log_group_name  = aws_cloudwatch_log_group.aurora_slowquery.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.logs_to_opensearch.arn
  depends_on      = [aws_lambda_permission.aurora_slowquery_allow_cloudwatch]
}

resource "aws_lambda_permission" "aurora_slowquery_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchAuroraSlowQuery"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs_to_opensearch.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.aurora_slowquery.arn}:*"
}

# ECS Frontend 로그 구독
resource "aws_cloudwatch_log_subscription_filter" "ecs_frontend_to_opensearch" {
  name            = "ecs-frontend-to-opensearch"
  log_group_name  = aws_cloudwatch_log_group.ecs_frontend.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.logs_to_opensearch.arn
  depends_on      = [aws_lambda_permission.ecs_frontend_allow_cloudwatch]
}

resource "aws_lambda_permission" "ecs_frontend_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchECSFrontend"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs_to_opensearch.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.ecs_frontend.arn}:*"
}

# ECS Backend 로그 구독
resource "aws_cloudwatch_log_subscription_filter" "ecs_backend_to_opensearch" {
  name            = "ecs-backend-to-opensearch"
  log_group_name  = aws_cloudwatch_log_group.ecs_backend.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.logs_to_opensearch.arn
  depends_on      = [aws_lambda_permission.ecs_backend_allow_cloudwatch]
}

resource "aws_lambda_permission" "ecs_backend_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchECSBackend"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs_to_opensearch.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.ecs_backend.arn}:*"
}

# ALB Public 로그 구독
resource "aws_cloudwatch_log_subscription_filter" "alb_public_to_opensearch" {
  name            = "alb-public-to-opensearch"
  log_group_name  = aws_cloudwatch_log_group.alb_public.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.logs_to_opensearch.arn
  depends_on      = [aws_lambda_permission.alb_public_allow_cloudwatch]
}

resource "aws_lambda_permission" "alb_public_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchALBPublic"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs_to_opensearch.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.alb_public.arn}:*"
}

# ALB Internal 로그 구독
resource "aws_cloudwatch_log_subscription_filter" "alb_internal_to_opensearch" {
  name            = "alb-internal-to-opensearch"
  log_group_name  = aws_cloudwatch_log_group.alb_internal.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.logs_to_opensearch.arn
  depends_on      = [aws_lambda_permission.alb_internal_allow_cloudwatch]
}

resource "aws_lambda_permission" "alb_internal_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchALBInternal"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs_to_opensearch.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.alb_internal.arn}:*"
}

# VPC Flow Logs 구독
resource "aws_cloudwatch_log_subscription_filter" "vpc_flowlogs_to_opensearch" {
  name            = "vpc-flowlogs-to-opensearch"
  log_group_name  = aws_cloudwatch_log_group.vpc_flow_logs.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.logs_to_opensearch.arn
  depends_on      = [aws_lambda_permission.vpc_flowlogs_allow_cloudwatch]
}

resource "aws_lambda_permission" "vpc_flowlogs_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchVPCFlowLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs_to_opensearch.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
}

# CloudTrail 로그 구독
resource "aws_cloudwatch_log_subscription_filter" "cloudtrail_to_opensearch" {
  name            = "cloudtrail-to-opensearch"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.logs_to_opensearch.arn
  depends_on      = [aws_lambda_permission.cloudtrail_allow_cloudwatch]
}

resource "aws_lambda_permission" "cloudtrail_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchCloudTrail"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs_to_opensearch.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
}

# Infrastructure Syslog 구독
resource "aws_cloudwatch_log_subscription_filter" "infrastructure_to_opensearch" {
  name            = "infrastructure-to-opensearch"
  log_group_name  = aws_cloudwatch_log_group.infrastructure.name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.logs_to_opensearch.arn
  depends_on      = [aws_lambda_permission.infrastructure_allow_cloudwatch]
}

resource "aws_lambda_permission" "infrastructure_allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatchInfrastructure"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.logs_to_opensearch.function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.infrastructure.arn}:*"
}

# ========================================
# 7. Data Sources
# ========================================

data "aws_caller_identity" "current" {}

# ========================================
# 8. Outputs
# ========================================

output "opensearch_endpoint" {
  description = "OpenSearch domain endpoint"
  value       = aws_opensearch_domain.logs.endpoint
}

output "opensearch_dashboard_endpoint" {
  description = "OpenSearch Dashboards endpoint"
  value       = aws_opensearch_domain.logs.dashboard_endpoint
}

output "cloudwatch_log_groups" {
  description = "All CloudWatch Log Groups"
  value = {
    ecs_frontend   = aws_cloudwatch_log_group.ecs_frontend.name
    ecs_backend    = aws_cloudwatch_log_group.ecs_backend.name
    alb_public     = aws_cloudwatch_log_group.alb_public.name
    alb_internal   = aws_cloudwatch_log_group.alb_internal.name
    aurora_error   = aws_cloudwatch_log_group.aurora_error.name
    aurora_slowquery = aws_cloudwatch_log_group.aurora_slowquery.name
    vpc_flowlogs   = aws_cloudwatch_log_group.vpc_flow_logs.name
    cloudtrail     = aws_cloudwatch_log_group.cloudtrail.name
    infrastructure = aws_cloudwatch_log_group.infrastructure.name
  }
}

# ========================================
# Bastion Host (OpenSearch 접근용)
# ========================================

# Bastion Host Security Group
resource "aws_security_group" "bastion" {
  name        = "${var.project_name}-bastion-sg"
  description = "Security group for Bastion Host"
  vpc_id      = aws_vpc.vpc1.id

  # SSH 접근
  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["121.160.41.207/32"]  # ← https://ifconfig.me/
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

# OpenSearch 보안 그룹 수정 (Bastion에서 접근 허용)
resource "aws_security_group_rule" "opensearch_from_bastion" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.opensearch.id
  source_security_group_id = aws_security_group.bastion.id
  description              = "HTTPS from Bastion"
}

# Bastion Host EC2
resource "aws_instance" "bastion" {
  ami           = "ami-04fcc2023d6e37430"  # Amazon Linux 2023 (ap-northeast-2)
  instance_type = "t3.micro"
  key_name      = "soldesk-507"  # ← SSH 키 페어 이름

  subnet_id                   = aws_subnet.vpc1_public_aza.id  # Public 서브넷
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  associate_public_ip_address = true

  tags = {
    Name        = "Bastion-Host"
    Environment = var.environment
  }
}

output "bastion_public_ip" {
  description = "Bastion Host Public IP"
  value       = aws_instance.bastion.public_ip
}