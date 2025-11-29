terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
}

# Variables
variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "cloudpentagon"
}

variable "environment" {
  description = "Project name for resource naming"
  type        = string
  default     = "dev"
}


# # Data source for latest Amazon Linux 2023 AMI
# data "aws_ami" "amazon_linux_2023" {
#   most_recent = true
#   owners      = ["amazon"]

#   filter {
#     name   = "name"
#     values = ["al2023-ami-2023.*-x86_64"]
#   }

#   filter {
#     name   = "virtualization-type"
#     values = ["hvm"]
#   }
# }

# Rocky Linux 9 최신 AMI 조회
data "aws_ami" "rocky9" {
  filter {
    name   = "image-id"
    values = ["ami-06b18c6a9a323f75f"]
  }
}

# Data source for existing key pair
data "aws_key_pair" "default" {
  key_name = "CloudPentagon"
}


# Data source for availability zones
data "aws_availability_zones" "available" {
  state = "available"
}


# ========================================
# VPC 및 기본 네트워크 구성
# ========================================

resource "aws_vpc" "vpc1" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "VPC1-Seoul-Production"
  }
}

# ========================================
# 퍼블릭 서브넷 (Public ALB용)
# ========================================

resource "aws_subnet" "vpc1_public_aza" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "VPC1-Public-Subnet-AZ-A"
    Tier = "Public-ALB"
  }
}

resource "aws_subnet" "vpc1_public_azc" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.2.0/24"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = true

  tags = {
    Name = "VPC1-Public-Subnet-AZ-C"
    Tier = "Public-ALB"
  }
}

# ========================================
# ECS Frontend 프라이빗 서브넷
# ========================================

resource "aws_subnet" "vpc1_ecs_frontend_aza" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.11.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-ECS-Frontend-Private-Subnet-AZ-A"
    Tier = "Application-ECS-Frontend"
  }
}

resource "aws_subnet" "vpc1_ecs_frontend_azc" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.12.0/24"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-ECS-Frontend-Private-Subnet-AZ-C"
    Tier = "Application-ECS-Frontend"
  }
}

# ========================================
# ECS Backend 프라이빗 서브넷
# ========================================

resource "aws_subnet" "vpc1_ecs_backend_aza" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.13.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-ECS-Backend-Private-Subnet-AZ-A"
    Tier = "Application-ECS-Backend"
  }
}

resource "aws_subnet" "vpc1_ecs_backend_azc" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.14.0/24"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-ECS-Backend-Private-Subnet-AZ-C"
    Tier = "Application-ECS-Backend"
  }
}

# ========================================
# DB 프라이빗 서브넷 (완전 격리)
# ========================================

resource "aws_subnet" "vpc1_db_aza" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.21.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-DB-Private-Subnet-AZ-A"
    Tier = "Database"
  }
}

resource "aws_subnet" "vpc1_db_azc" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.22.0/24"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-DB-Private-Subnet-AZ-C"
    Tier = "Database"
  }
}

# ========================================
# Internet Gateway
# ========================================

resource "aws_internet_gateway" "vpc1_igw" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "VPC1-IGW"
  }
}

# ========================================
# 퍼블릭 라우트 테이블
# ========================================

resource "aws_route_table" "vpc1_public_rt" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "VPC1-Public-RT"
  }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.vpc1_public_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.vpc1_igw.id
}

resource "aws_route_table_association" "public_aza" {
  subnet_id      = aws_subnet.vpc1_public_aza.id
  route_table_id = aws_route_table.vpc1_public_rt.id
}

resource "aws_route_table_association" "public_azc" {
  subnet_id      = aws_subnet.vpc1_public_azc.id
  route_table_id = aws_route_table.vpc1_public_rt.id
}

# ========================================
# ECS Frontend 프라이빗 라우트 테이블
# ========================================

resource "aws_route_table" "vpc1_ecs_frontend_rt_aza" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "VPC1-ECS-Frontend-RT-AZ-A"
  }
}

resource "aws_route_table_association" "ecs_frontend_aza" {
  subnet_id      = aws_subnet.vpc1_ecs_frontend_aza.id
  route_table_id = aws_route_table.vpc1_ecs_frontend_rt_aza.id
}

resource "aws_route_table" "vpc1_ecs_frontend_rt_azc" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "VPC1-ECS-Frontend-RT-AZ-C"
  }
}

resource "aws_route_table_association" "ecs_frontend_azc" {
  subnet_id      = aws_subnet.vpc1_ecs_frontend_azc.id
  route_table_id = aws_route_table.vpc1_ecs_frontend_rt_azc.id
}

# ========================================
# ECS Backend 프라이빗 라우트 테이블
# ========================================

resource "aws_route_table" "vpc1_ecs_backend_rt_aza" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "VPC1-ECS-Backend-RT-AZ-A"
  }
}

resource "aws_route_table_association" "ecs_backend_aza" {
  subnet_id      = aws_subnet.vpc1_ecs_backend_aza.id
  route_table_id = aws_route_table.vpc1_ecs_backend_rt_aza.id
}

resource "aws_route_table" "vpc1_ecs_backend_rt_azc" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "VPC1-ECS-Backend-RT-AZ-C"
  }
}

resource "aws_route_table_association" "ecs_backend_azc" {
  subnet_id      = aws_subnet.vpc1_ecs_backend_azc.id
  route_table_id = aws_route_table.vpc1_ecs_backend_rt_azc.id
}

# ========================================
# DB 프라이빗 라우트 테이블
# ========================================

resource "aws_route_table" "vpc1_db_rt_aza" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "VPC1-DB-RT-AZ-A"
    Type = "Local-Only"
  }
}

resource "aws_route_table_association" "db_aza" {
  subnet_id      = aws_subnet.vpc1_db_aza.id
  route_table_id = aws_route_table.vpc1_db_rt_aza.id
}

resource "aws_route_table" "vpc1_db_rt_azc" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "VPC1-DB-RT-AZ-C"
    Type = "Local-Only"
  }
}

resource "aws_route_table_association" "db_azc" {
  subnet_id      = aws_subnet.vpc1_db_azc.id
  route_table_id = aws_route_table.vpc1_db_rt_azc.id
}

# ========================================
# VPC Endpoints 보안 그룹
# ========================================

resource "aws_security_group" "vpc_endpoints_sg" {
  name        = "vpc-endpoints-sg"
  description = "Security group for VPC Endpoints"
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
    Name = "VPC-Endpoints-SG"
  }
}

# ========================================
# S3 Gateway Endpoint
# ========================================

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.vpc1.id
  service_name      = "com.amazonaws.ap-northeast-2.s3"
  vpc_endpoint_type = "Gateway"
  
  route_table_ids = [
    aws_route_table.vpc1_ecs_frontend_rt_aza.id,
    aws_route_table.vpc1_ecs_frontend_rt_azc.id,
    aws_route_table.vpc1_ecs_backend_rt_aza.id,
    aws_route_table.vpc1_ecs_backend_rt_azc.id
  ]

  tags = {
    Name = "S3-Gateway-Endpoint"
  }
}

# ========================================
# Interface Endpoints (ECS 필수)
# ========================================

# ECR API Endpoint
resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.vpc1.id
  service_name        = "com.amazonaws.ap-northeast-2.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [
    aws_subnet.vpc1_ecs_frontend_aza.id,
    aws_subnet.vpc1_ecs_backend_azc.id
  ]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = {
    Name = "ECR-API-Endpoint"
  }
}

# ECR Docker Registry Endpoint
resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.vpc1.id
  service_name        = "com.amazonaws.ap-northeast-2.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [
    aws_subnet.vpc1_ecs_frontend_aza.id,
    aws_subnet.vpc1_ecs_backend_azc.id
  ]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = {
    Name = "ECR-Docker-Endpoint"
  }
}

# ECR Docker Registry Endpoint
resource "aws_vpc_endpoint" "ecs" {
  vpc_id              = aws_vpc.vpc1.id
  service_name        = "com.amazonaws.ap-northeast-2.ecs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [
    aws_subnet.vpc1_ecs_frontend_aza.id,
    aws_subnet.vpc1_ecs_backend_azc.id
  ]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = {
    Name = "ECS-Endpoint"
  }
}

# ECS Agent Endpoint
resource "aws_vpc_endpoint" "ecs_agent" {
  vpc_id              = aws_vpc.vpc1.id
  service_name        = "com.amazonaws.ap-northeast-2.ecs-agent"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [
    aws_subnet.vpc1_ecs_frontend_aza.id,
    aws_subnet.vpc1_ecs_backend_azc.id
  ]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = {
    Name = "ECS-Agent-Endpoint"
  }
}

# ECS Telemetry Endpoint
resource "aws_vpc_endpoint" "ecs_telemetry" {
  vpc_id              = aws_vpc.vpc1.id
  service_name        = "com.amazonaws.ap-northeast-2.ecs-telemetry"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [
    aws_subnet.vpc1_ecs_frontend_aza.id,
    aws_subnet.vpc1_ecs_backend_azc.id
  ]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = {
    Name = "ECS-Telemetry-Endpoint"
  }
}

# CloudWatch Logs Endpoint
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.vpc1.id
  service_name        = "com.amazonaws.ap-northeast-2.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [
    aws_subnet.vpc1_ecs_frontend_aza.id,
    aws_subnet.vpc1_ecs_backend_azc.id
  ]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = {
    Name = "CloudWatch-Logs-Endpoint"
  }
}

# Secrets Manager Endpoint
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id              = aws_vpc.vpc1.id
  service_name        = "com.amazonaws.ap-northeast-2.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [
    aws_subnet.vpc1_ecs_frontend_aza.id,
    aws_subnet.vpc1_ecs_backend_azc.id
  ]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = {
    Name = "Secrets-Manager-Endpoint"
  }
}

# ========================================
# Public ALB (인터넷 → Frontend)
# ========================================

resource "aws_security_group" "public_alb_sg" {
  name        = "public-alb-sg"
  description = "Security group for Public ALB"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    description = "HTTP from Internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Public-ALB-SG"
  }
}

resource "aws_lb" "public_alb" {
  name               = "vpc1-public-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.public_alb_sg.id]
  subnets            = [
    aws_subnet.vpc1_public_aza.id,
    aws_subnet.vpc1_public_azc.id
  ]

  enable_deletion_protection = false
  enable_http2              = true

  tags = {
    Name = "VPC1-Public-ALB"
    Tier = "Public"
  }
}

# ========================================
# Internal ALB (Frontend → Backend)
# ========================================

resource "aws_security_group" "internal_alb_sg" {
  name        = "internal-alb-sg"
  description = "Security group for Internal ALB"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    description     = "HTTP from ECS Frontend"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_frontend_sg.id]
  }

  ingress {
    description     = "HTTPS from ECS Frontend"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_frontend_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Internal-ALB-SG"
  }
}

resource "aws_lb" "internal_alb" {
  name               = "vpc1-internal-alb"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.internal_alb_sg.id]
  subnets            = [
    aws_subnet.vpc1_ecs_frontend_aza.id,
    aws_subnet.vpc1_ecs_frontend_azc.id
  ]

  enable_deletion_protection = false
  enable_http2              = true

  tags = {
    Name = "VPC1-Internal-ALB"
    Tier = "Internal"
  }
}

# ========================================
# ECS Frontend 보안 그룹
# ========================================

resource "aws_security_group" "ecs_frontend_sg" {
  name        = "ecs-frontend-sg"
  description = "Security group for ECS Frontend"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    description     = "HTTP from Public ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.public_alb_sg.id]
  }

  ingress {
    description     = "App Port from Public ALB"
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.public_alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ECS-Frontend-SG"
  }
}

# ========================================
# ECS Backend 보안 그룹
# ========================================

resource "aws_security_group" "ecs_backend_sg" {
  name        = "ecs-backend-sg"
  description = "Security group for ECS Backend"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    description     = "HTTP from Internal ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.internal_alb_sg.id]
  }

  ingress {
    description     = "App Port from Internal ALB"
    from_port       = 8000
    to_port         = 8000d
    protocol        = "tcp"
    security_groups = [aws_security_group.internal_alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ECS-Backend-SG"
  }
}

# ========================================
# DB 보안 그룹
# ========================================

resource "aws_security_group" "db_sg" {
  name        = "db-sg"
  description = "Security group for Database"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    description     = "MySQL/Aurora from ECS Backend"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_backend_sg.id]
  }

  ingress {
    description     = "PostgreSQL from ECS Backend"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_backend_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "DB-SG"
  }
}

# ========================================
# Target Groups
# ========================================

# Public ALB Target Group (Frontend)
resource "aws_lb_target_group" "frontend_tg" {
  name        = "ecs-frontend-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc1.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }

  tags = {
    Name = "ECS-Frontend-TG"
  }
}

# Internal ALB Target Group (Backend)
resource "aws_lb_target_group" "backend_tg" {
  name        = "ecs-backend-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.vpc1.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }

  tags = {
    Name = "ECS-Backend-TG"
  }
}

# ========================================
# ALB Listeners
# ========================================

# Public ALB Listener
resource "aws_lb_listener" "public_alb_listener" {
  load_balancer_arn = aws_lb.public_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend_tg.arn
  }
}

# Internal ALB Listener
resource "aws_lb_listener" "internal_alb_listener" {
  load_balancer_arn = aws_lb.internal_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend_tg.arn
  }
}


# ============================================
# ECR 리포지토리
# ============================================
# resource "aws_ecr_repository" "frontend" {
#   name                 = "frontend-app"
#   image_tag_mutability = "MUTABLE"

#   image_scanning_configuration {
#     scan_on_push = true  # 보안 취약점 자동 스캔
#   }

#   encryption_configuration {
#     encryption_type = "AES256"
#   }

#   tags = {
#     Name        = "frontend-repository"
#     Environment = "production"
#   }
# }

# resource "aws_ecr_repository" "backend" {
#   name                 = "backend-app"
#   image_tag_mutability = "MUTABLE"

#   image_scanning_configuration {
#     scan_on_push = true
#   }

#   encryption_configuration {
#     encryption_type = "AES256"
#   }

#   tags = {
#     Name        = "backend-repository"
#     Environment = "production"
#   }
# }

# ECR 수명주기 정책 (오래된 이미지 자동 삭제)
# resource "aws_ecr_lifecycle_policy" "frontend_policy" {
#   repository = aws_ecr_repository.frontend.name

#   policy = jsonencode({
#     rules = [{
#       rulePriority = 1
#       description  = "Keep last 15 images"  #15장으로 수정하기
#       selection = {
#         tagStatus     = "any"
#         countType     = "imageCountMoreThan"
#         countNumber   = 15
#       }
#       action = {
#         type = "expire"
#       }
#     }]
#   })
# }

# ============================================
# CloudWatch 로그 그룹
# ============================================
resource "aws_cloudwatch_log_group" "frontend" {
  name              = "/ecs/frontend"
  retention_in_days = 30
  
  tags = {
    Name = "frontend-logs"
  }
}

resource "aws_cloudwatch_log_group" "backend" {
  name              = "/ecs/backend"
  retention_in_days = 30
  
  tags = {
    Name = "backend-logs"
  }
}

# ============================================
# IAM 역할
# ============================================
# ECS Task 실행 역할 (ECR pull, CloudWatch 로그 등)
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ECS Task 역할 (애플리케이션이 AWS 서비스 사용 시 필요)
resource "aws_iam_role" "ecs_task_role" {
  name = "ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

# ============================================
# 프론트엔드 ECS 클러스터
# ============================================
resource "aws_ecs_cluster" "frontend" {
  name = "frontend-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"  # 모니터링 강화
  }

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"
      log_configuration {
        cloud_watch_log_group_name = "/ecs/exec/frontend"
      }
    }
  }

  tags = {
    Name = "frontend-cluster"
  }
}

# ============================================
# 백엔드 ECS 클러스터
# ============================================
resource "aws_ecs_cluster" "backend" {
  name = "backend-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"  # 모니터링 강화
  }

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"
      log_configuration {
        cloud_watch_log_group_name = "/ecs/exec/backend"
      }
    }
  }

  tags = {
    Name = "backend-cluster"
  }
}

# ============================================
# 프론트엔드 ECS Task Definition
# ============================================
resource "aws_ecs_task_definition" "frontend" {
  family                   = "frontend-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"   # 0.5 vCPU
  memory                   = "1024"  # 1GB
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([{
    name      = "frontend-container" #컨테이너 이름 
    image     = "246737816332.dkr.ecr.ap-northeast-2.amazonaws.com/frontend-app:latest"   #repository_url 설정해주기
    essential = true

    portMappings = [{
      containerPort = 80
      protocol      = "tcp"
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.frontend.name
        "awslogs-region"        = "ap-northeast-2"
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = {
    Name = "frontend-task"
  }
}

# ============================================
# 백엔드 ECS Task Definition
# ============================================
resource "aws_ecs_task_definition" "backend" {
  family                   = "backend-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"  # 1 vCPU
  memory                   = "2048"  # 2GB
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([{
    name      = "backend-container" #컨테이너 이름 
    image     = "246737816332.dkr.ecr.ap-northeast-2.amazonaws.com/backend-app:latest"
    essential = true

    portMappings = [{
      containerPort = 8000
      protocol      = "tcp"
    }]

    environment = [
      {
        name  = "CLOUD_API_KEY"
        value = "222768776744816"
      },
      {
        name  = "CLOUD_API_SECRET"
        value = "1kj1qRyaxurxfH3vM6I3TJImlgQ"
      },
      {
        name  = "CLOUD_NAME"  
        value = "dqqhihcfa" 
      },
            {
        name  = "DB_PASSWORD"  
        value = "DB 비밀번호" 
      },
            {
        name  = "DB_URL"  
        value = "jdbc:mysql://DB명 입력:3306/social_network?useSSL=false&createDatabaseIfNotExist=true&serverTimezone=UTC" 
      },
            {
        name  = "DB_USERNAME"  
        value = "admin" 
      }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.backend.name
        "awslogs-region"        = "ap-northeast-2"
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = {
    Name = "backend-task"
  }
}


# ============================================
# 프론트엔드 ECS Service
# ============================================
resource "aws_ecs_service" "frontend" {
  name            = "frontend-service"
  cluster         = aws_ecs_cluster.frontend.id
  task_definition = aws_ecs_task_definition.frontend.arn
  desired_count   = 1    #빠른 구동을위해 임시로 1로 설정 
  launch_type     = "FARGATE"

  network_configuration {
    subnets = [
      aws_subnet.vpc1_ecs_frontend_aza.id,
      aws_subnet.vpc1_ecs_frontend_azc.id,
    ]

    security_groups  = [aws_security_group.ecs_frontend_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.frontend_tg.arn
    container_name   = "frontend-container"   # ← task_definition 안 name 과 동일해야 함
    container_port   = 80           # nginx 가 LISTEN 하는 포트
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener.public_alb_listener]
}


# ============================================
# 백엔드 ECS Service
# ============================================
resource "aws_ecs_service" "backend" {
  name            = "backend-service"
  cluster         = aws_ecs_cluster.backend.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = 1        #빠른 구동을위해 임시로 1로 설정 
  launch_type     = "FARGATE"

  network_configuration {
      subnets = [
      aws_subnet.vpc1_ecs_backend_aza.id,
      aws_subnet.vpc1_ecs_backend_azc.id,
    ]
    security_groups  = [aws_security_group.ecs_backend_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.backend_tg.arn
    container_name   = "backend-container"
    container_port   = 8000
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener.internal_alb_listener]
}

# ============================================
# Auto Scaling
# ============================================
#프론트엔드
resource "aws_appautoscaling_target" "frontend" {
  max_capacity       = 4
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.frontend.name}/${aws_ecs_service.frontend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "frontend_cpu" {
  name               = "frontend-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.frontend.resource_id
  scalable_dimension = aws_appautoscaling_target.frontend.scalable_dimension
  service_namespace  = aws_appautoscaling_target.frontend.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = 70.0

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

#백엔드
resource "aws_appautoscaling_target" "backend" {
  max_capacity       = 4
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.backend.name}/${aws_ecs_service.backend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "backend_cpu" {
  name               = "backend-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.backend.resource_id
  scalable_dimension = aws_appautoscaling_target.backend.scalable_dimension
  service_namespace  = aws_appautoscaling_target.backend.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = 70.0

    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }

    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# # ============================================
# # CloudWatch Alarms (모니터링)
# # ============================================
# resource "aws_cloudwatch_metric_alarm" "frontend_cpu_high" {
#   alarm_name          = "frontend-cpu-high"
#   comparison_operator = "GreaterThanThreshold"
#   evaluation_periods  = "2"
#   metric_name         = "CPUUtilization"
#   namespace           = "AWS/ECS"
#   period              = "300"
#   statistic           = "Average"
#   threshold           = "85"
#   alarm_description   = "Frontend CPU usage is too high"

#   dimensions = {
#     ClusterName = aws_ecs_cluster.main.name
#     ServiceName = aws_ecs_service.frontend.name
#   }
# }

# resource "aws_cloudwatch_metric_alarm" "backend_cpu_high" {
#   alarm_name          = "backend-cpu-high"
#   comparison_operator = "GreaterThanThreshold"
#   evaluation_periods  = "2"
#   metric_name         = "CPUUtilization"
#   namespace           = "AWS/ECS"
#   period              = "300"
#   statistic           = "Average"
#   threshold           = "85"
#   alarm_description   = "Backend CPU usage is too high"

#   dimensions = {
#     ClusterName = aws_ecs_cluster.main.name
#     ServiceName = aws_ecs_service.backend.name
#   }
# }







# ========================================
# VPC2 - IDC 환경
# ========================================

# VPC2 생성 (IDC 시뮬레이션)
resource "aws_vpc" "vpc2" {
  cidr_block           = "10.2.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "VPC2-Seoul-IDC"
  }
}

resource "aws_internet_gateway" "vpc2_igw" {
  vpc_id = aws_vpc.vpc2.id

  tags = {
    Name = "VPC2-IGW"
  }
}

# 프라이빗 서브넷 생성
resource "aws_subnet" "vpc2_subnet" {
  vpc_id            = aws_vpc.vpc2.id
  cidr_block        = "10.2.1.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "VPC2-Seoul-IDC-Subnet"
  }
}

# 프라이빗 라우트 테이블 생성
resource "aws_route_table" "vpc2_rt" {
  vpc_id = aws_vpc.vpc2.id

  tags = {
    Name = "VPC2-IDC-RouteTable"
  }
}

resource "aws_route" "vpc2_internet_route" {
  route_table_id         = aws_route_table.vpc2_rt.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.vpc2_igw.id
}

# 서브넷과 라우트 테이블 연결
resource "aws_route_table_association" "vpc2_assoc" {
  subnet_id      = aws_subnet.vpc2_subnet.id
  route_table_id = aws_route_table.vpc2_rt.id
}

# ========================================
# IDC EC2 인스턴스 (VPN 장비 역할)
# ========================================

# 보안 그룹 생성
resource "aws_security_group" "vpc2_idc_sg" {
  name        = "vpc2-idc-sg"
  description = "Security group for IDC EC2"
  vpc_id      = aws_vpc.vpc2.id

  # VPN 트래픽 허용
  ingress {
    description = "SSH Access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "IPSec IKE"
    from_port   = 500
    to_port     = 500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "IPSec NAT-T"
    from_port   = 4500
    to_port     = 4500
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VPC1에서 오는 트래픽 허용
  ingress {
    description = "From VPC1"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.1.0.0/16"]
  }

  # VPC2 내부 통신
  ingress {
    description = "VPC2 Internal"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.2.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "VPC2-IDC-SecurityGroup"
  }
}

# IDC EC2 인스턴스용 EIP
resource "aws_eip" "idc_vpn_eip" {
  domain = "vpc"

  tags = {
    Name = "IDC-VPN-Device-EIP"
  }
}



# IDC EC2 인스턴스
resource "aws_instance" "idc_vpn_server" {
  ami           = data.aws_ami.rocky9.id
  instance_type = "t3.small"   # x86_64 기반
  subnet_id     = aws_subnet.vpc2_subnet.id
  key_name = data.aws_key_pair.default.key_name
  vpc_security_group_ids = [aws_security_group.vpc2_idc_sg.id]
  source_dest_check = false

  # VPN 소프트웨어 설치를 위한 초기 설정
    user_data = base64encode(<<-EOF
    #!/bin/bash
    hostnamectl --static set-hostname VPC2-IDC-DB

    cat <<'EOT' > /etc/profile.d/prompt.sh
    export PS1="[\[\e[1;31m\]\u\[\e[m\]@\[\e[1;32m\]\h\[\e[m\]: \[\e[1;36m\]\w\[\e[m\]]#"
    EOT
    source /etc/profile

    # MariaDB 10.5 설치
    dnf install -y mariadb105-server mariadb105

    # 서비스 활성화
    systemctl enable --now mariadb

    cat >> /etc/my.cnf <<'EOF2'
    [client]
    default-character-set = utf8mb4

    [mysql]
    default-character-set = utf8mb4

    [mysqld]
    bind-address = 0.0.0.0
    character-set-server = utf8mb4
    collation-server = utf8mb4_unicode_ci
    skip-character-set-client-handshake
    default_authentication_plugin = mysql_native_password
    log-bin=mysql-bin
    server-id=2
    read_only=1
    EOF2

    systemctl restart mariadb

    # 보안 초기화 SQL
    cat > /root/secure_mariadb.sql <<'EOF3'
    DROP DATABASE IF EXISTS test;
    DELETE FROM mysql.db WHERE Db LIKE 'test%';

    DROP USER IF EXISTS ''@'localhost';
    DROP USER IF EXISTS ''@'%';

    DROP USER IF EXISTS 'root'@'::1';
    DROP USER IF EXISTS 'root'@'127.0.0.1';
    ALTER USER 'root'@'localhost' IDENTIFIED BY 'P@ssw0rd';

    FLUSH PRIVILEGES;
    EOF3

    mysql --protocol=socket -uroot < /root/secure_mariadb.sql

    # 사용자/DB/테이블 생성
    cat > /root/init_sqldb.sql <<'SQL'
    CREATE USER IF NOT EXISTS 'user1'@'%' IDENTIFIED BY 'P@ssw0rd';
    GRANT ALL PRIVILEGES ON *.* TO 'user1'@'%' WITH GRANT OPTION;

    CREATE DATABASE IF NOT EXISTS sqlDB
      CHARACTER SET utf8mb4
      COLLATE utf8mb4_unicode_ci;

    USE sqlDB;

    CREATE TABLE IF NOT EXISTS userTBL
    (
      userID    CHAR(8)      NOT NULL PRIMARY KEY,
      name      NVARCHAR(10) NOT NULL,
      birthYear INT          NOT NULL,
      addr      NCHAR(2)     NOT NULL,
      mobile1   CHAR(3),
      mobile2   CHAR(8),
      height    SMALLINT,
      mDATE     DATE
    );

    INSERT INTO userTBL VALUES ('LSG','이승기',1987,'서울','011','1111111',182,'2008-08-08');
    INSERT INTO userTBL VALUES ('KBS','김범수',1979,'경남','011','2222222',173,'2012-04-04');
    INSERT INTO userTBL VALUES ('KKH','김경호',1971,'전남','019','3333333',177,'2007-07-07');
    INSERT INTO userTBL VALUES ('JYP','조용필',1950,'경기','011','4444444',166,'2009-04-04');
    INSERT INTO userTBL VALUES ('SSK','성시경',1979,'서울',NULL,NULL,186,'2013-12-12');
    INSERT INTO userTBL VALUES ('LJB','임재범',1963,'서울','016','6666666',182,'2009-09-09');
    INSERT INTO userTBL VALUES ('YJS','윤종신',1969,'경남',NULL,NULL,170,'2005-05-05');
    INSERT INTO userTBL VALUES ('EJW','은지원',1972,'경북','011','8888888',174,'2014-03-03');
    INSERT INTO userTBL VALUES ('JKW','조관우',1965,'경기','018','9999999',172,'2010-10-10');
    INSERT INTO userTBL VALUES ('BBK','바비킴',1973,'서울','010','0000000',176,'2013-05-05');
    INSERT INTO userTBL VALUES ('JUL','김주일',1978,'서울','010','0000000',176,'2013-05-05');
    INSERT INTO userTBL VALUES ('CSJ','최소진',1986,'서울','010','0000000',176,'2013-05-05');

    FLUSH PRIVILEGES;
    SQL

    mysql -uroot -p'P@ssw0rd' < /root/init_sqldb.sql

    cat <<EOT> /home/ec2-user/list.txt
    10.1.3.100
    websrv1.awsseoul.internal
    10.1.4.100
    websrv2.awsseoul.internal
    10.2.1.100
    dbsrv.idcseoul.internal
    10.2.1.200
    dnssrv.idcseoul.internal
    10.3.3.100
    websrv1.awssingapore.internal
    10.4.1.100
    dbsrv.idcsingapore.internal
    10.4.1.200
    dnssrv.idcsingapore.internal
    EOT

    curl -o /home/ec2-user/pingall.sh https://cloudneta-book.s3.ap-northeast-2.amazonaws.com/chapter6/pingall.sh --silent
    chmod +x /home/ec2-user/pingall.sh
    EOF
  )

  tags = {
    Name = "VPC2-IDC-DB"
  }
}


# EIP를 EC2에 연결
resource "aws_eip_association" "idc_eip_assoc" {
  instance_id   = aws_instance.idc_vpn_server.id
  allocation_id = aws_eip.idc_vpn_eip.id
}

# ========================================
# VPC1 - AWS 클라우드 환경
# ========================================

# Customer Gateway (IDC 측 VPN 장비)
resource "aws_customer_gateway" "vpc1_cgw" {
  bgp_asn    = 65000
  ip_address = aws_eip.idc_vpn_eip.public_ip  # IDC EC2의 EIP 사용
  type       = "ipsec.1"

  tags = {
    Name = "VPC1-Seoul-CustomerGateway-IDC"
  }

  depends_on = [aws_eip.idc_vpn_eip]
}

# Virtual Private Gateway (VPC1에 연결)
resource "aws_vpn_gateway" "vpc1_vgw" {
  vpc_id = aws_vpc.vpc1.id

  tags = {
    Name = "VPC1-Seoul-VirtualPrivateGateway"
  }
}

# VPN Connection
resource "aws_vpn_connection" "vpc1_vpn" {
  customer_gateway_id = aws_customer_gateway.vpc1_cgw.id
  vpn_gateway_id      = aws_vpn_gateway.vpc1_vgw.id
  type                = "ipsec.1"
  static_routes_only  = true  # Static routing 사용 (EC2 VPN이므로)

  # Tunnel 1 설정
  tunnel1_preshared_key = "cloudneta"
  tunnel1_inside_cidr   = "169.254.159.32/30"

  # Tunnel 2 설정
  tunnel2_preshared_key = "cloudneta"
  tunnel2_inside_cidr   = "169.254.210.148/30"

  tags = {
    Name = "VPC1-Seoul-AWS-VPNConnection-IDC"
  }
}

# Static Route 추가 (VPC2 대역)
resource "aws_vpn_connection_route" "vpc2_route" {
  destination_cidr_block = "10.2.0.0/16"
  vpn_connection_id      = aws_vpn_connection.vpc1_vpn.id
}

# VPC1 Route Table에서 IDC(VPC2)로 가는 라우트
resource "aws_route" "vpc1_to_idc" {
  route_table_id         = aws_route_table.vpc1_db_rt_aza.id
  destination_cidr_block = "10.2.0.0/16"  # VPC2(IDC) 대역
  gateway_id             = aws_vpn_gateway.vpc1_vgw.id
  depends_on             = [aws_vpn_connection.vpc1_vpn]
}

# VPC2 Route Table에서 VPC1으로 가는 라우트
resource "aws_route" "vpc2_to_vpc1" {
  route_table_id         = aws_route_table.vpc2_rt.id
  destination_cidr_block = "10.1.0.0/16"  # VPC1 대역
  network_interface_id   = aws_instance.idc_vpn_server.primary_network_interface_id
  depends_on             = [aws_instance.idc_vpn_server]
}

# VPN을 통해 학습한 라우트가 자동으로 전파
resource "aws_vpn_gateway_route_propagation" "route_propagation" {
  vpn_gateway_id = aws_vpn_gateway.vpc1_vgw.id
  route_table_id = aws_route_table.vpc1_public_rt.id
}



# ========================================
# Outputs
# ========================================

output "idc_vpn_eip" {
  description = "IDC VPN EC2 Elastic IP"
  value       = aws_eip.idc_vpn_eip.public_ip
}

output "idc_ec2_private_ip" {
  description = "IDC EC2 Private IP"
  value       = aws_instance.idc_vpn_server.private_ip
}

output "vpn_connection_id" {
  description = "VPN Connection ID"
  value       = aws_vpn_connection.vpc1_vpn.id
}

output "vpn_tunnel1_address" {
  description = "VPN Tunnel 1 AWS endpoint"
  value       = aws_vpn_connection.vpc1_vpn.tunnel1_address
}

output "vpn_tunnel2_address" {
  description = "VPN Tunnel 2 AWS endpoint"
  value       = aws_vpn_connection.vpc1_vpn.tunnel2_address
}

output "vpn_configuration" {
  description = "VPN Configuration for IDC EC2"
  value = {
    tunnel1_address           = aws_vpn_connection.vpc1_vpn.tunnel1_address
    tunnel1_preshared_key     = "cloudneta"
    tunnel1_inside_cidr       = "169.254.159.32/30"
    tunnel1_cgw_inside_ip     = aws_vpn_connection.vpc1_vpn.tunnel1_cgw_inside_address
    tunnel1_vgw_inside_ip     = aws_vpn_connection.vpc1_vpn.tunnel1_vgw_inside_address
    tunnel2_address           = aws_vpn_connection.vpc1_vpn.tunnel2_address
    tunnel2_preshared_key     = "cloudneta"
    tunnel2_inside_cidr       = "169.254.210.148/30"
    tunnel2_cgw_inside_ip     = aws_vpn_connection.vpc1_vpn.tunnel2_cgw_inside_address
    tunnel2_vgw_inside_ip     = aws_vpn_connection.vpc1_vpn.tunnel2_vgw_inside_address
  }
  sensitive = true
}