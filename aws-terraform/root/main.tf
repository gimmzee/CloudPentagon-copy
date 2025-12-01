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

# Amazon Linux 2023 최신 AMI 조회
data "aws_ami" "amazon_linux_2023" {
  filter {
    name   = "image-id"
    values = ["ami-04fcc2023d6e37430"]
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
# 프라이빗 서브넷 (Internal ALB용)
# ========================================

resource "aws_subnet" "vpc1_private_alb_aza" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = "10.1.21.0/24"
  availability_zone = "ap-northeast-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-Private-ALB-Subnet-AZ-A"
    Tier = "Private-ALB"
  }
}

resource "aws_subnet" "vpc1_private_alb_azc" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = "10.1.22.0/24"
  availability_zone = "ap-northeast-2c"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-Private-ALB-Subnet-AZ-C"
    Tier = "Private-ALB"
  }
}

# ========================================
# ECS Backend 프라이빗 서브넷
# ========================================

resource "aws_subnet" "vpc1_ecs_backend_aza" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.31.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-ECS-Backend-Private-Subnet-AZ-A"
    Tier = "Application-ECS-Backend"
  }
}

resource "aws_subnet" "vpc1_ecs_backend_azc" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.32.0/24"
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
  cidr_block              = "10.1.41.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false

  tags = {
    Name = "VPC1-DB-Private-Subnet-AZ-A"
    Tier = "Database"
  }
}

resource "aws_subnet" "vpc1_db_azc" {
  vpc_id                  = aws_vpc.vpc1.id
  cidr_block              = "10.1.42.0/24"
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
    to_port         = 8000
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

# ========================================
# Secrets Manager 
# ========================================
# AWS Secrets Manager
resource "aws_secretsmanager_secret" "aws_db_secret" {
  name        = "db-credentials"
  description = "Credentials for Aurora MySQL"
}

resource "aws_secretsmanager_secret_version" "aws_db_secret_value" {
  secret_id = aws_secretsmanager_secret.aws_db_secret.id

  secret_string = jsonencode({
    idc_user   = "appuser"
    idc_pw     = "P@ssw0rd"
    rds_user   = "admin"
    rds_pw     = "Soldeskqwe123"
    azure_user = "azureadmin"
    azure_pw   = "Soldeskqwe123!"
    db_name    = "social_network"
  })
}

# 비밀을 로컬 변수로 디코딩 (resource에서 바로 참조)
locals {
  db_credentials = jsondecode(
    aws_secretsmanager_secret_version.aws_db_secret_value.secret_string
  )
}


# ========================================
# AWS Aurora RDS 
# ========================================
# RDS Subnet Group
resource "aws_db_subnet_group" "aurora_subnet_group" {
  name       = "aurora-subnet-group"
  subnet_ids = [
    aws_subnet.vpc1_db_aza.id,
    aws_subnet.vpc1_db_azc.id
  ]
  description = "Aurora DB subnet group for VPC1"
}

# Aurora MySQL 클러스터
resource "aws_rds_cluster" "aurora_cluster" {
  cluster_identifier             = "cloudpentagon-cluster"
  engine                         = "aurora-mysql"
  engine_version                 = "8.0.mysql_aurora.3.08.2"
  database_name                  = "mydatabase"
  master_username                = local.db_credentials.rds_user #"admin"
  master_password                = local.db_credentials.rds_pw #"Soldeskqwe123" # 안전하게 관리 필요
  db_subnet_group_name           = aws_db_subnet_group.aurora_subnet_group.name
  skip_final_snapshot            = true
  backup_retention_period        = 1
  deletion_protection            = false
  db_cluster_parameter_group_name = "default.aurora-mysql8.0" # 콘솔에서 만든 파라미터 그룹 이름
  availability_zones = [
    aws_subnet.vpc1_db_aza.availability_zone,
    aws_subnet.vpc1_db_azc.availability_zone
  ]
  vpc_security_group_ids = [
    aws_security_group.db_sg.id
  ]
  lifecycle {
    ignore_changes = [
      availability_zones,
      engine_version
    ]  
  }  
}

# Aurora 클러스터 인스턴스
resource "aws_rds_cluster_instance" "aurora_instance" {
  count               = 2
  identifier          = "aurora-instance-${count.index + 1}"
  cluster_identifier  = aws_rds_cluster.aurora_cluster.id
  instance_class      = "db.t3.medium"
  engine              = aws_rds_cluster.aurora_cluster.engine
  engine_version      = aws_rds_cluster.aurora_cluster.engine_version
  publicly_accessible = false
  db_parameter_group_name = "default.aurora-mysql8.0" # 인스턴스 파라미터 그룹도 지정 가능
}

# ===============
# WAF 설정   
# ===============
# WAFv2 Web ACL 생성
resource "aws_wafv2_web_acl" "sns_webapp_waf" {
  name  = "sns-webapp-waf"
  scope = "REGIONAL"
  default_action { 
    allow {} 
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "sns-webapp-waf"
    sampled_requests_enabled   = true
  }

  # 기본 웹 공격 방지
  rule {
    name     = "CommonRules"
    priority = 1
    override_action { 
      none {} 
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common-rules"
      sampled_requests_enabled   = true
    }
  }

  # 알려진 악성 입력 필터
  rule {
    name     = "KnownBadInputs"
    priority = 2
    override_action { 
      none {} 
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # 관리자 페이지 보호 (/admin)
  rule {
    name     = "AdminProtection"
    priority = 3
    override_action { 
      none {} 
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAdminProtectionRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "admin-protection"
      sampled_requests_enabled   = true
    }
  }

  # Rate Limit Rule (초당 100 요청)
  rule {
    name     = "RateLimit"
    priority = 4
    action { 
      block {} 
    }
    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }
}

# ALB에 WAF 연결
resource "aws_wafv2_web_acl_association" "alb_waf_assoc" {
  resource_arn = aws_lb.public_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.sns_webapp_waf.arn
}

#CloudFront에 WAF 연결
# resource "aws_wafv2_web_acl_association" "cloudfront_assoc" {
#   resource_arn = "arn:aws:cloudfront::123456789012:distribution/EXISTING_DISTRIBUTION_ID"
#   web_acl_arn  = aws_wafv2_web_acl.sns_webapp_waf.arn
# }

# ========================================
# Route53 
# ========================================
# 퍼블릭 호스팅 영역 생성
resource "aws_route53_zone" "public" {
  name = "607junha.cloud"
  comment = "Public hosted zone for 607junha.cloud"
  force_destroy = true  # Terraform 삭제 시 레코드도 함께 삭제
}

# Route53 A 레코드 (ALB Alias)
resource "aws_route53_record" "www" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "www.607junha.cloud"
  type    = "A"

  alias {
    name                   = aws_lb.public_alb.dns_name
    zone_id                = aws_lb.public_alb.zone_id
    evaluate_target_health = true
  }
}

# Failover
# resource "aws_route53_record" "primary" {
#   zone_id = aws_route53_zone.public.zone_id
#   name    = "www.607junha.cloud"
#   type    = "A"

#   set_identifier = "AWS-ALB"
#   failover_routing_policy {
#     type = "PRIMARY"
#   }

#   alias {
#     name                   = aws_lb.public_alb.dns_name
#     zone_id                = aws_lb.public_alb.zone_id
#     evaluate_target_health = true
#   }
# }

# resource "aws_route53_record" "secondary" {
#   zone_id = aws_route53_zone.public.zone_id
#   name    = "www.607junha.cloud"
#   type    = "A"

#   set_identifier = "Azure"
#   failover_routing_policy {
#     type = "SECONDARY"
#   }

#   ttl     = 60
#   records = ["<Azure 퍼블릭 IP 또는 Azure Front Door DNS>"]
# }

# ========================================
# IDC to AWS DMS 설정
# ========================================
# AWS IDC vpn 연결 뒤 주석해제
# #dms 역할
# resource "aws_iam_role" "dms_vpc_role" {
#   name = "dms-vpc-role"

#   assume_role_policy = jsonencode({
#     Version = "2012-10-17",
#     Statement = [{
#       Effect = "Allow",
#       Principal = {
#         Service = "dms.amazonaws.com"
#       },
#       Action = "sts:AssumeRole"
#     }]
#   })

#   tags = {
#     Name = "DMS-VPC-Role"
#   }
# }

# resource "aws_iam_role_policy_attachment" "dms_vpc_policy_attach" {
#   role       = aws_iam_role.dms_vpc_role.name
#   policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonDMSVPCManagementRole"
# }

# # DMS Subnet Group
# resource "aws_dms_replication_subnet_group" "dms_subnet_group" {
#   replication_subnet_group_id          = "dms-subnet-group"
#   subnet_ids                           = [aws_subnet.vpc1_db_aza.id, aws_subnet.vpc1_db_azc.id]
#   replication_subnet_group_description = "DMS Subnet Group for VPC1 Private DB"
# }

# # DMS Security Group
# resource "aws_security_group" "dms_sg" {
#   name        = "dms-sg"
#   description = "DMS Security Group"
#   vpc_id      = aws_vpc.vpc1.id

#   ingress {
#     from_port   = 3306
#     to_port     = 3306
#     protocol    = "tcp"
#     cidr_blocks = ["10.1.41.0/24", "10.1.42.0/24", "10.0.1.0/24"] # RDS 서브넷 + IDC DB
#   }

#   egress {
#     from_port   = 0
#     to_port     = 0
#     protocol    = "-1"
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }

# # DMS Replication Instance
# resource "aws_dms_replication_instance" "dms_instance" {
#   replication_instance_id   = "dms-idc-to-aws"
#   replication_instance_class = "dms.t3.micro"
#   allocated_storage         = 50
#   publicly_accessible       = false
#   vpc_security_group_ids    = [aws_security_group.dms_sg.id]
#   replication_subnet_group_id = aws_dms_replication_subnet_group.dms_subnet_group.id
#   engine_version            = "3.5.4"
#   depends_on = [
#     aws_dms_replication_subnet_group.dms_subnet_group
#   ]
#   tags = {
#   Name = "IDC-to-Aurora-DMS"
#   }
# }

# # DMS Source Endpoint (IDC MySQL)
# resource "aws_dms_endpoint" "source_idc" {
#   endpoint_id      = "idc-mysql-source"
#   endpoint_type    = "source"
#   engine_name      = "mysql"
#   username         = local.db_credentials.idc_user #"appuser"
#   password         = local.db_credentials.idc_pw #"P@ssw0rd"
#   server_name      = "10.0.1.100"   # IDC DB 고정 IP
#   port             = 3306
#   database_name    = local.db_credentials.db_name #"social_network"
# }

# # DMS Target Endpoint (AWS RDS)
# resource "aws_dms_endpoint" "target_rds" {
#   endpoint_id      = "rds-mysql-target"
#   endpoint_type    = "target"
#   engine_name      = "aurora"
#   username         = local.db_credentials.rds_user #"admin"
#   password         = local.db_credentials.rds_pw #"Soldeskqwe123"
#   server_name      = aws_rds_cluster.aurora_cluster.endpoint
#   port             = 3306
#   database_name    = local.db_credentials.db_name #"social_network"
# }

# # DMS Replication Task
# resource "aws_dms_replication_task" "idc_to_aurora_task" {
#   replication_task_id      = "idc-to-aurora-task"
#   replication_instance_arn = aws_dms_replication_instance.dms_instance.replication_instance_arn
#   source_endpoint_arn = aws_dms_endpoint.source_idc.endpoint_arn
#   target_endpoint_arn = aws_dms_endpoint.target_rds.endpoint_arn
#   migration_type           = "full-load-and-cdc"

#   table_mappings = <<JSON
# {
#   "rules": [
#     {
#       "rule-type": "selection",
#       "rule-id": "1",
#       "rule-name": "1",
#       "object-locator": {
#         "schema-name": "%",
#         "table-name": "%"
#       },
#       "rule-action": "include"
#     }
#   ]
# }
# JSON

#   replication_task_settings = <<JSON
# {
#   "TargetMetadata": {
#     "TargetSchema": "",
#     "SupportLobs": true,
#     "FullLobMode": true
#   },
#   "FullLoadSettings": {
#     "TargetTablePrepMode": "DO_NOTHING",
#     "StopTaskCachedChangesApplied": false
#   },
#   "Logging": {
#     "EnableLogging": true
#   }
# }
# JSON
#   depends_on = [
#     aws_dms_replication_instance.dms_instance,
#     aws_dms_endpoint.source_idc,
#     aws_dms_endpoint.target_rds
#   ]
# }

# # 태스크 시작 vpn
# resource "null_resource" "start_dms_task" {
#   depends_on = [aws_dms_replication_task.idc_to_aurora_task]
#   provisioner "local-exec" {
#     command = <<EOT
#   aws dms start-replication-task --replication-task-arn ${aws_dms_replication_task.idc_to_aurora_task.replication_task_arn} --start-replication-task-type start-replication
#   EOT
#   }
# }

# ===============================
# AWS Aurora to Azure DMS 설정 #
# ===============================
# AWS Azure vpn 연결 뒤 주석해제
# # DMS Replication Instance
# resource "aws_dms_replication_instance" "dms_instance" {
#   replication_instance_id   = "aurora-to-azure-dms"
#   replication_instance_class = "dms.t3.micro"
#   allocated_storage          = 50
#   engine_version             = "3.5.4"
#     tags = {
#     Name = "Aurora-to-Azure-DMS"
#   }
# }

# # Source Endpoint (Aurora MySQL)
# resource "aws_dms_endpoint" "source_aurora" {
#   endpoint_id   = "aws-aurora-source"
#   endpoint_type = "source"
#   engine_name   = "mysql"

#   server_name   = aws_rds_cluster.aurora_cluster.endpoint
#   port          = 3306
#   username      = local.db_credentials.rds_user #"admin"
#   password      = local.db_credentials.rds_pw #"Soldeskqwe123"
#   database_name = local.db_credentials.db_name #"social_network"
# }

# # Target Endpoint (Azure MySQL)
# resource "aws_dms_endpoint" "target_azure_mysql" {
#   endpoint_id   = "azure-mysql-target"
#   endpoint_type = "target"
#   engine_name   = "mysql"

#   server_name   = "your-azure-mysql.public.database.azure.com"
#   port          = 3306
#   username      = local.db_credentials.azure_user #"azureadmin"
#   password      = local.db_credentials.azure_pw #"Soldeskqwe123!"
#   database_name = local.db_credentials.db_name #"social_network"

#   ssl_mode = "none"
# }

# # Replication Task
# resource "aws_dms_replication_task" "aurora_to_azure_my_task" {
#   replication_task_id      = "aurora-to-azure-mysql"
#   replication_instance_arn = aws_dms_replication_instance.dms_instance.replication_instance_arn
#   source_endpoint_arn      = aws_dms_endpoint.source_aurora.endpoint_arn
#   target_endpoint_arn      = aws_dms_endpoint.target_azure_mysql.endpoint_arn
#   migration_type           = "full-load-and-cdc"

#   table_mappings = <<JSON
# {
#   "rules": [
#     {
#       "rule-type": "selection",
#       "rule-id": "1",
#       "rule-name": "1",
#       "object-locator": {
#         "schema-name": "%",
#         "table-name": "%"
#       },
#       "rule-action": "include"
#     }
#   ]
# }
# JSON
# }

# # Start task
# resource "null_resource" "start_aurora_to_azure_mysql" {
#   depends_on = [aws_dms_replication_task.aurora_to_azure_my_task]
#   provisioner "local-exec" {
#     command = <<EOT
# aws dms start-replication-task \
#   --replication-task-arn ${aws_dms_replication_task.aurora_to_azure_my_task.replication_task_arn} \
#   --start-replication-task-type start-replication
# EOT
#   }
# }


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
  cidr_block           = "10.0.0.0/16"
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
  cidr_block        = "10.0.1.0/24"
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
  private_ip                  = "10.0.1.10"
  key_name = data.aws_key_pair.default.key_name
  vpc_security_group_ids = [aws_security_group.vpc2_idc_sg.id]
  source_dest_check = false

  # VPN 소프트웨어 설치를 위한 초기 설정
    user_data = base64encode(<<-EOF
    #!/bin/bash
    hostnamectl --static set-hostname VPC2-IDC-CGW

    cat <<'EOT' > /etc/profile.d/prompt.sh
    export PS1="[\[\e[1;31m\]\u\[\e[m\]@\[\e[1;32m\]\h\[\e[m\]: \[\e[1;36m\]\w\[\e[m\]]#"
    EOT
    source /etc/profile

    EOF
  )

  tags = {
    Name = "VPC2-IDC-CGW"
  }
}

# IDC DB 인스턴스
resource "aws_instance" "idc_DB_server" {
  ami           = data.aws_ami.amazon_linux_2023.id
  instance_type = "t3.small"
  subnet_id     = aws_subnet.vpc2_subnet.id
  private_ip                  = "10.0.1.100"
  associate_public_ip_address = true
  key_name      = data.aws_key_pair.default.key_name
  vpc_security_group_ids = [aws_security_group.vpc2_idc_sg.id]
  source_dest_check      = false
    
    user_data = base64encode(<<-EOF
    #!/bin/bash
    hostnamectl set-hostname VPC2-IDC-DB
    cat <<'EOT' > /etc/profile.d/prompt.sh
    export PS1="[\[\e[1;31m\]\u\[\e[m\]@\[\e[1;32m\]\h\[\e[m\]: \[\e[1;36m\]\w\[\e[m\]]#"
    EOT
    source /etc/profile
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
  static_routes_only  = false

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

# # Static Route 추가 (VPC0 대역)
# resource "aws_vpn_connection_route" "vpc2_route" {
#   destination_cidr_block = "10.0.0.0/16"
#   vpn_connection_id      = aws_vpn_connection.vpc1_vpn.id
# }

# VPC1 Route Table에서 IDC(VPC0)로 가는 라우트
resource "aws_route" "vpc1_to_idc" {
  route_table_id         = aws_route_table.vpc1_db_rt_aza.id
  destination_cidr_block = "10.0.0.0/16"  # VPC0(IDC) 대역
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
# AWS Azure VPN 설정
# ========================================
# Azure VPN Gateway와 연결하는 설정 (주석 해제 후 사용)
# # 1. Azure VPN Gateway 정보를 기반으로 Customer Gateway 생성
# resource "aws_customer_gateway" "azure_vpn_cgw" {
#   bgp_asn    = 65015            # Azure VPN Gateway BGP ASN
#   ip_address = "Azure IP"   # Azure VPN Public IP
#   type       = "ipsec.1"

#   tags = {
#     Name = "Azure-VPN-CGW"
#   }
# }

# # 2. VGW와 연결할 VPN Connection 생성
# resource "aws_vpn_connection" "vpc1_to_azure" {
#   vpn_gateway_id      = aws_vpn_gateway.vpc1_vgw.id
#   customer_gateway_id = aws_customer_gateway.azure_vpn_cgw.id
#   type                = "ipsec.1"
  
#   # BGP를 사용할 경우
#   static_routes_only = false

#   tags = {
#     Name = "VPC1-to-Azure-VPN"
#   }
# }


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