  
  ╔══════════════════════════════════════════════════════════════════╗
  ║        3-Tier ECS Architecture with Dual ALB                     ║
  ╚══════════════════════════════════════════════════════════════════╝
  
  📍 VPC: 10.1.0.0/16
  
  ┌─ Tier 1: Public (ALB) ──────────────────────────────────────┐
  │  • AZ-A: 10.1.1.0/24                                         │
  │  • AZ-C: 10.1.2.0/24                                         │
  │  • Public ALB (Internet-facing)                             │
  │  • Route: 0.0.0.0/0 → Internet Gateway                      │
  └──────────────────────────────────────────────────────────────┘
                            ↓ HTTP/HTTPS
  ┌─ Tier 2a: ECS Frontend ──────────────────────────────────────┐
  │  • AZ-A: 10.1.11.0/24                                        │
  │  • AZ-C: 10.1.12.0/24                                        │
  │  • ECS Frontend Tasks (Port 3000)                           │
  │  • Internal ALB (Private)                                    │
  │  • VPC Endpoints: ECR, ECS, CloudWatch, Secrets             │
  │  • Route: 10.1.0.0/16 → local, S3 → Gateway Endpoint       │
  └──────────────────────────────────────────────────────────────┘
                            ↓ HTTP (Internal ALB)
  ┌─ Tier 2b: ECS Backend ───────────────────────────────────────┐
  │  • AZ-A: 10.1.13.0/24                                        │
  │  • AZ-C: 10.1.14.0/24                                        │
  │  • ECS Backend Tasks (Port 8080)                            │
  │  • VPC Endpoints: ECR, ECS, CloudWatch, Secrets             │
  │  • Route: 10.1.0.0/16 → local, S3 → Gateway Endpoint       │
  └──────────────────────────────────────────────────────────────┘
                            ↓ MySQL/PostgreSQL
  ┌─ Tier 3: Database (Isolated) ────────────────────────────────┐
  │  • AZ-A: 10.1.21.0/24                                        │
  │  • AZ-C: 10.1.22.0/24                                        │
  │  • RDS/Aurora (Port 3306/5432)                              │
  │  • Route: 10.1.0.0/16 → local only                          │
  │  🔒 완전 격리 (VPC 내부 통신만)                              │
  └──────────────────────────────────────────────────────────────┘
  
  🔄 트래픽 흐름:
  Internet → Public ALB → ECS Frontend → Internal ALB → ECS Backend → Database
  
  🔐 보안 그룹:
  • Public ALB SG: 0.0.0.0/0:80,443
  • ECS Frontend SG: Public ALB SG → 3000
  • Internal ALB SG: ECS Frontend SG → 80
  • ECS Backend SG: Internal ALB SG → 8080
  • DB SG: ECS Backend SG → 3306,5432
  
  💰 비용 예상 (월):
  • Interface Endpoints: ~$21.60
  • Public ALB: ~$16.20 (시간당 $0.0225 × 720시간)
  • Internal ALB: ~$16.20
  • 데이터 전송: ~$1.00
  ───────────────────────────────
  총 예상 비용: ~$55.00/월


# 1. Docker 이미지 빌드
docker build -t frontend:latest ./frontend
docker build -t backend:latest ./backend

# 2. ECR 로그인
aws ecr get-login-password --region ap-northeast-2 | \
  docker login --username AWS --password-stdin [account-id].dkr.ecr.ap-northeast-2.amazonaws.com

# 3. 이미지 태깅
docker tag frontend:latest [account-id].dkr.ecr.ap-northeast-2.amazonaws.com/frontend-app:latest
docker tag backend:latest [account-id].dkr.ecr.ap-northeast-2.amazonaws.com/backend-app:latest

# 4. ECR에 푸시
docker push [account-id].dkr.ecr.ap-northeast-2.amazonaws.com/frontend-app:latest
docker push [account-id].dkr.ecr.ap-northeast-2.amazonaws.com/backend-app:latest

# 5. ECS 서비스 업데이트 (자동으로 새 Task 배포)
aws ecs update-service --cluster web-app-cluster --service frontend-service --force-new-deployment