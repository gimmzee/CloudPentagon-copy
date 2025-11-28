Azure CLI (az) -> 공식 설치 관리자(MSI)를 다운로드
환경 변수 등록하기 -> C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin
az --version
Terraform CLI (terraform) 설치
terraform --version

az login
az account set --subscription "7adc47d6-5071-4675-9c57-70443589cb62"   #구독 ID or 구독 이름
안되면?
C:\Users\Ayoung>az login --use-device-code
To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code HYY9EL39T to authenticate.
https://microsoft.com/devicelogin -> 코드 입력 (예: HYY9EL39T)

C:\Users\Ayoung\Downloads\muti-cloud\muti-cloud\azure-terraform\root>az account list --output table
C:\Users\Ayoung\Downloads\muti-cloud\muti-cloud\azure-terraform\root>az account set --subscription "7adc47d6-5071-4675-9c57-70443589cb62"

#테라폼 버전 업그레이드하기
terraform init -upgrade

#az cli에서 그룹생성하기
az group create ^
  --name myFreeRG ^
  --location koreacentral

그룹 생성시 Subscription ID : 7adc47d6-5071-4675-9c57-70443589cb62

#그룹 삭제시 명령어
az group delete --name myFreeRG --yes --no-wait

#VM 생성시 키패쓰(=키페어) 필요
ssh-keygen -t rsa -b 4096 -C "azure-dr" -f C:\Users\soldesk\.ssh\id_rsa
<사용자이름> → 실제 Windows 계정 이름
.ssh 폴더가 없으면 먼저 생성

Terraform 코드 작성 및 백엔드 설정
배포할 인프라를 정의하는 Terraform 코드 파일을 작성하고, 상태 파일(State File)을 저장할 백엔드를 설정합니다. Azure에서는 보통 Azure Storage 계정을 백엔드로 사용합니다.

main.tf (리소스 정의)
versions.tf (Azure 백엔드 설정)
상태 파일을 안전하게 저장하고 팀원들과 공유하기 위해 Azure Storage Blob을 백엔드로 설정합니다.

# versions.tf

# Backend 설정: 상태 파일(State)을 Azure Storage에 저장
terraform {
  backend "azurerm" {
    # ⚠️ 아래 4개의 값은 실제 Azure 리소스로 대체해야 합니다.
    resource_group_name  = "tfstate-rg"         # 상태 저장을 위한 RG
    storage_account_name = "tfstatesa001"       # 상태 저장을 위한 Storage Account
    container_name       = "tfstate-container"  # 상태 저장을 위한 Container
    key                  = "my-app/terraform.tfstate" # 상태 파일 경로 및 이름
  }
}

💡 참고: 위의 백엔드 리소스 (tfstate-rg, tfstatesa001, tfstate-container)는 Terraform 배포 전에 Azure CLI를 사용해 수동으로 미리 생성해야 합니다.


Ansible 연계 방법 (DR 시 자동 배포)
terraform output public_ip
ansible-playbook -i inventory.ini dr-setup.yml

왜 ECS → Azure VM 구조가 일반적일까?
Azure VM + Docker
가장 빠르고 단순, DR에 최적
오케스트레이션 기능 없음 → 단일/소수 서버로만 운영
AKS 단점:초기 세팅 복잡, DR 상황에서 너무 무거움

AWS ECS(서비스 운영)
         ↓ 장애 발생
Terraform(Azure) → VM/VNet 생성
         ↓
Docker 이미지 가져오기(ECR → Azure)
         ↓
Ansible로 컨테이너 실행 / 웹 서비스 구성
         ↓
Azure Load Balancer로 트래픽 열기
         ↓
Route53 DNS → Azure LB로 장애 전환


참고로 VM으로 우분투를 많이 쓰는 이유는:
Azure에서 공식 지원이 좋음
Free Tier에서 안정적
패키지 관리가 편리함
커뮤니티와 문서가 풍부함

