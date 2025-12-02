#!/bin/bash

# Lambda 함수 패키징 및 배포 스크립트

echo "========================================="
echo "Lambda Function Packaging for OpenSearch"
echo "========================================="

# 변수 설정
LAMBDA_DIR="lambda_logs_to_opensearch"
OUTPUT_ZIP="logs_to_opensearch.zip"

# 작업 디렉토리로 이동
cd $LAMBDA_DIR

# 이전 패키지 삭제
rm -f ../$OUTPUT_ZIP
rm -rf package

# Python 패키지 디렉토리 생성
mkdir -p package

echo "Installing Python dependencies..."
pip install -r requirements.txt -t package/

# Lambda 코드 복사
echo "Copying Lambda function code..."
cp index.py package/

# ZIP 파일 생성
echo "Creating deployment package..."
cd package
zip -r ../../$OUTPUT_ZIP .
cd ..

# 정리
rm -rf package

echo "========================================="
echo "Deployment package created: $OUTPUT_ZIP"
echo "File size: $(ls -lh ../$OUTPUT_ZIP | awk '{print $5}')"
echo "========================================="
echo ""
echo "Now you can apply Terraform:"
echo "  terraform init"
echo "  terraform plan"
echo "  terraform apply"
