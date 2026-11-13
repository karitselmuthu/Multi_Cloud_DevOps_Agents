#!/usr/bin/env bash
# Daily build: ECR repo -> build+push arm64 image -> full apply. Needs AWS creds, backend.hcl, ALLOWED_CIDR.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ALLOWED_CIDR:?set ALLOWED_CIDR, e.g. 203.0.113.7/32}"
TAG=$(date +%Y%m%d%H%M%S)
TF=infrastructure/terraform/aws
terraform -chdir=$TF init -input=false -backend-config=backend.hcl
terraform -chdir=$TF apply -input=false -auto-approve -target=aws_ecr_repository.app -var "allowed_cidr=$ALLOWED_CIDR"
REPO=$(terraform -chdir=$TF output -raw ecr_repository_url)
aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%%/*}"
docker build --platform linux/arm64 -t "$REPO:$TAG" .
docker push "$REPO:$TAG"
terraform -chdir=$TF apply -input=false -auto-approve -var "allowed_cidr=$ALLOWED_CIDR" -var "image_tag=$TAG" ${API_KEY:+-var "api_key=$API_KEY"}
echo "UI: http://$(terraform -chdir=$TF output -raw alb_dns_name)/"
