#!/usr/bin/env bash
# Daily build: ECR repo -> build+push arm64 image -> full apply. Needs AWS creds, backend.hcl, ALLOWED_CIDR.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ALLOWED_CIDR:?set ALLOWED_CIDR, e.g. 203.0.113.7/32}"
: "${API_USERS:?set API_USERS json, e.g. '{\"key\":{\"user\":\"alice\",\"roles\":[\"requester\"]}}'}"
export TF_VAR_api_users="$API_USERS"   # optional extras: TF_VAR_temporal_address, TF_VAR_state_bucket, TF_VAR_execute ...
TAG=$(date +%Y%m%d%H%M%S)
TF=infrastructure/terraform/aws
terraform -chdir=$TF init -input=false -backend-config=backend.hcl
terraform -chdir=$TF apply -input=false -auto-approve -target=aws_ecr_repository.app -var "allowed_cidr=$ALLOWED_CIDR"
REPO=$(terraform -chdir=$TF output -raw ecr_repository_url)
aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%%/*}"
docker build --platform linux/arm64 -t "$REPO:$TAG" .
docker push "$REPO:$TAG"
terraform -chdir=$TF apply -input=false -auto-approve -var "allowed_cidr=$ALLOWED_CIDR" -var "image_tag=$TAG"
echo "UI: http://$(terraform -chdir=$TF output -raw alb_dns_name)/"
