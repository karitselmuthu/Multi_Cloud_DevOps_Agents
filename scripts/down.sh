#!/usr/bin/env bash
# Daily teardown: destroys everything this stack created (ECS, ALB, ECR+images, logs). Cost goes to ~0.
set -euo pipefail
cd "$(dirname "$0")/.."
TF=infrastructure/terraform/aws
terraform -chdir=$TF init -input=false -backend-config=backend.hcl
terraform -chdir=$TF destroy -input=false -auto-approve -var "allowed_cidr=${ALLOWED_CIDR:-192.0.2.1/32}"
