terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
  backend "s3" {} # supply with: terraform init -backend-config=backend.hcl (see backend.hcl.example)
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "image_tag" {
  type    = string
  default = "latest"
}

variable "allowed_cidr" {
  type        = string
  description = "Only this network may reach the ALB, e.g. 203.0.113.7/32"
  validation {
    condition     = var.allowed_cidr != "0.0.0.0/0"
    error_message = "Do not open the control plane to the world."
  }
}

variable "api_users" {
  type        = string
  sensitive   = true
  default     = "{}"
  description = "JSON: {\"<api key>\": {\"user\": \"alice\", \"roles\": [\"requester\"]}}. Empty = API refuses all requests."
}

variable "temporal_address" {
  type        = string
  default     = ""
  description = "host:port of Temporal (Cloud or self-hosted). Empty = no workers; the API runs in-process and can only dry-run."
}

variable "temporal_namespace" {
  type    = string
  default = "default"
}

variable "state_bucket" {
  type        = string
  default     = ""
  description = "S3 bucket for Terraform state of generated infrastructure (create it with ../aws-state). Required with temporal_address."
}

variable "execute" {
  type        = bool
  default     = false
  description = "Let the executor really run terraform. Off = executor plans/applies as dry runs."
}

variable "llm_provider" {
  type    = string
  default = "mock"
}

variable "agents_secrets" {
  type        = map(string)
  default     = {}
  description = "ENV_NAME => Secrets Manager ARN for the agents worker (e.g. ANTHROPIC_API_KEY)."
}

variable "executor_secrets" {
  type        = map(string)
  default     = {}
  description = "ENV_NAME => Secrets Manager ARN for the executor (e.g. GITHUB_TOKEN)."
}

variable "executor_policy_arns" {
  type        = list(string)
  default     = ["arn:aws:iam::aws:policy/AmazonS3FullAccess"]
  description = "What the executor may create. Least privilege by default; widen deliberately. iam:*, organizations:* and account:* are always denied."
}

locals {
  name = "devops-agent"
  tags = { project = local.name, managed_by = "terraform" }
  on   = var.temporal_address != ""
}

# ponytail: default VPC + public subnets to stay cheap (no NAT). Move to a dedicated VPC with private subnets for real prod.
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_ecr_repository" "app" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true # daily teardown must not be blocked by images
  image_scanning_configuration { scan_on_push = true }
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${local.name}"
  retention_in_days = 7
  tags              = local.tags
}

resource "aws_ecs_cluster" "this" {
  name = local.name
  tags = local.tags
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "exec" {
  name               = "${local.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "exec" {
  role       = aws_iam_role.exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_security_group" "alb" {
  name   = "${local.name}-alb"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

resource "aws_security_group" "task" {
  name   = "${local.name}-task"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = local.tags
}

# --- Postgres (RDS). Daily teardown: no final snapshot, no deletion protection. State is disposable by design. ---
resource "random_password" "db" {
  length  = 32
  special = false # keeps the connection URL free of characters that need escaping
}

resource "aws_security_group" "db" {
  name   = "${local.name}-db"
  vpc_id = data.aws_vpc.default.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.task.id]
  }
  tags = local.tags
}

resource "aws_db_subnet_group" "this" {
  name       = local.name
  subnet_ids = data.aws_subnets.default.ids
  tags       = local.tags
}

resource "aws_db_instance" "this" {
  identifier              = local.name
  engine                  = "postgres"
  engine_version          = "16"
  instance_class          = "db.t4g.micro"
  allocated_storage       = 20
  storage_type            = "gp3"
  storage_encrypted       = true
  db_name                 = "agents"
  username                = "agents"
  password                = random_password.db.result
  db_subnet_group_name    = aws_db_subnet_group.this.name
  vpc_security_group_ids  = [aws_security_group.db.id]
  publicly_accessible     = false
  skip_final_snapshot     = true
  deletion_protection     = false
  backup_retention_period = 0
  tags                    = local.tags
}

resource "aws_secretsmanager_secret" "db_url" {
  name                    = "${local.name}/database-url"
  recovery_window_in_days = 0 # delete immediately so the daily rebuild can reuse the name
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "db_url" {
  secret_id     = aws_secretsmanager_secret.db_url.id
  secret_string = "postgresql://agents:${random_password.db.result}@${aws_db_instance.this.address}:5432/agents?sslmode=require"
}

resource "random_password" "approval" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "approval" {
  name                    = "${local.name}/approval-secret"
  recovery_window_in_days = 0
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "approval" {
  secret_id     = aws_secretsmanager_secret.approval.id
  secret_string = random_password.approval.result
}

resource "aws_secretsmanager_secret" "api_users" {
  name                    = "${local.name}/api-users"
  recovery_window_in_days = 0
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "api_users" {
  secret_id     = aws_secretsmanager_secret.api_users.id
  secret_string = var.api_users
}

# The ECS agent (not the container) reads these when starting a task; each task definition lists only the secrets
# that role needs, so the agents worker never receives APPROVAL_SECRET and the executor never receives LLM keys.
resource "aws_iam_role_policy" "exec_secret" {
  role = aws_iam_role.exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "secretsmanager:GetSecretValue"
      Resource = concat(
        [aws_secretsmanager_secret.db_url.arn, aws_secretsmanager_secret.approval.arn, aws_secretsmanager_secret.api_users.arn],
        values(var.agents_secrets), values(var.executor_secrets),
      )
    }]
  })
}

resource "aws_lb" "this" {
  name               = local.name
  load_balancer_type = "application"
  subnets            = data.aws_subnets.default.ids
  security_groups    = [aws_security_group.alb.id]
  tags               = local.tags
}

resource "aws_lb_target_group" "app" {
  name        = local.name
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = data.aws_vpc.default.id
  health_check { path = "/healthz" }
  tags = local.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_ecs_task_definition" "app" {
  family                   = local.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.exec.arn
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  container_definitions = jsonencode([{
    name         = "app"
    image        = "${aws_ecr_repository.app.repository_url}:${var.image_tag}"
    essential    = true
    portMappings = [{ containerPort = 8000 }]
    environment = local.on ? [
      { name = "TEMPORAL_ADDRESS", value = var.temporal_address },
      { name = "TEMPORAL_NAMESPACE", value = var.temporal_namespace },
    ] : []
    secrets = [
      { name = "DATABASE_URL", valueFrom = aws_secretsmanager_secret.db_url.arn },
      { name = "API_USERS", valueFrom = aws_secretsmanager_secret.api_users.arn },
      { name = "APPROVAL_SECRET", valueFrom = aws_secretsmanager_secret.approval.arn },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options   = { awslogs-group = aws_cloudwatch_log_group.app.name, awslogs-region = var.region, awslogs-stream-prefix = "app" }
    }
  }])
  tags = local.tags
}

resource "aws_ecs_service" "app" {
  name            = local.name
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = true # needed to pull from ECR without NAT
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = 8000
  }
  depends_on = [aws_lb_listener.http, aws_secretsmanager_secret_version.db_url, aws_secretsmanager_secret_version.api_users, aws_secretsmanager_secret_version.approval, aws_iam_role_policy.exec_secret]
  tags       = local.tags
}

# --- Workers (only with temporal_address). Same image, different command, role and secrets. ---
resource "aws_iam_role" "executor" {
  count              = local.on ? 1 : 0
  name               = "${local.name}-executor"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = local.tags
  lifecycle {
    precondition {
      condition     = var.state_bucket != ""
      error_message = "state_bucket is required when temporal_address is set (create it with infrastructure/terraform/aws-state)."
    }
  }
}

resource "aws_iam_role_policy_attachment" "executor" {
  for_each   = local.on ? toset(var.executor_policy_arns) : toset([])
  role       = aws_iam_role.executor[0].name
  policy_arn = each.value
}

data "aws_iam_policy_document" "executor_guard" {
  statement {
    effect    = "Deny"
    actions   = ["iam:*", "organizations:*", "account:*", "sts:AssumeRole"]
    resources = ["*"]
  }
  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["arn:aws:s3:::${var.state_bucket}/requests/*"]
  }
  statement {
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.state_bucket}"]
  }
}

resource "aws_iam_role_policy" "executor_guard" {
  count  = local.on ? 1 : 0
  role   = aws_iam_role.executor[0].id
  policy = data.aws_iam_policy_document.executor_guard.json
}

locals {
  db_secret = { DATABASE_URL = aws_secretsmanager_secret.db_url.arn }
  workers = local.on ? {
    agents = {
      role    = "agents"
      task    = null # no cloud credentials at all
      env     = { LLM_PROVIDER = var.llm_provider, TEMPORAL_ADDRESS = var.temporal_address, TEMPORAL_NAMESPACE = var.temporal_namespace }
      secrets = merge(local.db_secret, var.agents_secrets)
    }
    executor = {
      role = "executor"
      task = one(aws_iam_role.executor[*].arn)
      env = {
        TEMPORAL_ADDRESS = var.temporal_address, TEMPORAL_NAMESPACE = var.temporal_namespace, EXECUTE = var.execute ? "1" : "0",
        TF_STATE_BUCKET  = var.state_bucket, AWS_REGION = var.region,
      }
      secrets = merge(local.db_secret, { APPROVAL_SECRET = aws_secretsmanager_secret.approval.arn }, var.executor_secrets)
    }
  } : {}
}

resource "aws_ecs_task_definition" "worker" {
  for_each                 = local.workers
  family                   = "${local.name}-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.exec.arn
  task_role_arn            = each.value.task
  runtime_platform {
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }
  container_definitions = jsonencode([{
    name        = "app"
    image       = "${aws_ecr_repository.app.repository_url}:${var.image_tag}"
    essential   = true
    command     = ["python", "-m", "devops_agent.worker", each.value.role]
    environment = [for k, v in each.value.env : { name = k, value = v }]
    secrets     = [for k, v in each.value.secrets : { name = k, valueFrom = v }]
    logConfiguration = {
      logDriver = "awslogs"
      options   = { awslogs-group = aws_cloudwatch_log_group.app.name, awslogs-region = var.region, awslogs-stream-prefix = each.key }
    }
  }])
  tags = local.tags
}

resource "aws_ecs_service" "worker" {
  for_each        = local.workers
  name            = "${local.name}-${each.key}"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.worker[each.key].arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.task.id]
    assign_public_ip = true # outbound only: Temporal, provider downloads, ECR
  }
  depends_on = [aws_secretsmanager_secret_version.approval, aws_iam_role_policy.exec_secret]
  tags       = local.tags
}

output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}
