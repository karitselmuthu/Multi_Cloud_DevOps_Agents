# Multi-Cloud DevOps Agents (V3.0)

Developers request infrastructure in plain language; a pipeline of agents plans it, writes Terraform, security-scans it,
and a human approves before anything executes. Agents never touch cloud APIs directly: only the policy-gated MCP layer can.

| Architecture layer | Where |
|---|---|
| Frontend / Developer Portal | `devops_agent/static/index.html` (served at `/`) |
| Enterprise Control Plane | `main.py` (FastAPI: per-user keys, roles, separation of duties), `db.py` (Postgres / SQLite, versioned migrations), `workflows.py` + `activities.py` + `worker.py` (Temporal) |
| Agent Orchestration | `agents.py` (Planning → Infra → Code → Security → DevOps → Monitoring, then a plan step) |
| Knowledge / RAG | `rag.py` over `knowledge/*.md` |
| Multi-Model Gateway | `llm.py` (`LLM_PROVIDER=mock\|anthropic\|openai`) |
| Secure MCP & Policy Gateway | `mcp.py` + `policy.py` + `approval.py`: allow-list, approval tokens, plan-file apply, audit |
| AWS target | `infrastructure/terraform/aws` (ECR, ECS Fargate, ALB, RDS, Secrets Manager, optional workers) and `aws-state` (state bucket) |
| Observability | `obs.py`: JSON logs → CloudWatch Logs Insights, `/metrics`, `/audit` |

## How a change is controlled
1. **Identity.** `API_USERS` maps API keys to a user and roles (`requester`, `approver`). Requesters see only their own requests.
   An approver can never approve a request they created (enforced server side; the attempt is audited).
2. **Plan binding.** After the agents produce and scan the artifact, the executor plans it (`terraform plan -out`) and the control plane stores
   `plan_hash = sha256(artifact + plan file)`. The approver sees the plan summary and hash.
3. **Approval token.** Approving mints an HMAC-signed token bound to the request id and plan hash (10 min, single use).
   The gateway refuses every mutating call without a valid token, recomputes the hash from what it is about to run, and consumes the token atomically.
   If the plan changed after approval the request returns to *awaiting approval* and nothing runs.
4. **Plan-file apply.** Terraform applies exactly the saved plan (`terraform apply tfplan`, never `-auto-approve` on a fresh plan), against
   per-request remote state in S3 with locking (`requests/<id>/terraform.tfstate`). Plans that destroy more than `TF_MAX_DESTROY` (default 0) resources are refused.
5. **Policy.** Generated Terraform must use only allow-listed block and resource types (`policy.py`, extend with `TF_ALLOWED_RESOURCES`). Providers, modules, backends,
   `data "external"`, provisioners and local file reads are rejected, both before approval and again at the gateway.
6. **Separated execution.** Agents (LLM-facing) run in the `agents` worker with no cloud credentials and no approval secret.
   Only the `executor` worker (`ROLE=executor`, own IAM role with `iam:*` denied, its own secrets, a scrubbed subprocess environment) executes for real, and only with `EXECUTE=1`.
   Without Temporal the API runs in-process and **can only dry-run**.

## Run locally
```
python -m venv .venv && .venv/bin/pip install -r requirements.txt
export APPROVAL_SECRET=$(openssl rand -hex 24)
export API_USERS='{"k-alice":{"user":"alice","roles":["requester"]},"k-bob":{"user":"bob","roles":["approver"]}}'
.venv/bin/uvicorn devops_agent.main:app --reload   # http://localhost:8000 (paste a key into the page)
python -m unittest discover -s . -t . -p "test_*.py"
```
Without `API_USERS` the API answers 503 (it never runs open). Full stack with Postgres, Temporal and both workers: `docker compose up --build`
(dev keys `dev-alice` / `dev-bob` / `dev-carol`, see the compose file). Tests: `DATABASE_URL=...` runs the suite on Postgres;
`temporal server start-dev` + `TEMPORAL_ADDRESS=localhost:7233` enables the Temporal tests. The real-Terraform tests run automatically when `terraform` is installed (local backend, builtin provider, no cloud).
Env: `DATABASE_URL`, `TEMPORAL_ADDRESS`, `API_USERS`, `APPROVAL_SECRET` (api + executor only), `LLM_PROVIDER` + `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` (agents only),
`EXECUTE=1` + `TF_STATE_BUCKET` (executor only), `GITHUB_REPO`/`GITHUB_TOKEN` (executor), `K8S_ALLOWED_NAMESPACES`, `TF_ALLOWED_RESOURCES`, `TF_MAX_DESTROY`.
Request kinds: `terraform`, `kubernetes`, `github` (opens a PR with the generated Terraform in `GITHUB_REPO`).

## Daily build / delete on AWS
```
# once: the state bucket (never destroyed by down.sh)
terraform -chdir=infrastructure/terraform/aws-state init && terraform -chdir=infrastructure/terraform/aws-state apply -var bucket_name=<unique-name>
cp infrastructure/terraform/aws/backend.hcl.example infrastructure/terraform/aws/backend.hcl   # edit bucket
export ALLOWED_CIDR=<your-ip>/32 API_USERS='{"<key>":{"user":"alice","roles":["requester"]},...}'
scripts/up.sh     # build image + deploy, prints UI URL
scripts/down.sh   # destroys everything this stack created
```
Real execution on AWS needs Temporal: set `TF_VAR_temporal_address` (Temporal Cloud or self-hosted), `TF_VAR_state_bucket`, and `TF_VAR_execute=true`.
That adds the `agents` and `executor` ECS services. Resources the executor creates carry the request id as a tag and live in per-request state, but are **not** removed by
`down.sh` (it only destroys this platform stack): destroy them deliberately first.
Also available as manual GitHub Actions `deploy` (repo variables and the `API_USERS` secret are listed in the workflow header).

## Observability (cheap by design)
Every LLM call, MCP call/denial and HTTP request is one JSON line on stdout; ECS ships it to the CloudWatch log group
(7-day retention), so cost is just log ingestion. `/metrics` has request-status gauges plus `llm_*_total` (calls, tokens, latency),
`mcp_*_total` and `http_requests_total`. Useful Logs Insights queries on `/ecs/devops-agent`:
```
filter event = "llm.call" | stats count(), sum(input_tokens), sum(output_tokens), avg(ms) by stage
filter event = "mcp.denied" | fields @timestamp, tool, reason | sort @timestamp desc
filter event = "http" and status >= 500
```
Not included: traces, Langfuse/RAGAS evals, Grafana. Add Grafana Cloud free tier scraping `/metrics` when you want dashboards.

## Not built yet (deliberate simplifications)
OIDC/JWT login (static per-user keys today), multi-approver rules for prod, audit hash-chain / S3 Object Lock, Backstage/Next.js (single HTML page),
OPA/Conftest on the real plan JSON (regex + allow-list in `policy.py`), Azure DevOps MCP tool, Azure execution target, kubectl execution (policy and tokens are in place, no cluster is provisioned),
RAG ingestion pipeline with access control, LLM tracing with request ids, LangGraph, Gemini/Llama providers, OpenTelemetry/Langfuse/RAGAS.
`docker-compose.yml`, the `Dockerfile` build and the AWS Terraform (RDS, secrets, workers, executor role) have been validated or reviewed but **not run**: no Docker daemon or AWS account was used while building.
