# Multi-Cloud DevOps Agents (V3.0)

Developers request infrastructure in plain language; a pipeline of agents plans it, writes Terraform, security-scans it,
and a human approves before anything executes. Agents never touch cloud APIs directly: only the policy-gated MCP layer can.

| Architecture layer | Where |
|---|---|
| Frontend / Developer Portal | `devops_agent/static/index.html` (served at `/`) |
| Enterprise Control Plane | `devops_agent/main.py` (FastAPI), `db.py` (Postgres via `DATABASE_URL`, SQLite fallback), approval workflow; durable lifecycle in `workflows.py` / `activities.py` / `worker.py` (Temporal, when `TEMPORAL_ADDRESS` is set) |
| Agent Orchestration | `devops_agent/agents.py` (Planning → Infra → Code → Security → DevOps → Monitoring) |
| Knowledge / RAG | `devops_agent/rag.py` over `knowledge/*.md` |
| Multi-Model Gateway | `devops_agent/llm.py` (`LLM_PROVIDER=mock\|anthropic\|openai`) |
| Secure MCP & Policy Gateway | `devops_agent/mcp.py` (allow-list, approval rule, audit, dry-run by default; `terraform.*`, `kubectl.apply` with namespace/kind policy, `github.create_pr` restricted to `GITHUB_REPO`, `requests/` paths and `agent/*` branches) |
| AWS target | `infrastructure/terraform/aws` (ECR, ECS Fargate, ALB, RDS Postgres + Secrets Manager) |
| Observability | `devops_agent/obs.py`: JSON logs -> CloudWatch Logs Insights, Prometheus-style `/metrics`, `/audit` (see below) |

## Run locally
```
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn devops_agent.main:app --reload   # http://localhost:8000
python -m unittest discover -s . -t . -p "test_*.py"
```
Full local stack (Postgres + Temporal + worker): `docker compose up --build`.
Temporal test: `temporal server start-dev` then `TEMPORAL_ADDRESS=localhost:7233 python -m unittest tests.test_temporal`.
Request kinds: `terraform`, `kubernetes`, or `github` (opens a PR with the generated Terraform in `GITHUB_REPO` using `GITHUB_TOKEN`, only with `EXECUTE=1`) (manifests are policy-checked; only namespaces in `K8S_ALLOWED_NAMESPACES`, default `apps`).
Env: `DATABASE_URL`, `TEMPORAL_ADDRESS`, `API_KEY` (require `X-API-Key`), `LLM_PROVIDER` + `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`, `EXECUTE=1` (really run terraform/kubectl; default is dry-run).

## Daily build / delete on AWS
```
cp infrastructure/terraform/aws/backend.hcl.example infrastructure/terraform/aws/backend.hcl  # edit
ALLOWED_CIDR=<your-ip>/32 scripts/up.sh     # build image + deploy, prints UI URL
ALLOWED_CIDR=<your-ip>/32 scripts/down.sh   # destroys everything this stack created
```
Also available as manual GitHub Actions `deploy` (needs repo variables, see the workflow header).

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
Backstage/Next.js (single HTML page), OPA (Python rules), Azure DevOps MCP tool, ECS wiring for `GITHUB_REPO`/`GITHUB_TOKEN`/LLM keys (set them as task env/secrets yourself),, Gemini/Llama providers,
OpenTelemetry traces/Langfuse/RAGAS, Azure target, LangGraph (plain sequential runner). Temporal on AWS is not provisioned
(the ECS app falls back to in-process runs); point `TEMPORAL_ADDRESS` at Temporal Cloud or a self-hosted cluster to enable it.
`docker-compose.yml` has not been run (no Docker daemon was available while building).
