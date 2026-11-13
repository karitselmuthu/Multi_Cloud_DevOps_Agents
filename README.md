# Multi-Cloud DevOps Agents (V3.0)

Developers request infrastructure in plain language; a pipeline of agents plans it, writes Terraform, security-scans it,
and a human approves before anything executes. Agents never touch cloud APIs directly: only the policy-gated MCP layer can.

| Architecture layer | Where |
|---|---|
| Frontend / Developer Portal | `devops_agent/static/index.html` (served at `/`) |
| Enterprise Control Plane | `devops_agent/main.py` (FastAPI), `db.py` (SQLite requests + audit), approval workflow |
| Agent Orchestration | `devops_agent/agents.py` (Planning → Infra → Code → Security → DevOps → Monitoring) |
| Knowledge / RAG | `devops_agent/rag.py` over `knowledge/*.md` |
| Multi-Model Gateway | `devops_agent/llm.py` (`LLM_PROVIDER=mock\|anthropic\|openai`) |
| Secure MCP & Policy Gateway | `devops_agent/mcp.py` (allow-list, approval rule, audit, dry-run by default) |
| AWS target | `infrastructure/terraform/aws` (ECR, ECS Fargate, ALB) |
| Observability | `/metrics`, `/audit` |

## Run locally
```
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn devops_agent.main:app --reload   # http://localhost:8000
python -m unittest discover -s . -t . -p "test_*.py"
```
Env: `API_KEY` (require `X-API-Key`), `LLM_PROVIDER` + `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`, `EXECUTE=1` (really run terraform/kubectl; default is dry-run).

## Daily build / delete on AWS
```
cp infrastructure/terraform/aws/backend.hcl.example infrastructure/terraform/aws/backend.hcl  # edit
ALLOWED_CIDR=<your-ip>/32 scripts/up.sh     # build image + deploy, prints UI URL
ALLOWED_CIDR=<your-ip>/32 scripts/down.sh   # destroys everything this stack created
```
Also available as manual GitHub Actions `deploy` (needs repo variables, see the workflow header).

## Not built yet (deliberate simplifications)
Temporal/LangGraph (plain sequential runner), Postgres (SQLite), Backstage/Next.js (single HTML page), OPA (Python rules),
GitHub/Azure DevOps/Jira MCP tools, Gemini/Llama providers, OpenTelemetry/Langfuse/RAGAS, Azure target, Kubernetes manifests.
