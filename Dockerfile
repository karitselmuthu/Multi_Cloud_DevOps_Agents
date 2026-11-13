FROM python:3.12-slim
ARG TF_VERSION=1.15.6
ARG TARGETARCH
# terraform is only *used* by the executor role (ROLE=executor); SHA256 is checked against HashiCorp's published sums (GPG signature not verified; add it if you need that)
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip ca-certificates && rm -rf /var/lib/apt/lists/* \
 && cd /tmp && curl -fsSLO "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_${TARGETARCH}.zip" \
 && curl -fsSLO "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_SHA256SUMS" \
 && grep "linux_${TARGETARCH}.zip" "terraform_${TF_VERSION}_SHA256SUMS" | sha256sum -c - \
 && unzip -q "terraform_${TF_VERSION}_linux_${TARGETARCH}.zip" -d /usr/local/bin terraform && rm -f /tmp/terraform_*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY devops_agent devops_agent
COPY knowledge knowledge
RUN useradd -r -m app && chown app /app
USER app
EXPOSE 8000
CMD ["uvicorn", "devops_agent.main:app", "--host", "0.0.0.0", "--port", "8000"]
