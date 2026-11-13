FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY devops_agent devops_agent
COPY knowledge knowledge
RUN useradd -r app && chown app /app
USER app
EXPOSE 8000
CMD ["uvicorn", "devops_agent.main:app", "--host", "0.0.0.0", "--port", "8000"]
