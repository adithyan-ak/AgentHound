# MCP discovery stub. Answers JSON-RPC initialize with the canonical
# server-info envelope so `agenthound discover` finds it.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.32.0
COPY app.py .
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
