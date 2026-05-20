# Open WebUI fingerprint stub. Serves /api/version + /api/config so the
# fingerprinter matches AND captures the configured Ollama backend URL,
# which drives the EXPOSES edge emission.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.32.0
COPY app.py .
EXPOSE 3000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "3000"]
