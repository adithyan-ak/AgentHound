# Jupyter Server fingerprint stub. Serves /api/status with the four
# canonical Jupyter status fields. The v0.3 fingerprinter matches on
# `started` (ISO timestamp) + `last_activity` body presence.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.32.0
COPY app.py .
EXPOSE 8888
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8888"]
