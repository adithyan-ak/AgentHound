# vLLM fingerprint stub. Real vLLM is multi-GiB CUDA; this stub serves
# /v1/models with the canonical OpenAI-list shape so the fingerprinter
# matches without dragging in a GPU image.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.32.0
COPY app.py .
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
