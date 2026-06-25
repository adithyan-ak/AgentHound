FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.32.0
COPY app.py .

EXPOSE 11434
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "11434"]
