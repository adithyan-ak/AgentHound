# Pinned by tag@digest (multi-arch manifest list: linux/amd64 + linux/arm64).
FROM python:3.12-slim@sha256:c3d81d25b3154142b0b42eb1e61300024426268edeb5b5a26dd7ddf64d9daf28

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .

EXPOSE 9000

CMD ["python", "agent.py"]
