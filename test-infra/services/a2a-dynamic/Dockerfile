# Pinned by tag@digest (multi-arch manifest list: linux/amd64 + linux/arm64).
FROM python:3.12-slim@sha256:c3d81d25b3154142b0b42eb1e61300024426268edeb5b5a26dd7ddf64d9daf28

WORKDIR /app

COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY agent.py .

EXPOSE 9000

CMD ["python", "agent.py"]
