FROM python:3.12-slim@sha256:c3d81d25b3154142b0b42eb1e61300024426268edeb5b5a26dd7ddf64d9daf28

WORKDIR /verify
COPY requirements.lock .
RUN python -m pip install --no-cache-dir --require-hashes --requirement requirements.lock
COPY derive_truth.py .

ENTRYPOINT ["python", "/verify/derive_truth.py"]
