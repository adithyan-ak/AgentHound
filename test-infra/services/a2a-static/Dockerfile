# --- Stage 1: reproducibly sign the agent card with openssl + JWS tooling ---
# Pinned by tag@digest (multi-arch manifest list: linux/amd64 + linux/arm64).
FROM python:3.12-slim@sha256:c3d81d25b3154142b0b42eb1e61300024426268edeb5b5a26dd7ddf64d9daf28 AS signer

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY keygen.sh sign_card.py ./
RUN chmod +x keygen.sh && ./keygen.sh /out

# --- Stage 2: lean nginx runtime serving the signed .well-known documents ---
FROM nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=signer /out/agent-card.json /out/jwks.json /usr/share/nginx/html/.well-known/

EXPOSE 80
