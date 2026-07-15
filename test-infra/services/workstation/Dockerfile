FROM debian:stable-slim

ENV HOME=/root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        coreutils \
        curl \
        jq \
        openssl \
    && rm -rf /var/lib/apt/lists/*

COPY bin/agenthound /usr/local/bin/agenthound
COPY home/ /opt/agenthound-workstation/home/
COPY entrypoint.sh /usr/local/bin/workstation-entrypoint

RUN chmod 0755 /usr/local/bin/agenthound /usr/local/bin/workstation-entrypoint \
    && cp -a /opt/agenthound-workstation/home/. /root/ \
    && mkdir -p /root/.agenthound \
    && touch \
        /root/.agenthound/loot-acknowledged \
        /root/.agenthound/poison-acknowledged \
        /root/.agenthound/extract-acknowledged \
        /root/.agenthound/campaign-acknowledged

WORKDIR /root/projects/example

ENTRYPOINT ["/usr/local/bin/workstation-entrypoint"]
CMD ["sleep", "infinity"]
