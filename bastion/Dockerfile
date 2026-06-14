# 6v6 bastion — SSH 점프 호스트 + Bastion API + rsyslog forward (syslog 패러다임)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo iputils-ping iproute2 dnsutils \
        rsyslog \
        curl wget jq python3 python3-pip ca-certificates \
        vim less tmux htop \
        gnupg lsb-release && \
    rm -rf /var/lib/apt/lists/*

# Docker CLI (read-only docker.sock + docker ps 학생 가시화용)
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu jammy stable" \
        > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# osquery (W07 호스트 가시화)
RUN curl -L https://pkg.osquery.io/deb/pubkey.gpg | \
        gpg --dearmor -o /etc/apt/keyrings/osquery.gpg && \
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
        > /etc/apt/sources.list.d/osquery.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends osquery && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir fastapi uvicorn[standard] httpx pydantic pyyaml \
    pandas numpy scikit-learn

# 추가 분석 도구 (CCC CURRICULUM 원칙 #8 — 도구 부재 시 설치 부터)
# secuops/W13/step2 (enrichment) — geoip-bin / whois
# attack/W11 (enum) — find / getcap 등 표준
# attack/W12 (persistence 검사) — auditd / inotify-tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        geoip-bin geoip-database \
        whois \
        net-tools traceroute mtr-tiny \
        libcap2-bin \
        inotify-tools \
        auditd audispd-plugins \
        && rm -rf /var/lib/apt/lists/*

# Wazuh agent (CCC week06 의 SSH brute → 5710/5712 detection 인프라 결함 해소)
RUN curl -L https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --dearmor -o /etc/apt/keyrings/wazuh.gpg && \
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends wazuh-agent && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /var/lib/bastion && \
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# 6v6 의 minimal stub api (fallback) — LLM_BASE_URL 미설정 시 /health 만
COPY bastion/api.py /opt/bastion-api/api.py

# Full CCC bastion source — apps/bastion + packages/bastion + packages/manager_ai
# (mrgrit/ccc 의 동일 코드, 6v6 build context 에 복사). aisec 89 step 의
# /chat + /kg/* endpoint 제공. PYTHONPATH 로 import 경로 통합.
COPY bastion/src /opt/ccc-src
ENV PYTHONPATH=/opt/ccc-src

COPY bastion/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 9100
ENTRYPOINT ["/entrypoint.sh"]
