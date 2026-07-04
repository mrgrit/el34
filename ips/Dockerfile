# el34 ips — inline IPS: pipe <-> dmz forwarding + Suricata sniff.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
# 시각: 전체 el34 컨테이너 KST(Asia/Seoul) 통일 — Suricata eve.json 타임스탬프 KST.
ENV TZ=Asia/Seoul
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo iputils-ping iproute2 \
        suricata suricata-update \
        nftables tzdata \
        curl wget gnupg lsb-release \
        jq vim less tcpdump \
        ca-certificates && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    rm -rf /var/lib/apt/lists/*

# osquery (W07)
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -L https://pkg.osquery.io/deb/pubkey.gpg | \
        gpg --dearmor -o /etc/apt/keyrings/osquery.gpg && \
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
        > /etc/apt/sources.list.d/osquery.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends osquery && \
    rm -rf /var/lib/apt/lists/*

# Wazuh agent — Suricata eve.json shipped via agent
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="10.20.32.100" apt-get install -y --no-install-recommends wazuh-agent=4.10.1-1 && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /var/log/suricata && \
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY ips/suricata-local.rules /etc/suricata/rules/local.rules
# secuops-easy 교육용 GUI (IPS 콘솔) — 이미지에 내장(vendored, 네트워크 불필요).
# entrypoint 가 :8080 으로 자동 기동 → down/up·재부팅 후 ips-gui.el34.lab 즉시 접속 가능.
COPY secuops-easy-deploy/gui/suricata_edu_gui/ /opt/suricata_edu_gui/
COPY ips/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
