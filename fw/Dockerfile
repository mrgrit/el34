# el34 fw — edge router: ext <-> pipe.
# nftables (firewall + L3 포트분기 DNAT) + ip_forward.  (HAProxy 제거 — 출처 IP 보존)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo iputils-ping iproute2 \
        nftables ipset \
        iptables \
        curl wget gnupg lsb-release \
        jq vim less tcpdump conntrack \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# osquery (W07 호스트 가시화)
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -L https://pkg.osquery.io/deb/pubkey.gpg | \
        gpg --dearmor -o /etc/apt/keyrings/osquery.gpg && \
    echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/osquery.gpg] https://pkg.osquery.io/deb deb main" \
        > /etc/apt/sources.list.d/osquery.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends osquery && \
    rm -rf /var/lib/apt/lists/*

# Wazuh agent — fw nftables/syslog events to manager
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="10.20.32.100" apt-get install -y --no-install-recommends wazuh-agent=4.10.1-1 && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd && \
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY fw/nftables.conf /etc/nftables.conf
# secuops-easy 교육용 GUI (방화벽 콘솔) — 이미지에 내장(vendored, 네트워크 불필요).
# entrypoint 가 :8080 으로 자동 기동 → down/up·재부팅 후 fw-gui.6v6.lab 즉시 접속 가능.
COPY secuops-easy-deploy/gui/nft_edu_gui/ /opt/nft_edu_gui/
COPY fw/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80 443 9100
ENTRYPOINT ["/entrypoint.sh"]
