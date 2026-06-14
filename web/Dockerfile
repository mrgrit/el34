# 6v6 web — Apache 2.4 + ModSecurity v2 + OWASP CRS + 랜딩 + 7 vuln reverse proxy + Wazuh agent
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo iputils-ping iproute2 \
        apache2 libapache2-mod-security2 modsecurity-crs \
        ssl-cert openssl ca-certificates gnupg lsb-release \
        curl wget jq vim less && \
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

# Wazuh agent (web → Wazuh manager 로 Apache + ModSec 로그 전송)
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="10.20.32.100" apt-get install -y --no-install-recommends wazuh-agent=4.10.1-1 && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd /var/www/landing /etc/apache2/ssl && \
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Apache 모듈
RUN a2enmod proxy proxy_http proxy_wstunnel headers ssl rewrite security2 && \
    a2dissite 000-default || true

# ModSecurity 활성화 + audit log JSON 형식 (Wazuh decoder + jq 처리 친화)
# Note: sed substitution 은 매치 없으면 silent skip 이라, JSON 형식 미보장. 새 파일로 다시 작성.
RUN if [ ! -f /etc/modsecurity/modsecurity.conf ]; then \
        cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf || true; \
    fi && \
    # 학습 환경 default = **SecRuleEngine On** (전역 차단). per-vhost override 로
    # juice.6v6.lab 만 DetectionOnly (010-juice.conf 에서 `SecRuleEngine DetectionOnly`).
    # 다른 vhost (dvwa/neobank/...) 는 On 유지 → secuops W01-S7 Red 차단 검증 통과.
    sed -i 's|^SecRuleEngine .*|SecRuleEngine On|' /etc/modsecurity/modsecurity.conf && \
    sed -i 's|^SecAuditEngine .*|SecAuditEngine RelevantOnly|' /etc/modsecurity/modsecurity.conf && \
    sed -i 's|^SecAuditLog .*|SecAuditLog /var/log/apache2/modsec_audit.log|' /etc/modsecurity/modsecurity.conf && \
    # SecAuditLogFormat / SecAuditLogType / SecAuditLogParts 명시 (기존 라인 제거 + 추가)
    sed -i '/^SecAuditLogFormat/d;/^SecAuditLogType/d;/^SecAuditLogParts/d' /etc/modsecurity/modsecurity.conf && \
    printf '\n# 6v6 — JSON one-line per transaction (jq + Wazuh decoder)\nSecAuditLogFormat JSON\nSecAuditLogType Serial\nSecAuditLogParts ABCFHZ\n' >> /etc/modsecurity/modsecurity.conf

# 랜딩 페이지 + vhost
COPY web/landing/ /var/www/landing/
COPY web/vhosts/ /etc/apache2/sites-available/

# Ubuntu 의 default vhost 제거 (Apache2 Default Page 가 뜨는 원인)
RUN rm -f /etc/apache2/sites-enabled/000-default.conf \
          /etc/apache2/sites-enabled/default-ssl.conf \
          /etc/apache2/sites-available/000-default.conf \
          /etc/apache2/sites-available/default-ssl.conf

# 우리 vhost 만 활성화 (sites-available 의 *.conf 전부)
RUN cd /etc/apache2/sites-available && \
    for f in *.conf; do a2ensite "$f"; done

# Wazuh agent ossec.conf — Apache + ModSec localfile 추가
COPY web/wazuh-agent.conf.append /tmp/wazuh-agent.conf.append

# secuops-easy 교육용 GUI (WAF 콘솔) — 이미지에 내장(vendored, 네트워크 불필요).
# entrypoint 가 :8080 으로 자동 기동 → down/up·재부팅 후 waf-gui.6v6.lab 즉시 접속 가능.
COPY secuops-easy-deploy/gui/modsec_edu_gui/ /opt/modsec_edu_gui/

COPY web/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80 443
ENTRYPOINT ["/entrypoint.sh"]
