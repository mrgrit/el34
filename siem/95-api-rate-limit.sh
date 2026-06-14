#!/bin/sh
# cont-init: Wazuh API rate limit 상향 (default 300/min → 5000/min).
# 이유: dashboard 정기 health check + bastion lifecycle alert 합산 시
#       default 300 초과 → wazuh-apid 가 429 응답 →
#       dashboard 가 "No API available to connect" 표시.

API_CONF=/var/ossec/api/configuration/api.yaml

if [ -f "$API_CONF" ] && ! grep -q "max_request_per_minute: 5000" "$API_CONF"; then
    printf '\naccess:\n  max_request_per_minute: 5000\n  max_login_attempts: 50\n  block_time: 30\n' >> "$API_CONF"
    echo "[siem] ★ api.yaml updated — access.max_request_per_minute=5000"
fi

exit 0
