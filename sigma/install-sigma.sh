#!/bin/bash
# el34 Sigma → Wazuh 설치: sigma/rules/*.yml → Wazuh local rules 로 변환·적재.
# 배포 후 1회 실행(멱등). siem 컨테이너 = el34-siem.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
SIEM_CONTAINER="${SIEM_CONTAINER:-el34-siem}"
OUT="$HERE/sigma_rules.xml"

# 1) PyYAML 보장 (호스트에서 변환)
python3 -c "import yaml" 2>/dev/null || {
    echo "[sigma] PyYAML 설치"; sudo apt-get install -y python3-yaml >/dev/null 2>&1 || pip install pyyaml -q
}

# 2) 변환
echo "[sigma] 변환: sigma/rules → $OUT"
python3 "$HERE/sigma2wazuh.py" "$HERE/rules" > "$OUT"

# 3) siem 컨테이너에 적재 (custom local rules — 다른 룰 불변, 멱등)
echo "[sigma] $SIEM_CONTAINER 의 /var/ossec/etc/rules/sigma_rules.xml 로 복사"
docker cp "$OUT" "$SIEM_CONTAINER:/var/ossec/etc/rules/sigma_rules.xml"
docker exec "$SIEM_CONTAINER" chown wazuh:wazuh /var/ossec/etc/rules/sigma_rules.xml 2>/dev/null || true

# 4) 룰 문법 검증 + manager 재시작 (룰 reload)
echo "[sigma] wazuh-logtest 룰 로드 점검 + manager restart"
docker exec "$SIEM_CONTAINER" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || \
    docker restart "$SIEM_CONTAINER" >/dev/null 2>&1 || true

echo "[sigma] 완료 — id 200001+ (group=sigma). Discover 에서 rule.groups:sigma 로 확인."
