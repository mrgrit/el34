#!/bin/sh
# cont-init: bastion audit decoder + rules 를 wazuh manager 에 강제 적용
# (wazuh-manager-etc volume 이 image 의 /var/ossec/etc 를 가릴 수 있어 매 시작 시 copy)

set -e

# /tmp 에 image build 시 보존한 원본 가져오기
IMG_DECODER=/opt/bastion-audit-decoder.xml
IMG_RULES=/opt/bastion-audit-rules.xml

# wazuh etc volume 의 실제 경로
DST_DECODER=/var/ossec/etc/decoders/bastion-audit-decoder.xml
DST_RULES=/var/ossec/etc/rules/bastion-audit-rules.xml

if [ -f "$IMG_DECODER" ] && [ -f "$IMG_RULES" ]; then
    cp -f "$IMG_DECODER" "$DST_DECODER"
    cp -f "$IMG_RULES" "$DST_RULES"
    chown root:wazuh "$DST_DECODER" "$DST_RULES" 2>/dev/null || true
    chmod 660 "$DST_DECODER" "$DST_RULES" 2>/dev/null || true
    echo "[siem] ★ bastion audit decoder + rules applied"
fi

# syslog remote (514/udp from 10.20.0.0/16) 강제 설정 — *정확히 1개* 보장(멱등).
# 주의: /var/ossec/etc 는 named volume 이라 과거(마커 없던) 스크립트가 넣은 514 블록이
# 남아 누적될 수 있다 → syslog 514 remote 가 2개면 둘째 bind 가 CRITICAL(1206 Address in
# use)로 실패한다. 마커가 아닌 *포트 514 syslog 블록 전체*를 먼저 제거하고 하나만 다시 넣는다.
OSSEC_CONF=/var/ossec/etc/ossec.conf
if [ -f "$OSSEC_CONF" ] && command -v python3 >/dev/null 2>&1; then
    python3 - "$OSSEC_CONF" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
# 기존 bastion-audit 마커 코멘트 + 모든 syslog/514 remote 블록 제거
s = re.sub(r'[ \t]*<!-- bastion-audit-syslog:.*?-->\n', '', s, flags=re.S)
s = re.sub(r'[ \t]*<remote>\s*<connection>\s*syslog\s*</connection>\s*<port>\s*514\s*</port>.*?</remote>\s*\n',
           '', s, flags=re.S)
block = ("  <!-- bastion-audit-syslog: bastion 의 rsyslog 514/udp 수신 -->\n"
         "  <remote>\n"
         "    <connection>syslog</connection>\n"
         "    <port>514</port>\n"
         "    <protocol>udp</protocol>\n"
         "    <allowed-ips>10.20.0.0/16</allowed-ips>\n"
         "  </remote>\n")
# </global> 바로 뒤에 하나만 삽입
s, n = re.subn(r'(</global>\n)', r'\1' + block, s, count=1)
if n == 0:   # </global> 없으면 무리하게 넣지 않음
    sys.exit(0)
open(p, "w").write(s)
PY
    echo "[siem] ★ ossec.conf — syslog remote :514/udp 정확히 1개로 정규화(10.20.0.0/16)"
fi

# (API rate limit 은 95-api-rate-limit 으로 분리 — sed fail 영향 차단)
