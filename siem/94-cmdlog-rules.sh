#!/bin/sh
# cont-init: 6v6 명령 로깅 decoder + rules 를 wazuh manager 에 강제 적용.
# (wazuh-manager-etc volume 이 image 의 /var/ossec/etc 를 가릴 수 있어 매 시작 copy —
#  96-bastion-audit-rules / 95-haproxy-denat 와 동일 패턴.)
set -e
IMG_DEC=/opt/cmdlog-decoder.xml
IMG_RULES=/opt/cmdlog-rules.xml
DST_DEC=/var/ossec/etc/decoders/cmdlog-decoder.xml
DST_RULES=/var/ossec/etc/rules/cmdlog-rules.xml
if [ -f "$IMG_DEC" ] && [ -f "$IMG_RULES" ]; then
  cp -f "$IMG_DEC" "$DST_DEC"
  cp -f "$IMG_RULES" "$DST_RULES"
  chown root:wazuh "$DST_DEC" "$DST_RULES" 2>/dev/null || true
  chmod 660 "$DST_DEC" "$DST_RULES" 2>/dev/null || true
  echo "[siem] ★ 6v6 cmdlog decoder + rules applied"
fi
# 명령 로그(attacker/bastion)는 기존 syslog remote :514 (96-bastion-audit-rules 가 활성)로 수신.
# web/fw/ips 는 Wazuh agent localfile(/var/log/6v6-cmd.log)로 수신.
