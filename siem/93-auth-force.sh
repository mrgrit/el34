#!/bin/bash
# 93-auth-force — Wazuh manager authd 가 동일 이름 에이전트 재등록을 *즉시* 교체하도록 force 설정.
#
# el34 는 down/up(볼륨 유지) 재배포 시 에이전트들이 같은 이름(web/ips/fw/...)으로 다시 enroll
# 한다. wazuh-authd 의 기본 force 임계(disconnected_time/after_registration_time ≈ 1h)에 걸려
#   "Duplicate name '<x>', rejecting enrollment. Agent ... not disconnected long enough"
# 로 거부 → 에이전트가 영영 연결 못 함. lab 에서는 최신 등록을 우선해야 하므로 임계를 0 으로
# 낮춰 즉시 교체를 허용한다. /var/ossec/etc 는 named volume 이라 cont-init 에서 매 기동 in-place
# 패치(멱등). 서비스(authd) 기동 전에 실행되어야 하므로 cont-init.d 의 2-manager 뒤·94+ 앞에 둔다.
set -e
CONF=/var/ossec/etc/ossec.conf
[ -f "$CONF" ] || exit 0
grep -q "el34-force-reenroll" "$CONF" && exit 0   # 이미 적용됨 (멱등)

python3 - "$CONF" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
block = ("    <force>\n"
         "      <enabled>yes</enabled> <!-- el34-force-reenroll -->\n"
         "      <key_mismatch>yes</key_mismatch>\n"
         "      <disconnected_time enabled=\"yes\">0</disconnected_time>\n"
         "      <after_registration_time>0</after_registration_time>\n"
         "    </force>\n")

def fix(m):
    inner = re.sub(r'[ \t]*<force>.*?</force>\n?', '', m.group(1), flags=re.S)  # 기존 force 제거
    return "<auth>" + inner.rstrip("\n") + "\n" + block + "  </auth>"

s2, n = re.subn(r'<auth>(.*?)\s*</auth>', fix, s, flags=re.S)
if n == 0:
    sys.exit(0)   # <auth> 블록 없음 — 건너뜀
open(p, "w").write(s2)
PY
echo "[93-auth-force] authd force re-enroll (0 임계) 적용 — 동일 이름 즉시 교체"
