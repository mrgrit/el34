#!/usr/bin/env bash
# secuops-easy 특강 배포/복구 — 6v6 호스트에서 실행 (★오프라인·멱등★).
#
# 2026-06 구조 변경:
#   GUI 3종(방화벽/IPS/WAF)은 이제 fw/ips/web **이미지에 내장**(secuops-easy-deploy/gui/)되어
#   각 컨테이너 entrypoint 가 :8080 으로 자동 기동하고, HAProxy 라우트도 fw/haproxy.cfg(base)에
#   포함된다. 따라서 'down→up'·재부팅 후 별도 배포 없이 fw-gui/ips-gui/waf-gui 가 즉시 열린다.
#   (이전엔 매 up 마다 GitHub clone + 런타임 HAProxy 패치 + 위험한 reload 에 의존 → 네트워크/앵커
#    불일치/레이스로 콘솔이 안 열리는 사고가 반복됨. 그 의존을 전부 제거했다.)
#
#   이 스크립트는 이제 그 상태를 **검증하고, 혹시 누락되면 vendored 소스로 치유**하는 보조 도구다.
#   네트워크가 전혀 필요 없다. up/restore 경로에서 best-effort 로 호출된다.
#
#   대상 컨테이너: 6v6-fw / 6v6-ips / 6v6-web  (port 8080)
#   접속(학생): http://fw-gui.6v6.lab  /  http://ips-gui.6v6.lab  /  http://waf-gui.6v6.lab
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GUI_SRC="$HERE/gui"

# "vendored-dir:컨테이너:vhost"
GUIS=(
  "nft_edu_gui:6v6-fw:fw-gui"
  "suricata_edu_gui:6v6-ips:ips-gui"
  "modsec_edu_gui:6v6-web:waf-gui"
)

echo "== [1/4] WAF(ModSecurity) 설정 보정(멱등) + Apache 확인 =="
if docker ps --format '{{.Names}}' | grep -q '^6v6-web$'; then
  docker cp "$HERE/fix_modsec.py" 6v6-web:/tmp/fix_modsec.py 2>/dev/null && \
    docker exec 6v6-web python3 /tmp/fix_modsec.py 2>/dev/null || true
  # Apache 는 entrypoint 가 기동. 혹시 죽어 있으면 best-effort 재기동.
  if ! docker exec 6v6-web pgrep -x apache2 >/dev/null 2>&1; then
    docker exec 6v6-web bash -c 'apache2ctl configtest && service apache2 start' 2>/dev/null || true
  fi
fi

echo "== [2/4] Suricata 룰 baseline 보정(멱등) + reload =="
if docker ps --format '{{.Names}}' | grep -q '^6v6-ips$' && \
   docker exec 6v6-ips test -d /etc/suricata/rules 2>/dev/null; then
  docker cp "$HERE/suricata_local.rules.baseline" 6v6-ips:/etc/suricata/rules/local.rules 2>/dev/null || true
  docker exec 6v6-ips suricatasc -c reload-rules 2>/dev/null || true
fi

echo "== [3/4] GUI 3종 검증 + 누락 시 vendored 소스로 치유(오프라인) =="
for spec in "${GUIS[@]}"; do
  repo="${spec%%:*}"; rest="${spec#*:}"; cont="${rest%%:*}"; vhost="${rest##*:}"
  if ! docker ps --format '{{.Names}}' | grep -q "^${cont}$"; then
    echo "  $vhost: SKIP ($cont not running)"; continue
  fi
  # 이미 :8080 정상 응답이면 skip (entrypoint 자동기동분 보호)
  if docker exec "$cont" curl -s -o /dev/null -m 2 "http://127.0.0.1:8080/" 2>/dev/null; then
    echo "  $vhost: OK (already serving on $cont:8080)"
    continue
  fi
  # 누락 → vendored 소스로 치유 (네트워크 불필요)
  if [ -f "$GUI_SRC/$repo/server.py" ]; then
    echo "  $vhost: healing from vendored gui/$repo → $cont:/opt/$repo"
    docker exec "$cont" mkdir -p "/opt/$repo/static" 2>/dev/null || true
    docker cp "$GUI_SRC/$repo/server.py" "$cont:/opt/$repo/server.py"
    docker cp "$GUI_SRC/$repo/static/." "$cont:/opt/$repo/static/"
    docker exec "$cont" pkill -f "/opt/$repo/server.py" 2>/dev/null || true
    sleep 1
    docker exec -d "$cont" bash -c "python3 /opt/$repo/server.py 8080 >/var/log/$repo.log 2>&1"
    sleep 2
    docker exec "$cont" curl -s -o /dev/null -m 2 "http://127.0.0.1:8080/" 2>/dev/null \
      && echo "    -> $vhost healed" || echo "    -> $vhost still down — /var/log/$repo.log 확인"
  else
    echo "  $vhost: ! vendored 소스 없음 ($GUI_SRC/$repo) — 'bash 6v6.sh up' 로 이미지 재빌드 필요"
  fi
done

echo "== [4/4] HAProxy GUI 라우트 확인 (base config 내장; 누락 시에만 backward-compat patch) =="
if docker ps --format '{{.Names}}' | grep -q '^6v6-fw$'; then
  if docker exec 6v6-fw grep -q 'is_fw_gui' /etc/haproxy/haproxy.cfg 2>/dev/null; then
    echo "  HAProxy: GUI 라우트가 base config 에 존재 → patch 불필요"
  else
    echo "  HAProxy: GUI 라우트 누락(구 이미지) — patch 적용 후 안전 reload"
    docker exec 6v6-fw cp /etc/haproxy/haproxy.cfg "/etc/haproxy/haproxy.cfg.bak" 2>/dev/null || true
    docker cp "$HERE/patch_haproxy.py" 6v6-fw:/tmp/patch_haproxy.py
    if docker exec 6v6-fw python3 /tmp/patch_haproxy.py | grep -q PATCHED; then
      if docker exec 6v6-fw haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
        docker exec 6v6-fw bash -c 'haproxy -f /etc/haproxy/haproxy.cfg -sf $(pgrep -o haproxy) -D' \
          && echo "    -> HAProxy reloaded (GUI 라우트 추가)"
      else
        echo "    -> ! 패치 후 config invalid — reload 생략"
      fi
    fi
  fi
fi

echo "== 검증 (fw HAProxy 경유 → 실제 '콘솔' 페이지인지 title 확인; 랜딩 fallthrough 거짓양성 차단) =="
for spec in "${GUIS[@]}"; do
  vhost="${spec##*:}"
  docker ps --format '{{.Names}}' | grep -q '^6v6-fw$' || { echo "  $vhost: SKIP (6v6-fw down)"; continue; }
  title=$(docker exec 6v6-fw curl -s -m 5 -H "Host: $vhost.6v6.lab" "http://127.0.0.1/" 2>/dev/null \
            | grep -ioE '<title>[^<]*</title>' | head -1)
  case "$title" in
    *콘솔*) echo "  [OK]   $vhost.6v6.lab => $title" ;;
    *)      echo "  [FAIL] $vhost.6v6.lab => '${title:-no-response}' (콘솔 아님 — 'bash 6v6.sh up' 재빌드 필요)" ;;
  esac
done
echo "done. 학생 접속: http://{fw,ips,waf}-gui.6v6.lab"
