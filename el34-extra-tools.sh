#!/usr/bin/env bash
# el34-extra-tools.sh — training 랩이 의존하는 "추가 도구"를 배포 후 설치(멱등·best-effort).
# 베이스 배포(`./el34.sh install && ./el34.sh up && ./el34.sh sigma`) 후 1회 실행.
# CC가 콘텐츠 제작 중 라이브로 설치했던 도구를 배포-시점에 재현한다.
# 주의: 컨테이너는 인터넷 차단 → 인터넷 필요한 것은 호스트에서 받아 docker cp.
set -uo pipefail
log(){ echo "[extra-tools] $*"; }

log "1) 호스트 trivy (cloud-container W03+/attack-adv W12 이미지·의존성 CVE 스캔)"
if ! command -v trivy >/dev/null 2>&1; then
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin || log "  trivy 설치 실패(수동)"
fi
trivy --version 2>/dev/null | head -1 || true

log "2) el34-attacker nuclei 템플릿 (web-vuln W13) — 호스트 clone → docker cp(컨테이너 인터넷 차단)"
if ! docker exec el34-attacker sh -c 'test -d /root/nuclei-templates/http' 2>/dev/null; then
  T=$(mktemp -d)
  if git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates "$T/nuclei-templates" 2>/dev/null; then
    docker exec el34-attacker mkdir -p /root && docker cp "$T/nuclei-templates" el34-attacker:/root/ && log "  템플릿 복사 완료"
  else log "  템플릿 clone 실패(수동)"; fi
  rm -rf "$T"
else log "  이미 있음"; fi

log "3) el34-attacker scapy (attack/web-vuln W09 패킷 크래프팅)"
docker exec el34-attacker sh -c 'python3 -c "import scapy" 2>/dev/null && echo "  이미 있음"' || \
  docker exec el34-attacker sh -c 'pip3 install --quiet scapy 2>/dev/null && echo "  설치됨"' || \
  log "  scapy 미설치(이미지에 포함되거나 인터넷 필요 — 수동)"

log "4) Caldera (web-vuln W13, 호스트 ~/caldera-src) — 선택/수동(대용량)"
[ -d "$HOME/caldera-src" ] && log "  이미 있음" || \
  log "  필요 시: git clone https://github.com/mitre/caldera.git ~/caldera-src --recursive"

log "참고: Sysmon=docker-compose.sysmon.yml(overlay), SIGMA=./el34.sh sigma 로 이미 배포됨."
log "완료."
