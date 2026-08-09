#!/bin/bash
# el34-hostip.sh — compose 가 바인딩하는 호스트 IP 를 보장 (멱등).
#   웹 외부 진입  WEB_HOST_IP  (compose: el34-fw/web/portal publish) — el34.sh 가 .env 에 기록
#   내부 GUI 전용 INT_HOST_IP=192.168.136.145 (SIEM/콘솔/MISP/OpenCTI publish, dummy)
#
# WEB_HOST_IP 처리(우선순위: env > .env):
#   · 빈값/0.0.0.0        → 모든 인터페이스 바인딩. 웹 IP alias 불필요(skip).
#   · 이미 존재(실 NIC/DHCP) → skip (멱등).
#   · LAN 서브넷과 동일    → DHCP 가 관리하는 VM 실제 IP → 정적 add 시 충돌하므로 skip.
#   · 외부 서브넷(레거시 .161 등) → LAN(default route) 인터페이스에 alias 부여.
#   .145 → dummy 인터페이스 el34int0 (호스트 Firefox 전용, LAN 격리).
# 호출 시점: el34.sh up (build 전) + 부팅 시 el34-hostip.service(After=network-online, Before=docker).
set -e
SELFDIR="$(dirname "$(readlink -f "$0")")"
# 부팅 시 systemd 실행 경로엔 WEB_HOST_IP env 가 없음 → .env(최초 setup 기록값)에서 로드.
if [ -z "${WEB_HOST_IP:-}" ] && [ -f "$SELFDIR/.env" ]; then
    WEB_HOST_IP="$(grep -E '^WEB_HOST_IP=' "$SELFDIR/.env" | tail -1 | cut -d= -f2-)"
fi
WEB_IP="${WEB_HOST_IP:-}"
INT_IP="${INT_HOST_IP:-192.168.136.145}"
SUDO() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

# ── 웹 외부 진입 IP ──
if [ -z "$WEB_IP" ] || [ "$WEB_IP" = "0.0.0.0" ]; then
    echo "[el34-hostip] WEB_HOST_IP=${WEB_IP:-(미설정)} — 모든 인터페이스 바인딩, 웹 IP alias 불필요"
elif ip -4 addr show | grep -qw "$WEB_IP"; then
    echo "[el34-hostip] $WEB_IP 이미 존재(실 NIC/DHCP) — skip"
else
    LAN_IF=$(ip -4 route show default | awk '{print $5; exit}')
    [ -z "$LAN_IF" ] && LAN_IF=$(ip -4 -br addr | awk '$3 ~ /^192\.168\./{print $1; exit}')
    # WEB_IP 가 LAN 인터페이스 현재 서브넷(/24)과 같으면 = DHCP 가 관리하는 VM 실제 IP.
    # 정적 add 하면 DHCP 와 충돌 → add 하지 않고 대기(네트워크 준비 시 커널이 부여).
    LAN_NET=$(ip -4 -br addr show "$LAN_IF" 2>/dev/null | awk '{print $3}' | cut -d/ -f1 | cut -d. -f1-3)
    WEB_NET=$(echo "$WEB_IP" | cut -d. -f1-3)
    if [ -n "$LAN_NET" ] && [ "$LAN_NET" = "$WEB_NET" ]; then
        # 여기 왔다는 건 "$WEB_IP 가 LAN 서브넷 안인데 호스트에는 없다" = netplan static /
        # DHCP 예약이 적용되지 않은 상태다. 예전엔 'DHCP 가 주겠지' 하고 skip 했는데, 그러면
        # compose 의 ${WEB_HOST_IP}:80 바인딩이 'cannot assign requested address' 로 실패해
        # el34-fw 가 exit 255 로 죽고 웹 진입 포트 전체(80/443/8001-8007)가 사라진다
        # → 랜딩/취약사이트가 통째로 "안 열림". 그래서 alias 로 자가치유한다.
        # 단 브리지 L2 에서 다른 장비가 이미 그 IP 를 쓰고 있으면 중복 배정이므로 그때만 skip.
        if ping -c1 -W1 "$WEB_IP" >/dev/null 2>&1; then
            echo "[el34-hostip] WARN: $WEB_IP 를 다른 장비가 이미 사용 중(ping 응답) — alias skip"
            echo "              다른 IP 로 변경: WEB_HOST_IP_FORCE=1 ./el34.sh install (또는 0.0.0.0)"
        else
            SUDO ip addr add "$WEB_IP/24" dev "$LAN_IF" 2>/dev/null || true
            echo "[el34-hostip] $WEB_IP -> $LAN_IF (LAN 서브넷 alias 자가치유 — netplan static/DHCP 예약 권장)"
        fi
    elif [ -n "$LAN_IF" ]; then
        SUDO ip addr add "$WEB_IP/24" dev "$LAN_IF" 2>/dev/null || true
        echo "[el34-hostip] $WEB_IP -> $LAN_IF (웹 외부 진입 alias)"
    else
        echo "[el34-hostip] WARN: LAN 인터페이스 미탐지 — $WEB_IP 수동 설정 필요"
    fi
fi

# ── 내부 GUI 전용 IP (호스트 Firefox 전용, dummy) ──
if ip -4 addr show | grep -qw "$INT_IP"; then
    echo "[el34-hostip] $INT_IP 이미 존재 — skip"
else
    ip link show el34int0 >/dev/null 2>&1 || SUDO ip link add el34int0 type dummy
    SUDO ip link set el34int0 up
    SUDO ip addr add "$INT_IP/24" dev el34int0 2>/dev/null || true
    echo "[el34-hostip] $INT_IP -> el34int0 (dummy, 내부 GUI 전용)"
fi
