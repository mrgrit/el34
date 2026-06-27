#!/bin/bash
# el34-hostip.sh — compose 가 바인딩하는 호스트 IP 를 보장 (멱등).
#   웹 외부 진입  WEB_HOST_IP=192.168.0.161  (compose: el34-fw/web/portal publish)
#   내부 GUI 전용 INT_HOST_IP=192.168.136.145 (SIEM/콘솔/MISP/OpenCTI publish)
#
# 실 NIC(ens37/ens38)에 이미 있으면 그대로 skip. 단일 NIC(WiFi/단일 유선 등) 호스트에선:
#   .161 → LAN(default route) 인터페이스에 alias 부여 (LAN 도달 가능)
#   .145 → dummy 인터페이스 el34int0 에 부여 (호스트 Firefox 전용, LAN 격리)
# 이 IP 가 없으면 `docker compose up` 이 "cannot assign requested address" 로 실패한다.
# 호출 시점: el34.sh up (build 전) + 부팅 시 el34-hostip.service(Before=docker.service).
set -e
WEB_IP="${WEB_HOST_IP:-192.168.0.161}"
INT_IP="${INT_HOST_IP:-192.168.136.145}"
SUDO() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

# ── 웹 외부 진입 IP (LAN 192.168.0.0/24) ──
if ip -4 addr show | grep -qw "$WEB_IP"; then
    echo "[el34-hostip] $WEB_IP 이미 존재 — skip"
else
    LAN_IF=$(ip -4 route show default | awk '{print $5; exit}')
    [ -z "$LAN_IF" ] && LAN_IF=$(ip -4 -br addr | awk '$3 ~ /^192\.168\.0\./{print $1; exit}')
    if [ -n "$LAN_IF" ]; then
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
