#!/bin/bash
# el34-net.sh — 호스트레벨 네트워크 글루 (docker compose up 직후 1회 실행, 멱등).
#
# `docker compose up` 만으로는 fw→ips→web 인터-브리지 체인이 동작하지 않는다. 두 가지가 필요:
#   1) net.bridge.bridge-nf-call-iptables=0  — br_netfilter 가 docker 브리지 통과 패킷을
#      host iptables FORWARD 로 넘기면 docker per-IP DROP 에 걸려 체인이 끊김.
#   2) DOCKER-USER 에 브리지 간 ACCEPT — docker 는 다른 브리지 간 forward 를 기본 차단.
#
# 출처 IP 보존(.202 → web) 은 daemon.json 의 "userland-proxy": false 와 함께 성립한다.
# (이 스크립트는 sysctl/iptables 만 — daemon.json 은 setup 시 1회 설정.)
set -e
SUDO() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

echo "[el34-net] 1) bridge-nf-call-iptables=0 (인터-브리지 forward 허용)"
SUDO sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null
grep -q 'bridge-nf-call-iptables' /etc/sysctl.conf 2>/dev/null || \
    echo 'net.bridge.bridge-nf-call-iptables=0' | SUDO tee -a /etc/sysctl.conf >/dev/null

echo "[el34-net] 2) detect el34 bridges"
declare -A BR
for n in ext pipe dmz int; do
    id=$(docker network inspect el34-$n -f '{{.Id}}' 2>/dev/null | cut -c1-12)
    br=$(docker network inspect el34-$n -f '{{range $k,$v := .Options}}{{if eq $k "com.docker.network.bridge.name"}}{{$v}}{{end}}{{end}}' 2>/dev/null)
    [ -z "$br" ] && br="br-$id"
    BR[$n]=$br
    echo "    el34-$n -> $br"
done
if [ -z "${BR[pipe]}" ] || [ -z "${BR[dmz]}" ]; then
    echo "[el34-net] ERROR: el34 브리지 미탐지 — 'docker compose up' 먼저 실행"; exit 1
fi

echo "[el34-net] 3) DOCKER-USER ACCEPT (ext<->pipe<->dmz<->int)"
SUDO iptables -F DOCKER-USER 2>/dev/null || true
for pair in \
    "${BR[ext]} ${BR[pipe]}" "${BR[pipe]} ${BR[ext]}" \
    "${BR[pipe]} ${BR[dmz]}" "${BR[dmz]} ${BR[pipe]}" \
    "${BR[dmz]} ${BR[int]}"  "${BR[int]} ${BR[dmz]}"  ; do
    set -- $pair
    SUDO iptables -I DOCKER-USER -i "$1" -o "$2" -j ACCEPT 2>/dev/null || true
done
SUDO iptables -A DOCKER-USER -j RETURN 2>/dev/null || true

echo "[el34-net] 완료 — fw→ips→web 체인 + 출처 IP 보존 활성."
