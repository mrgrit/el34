#!/usr/bin/env python3
"""el34-fw HAProxy 에 교육용 GUI 3종 vhost 를 추가한다 (idempotent).

  fw-gui.el34.lab  -> 127.0.0.1:8080   (방화벽 GUI, fw 자신)
  ips-gui.el34.lab -> 10.20.31.2:8080  (Suricata GUI, ips)
  waf-gui.el34.lab -> 10.20.32.80:8080 (ModSecurity GUI, web)

기존 'acl is_bastion …' / 'use_backend bastion …' 줄 뒤에 동일 블록을 양 frontend
(http_in/https_in)에 대칭으로 삽입하고, backend 3개를 파일 끝에 추가한다.
"""
P = "/etc/haproxy/haproxy.cfg"
conf = open(P, encoding="utf-8").read()

if "is_fw_gui" in conf:
    print("ALREADY-PATCHED: GUI vhost 가 이미 있음. 변경 없음.")
    raise SystemExit(0)

# NOTE: base haproxy.cfg 는 컬럼 정렬상 'is_bastion' 뒤에 공백 2칸이다. 과거 이 앵커가
# 1칸이라 count==0 → "ANCHOR-NOT-FOUND" 로 패치가 영구 실패, GUI vhost 라우트가 안 들어가
# fw-gui/ips-gui/waf-gui 가 랜딩으로 fallthrough 하던 버그가 있었다(2026-06 수정).
# 현재는 라우트가 base config 에 내장되어 이 스크립트는 보통 ALREADY-PATCHED 로 no-op 한다.
ACL_ANCHOR = "    acl is_bastion  hdr(host) -i bastion.el34.lab\n"
ACL_ADD = (
    "    acl is_fw_gui  hdr(host) -i fw-gui.el34.lab\n"
    "    acl is_ips_gui hdr(host) -i ips-gui.el34.lab\n"
    "    acl is_waf_gui hdr(host) -i waf-gui.el34.lab\n"
)
UB_ANCHOR = "    use_backend bastion   if is_bastion\n"
UB_ADD = (
    "    use_backend fw_gui  if is_fw_gui\n"
    "    use_backend ips_gui if is_ips_gui\n"
    "    use_backend waf_gui if is_waf_gui\n"
)
BACKENDS = (
    "\n# ─── 교육용 GUI (secuops-easy 특강) ───\n"
    "backend fw_gui\n    server fwgui 127.0.0.1:8080\n\n"
    "backend ips_gui\n    server ipsgui 10.20.31.2:8080\n\n"
    "backend waf_gui\n    server wafgui 10.20.32.80:8080\n"
)

n1 = conf.count(ACL_ANCHOR)
n2 = conf.count(UB_ANCHOR)
if n1 < 1 or n2 < 1:
    print("ANCHOR-NOT-FOUND: acl=%d use_backend=%d — 수동 확인 필요. 변경 없음." % (n1, n2))
    raise SystemExit(1)

conf = conf.replace(ACL_ANCHOR, ACL_ANCHOR + ACL_ADD)
conf = conf.replace(UB_ANCHOR, UB_ANCHOR + UB_ADD)
conf = conf.rstrip() + "\n" + BACKENDS

open(P, "w", encoding="utf-8").write(conf)
print("PATCHED: acl 삽입 x%d, use_backend 삽입 x%d, backend 3개 추가" % (n1, n2))
