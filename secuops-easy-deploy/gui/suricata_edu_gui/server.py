#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""suricata_edu_gui — IPS(Suricata) 교육용 GUI 백엔드.

el34 secuops-easy 특강용. el34-ips 컨테이너 안에서 root 로 실행되며, 학생이 웹 UI 에서
탐지룰을 구성하면 그것이 만들어내는 **실제 Suricata rule 한 줄** 을 미리보기로 보여준 뒤
local.rules 에 적용하고 `suricatasc -c reload-rules` 로 라이브 반영한다. 의존성 0.

설계 원칙
- GUI 가 만드는 룰은 local.rules 에 한 줄로 append. sid 는 9000000 이상 자동 배정
  (사전 시드 룰 1000000 대와 분리). 삭제는 sid 기준.
- 적용 직후 `suricatasc -c ruleset-stats` 로 loaded/failed 를 보여줘 학생이 자기 룰이
  실제 로딩됐는지 즉시 확인한다 (잘못 쓴 룰은 failed 증가).
- eve.json 은 매우 크므로(수 GB) 끝에서부터 N 줄만 읽는다.
- Suricata 는 IDS(af-packet) 모드라 drop 은 실제 차단이 아니라 표식이다 (UI 에서 안내).

실행:  python3 server.py [PORT]   (기본 8080)
"""
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

SURICATA_YAML = "/etc/suricata/suricata.yaml"
RULES_DIR = "/etc/suricata/rules"
LOCAL_RULES = os.path.join(RULES_DIR, "local.rules")
EVE = "/var/log/suricata/eve.json"
FASTLOG = "/var/log/suricata/fast.log"
SURICATASC = "suricatasc"
EDU_SID_BASE = 9000000  # GUI 가 만드는 룰 sid 시작점

OSSEC_CONF = "/var/ossec/etc/ossec.conf"
WAZUH_CTL = "/var/ossec/bin/wazuh-control"


# ────────────────────────────── helpers ──────────────────────────────
def run(cmd, timeout=20):
    argv = shlex.split(cmd) if isinstance(cmd, str) else cmd
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr,
                "cmd": " ".join(shlex.quote(a) for a in argv)}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout", "cmd": str(cmd)}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e), "cmd": str(cmd)}


def suricatasc(cmd):
    """suricatasc -c <cmd> → 파싱된 dict (실패 시 {'return':'NOK',...})."""
    r = run([SURICATASC, "-c", cmd], timeout=20)
    try:
        return json.loads(r["stdout"])
    except Exception:
        return {"return": "NOK", "message": (r["stdout"] + r["stderr"]).strip()[:300]}


def tail_lines(path, n=100, maxbytes=600000):
    """대용량 파일 끝에서 마지막 n 줄 반환 (끝에서부터 maxbytes 만 읽음)."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            start = max(0, size - maxbytes)
            f.seek(start)
            data = f.read()
        text = data.decode("utf-8", "ignore")
        lines = text.splitlines()
        if start > 0 and lines:
            lines = lines[1:]  # 잘린 첫 줄 버림
        return lines[-n:]
    except FileNotFoundError:
        return []


def ruleset_stats():
    d = suricatasc("ruleset-stats")
    try:
        m = d["message"][0]
        return {"loaded": m.get("rules_loaded"), "failed": m.get("rules_failed")}
    except Exception:
        return {"loaded": None, "failed": None, "raw": d}


# ────────────────────────────── rule parse / build ──────────────────────────────
_RULE_HEAD_RE = re.compile(
    r"^\s*(?P<action>alert|drop|pass|reject)\s+(?P<proto>\S+)\s+"
    r"(?P<src>\S+)\s+(?P<sport>\S+)\s+(?P<dir>->|<>)\s+(?P<dst>\S+)\s+(?P<dport>\S+)\s*\((?P<opts>.*)\)\s*$"
)


def parse_rule(line):
    """Suricata 룰 한 줄 → 구조 분해. 실패 시 {'error':...}."""
    line = line.strip()
    m = _RULE_HEAD_RE.match(line)
    if not m:
        return {"error": "룰 헤더를 인식할 수 없습니다.", "raw": line}
    d = m.groupdict()
    opts_raw = d.pop("opts")
    # 옵션 분해: 세미콜론 기준 (단, 따옴표 안의 ; 는 보존)
    opts, buf, in_q = [], "", False
    for ch in opts_raw:
        if ch == '"':
            in_q = not in_q
        if ch == ";" and not in_q:
            if buf.strip():
                opts.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        opts.append(buf.strip())
    parsed_opts = []
    for o in opts:
        if ":" in o:
            k, v = o.split(":", 1)
            parsed_opts.append({"k": k.strip(), "v": v.strip()})
        else:
            parsed_opts.append({"k": o.strip(), "v": None})
    sid = next((o["v"] for o in parsed_opts if o["k"] == "sid"), None)
    msg = next((o["v"].strip('"') for o in parsed_opts if o["k"] == "msg" and o["v"]), None)
    d["options"] = parsed_opts
    d["sid"] = sid
    d["msg"] = msg
    d["raw"] = line
    return d


HTTP_BUFFERS = {"http.uri", "http.user_agent", "http.host", "http.method",
                "http.header", "http.request_body", "http.response_body", "http.cookie",
                "dns.query", "tls.sni"}


def build_rule(p):
    """폼 입력 → Suricata 룰 한 줄 (실행 X)."""
    action = p.get("action", "alert")
    if action not in ("alert", "drop", "pass", "reject"):
        raise ValueError("action 은 alert/drop/pass/reject")
    proto = _tok(p.get("proto", "http"))
    # el34 는 폐쇄망 — 공격자(10.20.30.202)도 HOME_NET 안이라 EXTERNAL_NET 매칭이 안 된다.
    # 따라서 기본 src/dst 는 any (실전 관례인 $EXTERNAL_NET→$HOME_NET 는 강의에서 별도 설명).
    src = _net(p.get("src") or "any")
    sport = _tok(p.get("sport") or "any")
    direction = p.get("dir", "->")
    if direction not in ("->", "<>"):
        raise ValueError("방향은 -> 또는 <>")
    dst = _net(p.get("dst") or "any")
    dport = _tok(p.get("dport") or "any")

    opts = []
    msg = p.get("msg") or "EDU custom rule"
    opts.append('msg:"%s"' % _msg(msg))
    flow = p.get("flow")
    if flow:
        opts.append("flow:%s" % _tok(flow))
    # 탐지부: buffer + content  또는  pcre
    buf = p.get("buffer")          # 예: http.uri (sticky buffer)
    content = p.get("content")
    pcre = p.get("pcre")
    if buf and buf in HTTP_BUFFERS:
        opts.append(buf)            # sticky buffer 키워드 (content 앞)
    if content:
        neg = "!" if p.get("content_negate") else ""
        opts.append('content:%s"%s"' % (neg, _content(content)))
        if p.get("nocase"):
            opts.append("nocase")
    if pcre:
        opts.append('pcre:"%s"' % _pcre(pcre))
    # threshold (선택)
    if p.get("threshold_count"):
        track = _tok(p.get("threshold_track") or "by_src")
        cnt = int(p["threshold_count"])
        sec = int(p.get("threshold_seconds") or 60)
        ttype = _tok(p.get("threshold_type") or "both")
        opts.append("threshold:type %s, track %s, count %d, seconds %d" % (ttype, track, cnt, sec))
    if p.get("classtype"):
        opts.append("classtype:%s" % _tok(p["classtype"]))
    sid = int(p.get("sid") or next_sid())
    opts.append("sid:%d" % sid)
    opts.append("rev:%d" % int(p.get("rev") or 1))
    body = "; ".join(opts)
    return "%s %s %s %s %s %s %s (%s;)" % (action, proto, src, sport, direction, dst, dport, body)


# 입력 검증 (정규식 화이트리스트)
def _tok(s):
    s = str(s).strip()
    if not re.match(r"^[A-Za-z0-9_,./:\$!\[\]> <-]+$", s):
        raise ValueError("허용되지 않는 값: %r" % s)
    return s
def _net(s):
    s = str(s).strip()
    if not re.match(r"^[A-Za-z0-9_,./:\$!\[\] -]+$", s):
        raise ValueError("네트워크 형식 오류: %r" % s)
    return s
def _msg(s):
    return re.sub(r'["\\;()]', "", str(s))[:120]
def _content(s):
    # content 는 |hex| 와 일반 문자 허용, 따옴표/세미콜론만 제거
    return re.sub(r'["]', "", str(s))[:200]
def _pcre(s):
    return re.sub(r'["]', "", str(s))[:200]


def next_sid():
    mx = EDU_SID_BASE
    try:
        with open(LOCAL_RULES, encoding="utf-8") as f:
            for s in re.findall(r"sid:(\d+)", f.read()):
                si = int(s)
                if si >= EDU_SID_BASE and si > mx:
                    mx = si
    except FileNotFoundError:
        pass
    return mx + 1


def list_local_rules():
    """local.rules 에서 한 줄짜리 룰만 파싱 (GUI 관리 대상)."""
    out = []
    try:
        with open(LOCAL_RULES, encoding="utf-8") as f:
            for ln in f:
                s = ln.strip()
                if not s or s.startswith("#") or s.endswith("\\"):
                    continue
                if re.match(r"^(alert|drop|pass|reject)\s", s):
                    p = parse_rule(s)
                    if "error" not in p:
                        out.append({"sid": p["sid"], "msg": p["msg"], "action": p["action"],
                                    "proto": p["proto"], "raw": s,
                                    "edu": p["sid"] and int(p["sid"]) >= EDU_SID_BASE})
    except FileNotFoundError:
        pass
    return out


def apply_rule(line):
    """룰 한 줄을 local.rules 에 append + reload + stats."""
    before = ruleset_stats()
    sid_m = re.search(r"sid:(\d+)", line)
    sid = sid_m.group(1) if sid_m else None
    with open(LOCAL_RULES, "a", encoding="utf-8") as f:
        f.write(line.rstrip() + "\n")
    rl = suricatasc("reload-rules")
    time.sleep(1)
    after = ruleset_stats()
    log_event("rule_apply", {"sid": sid, "rule": line[:200],
                             "loaded": after.get("loaded"), "failed": after.get("failed")})
    # 이 sid 가 실제 로딩됐는지: failed 가 늘지 않았으면 성공으로 간주
    ok = (rl.get("return") == "OK")
    new_fail = (after.get("failed") or 0) - (before.get("failed") or 0)
    return {"ok": ok and new_fail <= 0, "sid": sid, "reload": rl.get("return"),
            "stats_before": before, "stats_after": after,
            "note": ("⚠ 이 룰이 로딩 실패했을 수 있습니다 (failed +%d). 문법을 확인하세요." % new_fail)
                    if new_fail > 0 else "룰이 정상 로딩되었습니다."}


def delete_rule(sid):
    sid = str(int(sid))
    try:
        with open(LOCAL_RULES, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return {"ok": False, "msg": "local.rules 없음"}
    kept = [ln for ln in lines if ("sid:%s;" % sid) not in ln and ("sid:%s ;" % sid) not in ln
            and not re.search(r"sid:%s\b" % sid, ln)]
    if len(kept) == len(lines):
        return {"ok": False, "msg": "sid %s 룰을 찾지 못함" % sid}
    with open(LOCAL_RULES, "w", encoding="utf-8") as f:
        f.writelines(kept)
    rl = suricatasc("reload-rules")
    log_event("rule_delete", {"sid": sid})
    return {"ok": rl.get("return") == "OK", "sid": sid, "stats": ruleset_stats()}


# ────────────────────────────── eve.json ──────────────────────────────
def eve_tail(event_type=None, n=80):
    raw = tail_lines(EVE, n=n * 3 if event_type else n)
    out = []
    for ln in reversed(raw):
        try:
            j = json.loads(ln)
        except Exception:
            continue
        if event_type and j.get("event_type") != event_type:
            continue
        out.append(slim_eve(j))
        if len(out) >= n:
            break
    return out


def slim_eve(j):
    et = j.get("event_type")
    base = {"ts": j.get("timestamp", "")[:19], "event_type": et,
            "src_ip": j.get("src_ip"), "dest_ip": j.get("dest_ip"),
            "src_port": j.get("src_port"), "dest_port": j.get("dest_port"),
            "proto": j.get("proto")}
    if et == "alert":
        a = j.get("alert", {})
        base["alert"] = {"signature": a.get("signature"), "sid": a.get("signature_id"),
                         "category": a.get("category"), "severity": a.get("severity")}
    elif et == "http":
        h = j.get("http", {})
        base["http"] = {"host": h.get("hostname"), "url": h.get("url"),
                        "method": h.get("http_method"), "status": h.get("status"),
                        "ua": h.get("http_user_agent")}
    elif et == "dns":
        base["dns"] = j.get("dns", {}).get("rrname")
    return base


def event_type_counts(n=400):
    raw = tail_lines(EVE, n=n)
    c = {}
    for ln in raw:
        try:
            et = json.loads(ln).get("event_type", "?")
        except Exception:
            continue
        c[et] = c.get(et, 0) + 1
    return c


# ────────────────────────────── SIEM ──────────────────────────────
SIEM_BLOCK = (
    "  <localfile>\n"
    "    <log_format>json</log_format>\n"
    "    <location>%s</location>\n"
    "  </localfile>\n" % EVE
)


def siem_status():
    has = False
    try:
        has = EVE in open(OSSEC_CONF, encoding="utf-8").read()
    except Exception:
        pass
    st = run([WAZUH_CTL, "status"])
    running = "running" in st["stdout"]
    mgr = None
    try:
        mgr = re.search(r"<address>([^<]+)</address>", open(OSSEC_CONF).read()).group(1)
    except Exception:
        pass
    return {"integrated": has, "agent_running": running, "manager": mgr,
            "event_log": EVE, "status_raw": st["stdout"][-600:]}


def siem_enable():
    try:
        conf = open(OSSEC_CONF, encoding="utf-8").read()
        if EVE in conf:
            return {"ok": True, "msg": "이미 eve.json 이 Wazuh 로 연동돼 있습니다."}
        idx = conf.rfind("</ossec_config>")
        conf = conf[:idx] + SIEM_BLOCK + conf[idx:]
        open(OSSEC_CONF, "w", encoding="utf-8").write(conf)
        r = run([WAZUH_CTL, "restart"], timeout=40)
        log_event("siem_enable", {"rc": r["rc"]})
        return {"ok": r["rc"] == 0, "msg": "eve.json localfile 추가 + 에이전트 재시작"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


# ────────────────────────────── events / scenarios ──────────────────────────────
EVENT_LOG = "/var/log/nft_edu/suricata_edu_events.log"


def log_event(action, detail):
    try:
        os.makedirs(os.path.dirname(EVENT_LOG), exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "source": "suricata_edu_gui", "action": action}
        rec.update(detail)
        with open(EVENT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        sys.stderr.write("[suricata_edu_gui] log_event fail: %s\n" % e)


def load_scenarios():
    try:
        return json.load(open(os.path.join(STATIC, "scenarios.json"), encoding="utf-8"))
    except Exception as e:
        return {"error": str(e), "scenarios": []}


def check_scenario(sid):
    data = load_scenarios()
    sc = next((s for s in data.get("scenarios", []) if s.get("id") == sid), None)
    if not sc:
        return {"ok": False, "msg": "시나리오 없음"}
    chk = sc.get("check", {})
    typ = chk.get("type")
    if typ == "rule_match":
        try:
            txt = open(LOCAL_RULES, encoding="utf-8").read()
        except FileNotFoundError:
            txt = ""
        evid = []
        for rx in chk.get("require", []):
            # MULTILINE: require 의 ^ 앵커가 local.rules 의 각 룰 줄 시작과 매칭되도록
            evid.append({"require": rx, "found": re.search(rx, txt, re.MULTILINE) is not None})
        passed = all(e["found"] for e in evid)
        # 추가로 reload 실패 룰이 없도록 stats 확인
        stats = ruleset_stats()
        return {"ok": passed, "evidence": evid, "stats": stats, "hint": sc.get("hint")}
    if typ == "alert_fired":
        sig = chk.get("signature")  # eve.json alert.signature 부분 문자열
        alerts = eve_tail(event_type="alert", n=60)
        hit = [a for a in alerts if sig and a.get("alert", {}).get("signature") and sig in a["alert"]["signature"]]
        return {"ok": len(hit) > 0, "evidence": hit[:3],
                "msg": "최근 alert 에서 '%s' %d건" % (sig, len(hit)), "hint": sc.get("hint")}
    return {"ok": False, "msg": "알 수 없는 check type"}


# ────────────────────────────── config / status ──────────────────────────────
def yaml_grep(keys):
    out = {}
    try:
        txt = open(SURICATA_YAML, encoding="utf-8").read()
        for k in keys:
            m = re.search(r"^\s*%s\s*:\s*(.+)$" % re.escape(k), txt, re.M)
            out[k] = m.group(1).strip() if m else None
    except Exception as e:
        out["_error"] = str(e)
    return out


def interfaces():
    r = run(["ip", "-br", "-o", "addr"])
    zone = {"eth0": "pipe (fw↔ips, Suricata 감시 대상)", "eth1": "dmz (ips↔web)", "lo": "loopback"}
    out = []
    for ln in r["stdout"].splitlines():
        p = ln.split()
        if not p:
            continue
        name = p[0].split("@")[0]
        out.append({"name": name, "state": p[1] if len(p) > 1 else "",
                    "addrs": [x for x in p[2:] if "/" in x], "zone": zone.get(name, "")})
    return out


def status():
    stats = ruleset_stats()
    pid = run(["pgrep", "-x", "Suricata-Main"])["stdout"].strip() or \
          run(["pgrep", "-f", "suricata -"])["stdout"].strip().split("\n")[0]
    try:
        evesize = os.path.getsize(EVE)
    except OSError:
        evesize = 0
    ver = run(["suricata", "-V"])["stdout"].strip()
    return {"hostname": run(["hostname"])["stdout"].strip(), "version": ver,
            "running": bool(pid), "pid": pid, "interfaces": interfaces(),
            "rules_loaded": stats.get("loaded"), "rules_failed": stats.get("failed"),
            "eve_mb": round(evesize / 1048576, 1), "local_rule_count": len(list_local_rules()),
            "home_net": yaml_grep(["HOME_NET"]).get("HOME_NET")}


# ────────────────────────────── HTTP handler ──────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "suricata_edu_gui/1.0"

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        if not n:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw)
        except Exception:
            return dict(urllib.parse.parse_qsl(raw.decode("utf-8", "ignore")))

    def log_message(self, *a):
        pass

    def _static(self, path):
        if path in ("/", ""):
            path = "/index.html"
        rel = path[len("/static/"):] if path.startswith("/static/") else path.lstrip("/")
        full = os.path.join(STATIC, os.path.normpath(rel))
        if not full.startswith(STATIC) or not os.path.isfile(full):
            return self._send(404, {"error": "not found"})
        ct = {"html": "text/html; charset=utf-8", "js": "application/javascript; charset=utf-8",
              "css": "text/css; charset=utf-8", "json": "application/json; charset=utf-8"}.get(
            full.rsplit(".", 1)[-1], "text/plain; charset=utf-8")
        self._send(200, open(full, "rb").read(), ct)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path == "/api/status":
                return self._send(200, status())
            if u.path == "/api/config":
                return self._send(200, {
                    "yaml": yaml_grep(["HOME_NET", "EXTERNAL_NET", "default-rule-path"]),
                    "rules_dir": sorted(os.listdir(RULES_DIR)) if os.path.isdir(RULES_DIR) else [],
                    "log_dir": sorted(os.listdir("/var/log/suricata")) if os.path.isdir("/var/log/suricata") else [],
                    "paths": {"yaml": SURICATA_YAML, "local_rules": LOCAL_RULES, "eve": EVE, "fastlog": FASTLOG}})
            if u.path == "/api/rules":
                return self._send(200, {"rules": list_local_rules(), "stats": ruleset_stats(),
                                        "next_sid": next_sid()})
            if u.path == "/api/eve":
                et = q.get("type", [None])[0] or None
                return self._send(200, {"events": eve_tail(et, int(q.get("n", ["80"])[0])),
                                        "counts": event_type_counts()})
            if u.path == "/api/fastlog":
                return self._send(200, {"lines": tail_lines(FASTLOG, int(q.get("n", ["60"])[0]))})
            if u.path == "/api/siem":
                return self._send(200, siem_status())
            if u.path == "/api/scenarios":
                return self._send(200, load_scenarios())
            return self._static(u.path)
        except Exception as e:
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        b = self._body()
        try:
            if u.path == "/api/rule/analyze":
                return self._send(200, parse_rule(b.get("rule", "")))
            if u.path == "/api/rule/preview":
                return self._send(200, {"rule": build_rule(b)})
            if u.path == "/api/rule/apply":
                rule = b.get("rule", "")
                if not re.match(r"^(alert|drop|pass|reject)\s", rule.strip()):
                    return self._send(400, {"ok": False, "error": "유효한 룰이 아닙니다 (action 으로 시작해야 함)"})
                return self._send(200, apply_rule(rule))
            if u.path == "/api/rule/delete":
                return self._send(200, delete_rule(b.get("sid")))
            if u.path == "/api/siem/enable":
                return self._send(200, siem_enable())
            if u.path == "/api/scenario/check":
                return self._send(200, check_scenario(b.get("id")))
            return self._send(404, {"error": "unknown endpoint"})
        except ValueError as e:
            return self._send(400, {"ok": False, "error": str(e)})
        except Exception as e:
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})


def main():
    log_event("boot", {"port": PORT})
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    sys.stderr.write("[suricata_edu_gui] listening on 0.0.0.0:%d\n" % PORT)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
