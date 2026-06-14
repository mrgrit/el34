#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nft_edu_gui — 방화벽(nftables) 교육용 GUI 백엔드.

6v6 secuops-easy 특강용. 6v6-fw 컨테이너 안에서 root 로 실행되며, 학생이 웹 UI 에서
방화벽 룰/NAT 을 구성하면 그것이 만들어내는 **실제 nft 명령** 을 미리보기로 보여준 뒤
적용한다. 의존성 0 — Python 3 표준 라이브러리만 사용한다 (폐쇄망 컨테이너용).

설계 원칙
- 변경(add/insert/delete/reset)은 오직 `inet six_filter`, `ip six_nat` 두 table 에만 허용.
  Docker 가 관리하는 `ip nat` 는 절대 건드리지 않는다 (안전장치 _is_allowed_target).
- 모든 적용/삭제/리셋은 /var/log/nft_edu/events.log 에 JSON 한 줄로 기록한다.
  이 파일이 곧 Wazuh(SIEM) 가 tail 하는 방화벽 이벤트 소스가 된다.
- 패킷 단위 native nft log 는 컨테이너에서 커널 ring buffer 로만 가고 파일에 안 남으므로,
  본 GUI 의 "로그/활동" 은 (1) 룰 카운터 (2) conntrack (3) 위 event log 를 근거로 한다.

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
EVENT_DIR = "/var/log/nft_edu"
EVENT_LOG = os.path.join(EVENT_DIR, "events.log")
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

# 변경을 허용하는 table (family, name). Docker 의 ip nat 는 제외.
ALLOWED_TABLES = {("inet", "six_filter"), ("ip", "six_nat")}
OSSEC_CONF = "/var/ossec/etc/ossec.conf"
WAZUH_CTL = "/var/ossec/bin/wazuh-control"


# ────────────────────────────── shell helpers ──────────────────────────────
def run(cmd, timeout=15):
    """cmd: list 또는 str. dict{rc,stdout,stderr,cmd} 반환."""
    if isinstance(cmd, str):
        argv = shlex.split(cmd)
    else:
        argv = cmd
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr,
                "cmd": " ".join(shlex.quote(a) for a in argv)}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout", "cmd": " ".join(argv)}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e), "cmd": " ".join(argv)}


def log_event(action, detail):
    try:
        os.makedirs(EVENT_DIR, exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "source": "nft_edu_gui",
               "action": action}
        rec.update(detail)
        with open(EVENT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:  # 로깅 실패가 기능을 막지 않도록
        sys.stderr.write("[nft_edu_gui] log_event fail: %s\n" % e)


# ────────────────────────────── nft state ──────────────────────────────
def nft_json():
    """nft -j list ruleset → dict. 실패 시 {'error':...}."""
    r = run(["nft", "-j", "list", "ruleset"])
    if r["rc"] != 0:
        return {"error": r["stderr"] or "nft -j failed", "raw": r}
    try:
        return json.loads(r["stdout"])
    except Exception as e:
        return {"error": "json parse: %s" % e, "raw": r["stdout"][:500]}


def _expr_to_text(exprs):
    """nft JSON expr 리스트를 사람이 읽는 짧은 매칭/액션 문자열로."""
    matchers, action, counter, logp = [], "", None, None
    for e in exprs:
        if "match" in e:
            m = e["match"]
            left, right, op = m.get("left"), m.get("right"), m.get("op", "==")
            field = _fmt_left(left)
            val = _fmt_right(right)
            txt = "%s %s %s" % (field, op if op != "==" else "", val)
            matchers.append(re.sub(r"\s+", " ", txt).strip())
        elif "counter" in e:
            c = e["counter"]
            if isinstance(c, dict):
                counter = "counter pkts %s bytes %s" % (c.get("packets", 0), c.get("bytes", 0))
            else:
                counter = "counter"
        elif "log" in e:
            lg = e["log"]
            logp = "log %s" % (("prefix %r" % lg.get("prefix")) if isinstance(lg, dict) and lg.get("prefix") else "")
        elif "accept" in e:
            action = "accept"
        elif "drop" in e:
            action = "drop"
        elif "reject" in e:
            action = "reject"
        elif "dnat" in e:
            d = e["dnat"]
            action = "dnat to %s" % _fmt_nat(d)
        elif "snat" in e:
            action = "snat to %s" % _fmt_nat(e["snat"])
        elif "masquerade" in e:
            action = "masquerade"
        elif "ct" in e:
            pass  # ct state 등은 match 로 처리되거나 표시 생략
    return matchers, action, counter, logp


def _fmt_left(left):
    if isinstance(left, dict):
        if "payload" in left:
            p = left["payload"]
            return "%s %s" % (p.get("protocol", ""), p.get("field", ""))
        if "meta" in left:
            return "meta %s" % left["meta"].get("key", "")
        if "ct" in left:
            return "ct %s" % left["ct"].get("key", "")
    return str(left)


def _fmt_right(right):
    if isinstance(right, dict):
        if "set" in right:
            return ",".join(str(_fmt_right(x)) for x in right["set"])
        if "prefix" in right:
            return "%s/%s" % (right["prefix"].get("addr"), right["prefix"].get("len"))
        return json.dumps(right, ensure_ascii=False)
    if isinstance(right, list):
        return ",".join(str(_fmt_right(x)) for x in right)
    return str(right)


def _fmt_nat(d):
    if isinstance(d, dict):
        addr = d.get("addr", "")
        port = d.get("port", "")
        return "%s%s" % (addr, ":%s" % port if port else "")
    return str(d)


def ruleset_model():
    """UI 친화 구조: tables → chains → rules(handle/counter/text/editable)."""
    data = nft_json()
    if "error" in data:
        return {"error": data["error"]}
    tables, chains, rules = {}, {}, []
    for item in data.get("nftables", []):
        if "table" in item:
            t = item["table"]
            key = "%s %s" % (t["family"], t["name"])
            tables[key] = {"family": t["family"], "name": t["name"], "chains": [],
                           "editable": (t["family"], t["name"]) in ALLOWED_TABLES,
                           "docker": t["name"] in ("nat", "DOCKER")}
        elif "chain" in item:
            c = item["chain"]
            key = "%s %s" % (c["family"], c["table"])
            ch = {"family": c["family"], "table": c["table"], "name": c["name"],
                  "type": c.get("type"), "hook": c.get("hook"), "policy": c.get("policy"),
                  "prio": c.get("prio"), "rules": []}
            chains["%s/%s" % (key, c["name"])] = ch
            if key in tables:
                tables[key]["chains"].append(ch)
        elif "rule" in item:
            ru = item["rule"]
            key = "%s %s" % (ru["family"], ru["table"])
            matchers, action, counter, logp = _expr_to_text(ru.get("expr", []))
            pkts = bytes_ = 0
            for e in ru.get("expr", []):
                if "counter" in e and isinstance(e["counter"], dict):
                    pkts = e["counter"].get("packets", 0)
                    bytes_ = e["counter"].get("bytes", 0)
            rdict = {"family": ru["family"], "table": ru["table"], "chain": ru["chain"],
                     "handle": ru.get("handle"), "matchers": matchers, "action": action,
                     "counter": counter, "log": logp, "packets": pkts, "bytes": bytes_,
                     "editable": (ru["family"], ru["table"]) in ALLOWED_TABLES}
            rules.append(rdict)
            ck = "%s/%s" % (key, ru["chain"])
            if ck in chains:
                chains[ck]["rules"].append(rdict)
    return {"tables": list(tables.values())}


def interfaces():
    r = run(["ip", "-br", "-o", "addr"])
    out = []
    zone = {"eth0": "ext (외부/HAProxy 입구)", "eth1": "pipe (fw↔ips 사이망)",
            "lo": "loopback"}
    for ln in r["stdout"].splitlines():
        parts = ln.split()
        if not parts:
            continue
        name = parts[0].split("@")[0]
        state = parts[1] if len(parts) > 1 else ""
        addrs = [p for p in parts[2:] if ":" not in p or "/" in p]
        out.append({"name": name, "state": state,
                    "addrs": [a for a in parts[2:] if "/" in a],
                    "zone": zone.get(name, "")})
    return out


def conntrack():
    r = run(["conntrack", "-L"], timeout=10)
    conns, summary = [], {}
    for ln in r["stdout"].splitlines():
        toks = ln.split()
        if len(toks) < 4:
            continue
        proto = toks[0]
        state = ""
        kv = {}
        for t in toks:
            if "=" in t:
                k, v = t.split("=", 1)
                kv.setdefault(k, v)
            elif t.isupper() and len(t) > 2 and "[" not in t and t not in ("ASSURED", "UNREPLIED"):
                state = t  # TCP 상태(ESTABLISHED 등). [ASSURED]/[UNREPLIED] 는 별도 플래그.
        conns.append({"proto": proto, "state": state,
                      "src": kv.get("src"), "dst": kv.get("dst"),
                      "sport": kv.get("sport"), "dport": kv.get("dport"),
                      "assured": "[ASSURED]" in ln, "unreplied": "[UNREPLIED]" in ln})
        summary[state or proto] = summary.get(state or proto, 0) + 1
    return {"count": len(conns), "summary": summary, "conns": conns[:200],
            "error": r["stderr"] if r["rc"] != 0 else None}


# ────────────────────────────── command builders ──────────────────────────────
def build_filter_cmd(p):
    """폼 입력 → nft add/insert rule 명령 문자열 생성 (실행 X)."""
    family, table = "inet", "six_filter"
    chain = p.get("chain", "input")
    if chain not in ("input", "forward", "output"):
        raise ValueError("chain 은 input/forward/output 만 가능")
    parts = []
    if p.get("iif"):
        parts.append('iifname "%s"' % _safe(p["iif"]))
    if p.get("oif"):
        parts.append('oifname "%s"' % _safe(p["oif"]))
    if p.get("saddr"):
        parts.append("ip saddr %s" % _addr_or_set(p["saddr"]))
    if p.get("daddr"):
        parts.append("ip daddr %s" % _addr_or_set(p["daddr"]))
    proto = p.get("proto", "")
    if proto in ("tcp", "udp"):
        if p.get("dport"):
            parts.append("%s dport %s" % (proto, _safe_port(p["dport"])))
        elif p.get("sport"):
            parts.append("%s sport %s" % (proto, _safe_port(p["sport"])))
        else:
            parts.append("ip protocol %s" % proto)
    elif proto == "icmp":
        parts.append("ip protocol icmp")
    if p.get("ct_state"):
        parts.append("ct state %s" % _safe(p["ct_state"]))
    if p.get("limit_rate"):
        # 예: "5/minute", "10/second" — brute force / flood 완화.
        # limit_over=True 면 'limit rate over X' (초과분만 매칭) → drop 과 결합.
        over = "over " if p.get("limit_over") else ""
        parts.append("limit rate %s%s" % (over, _safe_rate(p["limit_rate"])))
    parts.append("counter")
    if p.get("log"):
        prefix = _safe(p.get("log_prefix") or "EDU: ")
        parts.append('log prefix "%s"' % prefix)
    action = p.get("action", "accept")
    if action not in ("accept", "drop", "reject"):
        raise ValueError("action 은 accept/drop/reject")
    parts.append(action)
    verb = "insert" if p.get("position") == "top" else "add"
    body = " ".join(parts)
    return "nft %s rule %s %s %s %s" % (verb, family, table, chain, body)


def build_nat_cmd(p):
    family, table = "ip", "six_nat"
    kind = p.get("kind", "dnat")
    if kind == "dnat":
        chain = "prerouting"
        parts = ['iifname "%s"' % _safe(p.get("iif", "eth0"))]
        proto = p.get("proto", "tcp")
        if proto not in ("tcp", "udp"):
            raise ValueError("proto tcp/udp")
        parts.append("%s dport %s" % (proto, _safe_port(p["dport"])))
        parts.append("counter")
        tgt = "%s:%s" % (_safe_addr(p["to_ip"]), _safe_port(p["to_port"]))
        parts.append("dnat to %s" % tgt)
        return "nft add rule %s %s %s %s" % (family, table, chain, " ".join(parts))
    elif kind in ("snat", "masquerade"):
        chain = "postrouting"
        parts = ['oifname "%s"' % _safe(p.get("oif", "eth1"))]
        if p.get("saddr"):
            parts.append("ip saddr %s" % _safe_addr(p["saddr"]))
        parts.append("counter")
        if kind == "snat":
            parts.append("snat to %s" % _safe_addr(p["to_ip"]))
        else:
            parts.append("masquerade")
        return "nft add rule %s %s %s %s" % (family, table, chain, " ".join(parts))
    raise ValueError("kind dnat/snat/masquerade")


_ADDR_RE = re.compile(r"^[0-9a-fA-F:.\/,{} -]+$")
_PORT_RE = re.compile(r"^[0-9,{} -]+$")
_TOK_RE = re.compile(r"^[A-Za-z0-9_,./: -]+$")


def _safe(s):
    s = str(s)
    if not _TOK_RE.match(s):
        raise ValueError("허용되지 않는 문자: %r" % s)
    return s


def _safe_addr(s):
    s = str(s).strip()
    if not _ADDR_RE.match(s):
        raise ValueError("주소 형식 오류: %r" % s)
    return s


def _safe_port(s):
    s = str(s).strip()
    if not _PORT_RE.match(s):
        raise ValueError("포트 형식 오류: %r" % s)
    return s


_RATE_RE = re.compile(r"^\d+/(second|minute|hour|day)$")


def _safe_rate(s):
    s = str(s).strip()
    if not _RATE_RE.match(s):
        raise ValueError("rate 형식 오류 (예: 5/minute): %r" % s)
    return s


# ── 객체(Object/Alias/그룹) = nftables named set ──
_SETNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")
SET_TYPES = {"ipv4_addr": "IP 주소 그룹", "inet_service": "포트 그룹"}


def _safe_setname(s):
    s = str(s).strip()
    if not _SETNAME_RE.match(s):
        raise ValueError("그룹 이름은 영문/숫자/_ 만 (첫 글자 영문/_), 최대 32자: %r" % s)
    return s


def _addr_or_set(s):
    """주소 또는 @그룹이름. 룰에서 saddr/daddr 에 그룹 참조 허용."""
    s = str(s).strip()
    if s.startswith("@"):
        return "@" + _safe_setname(s[1:])
    return _safe_addr(s)


def _safe_elements(s, typ):
    items = [x for x in re.split(r"[ ,]+", str(s)) if x]
    out = []
    for it in items:
        out.append(_safe_addr(it) if typ == "ipv4_addr" else _safe_port(it))
    if not out:
        raise ValueError("구성원(elements)이 비어 있습니다")
    return out


def build_set_cmds(p):
    """폼 → named set 생성/구성원 추가 명령 (실행 X)."""
    name = _safe_setname(p.get("name", ""))
    typ = p.get("type", "ipv4_addr")
    if typ not in SET_TYPES:
        raise ValueError("종류는 ipv4_addr / inet_service")
    elems = _safe_elements(p.get("elements", ""), typ)
    create = "nft add set inet six_filter %s { type %s ; }" % (name, typ)
    element = "nft add element inet six_filter %s { %s }" % (name, ", ".join(elems))
    return {"create": create, "element": element, "commands": create + "\n" + element}


def objects_model():
    data = nft_json()
    if "error" in data:
        return {"error": data["error"], "objects": []}
    out = []
    for i in data.get("nftables", []):
        if "set" in i:
            s = i["set"]
            if (s.get("family"), s.get("table")) in ALLOWED_TABLES:
                elem = s.get("elem") or []
                vals = [e if isinstance(e, str) else json.dumps(e, ensure_ascii=False) for e in elem]
                out.append({"name": s.get("name"), "family": s.get("family"),
                            "table": s.get("table"), "type": s.get("type"),
                            "type_label": SET_TYPES.get(s.get("type"), s.get("type")),
                            "elements": vals})
    return {"objects": out}


def _set_type_of(name):
    for o in objects_model().get("objects", []):
        if o["name"] == name:
            return o["type"]
    return None


def apply_set(create, element):
    ok, why = _is_allowed_obj(create)
    if not ok:
        return {"ok": False, "error": why}
    r1 = run(create)
    if r1["rc"] != 0:
        return {"ok": False, "error": "set 생성 실패: " + r1["stderr"].strip(), "objects": objects_model()}
    r2 = {"rc": 0, "stderr": ""}
    if element:
        ok2, why2 = _is_allowed_obj(element)
        if not ok2:
            return {"ok": False, "error": why2}
        r2 = run(element)
    log_event("object_apply", {"create": create, "element": element, "rc": r2["rc"]})
    return {"ok": r2["rc"] == 0, "result": {"create": r1, "element": r2}, "objects": objects_model()}


def object_element(name, elements, action):
    name = _safe_setname(name)
    typ = _set_type_of(name)
    if not typ:
        return {"ok": False, "error": "그룹 %s 없음" % name}
    elems = _safe_elements(elements, typ)
    verb = "add" if action == "add" else "delete"
    cmd = "nft %s element inet six_filter %s { %s }" % (verb, name, ", ".join(elems))
    r = run(cmd)
    log_event("object_element", {"command": cmd, "rc": r["rc"]})
    return {"ok": r["rc"] == 0, "result": r, "objects": objects_model()}


def delete_set(name):
    name = _safe_setname(name)
    cmd = "nft delete set inet six_filter %s" % name
    r = run(cmd)
    log_event("object_delete", {"name": name, "rc": r["rc"]})
    if r["rc"] != 0:
        return {"ok": False, "error": "삭제 실패(룰이 이 그룹을 참조 중이면 먼저 룰을 지우세요): "
                + r["stderr"].strip(), "objects": objects_model()}
    return {"ok": True, "objects": objects_model()}


def _is_allowed_obj(cmd):
    toks = shlex.split(cmd)
    if len(toks) < 5 or toks[0] != "nft" or toks[1] not in ("add", "delete"):
        return False, "add/delete set|element 만 허용"
    if toks[2] not in ("set", "element"):
        return False, "set/element 명령이 아님"
    if (toks[3], toks[4]) not in ALLOWED_TABLES:
        return False, "%s %s 는 변경 불가 (six_filter/six_nat 만)" % (toks[3], toks[4])
    return True, ""


def _is_allowed_apply(cmd):
    """apply 안전장치: add/insert rule 이고 대상이 허용 table 인지."""
    toks = shlex.split(cmd)
    if len(toks) < 6 or toks[0] != "nft":
        return False, "nft 명령이 아님"
    if toks[1] not in ("add", "insert"):
        return False, "add/insert rule 만 적용 가능 (삭제는 별도 API)"
    if toks[2] != "rule":
        return False, "rule 명령이 아님"
    fam, tbl = toks[3], toks[4]
    if (fam, tbl) not in ALLOWED_TABLES:
        return False, "%s %s 는 변경 불가 (six_filter/six_nat 만 허용)" % (fam, tbl)
    return True, ""


# ────────────────────────────── SIEM (Wazuh agent) ──────────────────────────────
SIEM_BLOCK = (
    "  <localfile>\n"
    "    <log_format>json</log_format>\n"
    "    <location>%s</location>\n"
    "  </localfile>\n" % EVENT_LOG
)


def siem_status():
    has = False
    try:
        with open(OSSEC_CONF, encoding="utf-8") as f:
            has = EVENT_LOG in f.read()
    except Exception:
        pass
    st = run([WAZUH_CTL, "status"])
    agentd = "wazuh-agentd is running" in st["stdout"] or "wazuh-logcollector is running" in st["stdout"]
    return {"integrated": has, "agent_running": agentd, "manager": _siem_manager(),
            "event_log": EVENT_LOG, "status_raw": st["stdout"][-600:]}


def _siem_manager():
    try:
        with open(OSSEC_CONF, encoding="utf-8") as f:
            m = re.search(r"<address>([^<]+)</address>", f.read())
            return m.group(1) if m else None
    except Exception:
        return None


def siem_enable():
    try:
        with open(OSSEC_CONF, encoding="utf-8") as f:
            conf = f.read()
        if EVENT_LOG in conf:
            return {"ok": True, "msg": "이미 연동됨", "restart": None}
        # </ossec_config> 직전에 삽입
        idx = conf.rfind("</ossec_config>")
        if idx < 0:
            return {"ok": False, "msg": "ossec.conf 형식 인식 실패"}
        newconf = conf[:idx] + SIEM_BLOCK + conf[idx:]
        os.makedirs(EVENT_DIR, exist_ok=True)
        open(EVENT_LOG, "a").close()
        with open(OSSEC_CONF, "w", encoding="utf-8") as f:
            f.write(newconf)
        r = run([WAZUH_CTL, "restart"], timeout=40)
        log_event("siem_enable", {"detail": "localfile 추가 + agent restart", "rc": r["rc"]})
        return {"ok": r["rc"] == 0, "msg": "localfile 추가 + 에이전트 재시작",
                "restart": r["stdout"][-400:]}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


def siem_disable():
    try:
        with open(OSSEC_CONF, encoding="utf-8") as f:
            conf = f.read()
        if SIEM_BLOCK in conf:
            conf = conf.replace(SIEM_BLOCK, "")
            with open(OSSEC_CONF, "w", encoding="utf-8") as f:
                f.write(conf)
            r = run([WAZUH_CTL, "restart"], timeout=40)
            log_event("siem_disable", {"rc": r["rc"]})
            return {"ok": r["rc"] == 0, "msg": "localfile 제거 + 재시작"}
        return {"ok": True, "msg": "연동 항목 없음"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


# ────────────────────────────── scenarios ──────────────────────────────
def load_scenarios():
    p = os.path.join(STATIC, "scenarios.json")
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return {"error": str(e), "scenarios": []}


def check_scenario(sid):
    """시나리오 검증: 학생이 만든 룰이 기대 조건을 충족하는지 실측.

    각 시나리오의 check 규약(scenarios.json) 종류:
      - rule_match: 현재 ruleset 텍스트에 require(정규식 전부) 포함 + forbid 미포함
      - counter_gt: 특정 매칭 룰의 packets 가 0 초과 (실제 트래픽이 룰을 탐)
      - nat_present: six_nat 에 dnat/snat 존재
    """
    data = load_scenarios()
    sc = next((s for s in data.get("scenarios", []) if s.get("id") == sid), None)
    if not sc:
        return {"ok": False, "msg": "시나리오 없음: %s" % sid}
    chk = sc.get("check", {})
    raw = run(["nft", "-a", "list", "ruleset"])["stdout"]
    typ = chk.get("type")
    evid = []
    if typ == "rule_match":
        for rx in chk.get("require", []):
            ok = re.search(rx, raw) is not None
            evid.append({"require": rx, "found": ok})
        for rx in chk.get("forbid", []):
            bad = re.search(rx, raw) is not None
            evid.append({"forbid": rx, "present": bad})
        passed = all(e.get("found", True) for e in evid if "require" in e) and \
                 all(not e.get("present", False) for e in evid if "forbid" in e)
        return {"ok": passed, "evidence": evid, "hint": sc.get("hint")}
    if typ == "counter_gt":
        # require 정규식이 매칭되는 룰 라인에서 packets N 추출
        target_re = chk["match"]
        threshold = chk.get("gt", 0)
        found = None
        for ln in raw.splitlines():
            if re.search(target_re, ln):
                m = re.search(r"packets (\d+)", ln)
                if m:
                    found = int(m.group(1))
                    evid.append({"line": ln.strip(), "packets": found})
                    break
        passed = found is not None and found > threshold
        return {"ok": passed, "evidence": evid,
                "msg": "패킷 %s > %s" % (found, threshold) if found is not None else "매칭 룰 없음",
                "hint": sc.get("hint")}
    if typ == "nat_present":
        rx = chk["match"]
        ok = re.search(rx, raw) is not None
        return {"ok": ok, "evidence": [{"match": rx, "found": ok}], "hint": sc.get("hint")}
    return {"ok": False, "msg": "알 수 없는 check type: %s" % typ}


# ────────────────────────────── HTTP handler ──────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "nft_edu_gui/1.0"

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

    def log_message(self, fmt, *args):
        pass  # 콘솔 조용히

    # ---- static ----
    def _serve_static(self, path):
        if path in ("/", ""):
            path = "/index.html"
        # /static/<f> URL → STATIC/<f> (STATIC 이 이미 .../static 이므로 접두어 제거)
        rel = path[len("/static/"):] if path.startswith("/static/") else path.lstrip("/")
        safe = os.path.normpath(rel)
        full = os.path.join(STATIC, safe)
        if not full.startswith(STATIC) or not os.path.isfile(full):
            return self._send(404, {"error": "not found"})
        ctype = {"html": "text/html; charset=utf-8", "js": "application/javascript; charset=utf-8",
                 "css": "text/css; charset=utf-8", "json": "application/json; charset=utf-8",
                 "svg": "image/svg+xml"}.get(full.rsplit(".", 1)[-1], "text/plain; charset=utf-8")
        with open(full, "rb") as f:
            self._send(200, f.read(), ctype)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        path, q = u.path, urllib.parse.parse_qs(u.query)
        try:
            if path == "/api/status":
                rs = ruleset_model()
                nrules = sum(len(c["rules"]) for t in rs.get("tables", []) for c in t["chains"]) \
                    if "tables" in rs else 0
                return self._send(200, {
                    "hostname": run(["hostname"])["stdout"].strip(),
                    "nft_version": run(["nft", "--version"])["stdout"].strip(),
                    "interfaces": interfaces(),
                    "tables": [{"family": t["family"], "name": t["name"],
                                "editable": t["editable"], "chains": len(t["chains"])}
                               for t in rs.get("tables", [])],
                    "rule_count": nrules,
                    "conntrack_count": conntrack()["count"],
                })
            if path == "/api/ruleset":
                m = ruleset_model()
                m["raw"] = run(["nft", "-a", "list", "ruleset"])["stdout"]
                return self._send(200, m)
            if path == "/api/conntrack":
                return self._send(200, conntrack())
            if path == "/api/objects":
                return self._send(200, objects_model())
            if path == "/api/events":
                n = int(q.get("n", ["100"])[0])
                lines = []
                try:
                    with open(EVENT_LOG, encoding="utf-8") as f:
                        for ln in f.readlines()[-n:]:
                            try:
                                lines.append(json.loads(ln))
                            except Exception:
                                lines.append({"raw": ln.strip()})
                except FileNotFoundError:
                    pass
                return self._send(200, {"events": lines, "path": EVENT_LOG})
            if path == "/api/siem":
                return self._send(200, siem_status())
            if path == "/api/scenarios":
                return self._send(200, load_scenarios())
            return self._serve_static(path)
        except Exception as e:
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path
        b = self._body()
        try:
            if path == "/api/rule/preview":
                return self._send(200, {"command": build_filter_cmd(b)})
            if path == "/api/nat/preview":
                return self._send(200, {"command": build_nat_cmd(b)})
            if path in ("/api/rule/apply", "/api/nat/apply"):
                cmd = b.get("command", "")
                ok, why = _is_allowed_apply(cmd)
                if not ok:
                    return self._send(400, {"ok": False, "error": why})
                r = run(cmd)
                log_event("apply", {"command": cmd, "rc": r["rc"], "stderr": r["stderr"].strip()})
                return self._send(200, {"ok": r["rc"] == 0, "result": r,
                                        "ruleset": ruleset_model()})
            if path == "/api/rule/delete":
                fam, tbl = b.get("family"), b.get("table")
                if (fam, tbl) not in ALLOWED_TABLES:
                    return self._send(400, {"ok": False, "error": "삭제 불가 table"})
                chain, handle = b.get("chain"), int(b.get("handle"))
                cmd = "nft delete rule %s %s %s handle %d" % (fam, tbl, _safe(chain), handle)
                r = run(cmd)
                log_event("delete", {"command": cmd, "rc": r["rc"]})
                return self._send(200, {"ok": r["rc"] == 0, "result": r,
                                        "ruleset": ruleset_model()})
            if path == "/api/object/preview":
                return self._send(200, build_set_cmds(b))
            if path == "/api/object/apply":
                return self._send(200, apply_set(b.get("create", ""), b.get("element", "")))
            if path == "/api/object/element":
                return self._send(200, object_element(b.get("name"), b.get("elements", ""),
                                                       b.get("action", "add")))
            if path == "/api/object/delete":
                return self._send(200, delete_set(b.get("name", "")))
            if path == "/api/counters/reset":
                r1 = run(["nft", "reset", "counters", "table", "inet", "six_filter"])
                r2 = run(["nft", "reset", "counters", "table", "ip", "six_nat"])
                log_event("counters_reset", {"rc": r1["rc"]})
                return self._send(200, {"ok": r1["rc"] == 0, "filter": r1["stderr"],
                                        "nat": r2["stderr"]})
            if path == "/api/siem/enable":
                return self._send(200, siem_enable())
            if path == "/api/siem/disable":
                return self._send(200, siem_disable())
            if path == "/api/scenario/check":
                return self._send(200, check_scenario(b.get("id")))
            if path == "/api/cleanup":
                # 운영 SOP — 임시 룰 정리. 두 사용자 테이블의 모든 chain 을 flush 하고
                # 사용자 set 을 삭제한다. table/chain 정의(hook) 는 보존한다.
                actions = []
                for fam, tbl in (("inet", "six_filter"), ("ip", "six_nat")):
                    ls = run(["nft", "-j", "list", "table", fam, tbl])
                    try:
                        data = json.loads(ls["stdout"]) if ls["rc"] == 0 else {"nftables": []}
                    except Exception:
                        data = {"nftables": []}
                    for entry in data.get("nftables", []):
                        ch = entry.get("chain")
                        if ch and ch.get("table") == tbl and ch.get("family") == fam:
                            r = run(["nft", "flush", "chain", fam, tbl, ch["name"]])
                            actions.append({"flush_chain": "%s/%s/%s" % (fam, tbl, ch["name"]),
                                            "rc": r["rc"]})
                        st = entry.get("set")
                        if st and st.get("table") == tbl and st.get("family") == fam:
                            r = run(["nft", "delete", "set", fam, tbl, st["name"]])
                            actions.append({"delete_set": "%s/%s/%s" % (fam, tbl, st["name"]),
                                            "rc": r["rc"]})
                log_event("cleanup", {"actions": len(actions)})
                return self._send(200, {"ok": True, "status": "cleaned",
                                         "actions": actions, "count": len(actions)})
            return self._send(404, {"error": "unknown endpoint"})
        except ValueError as e:
            return self._send(400, {"ok": False, "error": str(e)})
        except Exception as e:
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})


def main():
    try:
        os.makedirs(EVENT_DIR, exist_ok=True)
    except Exception as e:
        sys.stderr.write("[nft_edu_gui] EVENT_DIR 생성 불가 (%s) — 이벤트 로그 비활성\n" % e)
    log_event("boot", {"port": PORT})
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    sys.stderr.write("[nft_edu_gui] listening on 0.0.0.0:%d (static=%s)\n" % (PORT, STATIC))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
