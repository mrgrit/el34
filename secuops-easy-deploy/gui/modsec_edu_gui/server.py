#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""modsec_edu_gui — WAF(ModSecurity) 교육용 GUI 백엔드.

el34 secuops-easy 특강용. el34-web 컨테이너 안에서 root 로 실행되며, 학생이 웹 UI 에서
탐지룰(SecRule)을 구성하면 그것이 만들어내는 **실제 SecRule 한 줄** 을 미리보기로 보여준 뒤
/etc/modsecurity/edu_rules.conf 에 적용하고 apache2ctl configtest → graceful 로 반영한다.

안전 설계 (운영 WAF 보호)
- 적용 시: 새 룰을 파일에 쓰기 전 현재 내용을 백업 → 쓰기 → `apache2ctl configtest`.
  Syntax OK 면 graceful reload, 아니면 **즉시 백업 복원**하고 문법 오류를 반환한다.
  → 잘못된 룰이 Apache 를 죽이지 않는다.
- GUI 룰 id 는 9000000 이상 자동 배정 (CRS 900000-999999 와 분리). 삭제는 id 기준.
- 입력값(변수/연산자/패턴/액션)은 정규식 화이트리스트로 검증.

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

MODSEC_CONF = "/etc/modsecurity/modsecurity.conf"
EDU_RULES = "/etc/modsecurity/edu_rules.conf"
CRS_DIR = "/usr/share/modsecurity-crs/rules"
AUDIT_LOG = "/var/log/apache2/modsec_audit.log"
APACHECTL = "apache2ctl"
EDU_ID_BASE = 9000000

OSSEC_CONF = "/var/ossec/etc/ossec.conf"
WAZUH_CTL = "/var/ossec/bin/wazuh-control"

VARIABLES = ["REQUEST_URI", "ARGS", "ARGS_NAMES", "QUERY_STRING", "REQUEST_BODY",
             "REQUEST_HEADERS", "REQUEST_HEADERS:User-Agent", "REQUEST_COOKIES",
             "REQUEST_FILENAME", "REQUEST_LINE", "REQUEST_HEADERS:Referer"]
OPERATORS = ["@rx", "@contains", "@pm", "@streq", "@beginsWith", "@endsWith"]
TRANSFORMS = ["lowercase", "urlDecodeUni", "removeNulls", "compressWhitespace", "none"]
ACTIONS = ["deny", "pass", "drop", "block"]
SEVERITIES = ["CRITICAL", "ERROR", "WARNING", "NOTICE"]


# ────────────────────────────── helpers ──────────────────────────────
def run(cmd, timeout=25):
    argv = shlex.split(cmd) if isinstance(cmd, str) else cmd
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "stdout": "", "stderr": str(e)}


EVENT_LOG = "/var/log/nft_edu/modsec_edu_events.log"


def log_event(action, detail):
    try:
        os.makedirs(os.path.dirname(EVENT_LOG), exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "source": "modsec_edu_gui", "action": action}
        rec.update(detail)
        with open(EVENT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        sys.stderr.write("[modsec_edu_gui] log_event fail: %s\n" % e)


def tail_lines(path, n=80, maxbytes=900000):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            start = max(0, size - maxbytes)
            f.seek(start)
            data = f.read()
        lines = data.decode("utf-8", "ignore").splitlines()
        if start > 0 and lines:
            lines = lines[1:]
        return lines[-n:]
    except FileNotFoundError:
        return []


def grep_conf(path, keys):
    out = {}
    try:
        txt = open(path, encoding="utf-8").read()
        for k in keys:
            m = re.search(r"^\s*%s\s+(.+)$" % re.escape(k), txt, re.M)
            out[k] = m.group(1).strip() if m else None
    except Exception as e:
        out["_error"] = str(e)
    return out


# ────────────────────────────── SecRule build / parse ──────────────────────────────
def _id_in(s):
    return bool(re.match(r"^\d+$", str(s)))


def build_secrule(p):
    var = p.get("variable", "REQUEST_URI")
    if var not in VARIABLES:
        raise ValueError("허용되지 않는 변수")
    op = p.get("operator", "@rx")
    if op not in OPERATORS:
        raise ValueError("허용되지 않는 연산자")
    pattern = _pat(p.get("pattern", ""))
    if not pattern:
        raise ValueError("탐지 패턴이 비어 있습니다")
    phase = str(p.get("phase", "2"))
    if phase not in ("1", "2"):
        raise ValueError("phase 는 1 또는 2")
    action = p.get("action", "deny")
    if action not in ACTIONS:
        raise ValueError("허용되지 않는 액션")
    sev = p.get("severity", "CRITICAL")
    if sev not in SEVERITIES:
        raise ValueError("허용되지 않는 severity")
    transforms = p.get("transforms") or ["none"]
    if isinstance(transforms, str):
        transforms = [transforms]
    tparts = []
    for t in transforms:
        if t not in TRANSFORMS:
            raise ValueError("허용되지 않는 transform: %s" % t)
        tparts.append("t:%s" % t)
    rid = p.get("id")
    rid = int(rid) if _id_in(rid) else next_id()
    msg = _msg(p.get("msg") or "EDU custom WAF rule")
    acts = ["id:%d" % rid, "phase:%s" % phase] + tparts + [action]
    if action == "deny":
        acts.append("status:%s" % str(p.get("status", "403")))
    acts += ["log", "msg:'%s'" % msg, "severity:'%s'" % sev]
    return 'SecRule %s "%s %s" "%s"' % (var, op, pattern, ",".join(acts))


_SECRULE_RE = re.compile(r'^\s*SecRule\s+(?P<vars>\S+)\s+"(?P<opval>(?:[^"\\]|\\.)*)"\s+"(?P<acts>(?:[^"\\]|\\.)*)"\s*$')


def parse_secrule(line):
    line = line.strip()
    m = _SECRULE_RE.match(line)
    if not m:
        # SecAction / chained / 멀티라인 등은 간이 처리
        return {"error": "SecRule 형식을 인식할 수 없습니다 (한 줄 SecRule 만 지원).", "raw": line}
    vars_ = m.group("vars")
    opval = m.group("opval").strip()
    op_m = re.match(r"^(@\w+)\s*(.*)$", opval)
    operator = op_m.group(1) if op_m else "(implicit @rx)"
    pattern = op_m.group(2) if op_m else opval
    # 액션을 콤마로 분리하되 작은따옴표 안의 콤마는 보존
    acts, cur, in_q = [], "", False
    for ch in m.group("acts"):
        if ch == "'":
            in_q = not in_q
        if ch == "," and not in_q:
            if cur.strip():
                acts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        acts.append(cur.strip())
    adict = {}
    for a in acts:
        if ":" in a:
            k, v = a.split(":", 1)
            adict[k.strip()] = v.strip().strip("'")
        else:
            adict[a.strip()] = True
    return {"variables": vars_, "operator": operator, "pattern": pattern,
            "actions": acts, "id": adict.get("id"), "phase": adict.get("phase"),
            "msg": adict.get("msg"), "severity": adict.get("severity"), "raw": line}


def _pat(s):
    # 패턴: 큰따옴표만 제거(룰이 큰따옴표로 감싸짐), 길이 제한
    return str(s).replace('"', "")[:300]
def _msg(s):
    return re.sub(r"['\"\\]", "", str(s))[:120]


def next_id():
    mx = EDU_ID_BASE
    try:
        for s in re.findall(r"id:(\d+)", open(EDU_RULES, encoding="utf-8").read()):
            if int(s) >= EDU_ID_BASE and int(s) > mx:
                mx = int(s)
    except FileNotFoundError:
        pass
    return mx + 1


def list_edu_rules():
    out = []
    try:
        for ln in open(EDU_RULES, encoding="utf-8"):
            s = ln.strip()
            if s.startswith("SecRule"):
                p = parse_secrule(s)
                if "error" not in p:
                    out.append({"id": p["id"], "msg": p["msg"], "variables": p["variables"],
                                "operator": p["operator"], "pattern": p["pattern"], "raw": s})
    except FileNotFoundError:
        pass
    return out


def apply_secrule(line):
    """edu_rules.conf 에 append. configtest 통과 시에만 graceful. 실패 시 백업 복원."""
    prev = ""
    if os.path.isfile(EDU_RULES):
        prev = open(EDU_RULES, encoding="utf-8").read()
    rid_m = re.search(r"id:(\d+)", line)
    rid = rid_m.group(1) if rid_m else None
    with open(EDU_RULES, "w", encoding="utf-8") as f:
        f.write(prev + line.rstrip() + "\n")
    ct = run([APACHECTL, "configtest"])
    if "Syntax OK" not in (ct["stdout"] + ct["stderr"]):
        # 복원
        with open(EDU_RULES, "w", encoding="utf-8") as f:
            f.write(prev)
        log_event("rule_apply_fail", {"id": rid, "error": (ct["stderr"] or ct["stdout"])[:200]})
        return {"ok": False, "error": "문법 오류 — 룰이 적용되지 않았고 기존 설정은 보존됨.",
                "detail": (ct["stderr"] or ct["stdout"]).strip()[-400:]}
    gr = run([APACHECTL, "graceful"])
    log_event("rule_apply", {"id": rid, "rule": line[:200]})
    return {"ok": gr["rc"] == 0, "id": rid, "reload": "graceful",
            "note": "configtest 통과 + graceful reload 완료. 룰이 살아있습니다."}


def delete_edu_rule(rid):
    rid = str(int(rid))
    try:
        lines = open(EDU_RULES, encoding="utf-8").readlines()
    except FileNotFoundError:
        return {"ok": False, "msg": "edu_rules.conf 없음"}
    kept = [ln for ln in lines if ("id:%s," % rid) not in ln and not re.search(r"id:%s\b" % rid, ln)]
    if len(kept) == len(lines):
        return {"ok": False, "msg": "id %s 룰 없음" % rid}
    open(EDU_RULES, "w", encoding="utf-8").writelines(kept)
    run([APACHECTL, "graceful"])
    log_event("rule_delete", {"id": rid})
    return {"ok": True, "id": rid}


# ────────────────────────────── audit log ──────────────────────────────
def parse_audit(j):
    req = j.get("request", {})
    rl = req.get("request_line", "")
    parts = rl.split()
    method = parts[0] if parts else ""
    uri = parts[1] if len(parts) > 1 else ""
    status = j.get("response", {}).get("status")
    ad = j.get("audit_data", {})
    msgs = ad.get("messages", []) or []
    fired = []
    score = None
    for mraw in msgs:
        idm = re.search(r'\[id "(\d+)"\]', mraw)
        msgm = re.search(r'\[msg "([^"]*)"\]', mraw)
        sm = re.search(r"Total (?:Inbound )?Score: (\d+)", mraw) or re.search(r"Anomaly Score[^0-9]*(\d+)", mraw)
        if sm:
            score = int(sm.group(1))
        fired.append({"id": idm.group(1) if idm else None,
                      "msg": (msgm.group(1) if msgm else mraw[:80]),
                      "blocked": "denied" in mraw.lower() or "access denied" in mraw.lower()})
    blocked = str(status) in ("403", "406")
    tx = j.get("transaction", {})
    ts = tx.get("time") or tx.get("time_stamp") or ""
    client_ip = tx.get("remote_address") or tx.get("client_ip") or ""
    return {"ts": str(ts)[:25], "client_ip": client_ip,
            "method": method, "uri": uri[:120], "status": status,
            "blocked": blocked, "anomaly_score": score,
            "rules": [f for f in fired if f["id"]][:8], "nmsgs": len(msgs)}


def audit_tail(n=60, only_blocked=False):
    out = []
    for ln in reversed(tail_lines(AUDIT_LOG, n=n * 2)):
        try:
            j = json.loads(ln)
        except Exception:
            continue
        e = parse_audit(j)
        if only_blocked and not e["blocked"]:
            continue
        out.append(e)
        if len(out) >= n:
            break
    return out


def crs_families():
    """CRS rules 디렉토리에서 파일별 룰 수 요약 (구조 학습용)."""
    fams = []
    try:
        for fn in sorted(os.listdir(CRS_DIR)):
            if fn.endswith(".conf") and "REQUEST" in fn or fn.endswith(".conf") and "RESPONSE" in fn:
                cnt = 0
                try:
                    cnt = sum(1 for ln in open(os.path.join(CRS_DIR, fn), encoding="utf-8", errors="ignore")
                              if ln.strip().startswith("SecRule"))
                except Exception:
                    pass
                fams.append({"file": fn, "rules": cnt})
    except FileNotFoundError:
        pass
    return fams


def crs_sample(fileprefix, n=6):
    """특정 CRS 파일에서 SecRule 샘플 몇 개 (구조 분석기용)."""
    try:
        for fn in os.listdir(CRS_DIR):
            if fn.startswith(fileprefix):
                rules = []
                cur = ""
                for ln in open(os.path.join(CRS_DIR, fn), encoding="utf-8", errors="ignore"):
                    s = ln.rstrip("\n")
                    cur += s
                    if s.endswith("\\"):
                        cur = cur[:-1] + " "
                        continue
                    if cur.strip().startswith("SecRule"):
                        rules.append(cur.strip())
                    cur = ""
                    if len(rules) >= n:
                        break
                return {"file": fn, "rules": rules}
    except FileNotFoundError:
        pass
    return {"file": None, "rules": []}


# ────────────────────────────── SIEM ──────────────────────────────
SIEM_BLOCK = ('  <localfile>\n    <log_format>json</log_format>\n'
              '    <location>%s</location>\n  </localfile>\n' % AUDIT_LOG)


def siem_status():
    integrated = False
    try:
        integrated = AUDIT_LOG in open(OSSEC_CONF, encoding="utf-8").read()
    except Exception:
        pass
    st = run([WAZUH_CTL, "status"])
    mgr = None
    try:
        mgr = re.search(r"<address>([^<]+)</address>", open(OSSEC_CONF).read()).group(1)
    except Exception:
        pass
    return {"integrated": integrated, "agent_running": "running" in st["stdout"],
            "manager": mgr, "audit_log": AUDIT_LOG, "status_raw": st["stdout"][-600:]}


def siem_enable():
    try:
        conf = open(OSSEC_CONF, encoding="utf-8").read()
        if AUDIT_LOG in conf:
            return {"ok": True, "msg": "이미 modsec_audit.log 가 Wazuh 로 연동돼 있습니다."}
        idx = conf.rfind("</ossec_config>")
        conf = conf[:idx] + SIEM_BLOCK + conf[idx:]
        open(OSSEC_CONF, "w", encoding="utf-8").write(conf)
        r = run([WAZUH_CTL, "restart"], timeout=40)
        return {"ok": r["rc"] == 0, "msg": "audit.log localfile 추가 + 에이전트 재시작"}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


# ────────────────────────────── scenarios ──────────────────────────────
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
    if chk.get("type") == "rule_match":
        try:
            txt = open(EDU_RULES, encoding="utf-8").read()
        except FileNotFoundError:
            txt = ""
        evid = [{"require": rx, "found": re.search(rx, txt) is not None} for rx in chk.get("require", [])]
        ct = run([APACHECTL, "configtest"])
        return {"ok": all(e["found"] for e in evid), "evidence": evid,
                "configtest": "Syntax OK" if "Syntax OK" in (ct["stdout"] + ct["stderr"]) else "오류",
                "hint": sc.get("hint")}
    if chk.get("type") == "audit_blocked":
        # 최근 audit 에서 해당 패턴 uri 가 차단됐는지
        sub = chk.get("uri_contains", "")
        recent = audit_tail(n=40)
        hit = [a for a in recent if sub in (a.get("uri") or "") and a.get("blocked")]
        return {"ok": len(hit) > 0, "evidence": hit[:3],
                "msg": "최근 차단(403) 중 '%s' %d건" % (sub, len(hit)), "hint": sc.get("hint")}
    return {"ok": False, "msg": "알 수 없는 check type"}


# ────────────────────────────── status ──────────────────────────────
def status():
    eng = grep_conf(MODSEC_CONF, ["SecRuleEngine", "SecAuditLog", "SecAuditLogFormat"])
    apache = run([APACHECTL, "-v"])["stdout"]
    apache_ver = (re.search(r"Apache/[\d.]+", apache) or [None])
    apache_ver = apache_ver.group(0) if hasattr(apache_ver, "group") else "Apache"
    running = bool(run(["pgrep", "-x", "apache2"])["stdout"].strip())
    try:
        auditmb = round(os.path.getsize(AUDIT_LOG) / 1048576, 1)
    except OSError:
        auditmb = 0
    crs = "?"
    try:
        crs = (re.search(r"OWASP_CRS/([\d.]+)", "".join(tail_lines(AUDIT_LOG, 1))) or [None])
        crs = crs.group(1) if hasattr(crs, "group") else "3.3.2"
    except Exception:
        crs = "3.3.2"
    return {"hostname": run(["hostname"])["stdout"].strip(), "apache": apache_ver,
            "apache_running": running, "modsec_version": "ModSecurity v2 (2.9.x)",
            "crs_version": crs, "engine": eng.get("SecRuleEngine"),
            "audit_format": eng.get("SecAuditLogFormat"), "audit_mb": auditmb,
            "edu_rule_count": len(list_edu_rules())}


# ────────────────────────────── HTTP handler ──────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "modsec_edu_gui/1.0"

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
                    "modsec": grep_conf(MODSEC_CONF, ["SecRuleEngine", "SecAuditLog", "SecAuditLogFormat",
                                                      "SecAuditLogParts", "SecRequestBodyAccess"]),
                    "paths": {"modsec_conf": MODSEC_CONF, "edu_rules": EDU_RULES, "crs_dir": CRS_DIR, "audit": AUDIT_LOG},
                    "crs_families": crs_families(),
                    "form": {"variables": VARIABLES, "operators": OPERATORS, "transforms": TRANSFORMS,
                             "actions": ACTIONS, "severities": SEVERITIES}})
            if u.path == "/api/rules":
                return self._send(200, {"rules": list_edu_rules(), "next_id": next_id()})
            if u.path == "/api/crs_sample":
                return self._send(200, crs_sample(q.get("prefix", ["REQUEST-941"])[0]))
            if u.path == "/api/audit":
                return self._send(200, {"events": audit_tail(int(q.get("n", ["60"])[0]),
                                                             q.get("blocked", ["0"])[0] == "1")})
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
                return self._send(200, parse_secrule(b.get("rule", "")))
            if u.path == "/api/rule/preview":
                return self._send(200, {"rule": build_secrule(b)})
            if u.path == "/api/rule/apply":
                rule = b.get("rule", "")
                if not rule.strip().startswith("SecRule"):
                    return self._send(400, {"ok": False, "error": "SecRule 로 시작해야 합니다"})
                return self._send(200, apply_secrule(rule))
            if u.path == "/api/rule/delete":
                return self._send(200, delete_edu_rule(b.get("id")))
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
    sys.stderr.write("[modsec_edu_gui] listening on 0.0.0.0:%d\n" % PORT)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
