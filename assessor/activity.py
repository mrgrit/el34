"""실습 모니터링 피드 — /activity 핸들러.

check-spec(/assess)가 채점용 pass/fail 이라면, 여기는 **진도·병목 모니터링용 활동
스트림**이다. 신호원은 전부 그 VM 의 로컬 Wazuh(alerts.json + docker.sock 프로브).

★ 여기선 raw 활동만 반환한다. 진도/병목 판정·Cohort/과목/학년 태깅은 전적으로
  서버(tubewar) 책임 — el34 클라이언트는 자기가 어떤 수업인지 모른다.

stdlib 만 사용(단위 테스트 친화). executor/alert_source 는 주입.
"""
from __future__ import annotations

from typing import Any

from .checks import base

WANT_ALL = ["commands", "fim", "alerts", "services"]

# /activity alerts 카테고리에 포함할 "보안 신호" 그룹(명령/FIM 은 별도 카테고리라 제외)
_SECURITY_GROUPS = {
    "ids", "suricata", "web", "web_attack", "attack", "modsecurity", "sysmon",
    "windows", "sql_injection", "xss", "intrusion_detection", "appsec",
}
_EXCLUDE_FROM_ALERTS = {"cmdlog", "syscheck"}


def _rule(a):
    return a.get("rule") or {}


def _groups(a):
    return [str(x).lower() for x in (_rule(a).get("groups") or [])]


def _agent(a):
    return (a.get("agent") or {}).get("name", "")


def _ts(a):
    return a.get("timestamp", "")[:19]


# ─── commands: cmdlog(PROMPT) + audit(execve) 병합 ───────────────────────────
def _command_rows(alerts, filt, limit):
    fc = filt.get("container")
    fu = filt.get("user")
    rows = []
    for a in alerts:
        g = _groups(a)
        data = a.get("data") or {}
        audit = data.get("audit") or {}
        if "cmdlog" in g:                      # PROMPT_COMMAND 경로(셸 빌트인 포함)
            container = data.get("cmd_host") or _agent(a)
            user = data.get("cmd_user", "")
            cmd = data.get("command") or a.get("full_log", "")
            exit_code = data.get("cmd_rc")
            src = "prompt"
        elif "audit" in g and (audit.get("command") or audit.get("exe")):
            container = _agent(a)               # auditd execve 경로(위변조에 강함)
            user = audit.get("auid") or audit.get("uid") or audit.get("euid") or ""
            cmd = audit.get("command") or audit.get("exe") or ""
            exit_code = audit.get("exit")
            src = "auditd"
        else:
            continue
        if fc and container != fc:
            continue
        if fu and str(user) != str(fu):
            continue
        rows.append({"ts": _ts(a), "container": container, "user": str(user),
                     "cmd": base.clip(cmd, 512), "exit": exit_code, "source": src})
    return rows[-limit:][::-1]


# ─── fim: Wazuh syscheck 최근 변경 ───────────────────────────────────────────
def _fim_rows(alerts, filt, limit):
    fc = filt.get("container")
    rows = []
    for a in alerts:
        if "syscheck" not in _groups(a):
            continue
        sc = a.get("syscheck") or {}
        if not sc.get("path"):
            continue
        agent = _agent(a)
        if fc and agent != fc:
            continue
        audit = sc.get("audit") or {}
        who = (((audit.get("effective_user") or {}).get("name"))
               or ((audit.get("user") or {}).get("name"))
               or sc.get("uname_after") or "")
        rows.append({"ts": _ts(a), "container": agent, "path": sc.get("path"),
                     "action": sc.get("event", ""), "who": who})
    return rows[-limit:][::-1]


# ─── alerts: Suricata/ModSec/Sysmon 등 보안 알림(명령/FIM 제외) ───────────────
def _alert_rows(alerts, filt, limit):
    fg = filt.get("groups")
    if isinstance(fg, str):
        fg = [fg]
    fg = [str(x).lower() for x in fg] if fg else None
    rows = []
    for a in alerts:
        g = set(_groups(a))
        if g & _EXCLUDE_FROM_ALERTS:           # 명령/FIM 은 별도 카테고리
            continue
        if fg is not None:
            if not (set(fg) & g):
                continue
        elif not (g & _SECURITY_GROUPS):       # 기본은 보안 신호만
            continue
        r = _rule(a)
        rows.append({"ts": _ts(a), "rule_id": r.get("id"), "level": r.get("level"),
                     "description": base.clip(r.get("description", ""), 256),
                     "agent": _agent(a), "groups": _rule(a).get("groups") or []})
    return rows[-limit:][::-1]


# ─── services: docker.sock 프로브(핵심 서비스 + 최근 에러 요약) ──────────────
def _service_probe(executor):
    out: dict[str, Any] = {}

    def running(container, pattern):
        try:
            r = executor.exec(container, ["pgrep", "-f", pattern])
            return r.exit_code == 0
        except Exception:
            return None

    out["apache"] = "up" if running("el34-web", "apache2") else "down"
    out["suricata"] = "up" if running("el34-ips", "suricata") else "down"
    out["haproxy"] = "up" if running("el34-fw", "haproxy") else "down"
    # 최근 Apache 에러 라인 수(요약)
    try:
        r = executor.exec("el34-web", ["sh", "-c",
                                      "tail -n 200 /var/log/apache2/error.log 2>/dev/null | wc -l"])
        out["recent_apache_errors"] = int((r.stdout or "0").strip() or 0)
    except Exception:
        out["recent_apache_errors"] = None
    return out


def build_activity(req: dict[str, Any], executor, alert_source) -> dict[str, Any]:
    since = req.get("since_sec", 300)
    try:
        since = int(since)
    except (TypeError, ValueError):
        since = 300
    limit = req.get("limit", 200)
    try:
        limit = max(1, min(1000, int(limit)))
    except (TypeError, ValueError):
        limit = 200
    want = req.get("want") or WANT_ALL
    if isinstance(want, str):
        want = [want]
    filt = req.get("filter") or {}
    if not isinstance(filt, dict):
        filt = {}

    # 명령/FIM/알림은 한 번의 alerts 조회를 공유(효율). services 는 docker 프로브.
    need_alerts = any(w in want for w in ("commands", "fim", "alerts"))
    alerts = alert_source.alerts(since_sec=since) if need_alerts else []

    result: dict[str, Any] = {"collected_at": None}
    if "commands" in want:
        result["commands"] = _command_rows(alerts, filt, limit)
    if "fim" in want:
        result["fim"] = _fim_rows(alerts, filt, limit)
    if "alerts" in want:
        result["alerts"] = _alert_rows(alerts, filt, limit)
    if "services" in want:
        result["services"] = _service_probe(executor)
    return result
