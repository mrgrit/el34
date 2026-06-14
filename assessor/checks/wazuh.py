"""보안 알림/로그 검사 — 로컬 Wazuh alerts.json 질의(읽기 전용).

간단 경로: wazuh-manager-logs 마운트의 alerts/alerts.json 읽기 + 필터.
(풍부 경로인 indexer 질의는 app.py 의 AlertSource 구현이 alerts.json 을 채우는 방식으로
 추상화 — 핸들러는 순수 필터 로직만 담당해 docker 없이 단위 테스트 가능.)

부작용 0. 미지원/잘못된 파라미터는 CheckError.
"""
from __future__ import annotations

from typing import Any

from . import base
from .base import CheckError, AlertSource


def _rule(a: dict) -> dict:
    return a.get("rule") or {}


def _groups(a: dict) -> list[str]:
    g = _rule(a).get("groups") or []
    return [str(x).lower() for x in g]


def _summary(a: dict) -> str:
    r = _rule(a)
    return (f"ts={a.get('timestamp','')[:19]} "
            f"rule={r.get('id')} lvl={r.get('level')} "
            f"agent={(a.get('agent') or {}).get('name','')} "
            f"desc={r.get('description','')}")


# ─── wazuh_alert {rule_id?|sid?|groups?|agent?, since_sec?} ──────────────────
def wazuh_alert(spec, src: AlertSource):
    p = spec["params"]
    since = p.get("since_sec")
    alerts = src.alerts(since_sec=since)

    rule_id = p.get("rule_id") or p.get("id")
    sid = p.get("sid")                      # suricata signature id
    groups = p.get("groups")
    agent = p.get("agent")

    if rule_id is not None:
        rule_id = base.validate_name(str(rule_id), "rule_id")
    if sid is not None:
        sid = base.validate_name(str(sid), "sid")
    if groups is not None:
        if isinstance(groups, str):
            groups = [groups]
        groups = [base.validate_name(str(g), "groups").lower() for g in groups]
    if agent is not None:
        agent = base.validate_name(str(agent), "agent")

    matches = []
    for a in alerts:
        r = _rule(a)
        if rule_id is not None and str(r.get("id")) != rule_id:
            continue
        if sid is not None:
            asid = (((a.get("data") or {}).get("alert") or {}).get("signature_id")
                    or (a.get("data") or {}).get("id"))
            if str(asid) != sid:
                continue
        if groups is not None and not all(g in _groups(a) for g in groups):
            continue
        if agent is not None and (a.get("agent") or {}).get("name") != agent:
            continue
        matches.append(a)

    passed = bool(matches)
    ev = _summary(matches[-1]) if passed else "no matching Wazuh alert"
    return base.ok(spec["id"], passed, ev, {"matches": len(matches)})


# ─── fim_change {path|dir, since_sec?} ── Wazuh syscheck(FIM) 이벤트 질의 ──────
def fim_change(spec, src: AlertSource):
    p = spec["params"]
    target = p.get("path") or p.get("dir")
    if not target:
        raise CheckError("fim_change: path|dir 누락")
    target = base.validate_path(target)
    since = p.get("since_sec")
    alerts = src.alerts(since_sec=since)

    matches = []
    for a in alerts:
        # syscheck(FIM) 알림만 — Wazuh 내장 룰(550/553/554 등)이 syscheck 그룹 부여
        if "syscheck" not in _groups(a):
            continue
        sc = (a.get("syscheck") or {})
        fpath = sc.get("path") or ""
        if fpath == target or fpath.startswith(target.rstrip("/") + "/") or target in fpath:
            matches.append(a)

    passed = bool(matches)
    if passed:
        sc = matches[-1].get("syscheck") or {}
        ev = (f"ts={matches[-1].get('timestamp','')[:19]} "
              f"event={sc.get('event')} path={sc.get('path')} "
              f"agent={(matches[-1].get('agent') or {}).get('name','')}")
    else:
        ev = f"no FIM(syscheck) change under {target}"
    return base.ok(spec["id"], passed, ev, {"matches": len(matches)})


# ─── command_ran {pattern, user?, since_sec?} ── 명령 로그 질의(local6 → cmdlog) ─
def command_ran(spec, src: AlertSource):
    p = spec["params"]
    pat = base.validate_pattern(p.get("pattern"), "pattern")
    user = p.get("user")
    if user is not None:
        user = base.validate_name(str(user), "user")
    since = p.get("since_sec")
    alerts = src.alerts(since_sec=since)

    import re as _re
    try:
        rx = _re.compile(pat)
    except _re.error:
        rx = None

    matches = []
    for a in alerts:
        if "cmdlog" not in _groups(a):
            continue
        data = a.get("data") or {}
        command = data.get("command") or a.get("full_log") or ""
        cmd_user = data.get("cmd_user") or ""
        if user is not None and cmd_user != user:
            continue
        if (rx.search(command) if rx else (pat in command)):
            matches.append(a)

    passed = bool(matches)
    if passed:
        d = matches[-1].get("data") or {}
        ev = (f"ts={matches[-1].get('timestamp','')[:19]} "
              f"user={d.get('cmd_user','')}@{d.get('cmd_host','')} "
              f"cmd={d.get('command') or matches[-1].get('full_log','')}")
    else:
        ev = f"no logged command matching {pat!r}"
    return base.ok(spec["id"], passed, ev, {"matches": len(matches)})


HANDLERS = {
    "wazuh_alert":  wazuh_alert,
    "fim_change":   fim_change,
    "command_ran":  command_ran,
}
