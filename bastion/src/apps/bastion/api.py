#!/usr/bin/env python3
"""bastion API 서버 — 비대화형 HTTP 인터페이스

Claude 또는 외부 시스템이 bastion을 headless로 호출할 때 사용.
TUI(main.py) 없이 agent.chat()을 직접 실행하고 이벤트 스트림을 반환.

Usage:
    python -m apps.bastion.api          # uvicorn 기본 실행 (port 8003)
    ./dev.sh bastion-api

Endpoints:
    POST /chat              — 자연어 요청 실행 (NDJSON 스트림)
    POST /onboard           — VM 온보딩 (NDJSON 스트림, 타임아웃 없음)
    GET  /skills            — Skill 목록
    GET  /playbooks         — Playbook 목록
    GET  /evidence          — 최근 실행 기록
    GET  /assets            — Asset 레지스트리
    PUT  /assets/{role}     — Asset 직접 등록/갱신
    GET  /health            — 헬스체크
"""
import json
import os
import sys

BASTION_DIR = os.path.abspath(os.path.dirname(__file__))
CCC_DIR = os.path.abspath(os.path.join(BASTION_DIR, "..", ".."))
sys.path.insert(0, CCC_DIR)

# .env 로드
ENV_PATH = os.path.join(BASTION_DIR, ".env")
if os.path.exists(ENV_PATH):
    with open(ENV_PATH) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import StreamingResponse
    from pydantic import BaseModel
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn[standard]", "-q"], check=True)
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import StreamingResponse
    from pydantic import BaseModel

from bastion.agent import BastionAgent
from bastion import INTERNAL_IPS


# ── 초기화 ─────────────────────────────────────────────────────────────────

def _get_vm_ips() -> dict[str, str]:
    vm_ips = {}
    for role in ["attacker", "secu", "web", "siem", "manager"]:
        ip = os.getenv(f"VM_{role.upper()}_IP", "")
        if ip:
            vm_ips[role] = ip
    return vm_ips or dict(INTERNAL_IPS)


from bastion import LLM_BASE_URL, LLM_MANAGER_MODEL
import threading

# ── Bastion lifecycle syslog emit → wazuh (local5) ──
# 모든 mission event 를 stage 별로 syslog 송신. request_id 로 correlation.
# wazuh 가 receiver: 10.20.32.100:514/udp (또는 SIEM_HOST env)
_BASTION_SYSLOG_LOGGER = None
def _emit_bastion_syslog(stage: str, payload: dict):
    """1 mission lifecycle 의 1 event 를 wazuh 로 syslog 송신."""
    global _BASTION_SYSLOG_LOGGER
    try:
        if _BASTION_SYSLOG_LOGGER is None:
            import logging, logging.handlers, socket
            lg = logging.getLogger("bastion-lifecycle")
            lg.setLevel(logging.INFO)
            siem_host = os.environ.get("SIEM_HOST", "10.20.32.100")
            try:
                h = logging.handlers.SysLogHandler(address=(siem_host, 514),
                                                    facility=logging.handlers.SysLogHandler.LOG_LOCAL5,
                                                    socktype=socket.SOCK_DGRAM)
                h.setFormatter(logging.Formatter("bastion-lifecycle %(message)s"))
                lg.addHandler(h)
            except Exception: pass
            try:
                fh = logging.FileHandler("/var/log/bastion-lifecycle.log")
                fh.setFormatter(logging.Formatter("%(asctime)s bastion-lifecycle %(message)s"))
                lg.addHandler(fh)
            except Exception: pass
            lg.propagate = False
            _BASTION_SYSLOG_LOGGER = lg
        # payload size cap (UDP 1.5KB 안전)
        msg = {"stage": stage, **payload}
        _BASTION_SYSLOG_LOGGER.info(json.dumps(msg, ensure_ascii=False)[:1200])
    except Exception:
        pass

def _slim_evt(evt: dict) -> dict:
    """agent event 를 syslog 용 핵심 field 만 추출 (noise 제거)."""
    ev = evt.get("event", "")
    out = {"event": ev}
    # 모든 event 공통 — 작은 필드만
    for k in ("stage", "skill", "playbook_id", "confidence", "decision", "reason",
              "attempt", "success", "host", "target", "score",
              "model", "attack_mode", "count", "index", "total", "task"):
        if k in evt: out[k] = evt[k]
    # stream_token 의 token 은 너무 짧고 양 많음 — 제외
    if ev == "stream_token": return {"event": "stream_token"}  # placeholder
    # skill_result 의 output 은 100자만 (timeline 가독성)
    if ev == "skill_result" and "output" in evt:
        out["output_head"] = (str(evt.get("output", ""))[:100])
    return out


# 공격/대전 과목은 derestricted 모델로 — gpt-oss:120b 가 공격 페이로드 작성을 거절하는 문제(B유형 fail)
# 해결. 방어/SOC/컴플라이언스 과목은 safety 보존된 기본 모델 유지.
LLM_MANAGER_MODEL_UNSAFE = os.getenv("LLM_MANAGER_MODEL_UNSAFE", "gurubot/gpt-oss-derestricted:120b")
ATTACK_COURSES = {
    "attack-ai", "attack-adv-ai",
    "battle-ai", "battle-adv-ai",
    # 공격 액션이 많은 과목도 lab-context preamble 필요 (SQLi/XSS/exploit step 거부 차단)
    "web-vuln-ai", "physical-pentest-ai",
    # AI 보안 공격 카테고리 (prompt injection / model jailbreak)
    "ai-security-ai",
    # R5 fix #12 (2026-05-07): agent-ir-* 과목도 deserialization payload 등 공격 step 다수 포함.
    # probe 가드레일 + attack-mode preamble 적용 필요.
    "agent-ir-ai", "agent-ir-adv-ai",
    # autonomous-* / autonomous-systems-* 도 attack chain step 비중 높음
    "autonomous-ai", "autonomous-systems-ai",
    # ai-safety-adv-ai: jailbreak 방어 평가에 공격 시뮬 step 포함
    "ai-safety-adv-ai",
}

_vm_ips = _get_vm_ips()
agent = BastionAgent(vm_ips=_vm_ips, ollama_url=LLM_BASE_URL, model=LLM_MANAGER_MODEL)
# 동시 요청에서 self.model 을 per-course 로 스왑하기 위한 락 (API는 대부분 순차 호출이지만 안전망)
_model_swap_lock = threading.Lock()


def _resolve_manager_model(course: str) -> str:
    """course 기반 manager LLM 선택. 공격/대전 계열만 derestricted.

    LLM_FAST_ATTACK=1 면 attack 도 일반 모델 사용 (derestricted 가 너무 느릴 때).
    attack_mode preamble + first_turn_retry 가 거부 패턴 잡아줌.
    """
    if course in ATTACK_COURSES:
        if os.getenv("LLM_FAST_ATTACK", "").lower() in ("1","true","yes"):
            return LLM_MANAGER_MODEL  # 빠른 일반 모델 + attack_mode preamble 의존
        return LLM_MANAGER_MODEL_UNSAFE
    return LLM_MANAGER_MODEL

app = FastAPI(
    title="Bastion API",
    description="CCC Bastion 보안 운영 에이전트 — Headless HTTP 인터페이스",
    version="1.0.0",
)


# ── 시작 banner — KG 통합이 활성화되어 있는지 stderr 에 명시 (운영자 가시화) ──
def _startup_kg_banner() -> None:
    """uvicorn 시작 시 KG 통합 상태를 한눈에. 한쪽이라도 빠지면 ★ 표시."""
    sys.stderr.write("\n" + "=" * 60 + "\n")
    sys.stderr.write("Bastion API — KG-Integrated Agent Startup\n")
    sys.stderr.write("=" * 60 + "\n")
    checks = []
    try:
        from bastion.kg_context import get_builder
        get_builder()
        checks.append(("kg_context module", True, ""))
    except Exception as e:
        checks.append(("kg_context module", False, str(e)))
    try:
        from bastion.kg_recorder import get_recorder
        get_recorder()
        checks.append(("kg_recorder module", True, ""))
    except Exception as e:
        checks.append(("kg_recorder module", False, str(e)))
    try:
        from bastion.kg_metrics import get_metrics
        get_metrics()
        checks.append(("kg_metrics module", True, ""))
    except Exception as e:
        checks.append(("kg_metrics module", False, str(e)))
    try:
        from bastion.graph import get_graph
        s = get_graph().stats()
        checks.append((f"graph DB ({s.get('total_nodes',0)} nodes)", True, ""))
    except Exception as e:
        checks.append(("graph DB", False, str(e)))
    try:
        from bastion.history import HistoryLayer
        h = HistoryLayer()
        with h._conn() as c:
            n = c.execute("SELECT COUNT(*) FROM history_anchors").fetchone()[0]
        checks.append((f"history DB ({n} anchors)", True, ""))
    except Exception as e:
        checks.append(("history DB", False, str(e)))

    all_ok = all(ok for _, ok, _ in checks)
    for name, ok, err in checks:
        mark = "[ OK ]" if ok else "[★FAIL]"
        line = f"  {mark}  {name}"
        if err:
            line += f"  — {err}"
        sys.stderr.write(line + "\n")
    sys.stderr.write("-" * 60 + "\n")
    if all_ok:
        sys.stderr.write("KG integration: ENABLED  (모든 LLM 호출 자동 KG 참조 + 결과 anchor 기록)\n")
    else:
        sys.stderr.write("★ KG integration: DEGRADED  — 위 [★FAIL] 항목 즉시 수정 필요\n")
        sys.stderr.write("★ chat 동작은 계속되지만 R5 학습 loop 는 작동 안 함\n")
    sys.stderr.write("=" * 60 + "\n\n")
    sys.stderr.flush()


@app.on_event("startup")
def _on_startup():
    _startup_kg_banner()
    # Auto-register Assets — bastion 이 시작 시점에 .env 의 VM_*_IP 로 인프라 자동 파악
    # (수동 PUT /assets/<role> 없이 즉시 사용 가능)
    try:
        registered = []
        for role, ip in agent.vm_ips.items():
            try:
                agent.evidence_db.update_asset(role, ip, "configured",
                                                "auto-registered from .env at startup")
                registered.append(f"{role}={ip}")
            except Exception as e:
                print(f"[startup] Asset auto-register fail for {role}: {e}",
                      file=__import__("sys").stderr, flush=True)
        if registered:
            print(f"[startup] Auto-registered {len(registered)} Assets: "
                  f"{', '.join(registered)}",
                  file=__import__("sys").stderr, flush=True)
    except Exception as e:
        print(f"[startup] Asset auto-register block failed: {e}",
              file=__import__("sys").stderr, flush=True)

    # Phase B: 인프라 자동 발견(docker 기반) — 역할→컨테이너 매핑 + 자산 등록.
    # best-effort: 실패해도 기존 동작 무영향(targets 정적 el34 폴백). BASTION_DISCOVERY=1 시
    # 발견 매핑을 스킬 실행에 사용. 미설정이면 발견은 하되 적용은 정적 폴백.
    try:
        from bastion.discovery import discover_infra
        d = discover_infra(agent.vm_ips)
        print(f"[startup] discovery: {d['count']} containers, role_map={d['role_map']}",
              file=__import__("sys").stderr, flush=True)
    except Exception as e:
        print(f"[startup] discovery skipped: {e}",
              file=__import__("sys").stderr, flush=True)


# ── 스키마 ──────────────────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    auto_approve: bool = False   # True: 고위험 작업 자동 승인 (주의)
    stream: bool = True          # False: 전체 이벤트 배열 한번에 반환
    # 승인 모드 — normal | danger_danger | danger_danger_danger
    approval_mode: str = "normal"
    # 테스트 메타데이터 — evidence DB에 함께 기록
    course: str = ""
    lab_id: str = ""
    step_order: int = 0
    test_session: str = ""
    # Step 3: 채점 기준 정렬 — agent 가 verify.semantic 을 보고 작업하도록
    verify_intent: str = ""              # success_criteria 의 한 줄 의도
    verify_success_criteria: list = []   # 충족해야 할 기준 (3+)
    verify_acceptable_methods: list = [] # 등가 허용 방법
    verify_negative_signs: list = []     # 명시적 fail 신호
    # EG ablation 평가용 — off | playbook | experience | full (default full = 운영 기본).
    # 운영은 항상 full(KG hard-coded). off/playbook/experience 는 Bastion-Bench 측정 전용.
    eg_mode: str = "full"


# ── 엔드포인트 ──────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """일반 health + KG 통합 활성 상태 (운영자가 KG 누락을 즉시 인지)."""
    return {
        "status": "ok",
        "model": agent.model,
        "model_unsafe": LLM_MANAGER_MODEL_UNSAFE,
        "attack_courses": sorted(ATTACK_COURSES),
        "llm": agent.ollama_url,
        "skills": len(agent.get_skills()),
        "playbooks": len(agent.get_playbooks()),
        # ── KG 통합 강제 — 한쪽이라도 false 면 운영자 즉시 조치 ──
        "kg": _kg_health_summary(),
    }


def _kg_health_summary() -> dict:
    """KG 시스템의 가용성 + 통합 status. /health 와 /kg/health 모두 사용."""
    out = {
        "context_module": False,
        "recorder_module": False,
        "metrics_module": False,
        "graph_db": False,
        "history_db": False,
        "graph_nodes": 0,
        "history_anchors": 0,
        "last_chat_kg_used": None,
        "last_chat_kg_recorded": None,
        "errors": [],
    }
    try:
        from bastion.kg_context import get_builder
        get_builder()
        out["context_module"] = True
    except Exception as e:
        out["errors"].append(f"kg_context import: {e}")
    try:
        from bastion.kg_recorder import get_recorder
        get_recorder()
        out["recorder_module"] = True
    except Exception as e:
        out["errors"].append(f"kg_recorder import: {e}")
    try:
        from bastion.kg_metrics import get_metrics
        get_metrics()
        out["metrics_module"] = True
    except Exception as e:
        out["errors"].append(f"kg_metrics import: {e}")
    try:
        from bastion.graph import get_graph
        g = get_graph()
        s = g.stats()
        out["graph_db"] = True
        out["graph_nodes"] = s.get("total_nodes", 0)
    except Exception as e:
        out["errors"].append(f"graph access: {e}")
    try:
        from bastion.history import HistoryLayer
        h = HistoryLayer()
        anchors = h.find_anchors(limit=1)
        out["history_db"] = True
        # full count 는 별도 sql 필요
        try:
            with h._conn() as c:
                cur = c.execute("SELECT COUNT(*) FROM history_anchors").fetchone()
                out["history_anchors"] = int(cur[0]) if cur else 0
        except Exception:
            out["history_anchors"] = -1
    except Exception as e:
        out["errors"].append(f"history access: {e}")
    # 최근 chat 의 KG 사용 흔적
    last_ctx = getattr(agent, "_last_kg_status", {}) or {}
    last_rec = getattr(agent, "_last_kg_record", {}) or {}
    out["last_chat_kg_used"] = bool(last_ctx.get("context_used"))
    out["last_chat_kg_recorded"] = bool(last_rec.get("success"))
    out["all_modules_loaded"] = (out["context_module"] and out["recorder_module"]
                                  and out["metrics_module"])
    return out


@app.get("/kg/health")
def kg_health():
    """KG 통합 전용 health — 모든 module + DB + 최근 chat 흔적."""
    return _kg_health_summary()


@app.get("/kg/audit")
def kg_audit(limit: int = 20):
    """최근 N chat 의 KG 사용 audit (audit_log 의 verify/turns 정보 활용).

    사용처: 운영자가 "지난 24h chat 중 KG record 실패한 건이 있나?" 확인.
    """
    try:
        from bastion.audit import get_audit_log
        log = get_audit_log()
        recent = log.recent(limit=limit) if hasattr(log, 'recent') else []
        # 각 row 에 KG 정보가 별도 컬럼은 아니므로, 현재는 최근 chat list + 최근 anchor 카운트
        from bastion.history import HistoryLayer
        h = HistoryLayer()
        try:
            with h._conn() as c:
                cur = c.execute(
                    "SELECT id, kind, label, created_at FROM history_anchors "
                    "WHERE kind='task_outcome' ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                recent_outcomes = [dict(r) for r in cur]
        except Exception:
            recent_outcomes = []
        return {
            "recent_chats": len(recent),
            "recent_task_outcome_anchors": recent_outcomes,
            "advice": ("KG 가 모든 chat 마다 작동하는지 확인하려면 chat 응답의 "
                       "'kg_status' event 를 모니터링하라. "
                       "context.used=true + record.success=true 가 정상."),
        }
    except Exception as e:
        return {"error": str(e), "recent_chats": 0, "recent_task_outcome_anchors": []}


@app.get("/skills")
def skills():
    return agent.get_skills()


@app.get("/playbooks")
def playbooks():
    return agent.get_playbooks()


@app.get("/evidence")
def evidence(limit: int = 20):
    return agent.get_evidence(limit)


# ── Audit log — 중요 시스템 작업 증적 (append-only, hash chain) ────────────

@app.get("/audit")
def audit_recent(limit: int = 50, session_id: str = "", user_id: str = "",
                 course: str = "", outcome: str = "", since: str = ""):
    """최근 audit log. 필터 가능."""
    from bastion.audit import get_audit_log
    log = get_audit_log()
    return {"audit": log.recent(limit=limit,
                                session_id=session_id, user_id=user_id,
                                course=course, outcome=outcome, since=since)}


@app.get("/audit/{request_id}")
def audit_get(request_id: str):
    """특정 request 전체 audit 조회 (사용자 지시·LLM turns·skill 흐름·결정 모두)."""
    from bastion.audit import get_audit_log
    rec = get_audit_log().get(request_id)
    if not rec:
        raise HTTPException(404, f"audit record not found: {request_id}")
    return rec


@app.get("/audit/_stats")
def audit_stats():
    from bastion.audit import get_audit_log
    return get_audit_log().stats()


@app.get("/audit/_verify-chain")
def audit_verify_chain(start_id: int = 1):
    """hash chain 무결성 검증 — 변조 시도 발견 시 깨진 첫 row 반환."""
    from bastion.audit import get_audit_log
    return get_audit_log().verify_chain(start_id=start_id)


# ── Compaction (KG-5) — experience 정제 / Insight 노드 생성 ─────────────────

@app.post("/graph/compact/{playbook_id}")
def compact_one(playbook_id: str, min_experiences: int = 5):
    """특정 playbook 의 experience 압축 → known_pitfalls·insights 생성."""
    from bastion.compaction import compact_playbook
    return compact_playbook(playbook_id, min_experiences=min_experiences)


@app.post("/graph/compact")
def compact_all_pb(min_experiences: int = 5, limit_playbooks: int = 50):
    """전체 playbook compaction."""
    from bastion.compaction import compact_all
    return compact_all(min_experiences=min_experiences,
                       limit_playbooks=limit_playbooks)


# ── Knowledge Graph 조회 (KG-6) ────────────────────────────────────────────

@app.get("/graph/stats")
def graph_stats():
    """노드/엣지 카운트 + 최근 변경."""
    from bastion.graph import get_graph
    return get_graph().stats()


@app.get("/graph/nodes")
def graph_nodes(types: str = "", limit: int = 500):
    """모든 노드 메타. types 콤마 구분 필터.

    UI 의 그래프 시각화 용 — content/embedding 제외 메타만.
    """
    from bastion.graph import get_graph
    type_list = [t.strip() for t in types.split(",") if t.strip()] if types else None
    g = get_graph()
    nodes = g.all_nodes(types=type_list)[:limit]
    return {"nodes": nodes, "count": len(nodes)}


@app.get("/graph/edges")
def graph_edges(types: str = ""):
    """모든 엣지. types 필터."""
    from bastion.graph import get_graph
    type_list = [t.strip() for t in types.split(",") if t.strip()] if types else None
    g = get_graph()
    edges = g.all_edges(types=type_list)
    return {"edges": edges, "count": len(edges)}


@app.get("/graph/node/{node_id}")
def graph_node_detail(node_id: str):
    """노드 풀 콘텐츠 + backlinks (incoming edges 그룹) + neighbors."""
    from bastion.graph import get_graph
    g = get_graph()
    node = g.get_node(node_id)
    if not node:
        raise HTTPException(404, f"node not found: {node_id}")
    backlinks = g.backlinks(node_id)
    out_edges = g.neighbors(node_id, direction="out")
    return {"node": node, "backlinks": backlinks, "out_edges": out_edges}


@app.get("/graph/search")
def graph_search(q: str = "", type: str = "", limit: int = 30):
    """전문 검색 (FTS5)."""
    from bastion.graph import get_graph
    if not q.strip():
        return {"results": []}
    g = get_graph()
    results = g.search_fts(q, type=type or None, limit=limit)
    return {"results": results, "count": len(results)}


@app.get("/graph/lineage/{node_id}")
def graph_lineage(node_id: str, max_depth: int = 3):
    """supersedes / depends_on 체인 — playbook 진화 경로 추적."""
    from bastion.graph import get_graph
    g = get_graph()
    node = g.get_node(node_id)
    if not node:
        raise HTTPException(404, f"node not found: {node_id}")
    lineage = g.traverse(node_id, max_depth=max_depth,
                         edge_types=["supersedes", "depends_on", "often_chains"])
    return {"start": node, "lineage": list(lineage.values())}


@app.delete("/graph/node/{node_id}")
def graph_delete_node(node_id: str):
    """노드 삭제 (관련 엣지 cascade) — admin 용."""
    from bastion.graph import get_graph
    g = get_graph()
    deleted = g.delete_node(node_id)
    return {"deleted": deleted, "node_id": node_id}


# ── KG metrics — agent 의 KG context/recorder 사용량 ──────────────────────

@app.get("/kg/metrics")
def kg_metrics():
    """KG context builder + recorder 의 in-memory metrics snapshot."""
    try:
        from bastion.kg_metrics import get_metrics
        return get_metrics().snapshot()
    except Exception as e:
        return {"error": str(e), "counters": [], "observations": []}


@app.get("/kg/anchors/recent")
def kg_anchors_recent(kind: str = "", limit: int = 50):
    """최근 history_anchors — KG 업데이트 검증용 (R4 진행 중 누적 확인)."""
    try:
        from bastion.history import HistoryLayer
        h = HistoryLayer()
        return {"anchors": h.find_anchors(kind=kind, limit=limit)}
    except Exception as e:
        return {"error": str(e), "anchors": []}


# ── History (L4) — 시계열·내러티브·anchor·changelog ────────────────────────

def _history():
    from bastion.history import HistoryLayer
    return HistoryLayer()


@app.get("/history/handoff/{asset_id}")
def history_handoff(asset_id: str, since: str = ""):
    """신규 운영자 인수인계 패키지 — narrative + anchor + changelog 일괄."""
    return _history().handoff(asset_id, since=since)


@app.get("/history/range")
def history_range(asset_id: str = "", since: str = "", until: str = ""):
    """규제 감사용 시간 범위 쿼리 — events + active anchors."""
    return _history().range_query(asset_id=asset_id, since=since, until=until)


@app.get("/history/events")
def history_events(asset_id: str = "", narrative_id: str = "", kind: str = "",
                   since: str = "", until: str = "", limit: int = 100):
    return {"events": _history().list_events(
        asset_id=asset_id, narrative_id=narrative_id, kind=kind,
        since=since, until=until, limit=limit,
    )}


@app.get("/history/narratives/{narrative_id}")
def history_narrative(narrative_id: str):
    n = _history().get_narrative(narrative_id)
    return n or {}


class NarrativeOpenBody(BaseModel):
    title: str
    tags: list[str] = []
    summary: str = ""


@app.post("/history/narratives")
def history_open_narrative(body: NarrativeOpenBody):
    nid = _history().open_narrative(body.title, tags=body.tags, summary=body.summary)
    return {"narrative_id": nid}


@app.post("/history/narratives/{narrative_id}/close")
def history_close_narrative(narrative_id: str, summary: str = ""):
    _history().close_narrative(narrative_id, summary=summary)
    return {"narrative_id": narrative_id, "status": "closed"}


class AnchorBody(BaseModel):
    kind: str           # ioc / regulatory / policy_decision / breach_record
    label: str
    body: str
    related_ids: list[str] = []
    valid_from: str = ""
    valid_until: str = ""


@app.post("/history/anchors")
def history_add_anchor(body: AnchorBody):
    """anchor 등록 — 압축 면역 영구 보존 사실."""
    aid = _history().add_anchor(
        body.kind, body.label, body.body,
        related_ids=body.related_ids,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
    )
    return {"anchor_id": aid}


@app.get("/history/anchors")
def history_list_anchors(kind: str = "", label_like: str = "", limit: int = 50):
    return {"anchors": _history().find_anchors(
        kind=kind, label_like=label_like, limit=limit,
    )}


# ── Knowledge / Concept 등록 (외부 지식 채널 P15) ──────────────────────────

class ConceptBody(BaseModel):
    """외부 표준·CVE·기법 등 Concept 노드 등록.
    P15 외부 지식 채널 (CISA KEV/MITRE ATT&CK/OWASP/NIST CSF/CWE/ISO 등) 통합용.
    """
    concept_id: str            # concept:cve:CVE-2024-XXXX, concept:mitre:T1041 등
    name: str                  # CVE-2024-XXXX, T1041 등
    description: str = ""
    source: str = ""           # CISA-KEV, MITRE-ATTCK, OWASP-2021, NIST-CSF-2.0 등
    properties: dict = {}      # source-specific 메타


@app.post("/knowledge/concept")
def knowledge_add_concept(body: ConceptBody):
    """Concept 노드 직접 등록 (anchor 가 아닌 graph 핵심 객체).
    재실행 시 같은 concept_id 면 update (idempotent).
    """
    from bastion.graph import get_graph
    g = get_graph()
    content = {"description": body.description, **body.properties}
    meta = {"source": body.source, "kind": "external_knowledge"}
    g.add_node(body.concept_id, "Concept", body.name, content=content, meta=meta)
    return {"concept_id": body.concept_id, "type": "Concept"}


class IocCheckBody(BaseModel):
    iocs: list[str]


@app.post("/history/repeat-iocs")
def history_check_repeat_iocs(body: IocCheckBody):
    """관찰된 IoC 가 과거 침해 anchor 와 매칭되는지 — 반복 침해 탐지."""
    return {"hits": _history().match_repeat_iocs(body.iocs)}


class ChangelogBody(BaseModel):
    target_kind: str   # asset / rule / policy / playbook
    target_id: str
    diff: str
    actor: str = ""
    rationale: str = ""


@app.post("/history/changelog")
def history_add_changelog(body: ChangelogBody):
    v = _history().add_changelog(
        body.target_kind, body.target_id, body.diff,
        actor=body.actor, rationale=body.rationale,
    )
    return {"version": v}


@app.get("/history/changelog/{target_kind}/{target_id}")
def history_changelog(target_kind: str, target_id: str):
    return {"changelog": _history().changelog(target_kind, target_id)}


@app.get("/history/graph-view")
def history_graph_view(limit: int = 200):
    """KG UI 통합용 — Anchor + Narrative 를 graph-compatible 노드 형태로 반환.
    Event 는 너무 많을 수 있어 graph 노드로 노출하지 않고 detail panel 에서 timeline 으로 표시.
    """
    h = _history()
    nodes: list[dict] = []
    edges: list[dict] = []
    next_eid = 1
    # Narratives
    with h._conn() as c:
        for r in c.execute(
            "SELECT * FROM history_narratives ORDER BY started_at DESC LIMIT ?",
            (limit,)
        ).fetchall():
            d = dict(r)
            nodes.append({
                "id": d["id"],
                "type": "Narrative",
                "name": d["title"],
                "meta": {"status": d["status"], "started_at": d["started_at"],
                         "ended_at": d["ended_at"], "summary": d["summary"]},
                "updated_at": d["started_at"],
            })
        # Anchors
        for r in c.execute(
            "SELECT * FROM history_anchors ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall():
            d = dict(r)
            nodes.append({
                "id": d["id"],
                "type": "Anchor",
                "name": d["label"],
                "meta": {"kind": d["kind"], "body": d["body"][:300],
                         "valid_from": d["valid_from"], "valid_until": d["valid_until"]},
                "updated_at": d["created_at"],
            })
            # Anchor → related_ids 엣지
            try:
                rel = json.loads(d["related_ids"] or "[]")
            except Exception:
                rel = []
            for target in rel:
                edges.append({"id": next_eid, "src": d["id"], "dst": target,
                              "type": "relates_to", "weight": 1.0})
                next_eid += 1
        # Narrative → contained Events 카운트 (참고)
        for n in nodes:
            if n["type"] != "Narrative":
                continue
            cnt = c.execute(
                "SELECT COUNT(*) FROM history_events WHERE narrative_id=?",
                (n["id"],)
            ).fetchone()[0]
            n["meta"]["event_count"] = cnt
    return {"nodes": nodes, "edges": edges}


@app.get("/history/asset-timeline/{asset_id}")
def history_asset_timeline(asset_id: str, limit: int = 200):
    """Asset 노드 detail panel 용 — 해당 자산의 timeline + narratives + anchors + changelog."""
    h = _history()
    pkg = h.handoff(asset_id)
    pkg["limit"] = limit
    return pkg


# ── Asset domain ─────────────────────────────────────────────────────────

class AssetRegisterBody(BaseModel):
    asset_id: str
    name: str
    kind: str = "host"   # host/application/model/data_store/network_device/...
    ip: str = ""
    os: str = ""
    services: list[str] = []
    meta: dict = {}


@app.post("/assets/register")
def assets_register(body: AssetRegisterBody):
    from bastion.asset_domain import register_asset
    return register_asset(
        asset_id=body.asset_id, name=body.name, kind=body.kind,
        ip=body.ip, os=body.os, services=body.services, meta=body.meta,
    )


@app.get("/assets/list")
def assets_list(kind: str = "", limit: int = 200):
    from bastion.asset_domain import list_assets
    return {"assets": list_assets(kind=kind, limit=limit)}


class AssetLinkBody(BaseModel):
    src: str
    dst: str
    edge_type: str = "connects_to"  # ARCH_EDGES 중 하나
    meta: dict = {}


@app.post("/assets/link")
def assets_link(body: AssetLinkBody):
    from bastion.asset_domain import link_assets
    return link_assets(body.src, body.dst, body.edge_type, body.meta)


# ── Architecture ─────────────────────────────────────────────────────────

@app.get("/architecture/topology")
def arch_topology(root: str = "", max_depth: int = 3):
    from bastion.asset_domain import architecture_topology
    return architecture_topology(root_asset=root, max_depth=max_depth)


@app.get("/architecture/flow")
def arch_flow(src: str, dst: str):
    from bastion.asset_domain import architecture_packet_flow
    return architecture_packet_flow(src, dst)


# ── Work domain — Strategic ───────────────────────────────────────────────

class MissionBody(BaseModel):
    title: str
    statement: str
    owner: str = "CISO"


@app.post("/work/mission")
def work_mission(body: MissionBody):
    from bastion.work_domain import add_mission
    return {"mission_id": add_mission(body.title, body.statement, body.owner)}


class VisionBody(BaseModel):
    title: str
    horizon_year: int
    statement: str
    mission_id: str = ""


@app.post("/work/vision")
def work_vision(body: VisionBody):
    from bastion.work_domain import add_vision
    return {"vision_id": add_vision(body.title, body.horizon_year,
                                     body.statement, body.mission_id)}


class GoalBody(BaseModel):
    title: str
    due: str
    vision_id: str = ""
    description: str = ""


@app.post("/work/goal")
def work_goal(body: GoalBody):
    from bastion.work_domain import add_goal
    return {"goal_id": add_goal(body.title, body.due, body.vision_id,
                                 body.description)}


class StrategyBody(BaseModel):
    title: str
    goal_id: str
    approach: str = ""


@app.post("/work/strategy")
def work_strategy(body: StrategyBody):
    from bastion.work_domain import add_strategy
    return {"strategy_id": add_strategy(body.title, body.goal_id, body.approach)}


class KpiBody(BaseModel):
    name: str
    target: float
    unit: str = ""
    measures: str = ""
    goal_id: str = ""
    strategy_id: str = ""


@app.post("/work/kpi")
def work_kpi(body: KpiBody):
    from bastion.work_domain import add_kpi
    return {"kpi_id": add_kpi(body.name, body.target, body.unit,
                                body.measures, body.goal_id, body.strategy_id)}


class KpiRecordBody(BaseModel):
    kpi_id: str
    value: float
    ts: str = ""
    note: str = ""


@app.post("/work/kpi/record")
def work_kpi_record(body: KpiRecordBody):
    from bastion.work_domain import record_kpi
    return record_kpi(body.kpi_id, body.value, body.ts, body.note)


# ── Work domain — Tactical ──────────────────────────────────────────────

class PlanBody(BaseModel):
    title: str
    period: str
    owner: str = ""
    strategy_id: str = ""
    goal_id: str = ""
    description: str = ""


@app.post("/work/plan")
def work_plan(body: PlanBody):
    from bastion.work_domain import add_plan
    return {"plan_id": add_plan(body.title, body.period, body.owner,
                                  body.strategy_id, body.goal_id,
                                  body.description)}


class TodoBody(BaseModel):
    title: str
    due: str
    plan_id: str = ""
    assignee: str = ""
    description: str = ""


@app.post("/work/todo")
def work_todo(body: TodoBody):
    from bastion.work_domain import add_todo
    return {"todo_id": add_todo(body.title, body.due, body.plan_id,
                                  body.assignee, body.description)}


class StatusBody(BaseModel):
    node_id: str
    status: str   # open/in_progress/completed/blocked/cancelled
    note: str = ""


@app.post("/work/status")
def work_status(body: StatusBody):
    from bastion.work_domain import update_status
    return update_status(body.node_id, body.status, body.note)


@app.get("/work/trace/{node_id}")
def work_trace(node_id: str, max_depth: int = 8):
    from bastion.work_domain import trace_to_mission
    return trace_to_mission(node_id, max_depth)


@app.get("/work/dashboard")
def work_dashboard():
    from bastion.work_domain import strategic_dashboard
    return strategic_dashboard()


@app.get("/assets")
def assets():
    return agent.evidence_db.get_assets()


class AssetUpdateBody(BaseModel):
    ip: str
    status: str = "healthy"
    notes: str = ""


@app.put("/assets/{role}")
def update_asset(role: str, body: AssetUpdateBody):
    """온보딩 완료 후 asset 등록/갱신. LLM 호출 없이 직접 등록."""
    agent.evidence_db.update_asset(role, body.ip, body.status, body.notes)
    return {"role": role, "ip": body.ip, "status": body.status}


# ── Ollama 호환 프록시 엔드포인트 ─────────────────────────────────────────────
# 실습 스크립트가 기존 Ollama API 형식 그대로 사용하되 bastion을 통해 라우팅

@app.post("/api/generate")
def ollama_generate_proxy(request: dict):
    """Ollama /api/generate 호환 프록시 — bastion을 통해 LLM으로 포워딩.
    모델이 지정되지 않거나 없는 모델 요청 시 bastion 설정 모델(LLM_SUBAGENT_MODEL)로 교체.
    """
    import httpx
    # 모델을 설정된 서브에이전트 모델로 강제 지정 (gemma3:4b 등 없는 모델 방지)
    request["model"] = agent.model
    request.setdefault("stream", False)
    try:
        resp = httpx.post(
            f"{agent.ollama_url}/api/generate",
            json=request,
            timeout=120,
        )
        return resp.json()
    except Exception as e:
        return {"error": str(e), "response": ""}


@app.post("/api/chat")
def ollama_chat_proxy(request: dict):
    """Ollama /api/chat 호환 프록시 — bastion을 통해 LLM으로 포워딩.
    모델을 bastion 설정 모델로 교체.
    """
    import httpx
    request["model"] = agent.model
    request.setdefault("stream", False)
    try:
        resp = httpx.post(
            f"{agent.ollama_url}/api/chat",
            json=request,
            timeout=120,
        )
        return resp.json()
    except Exception as e:
        return {"error": str(e), "message": {"content": ""}}


@app.get("/api/tags")
def ollama_tags_proxy():
    """Ollama /api/tags 호환 프록시"""
    import httpx
    try:
        resp = httpx.get(f"{agent.ollama_url}/api/tags", timeout=10)
        return resp.json()
    except Exception as e:
        return {"models": [], "error": str(e)}


@app.get("/api/version")
def ollama_version_proxy():
    """Ollama /api/version 호환 프록시"""
    import httpx
    try:
        resp = httpx.get(f"{agent.ollama_url}/api/version", timeout=10)
        return resp.json()
    except Exception as e:
        return {"version": "unknown", "error": str(e)}


class OnboardRequest(BaseModel):
    role: str
    ip: str
    ssh_user: str = "ccc"
    ssh_password: str = "1"
    gpu_url: str = ""


@app.post("/onboard")
def onboard(req: OnboardRequest):
    """VM 온보딩 — SubAgent 설치 + 역할별 소프트웨어 + Asset 등록.

    NDJSON 스트림으로 단계별 진행상황 실시간 반환. 타임아웃 없음.

    예시:
        curl -N -X POST http://localhost:8003/onboard \\
             -H 'Content-Type: application/json' \\
             -d '{"role": "secu", "ip": "192.168.208.155"}'
    """
    from bastion import onboard_vm, LLM_BASE_URL, LLM_MANAGER_MODEL, LLM_SUBAGENT_MODEL

    def event_generator():
        yield json.dumps({"event": "start", "role": req.role, "ip": req.ip}, ensure_ascii=False) + "\n"
        try:
            result = onboard_vm(
                ip=req.ip, role=req.role,
                user=req.ssh_user, password=req.ssh_password,
                gpu_url=req.gpu_url or LLM_BASE_URL,
                manager_model=LLM_MANAGER_MODEL,
                subagent_model=LLM_SUBAGENT_MODEL,
            )
            for step in result.get("steps", []):
                yield json.dumps({"event": "step", **step}, ensure_ascii=False) + "\n"

            healthy = result.get("healthy", False)
            internal_ip = result.get("internal_ip", req.ip)

            # Asset 등록
            status = "healthy" if healthy else "unreachable"
            agent.evidence_db.update_asset(req.role, internal_ip, status, "온보딩")

            yield json.dumps({
                "event": "done",
                "role": req.role,
                "healthy": healthy,
                "internal_ip": internal_ip,
                "error": result.get("error", ""),
            }, ensure_ascii=False) + "\n"

        except Exception as e:
            yield json.dumps({"event": "error", "role": req.role, "message": str(e)}, ensure_ascii=False) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")


@app.post("/chat")
def chat(req: ChatRequest):
    """자연어 요청을 bastion에 실행.

    stream=True (기본): NDJSON 스트림 — 이벤트마다 한 줄씩 반환.
    stream=False: 전체 이벤트 배열을 JSON으로 한번에 반환.

    NDJSON 예시 (curl):
        curl -N -X POST http://localhost:8003/chat \\
             -H 'Content-Type: application/json' \\
             -d '{"message": "suricata 상태 확인해줘"}'
    """
    def approval_callback(step_name: str, skill: str, params: dict) -> bool:
        return req.auto_approve

    # 승인 모드 주입 — agent._should_ask_approval 가 참조
    agent.approval_mode = (req.approval_mode or "normal").lower()

    # 테스트 메타데이터를 agent에 주입 → evidence DB 기록 시 사용
    agent._test_meta = {
        "course": req.course,
        "lab_id": req.lab_id,
        "step_order": req.step_order,
        "test_session": req.test_session,
    } if req.course else {}
    # EG ablation mode — _test_meta 는 evidence_db.add(**_test_meta) 로 spread 되므로
    # eg_mode 를 넣으면 TypeError. 별도 attr 로 분리.
    agent._eg_mode = (req.eg_mode or "full").lower()
    # Step 3: 채점 기준 정렬 — agent 가 같은 기준으로 작업
    agent._verify_context = {
        "intent": req.verify_intent or "",
        "success_criteria": list(req.verify_success_criteria or []),
        "acceptable_methods": list(req.verify_acceptable_methods or []),
        "negative_signs": list(req.verify_negative_signs or []),
    } if (req.verify_intent or req.verify_success_criteria) else {}

    # course 기반 manager LLM 선택 (공격/대전만 derestricted)
    target_model = _resolve_manager_model(req.course)
    is_attack = req.course in ATTACK_COURSES

    # request_id (mission lifecycle 의 모든 syslog event correlation)
    import uuid as _uuid, time as _time
    _req_id = _uuid.uuid4().hex
    _ts0 = _time.time()
    _meta = {"request_id": _req_id, "course": req.course, "step_order": req.step_order,
             "user_prompt": (req.message or "")[:120]}
    _emit_bastion_syslog("bastion.request.received", {**_meta, "model": target_model})

    def event_generator():
        with _model_swap_lock:
            original = agent.model
            original_attack = getattr(agent, "attack_mode", False)
            agent.model = target_model
            agent.attack_mode = is_attack
            seq = 0
            try:
                if target_model != original:
                    yield json.dumps({"event": "model_routing", "course": req.course, "model": target_model, "attack_mode": is_attack}, ensure_ascii=False) + "\n"
                for evt in agent.chat(req.message, approval_callback=approval_callback):
                    seq += 1
                    _emit_bastion_syslog(f"bastion.event.{evt.get('event','unknown')}",
                                          {**_meta, "seq": seq, **_slim_evt(evt)})
                    yield json.dumps(evt, ensure_ascii=False) + "\n"
                _emit_bastion_syslog("bastion.request.completed",
                                      {**_meta, "seq": seq,
                                       "duration_ms": int((_time.time()-_ts0)*1000)})
            finally:
                agent.model = original
                agent.attack_mode = original_attack
                agent._test_meta = {}

    if req.stream:
        return StreamingResponse(
            event_generator(),
            media_type="application/x-ndjson",
        )
    else:
        with _model_swap_lock:
            original = agent.model
            original_attack = getattr(agent, "attack_mode", False)
            agent.model = target_model
            agent.attack_mode = is_attack
            try:
                events = list(agent.chat(req.message, approval_callback=approval_callback))
                if target_model != original:
                    events.insert(0, {"event": "model_routing", "course": req.course, "model": target_model, "attack_mode": is_attack})
                # batch syslog (stream=False) — 모든 event 를 사후 송신
                for s, evt in enumerate(events, 1):
                    _emit_bastion_syslog(f"bastion.event.{evt.get('event','unknown')}",
                                          {**_meta, "seq": s, **_slim_evt(evt)})
                _emit_bastion_syslog("bastion.request.completed",
                                      {**_meta, "seq": len(events),
                                       "duration_ms": int((_time.time()-_ts0)*1000)})
            finally:
                agent.model = original
                agent.attack_mode = original_attack
                agent._test_meta = {}
        return {"events": events}


# ── Discovery (인프라 자동 발견, Phase B) ──────────────────────────────────
@app.post("/discover")
def discover():
    """docker 인프라를 다시 스캔 → 역할→컨테이너 매핑 + 자산 등록. 결과 반환."""
    try:
        from bastion.discovery import discover_infra
        return discover_infra(agent.vm_ips)
    except Exception as e:
        return {"error": str(e), "containers": [], "role_map": {}}


@app.get("/infra-map")
def infra_map():
    """현재 발견된 역할→컨테이너 매핑 + discovery 활성 여부."""
    import os as _os
    try:
        from bastion.discovery import discovered_map
        return {"discovery_enabled": _os.getenv("BASTION_DISCOVERY", "0") == "1",
                "role_map": discovered_map()}
    except Exception as e:
        return {"error": str(e), "role_map": {}}


# ── Harness (다중 페르소나 팀) ─────────────────────────────────────────────
class HarnessRunRequest(BaseModel):
    message: str
    harness_id: str = ""        # 비우면 트리거 자동 매칭
    auto_approve: bool = True
    approval_mode: str = "normal"
    course: str = ""
    stream: bool = True


@app.get("/harness/list")
def harness_list():
    """사용 가능한 하네스(.bastion/skills/*) 목록."""
    try:
        from bastion.harness import list_harnesses
        return {"harnesses": list_harnesses()}
    except Exception as e:
        return {"harnesses": [], "error": str(e)}


@app.get("/personas")
def personas():
    """기본 SOC 페르소나 라이브러리(.bastion/agents/*)."""
    try:
        from bastion.harness import load_personas, resolve_model
        ps = load_personas()
        return {"personas": [
            {"role": p.role, "model_tier": p.model_tier,
             "model": resolve_model(p.model_tier),
             "allowed_skills": p.allowed_skills, "can_write": p.can_write,
             "description": p.description} for p in ps.values()]}
    except Exception as e:
        return {"personas": [], "error": str(e)}


@app.post("/harness/generate")
def harness_generate(req: HarnessRunRequest):
    """dry-run — 하네스 spec 로드 + 검증만(실행 없음). 자동매칭 가능."""
    try:
        from bastion.harness import load_harness, validate_spec
    except Exception as e:
        return {"error": f"import: {e}"}
    hid = req.harness_id or (agent._should_use_harness(req.message) or "")
    if not hid:
        return {"error": "no harness matched", "message": req.message}
    try:
        spec = load_harness(hid)
    except Exception as e:
        return {"error": f"load {hid}: {e}"}
    errs = validate_spec(spec)
    return {"harness_id": hid, "valid": not errs, "errors": errs, "spec": spec.to_dict()}


@app.post("/harness/run")
def harness_run(req: HarnessRunRequest):
    """하네스 6단계 팀 실행 — NDJSON 스트림. harness_id 비우면 트리거 자동매칭."""
    def approval_callback(step_name: str, skill: str, params: dict) -> bool:
        return req.auto_approve
    agent.approval_mode = (req.approval_mode or "normal").lower()
    target_model = _resolve_manager_model(req.course)
    is_attack = req.course in ATTACK_COURSES

    def gen():
        from bastion.harness import load_harness, validate_spec
        from bastion import orchestrator as _orch
        with _model_swap_lock:
            original = agent.model
            original_attack = getattr(agent, "attack_mode", False)
            agent.model = target_model
            agent.attack_mode = is_attack
            try:
                hid = req.harness_id or (agent._should_use_harness(req.message) or "")
                if not hid:
                    yield json.dumps({"event": "error", "error": "no harness matched",
                                      "message": req.message}, ensure_ascii=False) + "\n"
                    return
                try:
                    spec = load_harness(hid)
                except Exception as e:
                    yield json.dumps({"event": "error", "error": f"load {hid}: {e}"},
                                     ensure_ascii=False) + "\n"
                    return
                errs = validate_spec(spec)
                if errs:
                    yield json.dumps({"event": "harness_invalid", "harness_id": hid,
                                      "errors": errs}, ensure_ascii=False) + "\n"
                    return
                if target_model != original:
                    yield json.dumps({"event": "model_routing", "course": req.course,
                                      "model": target_model}, ensure_ascii=False) + "\n"
                for evt in _orch.run_harness(spec, req.message, agent, approval_callback):
                    yield json.dumps(evt, ensure_ascii=False) + "\n"
            finally:
                agent.model = original
                agent.attack_mode = original_attack

    if req.stream:
        return StreamingResponse(gen(), media_type="application/x-ndjson")
    return {"events": [json.loads(l) for l in gen() if l.strip()]}


class AskRequest(BaseModel):
    message: str
    auto_approve: bool = True  # /ask는 기본 자동승인 (실습용)


@app.post("/ask")
def ask(req: AskRequest):
    """실습 스크립트용 단순 질문 API — LLM 답변 텍스트만 반환.

    /chat의 간소화 버전. 스트리밍 없이 답변 텍스트만 반환하여 셸 스크립트에서 쉽게 사용 가능.

    예시:
        curl -s -X POST http://localhost:8003/ask \\
             -H 'Content-Type: application/json' \\
             -d '{"message": "프롬프트 인젝션이란?"}' \\
             | python3 -c "import sys,json; print(json.load(sys.stdin)['answer'])"
    """
    def approval_callback(step_name: str, skill: str, params: dict) -> bool:
        return req.auto_approve

    answer = ""
    skill_outputs = []
    events = []
    for evt in agent.chat(req.message, approval_callback=approval_callback):
        events.append(evt)
        e = evt.get("event", "")
        if e == "stream_token":
            answer += evt.get("token", "")
        elif e == "skill_result":
            skill_outputs.append({
                "skill": evt.get("skill", ""),
                "output": evt.get("output", ""),
                "success": evt.get("success", False),
            })

    return {
        "answer": answer,
        "success": True,
        "skill_outputs": skill_outputs,
        "event_count": len(events),
    }


# ── 직접 실행 ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("BASTION_API_PORT", "8003"))
    uvicorn.run("apps.bastion.api:app", host="0.0.0.0", port=port, reload=False)
