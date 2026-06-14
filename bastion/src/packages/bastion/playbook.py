"""Bastion Playbook 엔진 — YAML 기반 구조화된 작업 실행

"Playbook이 법이다" — LLM이 즉흥하지 않고 등록된 Playbook의 순서대로 실행.
LLM은 Playbook 선택과 파라미터 채우기만 담당.

KG-2 확장 schema (v2):
  playbook_id: pb-...
  name: 한 줄 이름
  description: 한 단락 설명
  version: 정수 (변경마다 +1)
  risk_level: low | med | high
  reasoning:                          # LLM 의 의사결정 근거 (영구 박제)
    task_decomposition: |
      ...
    considered_alternatives:
      - {tool: ..., rejected_reason: ...}
    why_this_approach: ...
    assumptions: [...]
    known_risks: [...]
  plan:                               # 또는 steps (v1 호환)
    - step: 1
      intent: 한 줄 의도
      skill: shell
      params: {...}
      thinking: |                     # 이 step 의 LLM 추론
        ...
      success_signal: stdout 매치 패턴
      on_error:
        - {pattern: regex, action: ...}
  exec_history:                       # 자동 갱신
    total: int
    success: int
    recent_5: [pass|fail, ...]
  known_pitfalls: [...]              # compaction 산출물
  related_concepts: [T1053, ...]     # MITRE 등

v1 호환: reasoning 누락이면 자동 빈 객체로 채움. plan 대신 steps 도 OK.
"""
from __future__ import annotations
import os
import glob
import time
import re
import yaml
from typing import Any, Generator

from packages.bastion.skills import execute_skill, SKILLS


# ── 확장 schema 헬퍼 ────────────────────────────────────────────────────


PLAYBOOK_SCHEMA_VERSION = 2


def _slugify(text: str, max_len: int = 60) -> str:
    """한국어 + 영문 → 파일명 안전 slug."""
    s = re.sub(r"\s+", "-", text.strip().lower())
    s = re.sub(r"[^\w가-힣\-]", "", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s[:max_len] or "pb-untitled"


def normalize_playbook(pb: dict) -> dict:
    """v1/v2 혼재 → v2 정규화 (in-place 변형 후 반환)."""
    if not isinstance(pb, dict):
        return pb
    pb.setdefault("schema_version", PLAYBOOK_SCHEMA_VERSION)
    pb.setdefault("version", 1)
    pb.setdefault("risk_level", "low")
    pb.setdefault("reasoning", {})
    if not isinstance(pb.get("reasoning"), dict):
        pb["reasoning"] = {"why_this_approach": str(pb["reasoning"])}
    rs = pb["reasoning"]
    rs.setdefault("task_decomposition", "")
    rs.setdefault("considered_alternatives", [])
    rs.setdefault("why_this_approach", "")
    rs.setdefault("assumptions", [])
    rs.setdefault("known_risks", [])
    # plan 우선, 없으면 steps fallback
    if "plan" not in pb and "steps" in pb:
        pb["plan"] = pb["steps"]
    pb.setdefault("plan", [])
    # 각 step 기본 필드
    for i, step in enumerate(pb["plan"], 1):
        if not isinstance(step, dict):
            continue
        step.setdefault("step", i)
        step.setdefault("intent", step.get("name", ""))
        step.setdefault("thinking", "")
        step.setdefault("success_signal", "")
        step.setdefault("on_error", [])
    pb.setdefault("exec_history", {"total": 0, "success": 0, "recent_5": []})
    pb.setdefault("known_pitfalls", [])
    pb.setdefault("related_concepts", [])
    return pb


def validate_playbook(pb: dict) -> list[str]:
    """경고 목록 반환 (빈 리스트면 OK). 강제 오류 없음 — agent 가 점진 채움."""
    warnings = []
    if not isinstance(pb, dict):
        return ["not a dict"]
    if not pb.get("playbook_id"):
        warnings.append("missing playbook_id")
    if not pb.get("name") and not pb.get("title"):
        warnings.append("missing name")
    if not pb.get("plan") and not pb.get("steps"):
        warnings.append("no plan/steps")
    rs = pb.get("reasoning") or {}
    if isinstance(rs, dict):
        if not rs.get("why_this_approach") and not rs.get("task_decomposition"):
            warnings.append("reasoning empty (왜 이 방법인지 미기록)")
    for step in pb.get("plan") or pb.get("steps") or []:
        if isinstance(step, dict):
            if not step.get("skill"):
                warnings.append(f"step {step.get('step', '?')}: skill 누락")
            if not step.get("thinking") and not step.get("intent"):
                warnings.append(f"step {step.get('step', '?')}: thinking/intent 누락")
    return warnings


def write_playbook(pb: dict, playbooks_dir: str = "") -> str:
    """playbook dict → YAML 저장. 파일명 = playbook_id 기반.

    이미 존재하면 version+=1, supersedes 메타 추가 후 새 파일로 저장.
    반환: 저장된 파일 경로.
    """
    pb = normalize_playbook(dict(pb))
    if not pb.get("playbook_id"):
        pb["playbook_id"] = "pb-" + _slugify(pb.get("name") or pb.get("title") or "untitled")
    if not playbooks_dir:
        playbooks_dir = PLAYBOOKS_DIR
    os.makedirs(playbooks_dir, exist_ok=True)
    fname = pb["playbook_id"] + ".yaml"
    fpath = os.path.join(playbooks_dir, fname)
    # 기존 파일 있으면 version 증가
    if os.path.isfile(fpath):
        try:
            old = yaml.safe_load(open(fpath, encoding="utf-8")) or {}
            pb["version"] = int(old.get("version", 1)) + 1
            pb["supersedes_version"] = old.get("version", 1)
        except Exception:
            pass
    pb["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(fpath, "w", encoding="utf-8") as fh:
        yaml.safe_dump(pb, fh, allow_unicode=True, sort_keys=False,
                       default_flow_style=False, width=120)
    return fpath


def update_exec_history(playbook_id: str, success: bool,
                        playbooks_dir: str = "") -> None:
    """실행 후 exec_history 갱신 — recent_5 슬라이딩 윈도우 + total/success 카운트."""
    if not playbooks_dir:
        playbooks_dir = PLAYBOOKS_DIR
    fpath = os.path.join(playbooks_dir, playbook_id + ".yaml")
    if not os.path.isfile(fpath):
        # playbook_id 가 prefix 형태면 파일 검색
        for f in glob.glob(os.path.join(playbooks_dir, "*.yaml")):
            try:
                pb = yaml.safe_load(open(f, encoding="utf-8")) or {}
                if pb.get("playbook_id") == playbook_id:
                    fpath = f
                    break
            except Exception:
                continue
        if not os.path.isfile(fpath):
            return
    try:
        pb = yaml.safe_load(open(fpath, encoding="utf-8")) or {}
    except Exception:
        return
    pb = normalize_playbook(pb)
    eh = pb["exec_history"]
    eh["total"] = int(eh.get("total", 0)) + 1
    if success:
        eh["success"] = int(eh.get("success", 0)) + 1
    recent = list(eh.get("recent_5", []))[-4:]
    recent.append("pass" if success else "fail")
    eh["recent_5"] = recent
    pb["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(fpath, "w", encoding="utf-8") as fh:
        yaml.safe_dump(pb, fh, allow_unicode=True, sort_keys=False,
                       default_flow_style=False, width=120)


# ── 기존 API ────────────────────────────────────────────────────────────


def _resolve_playbooks_dir() -> str:
    """레이아웃별 playbook 경로 자동 감지.
    - CCC nested: packages/bastion/playbook.py → ../../contents/playbooks
    - bastion flat: bastion/playbook.py → ../contents/playbooks
    - 환경변수 override: BASTION_PLAYBOOKS_DIR
    """
    override = os.getenv("BASTION_PLAYBOOKS_DIR", "").strip()
    if override and os.path.isdir(override):
        return override
    here = os.path.dirname(__file__)
    candidates = [
        os.path.normpath(os.path.join(here, "..", "..", "contents", "playbooks")),  # CCC
        os.path.normpath(os.path.join(here, "..", "contents", "playbooks")),         # bastion flat
    ]
    for p in candidates:
        if os.path.isdir(p):
            return p
    # 둘 다 없으면 첫 후보 반환 (디렉토리 자동 생성 시 그쪽으로)
    return candidates[0]


PLAYBOOKS_DIR = _resolve_playbooks_dir()


def load_playbook(playbook_id: str) -> dict | None:
    """Playbook YAML 로드 — v1 자동으로 v2 schema 로 normalize."""
    for f in glob.glob(os.path.join(PLAYBOOKS_DIR, "*.yaml")):
        try:
            with open(f, encoding="utf-8") as fh:
                pb = yaml.safe_load(fh)
        except Exception:
            continue
        if pb and pb.get("playbook_id") == playbook_id:
            return normalize_playbook(pb)
    return None


def list_playbooks() -> list[dict]:
    """등록된 Playbook 목록 — exec_history / version 등 메타 포함."""
    result = []
    for f in sorted(glob.glob(os.path.join(PLAYBOOKS_DIR, "*.yaml"))):
        try:
            with open(f, encoding="utf-8") as fh:
                pb = yaml.safe_load(fh)
        except Exception:
            continue
        if not pb:
            continue
        pb = normalize_playbook(pb)
        eh = pb.get("exec_history") or {}
        result.append({
            "playbook_id": pb.get("playbook_id", ""),
            "title": pb.get("title", "") or pb.get("name", ""),
            "description": pb.get("description", ""),
            "version": pb.get("version", 1),
            "risk_level": pb.get("risk_level", "low"),
            "steps": len(pb.get("plan") or pb.get("steps") or []),
            "exec_total": eh.get("total", 0),
            "exec_success": eh.get("success", 0),
            "has_reasoning": bool((pb.get("reasoning") or {}).get("why_this_approach")
                                  or (pb.get("reasoning") or {}).get("task_decomposition")),
        })
    return result


def run_playbook(playbook_id: str, vm_ips: dict[str, str],
                 params: dict[str, Any] = None,
                 ollama_url: str = "", model: str = "",
                 approval_callback=None) -> Generator[dict, None, None]:
    """Playbook 실행 — 스텝별 SSE 이벤트 스트리밍

    approval_callback: requires_approval=True 스텝에서 호출. True 반환 시 실행, False면 스킵.
    """
    pb = load_playbook(playbook_id)
    if not pb:
        yield {"event": "error", "message": f"Playbook not found: {playbook_id}"}
        return

    params = params or {}
    steps = pb.get("steps", [])
    evidence = []

    yield {"event": "playbook_start", "playbook_id": playbook_id, "title": pb.get("title", ""), "total_steps": len(steps)}

    for i, step in enumerate(steps):
        step_name = step.get("name", f"Step {i+1}")
        skill_name = step.get("skill", "")
        step_params = {**params, **step.get("params", {})}
        on_failure = step.get("on_failure", "continue")
        requires_approval = step.get("requires_approval", False)

        # 파라미터 템플릿 치환 ({suspect_ip} → 실제 값)
        for k, v in step_params.items():
            if isinstance(v, str):
                for pk, pv in params.items():
                    v = v.replace(f"{{{pk}}}", str(pv))
                step_params[k] = v

        yield {"event": "step_start", "step": i+1, "name": step_name, "skill": skill_name}

        # 승인 필요
        if requires_approval or SKILLS.get(skill_name, {}).get("requires_approval"):
            if approval_callback:
                approved = approval_callback(step_name, skill_name, step_params)
                if not approved:
                    yield {"event": "step_skip", "step": i+1, "name": step_name, "reason": "User denied"}
                    continue

        # Skill 실행
        if skill_name and skill_name in SKILLS:
            result = execute_skill(skill_name, step_params, vm_ips, ollama_url, model)
        else:
            result = {"success": False, "error": f"Unknown skill: {skill_name}"}

        evidence.append({"step": step_name, "skill": skill_name, "result": result})

        yield {
            "event": "step_done", "step": i+1, "name": step_name,
            "success": result.get("success", False),
            "output": str(result.get("output", ""))[:500],
        }

        # 실패 정책
        if not result.get("success") and on_failure == "abort":
            yield {"event": "playbook_abort", "step": i+1, "name": step_name, "reason": "Step failed with on_failure=abort"}
            break

    passed = sum(1 for e in evidence if e["result"].get("success"))
    yield {
        "event": "playbook_done",
        "playbook_id": playbook_id,
        "passed": passed,
        "total": len(steps),
        "evidence_count": len(evidence),
    }
