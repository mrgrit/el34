"""Bastion Harness Engineering — 다중 페르소나 팀 하네스 (Phase A).

하네스(harness) = 미리 정의된 작업환경: 전문 페르소나 팀 + 단계(phase) 워크플로 +
도구 경계 + 의존 순서(depends_on) + 생성-검증 루프 + 무발화 리더.

이 모듈은 단일 표준 표현인 `HarnessSpec` 과 그 입출력을 담당한다:
  - 수동 인터페이스: `.bastion/agents/*.md` + `.bastion/skills/*/SKILL.md` + `BASTION.md`
    (revfactory/harness-engineering-with-cc 책 스타일을 bastion 컨벤션으로) → HarnessSpec 파싱.
  - 자동 생성(Phase C, harness_gen.py): discovery + Experience Graph → 동일 HarnessSpec.
양쪽이 같은 spec 을 만들고, orchestrator.run_harness() 가 6단계로 실행한다.

페르소나 = 논리적 서브에이전트(매니저 측). 컨테이너는 자산(asset)으로, 기존 실행 경로
(execute_skill → run_command → docker exec/ssh)로 작용한다. 기계에 묶이지 않는다.
"""
from __future__ import annotations

import os
import re
import json
from dataclasses import dataclass, field, asdict
from typing import Any

try:
    import yaml  # PyYAML (playbook.py 와 동일 의존)
except Exception:  # pragma: no cover
    yaml = None


# ── 모델 티어 → 실제 모델 해석 ────────────────────────────────────────────
# 책은 opus/sonnet/haiku 2~3 티어. bastion 은 manager/subagent/derestricted.
def resolve_model(tier: str) -> str:
    """model_tier → 실제 Ollama 모델명. 환경변수 기반(런타임)."""
    t = (tier or "reasoning").strip().lower()
    if t in ("execution", "exec", "sonnet", "haiku", "small"):
        return os.getenv("LLM_SUBAGENT_MODEL", "") or os.getenv("LLM_MANAGER_MODEL", "")
    if t in ("attack", "offensive", "unsafe", "derestricted"):
        return os.getenv("LLM_MANAGER_MODEL_UNSAFE", "") or os.getenv("LLM_MANAGER_MODEL", "")
    # reasoning | opus | big | default
    return os.getenv("LLM_MANAGER_MODEL", "")


_TIER_ALIASES = {
    "opus": "reasoning", "reasoning": "reasoning", "big": "reasoning",
    "sonnet": "execution", "haiku": "execution", "execution": "execution",
    "exec": "execution", "small": "execution",
    "attack": "attack", "unsafe": "attack", "derestricted": "attack",
}

# 책의 도구 단어(.claude/agents 의 tools) → bastion SKILLS 키 그룹.
# 수동 작성 md 는 보통 bastion 스킬 키를 직접 쓰지만, 책 스타일 import 호환용.
_TOOL_ALIASES = {
    "bash": ["shell"], "read": ["file_manage"], "grep": ["file_manage"],
    "glob": ["file_manage"], "write": ["file_manage"], "edit": ["file_manage"],
    "webfetch": ["http_request"], "web": ["http_request"],
}

# 8 섹션 표준 키 ← md 헤딩(한/영) 별칭
_SECTION_ALIASES = {
    "core_role": ["핵심 역할", "핵심역할", "core role", "role", "역할"],
    "work_principles": ["작업 원칙", "작업원칙", "work principles", "principles", "원칙"],
    "io_protocol": ["입출력 프로토콜", "입출력프로토콜", "io protocol", "input/output", "출력 프로토콜", "출력 형식"],
    "error_handling": ["에러 핸들링", "에러핸들링", "error handling", "errors", "오류 처리"],
    "collaboration": ["협업 정의", "협업정의", "collaboration", "협업"],
    "team_comms": ["팀 통신 프로토콜", "팀 통신", "team communication", "team comms", "통신 프로토콜"],
    "reinvocation": ["재호출 지침", "재호출", "reinvocation", "re-invocation"],
    "quality_self_check": ["품질 자체 검증", "품질자체검증", "quality self-check", "self check", "자체 검증"],
}
_SECTION_KEYS = list(_SECTION_ALIASES.keys())


# ── 데이터 모델 ───────────────────────────────────────────────────────────
@dataclass
class Persona:
    role: str
    description: str = ""               # 트리거 조건(자연어)
    model_tier: str = "reasoning"       # reasoning | execution | attack
    allowed_skills: list[str] = field(default_factory=list)  # ⊆ SKILLS 키 == 도구 경계
    can_write: bool = False             # state-변경 권한
    asset_scope: list[str] = field(default_factory=list)
    active_phases: list[int] = field(default_factory=list)
    prompt: dict[str, str] = field(default_factory=dict)     # 8 섹션
    meta: dict[str, Any] = field(default_factory=dict)       # origin/version/success_rate

    def system_prompt(self) -> str:
        """8 섹션 → 페르소나 시스템 프롬프트 본문."""
        titles = {
            "core_role": "핵심 역할", "work_principles": "작업 원칙",
            "io_protocol": "입출력 프로토콜", "error_handling": "에러 핸들링",
            "collaboration": "협업 정의", "team_comms": "팀 통신 프로토콜",
            "reinvocation": "재호출 지침", "quality_self_check": "품질 자체 검증",
        }
        out = [f"# {self.role}", "", self.description.strip(), ""]
        for k in _SECTION_KEYS:
            body = (self.prompt.get(k) or "").strip()
            if body:
                out.append(f"## {titles[k]}")
                out.append(body)
                out.append("")
        return "\n".join(out).strip()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Persona":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class Verify:
    enabled: bool = False
    criteria: list[str] = field(default_factory=list)
    max_retries: int = 3
    verifier_persona: str = ""


@dataclass
class Task:
    task_id: str
    persona: str
    name: str = ""
    instruction: str = ""
    output_key: str = ""
    depends_on: list[str] = field(default_factory=list)
    verify: Verify = field(default_factory=Verify)
    status: str = "pending"
    attempts: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Task":
        d = dict(d)
        v = d.get("verify") or {}
        if isinstance(v, dict):
            d["verify"] = Verify(**{k: v[k] for k in v if k in Verify.__dataclass_fields__})  # type: ignore[attr-defined]
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: val for k, val in d.items() if k in known})


@dataclass
class Phase:
    id: int
    name: str = ""
    goal: str = ""
    max_concurrency: int = 4
    tasks: list[Task] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "goal": self.goal,
                "max_concurrency": self.max_concurrency,
                "tasks": [t.to_dict() for t in self.tasks]}

    @classmethod
    def from_dict(cls, d: dict) -> "Phase":
        return cls(id=int(d.get("id", 0)), name=d.get("name", ""), goal=d.get("goal", ""),
                   max_concurrency=int(d.get("max_concurrency", 4)),
                   tasks=[Task.from_dict(t) for t in d.get("tasks", [])])


@dataclass
class HarnessSpec:
    harness_id: str
    name: str = ""
    description: str = ""
    source: str = "manual"             # manual | auto | hybrid
    rules: list[str] = field(default_factory=list)
    concurrency_cap: int = 4
    team: list[Persona] = field(default_factory=list)
    phases: list[Phase] = field(default_factory=list)
    bound_goal_id: str = ""
    triggers: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    # 편의 접근
    def persona(self, role: str) -> Persona | None:
        for p in self.team:
            if p.role == role:
                return p
        return None

    def all_tasks(self) -> list[Task]:
        return [t for ph in self.phases for t in ph.tasks]

    def to_dict(self) -> dict:
        return {
            "harness_id": self.harness_id, "name": self.name,
            "description": self.description, "source": self.source,
            "rules": self.rules, "concurrency_cap": self.concurrency_cap,
            "team": [p.to_dict() for p in self.team],
            "phases": [ph.to_dict() for ph in self.phases],
            "bound_goal_id": self.bound_goal_id, "triggers": self.triggers,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HarnessSpec":
        return cls(
            harness_id=d["harness_id"], name=d.get("name", ""),
            description=d.get("description", ""), source=d.get("source", "manual"),
            rules=list(d.get("rules", [])), concurrency_cap=int(d.get("concurrency_cap", 4)),
            team=[Persona.from_dict(p) for p in d.get("team", [])],
            phases=[Phase.from_dict(ph) for ph in d.get("phases", [])],
            bound_goal_id=d.get("bound_goal_id", ""), triggers=list(d.get("triggers", [])),
            meta=dict(d.get("meta", {})),
        )


# ── 디렉터리 해석 ─────────────────────────────────────────────────────────
def resolve_harness_dir() -> str:
    """하네스 콘텐츠 루트. playbook._resolve_playbooks_dir 와 동일 패턴.
    - 환경변수 override: BASTION_HARNESS_DIR
    - packages/bastion/harness.py → ../../harness (src 루트), 또는 ../harness (flat)
    """
    override = os.getenv("BASTION_HARNESS_DIR", "").strip()
    if override:
        return override
    here = os.path.dirname(__file__)
    candidates = [
        os.path.normpath(os.path.join(here, "..", "..", "harness")),  # bastion/src/harness
        os.path.normpath(os.path.join(here, "..", "harness")),
    ]
    for p in candidates:
        if os.path.isdir(p):
            return p
    return candidates[0]


def _agents_dir(root: str = "") -> str:
    return os.path.join(root or resolve_harness_dir(), ".bastion", "agents")


def _skills_dir(root: str = "") -> str:
    return os.path.join(root or resolve_harness_dir(), ".bastion", "skills")


# ── md 파싱 ───────────────────────────────────────────────────────────────
def _parse_frontmatter(text: str) -> tuple[dict, str]:
    """--- yaml --- frontmatter 분리 → (meta, body)."""
    m = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.S)
    if not m:
        return {}, text
    fm_raw, body = m.group(1), m.group(2)
    meta: dict = {}
    if yaml:
        try:
            meta = yaml.safe_load(fm_raw) or {}
        except Exception:
            meta = {}
    if not isinstance(meta, dict):
        meta = {}
    return meta, body


def _canon_section(heading: str) -> str | None:
    h = heading.strip().lower()
    for key, aliases in _SECTION_ALIASES.items():
        for a in aliases:
            if a.lower() in h:
                return key
    return None


def _split_sections(body: str) -> dict[str, str]:
    """'## 제목' 단위로 본문을 8 섹션에 매핑."""
    out: dict[str, str] = {}
    cur_key: str | None = None
    buf: list[str] = []

    def flush():
        nonlocal buf, cur_key
        if cur_key and buf:
            out[cur_key] = (out.get(cur_key, "") + "\n" + "\n".join(buf)).strip()
        buf = []

    for line in body.splitlines():
        hm = re.match(r"^#{1,6}\s+(.*)$", line)
        if hm:
            flush()
            cur_key = _canon_section(hm.group(1))
            continue
        if cur_key:
            buf.append(line)
    flush()
    return out


def _normalize_tools(tools: Any, valid_skills: set[str]) -> list[str]:
    """frontmatter tools → bastion SKILLS 키 리스트(∩ valid)."""
    items: list[str] = []
    if isinstance(tools, str):
        items = [t.strip() for t in re.split(r"[,\s]+", tools) if t.strip()]
    elif isinstance(tools, (list, tuple)):
        items = [str(t).strip() for t in tools if str(t).strip()]
    out: list[str] = []
    for it in items:
        low = it.lower()
        if it in valid_skills:
            out.append(it)
        elif low in _TOOL_ALIASES:
            out.extend(_TOOL_ALIASES[low])
        # 알 수 없는 항목은 무시(경계는 검증에서 ∩ SKILLS)
    # 중복 제거 + valid 교집합
    seen: list[str] = []
    for s in out:
        if s in valid_skills and s not in seen:
            seen.append(s)
    return seen


def parse_agent_md(path: str, valid_skills: set[str] | None = None) -> Persona:
    from bastion.skills import SKILLS  # 지연 import (순환 방지)
    valid_skills = valid_skills if valid_skills is not None else set(SKILLS.keys())
    with open(path, encoding="utf-8") as f:
        text = f.read()
    meta, body = _parse_frontmatter(text)
    role = str(meta.get("name") or os.path.splitext(os.path.basename(path))[0]).strip()
    tier = _TIER_ALIASES.get(str(meta.get("model", "reasoning")).strip().lower(), "reasoning")
    sections = _split_sections(body)
    can_write = bool(meta.get("can_write", False))
    persona = Persona(
        role=role,
        description=str(meta.get("description", "")).strip(),
        model_tier=tier,
        allowed_skills=_normalize_tools(meta.get("tools"), valid_skills),
        can_write=can_write,
        asset_scope=list(meta.get("asset_scope", []) or []),
        active_phases=[int(x) for x in (meta.get("active_phases", []) or [])],
        prompt=sections,
        meta={"origin": meta.get("origin", "base"), "version": int(meta.get("version", 1)),
              "success_rate": float(meta.get("success_rate", 0.0))},
    )
    return persona


def load_personas(root: str = "") -> dict[str, Persona]:
    d = _agents_dir(root)
    out: dict[str, Persona] = {}
    if not os.path.isdir(d):
        return out
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".md"):
            try:
                p = parse_agent_md(os.path.join(d, fn))
                out[p.role] = p
            except Exception:
                continue
    return out


def parse_rules_md(root: str = "") -> list[str]:
    path = os.path.join(root or resolve_harness_dir(), "BASTION.md")
    rules: list[str] = []
    if not os.path.isfile(path):
        return rules
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            m = re.match(r"^[-*]\s+(.*)$", s)
            if m:
                rules.append(m.group(1).strip())
    return rules


def _extract_workflow_yaml(body: str) -> dict | None:
    """SKILL.md 본문의 '## workflow' 다음 ```yaml ... ``` 블록을 파싱."""
    if not yaml:
        return None
    # ## workflow 섹션 안의 첫 코드펜스
    m = re.search(r"##\s*workflow\b.*?\n```(?:ya?ml)?\s*\n(.*?)\n```", body, re.S | re.I)
    if not m:
        # 섹션 헤딩 없이 yaml 펜스에 phases: 가 있으면 허용
        m = re.search(r"```(?:ya?ml)?\s*\n(\s*phases:.*?)\n```", body, re.S | re.I)
    if not m:
        return None
    try:
        data = yaml.safe_load(m.group(1))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _triggers_from(meta: dict, body: str) -> list[str]:
    trg: list[str] = []
    raw = meta.get("triggers") or meta.get("trigger")
    if isinstance(raw, str):
        trg = [t.strip() for t in re.split(r"[,\n]", raw) if t.strip()]
    elif isinstance(raw, (list, tuple)):
        trg = [str(t).strip() for t in raw if str(t).strip()]
    # description 내 "트리거 -" 패턴도 흡수
    dm = re.search(r"트리거\s*[-:]\s*(.+)", str(meta.get("description", "")))
    if dm:
        trg += [t.strip().strip("\"'.。 ").strip() for t in re.split(r"[,\n]", dm.group(1)) if t.strip()]
    return [t for t in dict.fromkeys(t for t in trg if t)]


def _phases_from_workflow(wf: dict) -> list[Phase]:
    phases: list[Phase] = []
    for ph in wf.get("phases", []):
        tasks = [Task.from_dict(t) for t in ph.get("tasks", [])]
        phases.append(Phase(
            id=int(ph.get("id", len(phases))),
            name=ph.get("name", ""), goal=ph.get("goal", ""),
            max_concurrency=int(ph.get("max_concurrency", 4)),
            tasks=tasks,
        ))
    return phases


def load_harness_from_dir(harness_id: str, root: str = "") -> HarnessSpec:
    """`.claude/skills/<harness_id>/SKILL.md` + 참조 페르소나 + CLAUDE.md → HarnessSpec."""
    root = root or resolve_harness_dir()
    skill_path = os.path.join(_skills_dir(root), harness_id, "SKILL.md")
    if not os.path.isfile(skill_path):
        raise FileNotFoundError(f"harness skill not found: {skill_path}")
    with open(skill_path, encoding="utf-8") as f:
        text = f.read()
    meta, body = _parse_frontmatter(text)
    personas_all = load_personas(root)
    wf = _extract_workflow_yaml(body) or {}
    phases = _phases_from_workflow(wf)
    # 워크플로에서 쓰이는 페르소나만 팀에 포함(없으면 전체)
    used_roles = {t.persona for ph in phases for t in ph.tasks}
    used_roles |= {t.verify.verifier_persona for ph in phases for t in ph.tasks if t.verify and t.verify.verifier_persona}
    team = [personas_all[r] for r in personas_all if (not used_roles or r in used_roles)]
    spec = HarnessSpec(
        harness_id=harness_id,
        name=str(meta.get("name", harness_id)),
        description=str(meta.get("description", "")).strip(),
        source="manual",
        rules=parse_rules_md(root),
        concurrency_cap=int(wf.get("concurrency_cap", meta.get("concurrency_cap", 4))),
        team=team,
        phases=phases,
        triggers=_triggers_from(meta, body),
        meta={"skill_path": skill_path},
    )
    return spec


def list_harnesses(root: str = "") -> list[dict]:
    root = root or resolve_harness_dir()
    d = _skills_dir(root)
    out: list[dict] = []
    if not os.path.isdir(d):
        return out
    for name in sorted(os.listdir(d)):
        sp = os.path.join(d, name, "SKILL.md")
        if os.path.isfile(sp):
            try:
                with open(sp, encoding="utf-8") as f:
                    meta, body = _parse_frontmatter(f.read())
                out.append({"harness_id": name, "name": meta.get("name", name),
                            "description": meta.get("description", ""),
                            "triggers": _triggers_from(meta, body)})
            except Exception:
                out.append({"harness_id": name, "name": name, "description": "", "triggers": []})
    return out


# ── 위상 정렬 (depends_on DAG → 배치) ───────────────────────────────────────
def topo_batches(tasks: list[Task]) -> list[list[Task]]:
    """Kahn 알고리즘. 같은 배치 = 동시에 시작 가능. 순환이면 ValueError."""
    by_id = {t.task_id: t for t in tasks}
    indeg = {t.task_id: 0 for t in tasks}
    for t in tasks:
        for dep in t.depends_on:
            if dep in by_id:
                indeg[t.task_id] += 1
    batches: list[list[Task]] = []
    remaining = dict(indeg)
    done: set[str] = set()
    while remaining:
        ready = [tid for tid, d in remaining.items() if d == 0]
        if not ready:
            raise ValueError(f"cyclic depends_on among tasks: {list(remaining)}")
        ready.sort()
        batches.append([by_id[tid] for tid in ready])
        for tid in ready:
            done.add(tid)
            del remaining[tid]
        for t in tasks:
            if t.task_id in remaining:
                remaining[t.task_id] = sum(1 for dep in t.depends_on if dep in by_id and dep not in done)
    return batches


# ── 검증 ──────────────────────────────────────────────────────────────────
def validate_spec(spec: HarnessSpec) -> list[str]:
    """오류/경고 리스트 반환(빈 리스트 = 통과)."""
    from bastion.skills import SKILLS
    valid_skills = set(SKILLS.keys())
    errs: list[str] = []
    roles = {p.role for p in spec.team}
    if not spec.team:
        errs.append("team is empty")
    if not spec.phases:
        errs.append("workflow has no phases")
    # 페르소나 도구 경계 ⊆ SKILLS
    for p in spec.team:
        bad = [s for s in p.allowed_skills if s not in valid_skills]
        if bad:
            errs.append(f"persona '{p.role}' allowed_skills not in SKILLS: {bad}")
    # 태스크 참조 무결성
    all_tasks = spec.all_tasks()
    task_ids = {t.task_id for t in all_tasks}
    if len(task_ids) != len(all_tasks):
        errs.append("duplicate task_id present")
    for t in all_tasks:
        if t.persona not in roles:
            errs.append(f"task '{t.task_id}' references unknown persona '{t.persona}'")
        for dep in t.depends_on:
            if dep not in task_ids:
                errs.append(f"task '{t.task_id}' depends_on unknown task '{dep}'")
        if t.verify and t.verify.enabled:
            vp = t.verify.verifier_persona
            if not vp:
                errs.append(f"task '{t.task_id}' verify enabled but no verifier_persona")
            elif vp not in roles:
                errs.append(f"task '{t.task_id}' verifier '{vp}' not in team")
            elif vp == t.persona:
                errs.append(f"task '{t.task_id}' verifier == producer ('{vp}') — 자기검증 금지")
    # 동시성
    if spec.concurrency_cap < 1:
        errs.append("concurrency_cap must be >= 1")
    for ph in spec.phases:
        if ph.max_concurrency < 1:
            errs.append(f"phase {ph.id} max_concurrency must be >= 1")
    # DAG 순환
    try:
        topo_batches(all_tasks)
    except ValueError as e:
        errs.append(str(e))
    return errs


# ── KG 입출력 ──────────────────────────────────────────────────────────────
def save_to_kg(spec: HarnessSpec) -> None:
    """HarnessSpec + 페르소나를 KG 노드/엣지로 영속화(멱등)."""
    try:
        from bastion.graph import get_graph
    except Exception:
        return
    g = get_graph()
    hid = f"harness:{spec.harness_id}"
    g.add_node(hid, "Harness", spec.name or spec.harness_id,
               content={"description": spec.description, "rules": spec.rules,
                        "source": spec.source, "concurrency_cap": spec.concurrency_cap,
                        "phases": [ph.to_dict() for ph in spec.phases],
                        "persona_roles": [p.role for p in spec.team],
                        "triggers": spec.triggers},
               meta=spec.meta)
    for p in spec.team:
        pid = f"persona:{p.role}"
        g.add_node(pid, "Persona", p.role, content=p.to_dict(), meta=p.meta)
        g.add_edge(pid, hid, "member_of")
        for sk in p.allowed_skills:
            try:
                g.add_edge(pid, f"skill:{sk}", "uses")
            except Exception:
                pass
    if spec.bound_goal_id:
        try:
            g.add_edge(hid, spec.bound_goal_id, "contributes_to")
        except Exception:
            pass


def load_from_kg(harness_id: str) -> HarnessSpec | None:
    try:
        from bastion.graph import get_graph
    except Exception:
        return None
    g = get_graph()
    node = g.get_node(f"harness:{harness_id}")
    if not node:
        return None
    c = node.get("content") or {}
    if isinstance(c, str):
        try:
            c = json.loads(c)
        except Exception:
            c = {}
    team: list[Persona] = []
    for role in c.get("persona_roles", []):
        pn = g.get_node(f"persona:{role}")
        if pn:
            pc = pn.get("content") or {}
            if isinstance(pc, str):
                try:
                    pc = json.loads(pc)
                except Exception:
                    pc = {}
            team.append(Persona.from_dict(pc))
    return HarnessSpec(
        harness_id=harness_id, name=node.get("name", harness_id),
        description=c.get("description", ""), source=c.get("source", "manual"),
        rules=list(c.get("rules", [])), concurrency_cap=int(c.get("concurrency_cap", 4)),
        team=team, phases=[Phase.from_dict(p) for p in c.get("phases", [])],
        triggers=list(c.get("triggers", [])), meta=node.get("meta", {}) or {},
    )


def load_harness(harness_id: str, root: str = "") -> HarnessSpec:
    """우선순위: 디스크(수동 md) > KG. 디스크가 정본."""
    try:
        return load_harness_from_dir(harness_id, root)
    except FileNotFoundError:
        spec = load_from_kg(harness_id)
        if spec is None:
            raise
        return spec
