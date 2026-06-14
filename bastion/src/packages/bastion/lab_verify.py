"""CCC Lab 콘텐츠 검증 — 실제 인프라에서 Lab step을 실행하여 verify 통과 확인"""
from __future__ import annotations
import re
import yaml
import os
import glob
from typing import Generator

from packages.bastion import run_command


def verify_lab_step(step: dict, vm_ips: dict[str, str]) -> dict:
    """단일 Lab step을 실행하고 verify 결과 반환"""
    answer = step.get("answer", "")
    verify = step.get("verify", {})
    expect = verify.get("expect", "")
    vtype = verify.get("type", "output_contains")
    field = verify.get("field", "stdout")
    target_vm = step.get("target_vm", "attacker")

    vm_ip = vm_ips.get(target_vm, "")
    if not vm_ip:
        return {"passed": False, "detail": f"VM '{target_vm}' IP not configured"}

    if not answer:
        return {"passed": False, "detail": "No answer/command"}

    import os, re

    # 1. python3 -c "...\\n..." → heredoc 변환 (멀티라인 Python 스크립트)
    if 'python3 -c "' in answer and "\\n" in answer:
        m = re.match(r'python3 -c "(.*)"$', answer, re.DOTALL)
        if m:
            script = m.group(1).replace("\\n", "\n").replace('\\"', '"')
            answer = f"python3 << 'PYEOF'\n{script}\nPYEOF"

    # 2. 환경변수 주입 (LLM_URL 등)
    llm_url = os.getenv("LLM_BASE_URL", "http://10.20.30.200:11434")
    answer = answer.replace("${LLM_URL:-http://10.20.30.200:11434}", llm_url)
    answer = answer.replace("${LLM_URL}", llm_url)

    r = run_command(vm_ip, answer, timeout=30)
    output = r.get(field, r.get("stdout", ""))

    if vtype == "output_contains":
        passed = expect.lower() in output.lower()
    elif vtype == "output_regex":
        passed = bool(re.search(expect, output, re.IGNORECASE))
    elif vtype == "exit_code":
        passed = str(r.get("exit_code", -1)) == str(expect)
    else:
        passed = expect in output

    return {
        "passed": passed,
        "detail": output[:100] if output else r.get("stderr", "")[:100],
    }


def verify_lab_stream(lab_file: str, vm_ips: dict[str, str]) -> Generator[dict, None, None]:
    """단일 Lab 파일의 모든 step을 실행하고 SSE 이벤트로 스트리밍"""
    with open(lab_file, encoding="utf-8") as f:
        lab = yaml.safe_load(f)

    lab_id = lab.get("lab_id", os.path.basename(lab_file))
    steps = lab.get("steps", [])

    yield {"event": "lab_start", "lab_id": lab_id, "title": lab.get("title", ""), "total_steps": len(steps)}

    passed = 0
    for step in steps:
        result = verify_lab_step(step, vm_ips)
        ok = result["passed"]
        if ok:
            passed += 1
        yield {
            "event": "lab_step",
            "lab_id": lab_id,
            "step": step.get("order", 0),
            "instruction": step.get("instruction", "")[:60],
            "target_vm": step.get("target_vm", ""),
            "passed": ok,
            "detail": result["detail"][:80],
        }

    yield {
        "event": "lab_done",
        "lab_id": lab_id,
        "passed": passed,
        "total": len(steps),
        "pct": round(passed / max(len(steps), 1) * 100),
    }


def verify_all_labs_stream(labs_dir: str, vm_ips: dict[str, str],
                           courses: list[str] | None = None,
                           version: str = "non-ai",
                           sample_weeks: list[int] | None = None) -> Generator[dict, None, None]:
    """전체 Lab 검증 스트리밍. courses=None이면 전체, sample_weeks=[1,8,15]면 샘플만."""
    suffix = "nonai" if version == "non-ai" else "ai"
    total_passed = 0
    total_steps = 0
    labs_tested = 0

    for course_dir in sorted(glob.glob(os.path.join(labs_dir, f"*-{suffix}"))):
        course_name = os.path.basename(course_dir)
        if courses and course_name.replace(f"-{suffix}", "") not in courses:
            continue

        files = sorted(glob.glob(os.path.join(course_dir, "*.yaml")))
        if sample_weeks:
            files = [f for f in files if any(f"week{w:02d}" in f for w in sample_weeks)]

        for lab_file in files:
            for evt in verify_lab_stream(lab_file, vm_ips):
                if evt["event"] == "lab_done":
                    total_passed += evt["passed"]
                    total_steps += evt["total"]
                    labs_tested += 1
                yield evt

    yield {
        "event": "verify_complete",
        "labs_tested": labs_tested,
        "total_passed": total_passed,
        "total_steps": total_steps,
        "pct": round(total_passed / max(total_steps, 1) * 100),
    }
