"""6v6 Portal — 학습용 관리 대시보드.

FastAPI + Jinja2 + HTMX. docker socket / suricata eve.json / apache modsec_audit.log /
bastion auth.log / siem alerts.json 을 통합해서 한 화면에서 보여준다.
300B portal 의 단순화 버전 (4-tier → 단일 network).
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

import docker
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates


BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

app = FastAPI(title="6v6 Portal", docs_url="/api/docs", redoc_url=None)

EXPECTED_CONTAINERS = [
    ("6v6-bastion",   "10.20.30.201", "Bastion (SSH 점프 + API)"),
    ("6v6-secu",      "10.20.30.1",   "Firewall + IDS"),
    ("6v6-web",       "10.20.30.80",  "Web (Apache + ModSec)"),
    ("6v6-juiceshop", "10.20.30.81",  "JuiceShop (web 만)"),
    ("6v6-siem",      "10.20.30.100", "SIEM (Wazuh)"),
    ("6v6-attacker",  "10.20.30.202", "Attacker (도구)"),
    ("6v6-portal",    "10.20.30.50",  "이 포털"),
]


def docker_client() -> docker.DockerClient:
    return docker.DockerClient(base_url="unix:///var/run/docker.sock")


# ─── 컨테이너 조회 ───────────────────────────────────────────

def list_containers() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        cli = docker_client()
        for c in cli.containers.list(all=True):
            attrs = c.attrs
            net = (attrs.get("NetworkSettings") or {}).get("Networks") or {}
            ip = ""
            for net_name, info in net.items():
                if info.get("IPAddress"):
                    ip = info["IPAddress"]
                    break
            ports = []
            for port_key, bindings in (attrs.get("NetworkSettings") or {}).get("Ports", {}).items():
                if bindings:
                    for b in bindings:
                        ports.append(f"{b.get('HostPort')}→{port_key}")
            out.append({
                "name": c.name,
                "status": c.status,
                "ip": ip,
                "image": (c.image.tags[0] if c.image.tags else c.image.short_id),
                "ports": ", ".join(ports) or "-",
                "started_at": attrs.get("State", {}).get("StartedAt", "")[:19],
            })
        out.sort(key=lambda x: x["name"])
    except Exception as e:
        return [{"name": "error", "status": str(e), "ip": "-", "image": "-", "ports": "-", "started_at": "-"}]
    return out


# ─── 로그 source 헬퍼 ────────────────────────────────────────

def tail_file(path: Path, n: int = 200) -> list[str]:
    if not path.exists():
        return []
    try:
        with path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, 64 * 1024)
            f.seek(-chunk, 2)
            data = f.read().decode("utf-8", errors="replace")
        return data.splitlines()[-n:]
    except Exception:
        return []


def parse_eve_alerts(path: Path, limit: int = 30) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in tail_file(path, n=2000):
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("event_type") != "alert":
            continue
        out.append({
            "time": d.get("timestamp", "")[:19],
            "sig": d.get("alert", {}).get("signature", ""),
            "sid": d.get("alert", {}).get("signature_id"),
            "src": d.get("src_ip"),
            "dst": d.get("dest_ip"),
            "proto": d.get("proto"),
        })
    return out[-limit:][::-1]


def parse_eve_top(path: Path) -> tuple[Counter, Counter]:
    sigs: Counter = Counter()
    types: Counter = Counter()
    for line in tail_file(path, n=2000):
        try:
            d = json.loads(line)
        except Exception:
            continue
        types[d.get("event_type", "?")] += 1
        if d.get("event_type") == "alert":
            sig = d.get("alert", {}).get("signature", "")
            if sig:
                sigs[sig] += 1
    return sigs, types


def parse_modsec_audit(path: Path, limit: int = 30) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    current_block: list[str] = []
    for line in tail_file(path, n=4000):
        if line.startswith("---") and line.endswith("---"):
            if current_block:
                txt = "\n".join(current_block)
                out.append({
                    "time": current_block[0][:30] if current_block else "",
                    "ids": ", ".join(sorted(set(_extract_ids(txt))))[:60],
                    "uri": _extract_first(txt, "GET ", "POST ")[:80],
                    "client": _extract_first(txt, "[client ")[:30],
                })
                current_block = []
        else:
            current_block.append(line)
    return out[-limit:][::-1]


def _extract_ids(text: str) -> list[str]:
    import re
    return re.findall(r'id "([0-9]+)"', text)


def _extract_first(text: str, *prefixes: str) -> str:
    for line in text.splitlines():
        for p in prefixes:
            if p in line:
                return line.strip()[:120]
    return ""


# ─── routes ──────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    containers = list_containers()
    running = sum(1 for c in containers if c["status"] == "running")
    expected_set = {n for n, _, _ in EXPECTED_CONTAINERS}
    missing = sorted(expected_set - {c["name"] for c in containers})
    latest_ids = parse_eve_alerts(Path("/data/suricata-logs/eve.json"))[:5]
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "containers": containers,
        "running": running,
        "total": len(containers),
        "missing": missing,
        "latest_ids_alerts": latest_ids,
        "page": "dashboard",
    })


@app.get("/resources", response_class=HTMLResponse)
def resources(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("resources.html", {
        "request": request,
        "containers": list_containers(),
        "expected": EXPECTED_CONTAINERS,
        "page": "resources",
    })


@app.get("/network", response_class=HTMLResponse)
def network(request: Request) -> HTMLResponse:
    networks = []
    try:
        cli = docker_client()
        for n in cli.networks.list():
            attrs = n.attrs
            cs = []
            for cid, info in (attrs.get("Containers") or {}).items():
                cs.append({
                    "name": info.get("Name", cid[:12]),
                    "ip": info.get("IPv4Address", "-").split("/")[0],
                })
            networks.append({
                "name": n.name,
                "driver": attrs.get("Driver"),
                "subnet": ((attrs.get("IPAM") or {}).get("Config") or [{}])[0].get("Subnet", "-"),
                "containers": sorted(cs, key=lambda x: x["name"]),
            })
    except Exception as e:
        networks = [{"name": "error", "driver": str(e), "subnet": "-", "containers": []}]
    return templates.TemplateResponse("network.html", {
        "request": request,
        "networks": networks,
        "page": "network",
    })


@app.get("/logs", response_class=HTMLResponse)
def logs_index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("logs.html", {
        "request": request,
        "services": [n for n, _, _ in EXPECTED_CONTAINERS],
        "page": "logs",
    })


@app.get("/logs/{name}/tail", response_class=PlainTextResponse)
def logs_tail(name: str, lines: int = 100) -> str:
    expected = [n for n, _, _ in EXPECTED_CONTAINERS]
    if name not in expected:
        raise HTTPException(404, f"unknown container: {name}")
    try:
        cli = docker_client()
        c = cli.containers.get(name)
        return c.logs(tail=lines).decode("utf-8", errors="replace")
    except Exception as e:
        return f"(error reading logs: {e})"


@app.get("/waf", response_class=HTMLResponse)
def waf(request: Request) -> HTMLResponse:
    audit = parse_modsec_audit(Path("/data/apache-logs/modsec_audit.log"))
    err_lines = tail_file(Path("/data/apache-logs/error.log"), n=80)
    err_modsec = [l for l in err_lines if "modsec" in l.lower() or "ModSecurity" in l][-30:]
    return templates.TemplateResponse("waf.html", {
        "request": request,
        "audit": audit,
        "errors": err_modsec[::-1],
        "page": "waf",
    })


@app.get("/ids", response_class=HTMLResponse)
def ids(request: Request) -> HTMLResponse:
    eve_path = Path("/data/suricata-logs/eve.json")
    alerts = parse_eve_alerts(eve_path, limit=30)
    sigs, types = parse_eve_top(eve_path)
    return templates.TemplateResponse("ids.html", {
        "request": request,
        "alerts": alerts,
        "top_sigs": sigs.most_common(10),
        "type_counts": types.most_common(),
        "page": "ids",
    })


@app.get("/audit", response_class=HTMLResponse)
def audit(request: Request) -> HTMLResponse:
    auth_lines = tail_file(Path("/data/bastion-data/auth.log"), n=200)
    if not auth_lines:
        try:
            cli = docker_client()
            auth_lines = cli.containers.get("6v6-bastion").logs(tail=200).decode().splitlines()
        except Exception:
            auth_lines = []
    rows = [l for l in auth_lines if any(k in l for k in ("Accepted", "Failed", "session", "Connection"))][-50:][::-1]
    return templates.TemplateResponse("audit.html", {
        "request": request,
        "lines": rows,
        "page": "audit",
    })


@app.get("/agent", response_class=HTMLResponse)
async def agent(request: Request) -> HTMLResponse:
    api_url = os.getenv("BASTION_API_URL", "http://bastion:9100")
    api_key = os.getenv("BASTION_API_KEY", "ccc-api-key-2026")
    health = {}
    skills: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=3.0) as cli:
            r = await cli.get(f"{api_url}/health")
            health = r.json()
            r = await cli.get(f"{api_url}/skills", headers={"X-API-Key": api_key})
            skills = r.json().get("skills", [])
            r = await cli.get(f"{api_url}/targets", headers={"X-API-Key": api_key})
            targets = r.json().get("targets", [])
    except Exception as e:
        health = {"error": str(e)}
    return templates.TemplateResponse("agent.html", {
        "request": request,
        "health": health,
        "skills": skills,
        "targets": targets,
        "api_url": api_url,
        "page": "agent",
    })


@app.get("/health")
def portal_health() -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "time": datetime.utcnow().isoformat() + "Z",
        "service": "6v6-portal",
    })
