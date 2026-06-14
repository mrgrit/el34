"""Asset / Architecture domain — 작업의 *대상* 영역.

Work domain (mission~todo~playbook~experience~history) 와 분리되는 별도 도메인.
KG 위에 얇게 얹힌 helper. 모든 데이터는 KG 노드/엣지로 저장된다.

분리 원리:
  Asset       = 단일 시스템 (host, app, model, data store)
  Architecture = 자산 간 관계 (topology, packet flow, dependency, data lineage)
  Work        = 무엇을 할지 (별도 모듈 work_domain.py)

엣지 (Architecture):
  connects_to    : 네트워크 연결
  depends_on     : 서비스 의존
  data_flows_to  : 데이터 흐름
  hosts          : 호스트→서비스
  manages        : 관리 관계 (Wazuh manager → agent 등)
"""
from __future__ import annotations

import json
import time
from typing import Any

from .graph import get_graph


# Asset 분류 — UI 색상·필터에 영향. KG 의 type 은 모두 'Asset' 으로 통일하고
# meta.kind 로 세분.
ASSET_KINDS = ("host", "application", "model", "data_store", "network_device",
               "credential_store", "secret", "endpoint")

# Architecture 엣지 타입
ARCH_EDGES = ("connects_to", "depends_on", "data_flows_to", "hosts", "manages",
              "trusts", "monitors")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ── Asset ────────────────────────────────────────────────────────────────────

def register_asset(asset_id: str, name: str, kind: str = "host",
                   ip: str = "", os: str = "", services: list[str] | None = None,
                   meta: dict | None = None) -> dict:
    """Asset 등록 (사용자 또는 auto-scan 호출).

    asset_id 권장 형식: 'asset:host:web', 'asset:model:gpt-oss-120b' 등.
    """
    g = get_graph()
    full_meta = dict(meta or {})
    full_meta.update({
        "kind": kind,
        "ip": ip,
        "os": os,
        "services": services or [],
        "registered_at": _now_iso(),
    })
    g.add_node(asset_id, "Asset", name,
               content={"summary": f"{kind} {name}",
                        "ip": ip, "os": os,
                        "services": services or []},
               meta=full_meta)
    return {"asset_id": asset_id, "kind": kind}


def list_assets(kind: str = "", limit: int = 200) -> list[dict]:
    g = get_graph()
    nodes = g.find_nodes(type="Asset", limit=limit)
    if kind:
        nodes = [n for n in nodes if (n.get("meta") or {}).get("kind") == kind]
    return nodes


def link_assets(src: str, dst: str, edge_type: str = "connects_to",
                meta: dict | None = None) -> dict:
    """Architecture edge 추가. edge_type ∈ ARCH_EDGES."""
    if edge_type not in ARCH_EDGES:
        return {"error": f"unknown architecture edge: {edge_type}",
                "allowed": list(ARCH_EDGES)}
    g = get_graph()
    g.add_edge(src, dst, edge_type)
    return {"src": src, "dst": dst, "type": edge_type}


# ── Architecture (자산 간 관계 보기) ────────────────────────────────────────

def architecture_topology(root_asset: str = "", max_depth: int = 3) -> dict:
    """Asset 토폴로지 — 단일 자산에서 시작해 N-hop traversal."""
    g = get_graph()
    if not root_asset:
        # 모든 asset + 엣지 일괄
        nodes = g.find_nodes(type="Asset", limit=500)
        edges = []
        try:
            all_e = g.list_edges() if hasattr(g, "list_edges") else []
        except Exception:
            all_e = []
        for e in all_e:
            if e.get("type") in ARCH_EDGES:
                edges.append(e)
        return {"root": "", "nodes": nodes, "edges": edges,
                "node_count": len(nodes), "edge_count": len(edges)}
    # root 부터 traverse
    try:
        result = g.traverse(root_asset, max_depth=max_depth,
                            edge_types=list(ARCH_EDGES))
    except Exception as e:
        return {"error": str(e), "root": root_asset}
    return {"root": root_asset, "lineage": list(result.values()),
            "depth": max_depth}


def architecture_packet_flow(src_asset: str, dst_asset: str) -> dict:
    """src → dst 사이의 packet flow 경로 (data_flows_to + connects_to 추적)."""
    g = get_graph()
    try:
        forward = g.traverse(src_asset, max_depth=5,
                             edge_types=["connects_to", "data_flows_to"])
    except Exception as e:
        return {"error": str(e), "src": src_asset, "dst": dst_asset}
    # dst 가 traverse 결과 안에 있는지
    found = dst_asset in forward
    return {
        "src": src_asset, "dst": dst_asset, "reachable": found,
        "path_nodes": list(forward.keys())[:20] if found else [],
    }


# ── Auto-scan 트리거 (probe_all 결과 활용) ────────────────────────────────

def autoscan_register(probe_result: dict, vm_role: str = "") -> dict:
    """probe_host / probe_all skill 결과를 받아 Asset 자동 등록.

    probe_result 예: {"hostname": "...", "ip": "...", "os": "...",
                      "services": [...], "uptime": "..."}
    """
    if not vm_role:
        vm_role = probe_result.get("role") or probe_result.get("hostname", "unknown")
    asset_id = f"asset:host:{vm_role}"
    return register_asset(
        asset_id=asset_id,
        name=vm_role,
        kind="host",
        ip=probe_result.get("ip", ""),
        os=probe_result.get("os", ""),
        services=probe_result.get("services", []),
        meta={"source": "autoscan",
              "uptime": probe_result.get("uptime", "")},
    )


__all__ = [
    "register_asset",
    "list_assets",
    "link_assets",
    "architecture_topology",
    "architecture_packet_flow",
    "autoscan_register",
    "ASSET_KINDS",
    "ARCH_EDGES",
]
