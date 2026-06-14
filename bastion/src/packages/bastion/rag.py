"""Bastion RAG — 교안/실습 콘텐츠 검색 + LLM 컨텍스트 주입

교안(Markdown)과 실습(YAML)을 인메모리 인덱스로 구축하고,
학생 질문에 관련 내용을 검색하여 LLM 프롬프트에 주입한다.
"""
from __future__ import annotations
import os
import re
import glob
from collections import defaultdict
from typing import Any

import yaml


KNOWLEDGE_DIR = os.path.join(os.path.dirname(__file__), "..", "knowledge")


class RAGIndex:
    """간단한 키워드 기반 인메모리 검색 인덱스"""

    def __init__(self):
        self.chunks: list[dict] = []  # {"id": str, "source": str, "title": str, "content": str, "keywords": set}
        self.inverted: dict[str, list[int]] = defaultdict(list)  # keyword → chunk indices

    def add_chunk(self, source: str, title: str, content: str, metadata: dict = None):
        """청크 추가 + 키워드 인덱싱"""
        idx = len(self.chunks)
        # 키워드 추출: 한글 2자+, 영어 3자+, 기술 용어
        words = set()
        for w in re.findall(r'[가-힣]{2,}|[a-zA-Z]{3,}|[a-zA-Z]+-[a-zA-Z]+', content.lower()):
            words.add(w)
        # 기술 용어 추가
        for term in re.findall(r'(?:nmap|suricata|wazuh|nftables|modsecurity|metasploit|sqlmap|hydra|nikto|'
                               r'owasp|cve|mitre|att&ck|sigma|yara|docker|kubernetes|ollama|jwt|xss|sqli|'
                               r'xxe|csrf|ssrf|idor|rce|lfi|rfi|dos|ddos|apt|c2|lateral|pivot|'
                               r'firewall|ids|ips|siem|waf|soc|forensic|incident|playbook|skill)',
                               content.lower()):
            words.add(term)

        chunk = {
            "id": f"{source}#{idx}",
            "source": source,
            "title": title,
            "content": content[:2000],  # 최대 2000자
            "keywords": words,
            **(metadata or {}),
        }
        self.chunks.append(chunk)

        for w in words:
            self.inverted[w].append(idx)

    def search(self, query: str, top_k: int = 3) -> list[dict]:
        """쿼리에서 키워드 추출 → 관련 청크 검색 (BM25-like 스코어링)"""
        query_words = set()
        for w in re.findall(r'[가-힣]{2,}|[a-zA-Z]{3,}|[a-zA-Z]+-[a-zA-Z]+', query.lower()):
            query_words.add(w)
        for term in re.findall(r'(?:nmap|suricata|wazuh|nftables|modsecurity|jwt|xss|sqli|xxe|siem|waf|soc|'
                               r'firewall|ids|forensic|incident|playbook|docker|ollama)',
                               query.lower()):
            query_words.add(term)

        if not query_words:
            return []

        # BM25-like 스코어링: IDF × TF 정규화
        import math
        N = max(len(self.chunks), 1)
        scores: dict[int, float] = defaultdict(float)
        for w in query_words:
            postings = self.inverted.get(w, [])
            if not postings:
                continue
            idf = math.log((N - len(postings) + 0.5) / (len(postings) + 0.5) + 1)
            for idx in postings:
                # TF: 키워드가 chunk에 있으면 1 (간소화)
                tf = 1.0
                scores[idx] += idf * tf

        # 상위 K개
        ranked = sorted(scores.items(), key=lambda x: -x[1])[:top_k]
        return [self.chunks[idx] for idx, _ in ranked]

    def stats(self) -> dict:
        return {
            "chunks": len(self.chunks),
            "keywords": len(self.inverted),
        }


# ── 인덱스 구축 ─────────────────────────────────

def build_index(knowledge_dir: str = None) -> RAGIndex:
    """교안(Markdown) + 실습(YAML)을 인덱스로 구축"""
    kdir = knowledge_dir or KNOWLEDGE_DIR
    index = RAGIndex()

    # 1. 교안 (Markdown) — knowledge/education/ 또는 knowledge/contents/education/
    edu_dir = os.path.join(kdir, "education")
    if not os.path.isdir(edu_dir):
        edu_dir = os.path.join(kdir, "contents", "education")
    for md_file in sorted(glob.glob(os.path.join(edu_dir, "*", "*", "lecture.md"))):
        parts = md_file.split(os.sep)
        course = [p for p in parts if p.startswith("course")]
        week = [p for p in parts if p.startswith("week")]
        source = f"{course[0] if course else '?'}/{week[0] if week else '?'}"

        try:
            with open(md_file, encoding="utf-8") as f:
                content = f.read()
        except Exception:
            continue

        title = content.split("\n")[0].strip("# ") if content else source

        # 섹션별로 분할 (## 헤더 기준)
        sections = re.split(r'\n## ', content)
        for i, section in enumerate(sections):
            if len(section.strip()) < 50:
                continue
            sec_title = section.split("\n")[0].strip() if i > 0 else title
            index.add_chunk(
                source=source,
                title=sec_title,
                content=section[:2000],
                metadata={"type": "lecture", "course": course[0] if course else ""},
            )

    # 2. 실습 (YAML)
    labs_dir = os.path.join(kdir, "labs")
    if not os.path.isdir(labs_dir):
        labs_dir = os.path.join(kdir, "contents", "labs")
    for yaml_file in sorted(glob.glob(os.path.join(labs_dir, "*", "*.yaml"))):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                lab = yaml.safe_load(f)
        except Exception:
            continue

        if not lab:
            continue

        lab_id = lab.get("lab_id", os.path.basename(yaml_file))
        title = lab.get("title", lab_id)
        description = lab.get("description", "")

        # Lab 메타 + 스텝 요약을 하나의 청크로
        steps_summary = "\n".join(
            f"- step{s.get('order',i+1)}: {s.get('instruction','')[:80]}"
            for i, s in enumerate(lab.get("steps", []))
        )
        content = f"{title}\n{description}\n\n실습 스텝:\n{steps_summary}"
        index.add_chunk(
            source=lab_id,
            title=title,
            content=content,
            metadata={"type": "lab", "course": lab.get("course", "")},
        )

    # 3. 매뉴얼 (보안 솔루션 레퍼런스)
    for mdir in [os.path.join(kdir, "manuals"),
                 os.path.join(kdir, "contents", "knowledge", "manuals"),
                 os.path.join(kdir, "..", "contents", "knowledge", "manuals")]:
        if os.path.isdir(mdir):
            for md_file in sorted(glob.glob(os.path.join(mdir, "*.md"))):
                try:
                    with open(md_file, encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    continue
                source = f"manual:{os.path.basename(md_file).replace('.md','')}"
                title = content.split("\n")[0].strip("# ") if content else source
                sections = re.split(r'\n## ', content)
                for i, section in enumerate(sections):
                    if len(section.strip()) < 50:
                        continue
                    sec_title = section.split("\n")[0].strip() if i > 0 else title
                    index.add_chunk(source=source, title=sec_title, content=section[:2000],
                                    metadata={"type": "manual"})
            break  # 첫 번째 유효한 디렉토리만

    # 4. Playbook (YAML)
    for pb_file in sorted(glob.glob(os.path.join(kdir, "..", "contents", "playbooks", "*.yaml"))):
        try:
            with open(pb_file, encoding="utf-8") as f:
                pb = yaml.safe_load(f)
        except Exception:
            continue
        if pb:
            steps = "\n".join(f"- {s.get('name','')}: {s.get('skill','')}" for s in pb.get("steps", []))
            index.add_chunk(
                source=f"playbook:{pb.get('playbook_id','')}",
                title=pb.get("title", ""),
                content=f"{pb.get('title','')}\n{pb.get('description','')}\n{steps}",
                metadata={"type": "playbook"},
            )

    return index


def format_context(chunks: list[dict], max_chars: int = 3000) -> str:
    """검색된 청크를 LLM 컨텍스트 문자열로 포맷"""
    if not chunks:
        return ""
    parts = ["[관련 교육 자료]"]
    total = 0
    for c in chunks:
        entry = f"\n--- {c['source']} | {c['title']} ---\n{c['content'][:800]}"
        if total + len(entry) > max_chars:
            break
        parts.append(entry)
        total += len(entry)
    return "\n".join(parts)
