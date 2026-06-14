#!/usr/bin/env python3
"""
sigma2wazuh — el34 Sigma → Wazuh local rules 변환기 (자족형, full_log 정규식 매칭).

설계: Wazuh 는 query 언어가 아니라 decoder+rule 모델이라 Sigma 의 공식 backend 가 없다.
가장 디코더-독립적이고 견고한 방식 = Sigma detection 의 문자열들을 Wazuh <regex>(full_log)
로 변환해 매칭. AND(여러 selection 값) → 여러 <regex>(전부 매칭), OR(list) → '|' 대안.

지원 subset (학습 랩 범위, 한계는 README 참조):
  - logsource: product/category/service  → 룰 그룹/코멘트
  - detection.<selection>: {field: value}, {field|contains: v}, {field|startswith},
    {field|endswith}, {field: [list]}, keywords(list)
  - condition: 'selection', 'all of them', '1 of them', '<sel> and not <filter>'
  - level: low→5 medium→7 high→10 critical→13  (Sigma level → Wazuh rule level)

사용:  python3 sigma2wazuh.py rules/ > sigma_rules.xml
"""
import sys, os, re, glob

try:
    import yaml
except ImportError:
    sys.stderr.write("ERROR: PyYAML 필요 — apt-get install -y python3-yaml (또는 pip install pyyaml)\n")
    sys.exit(2)

LEVEL_MAP = {"informational": 3, "low": 5, "medium": 7, "high": 10, "critical": 13}
RULE_ID_BASE = 200000


def esc(s):
    """Wazuh regex(OS_Regex) 특수문자를 리터럴로 — 단순 escape."""
    s = str(s)
    for ch in ["\\", "(", ")", "[", "]", "|", "^", "$", ".", "*", "+", "?", "{", "}"]:
        s = s.replace(ch, "\\" + ch)
    return s


def field_patterns(key, val):
    """detection 의 (field[|modifier]: value|list) → full_log 매칭용 regex 문자열 리스트(OR 묶음 1개)."""
    name, _, mod = key.partition("|")
    vals = val if isinstance(val, list) else [val]
    pats = []
    for v in vals:
        e = esc(v)
        if mod == "contains" or mod == "":
            pats.append(e)
        elif mod == "startswith":
            pats.append(e)
        elif mod == "endswith":
            pats.append(e)
        elif mod == "re":
            pats.append(str(v))  # raw regex
        else:
            pats.append(e)
    # list = OR
    return "(" + "|".join(pats) + ")" if len(pats) > 1 else pats[0]


def keyword_patterns(vals):
    vals = vals if isinstance(vals, list) else [vals]
    return "(" + "|".join(esc(v) for v in vals) + ")" if len(vals) > 1 else esc(vals[0])


def convert_rule(doc, rid):
    title = doc.get("title", "Sigma rule")
    desc = doc.get("description", title).replace("\n", " ").strip()
    level = LEVEL_MAP.get(str(doc.get("level", "medium")).lower(), 7)
    det = doc.get("detection", {})
    cond = str(det.get("condition", "")).strip()

    # selection 블록들 수집
    selections = {k: v for k, v in det.items() if k != "condition"}

    # 매칭 regex 들 (AND) 와 제외 regex (not) 분리
    include, exclude = [], []

    def block_to_pats(block):
        out = []
        if isinstance(block, dict):
            for k, v in block.items():
                out.append(field_patterns(k, v))
        elif isinstance(block, list):  # keywords
            out.append(keyword_patterns(block))
        else:
            out.append(esc(block))
        return out

    # condition 파싱 (단순): 'A and not B', '1 of them', 'all of them', 'A'
    cond_l = cond.lower()
    not_targets = set()
    m = re.search(r"not\s+([a-z0-9_*]+)", cond_l)
    if m:
        not_targets.add(m.group(1))

    if "1 of" in cond_l:
        # OR: 모든 selection 의 모든 패턴을 한 regex 로 OR
        allp = []
        for name, blk in selections.items():
            allp += block_to_pats(blk)
        include.append("(" + "|".join(allp) + ")")
    else:
        # all of them / 단일 / and: 각 selection 패턴을 AND (단 not 대상은 제외)
        for name, blk in selections.items():
            if name.lower() in not_targets:
                exclude += block_to_pats(blk)
            else:
                include += block_to_pats(blk)

    # XML 생성
    lines = []
    lines.append(f'  <!-- {title} (sigma level={doc.get("level","medium")}) -->')
    lines.append(f'  <rule id="{rid}" level="{level}">')
    # 첫 include 는 <regex>, 나머지도 <regex> (Wazuh: 같은 룰 내 여러 regex = AND)
    if not include:
        include = [".+"]
    for p in include:
        lines.append(f'    <regex type="pcre2">{p}</regex>')
    for p in exclude:
        lines.append(f'    <regex type="pcre2" negate="yes">{p}</regex>')
    lines.append(f'    <description>[Sigma] {desc[:180]}</description>')
    grp = "sigma,"
    ls = doc.get("logsource", {})
    for kk in ("product", "category", "service"):
        if ls.get(kk):
            grp += f"{ls[kk]},"
    lines.append(f'    <group>{grp}</group>')
    lines.append("  </rule>")
    return "\n".join(lines)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "rules"
    files = sorted(glob.glob(os.path.join(src, "**", "*.yml"), recursive=True) +
                   glob.glob(os.path.join(src, "**", "*.yaml"), recursive=True))
    print('<!-- el34 Sigma → Wazuh local rules (sigma2wazuh.py 자동생성, 직접 수정 금지) -->')
    print('<group name="sigma,el34,">')
    rid = RULE_ID_BASE
    n = 0
    for f in files:
        try:
            with open(f) as fh:
                for doc in yaml.safe_load_all(fh):
                    if not doc or "detection" not in doc:
                        continue
                    rid += 1
                    n += 1
                    print(convert_rule(doc, rid))
        except Exception as e:
            sys.stderr.write(f"WARN: {f} 변환 실패: {e}\n")
    print("</group>")
    sys.stderr.write(f"sigma2wazuh: {n} rule(s) from {len(files)} file(s) → id {RULE_ID_BASE+1}..{rid}\n")


if __name__ == "__main__":
    main()
