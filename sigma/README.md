# el34 Sigma → Wazuh 파이프라인

원본 6v6 에는 없던 **Sigma 탐지**를 el34 에 신규 추가. Sigma 룰(YAML) → Wazuh local rules(XML)
로 변환해 Wazuh manager 에 적재한다.

## 구성
- `rules/*.yml` — Sigma 룰 (lab 시작셋: SSH brute force / Web SQLi / Linux 의심명령)
- `sigma2wazuh.py` — 변환기 (자족형, PyYAML 만 필요)
- `install-sigma.sh` — 변환 + `el34-siem` 컨테이너 적재 + 룰 reload
- `sigma_rules.xml` — 생성물 (install 시 자동, git 미추적 권장)

## 사용
```bash
cd sigma && ./install-sigma.sh        # 배포 후 1회 (멱등)
```
적재 후 Wazuh Discover 에서 `rule.groups:sigma` 또는 `rule.id:>=200001` 로 확인.

## 변환 방식 / 한계
Wazuh 는 query 언어가 아닌 decoder+rule 모델이라 Sigma 공식 backend 가 없다. 가장
디코더-독립적인 **full_log 정규식(PCRE2) 매칭** 으로 변환한다.

지원 subset:
- logsource product/category/service → rule group
- detection: `field`, `field|contains|startswith|endswith|re`, list(OR), keywords(list)
- condition: `selection`, `all of them`, `1 of them`, `<sel> and not <filter>`
- level: low→5 medium→7 high→10 critical→13

미지원(필요 시 확장): 복잡한 `count()`/timeframe 상관, near 연산, `1 of selection_*` 와일드카드,
field-level 디코더 매핑(현재는 full_log 텍스트 매칭이라 정밀 필드 비교는 안 함).
→ 정밀 탐지가 필요한 룰은 Wazuh native rule 로 별도 작성 권장.
