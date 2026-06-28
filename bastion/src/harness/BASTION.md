# Bastion SOC Harness — 전역 규칙 (BASTION.md)

bastion 의 다중 페르소나 SOC 하네스가 공통으로 따르는 규칙. 모든 하네스 실행에 주입된다.

## 운영 규칙
- 리더(`soc-lead`)는 **무발화** — 직접 분석 본문을 쓰지 않고 라우팅·통합만 한다. 본문은 워커 페르소나가 생산한다.
- 페르소나는 frontmatter `tools` 에 명시된 skill 만 사용한다(도구 경계 = 물리적 강제).
- **검증자 ≠ 생산자** — 어떤 페르소나도 자기 산출물을 자기가 통과시키지 않는다.
- 상태를 바꾸는 작업(`danger`/`requires_approval` skill)은 반드시 verify 게이트 + 승인을 거친다.
- 추정과 단정을 구분한다 — 단정은 증거(로그·명령 출력)가 있을 때만.

## 안전
- 파괴적 명령(rm -rf /, mkfs, 서비스 중단 등)은 금지. 차단·격리는 최소 범위로.
- 컨테이너는 자산(asset)이다 — 페르소나는 `docker exec`/ssh(기존 skill)로 자산에 작용하며, 기계에 묶이지 않는다.
- 동일 자산을 두 페르소나가 동시에 변경하지 않는다(phase/depends_on 으로 직렬화).

## 산출물
- 중간 산출물은 실행별 `harness/workspace/<run_id>/<role>/` 에 둔다(보존 — 사람 재검토용).
- 최종 보고는 `soc-lead` 가 P0/P1/P2 우선순위로 통합한다.
- 결과는 KG(`kg_recorder`)와 Experience 에 기록되어 다음 하네스 품질을 높인다.
