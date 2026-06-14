"""6v6 Assessor — 읽기 전용 평가 수집(Assessor) 레이어.

중앙 플랫폼(CC/tubewar)이 선언적 check-spec 을 보내면, VM 내부에서 읽기 전용
검사를 수행해 구조화된 pass/fail + 근거를 반환한다. 클라이언트는 문맥 없이(dumb)
수집만 하며 과목/학년/반/index 분리 로직을 일절 갖지 않는다(서버 책임).
"""
