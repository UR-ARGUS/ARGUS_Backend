"""
payloads.py — 카테고리별 페이로드 상수 정의

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3
명세: 1-3_scan_engine_spec.md § 5

형식: {category: [(payload_value, description), ...]}
IDOR 카테고리는 원본 ID 값 기준으로 manipulator.py에서 동적 생성하므로 여기서는 빈 리스트.
"""

from typing import Dict, List, Tuple

PAYLOADS: Dict[str, List[Tuple[str, str]]] = {
    "PRICE": [
        ("1",         "1원으로 변조"),
        ("0",         "0원 변조"),
        ("-1",        "음수 금액 변조"),
        ("-9999",     "극소 음수 변조"),
        ("99999999",  "극대값 변조"),
        ("0.001",     "소수점 극소값"),
    ],
    "PRIVILEGE": [
        ("ADMIN",       "ADMIN 권한 주입"),
        ("SUPER_ADMIN", "SUPER_ADMIN 권한 주입"),
        ("admin",       "소문자 admin 주입"),
        ("true",        "boolean true 권한 플래그"),
        ("1",           "숫자형 권한 플래그"),
        ("0",           "권한 비활성화 시도"),
    ],
    "STATUS": [
        ("PAID",      "결제 완료 상태로 변조"),
        ("COMPLETED", "완료 상태로 변조"),
        ("APPROVED",  "승인 상태로 변조"),
        ("CONFIRMED", "확정 상태로 변조"),
        ("true",      "boolean true 상태 플래그"),
        ("1",         "숫자형 상태 플래그"),
    ],
    # IDOR: manipulator.py의 _get_payloads()가 원본 ID 기준 동적 생성
    "IDOR": [],
    "HIDDEN": [
        ("1",       "hidden 금액 1원 변조"),
        ("ADMIN",   "hidden 권한 변조"),
        ("true",    "hidden 플래그 변조"),
        ("../etc",  "hidden 경로 변조 시도"),
        ("0",       "hidden 0값 변조"),
    ],
}
