"""
signature_classifier.py

역할:
    - FieldInfo 목록을 받아 각 필드에 카테고리를 부여
    - 반환 형식: List[ClassifiedField] = FieldInfo + {"category": str}

카테고리:
    FINANCIAL      금액/가격 조작 가능성
    AUTHORIZATION  권한/역할 상승 가능성
    IDOR           타 사용자 객체 직접 참조
    LOGIC_FLOW     상태값/플로우 조작
    DEFAULT        분류 불가 - 기본 페이로드 적용

매칭 우선순위: FINANCIAL > AUTHORIZATION > IDOR > LOGIC_FLOW > DEFAULT

분류 패턴은 하드코딩하지 않고 payloads/{category}.yaml의 field_name_patterns를 읽어서
구성한다 - argus/services/scan/zap_scripts/parameter_diff_scan.js도 같은 YAML 파일을
읽으므로(SnakeYAML), 카테고리 패턴을 바꿀 땐 YAML 파일 하나만 고치면 양쪽에 반영된다
(JS 쪽은 SnakeYAML 로드에 실패하면 자체 하드코딩 폴백을 쓰므로, 그 폴백까지 동기화하려면
parameter_diff_scan.js의 폴백 블록도 함께 봐야 한다).

field_name_patterns_cased(IDOR.yaml/AUTHORIZATION.yaml)는 대소문자를 구분해서 원본
field_name 그대로 매칭한다 - "productId"/"isAdmin" 같은 camelCase는 "id"/"is_"를
소문자로 내린 뒤 매칭하면 카멜케이스 경계(소문자->대문자 전환)가 사라져서 못 잡히기
때문이다(예: "(^|_)id$"는 "_" 없는 "productId"에 매칭 안 됨). field_name_patterns(기존)는
자연어 키워드(price/role 등) 매칭이라 대소문자 구분이 필요 없으므로 그대로 소문자 매칭 유지.
"""

import re
from pathlib import Path

import yaml

PAYLOAD_DIR = Path(__file__).resolve().parent / "payloads"
CATEGORY_ORDER = ["FINANCIAL", "AUTHORIZATION", "IDOR", "LOGIC_FLOW"]


def _load_signatures() -> dict:
    signatures = {}
    for category in CATEGORY_ORDER:
        path = PAYLOAD_DIR / f"{category}.yaml"
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        patterns = data.get("field_name_patterns") or []
        cased_patterns = data.get("field_name_patterns_cased") or []
        signatures[category] = (
            re.compile("(" + "|".join(patterns) + ")") if patterns else None,
            re.compile("(" + "|".join(cased_patterns) + ")") if cased_patterns else None,
        )
    return signatures


SIGNATURES = _load_signatures()


def classify(fields: list) -> list:
    """
    각 필드의 field_name을 시그니처 패턴과 매칭하여
    카테고리를 부여한 ClassifiedField 목록을 반환한다.
    """
    result = []
    for field in fields:
        category = _match_category(field["field_name"])
        result.append({**field, "category": category})
    return result


def _match_category(field_name: str) -> str:
    lower_name = field_name.lower()
    for category in CATEGORY_ORDER:
        lower_pattern, cased_pattern = SIGNATURES.get(category, (None, None))
        if lower_pattern and lower_pattern.search(lower_name):
            return category
        if cased_pattern and cased_pattern.search(field_name):
            return category
    return "DEFAULT"
