"""
payloads.py — 1-5 리다이렉트/포워드 페이로드 (Reflected 검증용)

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-5
목적: 파라미터에 서비스가 신뢰하지 않을 외부 목적지를 주입해, 서버(혹은 클라이언트
     스크립트)가 화이트리스트/도메인 검증 없이 그대로 리다이렉트에 반영하는지 확인한다.

payload_host는 판별 기준 문자열로도 함께 쓰인다 (detector.py가 응답에 이 문자열이
그대로 노출되는지로 반영 여부를 판정) — 대상 서비스 자체 도메인과 절대 겹치지 않는
값을 써야 오탐(원래 자기 사이트로 정상 리다이렉트된 것을 취약점으로 오판)이 없다.
"""

DEFAULT_PAYLOAD_HOST = "argus-unvalidated-redirect-poc.invalid"


def build_payloads(payload_host: str = DEFAULT_PAYLOAD_HOST, allowlisted_host: str = "") -> list[tuple[str, str]]:
    """
    (payload_value, description) 목록을 반환한다.

    Args:
        payload_host:      리다이렉트 목적지로 주입할 미검증 외부 호스트
        allowlisted_host:  진단 대상 자체 도메인(urlparse(target).netloc). 값이 주어지면
                            "화이트리스트가 자기 도메인 포함 여부만 문자열로 검사하는"
                            허술한 필터를 겨냥한 우회 페이로드를 추가로 생성한다
                            (서브도메인 위장, 경로/쿼리/자격증명부 삽입 등).
    """
    payloads: list[tuple[str, str]] = [
        (f"https://{payload_host}/",  "절대 URL 변조 (https)"),
        (f"http://{payload_host}/",   "절대 URL 변조 (http)"),
        (f"//{payload_host}/",        "프로토콜 상대 경로(protocol-relative) 우회 — //host 형태"),
        (f"/\\{payload_host}",        "역슬래시 혼합 우회 — 브라우저가 //로 해석하는 파서 차이 악용"),
        (f"https:{payload_host}/",    "콜론만 남긴 스킴 우회 — '://' 문자열 블랙리스트 회피"),
        (f"https:/{payload_host}/",   "슬래시 1개 스킴 우회"),
        (f"   https://{payload_host}/", "선행 공백/제어문자 우회 — trim 없는 startswith 검증 회피"),
        (f"https://{payload_host}/%2f..", "인코딩 경로 조작 우회"),
    ]

    if allowlisted_host:
        # "허용 도메인 문자열이 포함되어 있으면 통과" 수준의 얕은 검증을 겨냥한 우회.
        payloads.extend([
            (f"https://{allowlisted_host}.{payload_host}/",
             f"서브도메인 위장 우회 — 허용 도메인('{allowlisted_host}')을 접두어로 배치"),
            (f"https://{payload_host}/{allowlisted_host}",
             f"경로에 허용 도메인('{allowlisted_host}') 포함 우회"),
            (f"https://{allowlisted_host}@{payload_host}/",
             f"@ userinfo 우회 — '{allowlisted_host}@'를 사용자정보로 위장해 실제 호스트({payload_host}) 은닉"),
            (f"https://{payload_host}#{allowlisted_host}",
             f"프래그먼트 뒤에 허용 도메인 배치 우회"),
            (f"https://{payload_host}?next={allowlisted_host}",
             f"쿼리스트링에 허용 도메인 배치 우회"),
        ])

    return payloads
