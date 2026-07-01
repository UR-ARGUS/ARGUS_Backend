"""
main.py

SK Shieldus Web/API 개발보안 Guideline v3.0.0 1-3(파라미터 값 및 히든 필드 조작) 진단
파이프라인 진입점.

명세서(param_injection_diagnosis.md)의 analyzer.py(Claude API 기반 비즈니스 로직 판단)는
이번 반영 범위에서 제외했다. 대신 명세서 "구현 시 주의사항 > 오탐 방지 기준"에 이미 정의된
규칙을 그대로 적용해 후보를 추린다:
    - 상태코드 변화 없음 + 응답 길이 변화 50bytes 미만 -> 스킵
    - 상태코드 400/422 반환 -> 서버가 정상적으로 거부한 것으로 판단, 스킵
    - 상태코드 500 반환 -> 1-3이 아니라 별도 6-1(오류 처리) 항목 대상이므로 이 결과에서는 제외

사용법:
    python -m argus.services.scan.param_injection.main --url https://target.com --auth-token "Bearer xxx"

주의: 카테고리 분류 패턴과 페이로드 "데이터"는 payloads/*.yaml이 단일 소스다.
argus/services/scan/zap_scripts/parameter_diff_scan.js도 같은 YAML 파일을 SnakeYAML로
읽으므로(zap.py가 스크립트 로드 직전에 실제 경로를 주입) 카테고리/페이로드를 바꿀 땐
YAML만 고치면 양쪽에 반영된다(JS 쪽 SnakeYAML 로딩이 실패하면 자체 하드코딩 폴백으로
동작하니, 그 폴백까지 동기화하려면 parameter_diff_scan.js도 함께 봐야 한다).

이 모듈은 "ZAP 없이" 동작하는 게 아니다 - zap_crawler.py는 여전히 ZAP AJAX Spider로
크롤링한다. 다른 점은 크롤링 이후 "요청을 누가 보내는지"다: injector.py가 ZAP 프록시를
거치지 않고 requests.Session으로 직접 재전송하기 때문에, ZAP의 Replacer 헤더/Forced
User 인증 세션을 물려받지 못하고 여기 --auth-token으로 넘긴 헤더 하나에만 의존한다
(로그인 폼 기반 세션은 지원 안 함). 그래서 인증이 필요한 엔드포인트를 정확히 진단하려면
zap_scripts/parameter_diff_scan.js(ZAP 액티브 스캔 안에서 실행, 세션 상속 검증됨) 쪽을
쓰고, 이 모듈은 ZAP 세션 없이 대략적으로 훑어볼 때의 보조 도구로 취급한다.
"""

import json
import os
from datetime import datetime

import requests

from argus.core.config import settings

from .injector import inject
from .signature_classifier import classify
from .zap_crawler import crawl_and_collect


def _passes_filter(result: dict) -> bool:
    diff = result["diff"]
    status = result["injected_response"]["status"]

    if not diff["status_changed"] and abs(diff["body_length_delta"]) < 50:
        return False
    if status in (400, 422):
        return False
    if status >= 500:
        return False

    return True


def run(target_url: str, auth_token: str = "", wait_seconds: int = 30) -> dict:
    session = requests.Session()
    if auth_token:
        session.headers.update({"Authorization": auth_token})

    fields = crawl_and_collect(
        target_url,
        zap_api_url=settings.ZAP_API_URL,
        api_key=settings.ZAP_API_KEY or None,
        wait_seconds=wait_seconds,
    )
    classified = classify(fields)
    injection_results = inject(classified, session)
    candidates = [r for r in injection_results if _passes_filter(r)]

    findings = [
        {
            "field_name": c["field"]["field_name"],
            "field_type": c["field"]["field_type"],
            "category": c["field"]["category"],
            "url": c["field"]["url"],
            "method": c["field"]["method"],
            "original_value": c["field"]["original_value"],
            "payload": c["payload"],
            "original_status": c["original_response"]["status"],
            "injected_status": c["injected_response"]["status"],
            "diff": c["diff"],
            "sk_shieldus_item": "1-3",
        }
        for c in candidates
    ]

    output = {
        "target_url": target_url,
        "timestamp": datetime.now().isoformat(),
        "total_fields": len(fields),
        "total_injections": len(injection_results),
        "findings": findings,
    }

    os.makedirs(settings.SCAN_RESULTS_DIR, exist_ok=True)
    filename = os.path.join(
        settings.SCAN_RESULTS_DIR,
        f"param_injection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
    )
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    output["result_json_path"] = filename
    return output


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--auth-token", default="")
    args = parser.parse_args()

    result = run(args.url, args.auth_token)
    print(f"완료: {len(result['findings'])}건 후보 (결과: {result['result_json_path']})")
