"""
test_swagger_parse.py — Swagger OpenAPI Spec 문서 파싱을 통한 파라미터 수집 단위 테스트
"""

import json
from unittest.mock import patch, MagicMock

# ── 모의 Swagger/OpenAPI 3.0 Spec 정의 ──────────────────────────────
MOCK_SWAGGER_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "Argus Mock API Specification",
        "version": "1.0.0"
    },
    "servers": [
        {"url": "http://localhost:8000/api/v1"}
    ],
    "paths": {
        "/orders/detail": {
            "get": {
                "summary": "주문 상세 조회",
                "parameters": [
                    {
                        "name": "orderId",
                        "in": "query",
                        "required": True,
                        "schema": {
                            "type": "integer",
                            "default": 1042
                        }
                    }
                ]
            }
        },
        "/users/signup": {
            "post": {
                "summary": "회원 가입",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {
                                        "type": "string",
                                        "default": "guest"
                                    },
                                    "role": {
                                        "type": "string",
                                        "default": "USER"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/payment": {
            "post": {
                "summary": "결제 요청",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "amount": {
                                        "type": "integer",
                                        "default": 15000
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


def run_swagger_test():
    print("=" * 62)
    print(" Swagger Spec 파싱 단위 테스트 시작")
    print("=" * 62)

    # requests.get을 모킹하여 스키마 JSON을 반환하도록 설정
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = MOCK_SWAGGER_SPEC

    with patch("requests.get", return_value=mock_resp):
        from scanners.param_manipulation.collector import collect_params
        
        # URL에 openapi 키워드가 포함되면 Swagger 파서가 동작함
        spec_url = "http://localhost:8000/openapi.json"
        collected = collect_params(spec_url)

    print(f"\n[결과] 수집된 파라미터 수: {len(collected)}개")
    for idx, p in enumerate(collected, 1):
        print(f"  [{idx}] URL: {p.url} ({p.method})")
        print(f"      명칭: {p.param_name} | 값: {p.param_value} | 타입: {p.param_type} | CT: {p.content_type}")

    # 검증 수행
    assert len(collected) == 4, f"수집된 개수 에러: {len(collected)}"
    assert any(p.param_name == "orderId" for p in collected)
    assert any(p.param_name == "role" for p in collected)
    assert any(p.param_name == "amount" for p in collected)
    
    print("\n[성공] 모든 파라미터가 정확하게 수집되었습니다!")


if __name__ == "__main__":
    run_swagger_test()
