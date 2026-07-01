# 파라미터 값 및 히든 필드 조작 진단 - 작업 기록

> SK Shieldus Web/API 개발보안 Guideline v3.0.0 - 1-3 항목 대응
> `param_injection_diagnosis.md` 명세서 기반 구현 + 기존 ZAP 파이프라인 통합 작업 기록

---

## 1. 출발점: 기존 방식의 한계

기존 `argus/services/scan/zap.py` + `zap_scripts/parameter_diff_scan.js`는 ZAP Active Scan 정책에서
40008(내장 Parameter Tampering) + 커스텀 스크립트(50000 번들)만 활성화하고, 나머지 스캐너는 전부 꺼둔 상태였다.
`semgrep.py`/`ssl.py`/`ai_advisor.py`는 주석 한 줄짜리 미구현 스텁.

**진단됐던 문제점**:
- 결과 JSON이 전부 `Argus Parameter Tampering (Structural Diff)` 알림 하나에서 나옴 - 응답 상태코드/길이/반사값 diff라는 범용 휴리스틱만 사용.
- SK Shieldus 가이드가 요구하는 3가지 구체 시나리오(①금액/결제 조작, ②히든 필드로 노출된 중요값 조작, ③인증키 대신 유추 가능한 값으로 개인정보 열람)를 직접 겨냥하지 못함.
- SAST/TLS/AI 판단은 아예 미구현.

---

## 2. 1차 개선: `parameter_diff_scan.js` 시나리오 특화

가이드 3개 시나리오에 맞춰 JS 스크립트를 재작성:

| 시나리오 | 로직 |
|---|---|
| 금액 조작 | `price/amount/cost/...` 패턴 파라미터를 0 또는 원본값의 음수로 변조 → 정상 응답 유지 + 변조값 반영 시 risk 3 |
| IDOR/개인정보 열람 | `id/uid/mdn/phone/...` 패턴 파라미터를 인접값으로 치환 → 동일 상태코드(200)인데 본문 내용이 달라지면 risk 3 |
| 접근 제어 우회 | 401/403 → 200/201/302로 상태 반전 시 risk 3 (기존 로직 유지) |
| Silent success | 위 신호가 하나도 안 걸려도, "민감" 후보인데 서버가 명시적으로 거부하지 않았다면 낮은 confidence로 수동 확인 후보 보고 |

한계로 짚었던 것: 영문 네이밍 의존, 숫자 포맷 의존, `HTTP 200 + 에러코드` 패턴을 못 씀, ZAP의 `target_params_injectable` 옵션 미설정으로 URL Path 파라미터(`/users/{id}`)가 스캔 대상에서 빠질 가능성.

---

## 3. Swagger/OpenAPI 결합 검토

`try_import_openapi_spec()`가 REST API 크롤링 문제를 풀어주지만, 그것만으로는 부족하다고 판단한 지점:
- URL Path 파라미터 스캔 옵션(`target_params_injectable`)이 기본적으로 꺼져 있어 IDOR 후보(`/users/{id}`)를 놓칠 수 있음.
- 스펙 자체가 인증이 필요하면 `try_import_openapi_spec`(순수 `requests.get`, ZAP 프록시 미경유)이 조용히 실패.
- 컨텍스트 스코프가 `target_url` 접두어 정규식이라, API origin 전체가 아니라 특정 페이지 URL을 넘기면 스코프 밖 엔드포인트에 인증이 안 걸림.

---

## 4. `param_injection_diagnosis.md` 명세서 반영 (Python 독립 모듈)

`argus/services/scan/param_injection/`에 명세서 기반 파이프라인 구현 (Claude API 판단(`analyzer.py`)은 제외, 대신 명세서의 "오탐 방지 기준"을 규칙 기반 필터로 적용):

- `zap_crawler.py` - ZAP AJAX Spider로 크롤링 + query/body/hidden 필드 추출 (명세서의 헬퍼 스텁을 실제 구현으로 채움. `raw_url`/`raw_body`/`content_type`을 FieldInfo에 추가 - 인젝터가 원본 요청을 재구성하는 데 필요).
- `signature_classifier.py` - FINANCIAL/AUTHORIZATION/IDOR/LOGIC_FLOW 분류.
- `payloads/*.yaml` - 카테고리별 페이로드 템플릿.
- `injector.py` - 페이로드 주입 + diff 계산(`status_changed`/`body_length_delta`/`keywords_found`).
- `main.py` - 오케스트레이션 + 규칙 기반 필터(상태 불변+길이변화<50byte 스킵, 400/422 스킵, 500은 6-1 별도 분류).

`pyproject.toml`에 `pyyaml` 의존성 추가.

**한계**: `injector.py`가 `requests.Session`으로 직접 재전송 - ZAP의 Replacer 헤더/Forced User 인증 세션을 물려받지 못함 (크롤링은 ZAP 사용, 인젝션만 세션 없이 나감 - 반쪽짜리 결합이라고 지적됨).

---

## 5. 아키텍처 결정: JS를 실행 엔진으로, YAML을 데이터 단일 소스로

두 파이프라인(JS-in-ZAP / 독립 Python)을 어떻게 합칠지 검토한 결과:

- **기각한 안**: Python injector가 `zap.core.send_request()`로 ZAP을 거쳐 전송 → Forced User Mode가 실제로 적용되는지 검증 불가(라이브 테스트 없이는 신뢰 못 함), 인증 필요 엔드포인트에서 조용히 실패할 리스크가 너무 큼.
- **채택한 안**: 실제 요청 전송/인증/크롤링은 검증된 경로(ZAP 액티브 스캔 안에서 `as.sendAndReceive` 실행)를 유지하고, 카테고리 분류 패턴 + 페이로드 **데이터**만 `payloads/*.yaml`을 단일 소스로 공유. JS는 SnakeYAML(Java interop)로 같은 YAML을 읽고, 실패 시 하드코딩 폴백으로 안전하게 저하.

### YAML 스키마 확장
각 카테고리 YAML에 `field_name_patterns`(분류 정규식 조각)를 추가하고, `FINANCIAL.yaml`에 `{original_value * -1}` 동적 템플릿 토큰 추가 (기존 `{original_value ± 1}`과 동일한 방식으로 실행 시점 원본값 기준 계산).

### 코드 변경
- `signature_classifier.py`: 하드코딩된 `SIGNATURES` 제거, YAML의 `field_name_patterns`에서 조립.
- `injector.py`: 템플릿 토큰 해석을 `_TEMPLATE_RESOLVERS` 딕셔너리로 일반화.
- `parameter_diff_scan.js`: `CATEGORY_CONFIG` 로더 추가 - SnakeYAML + Java interop으로 YAML 읽기, 실패 시 `FALLBACK_PATTERNS`(하드코딩)로 자동 전환. `buildCandidates`가 `CATEGORY_CONFIG` 유무에 따라 분기.
- `zap.py`: `_render_custom_diff_script()` 추가 - 스크립트 로드 직전 템플릿의 `__ARGUS_PAYLOAD_DIR__` 플레이스홀더를 실제 절대경로로 치환해 `parameter_diff_scan.generated.js`를 생성 (`.gitignore`에 추가).

---

## 6. 라이브 검증에서 발견한 치명적 버그

로컬에 실제 설치돼 있던 ZAP(2.17.0, 포트 8090)을 이용해 직접 검증을 진행했다.

1. **SnakeYAML 가용성 확인**: `commonlib` 애드온(automation/network 등의 공통 의존성)에 `org.yaml.snakeyaml.Yaml`이 번들돼 있음을 zip 내부 클래스 목록으로 확인. Graal.js standalone 테스트 스크립트로 `Java.type("org.yaml.snakeyaml.Yaml")` 접근 및 YAML 파일 읽기/파싱 성공 확인.

2. **버그 발견**: 플레이스홀더 미치환 감지 가드(`PAYLOAD_DIR.indexOf("__ARGUS_PAYLOAD_DIR__") >= 0`)에 플레이스홀더 리터럴이 그대로 들어있어서, Python의 `str.replace()`가 실제 대입문뿐 아니라 이 가드 문자열까지 치환해버림 → 치환이 정상적으로 끝난 뒤에도 조건이 항상 참이 되어 `CATEGORY_CONFIG`가 **항상 `null`**로 떨어지는 버그. 실제 렌더링된 프로덕션 스크립트를 standalone으로 ZAP에 로드해 실행한 결과로 발견 (`loaded: false`).

3. **수정**: 가드용 마커를 `"__ARGUS_" + "PAYLOAD_DIR__"`로 문자열을 쪼개 선언 - Python의 단순 문자열 치환이 이 리터럴은 건드리지 못하고 실제 대입문만 치환하도록 함.

4. **재검증**: 수정 후 동일한 방식으로 재확인 - `CATEGORY_CONFIG`가 FINANCIAL/AUTHORIZATION/IDOR/LOGIC_FLOW 4개 카테고리 모두 정확한 patternCount/payloadCount로 로드됨. `ZapScanner.setup_parameter_tampering_policy()`를 실제 호출해 `ArgusParamDiff` 스크립트가 `type: active, enabled: true, error: false`로 정상 등록되는 것까지 확인.

검증에 사용한 임시 스크립트/결과 파일은 ZAP과 디스크 양쪽에서 모두 정리했다.

---

## 7. 현재 상태 요약

- **실행 엔진(canonical)**: `argus/services/scan/zap_scripts/parameter_diff_scan.js` - ZAP 액티브 스캔 안에서 실행, 인증 세션 상속이 검증된 유일한 경로.
- **데이터 단일 소스**: `argus/services/scan/param_injection/payloads/*.yaml` - 분류 패턴 + 페이로드. Python(`signature_classifier.py`)과 JS(SnakeYAML)가 같은 파일을 공유.
- **Python 독립 파이프라인**: `argus/services/scan/param_injection/` - ZAP 세션 없이 대략적으로 훑어볼 때의 보조 도구로 유지 (인증 필요 엔드포인트에선 신뢰도 낮음, docstring에 명시).

## 8. 남은 한계 / 향후 과제

- URL Path 파라미터(`/users/{id}`) 스캔 - `ascan.set_option_target_params_injectable()`로 URL_PATH 비트를 켜는 작업 미완.
- `HTTP 200 + 바디 내 에러코드` 패턴을 쓰는 API에서는 접근 제어 우회 신호가 애초에 안 뜰 수 있음.
- IDOR 콘텐츠-diff 신호(`body !== baseBody`)는 CSRF 토큰/타임스탬프 등 요청마다 바뀌는 값 때문에 오탐 가능 - confidence를 낮게(1) 유지하는 것으로 완화 중.
- 히든 필드의 실제 제출(POST) 대상이 폼 `action`으로 다른 경로를 가리키는 경우 `param_injection/zap_crawler.py`의 재구성이 부정확할 수 있음(폼 action 파싱 미구현).
