"""
ZAP JSON/JSONC 결과 → CaptureJob 변환 모듈 (범용 버전)

특정 사이트가 아닌 "임의의 URL을 입력받아 진단하는" 범용 플랫폼을 전제로 설계됨.
따라서 다음 가정을 깔지 않는다:
  - alert가 항상 GET 요청일 것이다           (X — POST/PUT/DELETE 다수 존재)
  - evidence가 항상 채워져 있을 것이다         (X — 빈 문자열인 경우가 흔함)
  - 응답이 항상 HTML 페이지일 것이다           (X — JSON API 응답도 많음)
  - alert 종류가 몇 개 안 될 것이다            (X — 동일 alert가 수백 건 중복될 수 있음)
  - ZAP 표준 raw export 포맷만 들어올 것이다    (X — 팀/도구마다 가공 포맷이 다름, JSONC 주석 포함 가능)

지원하는 입력 형식:
  1. ZAP 표준 raw export: {"site": [{"alerts": [{"instances": [...]}]}]}
  2. zap.core.alerts() 단순 리스트: [{...}, {...}]
  3. 평탄화된 커스텀 포맷 (instances 없이 url/param/attack이 alert 객체에 바로 있음)
  4. 위 어떤 형식이든 JSONC(// 라인 주석, 인라인 주석 포함) 허용
"""

import json
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse


@dataclass
class CaptureJob:
    """Selenium 캡처 파이프라인 1건의 작업 단위."""

    job_id: str
    alert_type: str          # ZAP alert 이름
    alert_category: str      # 캡처 전략 분기용 정규화 카테고리 (xss / sqli / redirect / path_traversal / other)
    target_url: str          # payload가 포함된 공격 URL
    base_url: str            # payload를 제거한 정상 상태 URL (GET 전용, STEP1에서 사용)
    param: Optional[str]
    attack: Optional[str]
    evidence: Optional[str]
    risk: str = "Unknown"
    confidence: str = "Unknown"
    method: str = "GET"
    response_type_hint: str = "unknown"  # "html" / "json" / "unknown" — STEP2 전략 분기용
    request_body: Optional[dict] = None  # POST/PUT 시 본문에 payload를 넣어야 하는 경우 사용
    extra: dict = field(default_factory=dict)


# ──────────────────────────────────────────────
# alert 분류 — 범용 키워드 매칭 (한국어 표준 진단명 + 영어 ZAP 원문 모두 지원)
# ──────────────────────────────────────────────
_ALERT_CATEGORY_RULES = [
    (("cross site scripting", "xss", "스크립팅"), "xss"),
    (("sql injection", "sql 인젝션", "sql injection"), "sqli"),
    (("redirect", "리다이렉트"), "redirect"),
    (("path traversal", "directory traversal", "경로 추적", "경로추적"), "path_traversal"),
    (("remote file inclusion", "local file inclusion"), "lfi_rfi"),
    (("buffer overflow", "버퍼 오버플로우", "format string", "포맷 스트링"), "fuzz_crash"),
    (("csrf", "쿠키", "cookie", "samesite"), "csrf_cookie"),
    (("exception", "예외", "internal server error", "500"), "server_error"),
]


def _classify_alert(alert_name: str) -> str:
    name = alert_name.lower()
    for keywords, category in _ALERT_CATEGORY_RULES:
        if any(kw.lower() in name for kw in keywords):
            return category
    return "other"


# 캡처 전략이 사실상 동일한(=캡처해도 추가 정보가 없는) 카테고리.
# 범용 도구는 이런 alert가 수백 건씩 들어올 수 있으므로 기본적으로 샘플링 대상이 됨.
_LOW_VALUE_CATEGORIES = {"fuzz_crash"}


def _guess_response_type(alert: dict) -> str:
    """
    응답이 HTML인지 JSON인지 추정. DOM 하이라이트(STEP2)가 의미 있는지 판단하는 데 사용.
    ZAP raw export에는 명시적 Content-Type 필드가 없는 경우가 많아 휴리스틱으로 추정.
    """
    url = (alert.get("url") or "").lower()
    description = (alert.get("description") or "").lower()
    other = (alert.get("other") or "").lower()

    if "/api/" in url or url.endswith(".json"):
        return "json"
    if "json" in description or "json" in other:
        return "json"
    if any(url.endswith(ext) for ext in (".html", ".php", ".asp", ".jsp", "/")):
        return "html"
    return "unknown"


def _strip_payload_from_url(url: str, param: Optional[str]) -> str:
    """공격 URL에서 취약 파라미터 값만 제거해 STEP1용 base_url 생성 (GET 쿼리스트링 기준)."""
    if not param:
        return url
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if not any(k == param for k, _ in query_pairs):
        # 파라미터가 쿼리스트링이 아니라 path/body에 있는 경우 — URL 자체는 그대로 둠
        return url
    new_pairs = [(k, "" if k == param else v) for k, v in query_pairs]
    new_query = urlencode(new_pairs)
    return urlunparse(parsed._replace(query=new_query))


def _strip_jsonc_comments(text: str) -> str:
    """
    JSONC(JSON with Comments)에서 // 라인 주석을 제거.
    문자열 리터럴 내부의 //는 보존해야 하므로 상태 머신으로 문자열 안/밖을 추적.
    /* */ 블록 주석은 이 데이터셋에 안 나타나지만 혹시 몰라 같이 처리.
    """
    result = []
    in_string = False
    in_block_comment = False
    escape = False
    i, n = 0, len(text)

    while i < n:
        ch = text[i]

        if in_block_comment:
            if ch == "*" and i + 1 < n and text[i + 1] == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_string:
            result.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        # 문자열 밖
        if ch == '"':
            in_string = True
            result.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            in_block_comment = True
            i += 2
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def load_zap_json(json_path: str) -> list:
    """
    ZAP 결과 파일(JSON 또는 JSONC) 경로를 받아 raw dict 리스트로 로드.
    파일 확장자가 .json이어도 내용에 // 주석이 섞여 있으면 자동으로 제거 후 파싱.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        # 일반 JSON 파싱 실패 시 JSONC로 간주하고 주석 제거 후 재시도
        cleaned = _strip_jsonc_comments(raw_text)
        data = json.loads(cleaned)

    if isinstance(data, list):
        return data

    if isinstance(data, dict) and "site" in data:
        alerts = []
        for site in data["site"]:
            alerts.extend(site.get("alerts", []))
        return alerts

    raise ValueError(f"인식할 수 없는 ZAP JSON 구조: {json_path}")


def convert_to_capture_jobs(
    zap_alerts: list,
    only_risk: Optional[set] = None,
    max_per_alert_group: Optional[int] = 5,
) -> list:
    """
    ZAP alert raw dict 리스트 → CaptureJob 리스트 변환 (범용 버전).

    Args:
        zap_alerts: load_zap_json()의 반환값
        only_risk: {"High", "Medium"} 등 캡처 대상으로 한정할 risk 레벨 집합. None이면 전체.
        max_per_alert_group: 동일한 (alert_type, risk) 조합이 이 개수를 초과하면 샘플링.
            범용 도구는 같은 alert가 수백 건 중복되는 경우가 흔하므로(예: 동일 스캐너가
            여러 파라미터에 동일 패턴 시도) 캡처 비용을 통제하기 위한 안전장치.
            None이면 제한 없음.

    Returns:
        CaptureJob 리스트.
    """
    raw_jobs = []

    for alert in zap_alerts:
        risk = (alert.get("riskdesc") or alert.get("risk") or "Unknown").split(" ")[0]
        if only_risk and risk not in only_risk:
            continue

        instances = alert.get("instances", [alert])
        response_type_hint = _guess_response_type(alert)

        for inst in instances:
            url = inst.get("uri") or inst.get("url") or alert.get("url")
            if not url:
                continue

            # 기본 도메인을 https://onde.click으로 강제 치환
            try:
                parsed_url = urlparse(url)
                url = urlunparse(parsed_url._replace(scheme="https", netloc="onde.click"))
            except Exception:
                pass

            param = inst.get("param") or alert.get("param") or None
            attack = inst.get("attack") or alert.get("attack") or None
            evidence = inst.get("evidence") or alert.get("evidence") or None
            method = (inst.get("method") or alert.get("method") or "GET").upper()

            alert_name = alert.get("alert") or alert.get("name", "Unknown Alert")
            category = _classify_alert(alert_name)

            # 빈 문자열은 None과 동등하게 취급 (다운스트림에서 "값 없음" 판단을 단순화)
            param = param or None
            attack = attack or None
            evidence = evidence or None

            request_body = None
            if method in ("POST", "PUT", "PATCH") and param and attack:
                # body 기반 요청은 STEP2/3에서 driver.get()이 아닌 fetch/XHR 방식으로
                # 재현해야 하므로, payload를 본문 형태로 미리 구성해둔다.
                request_body = {param: attack}

            job = CaptureJob(
                job_id=str(uuid.uuid4())[:8],
                alert_type=alert_name,
                alert_category=category,
                target_url=url,
                base_url=_strip_payload_from_url(url, param) if method == "GET" else url,
                param=param,
                attack=attack,
                evidence=evidence,
                risk=risk,
                confidence=alert.get("confidence", "Unknown"),
                method=method,
                response_type_hint=response_type_hint,
                request_body=request_body,
                extra={"alert_id": alert.get("pluginid") or alert.get("pluginId") or alert.get("id")},
            )
            raw_jobs.append(job)

    return _sample_low_value_duplicates(raw_jobs, max_per_alert_group)


def _sample_low_value_duplicates(jobs: list, max_per_group: Optional[int]) -> list:
    """
    동일한 (alert_type, risk) 조합이 다량으로 중복될 때 일부만 샘플링.

    범용 진단 도구에서는 같은 스캐너 규칙이 사이트 전역의 모든 파라미터에 동일 패턴을
    시도하면서 alert가 수백 건씩 쌓이는 경우가 흔하다(예: 거대 무작위 문자열로 500 에러를
    유발하는 버퍼오버플로우류 점검). 이런 항목을 전부 캡처하는 건 시간/비용 대비 정보 가치가
    낮으므로, low-value 카테고리에 한해 그룹별 최대 개수를 둔다.
    하이밸류 카테고리(xss, sqli, path_traversal 등)는 항상 전부 보존.
    """
    if max_per_group is None:
        return jobs

    grouped = defaultdict(list)
    for job in jobs:
        grouped[(job.alert_type, job.risk)].append(job)

    result = []
    for (alert_type, risk), group in grouped.items():
        category = group[0].alert_category
        if category in _LOW_VALUE_CATEGORIES and len(group) > max_per_group:
            result.extend(group[:max_per_group])
        else:
            result.extend(group)

    return result


def jobs_to_dict_list(jobs: list) -> list:
    """CaptureJob 리스트를 JSON 직렬화 가능한 dict 리스트로 변환 (로깅/디버깅용)."""
    return [job.__dict__ for job in jobs]


def summarize_jobs(jobs: list) -> dict:
    """alert_category / risk 별 분포 요약. CLI 출력 및 진행 로그에 사용."""
    by_category = defaultdict(int)
    by_risk = defaultdict(int)
    by_method = defaultdict(int)
    for job in jobs:
        by_category[job.alert_category] += 1
        by_risk[job.risk] += 1
        by_method[job.method] += 1
    return {
        "total": len(jobs),
        "by_category": dict(by_category),
        "by_risk": dict(by_risk),
        "by_method": dict(by_method),
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("사용법: python capture_job.py <zap_result.json|.jsonc>")
        sys.exit(1)

    alerts = load_zap_json(sys.argv[1])
    jobs = convert_to_capture_jobs(alerts, only_risk={"High", "Medium", "Low"}, max_per_alert_group=5)

    summary = summarize_jobs(jobs)
    print(f"총 {summary['total']}개 CaptureJob 생성 (중복 샘플링 적용 후)")
    print(f"  카테고리별: {summary['by_category']}")
    print(f"  risk별:    {summary['by_risk']}")
    print(f"  method별:  {summary['by_method']}")
    print()
    for j in jobs[:10]:
        print(f"  [{j.risk}/{j.alert_category}/{j.method}] {j.alert_type} — "
              f"param={j.param} url={j.target_url[:70]}")
