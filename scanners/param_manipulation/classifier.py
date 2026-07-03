"""
classifier.py — Phase 2 (규칙 기반 사전 분류) + Phase 4 (LLM diff 해석)

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-3
명세: 1-3_scan_engine_spec.md § 4

역할 변경 (v2 — 자동화 안정성 개선):
    [기존] Phase 2에서 LLM이 파라미터 "이름"만 보고 위험 카테고리를 사전 분류.
           탐지 성공 여부 자체가 LLM 호출에 의존 → LLM이 멈추면 스캔 전체가 멈춤
           (timeout 미설정 시 무한 대기 가능. 실제로 celery 태스크가 이 단계에서
           수 시간째 STARTED 상태로 멈춰있던 사례 있음).
    [변경] 탐지는 규칙 기반으로만 수행해 LLM 비의존·실행시간 유계(bounded)로 만들고,
           LLM은 이미 잡힌 이상 징후를 해석·설명하는 보강 역할로 뒤로 이동.

파이프라인 위치:
    Phase 1: collector.py   → 파라미터 전체 수집
    Phase 2: classify_params (본 파일) → 이름 기반 규칙(정규식) 사전 태깅, LLM 미사용
    Phase 3: manipulator.py + comparator.py → 페이로드 주입 + 응답 diff 1차 탐지(RawFinding)
    Phase 4: interpret_findings (본 파일) → LLM이 diff 해석 + 취약 여부 확정 + 보고서 문장 생성

LLM은 Phase 4에서만 호출되며, 그 대상은 Phase 3에서 이미 규칙 기반으로 이상 신호가
잡힌 RawFinding만이다 (전체 파라미터 대비 훨씬 적음) — 호출 빈도도 낮아진다.

LLM 백엔드 선택 (자동, Phase 4):
    ANTHROPIC_API_KEY 설정 시 → Claude API 사용
    OLLAMA_BASE_URL 설정 시   → Ollama 로컬 서버 사용 (기본: http://localhost:11434)
    둘 다 없거나 호출 실패    → 규칙 기반 폴백 (RawFinding을 그대로 Finding으로 승격)

Ollama 타임아웃 대응:
    - httpx.Timeout으로 connect/read/write/pool 개별 설정 (기존: timeout 미설정 →
      응답이 없으면 무한정 대기하던 것이 근본 원인)
    - 청크 크기를 백엔드별로 분리 (Claude: 20개, Ollama: 5개) — Ollama는 로컬 모델이라
      한 번에 큰 프롬프트를 주면 응답이 느려지므로 작게 유지
    - body 미리보기 크기도 분리 (Claude: 500자, Ollama: 200자) — 입력 토큰 절감
    - LLM 호출/파싱 실패 시(타임아웃 포함) 규칙 기반 폴백으로 즉시 전환 — 취약점
      탐지 결과 자체는 유지되고 설명 품질만 낮아짐 (findings가 유실되지 않음)
"""

import json
import logging
import re
from itertools import islice
from typing import Iterator

from argus.core.config import settings
from .models import CollectedParam, ClassifiedParam, RawFinding, Finding

logger = logging.getLogger(__name__)

# 규칙 기반 분류 패턴 (Phase 2 사전 태깅 + Phase 4 폴백 공용)
#
# STATUS 규칙은 두 PRIVILEGE 규칙 사이에 끼워 넣는다 — role/admin류 구체적 권한
# 키워드는 여전히 PRIVILEGE로 먼저 잡히게 하고(예: isAdmin), 그다음에야 STATUS
# 키워드(paid/verified/approved 등)를 검사해 isPaid·isVerified 같은 주문/결제/승인
# 상태 플래그를 가로챈다. 이 순서가 아니면 마지막 "^is[A-Z]" 캐치올이 isPaid까지
# 전부 PRIVILEGE로 묶어버려 카테고리 의미가 어긋난다(가격/결제 우회인데 권한
# 우회로 잘못 분류됨 — severity·LLM 설명도 엉뚱해짐).
_FALLBACK_RULES: list[tuple[str, re.Pattern]] = [
    ("PRICE",     re.compile(r"price|amount|cost|fee|total|discount|point|pay|money|qty|quantity|charge|balance", re.I)),
    ("PRIVILEGE", re.compile(r"role|admin|perm|level|grade|authority|access|privilege", re.I)),
    ("STATUS",    re.compile(r"status|state|approved|verified|paid|confirmed|delivered|shipped|completed|complete|cancell?ed|refunded|published|enabled|active|deleted|archived", re.I)),
    ("PRIVILEGE", re.compile(r"^is[A-Z]|[a-z0-9]Flag$")),  # camelCase: isAdmin, isStaff 등 STATUS에 안 걸린 나머지 boolean 플래그
    ("IDOR",      re.compile(r"(^|_)(id|uid|no)$|userid|memberid|orderid|boardid|seq|mdn|phone", re.I)),
    ("IDOR",      re.compile(r"[a-z0-9](Id|Uid|No)$")),  # camelCase: userId, orderId
]

# anomaly_type → severity 기본값 (Phase 4 LLM 폴백 시 사용)
_DEFAULT_SEVERITY: dict[str, str] = {
    "PRIVILEGE_BYPASS":              "HIGH",
    "PERSISTED_PRIVILEGE_ESCALATION": "HIGH",
    "VALUE_ACCEPTED":                "HIGH",
    "DATA_EXPOSURE":                 "HIGH",
    "POTENTIAL_IDOR":                "MEDIUM",
    "ERROR_SUPPRESSED":              "MEDIUM",
}


# ══════════════════════════════════════════════════════════════════
# Phase 2 — 규칙 기반 사전 분류 (LLM 미사용)
# ══════════════════════════════════════════════════════════════════

def classify_params(params: list[CollectedParam]) -> list[ClassifiedParam]:
    """
    수집된 파라미터를 이름 기반 정규식 규칙으로 분류한다.
    LLM을 호출하지 않으므로 결정적이며 실행시간이 사실상 0에 수렴한다.

    hidden 타입은 규칙 판단 없이 즉시 HIDDEN 태깅.
    SAFE로 분류된 파라미터는 engine.py에서 필터링해 Phase 3(실 요청)에 전달하지 않는다
    — 대상 서비스로 나가는 불필요한 요청을 줄이기 위함.

    Args:
        params: Phase 1에서 수집된 CollectedParam 목록

    Returns:
        List[ClassifiedParam] — SAFE 포함 전체 분류 결과
    """
    classified: list[ClassifiedParam] = []

    for p in params:
        if p.param_type == "hidden":
            classified.append(ClassifiedParam(
                collected=p,
                category="HIDDEN",
                reason="HTML hidden input 필드로 전송되는 값",
            ))
            continue

        category, reason = _match_rule(p.param_name)
        classified.append(ClassifiedParam(collected=p, category=category, reason=reason))

    from collections import Counter
    counter = Counter(c.category for c in classified)
    logger.info(f"[Phase 2] 규칙 기반 분류 완료 — {dict(counter)}")
    return classified


def _match_rule(param_name: str) -> tuple[str, str]:
    """파라미터명을 규칙에 매칭시켜 (category, reason)을 반환한다. 미매칭 시 SAFE."""
    for category, pattern in _FALLBACK_RULES:
        if pattern.search(param_name):
            return category, f"규칙 기반: '{param_name}'이 {category} 패턴 매칭"
    return "SAFE", "규칙 미매칭 → SAFE"


# ══════════════════════════════════════════════════════════════════
# Phase 4 — LLM diff 해석 (Claude API 또는 Ollama, timeout 적용)
# ══════════════════════════════════════════════════════════════════

# 백엔드별 청크 크기 — Ollama는 body 포함 시 입력 토큰이 무거우므로 작게 유지
# (5→3으로 줄여도 여전히 36%가 출력 잘림으로 누락 → 정확도 우선 요청에 따라 1로 축소.
#  호출당 판단 항목이 하나뿐이면 출력이 짧아 잘릴 가능성이 사실상 사라짐. 대신 LLM
#  호출 횟수가 RawFinding 건수만큼 늘어나 스캔 시간은 길어짐 — 정확도와 맞바꾼 것)
_CHUNK_SIZE: dict[str, int] = {
    "claude": 20,
    "ollama":  1,
}

# 백엔드별 body 미리보기 크기 — Ollama 입력 토큰 절감, Claude는 여유 있으므로 더 많이 전달
_BODY_PREVIEW_LEN: dict[str, int] = {
    "claude": 500,
    "ollama": 200,
}

# Ollama 타임아웃 설정 (초) — 이 설정이 없어서 이전에는 응답이 없으면 무한 대기했음
_OLLAMA_TIMEOUT_CONNECT =   5.0   # TCP 연결 대기
_OLLAMA_TIMEOUT_READ    = 120.0   # 응답 스트림 읽기 (로컬 LLM은 첫 토큰까지 오래 걸릴 수 있음)
_OLLAMA_TIMEOUT_WRITE   =  10.0   # 요청 전송
_OLLAMA_TIMEOUT_POOL    =   5.0   # 커넥션 풀 대기


def interpret_findings(raw_findings: list[RawFinding], progress_callback=None) -> list[Finding]:
    """
    comparator.py(Phase 3)가 규칙 기반으로 탐지한 이상 징후(RawFinding)를
    LLM이 해석해 최종 Finding으로 확정한다.

    Args:
        raw_findings:       Phase 3에서 응답 diff 기반으로 탐지한 이상 징후 목록
        progress_callback:  Callable[[int], None] — 청크 단위 LLM 처리 진행률(0~100) 보고

    Returns:
        list[Finding] — LLM(또는 폴백)이 severity/설명을 채운 최종 결과
    """
    if not raw_findings:
        return []

    llm_client = _build_llm_client()
    backend    = llm_client[0]

    if backend == "fallback":
        return _fallback_promote(raw_findings)

    chunk_size = _CHUNK_SIZE[backend]
    chunks = list(_chunks(raw_findings, chunk_size))
    findings: list[Finding] = []
    for i, chunk in enumerate(chunks):
        findings.extend(_call_llm(llm_client, chunk))
        if progress_callback:
            progress_callback(int((i + 1) / len(chunks) * 100))

    logger.info(f"[Phase 4] LLM 해석 완료 — 입력 {len(raw_findings)}건 → 확정 {len(findings)}건")
    return findings


def _build_llm_client() -> tuple:
    """
    설정에 따라 LLM 클라이언트를 반환한다.

    우선순위:
        1. ANTHROPIC_API_KEY 설정 시 → Claude API
        2. OLLAMA_BASE_URL 설정 시   → Ollama (httpx.Timeout 적용, 연결 확인도 5초 제한)
        3. 둘 다 없거나 연결 실패    → ("fallback", None)
    """
    if getattr(settings, "ANTHROPIC_API_KEY", ""):
        try:
            import anthropic
            logger.info("[Phase 4] LLM 백엔드: Claude API")
            return ("claude", anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY))
        except ImportError:
            logger.warning("anthropic 패키지 없음 — Ollama로 전환")

    ollama_url   = getattr(settings, "OLLAMA_BASE_URL", "") or "http://localhost:11434"
    ollama_model = getattr(settings, "OLLAMA_MODEL",    "") or "qwen2.5:7b"

    try:
        import httpx
        from openai import OpenAI

        client = OpenAI(
            base_url=f"{ollama_url}/v1",
            api_key="ollama",
            timeout=httpx.Timeout(
                connect=_OLLAMA_TIMEOUT_CONNECT,
                read=_OLLAMA_TIMEOUT_READ,
                write=_OLLAMA_TIMEOUT_WRITE,
                pool=_OLLAMA_TIMEOUT_POOL,
            ),
        )

        # 연결 확인 — 별도 단기 타임아웃 (서버 미실행 시 빠르게 폴백)
        with httpx.Client(timeout=_OLLAMA_TIMEOUT_CONNECT) as probe:
            probe.get(f"{ollama_url}/api/tags")

        logger.info(f"[Phase 4] LLM 백엔드: Ollama ({ollama_url}, 모델: {ollama_model})")
        return ("ollama", client, ollama_model)

    except Exception as e:
        logger.warning(f"Ollama 연결 실패 ({ollama_url}): {e} — 규칙 기반 폴백 사용")
        return ("fallback", None)


def _call_llm(llm_client: tuple, chunk: list[RawFinding]) -> list[Finding]:
    """청크 단위로 LLM을 호출해 RawFinding → Finding 변환 결과를 반환한다."""
    backend = llm_client[0]

    diff_list = [_build_diff_summary(i, rf, backend) for i, rf in enumerate(chunk)]

    prompt = f"""\
당신은 웹 보안 취약점 분석 전문가입니다.
다음은 파라미터 조작 테스트 결과입니다. 각 항목에 대해 아래를 판단하세요.

판단 기준:
1. is_vulnerable: 실제 취약점인지 (true/false)
   - true  조건: 권한 없는 요청 성공 / 타인 데이터 노출 / 서버가 조작값을 수용
   - false 조건: 단순 크기 변화 / 에러 메시지 차이 / 정상 검증 후 거부
2. category: PRICE | PRIVILEGE | STATUS | IDOR | HIDDEN | UNKNOWN
3. severity: HIGH | MEDIUM | LOW
4. description: 한국어로 취약점 설명 (2문장 이내)
5. recommendation: 한국어로 개발자 대상 조치 방안 (1문장)

반드시 JSON 배열로만 응답하세요. 다른 텍스트 없이.

출력 형식:
[{{"index": 0, "is_vulnerable": true, "category": "PRIVILEGE", "severity": "HIGH", "description": "설명", "recommendation": "조치 방안"}}]

입력:
{json.dumps(diff_list, ensure_ascii=False)}
"""

    try:
        if backend == "claude":
            client   = llm_client[1]
            resp     = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )
            raw_text = resp.content[0].text

        else:  # ollama — timeout은 클라이언트 생성 시 이미 적용됨
            client, model = llm_client[1], llm_client[2]
            resp     = client.chat.completions.create(
                model=model,
                max_tokens=2048,
                temperature=0,
                messages=[{"role": "user", "content": prompt}],
            )
            raw_text = resp.choices[0].message.content

        json_match = re.search(r"\[.*\]", raw_text, re.DOTALL)
        results    = json.loads(json_match.group() if json_match else raw_text)
        index_map  = {r["index"]: r for r in results}

    except Exception as e:
        logger.warning(f"[Phase 4] LLM 호출/파싱 실패: {e} — 규칙 기반 폴백으로 전환")
        return _fallback_promote(chunk)

    # index_map에 없는 항목은 "LLM이 검토해서 아니라고 판단"한 게 아니라 "응답에서
    # 통째로 누락"된 것이다 (주로 max_tokens 부족으로 인한 출력 잘림). 이 둘을
    # 구분하지 않으면 20건 전부가 근거 없이 조용히 False가 되어버려 애초 이 필드를
    # 만든 목적("왜 걸러졌는지 보이게")이 무색해진다 — 그래서 명시적으로 표시한다.
    if len(index_map) < len(chunk):
        missing = [i for i in range(len(chunk)) if i not in index_map]
        logger.warning(
            f"[Phase 4] LLM 응답에 {len(missing)}/{len(chunk)}개 항목 누락 (index={missing}) "
            f"— 출력 잘림 가능성. 해당 항목은 '미검토'로 표시함"
        )

    output: list[Finding] = []
    for i, rf in enumerate(chunk):
        r = index_map.get(i)
        if r is None:
            # LLM 응답 자체에 이 index가 없음 — 명시적 거부가 아니라 미검토
            output.append(Finding(
                url=rf.url,
                method=rf.method,
                param_name=rf.param_name,
                category=rf.category,
                payload_used=rf.payload_used,
                payload_description=rf.payload_description,
                baseline_status=rf.baseline_status,
                test_status=rf.test_status,
                anomaly_type=rf.anomaly_type,
                anomaly_detail=rf.anomaly_detail,
                baseline_body=rf.baseline_body,
                test_body=rf.test_body,
                baseline_request_body=rf.baseline_request_body,
                test_request_body=rf.test_request_body,
                severity=_DEFAULT_SEVERITY.get(rf.anomaly_type, "MEDIUM"),
                llm_description="[미검토] LLM 응답에 이 항목이 누락되어 판단 결과 없음 (출력 잘림 등) — 수동 검토 필요",
                llm_recommendation="Selenium 캡처 후 담당자 확인 요망",
                is_vulnerable=False,
            ))
            continue

        output.append(Finding(
            url=rf.url,
            method=rf.method,
            param_name=rf.param_name,
            category=r.get("category", rf.category),
            payload_used=rf.payload_used,
            payload_description=rf.payload_description,
            baseline_status=rf.baseline_status,
            test_status=rf.test_status,
            anomaly_type=rf.anomaly_type,
            anomaly_detail=rf.anomaly_detail,
            baseline_body=rf.baseline_body,
            test_body=rf.test_body,
            baseline_request_body=rf.baseline_request_body,
            test_request_body=rf.test_request_body,
            severity=r.get("severity", _DEFAULT_SEVERITY.get(rf.anomaly_type, "MEDIUM")),
            llm_description=r.get("description", ""),
            llm_recommendation=r.get("recommendation", ""),
            is_vulnerable=bool(r.get("is_vulnerable", False)),
        ))

    return output


def _fallback_promote(chunk: list[RawFinding]) -> list[Finding]:
    """
    LLM 없이(또는 실패 시) RawFinding을 그대로 Finding으로 승격한다.
    Phase 2에서 이미 매긴 규칙 기반 category와 anomaly_type 기반 기본 severity를 사용.
    취약 여부를 확정하지 않으므로 전부 포함 (Selenium 단계에서 수동 검토 필요).
    """
    output = [
        Finding(
            url=rf.url,
            method=rf.method,
            param_name=rf.param_name,
            category=rf.category,
            payload_used=rf.payload_used,
            payload_description=rf.payload_description,
            baseline_status=rf.baseline_status,
            test_status=rf.test_status,
            anomaly_type=rf.anomaly_type,
            anomaly_detail=rf.anomaly_detail,
            baseline_body=rf.baseline_body,
            test_body=rf.test_body,
            baseline_request_body=rf.baseline_request_body,
            test_request_body=rf.test_request_body,
            severity=_DEFAULT_SEVERITY.get(rf.anomaly_type, "MEDIUM"),
            llm_description="LLM 미사용 — 수동 검토 필요",
            llm_recommendation="Selenium 캡처 후 담당자 확인 요망",
        )
        for rf in chunk
    ]
    logger.info(f"[Phase 4] 폴백 승격: {len(output)}건 (LLM 미사용)")
    return output


def _build_diff_summary(index: int, rf: RawFinding, backend: str) -> dict:
    """LLM에 전달할 diff 요약을 생성한다 (백엔드별 body 미리보기 크기 분리)."""
    preview_len      = _BODY_PREVIEW_LEN.get(backend, 200)
    baseline_preview = rf.baseline_body[:preview_len] if rf.baseline_body else ""
    test_preview     = rf.test_body[:preview_len]     if rf.test_body     else ""

    return {
        "index":               index,
        "url":                 rf.url,
        "method":              rf.method,
        "param_name":          rf.param_name,
        "payload_used":        rf.payload_used,
        "payload_description": rf.payload_description,
        "baseline_status":     rf.baseline_status,
        "test_status":         rf.test_status,
        "anomaly_type":        rf.anomaly_type,
        "anomaly_detail":      rf.anomaly_detail,
        "baseline_body":       baseline_preview,
        "test_body":           test_preview,
    }


def _chunks(lst: list, size: int) -> Iterator[list]:
    """리스트를 size 단위 청크로 분할하는 제너레이터."""
    it = iter(lst)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk
