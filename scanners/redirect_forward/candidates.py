"""
candidates.py — Phase 2: 리다이렉트/포워드 후보 파라미터 선별 (규칙 기반, LLM 미사용)

SK Shieldus Web/API 개발보안 Guideline v3.0.0 / 항목 1-5
1-3 스캔 엔진(scanners.param_manipulation.classifier)과 동일한 설계 원칙을 따른다:
    - 이름 기반 정규식으로만 판단 → 결정적이고 실행시간이 사실상 0에 수렴
    - 대상 서비스로 나가는 불필요한 요청을 줄이기 위해 후보가 아닌 파라미터는
      Phase 3(실 요청 + 페이로드 주입)로 넘기지 않는다.
"""

import logging
import re

from scanners.param_manipulation.models import CollectedParam
from .models import RedirectCandidate

logger = logging.getLogger(__name__)

# snake_case / 단어 경계 기준 리다이렉트·포워드 관련 파라미터명 패턴.
# SK Shieldus 가이드 예제(returl=evil.com)처럼 "return"류 축약형도 함께 커버한다.
_REDIRECT_NAME_PATTERN = re.compile(
    r"(^|_)("
    r"url|uri|link|href|"
    r"target|dest|destination|"
    r"redirect|redirecturl|redirecturi|redirectto|"
    r"return|returl|returnurl|returnto|"
    r"next|nexturl|nextpage|"
    r"forward|forwardurl|forwardto|"
    r"continue|continueurl|"
    r"callback|callbackurl|"
    r"success|successurl|"
    r"fail|failurl|"
    r"logout|logouturl|"
    r"checkout|checkouturl|"
    r"goto|out|jump|nav|navigate|"
    r"site|domain|host|"
    r"ref|referrer|referer"
    r")($|_)",
    re.IGNORECASE,
)

# camelCase 파라미터명 보조 패턴 — returnUrl, redirectUrl, nextPage, successUrl 등
# snake_case 패턴의 단어 경계(_)로는 못 잡는 표기법을 커버한다.
_REDIRECT_CAMEL_PATTERN = re.compile(
    r"(return|redirect|forward|continue|callback|success|fail|logout|checkout|target|dest|next)"
    r"(Url|URL|Uri|URI|Page|To|Path|Link|Href)$"
)

# 값 자체가 URL/경로 형태인지 판별 — 이름만으로는 애매한 파라미터(예: "go", "page")를
# 값 신호로 보강할 때 사용한다.
_URL_LIKE_VALUE_PATTERN = re.compile(r"^(https?://|//|/)", re.IGNORECASE)
_WEAK_NAME_HINT_PATTERN = re.compile(r"url|link|path|page|go\b|move|nav", re.IGNORECASE)


def select_candidates(params: list[CollectedParam]) -> list[RedirectCandidate]:
    """
    수집된 전체 파라미터 중 리다이렉트/포워드 후보만 골라 태깅한다.

    Args:
        params: 1-3 collector.collect_params()가 수집한 CollectedParam 전체 목록

    Returns:
        List[RedirectCandidate] — 후보로 선정된 파라미터만 (SAFE 필터링 완료 상태)
    """
    candidates: list[RedirectCandidate] = []

    for p in params:
        # dot-notation(JSON 중첩) 파라미터는 마지막 세그먼트만 이름 판단에 사용
        # (예: "data.redirectUrl" → "redirectUrl")
        leaf_name = p.param_name.rsplit(".", 1)[-1]

        if _REDIRECT_NAME_PATTERN.search(leaf_name) or _REDIRECT_CAMEL_PATTERN.search(leaf_name):
            candidates.append(RedirectCandidate(
                collected=p,
                reason=f"파라미터명 '{p.param_name}'이 리다이렉트/포워드 이름 규칙에 매칭",
            ))
            continue

        # 이름 신호가 약하더라도(예: go, page) 값 자체가 URL/경로 형태이면 보조로 포함
        if _WEAK_NAME_HINT_PATTERN.search(leaf_name) and _URL_LIKE_VALUE_PATTERN.match(p.param_value or ""):
            candidates.append(RedirectCandidate(
                collected=p,
                reason=(
                    f"파라미터명 '{p.param_name}'에 약한 네비게이션 신호가 있고, "
                    f"값이 URL/경로 형태({p.param_value!r})"
                ),
            ))

    logger.info(
        f"[1-5][Phase 2] 리다이렉트/포워드 후보 파라미터: {len(candidates)}개 "
        f"(전체 수집 {len(params)}개 중)"
    )
    return candidates
