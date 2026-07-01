import os
import time
import logging
import requests
from urllib.parse import urlparse
from zapv2 import ZAPv2

logger = logging.getLogger("argus.zap_scanner")

# LLM 판단 없이 구조적 응답 diff만으로 파라미터 조작 후보를 탐지하는 커스텀 액티브 스캔 스크립트.
# 40008(내장 Parameter Tampering)은 파라미터가 있어야, 그리고 에러 시그니처가 노출돼야 히트하는
# 좁은 휴리스틱이라 히트율이 낮다 — 이 스크립트를 같은 정책에 함께 태워 상태코드/응답길이/반사값
# 변화 같은 더 넓은 신호를 1차로 걸러낸다.
_CUSTOM_SCRIPT_NAME = "ArgusParamDiff"
_CUSTOM_SCRIPT_ENGINE = "ECMAScript : Graal.js"
# 소스에 커밋되는 템플릿 - "__ARGUS_PAYLOAD_DIR__" 플레이스홀더를 담고 있다.
_CUSTOM_SCRIPT_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "zap_scripts", "parameter_diff_scan.js")
# 위 템플릿의 플레이스홀더를 실제 payloads 절대경로로 치환한 실행용 사본 - .gitignore 대상,
# 매 스캔마다 _load_custom_diff_script()가 다시 생성하므로 머신별 경로가 커밋되지 않는다.
_CUSTOM_SCRIPT_RENDERED_PATH = os.path.join(os.path.dirname(__file__), "zap_scripts", "parameter_diff_scan.generated.js")
_PAYLOAD_DIR = os.path.join(os.path.dirname(__file__), "param_injection", "payloads")
_PAYLOAD_DIR_PLACEHOLDER = "__ARGUS_PAYLOAD_DIR__"

_TAMPERING_SCANNER_ID = "40008"
# ZAP은 활성화된 모든 "active" 타입 스크립트를 이 고정 ID의 번들 플러그인으로 묶어서 실행한다.
# 스크립트를 load/enable해도 이 플러그인 자체가 정책에서 꺼져 있으면 스크립트는 절대 호출되지 않는다.
_SCRIPT_RULES_SCANNER_ID = "50000"

# REST API 백엔드가 OpenAPI/Swagger 스펙을 흔히 노출하는 경로들.
# 대표 URL 하나만으로도 실제 엔드포인트/파라미터를 범용적으로 알아내기 위해,
# 크롤링(Spider) 전에 이 경로들을 먼저 시도해 스펙을 찾으면 통째로 import한다.
_OPENAPI_SPEC_PATHS = [
    "/v3/api-docs",
    "/v2/api-docs",
    "/openapi.json",
    "/swagger.json",
    "/swagger/v1/swagger.json",
]

class ZapScanner:
    """
    OWASP ZAP을 사용한 동적 취약점 진단(DAST) 서비스 클래스.
    특히 '파라미터 값 및 히든(hidden) 필드 조작 가능성' 진단을 지원하며,
    프론트엔드로부터 받은 로그인 정보를 기반으로 인증(Form-based/Script-based)을 수행한 후 스캔을 진행합니다.
    """
    def __init__(self, zap_api_url: str = "http://127.0.0.1:8090", api_key: str = None):
        self.zap = ZAPv2(proxies={"http": zap_api_url, "https": zap_api_url}, apikey=api_key)
        self.policy_name = "ParameterTamperingPolicy"

    def try_import_openapi_spec(self, target_url: str) -> bool:
        """
        대표 URL의 origin(scheme+host+port)에서 흔히 쓰이는 OpenAPI/Swagger 스펙 경로를
        순서대로 시도해, 발견되면 ZAP에 통째로 import한다.
        REST API는 크롤링으로 발견할 링크/폼이 없어 Spider/AJAX Spider가 무력하므로,
        스펙만 있으면 대표 URL 하나로도 모든 엔드포인트/파라미터를 범용적으로 알아낼 수 있다.
        성공 시 True, 스펙을 찾지 못하면 False (호출자는 기존 크롤링 방식으로 계속 진행).
        """
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in _OPENAPI_SPEC_PATHS:
            spec_url = origin + path

            # ZAP의 import 액션 응답/사이트 트리 부작용만으로는 성공 여부를 신뢰할 수 없었다
            # (인증 실패 JSON 등 진짜 스펙이 아닌 응답도 "0개짜리 스펙"으로 조용히 처리되는 경우가 있어
            #  오탐이 발생함을 직접 확인함). 그래서 import를 시도하기 전에 직접 fetch해서
            # 실제 OpenAPI/Swagger 문서인지(최소한 paths가 있는지) 먼저 검증한다.
            try:
                resp = requests.get(spec_url, timeout=5)
                spec = resp.json()
            except Exception:
                continue

            if not isinstance(spec, dict) or not spec.get("paths") or not ({"openapi", "swagger"} & spec.keys()):
                continue

            try:
                self.zap.openapi.import_url(spec_url)
            except Exception as e:
                logger.warning(f"유효한 OpenAPI 스펙이지만 ZAP import 실패 ({spec_url}): {e}")
                continue

            logger.info(f"OpenAPI 스펙 발견 및 import 완료: {spec_url} (경로 {len(spec['paths'])}개)")
            return True

        logger.info("OpenAPI 스펙을 찾지 못함 — 일반 Spider/AJAX Spider로 진행합니다.")
        return False

    def setup_replacer_header(self, raw_header: str = None):
        """
        ZAP Replacer Rule을 활용하여, 스캔 중 전송되는 모든 HTTP 요청 헤더에
        사용자 정의 헤더나 쿠키(Session ID)를 강제로 주입합니다.

        Replacer 규칙은 특정 스캔이 아니라 ZAP 인스턴스 전체에 전역으로 남기 때문에,
        이번 스캔에 raw_header가 없더라도(None/빈 문자열) 반드시 호출해서 이전 스캔이
        남긴 규칙을 먼저 지워야 한다. 그렇지 않으면 예전 스캔에서 쓴 인증 토큰/쿠키가
        커스텀 헤더를 지정하지 않은 이후의 모든 스캔에도 계속 주입된다.

        raw_header 예시: 'Cookie: SESSION_ID=abc123xyz' 또는 'Authorization: Bearer key'
        """
        rule_description = "ArgusCustomAuthHeader"
        try:
            # 이번 스캔에 커스텀 헤더가 있는지 여부와 무관하게, 이전 스캔이 남긴 규칙을 먼저 제거
            try:
                for rule in self.zap.replacer.rules:
                    if rule.get("description") == rule_description:
                        self.zap.replacer.remove_rule(rule_description)
            except Exception:
                pass

            if not raw_header:
                return

            raw_header = raw_header.strip()
            if raw_header.startswith("Bearer "):
                raw_header = f"Authorization: {raw_header}"

            if ":" not in raw_header:
                logger.warning(f"잘못된 헤더 포맷: {raw_header}. 'HeaderName: Value' 형식이어야 합니다.")
                return

            header_name, header_value = raw_header.split(":", 1)
            header_name = header_name.strip()
            header_value = header_value.strip()

            # description, enabled, matchType, matchString, matchRegex, replacement, initiators
            self.zap.replacer.add_rule(
                description=rule_description,
                enabled="true",
                matchtype="REQ_HEADER",
                matchstring=header_name,
                matchregex="false",
                replacement=header_value,
                initiators=""
            )
            logger.info(f"ZAP Replacer 규칙 추가 완료: {header_name} -> {header_value}")
        except Exception as e:
            logger.error(f"ZAP Replacer 규칙 설정 중 오류 발생: {e}")

    def setup_parameter_tampering_policy(self):
        """
        ZAP Active Scan 정책에서 '파라미터 조작(Parameter Tampering)' 관련 스캐너를 설정합니다.
        - Parameter Tampering (Alert ID: 40008)
        """
        try:
            # 기존 정책이 있으면 삭제 후 재 생성하거나 확인
            policies = self.zap.ascan.scan_policy_names
            if self.policy_name in policies:
                logger.info(f"기존 ZAP 스캔 정책({self.policy_name})이 존재합니다.")
            else:
                self.zap.ascan.add_scan_policy(self.policy_name)
                logger.info(f"ZAP 스캔 정책({self.policy_name})을 생성했습니다.")

            # 정책 내 모든 스캐너를 비활성화한 뒤, 파라미터 조작(40008) + 커스텀 스크립트 실행용
            # 번들 플러그인(50000)만 활성화
            # (set_policy_*는 강도/임계값만 조정할 뿐 다른 스캐너를 끄지 않으므로
            #  disable_all_scanners + enable_scanners로 범위를 명시적으로 좁혀야 함)
            self.zap.ascan.disable_all_scanners(scanpolicyname=self.policy_name)
            self.zap.ascan.enable_scanners(
                ids=f"{_TAMPERING_SCANNER_ID},{_SCRIPT_RULES_SCANNER_ID}",
                scanpolicyname=self.policy_name
            )
            self.zap.ascan.set_scanner_attack_strength(
                id=_TAMPERING_SCANNER_ID,
                attackstrength="HIGH",
                scanpolicyname=self.policy_name
            )
            self.zap.ascan.set_scanner_alert_threshold(
                id=_TAMPERING_SCANNER_ID,
                alertthreshold="MEDIUM",
                scanpolicyname=self.policy_name
            )
            logger.info("파라미터 조작 진단(ID: 40008)만 활성화하도록 정책 설정 완료.")
            self._load_custom_diff_script()
        except Exception as e:
            logger.error(f"ZAP 스캔 정책 설정 중 오류 발생: {e}")

    def _render_custom_diff_script(self) -> str:
        """
        parameter_diff_scan.js 템플릿의 "__ARGUS_PAYLOAD_DIR__" 플레이스홀더를 실제
        param_injection/payloads 절대경로로 치환해 실행용 사본(_CUSTOM_SCRIPT_RENDERED_PATH)에
        써넣는다. 스크립트 안에서는 이 경로를 SnakeYAML로 읽어 FINANCIAL/AUTHORIZATION/IDOR/
        LOGIC_FLOW 카테고리 패턴+페이로드를 가져온다(단일 소스: signature_classifier.py와 공유).

        치환에 실패해도(경로 문제 등) 예외를 흡수하고 템플릿 원본 그대로 로드되게 둔다 -
        스크립트 자체의 폴백 로직(FALLBACK_PATTERNS)이 이어서 동작하므로 스캔이 죽지는 않는다.
        """
        try:
            with open(_CUSTOM_SCRIPT_TEMPLATE_PATH, "r", encoding="utf-8") as f:
                template = f.read()

            # JS 문자열 리터럴 안에 안전하게 들어가도록 백슬래시를 슬래시로 정규화한다
            # (Windows 경로의 "\"가 JS 이스케이프 시퀀스로 오인되는 것을 방지).
            safe_path = _PAYLOAD_DIR.replace("\\", "/")
            rendered = template.replace(_PAYLOAD_DIR_PLACEHOLDER, safe_path)

            with open(_CUSTOM_SCRIPT_RENDERED_PATH, "w", encoding="utf-8") as f:
                f.write(rendered)
            return _CUSTOM_SCRIPT_RENDERED_PATH
        except Exception as e:
            logger.warning(f"파라미터 diff 스크립트 렌더링 실패, 템플릿 원본으로 로드합니다: {e}")
            return _CUSTOM_SCRIPT_TEMPLATE_PATH

    def _load_custom_diff_script(self):
        """
        parameter_diff_scan.js(구조적 응답 diff 기반, LLM 미사용)를 ZAP에 로드하고 활성화한다.
        실제 실행은 위에서 이미 켠 50000(Script Active Scan Rules) 번들 플러그인이 담당하므로,
        여기서는 스크립트 자체를 등록/활성화하기만 하면 된다.
        스크립트 애드온 미설치 등으로 실패해도 40008 자체 동작에는 영향 없도록 예외를 흡수한다.
        """
        try:
            existing_names = {s.get("name") for s in self.zap.script.list_scripts}
            if _CUSTOM_SCRIPT_NAME in existing_names:
                self.zap.script.remove(_CUSTOM_SCRIPT_NAME)

            script_path = self._render_custom_diff_script()

            self.zap.script.load(
                scriptname=_CUSTOM_SCRIPT_NAME,
                scripttype="active",
                scriptengine=_CUSTOM_SCRIPT_ENGINE,
                filename=script_path,
                scriptdescription="Argus 파라미터/히든 필드 조작(diff 기반) 탐지 스크립트 - LLM 미사용"
            )
            self.zap.script.enable(_CUSTOM_SCRIPT_NAME)
            logger.info("커스텀 파라미터 diff 스크립트 로드 및 활성화 완료.")
        except Exception as e:
            logger.error(f"커스텀 diff 스크립트 설정 중 오류 발생 (40008 자체 스캔은 계속 진행됨): {e}")

    def setup_authentication(self, target_url: str, login_config: dict) -> str:
        """
        ZAP 컨텍스트를 생성하고 로그인 양식/인증 세션을 구성합니다.
        """
        try:
            # 1. 컨텍스트 설정
            context_name = f"ArgusContext_{int(time.time())}"
            context_id = self.zap.context.new_context(context_name)
            
            # 컨텍스트에 대상 URL 범위 포함
            self.zap.context.include_in_context(context_name, f"{target_url}.*")
            
            login_url = login_config.get("login_url")
            username_field = login_config.get("username_field", "username")
            password_field = login_config.get("password_field", "password")
            username = login_config.get("username")
            password = login_config.get("password")
            logged_in_indicator = login_config.get("logged_in_indicator", "Sign out|Logout|로그아웃")

            # 2. Form-based Authentication 설정
            login_request_data = f"{username_field}={username}&{password_field}={password}"
            self.zap.authentication.set_authentication_method(
                contextid=context_id,
                authmethodname="formBasedAuthentication",
                authmethodconfigparams=f"loginUrl={login_url}&loginRequestData={login_request_data}"
            )
            
            # 로그인 성공/실패 인디케이터 설정 (Regex 패턴)
            self.zap.authentication.set_logged_in_indicator(context_id, f"(?i){logged_in_indicator}")
            
            # 3. 사용자(User) 추가 및 자격 증명 바인딩
            user_name = "ArgusScannerUser"
            user_id = self.zap.users.new_user(context_id, user_name)
            
            # Form-based 자격 증명 바인딩
            credentials_param = f"username={username}&password={password}"
            self.zap.users.set_authentication_credentials(context_id, user_id, credentials_param)
            self.zap.users.set_user_enabled(context_id, user_id, "true")
            
            # 4. 강제 사용자 모드(Forced User Mode) 활성화
            self.zap.forcedUser.set_forced_user(context_id, user_id)
            self.zap.forcedUser.set_forced_user_mode_enabled("true")
            
            logger.info(f"ZAP 인증 설정 완료: User ID {user_id} (Context: {context_name})")
            return context_id
        except Exception as e:
            logger.error(f"ZAP 인증 설정 중 오류 발생: {e}")
            raise

    def run_scan(self, target_url: str, context_id: str = None, progress_callback=None) -> dict:
        """
        ZAP Active Scan을 수행하고 결과를 반환합니다.
        progress_callback(phase: str, percent: int)이 주어지면 spider/active scan
        진행률이 바뀔 때마다 호출되어, 실제 ZAP 진행 속도를 호출자(Celery task)에 보고할 수 있습니다.
        """
        try:
            # 0. OpenAPI/Swagger 스펙 자동 탐지 — 있으면 대표 URL 하나로 모든 엔드포인트/
            # 파라미터를 범용적으로 확보(REST API는 크롤링으로 발견이 거의 불가능하므로 우선 시도)
            if progress_callback:
                progress_callback("openapi_discovery", 0)
            self.try_import_openapi_spec(target_url)
            if progress_callback:
                progress_callback("openapi_discovery", 100)

            logger.info(f"Target URL 스파이더 시작: {target_url}")

            # 1. Spider 진행
            if context_id:
                users = self.zap.users.users_list(context_id)
                user_id = users[0]["id"] if users else None
                spider_id = self.zap.spider.scan_as_user(context_id, user_id, target_url)
            else:
                spider_id = self.zap.spider.scan(target_url)

            spider_pct = int(self.zap.spider.status(spider_id))
            while spider_pct < 100:
                logger.info(f"Spider 진행률: {spider_pct}%")
                if progress_callback:
                    progress_callback("spider", spider_pct)
                time.sleep(2)
                spider_pct = int(self.zap.spider.status(spider_id))
            if progress_callback:
                progress_callback("spider", 100)
            logger.info("Spider 완료.")

            # 1-1. AJAX Spider — 일반 Spider는 정적 HTML만 파싱하므로 React/Vue 같은 SPA는
            # 클라이언트 JS로 렌더링되는 라우트/파라미터를 거의 발견하지 못한다.
            # AJAX Spider는 실제 헤드리스 브라우저로 페이지를 렌더링/클릭하며 크롤링한다.
            # (firefox-headless가 기본값이지만 이 환경엔 Firefox가 없어 항상 실패하므로
            #  설치되어 있는 chrome-headless로 강제 설정)
            try:
                self.zap.ajaxSpider.set_option_browser_id("chrome-headless")
                self.zap.ajaxSpider.set_option_max_duration(2)  # 분 단위 — 무제한 대기 방지
                logger.info(f"AJAX Spider 시작: {target_url}")
                self.zap.ajaxSpider.scan(url=target_url)
                if progress_callback:
                    progress_callback("ajax_spider", 0)
                while self.zap.ajaxSpider.status == "running":
                    logger.info(f"AJAX Spider 진행 중 — 발견된 리소스: {self.zap.ajaxSpider.number_of_results}건")
                    time.sleep(2)
                if progress_callback:
                    progress_callback("ajax_spider", 100)
                logger.info(f"AJAX Spider 완료 — 발견된 리소스: {self.zap.ajaxSpider.number_of_results}건")
                
                # AJAX Spider 완료 후, 탐색 중 발견된 모든 사이트/포트(예: http://localhost:8080)를 
                # 동적으로 컨텍스트 범위(Scope)에 추가하여 Active Scan에서 진단하도록 처리
                if context_id:
                    try:
                        context_data = self.zap.context.context(context_id)
                        context_name = context_data.get("name") if isinstance(context_data, dict) else f"ArgusContext_{context_id}"
                        
                        for site in self.zap.core.sites:
                            logger.info(f"동적으로 발견된 진단 대상 추가: {site}")
                            self.zap.context.include_in_context(context_name, f"{site}.*")
                    except Exception as ce:
                        logger.warning(f"동적 컨텍스트 스코프 추가 중 오류 발생: {ce}")
            except Exception as e:
                logger.warning(f"AJAX Spider 실행 중 오류 발생 (건너뜀): {e}")

            # 2. Active Scan 진행
            logger.info(f"Active Scan 시작: {target_url}")
            if context_id:
                users = self.zap.users.users_list(context_id)
                user_id = users[0]["id"] if users else None
                scan_id = self.zap.ascan.scan_as_user(
                    url=target_url,
                    contextid=context_id,
                    userid=user_id,
                    recurse="true",
                    scanpolicyname=self.policy_name
                )
            else:
                scan_id = self.zap.ascan.scan(
                    url=target_url,
                    recurse="true",
                    scanpolicyname=self.policy_name
                )

            ascan_pct = int(self.zap.ascan.status(scan_id))
            while ascan_pct < 100:
                logger.info(f"Active Scan 진행률: {ascan_pct}%")
                if progress_callback:
                    progress_callback("ascan", ascan_pct)
                time.sleep(5)
                ascan_pct = int(self.zap.ascan.status(scan_id))
            if progress_callback:
                progress_callback("ascan", 100)
            logger.info("Active Scan 완료.")

            # 3. 결과 수집
            unique_alerts = {}
            for site in self.zap.core.sites:
                try:
                    for alert in self.zap.core.alerts(baseurl=site):
                        # ZAP Alert 고유 식별값(id 또는 messageId)을 기준으로 중복 수집 방지
                        alert_id = alert.get("id") or alert.get("messageId")
                        if alert_id:
                            unique_alerts[alert_id] = alert
                except Exception as ae:
                    logger.warning(f"{site}의 Alert 수집 실패: {ae}")

            alerts = list(unique_alerts.values())
            tampering_alerts = [
                alert for alert in alerts 
                if alert.get("pluginId") == "40008" or "tamper" in alert.get("alert", "").lower()
            ]
            
            return {
                "target_url": target_url,
                "total_alerts": len(alerts),
                "parameter_tampering_alerts": tampering_alerts
            }
        except Exception as e:
            logger.error(f"ZAP 스캔 중 오류 발생: {e}")
            raise
