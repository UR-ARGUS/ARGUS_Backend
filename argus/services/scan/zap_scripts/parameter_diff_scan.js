/*
 * Argus 커스텀 액티브 스캔 스크립트 - 파라미터 값 및 히든(hidden) 필드 조작 가능성 진단
 * (SK Shieldus Web/API 개발보안 Guideline v3.0.0 - 1-3 항목 대응)
 *
 * param_injection_diagnosis.md 명세서의 시그니처 분류(FINANCIAL/AUTHORIZATION/IDOR/LOGIC_FLOW)와
 * 카테고리별 페이로드를 이 스크립트로 흡수했다. 원래 명세는 별도 Python 프로세스(zap_crawler ->
 * signature_classifier -> injector -> analyzer)로 크롤링/인젝션/판단을 전부 독립적으로 수행하는
 * 구조였지만, 그렇게 하면 ZAP이 이미 갖고 있는 인증 세션(Context/Forced User/Replacer 헤더)과
 * 크롤링 스레드풀을 하나도 재사용하지 못해 로그인 필요한 페이지에서 무력화된다. 대신 실제 요청
 * 전송/인증/크롤링은 ZAP 액티브 스캔 엔진에 맡기고(as.sendAndReceive가 세션을 물려받는 검증된
 * 경로), 카테고리 분류/페이로드 "데이터"만 argus/services/scan/param_injection/payloads/*.yaml에서
 * 읽어온다 - Python(signature_classifier.py)과 이 스크립트가 같은 YAML 파일을 공유하는 단일
 * 소스다. analyzer.py(Claude API 판단)는 흡수하지 않았다 - 아래 evaluateDiff의 규칙 기반
 * 신호(+ silent success 폴백)가 그 역할을 대체한다.
 *
 * 카테고리:
 *   FINANCIAL      결제/금액 파라미터를 0 또는 마이너스로 변조해도 서버가 그대로 수용하는지
 *   AUTHORIZATION  권한/역할 파라미터를 admin류 값으로 변조해도 거부되지 않는지
 *   IDOR           서버 발급 인증키가 아닌 유추 가능한 값(ID/MDN 등)에 조회 권한을 의존하는지
 *   LOGIC_FLOW     주문/결제 상태값을 완료/승인 등으로 직접 변조해도 서버가 그대로 수용하는지
 * 히든 필드는 별도 취급하지 않는다 - ZAP의 폼 파라미터 변조(Variant)는 <input type="hidden">도
 * 다른 필드와 동일하게 scan()에 파라미터로 전달하므로, 아래 파라미터명 패턴 분류가 화면 노출
 * 여부와 무관하게 그대로 적용된다.
 *
 * LLM 판단 없이 파라미터명 패턴 + 응답 비교로 후보를 걸러내는 1차 필터다. 여기서 나온 알림은
 * 실제 취약점이 아니라 "의심 후보"이며, 실제 비즈니스 영향(예: 가격이 실제로 깎였는지)은
 * 별도 검증(수동/AI/Selenium replay)이 필요하다.
 *
 * 주의(중요): 실제 금액 조작/권한 상승은 대부분 "정상적인 성공 응답(2xx)"으로 조용히 처리된다.
 * status flip/서버 에러/길이 급변/반사 같은 구조적 신호는 전부 "명확하게 달라진 경우"만 잡기 때문에,
 * 변조가 조용히 받아들여진 성공 케이스(가장 위험한 케이스)는 구조적 신호만으로는 놓칠 수 있다.
 * 이를 보완하기 위해 4개 카테고리에 해당하는 "민감" 후보에 대해서는, 구조적 신호가 하나도
 * 없어도 서버가 명시적으로 거부하지 않았다면 "수동 확인이 필요한 후보"로 낮은 confidence의
 * 별도 알림을 추가로 남긴다(evaluateDiff의 silent 플래그). 이 신호는 실제 취약점 여부를 판단하지
 * 않고 "자동으로는 판단할 수 없으니 사람이 응답 내용을 직접 대조하라"는 의미다.
 */

// param_injection_diagnosis.md의 injector.py가 diff에 함께 담아 Claude에 넘기던 키워드 목록.
// Claude 판단이 빠진 지금은 알림에 참고 정보로만 덧붙인다(그 자체로 신호를 발생시키지 않음).
var RESPONSE_KEYWORDS = [
    "error", "exception", "unauthorized", "forbidden", "denied",
    "admin", "success", "granted", "invalid", "stack trace", "traceback"
];

function findKeywords(body) {
    var lower = body.toLowerCase();
    var found = [];
    for (var i = 0; i < RESPONSE_KEYWORDS.length; i++) {
        if (lower.indexOf(RESPONSE_KEYWORDS[i]) >= 0) {
            found.push(RESPONSE_KEYWORDS[i]);
        }
    }
    return found;
}

// YAML 로딩(SnakeYAML)이 실패했을 때만 쓰는 비상 폴백 패턴. payloads/*.yaml의
// field_name_patterns와 같은 내용을 담고 있다 - YAML을 못 읽는 극단적인 경우에도
// 최소한의 탐지력은 유지하기 위한 것이라, 카테고리 패턴을 바꿀 땐 YAML을 우선 고치고
// 이 폴백은 웬만하면 건드리지 않는다.
var FALLBACK_PATTERNS = {
    FINANCIAL: /price|amount|cost|total|fee|point|balance|pay|money|qty|quantity|discount|charge/i,
    AUTHORIZATION: /role|admin|perm|level|^is_|_flag$/i,
    IDOR: /(^|_)(id|uid|no)$|user|account|mdn|phone|tel|hp(_|$)/i,
    LOGIC_FLOW: /status|state|type|flag|step|phase|stage|mode/i
};

// zap.py의 _load_custom_diff_script()가 스크립트를 로드하기 직전에 이 플레이스홀더를
// param_injection/payloads의 실제 절대경로로 치환해 넣는다. 치환이 안 된 채로 로드되면
// (수동 로드 등) 아래 로더가 이를 감지하고 폴백 패턴만 사용한다.
var PAYLOAD_DIR = "__ARGUS_PAYLOAD_DIR__";
var CATEGORY_FILES = ["FINANCIAL", "AUTHORIZATION", "IDOR", "LOGIC_FLOW"];

// 문자열을 두 조각으로 나눠서 이어붙인다 - 치환되지 않았을 때만 PAYLOAD_DIR과 정확히 일치하는
// "미치환 마커"를 만들기 위함이다. 아래처럼 나눠쓰지 않으면 zap.py의 문자열 치환(str.replace)이
// 이 리터럴도 함께 바꿔버려서, 치환이 정상적으로 끝난 뒤에도 "미치환됨"으로 오판하게 된다
// (실제로 겪은 버그: PAYLOAD_DIR.indexOf(플레이스홀더 리터럴) 체크가 치환 후 그대로 참이 되어
// CATEGORY_CONFIG가 항상 null로 떨어졌었다).
var _UNRENDERED_MARKER = "__ARGUS_" + "PAYLOAD_DIR__";

// payloads/*.yaml을 SnakeYAML(ZAP이 Automation Framework용으로 이미 번들하는 Java 라이브러리)로
// 읽어서 {category: {pattern: RegExp, payloads: string[]}} 형태로 반환한다.
// 실패(경로 미치환, SnakeYAML 부재, 파싱 오류 등) 시 null을 반환하고 buildCandidates는
// FALLBACK_PATTERNS + 하드코딩된 페이로드로 계속 동작한다 - 절대 스캔 자체가 죽지 않게 한다.
var CATEGORY_CONFIG = (function loadCategoryConfig() {
    if (PAYLOAD_DIR === _UNRENDERED_MARKER) {
        return null;
    }
    try {
        var Yaml = Java.type("org.yaml.snakeyaml.Yaml");
        var Paths = Java.type("java.nio.file.Paths");
        var Files = Java.type("java.nio.file.Files");
        var JString = Java.type("java.lang.String");
        var yamlParser = new Yaml();
        var config = {};

        for (var i = 0; i < CATEGORY_FILES.length; i++) {
            var category = CATEGORY_FILES[i];
            var filePath = Paths.get(PAYLOAD_DIR, category + ".yaml");
            var bytes = Files.readAllBytes(filePath);
            var content = new JString(bytes, "UTF-8");
            var data = yamlParser.load(content);

            var patterns = [];
            var rawPatterns = data.get("field_name_patterns");
            if (rawPatterns) {
                var patternIt = rawPatterns.iterator();
                while (patternIt.hasNext()) {
                    patterns.push(String(patternIt.next()));
                }
            }

            var payloads = [];
            var rawPayloads = data.get("payloads");
            if (rawPayloads) {
                var payloadIt = rawPayloads.iterator();
                while (payloadIt.hasNext()) {
                    payloads.push(String(payloadIt.next()));
                }
            }

            config[category] = {
                pattern: patterns.length > 0 ? new RegExp("(" + patterns.join("|") + ")", "i") : null,
                payloads: payloads
            };
        }

        return config;
    } catch (e) {
        return null;
    }
})();

function paramMatchesCategory(category, param) {
    if (CATEGORY_CONFIG && CATEGORY_CONFIG[category] && CATEGORY_CONFIG[category].pattern) {
        return CATEGORY_CONFIG[category].pattern.test(param);
    }
    return FALLBACK_PATTERNS[category].test(param);
}

function formatNumber(n) {
    return (n === Math.trunc(n)) ? String(Math.trunc(n)) : String(n);
}

// payloads/*.yaml에 등장하는 동적 템플릿 토큰을 실행 시점의 원본 값 기준으로 계산한다.
// 새 토큰을 추가하면 param_injection/injector.py의 _TEMPLATE_RESOLVERS도 함께 추가해야 한다.
// 원본 값이 숫자가 아니면 이 토큰은 적용할 수 없어 null을 반환한다(호출측에서 스킵).
function resolvePayloadTemplate(payload, originalValue) {
    if (payload !== "{original_value - 1}" && payload !== "{original_value + 1}" && payload !== "{original_value * -1}") {
        return payload;
    }
    var numeric = /^-?\d+(\.\d+)?$/.test(originalValue);
    if (!numeric) {
        return null;
    }
    var n = parseFloat(originalValue);
    if (payload === "{original_value - 1}") return formatNumber(n - 1);
    if (payload === "{original_value + 1}") return formatNumber(n + 1);
    return formatNumber(n * -1);
}

function buildCandidates(param, value) {
    var candidates = [];
    var indexByValue = {};

    // sensitive=true인 후보는 카테고리 판단 목적으로 넣은 값(=값 자체에 의미가 있음).
    // sensitive=false인 후보는 타입/범위 검증 여부만 보는 범용 프로브(필드 의미와 무관).
    // 같은 값이 양쪽에서 다 만들어지면(중복) 기존 항목을 sensitive로 승격시키고 요청은 한 번만 보낸다.
    function add(v, sensitive, reason, kind) {
        var s = String(v);
        if (s.length === 0 || s === value) {
            return;
        }
        if (indexByValue.hasOwnProperty(s)) {
            var existing = candidates[indexByValue[s]];
            if (sensitive && !existing.sensitive) {
                existing.sensitive = true;
                existing.reason = reason || existing.reason;
                existing.kind = kind || existing.kind;
            }
            return;
        }
        indexByValue[s] = candidates.length;
        candidates.push({ value: s, sensitive: !!sensitive, reason: reason || null, kind: kind || null });
    }

    var numeric = /^-?\d+(\.\d+)?$/.test(value);
    var n = numeric ? parseFloat(value) : null;

    if (CATEGORY_CONFIG) {
        // payloads/*.yaml(SnakeYAML로 로드) 기반 - 이게 canonical 경로다.
        for (var category in CATEGORY_CONFIG) {
            if (!CATEGORY_CONFIG.hasOwnProperty(category)) continue;
            var conf = CATEGORY_CONFIG[category];
            if (!conf.pattern || !conf.pattern.test(param)) continue;

            for (var p = 0; p < conf.payloads.length; p++) {
                var rawPayload = conf.payloads[p];
                var resolved = resolvePayloadTemplate(rawPayload, value);
                if (resolved === null) continue;
                add(resolved, true,
                    "YAML 설정 페이로드('" + rawPayload + "' -> '" + resolved + "')로 변조했지만 서버가 거부하지 않음 (" + category + ")",
                    category);
            }
        }
    } else {
        // SnakeYAML 로딩 실패 시의 비상 폴백 - FALLBACK_PATTERNS + 하드코딩된 페이로드.
        // (YAML을 우선 고치고, 이 블록은 "YAML 자체를 못 읽는 상황"에서만 의미가 있다.)
        var isAmountLike = paramMatchesCategory("FINANCIAL", param);
        var isRoleLike = paramMatchesCategory("AUTHORIZATION", param);
        var isIdLike = paramMatchesCategory("IDOR", param);
        var isLogicFlowLike = paramMatchesCategory("LOGIC_FLOW", param);

        if (isAmountLike && numeric) {
            add(0, true, "금액을 0으로 변조했지만 서버가 거부하지 않음 (FINANCIAL - 금액 조작 의심)", "FINANCIAL");
            if (n > 0) {
                add(-n, true, "플러스(+) 금액을 마이너스(-) 금액으로 변조했지만 서버가 거부하지 않음 (FINANCIAL - 금액 조작 의심)", "FINANCIAL");
            }
        }

        if (isRoleLike) {
            add("admin", true, "권한 상승 시도값(admin)으로 변조했지만 서버가 거부하지 않음 (AUTHORIZATION)", "AUTHORIZATION");
            add("true", true, "권한 상승 시도값(true)으로 변조했지만 서버가 거부하지 않음 (AUTHORIZATION)", "AUTHORIZATION");
            add("1", true, "권한 상승 시도값(1)으로 변조했지만 서버가 거부하지 않음 (AUTHORIZATION)", "AUTHORIZATION");
            add("superuser", true, "권한 상승 시도값(superuser)으로 변조했지만 서버가 거부하지 않음 (AUTHORIZATION)", "AUTHORIZATION");
        }

        if (isIdLike) {
            if (numeric) {
                add(n - 1, true, "인접 ID/MDN 값으로 치환했지만 서버가 거부하지 않음 (IDOR 의심)", "IDOR");
                add(n + 1, true, "인접 ID/MDN 값으로 치환했지만 서버가 거부하지 않음 (IDOR 의심)", "IDOR");
            } else {
                add("1", true, "다른 사용자로 추정되는 값으로 치환했지만 서버가 거부하지 않음 (IDOR 의심)", "IDOR");
                add("0", true, "다른 사용자로 추정되는 값으로 치환했지만 서버가 거부하지 않음 (IDOR 의심)", "IDOR");
            }
        }

        if (isLogicFlowLike) {
            add("COMPLETED", true, "상태값을 COMPLETED로 변조했지만 서버가 거부하지 않음 (LOGIC_FLOW - 절차 우회 의심)", "LOGIC_FLOW");
            add("APPROVED", true, "상태값을 APPROVED로 변조했지만 서버가 거부하지 않음 (LOGIC_FLOW - 절차 우회 의심)", "LOGIC_FLOW");
            add("PAID", true, "상태값을 PAID로 변조했지만 서버가 거부하지 않음 (LOGIC_FLOW - 절차 우회 의심)", "LOGIC_FLOW");
            add("CONFIRMED", true, "상태값을 CONFIRMED로 변조했지만 서버가 거부하지 않음 (LOGIC_FLOW - 절차 우회 의심)", "LOGIC_FLOW");
            add("ACTIVE", true, "상태값을 ACTIVE로 변조했지만 서버가 거부하지 않음 (LOGIC_FLOW - 절차 우회 의심)", "LOGIC_FLOW");
        }
    }

    // 불리언 플립 (카테고리 판단과 무관하게 항상 시도하되, AUTHORIZATION 파라미터면 민감으로 표시)
    if (value === "true" || value === "false") {
        var roleLikeForBool = paramMatchesCategory("AUTHORIZATION", param);
        add(value === "true" ? "false" : "true", roleLikeForBool, "불리언 값을 반전했지만 서버가 거부하지 않음", roleLikeForBool ? "AUTHORIZATION" : null);
    }

    // 타입 혼동 / 범위 확인 (일반 프로브 - 검증 미흡 여부만 확인, 필드 의미와 무관)
    add(value + "[]", false);
    add("null", false);
    if (numeric) {
        add(0, false);
        add(-1, false);
        add(n - 1, false);
        add(n + 1, false);
        add(999999999, false);
    }

    return candidates;
}

function evaluateDiff(baseStatus, baseBody, candMsg, candidateValue, candidate) {
    var status = candMsg.getResponseHeader().getStatusCode();
    var body = candMsg.getResponseBody().toString();
    var baseLen = baseBody.length;
    var len = body.length;
    var signals = [];

    // 인증/인가 실패 -> 성공으로 반전 (권한 우회 의심, 가장 위험도 높음)
    var wasDenied = (baseStatus === 401 || baseStatus === 403);
    var nowAllowed = (status === 200 || status === 201 || status === 302);
    if (wasDenied && nowAllowed) {
        signals.push({
            risk: 3, confidence: 2,
            reason: "인증/인가 실패 응답(" + baseStatus + ")이 파라미터 변조 후 성공 응답(" + status + ")으로 바뀜"
        });
    }

    // 정상 -> 서버 오류 반전 (입력 검증 미흡 의심)
    var wasOk = (baseStatus >= 200 && baseStatus < 300);
    var nowOk = (status >= 200 && status < 300) || status === 302;
    var nowError = (status >= 500);
    if (wasOk && nowError) {
        signals.push({
            risk: 2, confidence: 2,
            reason: "정상 응답이 변조 후 서버 오류(" + status + ")로 바뀜 - 입력 검증 미흡 가능성"
        });
    }

    // 결제/주문 금액 파라미터를 0 또는 마이너스로 변조했는데도 서버가 정상 응답을 유지하고
    // 변조값을 그대로 반영 (FINANCIAL - 금액 조작 성공 의심, 가장 위험도 높음)
    if (wasOk && nowOk && candidate && candidate.kind === "FINANCIAL") {
        var amountReflected = candidateValue.length > 0 && body.indexOf(candidateValue) >= 0;
        if (amountReflected) {
            signals.push({
                risk: 3, confidence: 2,
                reason: "금액 관련 파라미터를 '" + candidateValue + "'로 변조했으나 서버가 정상 응답(" + status + ")으로 그대로 수용하고 변조값이 응답에 반영됨 (FINANCIAL - 금액 조작 의심)"
            });
        }
    }

    // 식별자(ID/MDN 등) 파라미터만 바꿨는데 상태코드는 baseline과 동일하고 응답 길이도 비슷한데
    // 본문 내용은 달라짐 - 같은 200이지만 다른 사람의 데이터가 조회되는 정석적 IDOR 패턴
    // (IDOR - 인증키 대신 유추 가능한 값에 조회 권한을 의존하는 경우)
    if (wasOk && status === baseStatus && candidate && candidate.kind === "IDOR" && body !== baseBody) {
        var idLenDelta = baseLen > 0 ? Math.abs(len - baseLen) / baseLen : 1;
        if (idLenDelta < 0.5) {
            signals.push({
                risk: 3, confidence: 1,
                reason: "식별자(ID/MDN 등) 파라미터만 변경했는데도 동일 상태코드(" + status + ")로 응답 본문 내용이 달라짐 - 서버 발급 인증키가 아닌 유추 가능한 값에 조회 권한을 의존할 가능성 (IDOR - 개인정보 열람 의심)"
            });
        }
    }

    // 응답 길이 급변 (20% 이상)
    if (baseLen > 0) {
        var delta = Math.abs(len - baseLen) / baseLen;
        if (delta >= 0.2) {
            signals.push({
                risk: 1, confidence: 1,
                reason: "응답 길이가 " + Math.round(delta * 100) + "% 변화함 (base=" + baseLen + ", now=" + len + ")"
            });
        }
    }

    // 변조값이 그대로 응답에 반사되면서 응답 자체도 달라짐
    if (candidateValue.length > 0 && body.indexOf(candidateValue) >= 0 && baseLen !== len) {
        signals.push({
            risk: 1, confidence: 1,
            reason: "변조한 값(" + candidateValue + ")이 응답에 그대로 반영됨"
        });
    }

    // 조용한 성공(silent success) - 위의 구조적 신호가 하나도 안 걸렸어도,
    // 이 후보가 FINANCIAL/AUTHORIZATION/IDOR/LOGIC_FLOW 중 하나를 노린 "민감" 값이고 서버가
    // 명시적으로 거부(4xx)하거나 에러를 낸 게 아니라면(=응답 구조는 baseline과 비슷하지만 조작이
    // 그냥 받아들여진 상태) 자동으로는 실제 금액/권한/상태가 바뀌었는지 판단할 수 없으므로
    // 수동 확인 후보로 별도 보고한다. LOGIC_FLOW(상태값 변조)는 대부분 이 경로로만 잡힌다.
    if (signals.length === 0 && candidate && candidate.sensitive) {
        var explicitlyRejected = (status === 400 || status === 401 || status === 403 || status === 404 || status === 422 || status >= 500);
        var stillSuccessLike = (status >= 200 && status < 400);
        if (!explicitlyRejected && stillSuccessLike) {
            signals.push({
                risk: 1, confidence: 1,
                reason: (candidate.reason || "FINANCIAL/AUTHORIZATION/IDOR/LOGIC_FLOW 관련 값 변조") + " (status=" + status + ", 응답 구조는 baseline과 유사)",
                category: candidate.kind,
                silent: true
            });
        }
    }

    return signals;
}

function scan(as, msg, param, value) {
    if (value === null || value === undefined || String(value).length === 0) {
        // 원본 값이 없으면 비교 기준(baseline)을 만들 수 없어 스킵
        return;
    }

    // scan()으로 전달되는 msg는 응답이 채워져 있지 않을 수 있어(ZAP 버전에 따라 다름),
    // 직접 원본 값 그대로 한 번 더 보내서 신뢰할 수 있는 baseline 응답을 확보한다.
    var baseMsg = msg.cloneRequest();
    try {
        as.sendAndReceive(baseMsg, false, false);
    } catch (e) {
        return; // baseline을 얻지 못하면 비교 자체가 불가능하므로 스킵
    }
    var baseStatus = baseMsg.getResponseHeader().getStatusCode();
    var baseBody = baseMsg.getResponseBody().toString();

    var candidates = buildCandidates(param, String(value));
    // 민감(FINANCIAL/AUTHORIZATION/IDOR/LOGIC_FLOW) 후보를 buildCandidates에서 앞쪽에 배치했으므로,
    // 캡에 걸려도 그 값들이 먼저 소진되도록 보장된다. LOGIC_FLOW 후보(최대 5개)가 추가되면서
    // 한 파라미터가 여러 카테고리에 동시에 매칭될 가능성까지 감안해 12로 늘렸다
    // (그래도 파라미터당 요청 폭주는 방지해야 하므로 무제한으로 늘리지는 않음).
    var maxCandidates = 12;

    for (var i = 0; i < candidates.length && i < maxCandidates; i++) {
        if (as.isStop()) {
            return;
        }

        var candidate = candidates[i];
        var candidateValue = candidate.value;
        var testMsg = msg.cloneRequest();
        as.setParam(testMsg, param, candidateValue);

        try {
            as.sendAndReceive(testMsg, false, false);
        } catch (e) {
            continue;
        }

        var signals = evaluateDiff(baseStatus, baseBody, testMsg, candidateValue, candidate);
        if (signals.length > 0) {
            var responseBody = testMsg.getResponseBody().toString();
            var keywords = findKeywords(responseBody);
            var keywordNote = keywords.length > 0 ? (" 응답에서 발견된 키워드: [" + keywords.join(", ") + "].") : "";

            for (var j = 0; j < signals.length; j++) {
                var sig = signals[j];
                var category = sig.category || (candidate && candidate.kind) || "GENERIC";
                var description = sig.silent
                    ? ("[" + category + "] 파라미터 '" + param + "'의 값을 '" + value + "' -> '" + candidateValue + "'로 변조: " + sig.reason +
                       ". 상태코드/응답길이/반사값 같은 구조적 신호는 없었지만, 이 파라미터는 금액/권한/ID/상태값 성격을 가진 것으로 " +
                       "보이고 변조된 값이 명시적으로 거부되지 않았습니다. 조작이 조용히 받아들여졌을 가능성이 있으므로, " +
                       "실제로 결제금액이 바뀌었는지/권한이 상승했는지/다른 사용자의 데이터가 노출됐는지/절차가 우회됐는지는 " +
                       "응답 내용을 직접 비교해 수동으로 확인하세요." + keywordNote)
                    : ("[" + category + "] 파라미터 '" + param + "'의 값을 '" + value + "' -> '" + candidateValue +
                       "'로 변조했을 때 응답이 구조적으로 달라짐: " + sig.reason +
                       ". 서버가 이 파라미터 값을 충분히 검증하지 않거나 접근 제어를 파라미터 값에만 의존할 가능성을 시사합니다. " +
                       "단, 실제 비즈니스 영향(예: 실제로 가격/권한이 바뀌었는지)은 별도 확인이 필요합니다." + keywordNote);

                as.raiseAlert(
                    sig.risk,
                    sig.confidence,
                    (sig.silent ? "Argus Parameter Tampering (Silent Success - Manual Review Needed) - " : "Argus Parameter Tampering - ") + category,
                    description,
                    testMsg.getRequestHeader().getURI().toString(),
                    param,
                    candidateValue,
                    "baseStatus=" + baseStatus + ", baseLen=" + baseBody.length + ", sk_shieldus_item=1-3",
                    "서버 측에서 파라미터/히든 필드 값의 타입/범위/권한/소유권을 재검증하세요. 결제금액 등 중요 정보는 " +
                    "클라이언트가 전송한 값(파라미터·히든 필드)을 신뢰하지 말고 서버 측 DB 값을 기준으로 재계산하고, " +
                    "인증에는 서버가 발급한 토큰만 사용하며 ID 등 유추 가능한 값을 인증 수단으로 쓰지 마세요.",
                    sig.reason,
                    20,
                    20,
                    testMsg
                );
            }
        }
    }
}

function scanNode(as, msg) {
    // 파라미터 단위(scan)만 사용하므로 노드 단위 로직은 사용하지 않음
}

function appliesToHistoryType(historyType) {
    return true;
}
