"""
Selenium 3단계 캡처 모듈 (범용 버전)

특정 사이트가 아닌 임의의 ZAP 스캔 대상을 가정하고 다음을 추가 지원:
  - GET 외 POST/PUT/PATCH 요청 재현 (페이지 네비게이션이 아닌 fetch() 기반)
  - JSON API 응답 캡처 (DOM 하이라이트 대신 응답 본문 텍스트를 화면에 표시해서 캡처)
  - evidence가 비어있는 경우의 폴백 (HTTP status code 기반 트리거 판단 추가)

흐름은 기존과 동일하게 STEP1(공격 전) → STEP2(payload 입력) → STEP3(결과/트리거 감지)을 따르되,
job.method와 job.response_type_hint에 따라 각 단계의 구체적 동작이 분기된다.
"""

import os
import time
import logging
import subprocess
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse
import re

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    UnexpectedAlertPresentException,
    WebDriverException,
)

from capture_job import CaptureJob

logger = logging.getLogger("selenium_capture")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


@dataclass
class CaptureResult:
    """캡처 파이프라인 1건의 최종 산출물."""

    job_id: str
    before_path: Optional[str] = None
    input_path: Optional[str] = None
    result_path: Optional[str] = None
    confirmed: bool = False
    failure_reason: Optional[str] = None
    highlight_box: Optional[dict] = None
    http_status: Optional[int] = None   # body 요청 재현 시 받은 실제 상태 코드 (STEP4 보고서에 표시)


_CSS_RESPONSE_RENDER = (
    "<style>"
    "body{font-family:monospace;background:#1a1a1a;color:#e0e0e0;padding:20px}"
    ".status{font-size:14px;padding:6px 10px;border-radius:4px;display:inline-block;margin-bottom:12px}"
    ".status-ok{background:#1a5c1a}"
    ".status-error{background:#5c1a1a}"
    ".body{white-space:pre-wrap;word-break:break-all;font-size:13px;line-height:1.5}"
    "</style>"
)


class SeleniumCaptureEngine:
    """하나의 WebDriver 인스턴스를 재사용하며 여러 CaptureJob을 순차 처리하는 엔진."""

    def __init__(
        self,
        output_dir: str = "./captures",
        headless: bool = True,
        window_size: tuple = (1440, 900),
        page_load_timeout: int = 15,
        trigger_wait_seconds: float = 2.5,
        auth_cookies: Optional[list] = None,
        auth_headers: Optional[dict] = None,
    ):
        self.output_dir = output_dir
        self.trigger_wait_seconds = trigger_wait_seconds
        self.auth_cookies = auth_cookies or []
        self.auth_headers = auth_headers or {}
        os.makedirs(output_dir, exist_ok=True)

        options = Options()
        if headless:
            options.add_argument("--headless=new")
        options.add_argument(f"--window-size={window_size[0]},{window_size[1]}")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        options.set_capability("unhandledPromptBehavior", "ignore")

        self.driver = webdriver.Chrome(options=options)
        self.driver.set_page_load_timeout(page_load_timeout)

        if self.auth_headers:
            self._inject_auth_headers(self.auth_headers)

    def _inject_auth_headers(self, headers: dict):
        self.driver.execute_cdp_cmd("Network.enable", {})
        self.driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": headers})
        logger.info("CDP를 통해 인증 헤더 주입 완료: %s", list(headers.keys()))

    def _apply_cookies(self, url_domain: str):
        if not self.auth_cookies:
            return
        for cookie in self.auth_cookies:
            try:
                self.driver.add_cookie(cookie)
            except WebDriverException as e:
                logger.warning("쿠키 주입 실패 (%s): %s", cookie.get("name"), e)

    def _safe_get(self, url: str) -> bool:
        try:
            self.driver.get(url)
            return True
        except TimeoutException:
            logger.warning("페이지 로드 타임아웃: %s", url)
            return False
        except UnexpectedAlertPresentException:
            return True
        except WebDriverException as e:
            logger.warning("페이지 로드 실패: %s — %s", url, e)
            return False

    def _fetch_via_js(self, url: str, method: str, body: Optional[dict]) -> dict:
        """
        브라우저 컨텍스트 안에서 fetch()를 실행해 POST/PUT/PATCH 같은
        body 기반 요청을 재현. driver.get()은 GET 네비게이션만 가능하므로,
        non-GET 메서드는 현재 로드된 페이지의 JS 컨텍스트를 통해 요청을 보낸다.

        반환값: {"status": int, "body": str, "ok": bool, "error": str|None}
        """
        script = """
        const callback = arguments[arguments.length - 1];
        const url = arguments[0];
        const method = arguments[1];
        const bodyData = arguments[2];

        fetch(url, {
            method: method,
            headers: {"Content-Type": "application/json"},
            body: bodyData ? JSON.stringify(bodyData) : undefined,
            credentials: "include"
        })
        .then(async (res) => {
            const text = await res.text();
            callback({status: res.status, body: text, ok: res.ok, error: null});
        })
        .catch((err) => {
            callback({status: 0, body: "", ok: false, error: String(err)});
        });
        """
        try:
            self.driver.set_script_timeout(self.driver.timeouts.page_load)
            result = self.driver.execute_async_script(script, url, method, body)
            return result
        except WebDriverException as e:
            logger.warning("fetch() 기반 요청 실패: %s %s — %s", method, url, e)
            return {"status": 0, "body": "", "ok": False, "error": str(e)}

    def _render_response_as_page(self, url: str, method: str, status: int, body_text: str):
        """
        fetch() 응답 결과를 사람이 읽을 수 있는 형태로 화면에 렌더링해서
        스크린샷 대상이 되도록 한다 (JSON API라 원래는 화면에 아무것도 안 보이는 상황 보완).

        document.write()를 사용해 현재 origin을 유지한다.
        data: URL 방식은 null origin 문제로 이후 fetch() CORS 차단과
        특수문자(#, %) URL 파싱 오류를 유발하므로 사용하지 않는다.
        """
        status_class = "status-ok" if 200 <= status < 400 else "status-error"
        truncated_body = body_text[:3000]
        # HTML 특수문자 이스케이프 (f-string 삽입 전에 처리)
        def _esc(s: str) -> str:
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

        html = (
            '<!DOCTYPE html><html><head><meta charset="utf-8">'
            + _CSS_RESPONSE_RENDER
            + '</head><body>'
            + f'<div class="status {status_class}">HTTP {status} — {method} {_esc(url)}</div>'
            + f'<div class="body">{_esc(truncated_body)}</div>'
            + '</body></html>'
        )
        self.driver.execute_script(
            "document.open(); document.write(arguments[0]); document.close();",
            html,
        )

    def _inject_mock_url_bar(self, step: int, url: str, response_type: str = "html", body_text: str = ""):
        script = """
        // Remove existing mock URL/security bar if any
        const existing = document.getElementById('mock-chrome-frame');
        if (existing) { existing.remove(); }

        const frame = document.createElement('div');
        frame.id = 'mock-chrome-frame';
        frame.style.position = 'fixed';
        frame.style.top = '0';
        frame.style.left = '0';
        frame.style.right = '0';
        frame.style.zIndex = '2147483647';
        frame.style.fontFamily = 'Segoe UI, Tahoma, sans-serif';
        frame.style.boxSizing = 'border-box';
        frame.style.backgroundColor = '#ffffff';

        // 1. Tab Bar
        const tabBar = document.createElement('div');
        tabBar.style.height = '36px';
        tabBar.style.backgroundColor = '#dee1e6';
        tabBar.style.display = 'flex';
        tabBar.style.alignItems = 'flex-end';
        tabBar.style.paddingLeft = '8px';

        const tab = document.createElement('div');
        tab.style.height = '28px';
        tab.style.backgroundColor = '#ffffff';
        tab.style.borderTopLeftRadius = '8px';
        tab.style.borderTopRightRadius = '8px';
        tab.style.width = '160px';
        tab.style.display = 'flex';
        tab.style.alignItems = 'center';
        tab.style.padding = '0 10px';
        tab.style.fontSize = '12px';
        tab.style.color = '#3b3b3b';

        const favicon = document.createElement('span');
        favicon.innerText = '⚡ ';
        favicon.style.marginRight = '6px';

        const tabTitle = document.createElement('span');
        tabTitle.innerText = 'ONDE';
        tabTitle.style.flex = '1';
        tabTitle.style.overflow = 'hidden';
        tabTitle.style.whiteSpace = 'nowrap';
        tabTitle.style.textOverflow = 'ellipsis';

        const closeBtn = document.createElement('span');
        closeBtn.innerText = '×';
        closeBtn.style.fontSize = '14px';
        closeBtn.style.color = '#5f6368';
        closeBtn.style.marginLeft = '4px';

        tab.appendChild(favicon);
        tab.appendChild(tabTitle);
        tab.appendChild(closeBtn);
        tabBar.appendChild(tab);

        // Plus button
        const plusBtn = document.createElement('span');
        plusBtn.innerText = '+';
        plusBtn.style.fontSize = '16px';
        plusBtn.style.color = '#5f6368';
        plusBtn.style.marginLeft = '10px';
        plusBtn.style.marginBottom = '6px';
        tabBar.appendChild(plusBtn);

        // 2. Navigation Bar
        const navBar = document.createElement('div');
        navBar.style.height = '40px';
        navBar.style.backgroundColor = '#ffffff';
        navBar.style.borderBottom = '1px solid #dee1e6';
        navBar.style.display = 'flex';
        navBar.style.alignItems = 'center';
        navBar.style.padding = '0 10px';
        navBar.style.gap = '12px';

        // Back / Forward / Reload
        const navBtns = document.createElement('div');
        navBtns.style.display = 'flex';
        navBtns.style.gap = '14px';
        navBtns.style.fontSize = '16px';
        navBtns.style.color = '#5f6368';

        const back = document.createElement('span');
        back.innerHTML = '&#8592;';
        const forward = document.createElement('span');
        forward.innerHTML = '&#8594;';
        forward.style.color = '#babdbe';
        const reload = document.createElement('span');
        reload.innerHTML = '&#8635;';

        navBtns.appendChild(back);
        navBtns.appendChild(forward);
        navBtns.appendChild(reload);

        // Address Bar Input Box
        const addressBox = document.createElement('div');
        addressBox.style.flex = '1';
        addressBox.style.height = '28px';
        addressBox.style.borderRadius = '14px';
        addressBox.style.backgroundColor = (arguments[0] === 2) ? '#ffffff' : '#f1f3f4';
        addressBox.style.border = (arguments[0] === 2) ? '2px solid #1a73e8' : '1px solid #dadce0';
        addressBox.style.display = 'flex';
        addressBox.style.alignItems = 'center';
        addressBox.style.padding = '0 12px';
        addressBox.style.fontSize = '12px';
        addressBox.style.color = '#202124';

        const lock = document.createElement('span');
        lock.innerHTML = '🔒';
        lock.style.fontSize = '10px';
        lock.style.marginRight = '8px';

        const addressText = document.createElement('span');
        addressText.innerText = arguments[1];
        addressText.style.flex = '1';
        addressText.style.overflow = 'hidden';
        addressText.style.whiteSpace = 'nowrap';
        addressText.style.textOverflow = 'ellipsis';

        addressBox.appendChild(lock);
        addressBox.appendChild(addressText);

        navBar.appendChild(navBtns);
        navBar.appendChild(addressBox);

        frame.appendChild(tabBar);
        frame.appendChild(navBar);

        // 3. Dropdown autocomplete (Step 2 only)
        if (arguments[0] === 2) {
            const dropdown = document.createElement('div');
            dropdown.style.position = 'absolute';
            dropdown.style.top = '72px';
            dropdown.style.left = '48px';
            dropdown.style.right = '10px';
            dropdown.style.backgroundColor = '#ffffff';
            dropdown.style.boxShadow = '0 4px 6px rgba(32,33,36,0.28)';
            dropdown.style.borderRadius = '0 0 16px 16px';
            dropdown.style.border = '1px solid #dadce0';
            dropdown.style.borderTop = 'none';
            dropdown.style.padding = '8px 0';
            dropdown.style.zIndex = '2147483648';

            const row1 = document.createElement('div');
            row1.style.padding = '6px 16px';
            row1.style.display = 'flex';
            row1.style.alignItems = 'center';
            row1.style.backgroundColor = '#e8f0fe';
            row1.style.fontSize = '12px';
            row1.style.cursor = 'default';

            const globeIcon = document.createElement('span');
            globeIcon.innerHTML = '🌐 ';
            globeIcon.style.marginRight = '12px';

            const row1Text = document.createElement('span');
            row1Text.innerText = arguments[1];
            row1Text.style.color = '#1967d2';
            row1Text.style.fontWeight = '500';

            row1.appendChild(globeIcon);
            row1.appendChild(row1Text);
            dropdown.appendChild(row1);

            const row2 = document.createElement('div');
            row2.style.padding = '6px 16px';
            row2.style.display = 'flex';
            row2.style.alignItems = 'center';
            row2.style.fontSize = '12px';

            const searchIcon = document.createElement('span');
            searchIcon.innerHTML = '🔍 ';
            searchIcon.style.marginRight = '12px';

            const row2Text = document.createElement('span');
            row2Text.innerText = arguments[1] + ' - Google 검색';
            row2Text.style.color = '#5f6368';

            row2.appendChild(searchIcon);
            row2.appendChild(row2Text);
            dropdown.appendChild(row2);

            frame.appendChild(dropdown);
        }

        document.body.style.paddingTop = '76px';
        document.body.appendChild(frame);

        // 4. Custom JSON Pretty Print Header (Step 3 only)
        if (arguments[0] === 3 && arguments[2] === 'json') {
            const jsonHeader = document.createElement('div');
            jsonHeader.style.padding = '8px 12px';
            jsonHeader.style.backgroundColor = '#f1f1f1';
            jsonHeader.style.borderBottom = '1px solid #dadce0';
            jsonHeader.style.fontSize = '12px';
            jsonHeader.style.color = '#333';
            jsonHeader.style.display = 'flex';
            jsonHeader.style.alignItems = 'center';
            jsonHeader.style.gap = '6px';
            jsonHeader.style.fontFamily = 'monospace';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = false;

            const label = document.createElement('label');
            label.innerText = 'pretty print 적용';

            jsonHeader.appendChild(label);
            jsonHeader.appendChild(checkbox);

            const bodyContent = document.createElement('div');
            bodyContent.style.padding = '20px';
            bodyContent.style.fontFamily = 'monospace';
            bodyContent.style.fontSize = '13px';
            bodyContent.style.whiteSpace = 'pre-wrap';
            bodyContent.style.wordBreak = 'break-all';
            bodyContent.innerText = arguments[3];

            document.body.innerHTML = '';
            document.body.style.backgroundColor = '#ffffff';
            document.body.style.color = '#000000';
            document.body.style.margin = '0';
            document.body.style.paddingTop = '76px';

            document.body.appendChild(frame);
            document.body.appendChild(jsonHeader);
            document.body.appendChild(bodyContent);
        }
        """
        try:
            self.driver.execute_script(script, step, url, response_type, body_text)
            time.sleep(0.1)
        except Exception:
            pass



    def _inject_burp_repeater_ui(self, step: int, job: CaptureJob, status: int = 500, response_body: str = ""):
        # 먼저 mock URL 바를 주입하여 두 화면이 공존할 수 있도록 함
        response_type = "json" if job.response_type_hint == "json" else "html"
        self._inject_mock_url_bar(step, job.target_url, response_type, response_body)

        parsed = urlparse(job.target_url)
        path = parsed.path
        if parsed.query:
            path += f"?{parsed.query}"
        
        req_headers = f"{job.method} {path} HTTP/1.1\n"
        req_headers += f"Host: {parsed.netloc}\n"
        req_headers += "Accept: application/json, text/plain, */*\n"
        req_headers += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\n"
        if self.auth_headers:
            for k, v in self.auth_headers.items():
                req_headers += f"{k}: {v}\n"
        
        req_body = ""
        if job.method in ("POST", "PUT", "PATCH") and job.param and job.attack:
            import json
            req_headers += "Content-Type: application/json\n"
            req_body = json.dumps({job.param: job.attack}, indent=2)
        
        res_headers = f"HTTP/1.1 {status}\n"
        res_headers += "Content-Type: application/json;charset=UTF-8\n"
        res_headers += "Connection: close\n"
        res_headers += "Cache-Control: no-cache, no-store, must-revalidate\n"
        
        script = """
        const existingPanel = document.getElementById('burp-repeater-panel');
        if (existingPanel) { existingPanel.remove(); }

        let pageWrapper = document.getElementById('page-wrapper');
        if (!pageWrapper) {
            pageWrapper = document.createElement('div');
            pageWrapper.id = 'page-wrapper';
            pageWrapper.style.height = '50vh';
            pageWrapper.style.overflow = 'auto';
            pageWrapper.style.position = 'relative';
            pageWrapper.style.boxSizing = 'border-box';
            pageWrapper.style.borderBottom = '4px solid #ff6600';

            const children = Array.from(document.body.children);
            children.forEach(child => {
                if (child.id !== 'mock-chrome-frame' && child.id !== 'page-wrapper') {
                    pageWrapper.appendChild(child);
                }
            });
            document.body.appendChild(pageWrapper);
        }

        // mock-chrome-frame이 fixed 포지션이 아니라 flex 레이아웃에 참여하도록 스타일 조정
        const mockFrame = document.getElementById('mock-chrome-frame');
        if (mockFrame) {
            mockFrame.style.position = 'relative';
            mockFrame.style.top = 'auto';
            mockFrame.style.left = 'auto';
            mockFrame.style.right = 'auto';
            mockFrame.style.width = '100%';
            if (document.body.firstChild !== mockFrame) {
                document.body.insertBefore(mockFrame, document.body.firstChild);
            }
        }

        document.body.style.margin = '0';
        document.body.style.padding = '0';
        document.body.style.paddingTop = '0'; // mock URL 바 때문에 들어갔던 바디 패딩 제거
        document.body.style.height = '100vh';
        document.body.style.display = 'flex';
        document.body.style.flexDirection = 'column';
        document.body.style.overflow = 'hidden';

        pageWrapper.style.flex = '1';

        const panel = document.createElement('div');
        panel.id = 'burp-repeater-panel';
        panel.style.height = '42vh';
        panel.style.backgroundColor = '#151515';
        panel.style.color = '#e0e0e0';
        panel.style.fontFamily = 'Consolas, Monaco, monospace';
        panel.style.fontSize = '11px';
        panel.style.display = 'flex';
        panel.style.flexDirection = 'column';
        panel.style.boxSizing = 'border-box';
        panel.style.zIndex = '2147483640';

        const topMenu = document.createElement('div');
        topMenu.style.height = '24px';
        topMenu.style.backgroundColor = '#2c2c2c';
        topMenu.style.borderBottom = '1px solid #3c3c3c';
        topMenu.style.display = 'flex';
        topMenu.style.alignItems = 'center';
        topMenu.style.padding = '0 10px';
        topMenu.style.gap = '15px';
        topMenu.style.fontWeight = 'bold';
        topMenu.style.color = '#a0a0a0';

        const logo = document.createElement('span');
        logo.innerText = 'Burp Suite Professional';
        logo.style.color = '#ff6600';
        logo.style.marginRight = '20px';
        topMenu.appendChild(logo);

        const tabs = ['Target', 'Proxy', 'Intruder', 'Repeater', 'Collaborator'];
        tabs.forEach(t => {
            const span = document.createElement('span');
            span.innerText = t;
            if (t === 'Repeater') {
                span.style.color = '#ffffff';
                span.style.borderBottom = '2px solid #ff6600';
            }
            topMenu.appendChild(span);
        });
        panel.appendChild(topMenu);

        const repBar = document.createElement('div');
        repBar.style.height = '28px';
        repBar.style.backgroundColor = '#202020';
        repBar.style.borderBottom = '1px solid #3c3c3c';
        repBar.style.display = 'flex';
        repBar.style.alignItems = 'center';
        repBar.style.padding = '0 10px';
        repBar.style.gap = '10px';

        const sendBtn = document.createElement('button');
        sendBtn.innerText = 'Send';
        sendBtn.style.backgroundColor = '#ff6600';
        sendBtn.style.color = '#ffffff';
        sendBtn.style.border = 'none';
        sendBtn.style.borderRadius = '3px';
        sendBtn.style.padding = '2px 8px';
        sendBtn.style.fontWeight = 'bold';
        
        const urlLabel = document.createElement('span');
        urlLabel.innerHTML = `Target: <span style="color: #ffaa66; font-weight: bold;">${arguments[0]}</span>`;

        repBar.appendChild(sendBtn);
        repBar.appendChild(urlLabel);
        panel.appendChild(repBar);

        const contentArea = document.createElement('div');
        contentArea.style.flex = '1';
        contentArea.style.display = 'flex';
        contentArea.style.overflow = 'hidden';

        const leftPane = document.createElement('div');
        leftPane.style.flex = '1';
        leftPane.style.borderRight = '1px solid #3c3c3c';
        leftPane.style.display = 'flex';
        leftPane.style.flexDirection = 'column';

        const leftHeader = document.createElement('div');
        leftHeader.innerText = 'Request';
        leftHeader.style.padding = '4px 8px';
        leftHeader.style.backgroundColor = '#2a2a2a';
        leftHeader.style.borderBottom = '1px solid #3c3c3c';
        leftHeader.style.fontWeight = 'bold';
        leftHeader.style.color = '#ff6600';

        const leftContent = document.createElement('pre');
        leftContent.style.margin = '0';
        leftContent.style.padding = '8px';
        leftContent.style.overflow = 'auto';
        leftContent.style.flex = '1';
        leftContent.style.whiteSpace = 'pre-wrap';
        leftContent.style.wordBreak = 'break-all';
        leftContent.style.color = '#c0c0c0';

        const attack = arguments[4];
        let reqText = arguments[1] + (arguments[2] ? '\\n' + arguments[2] : '');
        if (attack && reqText.includes(attack)) {
            const escText = reqText.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            const escAttack = attack.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            leftContent.innerHTML = escText.replace(escAttack, `<span style="background-color: #ff6600; color: #ffffff; padding: 1px 3px; border-radius: 2px; font-weight: bold;">${escAttack}</span>`);
        } else {
            leftContent.innerText = reqText;
        }

        leftPane.appendChild(leftHeader);
        leftPane.appendChild(leftContent);
        contentArea.appendChild(leftPane);

        const rightPane = document.createElement('div');
        rightPane.style.flex = '1';
        rightPane.style.display = 'flex';
        rightPane.style.flexDirection = 'column';

        const rightHeader = document.createElement('div');
        rightHeader.innerText = 'Response';
        rightHeader.style.padding = '4px 8px';
        rightHeader.style.backgroundColor = '#2a2a2a';
        rightHeader.style.borderBottom = '1px solid #3c3c3c';
        rightHeader.style.fontWeight = 'bold';
        rightHeader.style.color = '#00cc66';

        const rightContent = document.createElement('pre');
        rightContent.style.margin = '0';
        rightContent.style.padding = '8px';
        rightContent.style.overflow = 'auto';
        rightContent.style.flex = '1';
        rightContent.style.whiteSpace = 'pre-wrap';
        rightContent.style.wordBreak = 'break-all';
        rightContent.style.color = '#c0c0c0';

        if (arguments[5] === 2) {
            rightContent.innerText = '(Waiting for response...)';
            rightContent.style.color = '#555555';
        } else {
            const resText = arguments[6] + '\\n\\n' + arguments[7];
            rightContent.innerText = resText;
        }

        rightPane.appendChild(rightHeader);
        rightPane.appendChild(rightContent);
        contentArea.appendChild(rightPane);

        panel.appendChild(contentArea);
        document.body.appendChild(panel);
        """
        try:
            self.driver.execute_script(
                script,
                job.target_url,
                req_headers,
                req_body,
                job.param or "",
                job.attack or "",
                step,
                res_headers,
                response_body
            )
            time.sleep(0.1)
        except Exception as e:
            logger.warning("Burp Repeater UI injection failed: %s", e)

    def initialize_auth(self, sample_url: str):
        if not self.auth_cookies:
            return
        parsed = urlparse(sample_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        try:
            logger.info("인증 쿠키 주입을 위해 도메인 접속: %s", origin)
            self.driver.get(origin)
            time.sleep(1)
            for cookie in self.auth_cookies:
                try:
                    self.driver.add_cookie(cookie)
                except WebDriverException as e:
                    logger.warning("초기 쿠키 주입 실패 (%s): %s", cookie.get("name"), e)
            logger.info("인증 쿠키 주입 완료")
        except Exception as e:
            logger.warning("인증 쿠키 주입 중 오류 발생: %s", e)

    def _get_frontend_url(self, target_url: str) -> str:
        """API URL 경로를 대응되는 프론트엔드 플랫폼 페이지 경로로 매핑."""
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path.lower()
        
        # API 경로를 프론트엔드 플랫폼 UI URL에 매핑
        if "/api/v1/posts" in path:
            return f"{origin}/feed"
        elif "/api/v1/cars" in path or "/rental_cars" in path:
            return f"{origin}/car"
        elif "/insurance" in path:
            return f"{origin}/insurance"
        elif "/reservations/flights" in path or "/flights" in path:
            return f"{origin}/flight"
        elif "/properties" in path or "/property" in path or "/inventory" in path:
            return f"{origin}/map"
        elif "/auth/signup" in path:
            return f"{origin}/signup/email"
        elif "/members/me" in path or "/wallet" in path or "/mileage" in path:
            return f"{origin}/mypage"
        elif "/admin" in path:
            return f"{origin}/admin"
        else:
            return f"{origin}/"  # 홈/숙소 페이지

    # ──────────────────────────────────────────────
    # STEP 1 — 공격 전 정상 화면 캡처
    # ──────────────────────────────────────────────
    def capture_before(self, job: CaptureJob) -> Optional[str]:
        # 스크린샷의 배경으로 표시할 프론트엔드 플랫폼 화면으로 브라우저를 먼저 이동시킵니다.
        frontend_url = self._get_frontend_url(job.target_url)
        if not self._safe_get(frontend_url):
            return None
        self._apply_cookies(frontend_url)
        time.sleep(0.5)

        # GET API 또는 non-GET API 요청을 백그라운드 fetch로 테스트하여, 원래 API 결과와 에러가 존재하는지 검증합니다.
        # GET API인 경우 파라미터가 비워진 base_url을 호출하여 정상 상태 코드를 확인합니다.
        target_api_url = job.base_url if job.method == "GET" else job.target_url
        result = self._fetch_via_js(target_api_url, job.method, None)
        
        alert_slug = re.sub(r'[^a-zA-Z0-9가-힣ㄱ-ㅎㅏ-ㅣ]', '_', job.alert_type).lower()
        alert_slug = re.sub(r'_+', '_', alert_slug).strip('_')
        if not alert_slug:
            alert_slug = job.alert_category
        path = os.path.join(self.output_dir, f"{job.job_id}_{alert_slug}_1_before.png")
        self._inject_burp_repeater_ui(
            step=1,
            job=job,
            status=result.get("status", 200),
            response_body=result.get("body", "")
        )
        self.driver.save_screenshot(path)
        logger.info("[%s] STEP1 공격 전 캡처 완료 (배경: %s, API: %s) → %s", 
                    job.job_id, frontend_url, urlparse(target_api_url).path, path)
        return path

    # ──────────────────────────────────────────────
    # STEP 2 — payload 입력 + 취약 요소 하이라이트 (또는 JSON 응답 렌더링)
    # ──────────────────────────────────────────────
    def capture_input(self, job: CaptureJob) -> tuple:
        """
        Returns:
            (screenshot_path, highlight_box, fetch_result)
        """
        fetch_result = None
        highlight_box = None

        frontend_url = self._get_frontend_url(job.target_url)
        if not self._safe_get(frontend_url):
            return None, None, None
        self._apply_cookies(frontend_url)
        time.sleep(0.5)

        # 실제 프론트엔드 화면 상에 취약 파라미터에 매칭되는 입력 필드가 존재하는지 확인하고 입력/하이라이트 시도
        highlight_box = self._type_and_highlight_param_element(job.param, job.attack)
        if highlight_box:
            fetch_result = {"ui_interacted": True}
        else:
            # 매칭되는 폼 필드가 없는 경우(대부분 백엔드 단독 API), 공격 페이로드를 동반한 백그라운드 fetch를 미리 실행해 봅니다.
            # 백그라운드 공격에 대한 응답 코드를 배너에 노출하기 위함
            logger.info("[%s] 프론트엔드 입력 필드를 찾지 못해 백그라운드 fetch로 API 공격을 재현합니다.", job.job_id)
            fetch_result = self._fetch_via_js(job.target_url, job.method, job.request_body)

        self._inject_burp_repeater_ui(
            step=2,
            job=job,
            status=0,
            response_body=""
        )
        alert_slug = re.sub(r'[^a-zA-Z0-9가-힣ㄱ-ㅎㅏ-ㅣ]', '_', job.alert_type).lower()
        alert_slug = re.sub(r'_+', '_', alert_slug).strip('_')
        if not alert_slug:
            alert_slug = job.alert_category
        path = os.path.join(self.output_dir, f"{job.job_id}_{alert_slug}_2_input.png")
        self.driver.save_screenshot(path)
        logger.info("[%s] STEP2 입력값 캡처 완료 → %s (요소 탐지: %s, method: %s)",
                    job.job_id, path, bool(highlight_box), job.method)
        return path, highlight_box, fetch_result

    def _type_and_highlight_param_element(self, param: Optional[str], value: Optional[str]) -> Optional[dict]:
        if not param or not value:
            return None

        # 여러 셀렉터를 쉼표(,)로 결합하여 단 한 번의 WebDriverWait로 일괄 탐색
        selectors = [
            f"[name='{param}']",
            f"#{param}",
            f"[id='{param}']",
            f"input[name*='{param}' i]",
            f"textarea[name*='{param}' i]",
            f"[placeholder*='{param}' i]",
            f"input[id*='{param}' i]",
            f"textarea[id*='{param}' i]"
        ]
        combined_selector = ", ".join(selectors)
        element = None
        try:
            element = WebDriverWait(self.driver, 6).until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, combined_selector))
            )
        except (TimeoutException, NoSuchElementException):
            pass

        if not element:
            logger.warning("파라미터 '%s'에 해당하는 DOM 요소를 찾지 못함 (CSS: %s)", param, combined_selector)
            return None

        try:
            # input/textarea 요소에 값을 지우고 입력
            tag_name = element.tag_name.lower()
            if tag_name in ("input", "textarea"):
                element.clear()
                element.send_keys(value)
                logger.info("요소 '%s'에 값 입력 완료: %s", param, value)

            self.driver.execute_script(
                "arguments[0].style.outline = '3px solid #e8453c';"
                "arguments[0].style.outlineOffset = '2px';"
                "arguments[0].scrollIntoView({block: 'center'});",
                element,
            )
            time.sleep(0.3)
            rect = self.driver.execute_script(
                "const r = arguments[0].getBoundingClientRect();"
                "return {x: r.x, y: r.y, width: r.width, height: r.height};",
                element,
            )
            return rect
        except WebDriverException as e:
            logger.warning("요소 입력/하이라이트 중 오류: %s", e)
            return None

    def _find_and_highlight_param_element(self, param: Optional[str]) -> Optional[dict]:
        if not param:
            return None

        selectors = [
            f"[name='{param}']",
            f"#{param}",
            f"[id='{param}']",
            f"input[name*='{param}' i]",
            f"textarea[name*='{param}' i]",
            f"[placeholder*='{param}' i]",
            f"input[id*='{param}' i]",
            f"textarea[id*='{param}' i]"
        ]
        combined_selector = ", ".join(selectors)
        element = None
        try:
            element = WebDriverWait(self.driver, 6).until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, combined_selector))
            )
        except (TimeoutException, NoSuchElementException):
            pass

        if not element:
            logger.warning("파라미터 '%s'에 해당하는 DOM 요소를 찾지 못함 (CSS: %s)", param, combined_selector)
            return None

        try:
            self.driver.execute_script(
                "arguments[0].style.outline = '3px solid #e8453c';"
                "arguments[0].style.outlineOffset = '2px';"
                "arguments[0].scrollIntoView({block: 'center'});",
                element,
            )
            time.sleep(0.3)
            rect = self.driver.execute_script(
                "const r = arguments[0].getBoundingClientRect();"
                "return {x: r.x, y: r.y, width: r.width, height: r.height};",
                element,
            )
            return rect
        except WebDriverException as e:
            logger.warning("요소 하이라이트 중 오류: %s", e)
            return None

    # ──────────────────────────────────────────────
    # STEP 3 — 트리거 감지 + 결과 캡처
    # ──────────────────────────────────────────────
    def capture_result(self, job: CaptureJob, fetch_result: Optional[dict]) -> tuple:
        # UI 상호작용으로 값을 입력한 경우 폼 제출을 선행
        if fetch_result and fetch_result.get("ui_interacted"):
            self._submit_interacted_form(job.param)
            fetch_result = None  # 이후 트리거 감지는 일반 페이지 소스를 타도록 None 처리
        else:
            # UI 입력이 아닌 일반 API 점검인 경우 백그라운드 fetch를 통한 실제 공격 검증을 수행
            if not fetch_result:
                fetch_result = self._fetch_via_js(job.target_url, job.method, job.request_body)

        time.sleep(self.trigger_wait_seconds)

        dispatch = {
            "xss": self._detect_xss_trigger,
            "redirect": self._detect_redirect_trigger,
            "sqli": self._detect_sqli_trigger,
            "path_traversal": self._detect_evidence_trigger,
            "lfi_rfi": self._detect_evidence_trigger,
            "server_error": self._detect_server_error_trigger,
            "csrf_cookie": self._detect_evidence_trigger,
            "fuzz_crash": self._detect_server_error_trigger,
            "other": self._detect_evidence_trigger,
        }
        detector = dispatch.get(job.alert_category, self._detect_evidence_trigger)

        confirmed, reason = detector(job, fetch_result)

        alert_slug = re.sub(r'[^a-zA-Z0-9가-힣ㄱ-ㅎㅏ-ㅣ]', '_', job.alert_type).lower()
        alert_slug = re.sub(r'_+', '_', alert_slug).strip('_')
        if not alert_slug:
            alert_slug = job.alert_category
        path = os.path.join(self.output_dir, f"{job.job_id}_{alert_slug}_3_result.png")
        response_type = "json" if job.response_type_hint == "json" else "html"
        body_text = ""
        if fetch_result:
            body_text = fetch_result.get("body", "")
        else:
            try:
                body_text = self.driver.execute_script("return document.body ? document.body.innerText : ''")
            except Exception:
                pass

        status_code = fetch_result.get("status", 500) if fetch_result else 500
        try:
            self._inject_burp_repeater_ui(
                step=3,
                job=job,
                status=status_code,
                response_body=body_text
            )
            self.driver.save_screenshot(path)
        except WebDriverException:
            self._try_dismiss_alert()
            self._inject_burp_repeater_ui(
                step=3,
                job=job,
                status=status_code,
                response_body=body_text
            )
            self.driver.save_screenshot(path)

        logger.info("[%s] STEP3 결과 캡처 완료 (Confirmed: %s) → %s",
                    job.job_id, confirmed, path)
        return path, confirmed, reason

    def _submit_interacted_form(self, param: Optional[str]):
        if not param:
            return

        selectors = [f"[name='{param}']", f"#{param}", f"[id='{param}']"]
        element = None
        for sel in selectors:
            try:
                element = self.driver.find_element(By.CSS_SELECTOR, sel)
                if element:
                    break
            except Exception:
                continue

        if element:
            try:
                # 1. 폼 자체 제출 시도
                element.submit()
                logger.info("element.submit()을 통해 폼 전송 완료")
                return
            except Exception as e:
                logger.warning("element.submit() 실패: %s. ENTER 키 전송 시도...", e)

            try:
                # 2. Enter 키 전송
                from selenium.webdriver.common.keys import Keys
                element.send_keys(Keys.ENTER)
                logger.info("ENTER 키 입력을 통해 전송 완료")
                return
            except Exception as e:
                logger.warning("ENTER 키 전송 실패: %s. 버튼 클릭 시도...", e)

        # 3. 일반 Submit 버튼 클릭 시도
        submit_selectors = [
            "button[type='submit']",
            "input[type='submit']",
            "button",
            "input[type='button']"
        ]
        for sel in submit_selectors:
            try:
                buttons = self.driver.find_elements(By.CSS_SELECTOR, sel)
                for btn in buttons:
                    if btn.is_displayed() and btn.is_enabled():
                        btn.click()
                        logger.info("제출 버튼 클릭을 통해 전송 완료: %s", sel)
                        return
            except Exception:
                continue
        logger.warning("폼 제출용 요소나 버튼을 찾지 못함")

    def _try_dismiss_alert(self):
        try:
            alert = self.driver.switch_to.alert
            alert.accept()
        except Exception:
            pass

    def _detect_xss_trigger(self, job: CaptureJob, fetch_result: Optional[dict]) -> tuple:
        """alert() 팝업 발생 여부로 XSS 트리거 판단 (HTML 페이지 한정). JSON 응답은 evidence 폴백."""
        if job.response_type_hint == "json" or job.method != "GET":
            # JSON 응답에 반영된 XSS는 alert가 안 뜨므로(브라우저가 직접 실행 안 함)
            # payload 문자열이 응답 본문에 그대로 들어있는지로 판단
            return self._detect_payload_reflected(job, fetch_result)
        try:
            WebDriverWait(self.driver, 3).until(EC.alert_is_present())
            alert_text = self.driver.switch_to.alert.text
            self.driver.switch_to.alert.accept()
            return True, f"alert 팝업 감지: '{alert_text}'"
        except TimeoutException:
            return self._detect_evidence_trigger(job, fetch_result)

    def _detect_redirect_trigger(self, job: CaptureJob, fetch_result: Optional[dict]) -> tuple:
        current_url = self.driver.current_url
        if current_url != job.target_url and job.attack and job.attack in current_url:
            return True, f"리다이렉트 발생: {current_url}"
        if current_url != job.target_url:
            return True, f"URL 변경 감지: {current_url}"
        return False, "URL 변화 없음 — 리다이렉트 미발생"

    def _detect_sqli_trigger(self, job: CaptureJob, fetch_result: Optional[dict]) -> tuple:
        page_source = self.driver.page_source.lower()
        sql_error_signatures = [
            "sql syntax", "mysql_fetch", "ora-01756", "unclosed quotation",
            "sqlstate", "pg_query", "sqlite_error",
        ]
        for sig in sql_error_signatures:
            if sig in page_source:
                return True, f"SQL 에러 시그니처 노출: '{sig}'"
        return self._detect_evidence_trigger(job, fetch_result)

    def _detect_server_error_trigger(self, job: CaptureJob, fetch_result: Optional[dict]) -> tuple:
        """
        evidence가 비어있는 경우가 많은 카테고리(서버 예외 노출, 강제 크래시 유도 등)를 위한 판단.
        실제 HTTP status code를 1차 기준으로 삼는다 — body 요청은 fetch_result에서,
        GET 요청은 페이지 소스에 노출된 상태 코드 패턴(500, 502 등)으로 추정.
        """
        if fetch_result and fetch_result.get("status"):
            status = fetch_result["status"]
            if status >= 500:
                return True, f"서버 에러 상태 코드 확인: HTTP {status}"
            return False, f"정상 응답 코드 (HTTP {status}) — 서버 에러 미재현"

        # evidence에 "HTTP/2 500" 같은 패턴이 있는 GET 케이스 — 페이지 소스에서 직접 확인은
        # 불가하므로(브라우저는 상태 코드를 본문에 보여주지 않음) evidence 문자열 자체에서 추정
        if job.evidence and any(code in job.evidence for code in ("500", "502", "503")):
            return True, f"ZAP 보고 evidence에 서버 에러 코드 포함: '{job.evidence}'"

        return self._detect_evidence_trigger(job, fetch_result)

    def _detect_payload_reflected(self, job: CaptureJob, fetch_result: Optional[dict]) -> tuple:
        """fetch_result의 응답 본문(JSON API 등)에 payload 원문이 그대로 반영됐는지 확인."""
        if not job.attack:
            return False, "attack(payload) 필드 없음 — 자동 판단 불가"

        body_text = ""
        if fetch_result:
            body_text = fetch_result.get("body", "")
        else:
            body_text = self.driver.page_source

        if job.attack in body_text:
            return True, f"payload가 응답 본문에 그대로 반영됨: '{job.attack[:50]}'"
        return False, "payload가 응답 본문에서 발견되지 않음 (필터링되었거나 오탐 가능성)"

    def _detect_evidence_trigger(self, job: CaptureJob, fetch_result: Optional[dict]) -> tuple:
        """
        가장 범용적인 폴백: evidence 문자열이 현재 페이지/응답 본문에 존재하는지 확인.
        evidence 자체가 없는 경우(흔함)에는 "수동 확인 필요"로 명확히 표시 —
        무리하게 confirmed를 추정하지 않는 것이 오탐을 줄이는 데 더 안전하기 때문.
        """
        if not job.evidence:
            return False, "evidence 필드 없음 — 자동 판단 불가, 수동 확인 필요"

        body_text = fetch_result.get("body", "") if fetch_result else self.driver.page_source
        if job.evidence in body_text:
            return True, f"evidence 문자열 응답 내 반영 확인: '{job.evidence[:40]}...'"
        return False, "evidence 문자열이 현재 응답에서 발견되지 않음 (오탐 가능성)"

    # ──────────────────────────────────────────────
    # 단일 job 전체 파이프라인 실행
    # ──────────────────────────────────────────────
    def run_job(self, job: CaptureJob) -> CaptureResult:
        result = CaptureResult(job_id=job.job_id)

        try:
            result.before_path = self.capture_before(job)
            result.input_path, result.highlight_box, fetch_result = self.capture_input(job)
            result.result_path, result.confirmed, result.failure_reason = self.capture_result(
                job, fetch_result
            )
            if fetch_result:
                result.http_status = fetch_result.get("status")
        except Exception as e:
            logger.error("[%s] 캡처 파이프라인 중 예외 발생: %s", job.job_id, e)
            result.failure_reason = f"예외 발생: {e}"

        return result

    def close(self):
        self.driver.quit()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def run_jobs(
    jobs: list,
    output_dir: str = "./captures",
    auth_cookies: Optional[list] = None,
    auth_headers: Optional[dict] = None,
) -> list:
    """여러 CaptureJob을 하나의 driver 세션으로 순차 처리."""
    results = []
    with SeleniumCaptureEngine(
        output_dir=output_dir,
        auth_cookies=auth_cookies,
        auth_headers=auth_headers,
    ) as engine:
        if jobs and auth_cookies:
            # 첫 번째 job의 target_url을 기준으로 인증 쿠키를 먼저 세팅
            engine.initialize_auth(jobs[0].target_url)

        for job in jobs:
            logger.info("=== Job %s 시작 (%s / %s / %s) ===",
                        job.job_id, job.alert_type, job.alert_category, job.method)
            result = engine.run_job(job)
            results.append(result)
    return results


if __name__ == "__main__":
    import sys
    from capture_job import load_zap_json, convert_to_capture_jobs, summarize_jobs

    if len(sys.argv) < 2:
        print("사용법: python selenium_capture.py <zap_result.json|.jsonc>")
        sys.exit(1)

    alerts = load_zap_json(sys.argv[1])
    jobs = convert_to_capture_jobs(alerts, only_risk={"High", "Medium", "Low"}, max_per_alert_group=5)

    summary = summarize_jobs(jobs)
    print(f"{summary['total']}개 job 처리 시작 — {summary['by_category']}")

    results = run_jobs(jobs)

    confirmed_count = sum(1 for r in results if r.confirmed)
    print(f"완료: {len(results)}건 중 {confirmed_count}건 confirmed=True")
