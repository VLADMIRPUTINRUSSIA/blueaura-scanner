#!/usr/bin/env python3
"""
Full Advanced Web Security Scanner - Refactored and Enhanced
My Telegram: t.me/anonx512 MADE BY ANONX512
This script incorporates advanced features for web application security scanning,
including a sophisticated Playwright-based crawler, detailed vulnerability reporting,
numerous scanner modules, authentication handling, and external payload management.

Features:
- YAML config + CLI arguments
- Structured JSON logging
- Asynchronous Playwright-based crawler for full JS rendering
- Advanced crawling: Forms, JS files, XHR/AJAX interception
- Enhanced BrowserSession: Returns full request/response objects, handles POST,
  proxies, and User-Agent rotation.
- Modular Scanners:
  - SQLi (Error-based, Time-based, POST)
  - XSS (Reflected, DOM-based, POST)
  - SSRF (Out-of-band confirmation)
  - IDOR (Content comparison)
  - NEW: Security Headers
  - NEW: Open Redirect
  - NEW: Directory Fuzzer
- Detailed Reporting: Captures severity, remediation, and full evidence.
- Authentication: Automated login before scanning.
- External Payloads: Loads payloads from a YAML file.
- Out-of-Band (OOB) server for callback detection.
- Graceful shutdown, rate limiting, and retry logic.
"""

import argparse
import asyncio
import json
import logging
import random
import signal
import sys
import time
import traceback
from dataclasses import dataclass, field
from functools import wraps
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import List, Dict, Optional, Any, Set, Union
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

import yaml
from jinja2 import Environment, FileSystemLoader

try:
    from playwright.async_api import (
        async_playwright,
        Page,
        BrowserContext,
        Browser,
        Response,
        Request,
        Playwright,
        TimeoutError as PlaywrightTimeoutError,
        Error as PlaywrightError,
    )
except ImportError:
    print("Playwright not installed. Please run: pip install playwright && playwright install")
    sys.exit(1)

# -------------------- Global Objects --------------------
shutdown_event = asyncio.Event()
OOB_LOGS = [] # Global log for OOB server callbacks

# -------------------- Logging Setup --------------------
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "module": record.module,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_record['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(log_record)

def setup_logger(level=logging.INFO):
    logger = logging.getLogger("WebSecScanner")
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    # Prevent playwright from spamming logs
    logging.getLogger("playwright").setLevel(logging.WARNING)
    return logger

logger = setup_logger()

# -------------------- Configuration & Data Classes --------------------
@dataclass
class ScanConfig:
    target_url: str
    modules: List[str] = field(default_factory=list)
    excluded_paths: List[str] = field(default_factory=list)
    proxies: Optional[Dict[str, str]] = None
    auth: Optional[Dict[str, Any]] = None
    rate_limit_per_sec: float = 5.0
    report_format: str = "html"
    oob_listen_port: int = 8000
    oob_base_domain: str = "127.0.0.1"
    max_crawl_depth: int = 3
    max_crawl_urls: int = 100
    scan_timeout_per_url: int = 15  # seconds
    headless: bool = True
    debug: bool = False

@dataclass
class Payloads:
    user_agents: List[str] = field(default_factory=list)
    sqli: List[Dict[str, Any]] = field(default_factory=list)
    xss: List[Dict[str, Any]] = field(default_factory=list)
    ssrf: List[str] = field(default_factory=list)
    open_redirect: List[str] = field(default_factory=list)
    dir_fuzz: List[str] = field(default_factory=list)

@dataclass
class RequestWrapper:
    method: str
    url: str
    headers: Dict[str, str]
    post_data: Optional[Union[Dict, str]] = None

@dataclass
class ResponseWrapper:
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    request: RequestWrapper

@dataclass
class Evidence:
    request: RequestWrapper
    response: ResponseWrapper

@dataclass
class Vulnerability:
    url: str
    module: str
    type: str
    severity: str
    payload: str
    proof: str
    remediation: str
    evidence: Evidence

def load_config(path: str) -> ScanConfig:
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return ScanConfig(**raw.get('config', {}))

def load_payloads(path: str) -> Payloads:
    with open(path, "r") as f:
        raw = yaml.safe_load(f)
    return Payloads(**raw.get('payloads', {}))

# -------------------- Rate Limiter --------------------
class RateLimiter:
    def __init__(self, rate: float):
        self._rate = rate
        self._tokens = rate
        self._timestamp = time.monotonic()

    async def wait(self):
        while self._tokens < 1:
            now = time.monotonic()
            elapsed = now - self._timestamp
            self._tokens += elapsed * self._rate
            self._tokens = min(self._tokens, self._rate)
            self._timestamp = now
            if self._tokens < 1:
                await asyncio.sleep(0.1)
        self._tokens -= 1

# -------------------- Signal Handling --------------------
def graceful_shutdown_handler(signum, frame):
    logger.info(f"Shutdown signal {signum} received, stopping...")
    shutdown_event.set()

signal.signal(signal.SIGINT, graceful_shutdown_handler)
signal.signal(signal.SIGTERM, graceful_shutdown_handler)

# -------------------- Retry Decorator --------------------
def retry(max_attempts=3, delay=1, exceptions=(PlaywrightError,)):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                if shutdown_event.is_set():
                    return
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exc = e
                    logger.warning(f"Retry {attempt}/{max_attempts} for {func.__name__} after exception: {type(e).__name__}")
                    await asyncio.sleep(delay * attempt)
            if last_exc:
                raise last_exc
        return wrapper
    return decorator

# -------------------- Browser Session Wrapper --------------------
class BrowserSession:
    def __init__(self, config: ScanConfig, payloads: Payloads, headless: bool = True):
        self._playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self._config = config
        self._payloads = payloads
        self._headless = headless

    async def __aenter__(self):
        self._playwright = await async_playwright().start()
        proxy_settings = self._config.proxies if self._config.proxies else None
        self.browser = await self._playwright.chromium.launch(headless=self._headless, proxy=proxy_settings)
        self.context = await self.browser.new_context(
            user_agent=random.choice(self._payloads.user_agents),
            ignore_https_errors=True
        )
        self.page = await self.context.new_page()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.context: await self.context.close()
        if self.browser: await self.browser.close()
        if self._playwright: await self._playwright.stop()

    async def _wrap_response(self, response: Optional[Response]) -> Optional[ResponseWrapper]:
        if not response:
            return None
        request = response.request
        req_wrapper = RequestWrapper(
            method=request.method,
            url=request.url,
            headers=await request.all_headers(),
            post_data=request.post_data
        )
        return ResponseWrapper(
            url=response.url,
            status=response.status,
            headers=await response.all_headers(),
            body=await response.text(),
            request=req_wrapper
        )

    @retry()
    async def get(self, url: str) -> Optional[ResponseWrapper]:
        logger.debug(f"GET: {url}")
        response = await self.page.goto(url, timeout=self._config.scan_timeout_per_url * 1000, wait_until='domcontentloaded')
        return await self._wrap_response(response)

    @retry()
    async def post(self, url: str, data: Dict[str, str]) -> Optional[ResponseWrapper]:
        logger.debug(f"POST: {url} with data: {data}")
        # Playwright's page.request is separate from the page's context,
        # so we simulate a form submission to keep it within the same session/cookies
        js_submit_form = f"""
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '{url}';
        const data = {json.dumps(data)};
        for (const key in data) {{
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = key;
            input.value = data[key];
            form.appendChild(input);
        }}
        document.body.appendChild(form);
        form.submit();
        """
        # We listen for the response that results from the form submission
        async with self.page.expect_response(lambda r: r.url == url and r.request.method == 'POST') as response_info:
            await self.page.evaluate(js_submit_form)
        response = await response_info.value
        return await self._wrap_response(response)

# -------------------- Crawler --------------------
async def crawl(
    config: ScanConfig,
    session: BrowserSession,
    rate_limiter: RateLimiter
) -> Dict[str, Dict]:
    logger.info(f"Starting crawl from {config.target_url}")
    target_domain = urllib.parse.urlparse(config.target_url).netloc
    urls_to_visit = asyncio.Queue()
    await urls_to_visit.put((config.target_url, 0))
    
    visited = {} # {url: {"forms": [...], "params": [...]}}
    ajax_requests = set()

    # --- Event Handlers for dynamic content discovery ---
    def handle_request(request: Request):
        if request.is_navigation_request():
            return
        if "fetch" in request.resource_type or "xhr" in request.resource_type:
            if target_domain in urllib.parse.urlparse(request.url).netloc:
                if request.url not in ajax_requests:
                    logger.debug(f"AJAX request discovered: {request.method} {request.url}")
                    ajax_requests.add(request.url)

    session.page.on("request", handle_request)

    while not urls_to_visit.empty() and len(visited) < config.max_crawl_urls:
        if shutdown_event.is_set(): break
        
        current_url, depth = await urls_to_visit.get()
        
        if current_url in visited or depth > config.max_crawl_depth:
            continue
        
        # Check scope
        if urllib.parse.urlparse(current_url).netloc != target_domain:
            continue

        await rate_limiter.wait()
        logger.info(f"Crawling: {current_url} at depth {depth}")
        
        try:
            await session.page.goto(current_url, timeout=10000, wait_until='domcontentloaded')
            visited[current_url] = {"forms": [], "params": list(urllib.parse.parse_qs(urllib.parse.urlparse(current_url).query).keys())}

            # 1. Discover links
            links = await session.page.eval_on_selector_all("a[href]", "elements => elements.map(e => e.href)")
            for link in links:
                if link and not link.startswith(('mailto:', 'tel:')):
                    abs_link = urllib.parse.urljoin(current_url, link)
                    if abs_link not in visited and urllib.parse.urlparse(abs_link).netloc == target_domain:
                        await urls_to_visit.put((abs_link, depth + 1))
            
            # 2. Discover Forms
            forms = await session.page.locator("form").element_handles()
            for form_handle in forms:
                action = await form_handle.get_attribute("action") or current_url
                method = (await form_handle.get_attribute("method") or "GET").upper()
                form_action_url = urllib.parse.urljoin(current_url, action)
                
                inputs = await form_handle.query_selector_all("input, textarea, select")
                param_names = [await i.get_attribute("name") for i in inputs if await i.get_attribute("name")]
                
                form_data = {"action": form_action_url, "method": method, "params": param_names}
                visited[current_url]["forms"].append(form_data)
                logger.debug(f"Form discovered on {current_url}: {form_data}")

        except Exception as e:
            logger.warning(f"Error crawling {current_url}: {type(e).__name__} - {e}")
            
    session.page.remove_listener("request", handle_request)
    
    # Add discovered AJAX URLs to the list of things to scan
    for ajax_url in ajax_requests:
        if ajax_url not in visited:
            visited[ajax_url] = {"forms": [], "params": list(urllib.parse.parse_qs(urllib.parse.urlparse(ajax_url).query).keys())}

    logger.info(f"Crawl finished. Found {len(visited)} pages/endpoints.")
    return visited

# -------------------- OOB Server --------------------
class OOBRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        log_entry = f"GET {self.path} from {self.client_address[0]}"
        logger.info(f"[OOB Server] Received callback: {log_entry}")
        OOB_LOGS.append(log_entry)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_message(self, format, *args):
        return # Suppress default logging

def run_oob_server(port: int):
    with HTTPServer(("0.0.0.0", port), OOBRequestHandler) as httpd:
        logger.info(f"OOB server starting on port {port}")
        httpd.serve_forever()

# -------------------- Scanner Base Class --------------------
class ScannerModule:
    name = "BaseScanner"
    description = "Base scanner module"

    def __init__(self, config: ScanConfig, payloads: Payloads):
        self.config = config
        self.payloads = payloads
        self.results: List[Vulnerability] = []

    async def run(self, session: BrowserSession, target: Dict, url: str):
        raise NotImplementedError()

# -------------------- Scanner Modules --------------------

class SQLiScanner(ScannerModule):
    name = "SQLiScanner"
    remediation = "Use parameterized queries or prepared statements. Sanitize and validate all user input."

    async def run(self, session: BrowserSession, target: Dict, url: str):
        # Test GET parameters
        if target['params']:
            for param in target['params']:
                await self._test_get_sqli(session, url, param)
        
        # Test POST parameters from forms
        for form in target.get('forms', []):
            if form['method'] == 'POST':
                await self._test_post_sqli(session, form['action'], form['params'])
    
    async def _test_get_sqli(self, session: BrowserSession, url: str, param: str):
        for p in self.payloads.sqli:
            if shutdown_event.is_set(): return

            original_url_parts = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(original_url_parts.query)
            
            # Time-based blind test
            if p['type'] == 'time':
                query_params[param] = p['payload']
                test_url = original_url_parts._replace(query=urllib.parse.urlencode(query_params, doseq=True)).geturl()
                
                start_time = time.monotonic()
                try:
                    await session.get(test_url)
                except PlaywrightTimeoutError: # A timeout is a strong indicator
                    duration = time.monotonic() - start_time
                    if duration >= (p['sleep_time'] - 1):
                        self._log_vuln(url, "Time-Based Blind SQLi", p['severity'], p['payload'], f"Response took {duration:.2f}s, indicating command execution.", None)
                except Exception:
                    pass
                continue

            # Error-based test
            query_params[param] = p['payload']
            test_url = original_url_parts._replace(query=urllib.parse.urlencode(query_params, doseq=True)).geturl()
            response = await session.get(test_url)
            if response:
                for error_sig in p.get('errors', []):
                    if error_sig.lower() in response.body.lower():
                        evidence = Evidence(request=response.request, response=response)
                        self._log_vuln(url, "Error-Based SQLi", p['severity'], p['payload'], f"Database error found: '{error_sig}'", evidence)
                        break

    async def _test_post_sqli(self, session: BrowserSession, url: str, params: List[str]):
        for param in params:
            for p in self.payloads.sqli:
                if shutdown_event.is_set(): return
                if p['type'] == 'error':
                    post_data = {k: "test" for k in params}
                    post_data[param] = p['payload']
                    response = await session.post(url, data=post_data)
                    if response:
                        for error_sig in p.get('errors', []):
                            if error_sig.lower() in response.body.lower():
                                evidence = Evidence(request=response.request, response=response)
                                self._log_vuln(url, "Error-Based SQLi (POST)", p['severity'], p['payload'], f"Database error found: '{error_sig}'", evidence)
                                break
    
    def _log_vuln(self, url, v_type, severity, payload, proof, evidence):
        vuln = Vulnerability(url, self.name, v_type, severity, payload, proof, self.remediation, evidence)
        self.results.append(vuln)
        logger.critical(f"[{self.name}] Vulnerability Found! Type: {v_type}, URL: {url}, Payload: {payload}")


class XSSScanner(ScannerModule):
    name = "XSSScanner"
    remediation = "Implement context-aware output encoding (e.g., HTML entity encoding, JavaScript escaping). Use a strong Content Security Policy (CSP)."

    async def run(self, session: BrowserSession, target: Dict, url: str):
        # 1. Test for DOM-based XSS by listening for alerts
        dialog_triggered = asyncio.Event()
        def on_dialog(dialog):
            logger.critical(f"[XSS] DOM XSS detected via '{dialog.type}' event with message: {dialog.message}")
            dialog_triggered.set()
            asyncio.create_task(dialog.dismiss()) # Use create_task to avoid blocking
        
        session.page.on("dialog", on_dialog)
        
        # Test GET params
        if target['params']:
            for param in target['params']:
                await self._test_param(session, url, param, dialog_triggered, "GET")
        
        # Test POST params
        for form in target.get('forms', []):
            if form['method'] == 'POST':
                for param in form['params']:
                    await self._test_param(session, form['action'], param, dialog_triggered, "POST", all_params=form['params'])
        
        session.page.remove_listener("dialog", on_dialog)
    
    async def _test_param(self, session: BrowserSession, url: str, param: str, dialog_event: asyncio.Event, method: str, all_params: List[str] = None):
        for p in self.payloads.xss:
            if shutdown_event.is_set(): return
            
            payload_str = p['payload']
            response = None
            
            # Reset the event for each payload test
            dialog_event.clear()

            try:
                if method == "GET":
                    original_url_parts = urllib.parse.urlparse(url)
                    query_params = urllib.parse.parse_qs(original_url_parts.query)
                    query_params[param] = payload_str
                    test_url = original_url_parts._replace(query=urllib.parse.urlencode(query_params, doseq=True)).geturl()
                    response = await session.get(test_url)
                else: # POST
                    post_data = {k: "test" for k in all_params}
                    post_data[param] = payload_str
                    response = await session.post(url, data=post_data)

                # Wait a moment for any potential dialog to pop up
                await asyncio.sleep(0.5)

                if dialog_event.is_set():
                    evidence = Evidence(request=response.request, response=response)
                    self._log_vuln(url, "DOM-Based XSS", p['severity'], payload_str, "JavaScript execution (alert dialog) detected.", evidence)
                    return # Found a vuln for this param, move to the next

                if response and payload_str in response.body:
                    evidence = Evidence(request=response.request, response=response)
                    self._log_vuln(url, "Reflected XSS", p['severity'], payload_str, "Payload was reflected in the HTML response body.", evidence)

            except Exception as e:
                logger.debug(f"Exception during XSS test for {param}: {e}")

    def _log_vuln(self, url, v_type, severity, payload, proof, evidence):
        vuln = Vulnerability(url, self.name, v_type, severity, payload, proof, self.remediation, evidence)
        self.results.append(vuln)
        logger.critical(f"[{self.name}] Vulnerability Found! Type: {v_type}, URL: {url}")


class SSRFScanner(ScannerModule):
    name = "SSRFScanner"
    severity = "High"
    remediation = "Whitelist allowed domains and protocols for server-side requests. Disable unused URL schemes. Do not proxy requests based on user-supplied URLs."

    async def run(self, session: BrowserSession, target: Dict, url: str):
        if not target['params']: return
        
        oob_domain = f"{self.config.oob_base_domain}:{self.config.oob_listen_port}"

        for param in target['params']:
             for p_template in self.payloads.ssrf:
                if shutdown_event.is_set(): return
                
                payload = p_template.format(oob_domain=oob_domain)
                
                original_url_parts = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(original_url_parts.query)
                query_params[param] = payload
                test_url = original_url_parts._replace(query=urllib.parse.urlencode(query_params, doseq=True)).geturl()

                try:
                    # Just send the request, don't care about the response
                    await session.get(test_url)
                    
                    # Wait briefly for OOB callback to arrive
                    await asyncio.sleep(1)

                    # Check OOB logs for confirmation
                    for log_entry in OOB_LOGS:
                        if payload in log_entry:
                            proof = f"Confirmed OOB interaction from {log_entry.split()[3]} to {payload}"
                            # Evidence is tricky here, as the vuln is confirmed out-of-band.
                            # We can capture the request that triggered it.
                            req_wrapper = RequestWrapper("GET", test_url, {}, None)
                            evidence = Evidence(request=req_wrapper, response=None)
                            self._log_vuln(url, "Server-Side Request Forgery (SSRF)", payload, proof, evidence)
                            OOB_LOGS.remove(log_entry) # Consume log
                            return # Found vuln, move to next target
                except Exception as e:
                    logger.debug(f"Exception during SSRF test for {param}: {e}")

    def _log_vuln(self, url, v_type, payload, proof, evidence):
        vuln = Vulnerability(url, self.name, v_type, self.severity, payload, proof, self.remediation, evidence)
        self.results.append(vuln)
        logger.critical(f"[{self.name}] Vulnerability Found! Type: {v_type}, URL: {url}")


class IDORScanner(ScannerModule):
    name = "IDORScanner"
    severity = "High"
    remediation = "Implement object-level authorization checks. Ensure users can only access resources they are permitted to see. Use non-sequential, random identifiers (UUIDs)."

    async def run(self, session: BrowserSession, target: Dict, url: str):
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        for param, values in query_params.items():
            if not values: continue
            original_value = values[0]
            
            if original_value.isdigit():
                try:
                    original_id = int(original_value)
                    # Test +1 and -1, but not 0
                    test_ids = {original_id + 1, original_id -1} - {0}
                except ValueError:
                    continue

                for test_id in test_ids:
                    if shutdown_event.is_set(): return

                    # Original request
                    original_response = await session.get(url)
                    if not original_response or original_response.status != 200:
                        continue
                    
                    # Manipulated request
                    new_qs = query_params.copy()
                    new_qs[param] = str(test_id)
                    new_query = urllib.parse.urlencode(new_qs, doseq=True)
                    test_url = parsed_url._replace(query=new_query).geturl()
                    
                    manipulated_response = await session.get(test_url)

                    if manipulated_response and manipulated_response.status == 200:
                        # Simple check: different content of similar length
                        len_diff = abs(len(original_response.body) - len(manipulated_response.body))
                        if len_diff / len(original_response.body) < 0.2: # less than 20% different
                            proof = f"Accessed resource with ID {test_id} on param '{param}'. Original and manipulated responses were both status 200 with similar content length."
                            evidence = Evidence(request=manipulated_response.request, response=manipulated_response)
                            self._log_vuln(url, "Insecure Direct Object Reference (IDOR)", f"{param}={test_id}", proof, evidence)

    def _log_vuln(self, url, v_type, payload, proof, evidence):
        vuln = Vulnerability(url, self.name, v_type, self.severity, payload, proof, self.remediation, evidence)
        self.results.append(vuln)
        logger.critical(f"[{self.name}] Vulnerability Found! Type: {v_type}, URL: {url}")


class SecurityHeadersScanner(ScannerModule):
    name = "SecurityHeadersScanner"
    remediation = "Consult web security best practices (e.g., OWASP Secure Headers Project) to implement missing headers like CSP, HSTS, X-Frame-Options, etc."

    async def run(self, session: BrowserSession, target: Dict, url: str):
        # This scanner only needs to run once on the main URL
        if url != self.config.target_url:
            return
            
        logger.info(f"[{self.name}] Analyzing security headers for {url}")
        response = await session.get(url)
        if not response: return

        headers = {k.lower(): v for k, v in response.headers.items()}
        evidence = Evidence(request=response.request, response=response)

        checks = {
            "Content-Security-Policy": ("Medium", "Prevents XSS and data injection attacks."),
            "Strict-Transport-Security": ("Medium", "Enforces secure (HTTPS) connections."),
            "X-Content-Type-Options": ("Low", "Prevents MIME-sniffing attacks."),
            "X-Frame-Options": ("Low", "Protects against clickjacking attacks."),
            "Referrer-Policy": ("Low", "Controls how much referrer information is sent."),
            "Permissions-Policy": ("Low", "Controls which browser features can be used.")
        }
        
        for header, (severity, purpose) in checks.items():
            if header.lower() not in headers:
                proof = f"The '{header}' HTTP response header is missing."
                self._log_vuln(url, "Missing Security Header", severity, header, proof, self.remediation + " " + purpose, evidence)

    def _log_vuln(self, url, v_type, severity, payload, proof, remediation, evidence):
        vuln = Vulnerability(url, self.name, v_type, severity, payload, proof, remediation, evidence)
        self.results.append(vuln)
        logger.warning(f"[{self.name}] Finding: {v_type} - {payload} on {url}")


class OpenRedirectScanner(ScannerModule):
    name = "OpenRedirectScanner"
    severity = "Medium"
    remediation = "Avoid using user-supplied input in redirection targets. If necessary, maintain a whitelist of allowed redirect URLs."

    async def run(self, session: BrowserSession, target: Dict, url: str):
        # We need a domain that is clearly not the target
        evil_domain = "evil-untrusted-site.com"
        
        url_parts = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(url_parts.query)

        # Common redirect parameter names
        redirect_param_names = {'next', 'url', 'target', 'r', 'dest', 'destination', 'redirect_uri', 'redirect_url', 'redirect'}
        
        for param in params:
            if param.lower() in redirect_param_names:
                for p_payload in self.payloads.open_redirect:
                    payload = p_payload.format(domain=evil_domain)
                    
                    new_qs = params.copy()
                    new_qs[param] = payload
                    test_url = url_parts._replace(query=urllib.parse.urlencode(new_qs, doseq=True)).geturl()

                    try:
                        # We use page.goto and check the final URL after redirects
                        await session.page.goto(test_url)
                        final_url = session.page.url
                        if evil_domain in urllib.parse.urlparse(final_url).netloc:
                            proof = f"Redirected to {final_url} after setting '{param}' to '{payload}'"
                            # We don't have a simple response object here, so we fake it.
                            req_wrapper = RequestWrapper("GET", test_url, {}, None)
                            evidence = Evidence(request=req_wrapper, response=None)
                            self._log_vuln(url, "Open Redirect", payload, proof, evidence)
                            break # Move to next param
                    except Exception as e:
                        logger.debug(f"Exception during Open Redirect test: {e}")

    def _log_vuln(self, url, v_type, payload, proof, evidence):
        vuln = Vulnerability(url, self.name, v_type, self.severity, payload, proof, self.remediation, evidence)
        self.results.append(vuln)
        logger.warning(f"[{self.name}] Vulnerability Found! Type: {v_type}, URL: {url}")


class DirectoryFuzzer(ScannerModule):
    name = "DirectoryFuzzer"
    remediation = "Ensure proper access controls on web server directories. Disable directory listings. Remove any unnecessary or sensitive files from the web root."

    async def run(self, session: BrowserSession, target: Dict, url: str):
        # This scanner only needs to run once on the base URL
        if url != self.config.target_url:
            return

        base_url = self.config.target_url.rstrip('/')
        logger.info(f"[{self.name}] Fuzzing directories and files on {base_url}")

        for path in self.payloads.dir_fuzz:
            if shutdown_event.is_set(): return
            
            test_url = f"{base_url}/{path.lstrip('/')}"
            try:
                response = await session.get(test_url)
                if response and response.status == 200:
                    severity = "Medium"
                    proof = f"Request to '{test_url}' returned HTTP 200 OK."
                    if "index of" in response.body.lower() and "parent directory" in response.body.lower():
                        severity = "High"
                        proof += " Directory listing appears to be enabled."
                    
                    evidence = Evidence(request=response.request, response=response)
                    self._log_vuln(url, "Information Disclosure / Exposed Path", severity, path, proof, evidence)
            except Exception:
                # 404s are expected and will raise exceptions, we can ignore them
                pass
    
    def _log_vuln(self, url, v_type, severity, payload, proof, evidence):
        vuln = Vulnerability(url, self.name, v_type, severity, payload, proof, self.remediation, evidence)
        self.results.append(vuln)
        logger.warning(f"[{self.name}] Finding: {v_type} - {payload} on {url}")

# -------------------- Main Scan Logic --------------------

MODULE_MAPPING = {
    "sqli": SQLiScanner,
    "xss": XSSScanner,
    "ssrf": SSRFScanner,
    "idor": IDORScanner,
    "headers": SecurityHeadersScanner,
    "redirect": OpenRedirectScanner,
    "dirfuzz": DirectoryFuzzer,
}

async def login(session: BrowserSession, auth_config: Dict):
    logger.info(f"Attempting login to {auth_config['login_url']}")
    try:
        await session.page.goto(auth_config['login_url'])
        await session.page.fill(auth_config['user_field_selector'], auth_config['username'])
        await session.page.fill(auth_config['pass_field_selector'], auth_config['password'])
        await session.page.click(auth_config['submit_selector'])
        await session.page.wait_for_load_state('networkidle')
        
        # Verify login
        if auth_config['success_indicator_type'] == 'url':
            if auth_config['success_indicator_value'] in session.page.url:
                logger.info("Login successful.")
                return True
        elif auth_config['success_indicator_type'] == 'selector':
            if await session.page.locator(auth_config['success_indicator_value']).count() > 0:
                logger.info("Login successful.")
                return True

        logger.error("Login failed. Check authentication configuration and credentials.")
        return False
    except Exception as e:
        logger.error(f"An error occurred during login: {e}")
        return False

async def scan_target(config: ScanConfig, payloads: Payloads, rate_limiter: RateLimiter):
    all_results: List[Vulnerability] = []
    start_time = time.time()
    
    async with BrowserSession(config, payloads, headless=config.headless) as session:
        # 1. Handle Authentication if configured
        if config.auth and config.auth.get('enabled', False):
            if not await login(session, config.auth):
                return [], 0 # Stop scan if login fails
        
        # 2. Crawl the target
        scannable_targets = await crawl(config, session, rate_limiter)

        # 3. Prepare scanner modules
        scanners = []
        for mod_name in config.modules:
            if mod_name in MODULE_MAPPING:
                scanners.append(MODULE_MAPPING[mod_name](config, payloads))
            else:
                logger.warning(f"Unknown module '{mod_name}' requested in config.")
        
        # 4. Run scanners
        logger.info(f"Starting scan with modules: {[s.name for s in scanners]}")
        
        scan_tasks = []
        for scanner in scanners:
            for url, target_data in scannable_targets.items():
                if shutdown_event.is_set(): break
                await rate_limiter.wait()
                task = scanner.run(session, target_data, url)
                scan_tasks.append(task)
            if shutdown_event.is_set(): break
        
        await asyncio.gather(*scan_tasks, return_exceptions=True)

        for scanner in scanners:
            all_results.extend(scanner.results)

    duration = time.time() - start_time
    return all_results, duration

# -------------------- Reporting --------------------
def generate_report(results: List[Vulnerability], target_url: str, duration: float, fmt: str, out_file: str):
    if fmt == "json":
        report_data = {
            "target": target_url,
            "duration_seconds": duration,
            "findings_count": len(results),
            "findings": [vars(r) for r in results]
        }
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, default=str)
    else: # HTML / MD
        env = Environment(loader=FileSystemLoader('.'))
        template_name = 'report_template.html' if fmt == 'html' else 'report_template.md'
        try:
            template = env.get_template(template_name)
            rendered_report = template.render(
                results=sorted(results, key=lambda x: ('Critical', 'High', 'Medium', 'Low', 'Info').index(x.severity)),
                target=target_url,
                duration=f"{duration:.2f}",
                scan_date=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(rendered_report)
        except Exception as e:
            logger.error(f"Failed to generate report from template {template_name}: {e}")
            logger.error("Please ensure 'report_template.html' exists in the same directory.")

# -------------------- CLI & Main --------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Full Advanced Web Security Scanner")
    parser.add_argument("-c", "--config", required=True, help="Path to the main config YAML file (e.g., config.yml)")
    parser.add_argument("-p", "--payloads", required=True, help="Path to the payloads YAML file (e.g., payloads.yml)")
    parser.add_argument("-o", "--output", help="Output report filename")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging and run browser in non-headless mode")
    return parser.parse_args()

def main():
    args = parse_args()
    
    try:
        config = load_config(args.config)
        payloads = load_payloads(args.payloads)
    except FileNotFoundError as e:
        logger.error(f"Configuration or payload file not found: {e}")
        return
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return

    if args.debug:
        config.debug = True
        config.headless = False
        logger.setLevel(logging.DEBUG)
    
    # Start OOB server in a background thread
    oob_executor = ThreadPoolExecutor(max_workers=1)
    oob_future = oob_executor.submit(run_oob_server, config.oob_listen_port)

    # Setup main async loop
    loop = asyncio.get_event_loop()
    results, duration = [], 0
    
    try:
        rate_limiter = RateLimiter(config.rate_limit_per_sec)
        results, duration = loop.run_until_complete(scan_target(config, payloads, rate_limiter))
    except KeyboardInterrupt:
        logger.info("User interrupted scan.")
    except Exception as e:
        logger.error(f"An unhandled exception occurred during the scan: {e}")
        traceback.print_exc()
    finally:
        shutdown_event.set()
        oob_executor.shutdown(wait=False) # Will not wait for server to stop
        loop.close()

    if results:
        report_fmt = config.report_format
        ext = 'md' if report_fmt == 'markdown' else report_fmt
        report_filename = args.output or f"scan_report_{urllib.parse.urlparse(config.target_url).netloc}.{ext}"
        
        generate_report(results, config.target_url, duration, report_fmt, report_filename)
        logger.info(f"Scan complete. Found {len(results)} vulnerabilities. Report saved to {report_filename}")
    else:
        logger.info("Scan complete. No vulnerabilities found.")

if __name__ == "__main__":
    # Create a dummy report template if it doesn't exist
    if not Path("report_template.html").exists():
        with open("report_template.html", "w") as f:
            f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Scan Report for {{ target }}</title>
    <style>
        body { font-family: sans-serif; margin: 2em; } h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; } th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; } pre { white-space: pre-wrap; word-wrap: break-word; background: #eee; padding: 5px; border: 1px solid #ccc; }
        .severity-Critical { background-color: #ff4d4d; color: white; } .severity-High { background-color: #ff9933; }
        .severity-Medium { background-color: #ffff66; } .severity-Low { background-color: #87ceeb; }
        .details { cursor: pointer; } .evidence { display: none; }
    </style>
</head>
<body>
    <h1>Web Security Scan Report</h1>
    <p><strong>Target:</strong> <a href="{{ target }}" target="_blank">{{ target }}</a></p>
    <p><strong>Scan Date:</strong> {{ scan_date }}</p>
    <p><strong>Duration:</strong> {{ duration }} seconds</p>
    <h2>Summary: Found {{ results|length }} vulnerabilities</h2>
    {% if results %}
        <table>
            <thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Details</th></tr></thead>
            <tbody>
            {% for item in results %}
                <tr>
                    <td class="severity-{{ item.severity }}">{{ item.severity }}</td>
                    <td>{{ item.type }}</td>
                    <td><a href="{{ item.url }}" target="_blank">{{ item.url }}</a></td>
                    <td class="details" onclick="toggleEvidence('evidence-{{ loop.index }}')">Click to see details &#9662;</td>
                </tr>
                <tr class="evidence" id="evidence-{{ loop.index }}"><td colspan="4">
                    <p><strong>Module:</strong> {{ item.module }}</p>
                    <p><strong>Payload:</strong> <pre>{{ item.payload }}</pre></p>
                    <p><strong>Proof:</strong> {{ item.proof }}</p>
                    <p><strong>Remediation:</strong> {{ item.remediation }}</p>
                    {% if item.evidence %}
                        <h3>Evidence</h3>
                        <h4>Request</h4>
                        <pre>{{ item.evidence.request.method }} {{ item.evidence.request.url }}\n{% for h,v in item.evidence.request.headers.items() %}{{h}}: {{v}}\n{% endfor %}\n\n{{ item.evidence.request.post_data }}</pre>
                        {% if item.evidence.response %}
                        <h4>Response (Status: {{ item.evidence.response.status }})</h4>
                        <pre>{% for h,v in item.evidence.response.headers.items() %}{{h}}: {{v}}\n{% endfor %}</pre>
                        {% endif %}
                    {% endif %}
                </td></tr>
            {% endfor %}
            </tbody>
        </table>
    {% else %}
        <p>No vulnerabilities found.</p>
    {% endif %}
    <script>
        function toggleEvidence(id) {
            var x = document.getElementById(id);
            if (x.style.display === 'none' || x.style.display === '') { x.style.display = 'table-row'; }
            else { x.style.display = 'none'; }
        }
    </script>
</body>
</html>""")
    main()
