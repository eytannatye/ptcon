#!/usr/bin/env python3
"""
PT Automation Orchestrator MVP
Runs 11 security checks on target domains and generates comprehensive reports.
"""

import json
import subprocess
import concurrent.futures
import sys
import pathlib
from pathlib import Path
import time
import os
import signal
import logging
from datetime import datetime
from jinja2 import Template
import requests
from dotenv import load_dotenv
import urllib3
import random

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from .env file
load_dotenv()

OUTDIR = pathlib.Path("pt_output")
OUTDIR.mkdir(exist_ok=True)
(OUTDIR / "screenshots").mkdir(exist_ok=True)
(OUTDIR / "logs").mkdir(exist_ok=True)

# Setup logging
LOG_DIR = OUTDIR / "logs"
# Use stderr for logging to avoid conflict with progress bar on stdout
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / f"pt_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(sys.stderr)  # Changed to stderr to not interfere with progress
    ]
)
logger = logging.getLogger(__name__)

# Timeout values (in seconds)
TIMEOUTS = {
    "headers": 30,
    "subdomains": 120,
    "nmap": 600,
    "nuclei": 600,
    "screenshot": 60,
    "wayback": 60,
    "sucuri": 60,
    "checkhost": 60,
    "securityheaders": 60,
    "shodan": 60,
    "ssl": 600,
    "tech_detection": 30,
    "dns": 30,
    "js_endpoints": 120,
    "secretfinder": 300,
    "cookies": 180,
}

# Default timeout
DEFAULT_TIMEOUT = 300


def run_cmd(cmd, timeout=DEFAULT_TIMEOUT, task_name="unknown"):
    """Execute shell command and return results with logging. Kills process tree on timeout."""
    start_time = time.time()
    logger.info(f"[{task_name}] Starting command: {cmd[:100]}...")
    logger.info(f"[{task_name}] Timeout set to: {timeout}s")
    
    # Log command for debugging (full command if not too long)
    if len(cmd) < 200:
        logger.debug(f"[{task_name}] Full command: {cmd}")
    
    process = None
    try:
        # Use Popen to have better control over process termination
        # Start in new session/process group so we can kill all children on timeout
        process = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True  # Create new process group for proper cleanup
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            elapsed = time.time() - start_time
            
            if elapsed > timeout * 0.8:
                logger.warning(f"[{task_name}] Command took {elapsed:.1f}s (close to timeout of {timeout}s)")
            
            if process.returncode != 0:
                logger.error(f"[{task_name}] Command failed with return code {process.returncode}")
                logger.error(f"[{task_name}] STDERR: {stderr[:500]}")
            else:
                logger.info(f"[{task_name}] Command completed successfully in {elapsed:.1f}s")
            
            return {
                "cmd": cmd,
                "rc": process.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "duration": elapsed,
            }
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            logger.error(f"[{task_name}] ⚠️ TIMEOUT after {timeout}s (actual time: {elapsed:.1f}s)")
            logger.error(f"[{task_name}] Command that timed out: {cmd[:200]}")
            
            # Kill the process and its children
            if process:
                logger.warning(f"[{task_name}] Killing process (PID: {process.pid}) and its children...")
                try:
                    # On Unix systems, kill the process group to kill children too
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    time.sleep(0.5)
                    # Force kill if still running
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass  # Process already dead
                    logger.info(f"[{task_name}] Process terminated")
                except (ProcessLookupError, OSError) as e:
                    logger.warning(f"[{task_name}] Could not kill process: {e}")
                    # Fallback: try to kill just the process
                    try:
                        process.kill()
                        process.wait(timeout=1)
                    except:
                        pass
            
            return {
                "cmd": cmd,
                "rc": -1,
                "stdout": "",
                "stderr": f"timeout after {timeout}s",
                "duration": elapsed,
            }
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[{task_name}] ❌ EXCEPTION after {elapsed:.1f}s: {type(e).__name__}: {str(e)}")
        logger.error(f"[{task_name}] Command that caused exception: {cmd[:200]}")
        
        # Clean up process if it exists
        if process and process.poll() is None:
            try:
                process.kill()
                process.wait(timeout=1)
            except:
                pass
        
        return {
            "cmd": cmd,
            "rc": -2,
            "stdout": "",
            "stderr": str(e),
            "duration": elapsed,
        }


def create_stealth_browser_context(playwright_instance, viewport_size=None):
    """
    Create a stealth browser context with enhanced fingerprinting to bypass WAF.
    
    Args:
        playwright_instance: Playwright instance from playwright.sync_api
        viewport_size: Optional tuple (width, height). If None, randomly selected.
    
    Returns:
        Tuple of (browser, context, page) with stealth configuration
    """
    try:
        # Apply stealth enhancements using undetected-playwright if available
        from undetected_playwright import stealth_sync
        stealth_sync(playwright_instance.chromium)
        logger.debug(f"[WAF] Applied undetected-playwright stealth enhancements")
    except (ImportError, AttributeError):
        # If undetected-playwright not available, use manual stealth only
        logger.debug(f"[WAF] Using manual stealth only (undetected-playwright not available)")
    except Exception as e:
        logger.debug(f"[WAF] stealth_sync failed: {str(e)[:50]}, using manual stealth")
    
    # Realistic User-Agents (updated Chrome/Firefox)
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ]
    
    # Realistic viewport sizes
    viewports = [
        {'width': 1920, 'height': 1080},
        {'width': 1366, 'height': 768},
        {'width': 1440, 'height': 900},
        {'width': 1536, 'height': 864},
        {'width': 1280, 'height': 720},
    ]
    
    # Select random viewport if not specified
    if viewport_size:
        viewport = {'width': viewport_size[0], 'height': viewport_size[1]}
    else:
        viewport = random.choice(viewports)
    
    # Realistic locales and timezones
    locales = ['en-US', 'en-GB', 'en-CA', 'en-AU']
    locale = random.choice(locales)
    
    # Launch browser with stealth enhancements
    browser = playwright_instance.chromium.launch(
        headless=True,
        args=[
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-blink-features=AutomationControlled',  # Hide automation
            '--disable-features=IsolateOrigins,site-per-process',
        ]
    )
    
    # Create context with enhanced fingerprinting
    context = browser.new_context(
        viewport=viewport,
        user_agent=random.choice(user_agents),
        locale=locale,
        timezone_id='America/New_York',  # Realistic timezone
        permissions=['geolocation', 'notifications'],
        extra_http_headers={
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': f'{locale},en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        },
        # Override webdriver detection
        java_script_enabled=True,
        ignore_https_errors=True,
        # Realistic colors
        color_scheme='light',
        reduced_motion='no-preference',
        # Realistic device
        device_scale_factor=1,
        has_touch=False,
        is_mobile=False,
    )
    
    # Execute JavaScript to further hide automation
    page = context.new_page()
    
    # Remove webdriver property and enhance fingerprint
    page.add_init_script(f"""
        Object.defineProperty(navigator, 'webdriver', {{
            get: () => undefined
        }});
        
        // Override plugins
        Object.defineProperty(navigator, 'plugins', {{
            get: () => [1, 2, 3, 4, 5]
        }});
        
        // Override languages
        Object.defineProperty(navigator, 'languages', {{
            get: () => ['{locale}', 'en']
        }});
        
        // Override permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({{ state: Notification.permission }}) :
                originalQuery(parameters)
        );
    """)
    
    return browser, context, page


def wait_for_cloudflare_challenge(page, max_wait=30):
    """
    Wait for Cloudflare challenge to complete with smart detection.
    
    Args:
        page: Playwright page object
        max_wait: Maximum seconds to wait for challenge
    
    Returns:
        True if challenge detected and handled, False otherwise
    """
    challenge_indicators = [
        "Just a moment",
        "Checking your browser",
        "verify you are human",
        "Please wait",
        "DDoS protection by Cloudflare",
        "#cf-wrapper",  # Cloudflare wrapper element
    ]
    
    try:
        # Wait for page to load
        page.wait_for_selector("body", timeout=5000)
        
        # Check for challenge iframe
        iframe_count = page.locator("iframe[src*='challenges.cloudflare.com']").count()
        if iframe_count > 0:
            logger.info(f"[WAF] Cloudflare challenge iframe detected, waiting up to {max_wait}s...")
            # Wait for challenge to complete (check every 2 seconds)
            waited = 0
            while waited < max_wait:
                page.wait_for_timeout(2000)
                waited += 2
                
                # Check if challenge is gone
                current_iframe_count = page.locator("iframe[src*='challenges.cloudflare.com']").count()
                if current_iframe_count == 0:
                    # Check page text for challenge indicators
                    page_text = page.locator("body").text_content() or ""
                    if not any(indicator.lower() in page_text.lower() for indicator in challenge_indicators):
                        logger.info(f"[WAF] Challenge completed after {waited}s")
                        page.wait_for_timeout(2000)  # Extra wait for page render
                        return True
                
                # If still waiting and max time reached
                if waited >= max_wait:
                    logger.warning(f"[WAF] Challenge wait timeout ({max_wait}s), continuing anyway...")
                    return True
            return True
        else:
            # Check page text for challenge indicators
            page_text = page.locator("body").text_content() or ""
            if any(indicator.lower() in page_text.lower() for indicator in challenge_indicators):
                logger.info(f"[WAF] Cloudflare challenge text detected, waiting...")
                # Wait and check again
                page.wait_for_timeout(5000)
                page_text_after = page.locator("body").text_content() or ""
                if not any(indicator.lower() in page_text_after.lower() for indicator in challenge_indicators):
                    logger.info(f"[WAF] Challenge resolved")
                    return True
                else:
                    logger.warning(f"[WAF] Challenge still present after wait")
                    return False
            return False
                    
    except Exception as e:
        logger.debug(f"[WAF] Challenge detection error: {str(e)[:50]}")
        return False


def task_headers(domain):
    """Fetch and analyze HTTP headers."""
    start_time = time.time()
    logger.info(f"[HEADERS] Starting headers check for {domain}")
    
    # Use session to control redirects better
    session = requests.Session()
    session.verify = False  # Disable SSL verification warnings
    session.max_redirects = 30  # Increased limit for complex redirects
    
    # Track redirects to detect loops
    seen_urls = set()
    
    def check_redirect_loop(url):
        """Check if URL is part of a redirect loop."""
        if url in seen_urls:
            return True
        seen_urls.add(url)
        return False
    
    try:
        # Try HTTPS first
        try:
            logger.info(f"[HEADERS] Trying HTTPS connection (max 30 redirects)...")
            seen_urls.clear()
            seen_urls.add(f"https://{domain}")
            
            # Use GET instead of HEAD - some servers don't handle HEAD properly and return redirects
            response = session.get(
                f"https://{domain}",
                timeout=TIMEOUTS["headers"],
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
                stream=True  # Don't download body, just headers
            )
            
            # Check for redirect loop
            redirect_chain = [f"https://{domain}"] + [r.url for r in response.history] + [response.url]
            if len(redirect_chain) != len(set(redirect_chain)):
                logger.warning(f"[HEADERS] Redirect loop detected! Chain: {redirect_chain[-5:]}")
                raise requests.exceptions.TooManyRedirects("Redirect loop detected")
            headers_str = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
            http_version = "1.1"  # Default HTTP version
            if hasattr(response, 'raw') and hasattr(response.raw, 'version'):
                http_version = f"{response.raw.version/10:.1f}"
            elapsed = time.time() - start_time
            logger.info(f"[HEADERS] ✓ HTTPS succeeded in {elapsed:.1f}s (Status: {response.status_code}, {len(response.history)} redirects)")
            redirect_info = ""
            if response.history:
                redirect_info = f"\nRedirects followed: {len(response.history)}\nFinal URL: {response.url}"
            # CSP & Cookie Analysis
            csp_analysis = {}
            cookie_analysis = []
            referrer_policy = None
            
            # Parse Content-Security-Policy
            csp_header = response.headers.get('Content-Security-Policy', '')
            if csp_header:
                # Extract directives
                directives = {}
                weaknesses = []
                for directive in csp_header.split(';'):
                    directive = directive.strip()
                    if ' ' in directive:
                        key, value = directive.split(' ', 1)
                        directives[key.strip()] = value.strip()
                        # Check for weaknesses
                        if key.strip() in ['script-src', 'style-src'] and ('unsafe-inline' in value or "'unsafe-inline'" in value):
                            weaknesses.append(f"{key.strip()} contains 'unsafe-inline'")
                        if key.strip() == 'script-src' and ('unsafe-eval' in value or "'unsafe-eval'" in value):
                            weaknesses.append(f"{key.strip()} contains 'unsafe-eval'")
                
                # Check for missing important directives
                important_directives = ['default-src', 'script-src', 'style-src', 'img-src', 'connect-src']
                missing = [d for d in important_directives if d not in directives]
                
                csp_analysis = {
                    "present": True,
                    "directives": directives,
                    "weaknesses": weaknesses,
                    "missing_directives": missing
                }
            else:
                csp_analysis = {
                    "present": False,
                    "directives": {},
                    "weaknesses": [],
                    "missing_directives": ["Content-Security-Policy header not present"]
                }
            
            # Parse Set-Cookie headers
            if 'Set-Cookie' in response.headers:
                # Get all Set-Cookie headers (requests.get_list doesn't exist, so we parse manually)
                set_cookie_raw = response.headers.get('Set-Cookie', '')
                if isinstance(set_cookie_raw, str):
                    cookies_raw = [set_cookie_raw]
                else:
                    cookies_raw = set_cookie_raw if isinstance(set_cookie_raw, list) else [str(set_cookie_raw)]
                
                for cookie_str in cookies_raw:
                    cookie_info = {"raw": cookie_str}
                    # Extract cookie name
                    if '=' in cookie_str:
                        cookie_info["name"] = cookie_str.split('=')[0]
                    else:
                        cookie_info["name"] = "unknown"
                    
                    # Extract flags
                    cookie_info["secure"] = "Secure" in cookie_str
                    cookie_info["httponly"] = "HttpOnly" in cookie_str or "httponly" in cookie_str.lower()
                    cookie_info["samesite"] = None
                    if "SameSite=" in cookie_str or "samesite=" in cookie_str.lower():
                        samesite_part = [p for p in cookie_str.split(';') if 'samesite' in p.lower()]
                        if samesite_part:
                            samesite_value = samesite_part[0].split('=')[1].strip() if '=' in samesite_part[0] else None
                            cookie_info["samesite"] = samesite_value
                    
                    # Check for weaknesses
                    weaknesses = []
                    if not cookie_info["secure"]:
                        weaknesses.append("Missing Secure flag")
                    if not cookie_info["httponly"]:
                        weaknesses.append("Missing HttpOnly flag")
                    cookie_info["weaknesses"] = weaknesses
                    
                    cookie_analysis.append(cookie_info)
            
            # Parse Referrer-Policy
            referrer_policy = response.headers.get('Referrer-Policy', None)
            
            result = {
                "cmd": f"requests HEAD https://{domain}",
                "rc": 0,
                "stdout": f"HTTP/{http_version} {response.status_code} {response.reason}{redirect_info}\n{headers_str}",
                "stderr": "",
                "duration": elapsed,
                "csp_analysis": csp_analysis,
                "cookie_analysis": cookie_analysis,
                "referrer_policy": referrer_policy,
            }
            
            return ("headers", result)
        except requests.exceptions.TooManyRedirects as e:
            logger.warning(f"[HEADERS] HTTPS exceeded redirect limit: {str(e)}, trying HTTP with limited redirects...")
            # Fallback to HTTP with limited redirects
            seen_urls.clear()
            seen_urls.add(f"http://{domain}")
            
            # Create new session with fewer redirects for HTTP fallback
            session_http = requests.Session()
            session_http.verify = False
            session_http.max_redirects = 5  # Limit redirects to prevent infinite loops
            
            try:
                response = session_http.head(
                    f"http://{domain}",
                    timeout=TIMEOUTS["headers"],
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                
                # Check for redirect loop
                redirect_chain = [f"http://{domain}"] + [r.url for r in response.history] + [response.url]
                if len(redirect_chain) != len(set(redirect_chain)):
                    logger.warning(f"[HEADERS] Redirect loop detected in HTTP! Chain: {redirect_chain[-5:]}")
                    raise requests.exceptions.TooManyRedirects("Redirect loop detected in HTTP fallback")
                
                headers_str = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                http_version = "1.1"
                if hasattr(response, 'raw') and hasattr(response.raw, 'version'):
                    http_version = f"{response.raw.version/10:.1f}"
                elapsed = time.time() - start_time
                logger.info(f"[HEADERS] ✓ HTTP succeeded in {elapsed:.1f}s (Status: {response.status_code}, {len(response.history)} redirects)")
                redirect_info = ""
                if response.history:
                    redirect_info = f"\nRedirects followed: {len(response.history)}\nFinal URL: {response.url}"
                
                # CSP & Cookie Analysis (same as HTTPS path)
                csp_analysis = {}
                cookie_analysis = []
                referrer_policy = None
                
                csp_header = response.headers.get('Content-Security-Policy', '')
                if csp_header:
                    directives = {}
                    weaknesses = []
                    for directive in csp_header.split(';'):
                        directive = directive.strip()
                        if ' ' in directive:
                            key, value = directive.split(' ', 1)
                            directives[key.strip()] = value.strip()
                            if key.strip() in ['script-src', 'style-src'] and ('unsafe-inline' in value or "'unsafe-inline'" in value):
                                weaknesses.append(f"{key.strip()} contains 'unsafe-inline'")
                            if key.strip() == 'script-src' and ('unsafe-eval' in value or "'unsafe-eval'" in value):
                                weaknesses.append(f"{key.strip()} contains 'unsafe-eval'")
                    important_directives = ['default-src', 'script-src', 'style-src', 'img-src', 'connect-src']
                    missing = [d for d in important_directives if d not in directives]
                    csp_analysis = {
                        "present": True,
                        "directives": directives,
                        "weaknesses": weaknesses,
                        "missing_directives": missing
                    }
                else:
                    csp_analysis = {
                        "present": False,
                        "directives": {},
                        "weaknesses": [],
                        "missing_directives": ["Content-Security-Policy header not present"]
                    }
                
                if 'Set-Cookie' in response.headers:
                    set_cookie_raw = response.headers.get('Set-Cookie', '')
                    cookies_raw = [set_cookie_raw] if isinstance(set_cookie_raw, str) else (set_cookie_raw if isinstance(set_cookie_raw, list) else [str(set_cookie_raw)])
                    for cookie_str in cookies_raw:
                        cookie_info = {"raw": cookie_str}
                        cookie_info["name"] = cookie_str.split('=')[0] if '=' in cookie_str else "unknown"
                        cookie_info["secure"] = "Secure" in cookie_str
                        cookie_info["httponly"] = "HttpOnly" in cookie_str or "httponly" in cookie_str.lower()
                        cookie_info["samesite"] = None
                        if "SameSite=" in cookie_str or "samesite=" in cookie_str.lower():
                            samesite_part = [p for p in cookie_str.split(';') if 'samesite' in p.lower()]
                            if samesite_part:
                                samesite_value = samesite_part[0].split('=')[1].strip() if '=' in samesite_part[0] else None
                                cookie_info["samesite"] = samesite_value
                        weaknesses = []
                        if not cookie_info["secure"]:
                            weaknesses.append("Missing Secure flag")
                        if not cookie_info["httponly"]:
                            weaknesses.append("Missing HttpOnly flag")
                        cookie_info["weaknesses"] = weaknesses
                        cookie_analysis.append(cookie_info)
                
                referrer_policy = response.headers.get('Referrer-Policy', None)
                
                return ("headers", {
                    "cmd": f"requests HEAD http://{domain}",
                    "rc": 0,
                    "stdout": f"HTTP/{http_version} {response.status_code} {response.reason}{redirect_info}\n{headers_str}",
                    "stderr": "",
                    "duration": elapsed,
                    "csp_analysis": csp_analysis,
                    "cookie_analysis": cookie_analysis,
                    "referrer_policy": referrer_policy,
                })
            except requests.exceptions.TooManyRedirects:
                # Even HTTP has too many redirects
                elapsed = time.time() - start_time
                logger.error(f"[HEADERS] ❌ Both HTTPS and HTTP exceeded redirect limits")
                return ("headers", {
                    "cmd": f"requests HEAD https://{domain} (fallback: http://{domain})",
                    "rc": -1,
                    "stdout": "",
                    "stderr": f"Exceeded redirect limits: HTTPS (10) and HTTP (5). Possible redirect loop.",
                    "duration": elapsed,
                })
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"[HEADERS] ❌ HTTP fallback also failed: {str(e)}")
                return ("headers", {
                    "cmd": f"requests HEAD https://{domain} (fallback: http://{domain})",
                    "rc": -1,
                    "stdout": "",
                    "stderr": f"HTTPS failed: {str(e)}. HTTP fallback also failed.",
                    "duration": elapsed,
                })
        except Exception as e:
            logger.warning(f"[HEADERS] HTTPS failed: {str(e)}, trying HTTP...")
            # Fallback to HTTP
            seen_urls.clear()
            seen_urls.add(f"http://{domain}")
            
            # Create new session with fewer redirects for HTTP fallback
            session_http = requests.Session()
            session_http.verify = False
            session_http.max_redirects = 5  # Limit redirects to prevent infinite loops
            
            try:
                response = session_http.head(
                    f"http://{domain}",
                    timeout=TIMEOUTS["headers"],
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                headers_str = "\n".join([f"{k}: {v}" for k, v in response.headers.items()])
                http_version = "1.1"
                if hasattr(response, 'raw') and hasattr(response.raw, 'version'):
                    http_version = f"{response.raw.version/10:.1f}"
                elapsed = time.time() - start_time
                logger.info(f"[HEADERS] ✓ HTTP succeeded in {elapsed:.1f}s (Status: {response.status_code})")
                redirect_info = ""
                if response.history:
                    redirect_info = f"\nRedirects followed: {len(response.history)}\nFinal URL: {response.url}"
                
                # CSP & Cookie Analysis (same as HTTPS path)
                csp_analysis = {}
                cookie_analysis = []
                referrer_policy = None
                
                csp_header = response.headers.get('Content-Security-Policy', '')
                if csp_header:
                    directives = {}
                    weaknesses = []
                    for directive in csp_header.split(';'):
                        directive = directive.strip()
                        if ' ' in directive:
                            key, value = directive.split(' ', 1)
                            directives[key.strip()] = value.strip()
                            if key.strip() in ['script-src', 'style-src'] and ('unsafe-inline' in value or "'unsafe-inline'" in value):
                                weaknesses.append(f"{key.strip()} contains 'unsafe-inline'")
                            if key.strip() == 'script-src' and ('unsafe-eval' in value or "'unsafe-eval'" in value):
                                weaknesses.append(f"{key.strip()} contains 'unsafe-eval'")
                    important_directives = ['default-src', 'script-src', 'style-src', 'img-src', 'connect-src']
                    missing = [d for d in important_directives if d not in directives]
                    csp_analysis = {
                        "present": True,
                        "directives": directives,
                        "weaknesses": weaknesses,
                        "missing_directives": missing
                    }
                else:
                    csp_analysis = {
                        "present": False,
                        "directives": {},
                        "weaknesses": [],
                        "missing_directives": ["Content-Security-Policy header not present"]
                    }
                
                if 'Set-Cookie' in response.headers:
                    set_cookie_raw = response.headers.get('Set-Cookie', '')
                    cookies_raw = [set_cookie_raw] if isinstance(set_cookie_raw, str) else (set_cookie_raw if isinstance(set_cookie_raw, list) else [str(set_cookie_raw)])
                    for cookie_str in cookies_raw:
                        cookie_info = {"raw": cookie_str}
                        cookie_info["name"] = cookie_str.split('=')[0] if '=' in cookie_str else "unknown"
                        cookie_info["secure"] = "Secure" in cookie_str
                        cookie_info["httponly"] = "HttpOnly" in cookie_str or "httponly" in cookie_str.lower()
                        cookie_info["samesite"] = None
                        if "SameSite=" in cookie_str or "samesite=" in cookie_str.lower():
                            samesite_part = [p for p in cookie_str.split(';') if 'samesite' in p.lower()]
                            if samesite_part:
                                samesite_value = samesite_part[0].split('=')[1].strip() if '=' in samesite_part[0] else None
                                cookie_info["samesite"] = samesite_value
                        weaknesses = []
                        if not cookie_info["secure"]:
                            weaknesses.append("Missing Secure flag")
                        if not cookie_info["httponly"]:
                            weaknesses.append("Missing HttpOnly flag")
                        cookie_info["weaknesses"] = weaknesses
                        cookie_analysis.append(cookie_info)
                
                referrer_policy = response.headers.get('Referrer-Policy', None)
                
                return ("headers", {
                    "cmd": f"requests HEAD http://{domain}",
                    "rc": 0,
                    "stdout": f"HTTP/{http_version} {response.status_code} {response.reason}{redirect_info}\n{headers_str}",
                    "stderr": "",
                    "duration": elapsed,
                    "csp_analysis": csp_analysis,
                    "cookie_analysis": cookie_analysis,
                    "referrer_policy": referrer_policy,
                })
            except requests.exceptions.TooManyRedirects:
                elapsed = time.time() - start_time
                logger.error(f"[HEADERS] ❌ HTTP also exceeded redirect limit after {elapsed:.1f}s")
                return ("headers", {
                    "cmd": f"requests HEAD {domain}",
                    "rc": -1,
                    "stdout": "",
                    "stderr": "Site has too many redirects (possible redirect loop). Limit: 5 redirects for HTTP.",
                    "duration": elapsed,
                    "csp_analysis": {"present": False, "directives": {}, "weaknesses": [], "missing_directives": []},
                    "cookie_analysis": [],
                    "referrer_policy": None,
                })
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[HEADERS] ❌ Failed after {elapsed:.1f}s: {type(e).__name__}: {str(e)}")
        return ("headers", {
            "cmd": f"requests HEAD {domain}",
            "rc": -1,
            "stdout": "",
            "stderr": str(e),
            "duration": elapsed,
            "csp_analysis": {"present": False, "directives": {}, "weaknesses": [], "missing_directives": []},
            "cookie_analysis": [],
            "referrer_policy": None,
        })


def task_dns(domain):
    """Perform DNS/Network Layer checks (A, AAAA, MX, TXT records)."""
    logger.info(f"[DNS] Starting DNS checks for {domain}")
    start_time = time.time()
    
    result = {
        "cmd": f"DNS queries for {domain}",
        "rc": 0,
        "stdout": "",
        "stderr": "",
        "duration": 0,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "txt_records": [],
        "spf": None,
        "dmarc": None,
        "dkim": None,
        "misconfigurations": [],
    }
    
    try:
        import dns.resolver
        
        # Resolve A records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            result["a_records"] = [str(r) for r in a_records]
            logger.info(f"[DNS] Found {len(result['a_records'])} A records")
        except Exception as e:
            logger.warning(f"[DNS] A record resolution failed: {str(e)}")
            result["misconfigurations"].append("No A records found")
        
        # Resolve AAAA records
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            result["aaaa_records"] = [str(r) for r in aaaa_records]
            logger.info(f"[DNS] Found {len(result['aaaa_records'])} AAAA records")
        except Exception as e:
            logger.debug(f"[DNS] AAAA record resolution failed (may be normal): {str(e)}")
        
        # Resolve MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            result["mx_records"] = [{"priority": r.preference, "host": str(r.exchange).rstrip('.')} for r in mx_records]
            logger.info(f"[DNS] Found {len(result['mx_records'])} MX records")
        except Exception as e:
            logger.debug(f"[DNS] MX record resolution failed (may be normal): {str(e)}")
        
        # Resolve TXT records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            txt_strings = []
            for r in txt_records:
                txt_str = ''.join([s.decode('utf-8') if isinstance(s, bytes) else str(s) for s in r.strings])
                txt_strings.append(txt_str)
            
            result["txt_records"] = txt_strings
            logger.info(f"[DNS] Found {len(result['txt_records'])} TXT records")
            
            # Parse TXT for SPF, DMARC, DKIM
            for txt in txt_strings:
                txt_upper = txt.upper()
                if txt.startswith('v=spf1') or 'V=SPF1' in txt_upper:
                    result["spf"] = txt
                    # Check SPF configuration
                    if '-all' not in txt and '~all' not in txt:
                        result["misconfigurations"].append("SPF record missing -all or ~all (weak policy)")
                    logger.info(f"[DNS] Found SPF record")
                
                if txt.startswith('v=DMARC1') or 'V=DMARC1' in txt_upper:
                    result["dmarc"] = txt
                    logger.info(f"[DNS] Found DMARC record")
                
                if txt.startswith('v=DKIM1') or 'V=DKIM1' in txt_upper or 'DKIM1' in txt_upper:
                    result["dkim"] = txt
                    logger.info(f"[DNS] Found DKIM record")
            
            # Check for missing DMARC
            if not result["dmarc"] and result["mx_records"]:
                result["misconfigurations"].append("DMARC record missing (email security risk)")
        except Exception as e:
            logger.warning(f"[DNS] TXT record resolution failed: {str(e)}")
        
        elapsed = time.time() - start_time
        result["duration"] = elapsed
        
        if result["misconfigurations"]:
            logger.warning(f"[DNS] Found {len(result['misconfigurations'])} misconfigurations")
        else:
            logger.info(f"[DNS] ✓ DNS check completed in {elapsed:.1f}s")
        
        return ("dns", result)
        
    except ImportError:
        elapsed = time.time() - start_time
        logger.error(f"[DNS] ❌ dnspython not installed")
        return ("dns", {
            "cmd": f"DNS queries",
            "rc": -1,
            "stdout": "",
            "stderr": "dnspython package not installed. Install with: pip install dnspython",
            "duration": elapsed,
        })
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[DNS] ❌ Failed after {elapsed:.1f}s: {str(e)}")
        return ("dns", {
            "cmd": f"DNS queries",
            "rc": -1,
            "stdout": "",
            "stderr": str(e),
            "duration": elapsed,
        })


def task_subdomains(domain):
    """Discover subdomains using subfinder and validate live subdomains."""
    logger.info(f"[SUBDOMAINS] Starting subdomain discovery for {domain}")
    out = OUTDIR / f"{domain}_subs.txt"
    cmd = f"subfinder -silent -d {domain} -o {out}"
    result = run_cmd(cmd, timeout=TIMEOUTS["subdomains"], task_name="SUBDOMAINS")
    
    # Read and clean subdomains
    if out.exists():
        all_subdomains = [s.strip() for s in out.read_text().strip().split("\n") if s.strip()]
        
        # Remove duplicates (case-insensitive)
        seen = set()
        unique_subdomains = []
        for sub in all_subdomains:
            sub_lower = sub.lower()
            if sub_lower not in seen:
                seen.add(sub_lower)
                unique_subdomains.append(sub)
        
        logger.info(f"[SUBDOMAINS] Found {len(all_subdomains)} total, {len(unique_subdomains)} unique subdomains")
        
        # Validate live subdomains (quick HTTP/HTTPS check) and get titles
        logger.info(f"[SUBDOMAINS] Validating {len(unique_subdomains)} subdomains...")
        live_subdomains = []
        
        for sub in unique_subdomains:
            subdomain_info = {"subdomain": sub}
            try:
                # Quick check - try HTTPS first, then HTTP
                for protocol in ['https', 'http']:
                    try:
                        resp = requests.get(
                            f"{protocol}://{sub}",
                            timeout=5,
                            allow_redirects=True,
                            verify=False,
                            headers={"User-Agent": "Mozilla/5.0"}
                        )
                        if resp.status_code < 500:  # Not a server error
                            live_subdomains.append(subdomain_info)
                            
                            # Try to extract title
                            try:
                                from bs4 import BeautifulSoup
                                soup = BeautifulSoup(resp.text[:50000], 'html.parser')  # Limit to first 50KB
                                title_tag = soup.find('title')
                                if title_tag and title_tag.text:
                                    subdomain_info["title"] = title_tag.text.strip()[:100]
                                else:
                                    subdomain_info["title"] = None
                            except Exception:
                                subdomain_info["title"] = None
                            
                            logger.debug(f"[SUBDOMAINS] ✓ {sub} is live ({protocol}, status: {resp.status_code})")
                            break
                    except requests.exceptions.RequestException:
                        continue
                else:
                    # Neither HTTPS nor HTTP worked
                    logger.debug(f"[SUBDOMAINS] ✗ {sub} is not responding")
            except Exception as e:
                logger.debug(f"[SUBDOMAINS] Error checking {sub}: {str(e)[:50]}")
                continue
        
        result["subdomains"] = live_subdomains
        result["subdomains_raw"] = unique_subdomains  # Keep raw for reference
        logger.info(f"[SUBDOMAINS] ✓ Found {len(live_subdomains)} live subdomains (out of {len(unique_subdomains)} unique)")
    else:
        result["subdomains"] = []
        logger.warning(f"[SUBDOMAINS] No output file found")
    
    return ("subdomains", result)


def task_nuclei(domain):
    """Run nuclei scan with technologies and misconfiguration templates."""
    logger.info(f"[NUCLEI] Starting nuclei scan for {domain}")
    out = OUTDIR / f"{domain}_nuclei.txt"
    # Use technologies and misconfiguration templates with info,low,medium severity
    # Expand ~ to full home path for reliability
    import os
    home_dir = os.path.expanduser("~")
    tech_templates = f"{home_dir}/nuclei-templates/technologies/"
    misconfig_templates = f"{home_dir}/nuclei-templates/misconfiguration/"
    cmd = f"nuclei -u https://{domain} -t {tech_templates} -t {misconfig_templates} -s info,low,medium -silent -o {out}"
    result = run_cmd(cmd, timeout=300, task_name="NUCLEI")  # 5 minutes timeout
    
    # Filter out template loading errors from stderr
    if result.get("stderr"):
        stderr_lines = result["stderr"].split("\n")
        # Filter out template loading related errors
        filtered_stderr = []
        for line in stderr_lines:
            line_lower = line.lower()
            # Skip template loading errors, but keep other important errors
            # Filter out [WRN] warnings and template loading related errors
            # Be specific to avoid filtering important error messages
            if any(skip in line_lower for skip in [
                "[wrn]", 
                "could not load template",
                "could not parse template",
                "failed to load template", 
                "template can't be used for offline matching",
                "unmarshal errors",
                "invalid action type",
                "field", "not found in type",
                "yaml: unmarshal"
            ]) and ("template" in line_lower or "unmarshal" in line_lower or "[wrn]" in line_lower):
                continue
            filtered_stderr.append(line)
        result["stderr"] = "\n".join(filtered_stderr).strip()
    
    # Also capture stdout for display (filtered)
    if result.get("stdout"):
        stdout_lines = result["stdout"].split("\n")
        filtered_stdout = []
        for line in stdout_lines:
            line_lower = line.lower()
            # Skip template loading messages from stdout too
            if any(skip in line_lower for skip in [
                "[wrn]",
                "could not load template",
                "could not parse template",
                "failed to load template",
                "template can't be used for offline matching",
                "unmarshal errors",
                "invalid action type",
                "yaml: unmarshal"
            ]) and ("template" in line_lower or "unmarshal" in line_lower or "[wrn]" in line_lower):
                continue
            filtered_stdout.append(line)
        result["output"] = "\n".join(filtered_stdout).strip()  # Keep filtered output for display
    
    # If process was killed (SIGTERM/SIGKILL), return code might be -15 or other negative
    # Check if we have partial results
    if result.get("rc") in (-15, -9) or result.get("rc", 0) < 0:
        if not out.exists():
            logger.warning(f"[NUCLEI] Process terminated (rc: {result.get('rc')}) and no output file created")
            result["stderr"] = (result.get("stderr", "") + f"\nProcess terminated before completion (return code: {result.get('rc')}). "
                              f"This may indicate a timeout or the process was killed. "
                              f"Consider increasing the timeout or checking for templates with syntax errors.").strip()
        else:
            logger.info(f"[NUCLEI] Process terminated but output file exists - parsing partial results...")
    
    # Parse text output if it exists
    findings = []
    if out.exists():
        try:
            content = out.read_text().strip()
            if content:
                # Parse text output line by line
                # Nuclei output format: [template-name] [protocol] [severity] [url] [matched-text]
                for line in content.split('\n'):
                    line = line.strip()
                    if line and not any(skip in line.lower() for skip in ['template', 'loading', '[wrn]', '[dbg]']):
                        # Parse nuclei output - format examples:
                        # [missing-sri] [http] [info] https://example.com
                        # [tech-detect:cloudflare] [http] [info] https://example.com
                        
                        # Try to extract structured data
                        finding_dict = None
                        if line.startswith('[') and ']' in line:
                            parts = line.split(']')
                            if len(parts) >= 4:
                                template = parts[0].replace('[', '').strip()
                                protocol = parts[1].replace('[', '').strip() if len(parts) > 1 else ''
                                severity = parts[2].replace('[', '').strip() if len(parts) > 2 else 'info'
                                url = parts[3].strip() if len(parts) > 3 else ''
                                
                                # Extract URL from JSON-like strings in URL part
                                if url.startswith('["') and url.endswith('"]'):
                                    # Extract URLs from JSON array format
                                    import json
                                    try:
                                        url_list = json.loads(url)
                                        if isinstance(url_list, list) and len(url_list) > 0:
                                            url = url_list[0]
                                    except:
                                        # If JSON parse fails, try to extract first URL manually
                                        if 'http' in url:
                                            url_match = re.search(r'https?://[^\s"\']+', url)
                                            if url_match:
                                                url = url_match.group(0)
                                
                                finding_dict = {
                                    'template': template if template else 'unknown',
                                    'protocol': protocol,
                                    'severity': severity if severity else 'info',
                                    'url': url,
                                    'full_line': line
                                }
                        
                        # Store structured dict if we could parse it, otherwise store as dict with full_line
                        if finding_dict:
                            findings.append(finding_dict)
                        else:
                            # Store raw line as dict for consistency
                            findings.append({
                                'template': 'unknown',
                                'protocol': 'http',
                                'severity': 'info',
                                'url': line[:200],
                                'full_line': line
                            })
                
                result["output"] = content  # Store full output
                result["findings"] = findings if findings else []
                
                if findings:
                    logger.info(f"[NUCLEI] Found {len(findings)} findings")
                else:
                    logger.info(f"[NUCLEI] Scan completed, no findings")
            else:
                result["output"] = "Nuclei scan completed. No findings."
                result["findings"] = []
        except Exception as e:
            logger.warning(f"[NUCLEI] Failed to parse output: {str(e)[:100]}")
            result["output"] = f"Output file exists but parsing failed: {str(e)[:100]}"
            result["findings"] = []
    else:
        # No output file - check if process completed
        if result.get("rc") == 0:
            result["output"] = "Nuclei scan completed. No findings."
        else:
            result["output"] = f"Nuclei scan completed with return code {result.get('rc')}. Check stderr for details."
        result["findings"] = []
    return ("nuclei", result)


def task_screenshot(domain):
    """Capture screenshot using Playwright with WAF bypass."""
    start_time = time.time()
    logger.info(f"[SCREENSHOT] Starting screenshot capture for {domain}")
    try:
        from playwright.sync_api import sync_playwright

        screenshot_path = OUTDIR / "screenshots" / f"{domain}.png"
        result = {"cmd": "playwright screenshot", "rc": 0, "stdout": "", "stderr": ""}

        with sync_playwright() as p:
            logger.info(f"[SCREENSHOT] Launching stealth browser...")
            browser = None
            context = None
            page = None
            try:
                # Use stealth browser context with WAF bypass
                browser, context, page = create_stealth_browser_context(p, viewport_size=(1024, 768))
                
                # Try HTTPS first, then HTTP
                try:
                    logger.info(f"[SCREENSHOT] Trying HTTPS...")
                    page.goto(f"https://{domain}", timeout=TIMEOUTS["screenshot"] * 1000, wait_until="domcontentloaded")
                    
                    # Wait for Cloudflare challenges with enhanced detection
                    wait_for_cloudflare_challenge(page, max_wait=20)
                    
                    # Wait for page to fully load and render
                    page.wait_for_timeout(3000)  # Wait 3 seconds for content to render
                    try:
                        page.wait_for_load_state("networkidle", timeout=10000)  # Wait for network to be idle
                    except:
                        page.wait_for_load_state("load", timeout=5000)  # Fallback to load
                    
                    # Check if page has content - if body is empty, wait more
                    body_content = page.evaluate("() => document.body ? document.body.innerText.length : 0")
                    if body_content < 100:
                        logger.warning(f"[SCREENSHOT] Page content seems minimal ({body_content} chars), waiting more...")
                        page.wait_for_timeout(5000)
                        body_content = page.evaluate("() => document.body ? document.body.innerText.length : 0")
                        logger.info(f"[SCREENSHOT] After additional wait: {body_content} chars")
                    
                    logger.info(f"[SCREENSHOT] ✓ HTTPS page loaded ({body_content} chars of content)")
                except Exception as e:
                    logger.warning(f"[SCREENSHOT] HTTPS failed: {str(e)[:100]}, trying HTTP...")
                    page.goto(f"http://{domain}", timeout=TIMEOUTS["screenshot"] * 1000, wait_until="domcontentloaded")
                    wait_for_cloudflare_challenge(page, max_wait=15)
                    page.wait_for_timeout(3000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=10000)
                    except:
                        page.wait_for_load_state("load", timeout=5000)
                    
                    body_content = page.evaluate("() => document.body ? document.body.innerText.length : 0")
                    if body_content < 100:
                        page.wait_for_timeout(5000)
                        body_content = page.evaluate("() => document.body ? document.body.innerText.length : 0")
                    logger.info(f"[SCREENSHOT] ✓ HTTP page loaded ({body_content} chars of content)")
                
                logger.info(f"[SCREENSHOT] Taking screenshot...")
                # Take screenshot with higher quality
                page.screenshot(path=str(screenshot_path), full_page=False, scale='css', type='png')
                elapsed = time.time() - start_time
                logger.info(f"[SCREENSHOT] ✓ Screenshot saved to {screenshot_path} in {elapsed:.1f}s")
                result["stdout"] = f"Screenshot saved to {screenshot_path}"
                # Use relative path from HTML report location
                result["screenshot_path"] = f"screenshots/{screenshot_path.name}"
                result["duration"] = elapsed
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"[SCREENSHOT] ❌ Failed after {elapsed:.1f}s: {str(e)}")
                result["rc"] = -1
                result["stderr"] = f"Screenshot failed: {str(e)}"
                result["duration"] = elapsed
            finally:
                # Clean up in correct order
                try:
                    if page:
                        page.close()
                except:
                    pass
                try:
                    if context:
                        context.close()
                except:
                    pass
                try:
                    if browser:
                        browser.close()
                except:
                    pass
                logger.debug(f"[SCREENSHOT] Browser closed")

        return ("screenshot", result)
    except ImportError:
        elapsed = time.time() - start_time
        logger.error(f"[SCREENSHOT] Playwright not installed")
        return (
            "screenshot",
            {
                "cmd": "playwright screenshot",
                "rc": -1,
                "stdout": "",
                "stderr": "Playwright not installed. Run: pip install playwright && playwright install chromium",
                "duration": elapsed,
            },
        )
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[SCREENSHOT] ❌ Exception: {type(e).__name__}: {str(e)}")
        return ("screenshot", {"cmd": "playwright screenshot", "rc": -2, "stdout": "", "stderr": str(e), "duration": elapsed})


def task_cookies(domain):
    """Analyze cookies with Playwright, accepting cookie banners if present."""
    logger.info(f"[COOKIES] Starting cookie analysis for {domain}")
    start_time = time.time()
    
    try:
        from playwright.sync_api import sync_playwright
        from http.cookiejar import Cookie
        
        screenshot_path = OUTDIR / "screenshots" / f"{domain}_cookies.png"
        result = {"cmd": "playwright cookie analysis", "rc": 0, "stdout": "", "stderr": ""}
        
        with sync_playwright() as p:
            browser = None
            context = None
            page = None
            try:
                browser, context, page = create_stealth_browser_context(p, viewport_size=(1920, 1080))
                
                # Navigate to domain
                try:
                    logger.info(f"[COOKIES] Navigating to https://{domain}...")
                    page.goto(f"https://{domain}", timeout=60000, wait_until="domcontentloaded")
                    wait_for_cloudflare_challenge(page, max_wait=20)
                except Exception as e:
                    logger.warning(f"[COOKIES] HTTPS failed: {str(e)[:100]}, trying HTTP...")
                    page.goto(f"http://{domain}", timeout=60000, wait_until="domcontentloaded")
                    wait_for_cloudflare_challenge(page, max_wait=15)
                
                # Wait a bit for page to load
                page.wait_for_timeout(2000)
                
                # Try to accept cookie banners - common selectors
                cookie_selectors = [
                    'button:has-text("Accept")',
                    'button:has-text("Accept All")',
                    'button:has-text("I Accept")',
                    'button:has-text("Agree")',
                    'button:has-text("OK")',
                    'button:has-text("Allow")',
                    'button:has-text("Allow All")',
                    'button[id*="accept"]',
                    'button[class*="accept"]',
                    'button[id*="cookie"]',
                    'button[class*="cookie"]',
                    '[id*="cookie"] button',
                    '[class*="cookie"] button',
                    'button[data-consent="accept"]',
                    'button[data-accept="true"]',
                    '#cookie-accept',
                    '.cookie-accept',
                    '#accept-cookies',
                    '.accept-cookies',
                    '#cookie-consent-accept',
                    '.cookie-consent-accept',
                ]
                
                cookie_accepted = False
                for selector in cookie_selectors:
                    try:
                        element = page.locator(selector).first
                        if element.is_visible(timeout=1000):
                            logger.info(f"[COOKIES] Found cookie banner with selector: {selector}, clicking...")
                            element.click()
                            page.wait_for_timeout(1000)  # Wait for banner to disappear
                            cookie_accepted = True
                            logger.info(f"[COOKIES] ✓ Cookie banner accepted")
                            break
                    except Exception:
                        continue
                
                if not cookie_accepted:
                    logger.info(f"[COOKIES] No cookie banner found or couldn't accept automatically")
                
                # Wait for any additional cookies to be set
                page.wait_for_timeout(3000)
                
                # Wait for page to fully load
                try:
                    page.wait_for_load_state("load", timeout=5000)
                except:
                    pass
                
                # Navigate through a few pages to trigger more cookies
                try:
                    # Try clicking on links or navigating
                    links = page.locator('a').all()
                    if len(links) > 0:
                        try:
                            links[0].click(timeout=3000)
                            page.wait_for_timeout(2000)
                            page.wait_for_load_state("load", timeout=3000)
                        except:
                            pass
                except:
                    pass
                
                # Wait a bit more for all cookies to be fully set
                page.wait_for_timeout(3000)
                
                # Get all cookies BEFORE screenshot
                cookies = context.cookies()
                logger.info(f"[COOKIES] Found {len(cookies)} cookies")
                
                # Analyze cookies
                cookie_analysis = []
                for cookie in cookies:
                    cookie_info = {
                        "name": cookie.get("name", "unknown"),
                        "value": cookie.get("value", "")[:50] + "..." if len(cookie.get("value", "")) > 50 else cookie.get("value", ""),
                        "domain": cookie.get("domain", ""),
                        "path": cookie.get("path", "/"),
                        "secure": cookie.get("secure", False),
                        "httpOnly": cookie.get("httpOnly", False),
                        "sameSite": cookie.get("sameSite", "None"),
                        "expires": cookie.get("expires", -1),
                        "session": cookie.get("expires", -1) == -1,
                    }
                    
                    # Check for weaknesses
                    weaknesses = []
                    if not cookie_info["secure"]:
                        weaknesses.append("Missing Secure flag")
                    if not cookie_info["httpOnly"]:
                        weaknesses.append("Missing HttpOnly flag")
                    if cookie_info["sameSite"] not in ["Strict", "Lax"]:
                        weaknesses.append(f"SameSite={cookie_info['sameSite']} (should be Strict or Lax)")
                    if cookie_info["session"]:
                        weaknesses.append("Session cookie (no expiration)")
                    
                    cookie_info["weaknesses"] = weaknesses
                    cookie_analysis.append(cookie_info)
                
                # Navigate to a page that shows cookies (like browser DevTools or a cookie management page)
                # OR take screenshot showing the cookies banner acceptance status
                # For now, we'll take screenshot after cookies are set, showing the page state
                
                # Take screenshot AFTER cookies are collected - show the final page state
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except:
                    page.wait_for_timeout(3000)
                
                # Verify page has content before screenshot
                body_content = page.evaluate("() => document.body ? document.body.innerText.length : 0")
                logger.info(f"[COOKIES] Page content: {body_content} chars before screenshot")
                
                # Screenshot should show the page AFTER cookies were set and banner was accepted
                # This gives context about what cookies were triggered
                page.screenshot(path=str(screenshot_path), full_page=False, scale='css', type='png')
                result["screenshot_path"] = f"screenshots/{screenshot_path.name}"
                
                elapsed = time.time() - start_time
                result["duration"] = elapsed
                result["cookies"] = cookie_analysis
                result["cookies_count"] = len(cookie_analysis)
                result["cookie_banner_accepted"] = cookie_accepted
                result["stdout"] = f"Found {len(cookie_analysis)} cookies. Cookie banner accepted: {cookie_accepted}"
                
                logger.info(f"[COOKIES] ✓ Analysis completed in {elapsed:.1f}s")
                return ("cookies", result)
                
            finally:
                try:
                    if browser:
                        browser.close()
                except:
                    pass
                    
    except ImportError:
        elapsed = time.time() - start_time
        logger.error(f"[COOKIES] Playwright not installed")
        return ("cookies", {
            "cmd": "cookie analysis",
            "rc": -1,
            "stdout": "",
            "stderr": "Playwright not installed",
            "duration": elapsed,
            "cookies": [],
            "cookies_count": 0,
        })
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[COOKIES] ❌ Failed: {str(e)}")
        return ("cookies", {
            "cmd": "cookie analysis",
            "rc": -2,
            "stdout": "",
            "stderr": str(e),
            "duration": elapsed,
            "cookies": [],
            "cookies_count": 0,
        })


def task_secretfinder(domain):
    """Find secrets in JavaScript files using SecretFinder."""
    logger.info(f"[SECRETFINDER] Starting SecretFinder scan for {domain}")
    start_time = time.time()
    out = OUTDIR / f"{domain}_secrets.txt"
    
    # Path to SecretFinder
    secretfinder_path = Path(__file__).parent / "tools" / "secretfinder" / "SecretFinder.py"
    
    try:
        # Use SecretFinder with extract mode to analyze the domain
        # Output to CLI format for easier parsing
        cmd = f"python3 {secretfinder_path} -i https://{domain} -e -o cli"
        result = run_cmd(cmd, timeout=TIMEOUTS.get("secretfinder", 300), task_name="SECRETFINDER")
        
        # Parse output
        secrets = []
        if result.get("stdout"):
            # SecretFinder CLI output format: [secret_type] [value] [context]
            for line in result.get("stdout", "").split('\n'):
                line = line.strip()
                if line and not any(skip in line.lower() for skip in ['url:', '[+]', '[-]', 'error']):
                    secrets.append(line)
        
        elapsed = time.time() - start_time
        result["secrets"] = secrets
        result["secrets_count"] = len(secrets)
        result["output"] = result.get("stdout", "")
        
        if secrets:
            logger.info(f"[SECRETFINDER] ✓ Found {len(secrets)} secrets")
        else:
            logger.info(f"[SECRETFINDER] ✓ Scan completed, no secrets found")
        
        return ("secretfinder", result)
        
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[SECRETFINDER] ❌ Failed after {elapsed:.1f}s: {str(e)}")
        return ("secretfinder", {
            "cmd": f"SecretFinder scan",
            "rc": -1,
            "stdout": "",
            "stderr": str(e),
            "duration": elapsed,
            "secrets": [],
            "secrets_count": 0,
        })


def task_js_endpoints(domain):
    """Extract JavaScript endpoints using LinkFinder or regex fallback."""
    logger.info(f"[JS_ENDPOINTS] Starting JavaScript endpoint extraction for {domain}")
    start_time = time.time()
    
    endpoints = []
    linkfinder_used = False
    
    # Check if LinkFinder is available
    linkfinder_available = False
    try:
        result_check = run_cmd("which linkfinder", timeout=5, task_name="JS_ENDPOINTS_CHECK")
        if result_check.get("rc") == 0 and result_check.get("stdout", "").strip():
            linkfinder_available = True
        else:
            # Try linkfinder --version
            result_version = run_cmd("linkfinder --version", timeout=5, task_name="JS_ENDPOINTS_CHECK")
            if result_version.get("rc") == 0:
                linkfinder_available = True
    except:
        pass
    
    try:
        # Fetch main page to find JavaScript files
        js_files = []
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=30, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                if response.status_code < 500:
                    # Extract JS file URLs from HTML
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(response.text[:200000], 'html.parser')  # Limit to first 200KB
                    
                    # Find script tags
                    for script in soup.find_all('script'):
                        src = script.get('src')
                        if src:
                            # Convert relative URLs to absolute
                            if src.startswith('//'):
                                src = f"{protocol}:{src}"
                            elif src.startswith('/'):
                                src = f"{protocol}://{domain}{src}"
                            elif not src.startswith('http'):
                                src = f"{protocol}://{domain}/{src}"
                            
                            if src not in js_files:
                                js_files.append(src)
                    
                    # Also find JS files in link tags (for preload, etc.)
                    for link in soup.find_all('link', rel='preload'):
                        href = link.get('href')
                        if href and ('.js' in href or 'javascript' in link.get('as', '')):
                            if href.startswith('//'):
                                href = f"{protocol}:{href}"
                            elif href.startswith('/'):
                                href = f"{protocol}://{domain}{href}"
                            elif not href.startswith('http'):
                                href = f"{protocol}://{domain}/{href}"
                            
                            if href not in js_files:
                                js_files.append(href)
                    
                    logger.info(f"[JS_ENDPOINTS] Found {len(js_files)} JavaScript files")
                    break
            except Exception as e:
                logger.debug(f"[JS_ENDPOINTS] {protocol} failed: {str(e)[:50]}")
                continue
        
        # Process JS files with LinkFinder or regex
        if linkfinder_available and js_files:
            linkfinder_used = True
            logger.info(f"[JS_ENDPOINTS] Using LinkFinder to extract endpoints...")
            
            for js_url in js_files[:10]:  # Limit to first 10 JS files
                try:
                    cmd = f"linkfinder -i {js_url} -o cli"
                    result_cmd = run_cmd(cmd, timeout=30, task_name="JS_ENDPOINTS")
                    
                    if result_cmd.get("rc") == 0 and result_cmd.get("stdout"):
                        # Parse LinkFinder output
                        output = result_cmd.get("stdout", "")
                        for line in output.split('\n'):
                            line = line.strip()
                            if line and (line.startswith('http://') or line.startswith('https://') or line.startswith('/')):
                                if line not in endpoints:
                                    endpoints.append(line)
                except Exception as e:
                    logger.debug(f"[JS_ENDPOINTS] LinkFinder failed for {js_url}: {str(e)[:50]}")
                    continue
        
        # Fallback to regex extraction if LinkFinder not available or failed
        if not linkfinder_used and js_files:
            logger.info(f"[JS_ENDPOINTS] Using regex fallback to extract endpoints...")
            
            import re
            
            for js_url in js_files[:10]:  # Limit to first 10 JS files
                try:
                    response = requests.get(js_url, timeout=15, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                    if response.status_code < 500:
                        js_content = response.text[:50000]  # Limit to first 50KB
                        
                        # Regex patterns for endpoint extraction - improved patterns
                        patterns = [
                            r'https?://[^"\'\\s\)\]]+',  # Full URLs
                            r'/api/[^"\'\\s\)\]]+',  # API paths
                            r'/api/v\d+/[^"\'\\s\)\]]+',  # API versioned paths
                            r'/[a-zA-Z0-9_/]+\.json[^"\'\\s\)\]]*',  # JSON endpoints
                            r'/v\d+/[^"\'\\s\)\]]+',  # Versioned endpoints
                            r'/[a-zA-Z0-9_\-/]+/[a-zA-Z0-9_\-/]+',  # General path patterns (with hyphens)
                            r'"([^"]*(?:api|endpoint|url|path)[^"]*)"',  # Quoted strings containing api/endpoint/url/path
                            r"'([^']*(?:api|endpoint|url|path)[^']*)'",  # Single-quoted strings
                            r'fetch\(["\']([^"\']+)["\']',  # fetch() calls
                            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',  # axios calls
                            r'\.ajax\([^,]*["\']([^"\']+)["\']',  # jQuery ajax
                            r'url:\s*["\']([^"\']+)["\']',  # url: property
                        ]
                        
                        for pattern in patterns:
                            matches = re.findall(pattern, js_content, re.IGNORECASE)
                            for match in matches:
                                # Handle tuple matches (from groups)
                                if isinstance(match, tuple):
                                    match = match[0] if match[0] else match[1] if len(match) > 1 else None
                                if match and match not in endpoints and len(match) > 3:
                                    # Clean up match
                                    match = match.strip('\'"')
                                    # Skip common false positives and code snippets
                                    # Skip if it's too long (likely code, not endpoint)
                                    if len(match) > 200:
                                        continue
                                    # Skip if contains code patterns
                                    if any(pattern in match for pattern in ['require.config', 'function()', 'var config', 'module.exports', 'return ', '})', '{', '}']):
                                        continue
                                    # Skip common false positives
                                    skip_list = ['javascript:', 'data:', 'mailto:', '//cdn.', '//ajax.', 'css', '.css', '.js', '.png', '.jpg', '.svg', '.ico']
                                    if not any(skip in match.lower() for skip in skip_list):
                                        # Only add if it looks like a URL path or endpoint
                                        # Accept: paths starting with /, full URLs (http/https), or containing api/v/
                                        if (match.startswith('/') or match.startswith('http://') or match.startswith('https://') or 
                                            '/api/' in match.lower() or '/v' in match.lower() or match.count('/') >= 1):
                                            # Additional validation: must be at least 2 chars and not just punctuation
                                            if len(match) >= 2 and any(c.isalnum() for c in match):
                                                endpoints.append(match)
                                                logger.debug(f"[JS_ENDPOINTS] Found endpoint via regex: {match[:100]}")
                except Exception as e:
                    logger.debug(f"[JS_ENDPOINTS] Failed to fetch {js_url}: {str(e)[:50]}")
                    continue
        
        # Remove duplicates and sort
        endpoints = sorted(list(set(endpoints)))
        
        elapsed = time.time() - start_time
        
        logger.info(f"[JS_ENDPOINTS] ✓ Extracted {len(endpoints)} endpoints using {'LinkFinder' if linkfinder_used else 'regex fallback'}")
        
        result = {
            "cmd": f"JavaScript endpoint extraction ({'LinkFinder' if linkfinder_used else 'regex'})",
            "rc": 0,
            "stdout": "",
            "stderr": "",
            "duration": elapsed,
            "endpoints": endpoints,
            "endpoint_count": len(endpoints),
            "linkfinder_used": linkfinder_used,
            "js_files_found": len(js_files),
        }
        
        return ("js_endpoints", result)
        
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[JS_ENDPOINTS] ❌ Failed after {elapsed:.1f}s: {str(e)}")
        return ("js_endpoints", {
            "cmd": f"JavaScript endpoint extraction",
            "rc": -1,
            "stdout": "",
            "stderr": str(e),
            "duration": elapsed,
            "endpoints": [],
            "endpoint_count": 0,
            "linkfinder_used": False,
        })


def task_wayback(domain):
    """Query Wayback Machine CDX API."""
    start_time = time.time()
    logger.info(f"[WAYBACK] Starting Wayback Machine query for {domain}")
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&fl=original&collapse=urlkey"
        logger.info(f"[WAYBACK] Querying: {url[:80]}...")
        response = requests.get(url, timeout=TIMEOUTS["wayback"])
        response.raise_for_status()
        
        # Parse results - limit to 5000 URLs for performance
        lines = response.text.strip().split("\n")
        all_urls = [line.strip() for line in lines if line.strip()]
        urls = all_urls[:5000]  # Limit to first 5000 URLs for performance
        elapsed = time.time() - start_time
        
        if len(all_urls) > 5000:
            logger.info(f"[WAYBACK] ✓ Found {len(all_urls)} URLs, showing first 5000 in {elapsed:.1f}s")
        else:
            logger.info(f"[WAYBACK] ✓ Found {len(urls)} URLs in {elapsed:.1f}s")
        
        result = {
            "cmd": f"wayback API: {url}",
            "rc": 0,
            "stdout": response.text[:5000],  # Limit output size
            "stderr": "",
            "duration": elapsed,
        }
        result["urls_found"] = len(all_urls)  # Total found
        result["urls_displayed"] = len(urls)  # Displayed (limited)
        result["urls"] = urls  # Limited URLs for display
        
        return ("wayback", result)
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[WAYBACK] ❌ Failed after {elapsed:.1f}s: {str(e)}")
        return ("wayback", {"cmd": f"wayback API", "rc": -1, "stdout": "", "stderr": str(e), "duration": elapsed})


def task_sucuri(domain):
    """Check Sucuri SiteCheck."""
    start_time = time.time()
    logger.info(f"[SUCURI] Starting Sucuri SiteCheck for {domain}")
    try:
        # Sucuri SiteCheck - using their API endpoint if available, or scraping
        url = f"https://sitecheck.sucuri.net/api/v3/?scan={domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        logger.info(f"[SUCURI] Querying Sucuri API...")
        response = requests.get(url, headers=headers, timeout=TIMEOUTS["sucuri"])
        
        elapsed = time.time() - start_time
        result = {
            "cmd": f"sucuri API: {url}",
            "rc": 0,
            "stdout": "",
            "stderr": "",
            "duration": elapsed,
        }
        
        try:
            data = response.json()
            result["stdout"] = json.dumps(data, indent=2)
            result["data"] = data
            
            # Extract key information for display
            if isinstance(data, dict):
                result["ratings"] = data.get("ratings", {})
                result["recommendations"] = data.get("recommendations", {})
                result["software"] = data.get("software", {})
                result["tls_info"] = data.get("tls", {})
                
            logger.info(f"[SUCURI] ✓ Received JSON response in {elapsed:.1f}s")
        except:
            result["stdout"] = response.text[:5000]
            result["rc"] = 0  # Still successful even if not JSON
            logger.warning(f"[SUCURI] Response is not JSON, saved as text")
        
        return ("sucuri", result)
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[SUCURI] ❌ Failed after {elapsed:.1f}s: {str(e)}")
        return ("sucuri", {"cmd": f"sucuri API", "rc": -1, "stdout": "", "stderr": str(e), "duration": elapsed})


def task_checkhost(domain):
    """Check host via check-host.net API and capture screenshot of results."""
    start_time = time.time()
    logger.info(f"[CHECKHOST] Starting check-host.net query for {domain}")
    
    # Add www. to domain for check-host scan (remove http/https prefix, ports, and paths)
    clean_domain = domain.replace('http://', '').replace('https://', '').strip('/')
    # Remove ports if present (e.g., domain.com:80 -> domain.com)
    if ':' in clean_domain:
        clean_domain = clean_domain.split(':')[0]
    # Remove paths
    if '/' in clean_domain:
        clean_domain = clean_domain.split('/')[0]
    check_domain = f"www.{clean_domain}" if not clean_domain.startswith('www.') else clean_domain
    
    try:
        # Check-host.net API - use check-http endpoint (host should be domain without protocol or port)
        # Use https://www.domain format explicitly
        url = f"https://check-host.net/check-http?host=https://{check_domain}"
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        logger.info(f"[CHECKHOST] Querying check-host.net API for {check_domain}...")
        response = requests.get(url, headers=headers, timeout=TIMEOUTS["checkhost"])
        response.raise_for_status()
        
        elapsed = time.time() - start_time
        result = {
            "cmd": f"check-host API: {url}",
            "rc": 0,
            "stdout": "",
            "stderr": "",
            "duration": elapsed,
        }
        
        try:
            data = response.json()
            result["stdout"] = json.dumps(data, indent=2)
            result["data"] = data
            logger.info(f"[CHECKHOST] ✓ Received response in {elapsed:.1f}s")
            
            # Wait for scan to complete and capture screenshot
            request_id = data.get("request_id")
            if request_id:
                logger.info(f"[CHECKHOST] Waiting for scan completion (request_id: {request_id})...")
                # Poll for results (check-host.net may need time to complete scan)
                import time as time_module
                max_wait = 60  # Wait up to 60 seconds
                check_interval = 5  # Check every 5 seconds
                waited = 0
                
                while waited < max_wait:
                    time_module.sleep(check_interval)
                    waited += check_interval
                    result_url = f"https://check-host.net/check-report/{request_id}"
                    try:
                        result_response = requests.get(result_url, headers=headers, timeout=10)
                        if result_response.status_code == 200:
                            logger.info(f"[CHECKHOST] Scan results available, capturing screenshot...")
                            # Capture screenshot of results page
                            try:
                                from playwright.sync_api import sync_playwright
                                screenshot_path = OUTDIR / "screenshots" / f"{domain}_checkhost.png"
                                
                                with sync_playwright() as p:
                                    browser, context, page = create_stealth_browser_context(p, viewport_size=(1280, 720))
                                    page.goto(result_url, wait_until="domcontentloaded", timeout=60000)
                                    wait_for_cloudflare_challenge(page, max_wait=15)
                                    page.wait_for_timeout(3000)
                                    page.wait_for_load_state("load", timeout=5000)
                                    page.screenshot(path=str(screenshot_path), full_page=False, scale='css', type='png')
                                    browser.close()
                                
                                # Use relative path from HTML report location
                                result["screenshot_path"] = f"screenshots/{screenshot_path.name}"
                                logger.info(f"[CHECKHOST] ✓ Screenshot saved: {screenshot_path}")
                                break
                            except Exception as e:
                                logger.warning(f"[CHECKHOST] Screenshot capture failed: {str(e)}")
                    except Exception as e:
                        logger.debug(f"[CHECKHOST] Still waiting for results: {str(e)[:50]}")
        except json.JSONDecodeError:
            result["stdout"] = response.text[:5000]
            logger.warning(f"[CHECKHOST] Response is not JSON")
        
        return ("checkhost", result)
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[CHECKHOST] ❌ Failed after {elapsed:.1f}s: {str(e)}")
        return ("checkhost", {"cmd": f"check-host API", "rc": -1, "stdout": "", "stderr": str(e), "duration": elapsed})


def task_securityheaders(domain):
    """Check security headers via securityheaders.com API and capture screenshot."""
    start_time = time.time()
    logger.info(f"[SECURITYHEADERS] Starting securityheaders.com check for {domain}")
    try:
        # Use domain with https://www. prefix for better results
        test_domain = f"https://www.{domain}" if not domain.startswith(('http://', 'https://')) else domain
        url = f"https://securityheaders.com/?q={test_domain}&followRedirects=on"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        }
        
        # Note: securityheaders.com may not have a direct JSON API
        # We'll fetch the page and parse key information
        logger.info(f"[SECURITYHEADERS] Fetching security headers report for {test_domain}...")
        response = requests.get(url, headers=headers, timeout=TIMEOUTS["securityheaders"], allow_redirects=True)
        response.raise_for_status()
        
        elapsed = time.time() - start_time
        result = {
            "cmd": f"securityheaders API: {url}",
            "rc": 0,
            "stdout": response.text[:10000],  # HTML response
            "stderr": "",
            "duration": elapsed,
        }
        
        # Parse HTML to extract key information
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract grade
            grade = None
            grade_elements = soup.find_all(string=lambda text: text and 'grade' in text.lower() and any(g in text.upper() for g in ['A', 'B', 'C', 'D', 'F']))
            for elem in grade_elements:
                import re
                grade_match = re.search(r'grade\s+([A-F][\+]?)', elem, re.IGNORECASE)
                if grade_match:
                    grade = grade_match.group(1).upper()
                    break
            
            # Extract headers status
            headers_present = []
            headers_missing = []
            
            # Look for pill-green and pill-red classes
            green_pills = soup.find_all(class_=lambda x: x and 'pill-green' in str(x))
            red_pills = soup.find_all(class_=lambda x: x and 'pill-red' in str(x))
            
            for pill in green_pills:
                text = pill.get_text().strip().lower()
                if 'x-frame-options' in text:
                    headers_present.append('X-Frame-Options')
                elif 'x-content-type-options' in text:
                    headers_present.append('X-Content-Type-Options')
                elif 'strict-transport-security' in text or 'sts' in text:
                    headers_present.append('Strict-Transport-Security')
                elif 'content-security-policy' in text or 'csp' in text:
                    headers_present.append('Content-Security-Policy')
                elif 'referrer-policy' in text:
                    headers_present.append('Referrer-Policy')
                elif 'permissions-policy' in text:
                    headers_present.append('Permissions-Policy')
            
            for pill in red_pills:
                text = pill.get_text().strip().lower()
                if 'content-security-policy' in text or 'csp' in text:
                    if 'Content-Security-Policy' not in headers_present:
                        headers_missing.append('Content-Security-Policy')
                elif 'referrer-policy' in text:
                    if 'Referrer-Policy' not in headers_present:
                        headers_missing.append('Referrer-Policy')
                elif 'permissions-policy' in text:
                    if 'Permissions-Policy' not in headers_present:
                        headers_missing.append('Permissions-Policy')
            
            # Add parsed data to result
            result["grade"] = grade
            result["headers_present"] = list(set(headers_present))  # Remove duplicates
            result["headers_missing"] = list(set(headers_missing))  # Remove duplicates
            result["has_grade"] = grade is not None
            
            if grade:
                logger.info(f"[SECURITYHEADERS] ✓ Report fetched in {elapsed:.1f}s (Grade: {grade}, {len(headers_present)} headers present, {len(headers_missing)} missing)")
            else:
                logger.info(f"[SECURITYHEADERS] ✓ Report fetched in {elapsed:.1f}s (contains grade info)")
        except Exception as e:
            logger.debug(f"[SECURITYHEADERS] HTML parsing failed: {str(e)[:100]}")
            # Fallback
            if "grade" in response.text.lower():
                result["has_grade"] = True
                logger.info(f"[SECURITYHEADERS] ✓ Report fetched in {elapsed:.1f}s (contains grade info)")
            else:
                logger.warning(f"[SECURITYHEADERS] Report fetched but no grade found")
        
        # Capture screenshot of security headers results
        try:
            from playwright.sync_api import sync_playwright
            screenshot_path = OUTDIR / "screenshots" / f"{domain}_securityheaders.png"
            
            logger.info(f"[SECURITYHEADERS] Capturing screenshot...")
            with sync_playwright() as p:
                browser, context, page = create_stealth_browser_context(p, viewport_size=(1280, 720))
                # Use domcontentloaded instead of networkidle for faster loading, with longer timeout
                page.goto(url, wait_until="domcontentloaded", timeout=60000)
                
                # Wait for Cloudflare challenge with enhanced detection
                wait_for_cloudflare_challenge(page, max_wait=25)  # Longer wait for securityheaders
                
                # Wait a bit more for page to render
                page.wait_for_timeout(3000)
                page.wait_for_load_state("load", timeout=5000)
                page.screenshot(path=str(screenshot_path), full_page=False, scale='css', type='png')  # Only viewport
                browser.close()
            
            # Use relative path from HTML report location
            result["screenshot_path"] = f"screenshots/{screenshot_path.name}"
            logger.info(f"[SECURITYHEADERS] ✓ Screenshot saved: {screenshot_path}")
        except Exception as e:
            logger.warning(f"[SECURITYHEADERS] Screenshot capture failed: {str(e)}")
        
        return ("securityheaders", result)
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[SECURITYHEADERS] ❌ Failed after {elapsed:.1f}s: {str(e)}")
        return ("securityheaders", {"cmd": f"securityheaders API", "rc": -1, "stdout": "", "stderr": str(e), "duration": elapsed})


def task_shodan(domain):
    """Query Shodan API (requires API key)."""
    start_time = time.time()
    logger.info(f"[SHODAN] Starting Shodan query for {domain}")
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        elapsed = time.time() - start_time
        logger.warning(f"[SHODAN] API key not set, skipping check")
        return (
            "shodan",
            {
                "cmd": "shodan API",
                "rc": -1,
                "stdout": "",
                "stderr": "SHODAN_API_KEY environment variable not set. Skipping Shodan check.",
                "duration": elapsed,
            },
        )
    
    try:
        # Try multiple Shodan endpoints - first try host search, then host lookup by IP
        # First, get IP address of domain
        try:
            import socket
            ip = socket.gethostbyname(domain)
        except:
            ip = None
        
        # Try host search first (requires paid API for some queries)
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}"
        try:
            response = requests.get(url, timeout=TIMEOUTS["shodan"])
            if response.status_code == 200:
                data = response.json()
                result = {
                    "cmd": f"shodan API (search)",
                    "rc": 0,
                    "stdout": json.dumps(data, indent=2),
                    "stderr": "",
                }
                result["data"] = data
                result["total_found"] = data.get("total", 0)
                return ("shodan", result)
            elif response.status_code == 403:
                # 403 might mean insufficient API plan or query restrictions
                # Try host lookup by IP instead (works with free API)
                logger.info(f"[SHODAN] Search API returned 403, trying host lookup by IP...")
                if ip:
                    url2 = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
                    logger.info(f"[SHODAN] Looking up host by IP: {ip}")
                    response2 = requests.get(url2, timeout=TIMEOUTS["shodan"])
                    if response2.status_code == 200:
                        data = response2.json()
                        logger.info(f"[SHODAN] ✓ Host lookup succeeded")
                        result = {
                            "cmd": f"shodan API (host lookup)",
                            "rc": 0,
                            "stdout": json.dumps(data, indent=2),
                            "stderr": "",
                        }
                        result["data"] = data
                        result["host_data"] = True
                        return ("shodan", result)
                    elif response2.status_code == 401:
                        logger.error(f"[SHODAN] Authentication failed - API key may be invalid")
                        return ("shodan", {
                            "cmd": f"shodan API (host lookup)",
                            "rc": -1,
                            "stdout": "",
                            "stderr": "Shodan API authentication failed. Please check your API key.",
                        })
                    else:
                        error_data = response2.json() if response2.content else {}
                        error_msg = error_data.get("error", response2.text[:200])
                        logger.warning(f"[SHODAN] Host lookup also failed ({response2.status_code}): {error_msg}")
                        if response2.status_code == 403:
                            return ("shodan", {
                                "cmd": f"shodan API (host lookup)",
                                "rc": -1,
                                "stdout": "",
                                "stderr": f"Shodan API error (403): This endpoint requires a paid Shodan membership. "
                                         f"Free API keys have limited access. This is an API limitation, not a tool error.",
                            })
                        return ("shodan", {
                            "cmd": f"shodan API (host lookup)",
                            "rc": -1,
                            "stdout": "",
                            "stderr": f"Shodan API error ({response2.status_code}): {error_msg}",
                        })
                else:
                    error_data = response.json() if response.content else {}
                    error_msg = error_data.get("error", response.text[:200])
                    logger.warning(f"[SHODAN] Could not resolve IP for host lookup fallback")
                    return ("shodan", {
                        "cmd": f"shodan API (search)",
                        "rc": -1,
                        "stdout": "",
                        "stderr": f"Shodan search API requires paid membership (403: {error_msg}). Host lookup unavailable - could not resolve IP.",
                    })
            else:
                response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            error_data = {}
            try:
                if e.response.content:
                    error_data = e.response.json()
            except:
                pass
            error_msg = error_data.get("error", str(e)) if error_data else str(e)
            return ("shodan", {"cmd": f"shodan API", "rc": -1, "stdout": "", "stderr": f"Shodan API HTTP error: {error_msg}"})
    except Exception as e:
        return ("shodan", {"cmd": f"shodan API", "rc": -1, "stdout": "", "stderr": f"Shodan API error: {str(e)}"})


def task_tech_detection(domain):
    """Detect website technologies (CMS, frameworks, etc.)."""
    logger.info(f"[TECH] Starting technology detection for {domain}")
    start_time = time.time()
    
    technologies = []
    evidence = {}
    
    try:
        # Try HTTPS first, then HTTP
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                logger.info(f"[TECH] Checking {url}...")
                
                # Get page content and headers
                response = requests.get(
                    url,
                    timeout=30,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                
                if response.status_code < 500:
                    html_content = response.text.lower()
                    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                    
                    # WordPress detection
                    wp_signals = [
                        ('wp-content', 'wp-content' in html_content or '/wp-content/' in url.lower()),
                        ('wp-includes', 'wp-includes' in html_content or '/wp-includes/' in url.lower()),
                        ('wp-json', 'wp-json' in html_content or '/wp-json/' in url.lower()),
                        ('wordpress', 'wordpress' in html_content or 'generator' in headers.get('x-powered-by', '')),
                    ]
                    if any(signal[1] for signal in wp_signals):
                        technologies.append('WordPress')
                        evidence['WordPress'] = [s[0] for s in wp_signals if s[1]]
                    
                    # Magento detection
                    magento_signals = [
                        ('skin/frontend', 'skin/frontend' in html_content),
                        ('media/js', '/media/js/' in html_content),
                        ('mage.cookies', 'mage.cookies' in html_content or 'mage.' in html_content),
                        ('magento', 'magento' in html_content),
                    ]
                    if any(signal[1] for signal in magento_signals):
                        technologies.append('Magento')
                        evidence['Magento'] = [s[0] for s in magento_signals if s[1]]
                    
                    # vBulletin detection
                    if any(x in html_content for x in ['vbulletin', 'vb-version', 'vb:version']):
                        technologies.append('vBulletin')
                        evidence['vBulletin'] = ['vBulletin indicators found']
                    
                    # Drupal detection
                    if any(x in html_content for x in ['drupal', 'sites/default', 'modules/system']):
                        technologies.append('Drupal')
                        evidence['Drupal'] = ['Drupal indicators found']
                    
                    # Joomla detection
                    joomla_signals = [
                        ('joomla', 'joomla' in html_content or 'joomla' in headers.get('x-powered-by', '')),
                        ('/media/system/', '/media/system/' in html_content),
                        ('option=com_', 'option=com_' in html_content),
                    ]
                    if any(signal[1] for signal in joomla_signals):
                        technologies.append('Joomla')
                        evidence['Joomla'] = [s[0] for s in joomla_signals if s[1]]
                    
                    # React detection
                    if 'react' in html_content or 'reactjs' in html_content or '__REACT_DEVTOOLS_GLOBAL_HOOK__' in html_content:
                        technologies.append('React')
                        evidence['React'] = ['React indicators found']
                    
                    # Angular detection
                    if 'angular' in html_content or 'ng-app' in html_content or 'angularjs' in html_content:
                        technologies.append('Angular')
                        evidence['Angular'] = ['Angular indicators found']
                    
                    # Vue.js detection
                    if 'vue.js' in html_content or '__vue__' in html_content or 'v-if' in html_content:
                        technologies.append('Vue.js')
                        evidence['Vue.js'] = ['Vue.js indicators found']
                    
                    # Shopify detection
                    if 'shopify' in html_content or 'cdn.shopify.com' in html_content or 'myshopify.com' in html_content:
                        technologies.append('Shopify')
                        evidence['Shopify'] = ['Shopify indicators found']
                    
                    # WooCommerce detection (usually with WordPress)
                    if 'woocommerce' in html_content or 'wp-content/plugins/woocommerce' in html_content:
                        technologies.append('WooCommerce')
                        evidence['WooCommerce'] = ['WooCommerce indicators found']
                    
                    # Check server headers
                    server_header = headers.get('server', '')
                    x_powered_by = headers.get('x-powered-by', '')
                    
                    # PHP detection
                    if 'php' in server_header or 'php' in x_powered_by or '.php' in html_content[:10000]:
                        technologies.append('PHP')
                        if 'PHP' not in evidence:
                            evidence['PHP'] = []
                        if server_header:
                            evidence['PHP'].append(f"Server: {server_header}")
                    
                    # ASP.NET detection
                    if 'asp.net' in x_powered_by or 'asp.net' in server_header or '__viewstate' in html_content:
                        technologies.append('ASP.NET')
                        evidence['ASP.NET'] = ['ASP.NET indicators found']
                    
                    # Node.js detection
                    if 'node' in server_header or 'express' in server_header or 'nodejs' in server_header:
                        technologies.append('Node.js')
                        evidence['Node.js'] = ['Node.js indicators found']
                    
                    # Nginx detection
                    if 'nginx' in server_header:
                        technologies.append('Nginx')
                        evidence['Nginx'] = [f"Server: {server_header}"]
                    
                    # Apache detection
                    if 'apache' in server_header:
                        technologies.append('Apache')
                        evidence['Apache'] = [f"Server: {server_header}"]
                    
                    # Cloudflare detection
                    if 'cloudflare' in server_header or 'cf-ray' in headers:
                        technologies.append('Cloudflare')
                        evidence['Cloudflare'] = ['Cloudflare CDN detected']
                    
                    break  # Success, no need to try HTTP
                    
            except requests.exceptions.RequestException as e:
                logger.debug(f"[TECH] {protocol} failed: {str(e)[:50]}")
                continue
        
        elapsed = time.time() - start_time
        
        if technologies:
            logger.info(f"[TECH] ✓ Detected technologies: {', '.join(technologies)}")
        else:
            logger.info(f"[TECH] No common technologies detected")
        
        result = {
            "cmd": f"Technology detection for {domain}",
            "rc": 0,
            "stdout": "",
            "stderr": "",
            "duration": elapsed,
            "technologies": technologies,
            "evidence": evidence,
        }
        
        return ("tech_detection", result)
        
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[TECH] ❌ Failed after {elapsed:.1f}s: {str(e)}")
        return ("tech_detection", {
            "cmd": f"Technology detection",
            "rc": -1,
            "stdout": "",
            "stderr": str(e),
            "duration": elapsed,
            "technologies": [],
            "evidence": {},
        })


def task_ssl(domain):
    """Check SSL/TLS certificate using Python ssl library."""
    logger.info(f"[SSL] Starting SSL/TLS certificate check for {domain}")
    start_time = time.time()
    
    try:
        import ssl
        import socket
        from datetime import datetime
        
        ssl_info = {}
        
        # Connect to domain and get certificate
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Don't verify, just get info
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Extract certificate information - handle subject/issuer properly
                    # Subject/Issuer format: [(('commonName', 'example.com'),), (('organizationName', 'Org'),), ...]
                    subject_dict = {}
                    for item in cert.get('subject', []):
                        if isinstance(item, tuple):
                            # Handle nested tuples: (('key', 'value'),)
                            for subitem in item:
                                if isinstance(subitem, tuple) and len(subitem) >= 2:
                                    key = subitem[0]
                                    value = subitem[1]
                                    if key:
                                        subject_dict[key] = value
                                elif isinstance(subitem, (str, bytes)):
                                    # Sometimes it's just a string
                                    subject_dict['value'] = subitem
                    
                    issuer_dict = {}
                    for item in cert.get('issuer', []):
                        if isinstance(item, tuple):
                            # Handle nested tuples: (('key', 'value'),)
                            for subitem in item:
                                if isinstance(subitem, tuple) and len(subitem) >= 2:
                                    key = subitem[0]
                                    value = subitem[1]
                                    if key:
                                        issuer_dict[key] = value
                                elif isinstance(subitem, (str, bytes)):
                                    issuer_dict['value'] = subitem
                    
                    # Extract certificate information
                    ssl_info = {
                        "domain": domain,
                        "subject": subject_dict,
                        "issuer": issuer_dict,
                        "version": cert.get('version'),
                        "serialNumber": str(cert.get('serialNumber', '')) if cert.get('serialNumber') else None,
                        "notBefore": cert.get('notBefore'),
                        "notAfter": cert.get('notAfter'),
                        "tls_version": version,
                        "cipher_suite": {
                            "name": cipher[0] if cipher else None,
                            "protocol": cipher[1] if cipher and len(cipher) > 1 else None,
                            "bits": cipher[2] if cipher and len(cipher) > 2 else None,
                        },
                        "san": cert.get('subjectAltName', []),
                    }
                    
                    logger.info(f"[SSL] ✓ Certificate retrieved successfully")
        except Exception as e:
            logger.warning(f"[SSL] Failed to get certificate: {str(e)[:100]}")
            ssl_info["error"] = str(e)[:200]
        
        # Check certificate expiry
        if ssl_info.get('notAfter'):
            try:
                from dateutil import parser as date_parser
                expiry_date = date_parser.parse(ssl_info['notAfter'])
                days_until_expiry = (expiry_date - datetime.now()).days
                ssl_info["days_until_expiry"] = days_until_expiry
                ssl_info["expiry_status"] = "valid" if days_until_expiry > 0 else "expired"
                if days_until_expiry < 30:
                    ssl_info["warning"] = f"Certificate expires in {days_until_expiry} days"
            except:
                try:
                    from datetime import datetime
                    # Try parsing manually if dateutil not available
                    import re
                    date_str = ssl_info['notAfter']
                    # Format: "Nov  1 00:00:00 2025 GMT" or similar
                    match = re.search(r'(\w{3})\s+(\d+)\s+.*?(\d{4})', date_str)
                    if match:
                        month, day, year = match.groups()
                        # Simple parsing (approximate)
                        ssl_info["days_until_expiry"] = "unknown"
                        ssl_info["expiry_status"] = "check_manually"
                except:
                    pass
        
        elapsed = time.time() - start_time
        
        # Format output
        output_lines = []
        output_lines.append(f"SSL/TLS Certificate Information for {domain}")
        output_lines.append("=" * 60)
        if ssl_info.get('subject'):
            output_lines.append(f"\nSubject: {ssl_info['subject'].get('commonName', 'N/A')}")
        if ssl_info.get('issuer'):
            output_lines.append(f"Issuer: {ssl_info['issuer'].get('organizationName', 'N/A')}")
        if ssl_info.get('notBefore'):
            output_lines.append(f"Valid From: {ssl_info['notBefore']}")
        if ssl_info.get('notAfter'):
            output_lines.append(f"Valid To: {ssl_info['notAfter']}")
        if ssl_info.get('days_until_expiry') is not None:
            output_lines.append(f"Days Until Expiry: {ssl_info['days_until_expiry']}")
        if ssl_info.get('warning'):
            output_lines.append(f"⚠️ WARNING: {ssl_info['warning']}")
        output_lines.append(f"\nTLS Version: {ssl_info.get('tls_version', 'N/A')}")
        if ssl_info.get('cipher_suite', {}).get('name'):
            output_lines.append(f"Cipher Suite: {ssl_info['cipher_suite']['name']}")
            if ssl_info['cipher_suite'].get('bits'):
                output_lines.append(f"Cipher Strength: {ssl_info['cipher_suite']['bits']} bits")
        if ssl_info.get('san'):
            output_lines.append(f"\nSubject Alternative Names (SAN):")
            for name_type, name_value in ssl_info['san'][:5]:  # Show first 5
                output_lines.append(f"  - {name_value}")
            if len(ssl_info['san']) > 5:
                output_lines.append(f"  ... and {len(ssl_info['san']) - 5} more")
        
        result = {
            "cmd": f"SSL certificate check for {domain}",
            "rc": 0,
            "stdout": "\n".join(output_lines),
            "stderr": "",
            "duration": elapsed,
            "data": ssl_info,
        }
        
        logger.info(f"[SSL] ✓ Certificate check completed in {elapsed:.1f}s")
        return ("ssl", result)
    except Exception as e:
        elapsed = time.time() - start_time
        logger.error(f"[SSL] ❌ Failed after {elapsed:.1f}s: {str(e)}")
        return ("ssl", {
            "cmd": f"SSL certificate check",
            "rc": -1,
            "stdout": "",
            "stderr": f"SSL check failed: {str(e)}",
            "duration": elapsed,
        })


# Define all tasks (NMAP removed as requested)
TASKS = [
    task_headers,
    task_dns,
    task_subdomains,
    task_nuclei,
    task_screenshot,
    task_js_endpoints,
    task_secretfinder,
    task_cookies,
    task_wayback,
    task_sucuri,
    task_checkhost,
    task_securityheaders,
    task_ssl,
    task_tech_detection,
]


def run_all(domain, progress_callback=None):
    """Run all tasks in parallel and aggregate results with stuck process detection."""
    results = {
        "domain": domain,
        "started": datetime.utcnow().isoformat() + "Z",
        "results": {},
    }
    
    # Map task functions to friendly names
    task_names = {
        task_headers: "Headers",
        task_dns: "DNS Records",
        task_subdomains: "Subdomains",
        task_nuclei: "Nuclei",
        task_screenshot: "Screenshot",
        task_js_endpoints: "JavaScript Endpoints",
        task_secretfinder: "Secret Finder",
        task_cookies: "Cookies Analysis",
        task_wayback: "Wayback Machine",
        task_sucuri: "Sucuri SiteCheck",
        task_checkhost: "Check-Host",
        task_securityheaders: "Security Headers",
        task_ssl: "SSL/TLS",
        task_tech_detection: "Technology Detection",
    }
    
    logger.info(f"Starting scan for {domain} with {len(TASKS)} tasks")
    
    # Add small delay between API calls to respect rate limits
    api_tasks = [task_wayback, task_sucuri, task_checkhost, task_securityheaders]
    
    total_tasks = len(TASKS)
    completed = 0
    
    # Track task start times and last activity for stuck detection
    task_start_times = {}
    task_last_check = {}
    task_durations = {}  # Track how long each task has been running
    STUCK_THRESHOLD = 300  # 5 minutes without any update = stuck
    PROGRESS_UPDATE_INTERVAL = 2  # Update progress every 2 seconds for better visibility
    
    if progress_callback:
        progress_callback(0, total_tasks, "Starting scan...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {}
        active_futures = set()
        
        # Submit ALL tasks immediately for true parallel execution
        # No delays here - rate limiting should be handled within tasks if needed
        for task in TASKS:
            task_friendly_name = task_names.get(task, task.__name__)
            # Submit immediately - ThreadPoolExecutor handles concurrency
            future = executor.submit(task, domain)
            futures[future] = (task.__name__, task_friendly_name)
            active_futures.add(future)
            task_start_times[future] = time.time()
            task_last_check[future] = time.time()
        
        # Log all tasks started
        if progress_callback:
            active_list = [futures[f][1] for f in active_futures if f in futures]
            progress_callback(0, total_tasks, f"Started {len(TASKS)} tasks in parallel...", active_list)
        
        # Monitor and collect results with stuck detection
        last_progress_update = time.time()
        while active_futures:
            # Check for completed tasks
            done_futures = [f for f in active_futures if f.done()]
            stuck_futures = []
            
            # Check for stuck tasks (no progress for too long)
            current_time = time.time()
            for future in active_futures:
                if not future.done():
                    elapsed = current_time - task_start_times[future]
                    time_since_last_check = current_time - task_last_check[future]
                    task_name, task_friendly_name = futures[future]
                    
                    # Check if task is stuck (exceeded timeout and no recent activity)
                    timeout = TIMEOUTS.get(task_name.replace("task_", "").replace("_", ""), DEFAULT_TIMEOUT)
                    
                    # If significantly past expected timeout and no recent logging activity
                    if elapsed > timeout * 1.5 and time_since_last_check > STUCK_THRESHOLD:
                        stuck_futures.append(future)
                        logger.error(f"[{task_friendly_name.upper()}] ⚠️ STUCK DETECTED! Running for {elapsed:.1f}s (timeout: {timeout}s)")
                        logger.error(f"[{task_friendly_name.upper()}] Killing stuck process...")
                        # Try to cancel (won't work if already running, but logs the attempt)
                        future.cancel()
                        if future.cancelled():
                            logger.warning(f"[{task_friendly_name.upper()}] Process cancelled")
                        else:
                            logger.error(f"[{task_friendly_name.upper()}] Could not cancel - may need manual intervention")
            
            # Process stuck futures
            for future in stuck_futures:
                task_name, task_friendly_name = futures[future]
                elapsed = current_time - task_start_times[future]
                logger.error(f"[{task_friendly_name.upper()}] ⚠️ PROCESS MARKED AS STUCK after {elapsed:.1f}s")
                results["results"][task_name] = {
                    "cmd": f"{task_friendly_name} task",
                    "rc": -3,
                    "stdout": "",
                    "stderr": f"Process stuck - exceeded expected timeout significantly ({elapsed:.1f}s). No progress detected.",
                    "duration": elapsed,
                    "stuck": True,
                }
                active_futures.discard(future)
                completed += 1
                if progress_callback:
                    active_list = [futures[f][1] for f in active_futures if f in futures]
                    progress_callback(completed, total_tasks, f"⚠️ {task_friendly_name} stuck/killed", active_list)
            
            # Process completed futures
            for future in done_futures:
                task_name, task_friendly_name = futures[future]
                active_futures.discard(future)
                completed += 1
                task_last_check.pop(future, None)
                
                try:
                    key, res = future.result(timeout=1)
                    results["results"][key] = res
                    
                    # Log detailed results
                    duration = res.get("duration", 0)
                    if duration > 0:
                        logger.info(f"[{task_friendly_name.upper()}] Completed in {duration:.1f}s")
                    
                    status = "✓" if res.get("rc") == 0 else "✗"
                    if res.get("rc") != 0:
                        logger.error(f"[{task_friendly_name.upper()}] Failed with return code {res.get('rc')}")
                        error_msg = res.get('stderr', 'No error message')[:300]
                        if error_msg:
                            logger.error(f"[{task_friendly_name.upper()}] Error: {error_msg}")
                    
                    if progress_callback:
                        active_list = [futures[f][1] for f in active_futures if f in futures]
                        progress_callback(completed, total_tasks, f"{status} {task_friendly_name} completed", active_list)
                except concurrent.futures.TimeoutError:
                    logger.error(f"[{task_friendly_name.upper()}] Future result timeout")
                    results["results"][task_name] = {
                        "cmd": "",
                        "rc": -2,
                        "stdout": "",
                        "stderr": "Task completion timeout",
                    }
                    if progress_callback:
                        active_list = [futures[f][1] for f in active_futures if f in futures]
                        progress_callback(completed, total_tasks, f"✗ {task_friendly_name} timeout", active_list)
                except Exception as e:
                    logger.error(f"[{task_friendly_name.upper()}] ❌ EXCEPTION in task execution: {type(e).__name__}: {str(e)}")
                    import traceback
                    logger.error(f"[{task_friendly_name.upper()}] Traceback:\n{traceback.format_exc()}")
                    results["results"][task_name] = {
                        "cmd": "",
                        "rc": -2,
                        "stdout": "",
                        "stderr": str(e),
                    }
                    if progress_callback:
                        active_list = [futures[f][1] for f in active_futures if f in futures]
                        progress_callback(completed, total_tasks, f"✗ {task_friendly_name} failed: {str(e)[:50]}", active_list)
            
            # Periodic progress updates
            if current_time - last_progress_update > PROGRESS_UPDATE_INTERVAL:
                if active_futures:
                    active_list = [futures[f][1] for f in active_futures if f in futures]
                    # Update last check times for active tasks
                    for future in active_futures:
                        if future in task_last_check:
                            task_last_check[future] = current_time
                    if progress_callback:
                        elapsed_total = current_time - min(task_start_times.values()) if task_start_times else 0
                        
                        # Calculate estimated time remaining
                        if completed > 0:
                            avg_time_per_task = elapsed_total / completed
                            remaining_tasks = total_tasks - completed
                            est_remaining = avg_time_per_task * remaining_tasks
                            time_info = f"{elapsed_total:.0f}s elapsed | ~{est_remaining:.0f}s remaining"
                        else:
                            time_info = f"{elapsed_total:.0f}s elapsed"
                        
                        # Show task durations for active tasks
                        task_status = []
                        for f in active_futures:
                            if f in task_start_times:
                                task_name, task_friendly_name = futures[f]
                                task_elapsed = current_time - task_start_times[f]
                                timeout = TIMEOUTS.get(task_name.replace("task_", "").replace("_", ""), DEFAULT_TIMEOUT)
                                
                                # Warning if task is taking a long time
                                if task_elapsed > timeout * 0.8:
                                    task_status.append(f"{task_friendly_name}({task_elapsed:.0f}s⚠️)")
                                else:
                                    task_status.append(f"{task_friendly_name}({task_elapsed:.0f}s)")
                        
                        status_msg = f"{time_info}" + (f" | {' '.join(task_status[:3])}" if task_status else "")
                        progress_callback(completed, total_tasks, status_msg, active_list)
                    last_progress_update = current_time
            
            # Small sleep to avoid busy waiting, but not too long to keep responsiveness
            if active_futures:
                time.sleep(0.1)  # Reduced from 1s to 0.1s for better responsiveness
    
    results["finished"] = datetime.utcnow().isoformat() + "Z"
    if progress_callback:
        progress_callback(total_tasks, total_tasks, "Scan completed!")
    return results


def render_html(report):
    """Render HTML report using Jinja2 template."""
    template_path = pathlib.Path("templates/report.html")
    if template_path.exists():
        template_content = template_path.read_text()
        from jinja2 import Environment
        env = Environment()
        env.filters['tojson'] = lambda x: json.dumps(x, indent=2, ensure_ascii=False)
        env.filters['from_json'] = lambda x: json.loads(x) if isinstance(x, str) else x
        template = env.from_string(template_content)
        # Convert any dict/list data to JSON strings for better template rendering
        processed_report = json.loads(json.dumps(report))  # Deep copy and ensure JSON-serializable
        return template.render(**processed_report)
    else:
        # Fallback simple template
        return f"""
        <html>
        <head><meta charset="utf-8"><title>PT Report - {report['domain']}</title></head>
        <body>
        <h1>PT Report - {report['domain']}</h1>
        <p>Started: {report['started']} | Finished: {report['finished']}</p>
        <pre>{json.dumps(report, indent=2)}</pre>
        </body>
        </html>
        """


def load_env_file():
    """Load environment variables from .env file if it exists."""
    env_path = pathlib.Path(".env")
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip()


def print_progress(completed, total, message, active_tasks=None):
    """Print progress update with active tasks monitoring - improved visibility."""
    percentage = int((completed / total) * 100) if total > 0 else 0
    bar_length = 40
    filled = int(bar_length * completed / total) if total > 0 else 0
    bar = "█" * filled + "░" * (bar_length - filled)
    
    # Show active tasks if provided - show more tasks for better visibility
    active_info = ""
    if active_tasks:
        active_tasks_str = ', '.join(active_tasks[:4])  # Show up to 4 active tasks
        if len(active_tasks) > 4:
            active_tasks_str += f" +{len(active_tasks)-4} more"
        active_info = f" | Active: {active_tasks_str}"
    
    # Print to stdout for better visibility (logging goes to stderr now)
    import sys
    progress_line = f"\r[{bar}] {percentage:3d}% ({completed}/{total}) {message}{active_info}"
    print(progress_line, end="", flush=True)
    
    if completed >= total:
        print()  # New line when complete


def normalize_domain(domain_input):
    """Normalize domain - remove www, protocol, paths, and clean up."""
    domain = domain_input.strip().lower()
    
    # Remove protocol
    domain = domain.replace("http://", "").replace("https://", "")
    
    # Remove paths and query strings
    if "/" in domain:
        domain = domain.split("/")[0]
    if "?" in domain:
        domain = domain.split("?")[0]
    
    # Remove www. prefix (common but not always desired)
    # We keep it for subdomains like www.example.com, but remove if user didn't specify
    # Actually, let's keep www if explicitly provided, remove if not
    # But for simplicity, we'll remove www. prefix as it's usually redundant
    if domain.startswith("www."):
        domain = domain[4:]
    
    # Remove trailing dots
    domain = domain.rstrip(".")
    
    # Basic validation
    if not domain or " " in domain:
        raise ValueError(f"Invalid domain: {domain_input}")
    
    return domain


def main():
    """Main entry point."""
    # Load .env file manually (dotenv might not be installed)
    load_env_file()
    
    if len(sys.argv) < 2:
        print("Usage: pt_orchestrator.py target.example.com")
        sys.exit(1)
    
    try:
        domain = normalize_domain(sys.argv[1])
        logger.info(f"Normalized domain: '{sys.argv[1]}' → '{domain}'")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    print(f"[*] Starting security scan for {domain}...")
    print(f"[*] Output directory: {OUTDIR}")
    print(f"[*] Running {len(TASKS)} security checks...\n")
    
    out = run_all(domain, progress_callback=print_progress)
    
    json_path = OUTDIR / f"{domain}.json"
    html_path = OUTDIR / f"{domain}.html"
    
    # Write JSON report
    json_path.write_text(json.dumps(out, indent=2))
    print(f"[+] JSON report saved: {json_path}")
    
    # Write HTML report
    html_content = render_html(out)
    html_path.write_text(html_content)
    print(f"[+] HTML report saved: {html_path}")
    
    # Summary
    print(f"\n[*] Scan completed!")
    print(f"[*] Total checks: {len(out['results'])}")
    
    successful = sum(1 for r in out["results"].values() if r.get("rc") == 0)
    print(f"[*] Successful: {successful}/{len(out['results'])}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

