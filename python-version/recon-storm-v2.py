#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                     RECON STORM - Bug Bounty Pipeline                       ║
║                                                                              ║
║  A 5-stage automated reconnaissance pipeline combining popular               ║
║  bug bounty tools into a unified workflow.                                   ║
║                                                                              ║
║  Author : Security Researcher                                                ║
║  Version: 2.0                                                                ║
║  License: MIT                                                                ║
╚══════════════════════════════════════════════════════════════════════════════╝

PREREQUISITES:
    pip install shodan censys python-dotenv requests colorama pyyaml schedule

TOOL DEPENDENCIES (must be in $PATH):
    - subfinder, amass, assetfinder, findomain
    - httpx, httprobe
    - naabu, nmap, masscan
    - ffuf, feroxbuster, dirsearch
    - linkfinder, secretfinder
    - trufflehog, gitleaks
    - gowitness, eyewitness
    - theharvester, nuclei, notify

USAGE:
    python3 recon_storm.py --target example.com
    python3 recon_storm.py --target example.com --stages 1,2,3
    python3 recon_storm.py --target-list targets.txt --monitor --interval 6
    python3 recon_storm.py --target example.com --config config.yaml
"""

import os
import sys
import json
import time
import shutil
import signal
import hashlib
import logging
import argparse
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum

try:
    import yaml
    import requests
    import schedule
    from colorama import Fore, Back, Style, init as colorama_init
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Run: pip install shodan censys python-dotenv requests colorama pyyaml schedule")
    sys.exit(1)

colorama_init(autoreset=True)

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "2.0.0"
BANNER = f"""
{Fore.CYAN}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ███████╗████████╗ ██████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗████╗ ████║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ███████╗   ██║   ██║   ██║██████╔╝██╔████╔██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ╚════██║   ██║   ██║   ██║██╔══██╗██║╚██╔╝██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ███████║   ██║   ╚██████╔╝██║  ██║██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝
{Style.RESET_ALL}
  {Fore.YELLOW}[ Bug Bounty Recon Pipeline v{VERSION} ]{Style.RESET_ALL}
  {Fore.WHITE}[ 5-Stage Automated Reconnaissance ]{Style.RESET_ALL}
"""

DEFAULT_CONFIG = {
    "general": {
        "threads": 10,
        "timeout": 300,
        "verbose": True,
        "notify_enabled": False,
        "notify_provider": "discord",
    },
    "api_keys": {
        "shodan": "",
        "censys_id": "",
        "censys_secret": "",
        "github_token": "",
        "virustotal": "",
    },
    "stage1": {
        "subfinder_threads": 30,
        "amass_timeout": 15,
        "amass_passive": True,
        "resolve_subdomains": True,
        "wordlist": "",
    },
    "stage2": {
        "httpx_threads": 50,
        "httpx_rate_limit": 150,
        "screenshot_threads": 10,
        "tech_detect": True,
    },
    "stage3": {
        "naabu_rate": 5000,
        "naabu_top_ports": 1000,
        "nmap_scripts": "default,vuln",
        "masscan_rate": 10000,
        "full_port_scan": False,
    },
    "stage4": {
        "github_dork_delay": 5,
        "google_dork_delay": 10,
        "theharvester_sources": "google,bing,linkedin,twitter,dnsdumpster",
        "gitleaks_depth": 5,
        "trufflehog_verified_only": True,
    },
    "stage5": {
        "monitor_interval_hours": 6,
        "notify_new_subdomains": True,
        "notify_new_ports": True,
        "notify_new_vulns": True,
        "nuclei_severity": "critical,high,medium",
        "nuclei_rate_limit": 150,
    },
    "content_discovery": {
        "wordlist": "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "ffuf_threads": 40,
        "ffuf_rate": 0,
        "extensions": "php,asp,aspx,jsp,html,js,json,xml,txt,bak,old,config",
        "feroxbuster_depth": 3,
    },
}

# Common GitHub dorks for bug bounty
GITHUB_DORKS = [
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" apikey',
    '"{domain}" access_token',
    '"{domain}" auth_token',
    '"{domain}" aws_access_key',
    '"{domain}" aws_secret_key',
    '"{domain}" BEGIN RSA PRIVATE KEY',
    '"{domain}" BEGIN OPENSSH PRIVATE KEY',
    '"{domain}" jdbc:',
    '"{domain}" mongodb+srv:',
    '"{domain}" smtp_password',
    '"{domain}" .env',
    '"{domain}" firebase',
    '"{domain}" Bearer',
    '"{domain}" Authorization',
    '"{domain}" filename:.env',
    '"{domain}" extension:pem private',
    '"{domain}" extension:sql password',
]

# Common Google dorks for bug bounty
GOOGLE_DORKS = [
    'site:{domain} inurl:admin',
    'site:{domain} inurl:login',
    'site:{domain} inurl:dashboard',
    'site:{domain} intitle:"index of"',
    'site:{domain} ext:sql | ext:db | ext:log',
    'site:{domain} ext:xml | ext:conf | ext:cnf | ext:cfg',
    'site:{domain} ext:json | ext:env | ext:ini',
    'site:{domain} ext:bak | ext:old | ext:backup',
    'site:{domain} inurl:api',
    'site:{domain} inurl:token | inurl:auth',
    'site:{domain} inurl:signup | inurl:register',
    'site:{domain} inurl:upload',
    'site:{domain} inurl:redirect | inurl:url= | inurl:return=',
    'site:{domain} intext:"sql syntax near"',
    'site:{domain} intext:"error in your SQL syntax"',
    'site:{domain} filetype:pdf | filetype:doc | filetype:xls',
    'site:{domain} inurl:wp-content | inurl:wp-includes',
    'site:{domain} inurl:".php?" | inurl:".asp?"',
]


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════════

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for terminal output."""
    COLORS = {
        logging.DEBUG: Fore.BLUE,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger(name: str, log_file: str = None, level=logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        ColoredFormatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    )
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")
        )
        logger.addHandler(file_handler)

    return logger


# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class StageStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"


@dataclass
class SubdomainInfo:
    subdomain: str
    ip: str = ""
    status_code: int = 0
    title: str = ""
    tech: List[str] = field(default_factory=list)
    content_length: int = 0
    cdn: str = ""
    cname: str = ""
    ports: List[PortInfo] = field(default_factory=list)
    screenshot_path: str = ""
    is_alive: bool = False


@dataclass
class ReconResults:
    target: str
    start_time: str = ""
    end_time: str = ""
    subdomains: Dict[str, SubdomainInfo] = field(default_factory=dict)
    live_hosts: List[str] = field(default_factory=list)
    open_ports: Dict[str, List[PortInfo]] = field(default_factory=dict)
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    secrets_found: List[Dict] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    github_dork_results: List[Dict] = field(default_factory=list)
    google_dork_results: List[str] = field(default_factory=list)
    osint_data: Dict[str, Any] = field(default_factory=dict)
    content_discovery: Dict[str, List[str]] = field(default_factory=dict)
    js_links: List[str] = field(default_factory=list)
    js_secrets: List[Dict] = field(default_factory=list)
    stage_status: Dict[str, StageStatus] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize results to dictionary."""
        data = {
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "summary": {
                "total_subdomains": len(self.subdomains),
                "live_hosts": len(self.live_hosts),
                "open_ports_count": sum(len(p) for p in self.open_ports.values()),
                "vulnerabilities_found": len(self.vulnerabilities),
                "secrets_found": len(self.secrets_found),
            },
            "subdomains": list(self.subdomains.keys()),
            "live_hosts": self.live_hosts,
            "open_ports": {
                host: [{"port": p.port, "service": p.service, "version": p.version}
                       for p in ports]
                for host, ports in self.open_ports.items()
            },
            "technologies": self.technologies,
            "vulnerabilities": self.vulnerabilities,
            "secrets_found": self.secrets_found,
            "github_dork_results": self.github_dork_results,
            "google_dork_results": self.google_dork_results,
            "osint_data": self.osint_data,
            "content_discovery": self.content_discovery,
            "js_links": self.js_links,
            "js_secrets": self.js_secrets,
        }
        return data


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

class Utils:
    """Utility helper methods."""

    @staticmethod
    def check_tool(tool_name: str) -> bool:
        """Check if a tool is installed and in PATH."""
        return shutil.which(tool_name) is not None

    @staticmethod
    def check_required_tools(tools: List[str]) -> Tuple[List[str], List[str]]:
        """Check which tools are available. Returns (found, missing)."""
        found = []
        missing = []
        for tool in tools:
            if Utils.check_tool(tool):
                found.append(tool)
            else:
                missing.append(tool)
        return found, missing

    @staticmethod
    def run_command(
        cmd: str,
        timeout: int = 300,
        shell: bool = True,
        capture: bool = True,
        cwd: str = None,
        logger: logging.Logger = None,
    ) -> Tuple[int, str, str]:
        """Execute a shell command with timeout."""
        if logger:
            logger.debug(f"Executing: {cmd}")
        try:
            proc = subprocess.run(
                cmd,
                shell=shell,
                capture_output=capture,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            if logger:
                logger.warning(f"Command timed out after {timeout}s: {cmd}")
            return -1, "", "TIMEOUT"
        except Exception as e:
            if logger:
                logger.error(f"Command failed: {cmd} -> {e}")
            return -1, "", str(e)

    @staticmethod
    def read_file_lines(filepath: str) -> List[str]:
        """Read lines from a file, strip whitespace, skip empty lines."""
        if not os.path.exists(filepath):
            return []
        with open(filepath, "r") as f:
            return [line.strip() for line in f if line.strip()]

    @staticmethod
    def write_file_lines(filepath: str, lines: List[str]):
        """Write lines to a file."""
        with open(filepath, "w") as f:
            f.write("\n".join(lines) + "\n")

    @staticmethod
    def merge_files(file_list: List[str], output_file: str) -> int:
        """Merge multiple files, deduplicate lines."""
        all_lines: Set[str] = set()
        for fpath in file_list:
            all_lines.update(Utils.read_file_lines(fpath))
        sorted_lines = sorted(all_lines)
        Utils.write_file_lines(output_file, sorted_lines)
        return len(sorted_lines)

    @staticmethod
    def file_hash(filepath: str) -> str:
        """Get SHA256 hash of a file for change detection."""
        if not os.path.exists(filepath):
            return ""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def diff_files(old_file: str, new_file: str) -> List[str]:
        """Find new lines in new_file that aren't in old_file."""
        old_lines = set(Utils.read_file_lines(old_file)) if os.path.exists(old_file) else set()
        new_lines = set(Utils.read_file_lines(new_file))
        return sorted(new_lines - old_lines)

    @staticmethod
    def timestamp() -> str:
        return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    @staticmethod
    def ensure_dir(path: str):
        Path(path).mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class Notifier:
    """Handles notifications via the 'notify' tool or direct webhooks."""

    def __init__(self, config: dict, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.enabled = config.get("general", {}).get("notify_enabled", False)

    def send(self, message: str, severity: str = "info"):
        """Send notification."""
        if not self.enabled:
            return

        prefix_map = {
            "info": "ℹ️",
            "warning": "⚠️",
            "critical": "🚨",
            "success": "✅",
            "new_finding": "🔍",
        }
        prefix = prefix_map.get(severity, "📢")
        full_message = f"{prefix} [ReconStorm] {message}"

        # Try using the 'notify' tool (projectdiscovery/notify)
        if Utils.check_tool("notify"):
            try:
                proc = subprocess.Popen(
                    ["notify", "-silent"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                proc.communicate(input=full_message, timeout=30)
                self.logger.debug(f"Notification sent: {message[:80]}")
            except Exception as e:
                self.logger.warning(f"Notify failed: {e}")
        else:
            self.logger.debug(f"Notify tool not found. Message: {full_message}")


# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 1: ASSET DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════

class Stage1AssetDiscovery:
    """
    Stage 1: Asset Discovery
    - Subdomain enumeration via subfinder, amass, assetfinder, findomain
    - Certificate Transparency log queries
    - DNS resolution and validation
    """

    STAGE_NAME = "Stage 1: Asset Discovery"

    def __init__(self, target: str, output_dir: str, config: dict, logger: logging.Logger):
        self.target = target
        self.output_dir = os.path.join(output_dir, "stage1_asset_discovery")
        self.config = config.get("stage1", {})
        self.general_config = config.get("general", {})
        self.api_keys = config.get("api_keys", {})
        self.logger = logger
        Utils.ensure_dir(self.output_dir)

    def run(self) -> Set[str]:
        """Run all subdomain enumeration tools in parallel."""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"  {self.STAGE_NAME} - Target: {self.target}")
        self.logger.info(f"{'='*60}")

        all_subdomains: Set[str] = set()
        tool_outputs = []

        tasks = {
            "subfinder": self._run_subfinder,
            "amass": self._run_amass,
            "assetfinder": self._run_assetfinder,
            "findomain": self._run_findomain,
            "crt.sh": self._run_crtsh,
        }

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for name, func in tasks.items():
                futures[executor.submit(func)] = name

            for future in as_completed(futures):
                tool_name = futures[future]
                try:
                    output_file, count = future.result()
                    if output_file and count > 0:
                        self.logger.info(f"  ✓ {tool_name}: {count} subdomains found")
                        tool_outputs.append(output_file)
                    else:
                        self.logger.warning(f"  ✗ {tool_name}: no results or tool not available")
                except Exception as e:
                    self.logger.error(f"  ✗ {tool_name} failed: {e}")

        # Merge all results
        merged_file = os.path.join(self.output_dir, "all_subdomains.txt")
        total = Utils.merge_files(tool_outputs, merged_file)
        all_subdomains = set(Utils.read_file_lines(merged_file))

        self.logger.info(f"  ► Total unique subdomains: {total}")

        # DNS resolution to filter live subdomains
        if self.config.get("resolve_subdomains", True):
            self._resolve_subdomains(merged_file)

        return all_subdomains

    def _run_subfinder(self) -> Tuple[Optional[str], int]:
        """Run subfinder for subdomain enumeration."""
        if not Utils.check_tool("subfinder"):
            return None, 0

        output_file = os.path.join(self.output_dir, "subfinder.txt")
        threads = self.config.get("subfinder_threads", 30)
        cmd = f"subfinder -d {self.target} -all -silent -t {threads} -o {output_file}"

        # Add API providers config if available
        if self.api_keys.get("virustotal"):
            # subfinder uses its own provider-config.yaml, but we can pass env
            pass

        code, stdout, stderr = Utils.run_command(cmd, timeout=600, logger=self.logger)
        if code == 0:
            lines = Utils.read_file_lines(output_file)
            return output_file, len(lines)
        return None, 0

    def _run_amass(self) -> Tuple[Optional[str], int]:
        """Run amass for subdomain enumeration."""
        if not Utils.check_tool("amass"):
            return None, 0

        output_file = os.path.join(self.output_dir, "amass.txt")
        timeout_min = self.config.get("amass_timeout", 15)
        passive_flag = "-passive" if self.config.get("amass_passive", True) else ""

        cmd = (
            f"amass enum {passive_flag} -d {self.target} "
            f"-timeout {timeout_min} -o {output_file}"
        )

        code, stdout, stderr = Utils.run_command(
            cmd, timeout=timeout_min * 60 + 120, logger=self.logger
        )
        if code == 0:
            lines = Utils.read_file_lines(output_file)
            return output_file, len(lines)
        return None, 0

    def _run_assetfinder(self) -> Tuple[Optional[str], int]:
        """Run assetfinder for subdomain enumeration."""
        if not Utils.check_tool("assetfinder"):
            return None, 0

        output_file = os.path.join(self.output_dir, "assetfinder.txt")
        cmd = f"assetfinder --subs-only {self.target} | sort -u > {output_file}"

        code, stdout, stderr = Utils.run_command(cmd, timeout=300, logger=self.logger)
        if code == 0:
            lines = Utils.read_file_lines(output_file)
            return output_file, len(lines)
        return None, 0

    def _run_findomain(self) -> Tuple[Optional[str], int]:
        """Run findomain for subdomain enumeration."""
        if not Utils.check_tool("findomain"):
            return None, 0

        output_file = os.path.join(self.output_dir, "findomain.txt")
        cmd = f"findomain -t {self.target} -u {output_file} -q"

        code, stdout, stderr = Utils.run_command(cmd, timeout=300, logger=self.logger)
        if code == 0:
            lines = Utils.read_file_lines(output_file)
            return output_file, len(lines)
        return None, 0

    def _run_crtsh(self) -> Tuple[Optional[str], int]:
        """Query crt.sh Certificate Transparency logs."""
        output_file = os.path.join(self.output_dir, "crtsh.txt")
        subdomains = set()

        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = requests.get(url, timeout=60)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub and sub.endswith(self.target):
                            subdomains.add(sub)

                Utils.write_file_lines(output_file, sorted(subdomains))
                return output_file, len(subdomains)
        except Exception as e:
            self.logger.debug(f"crt.sh query failed: {e}")

        return None, 0

    def _resolve_subdomains(self, subdomains_file: str):
        """Resolve subdomains to IPs using dnsx or a simple dig fallback."""
        resolved_file = os.path.join(self.output_dir, "resolved_subdomains.txt")

        if Utils.check_tool("dnsx"):
            cmd = f"cat {subdomains_file} | dnsx -silent -a -resp -o {resolved_file}"
            Utils.run_command(cmd, timeout=600, logger=self.logger)
            resolved = Utils.read_file_lines(resolved_file)
            self.logger.info(f"  ► Resolved subdomains: {len(resolved)}")
        else:
            self.logger.debug("dnsx not found, skipping DNS resolution step")


# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 2: TECHNOLOGY FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════

class Stage2TechFingerprinting:
    """
    Stage 2: Technology Fingerprinting
    - HTTP probing with httpx / httprobe
    - Technology detection
    - Screenshot capture with gowitness / eyewitness
    - Content discovery with ffuf / feroxbuster
    - JavaScript analysis with LinkFinder / SecretFinder
    """

    STAGE_NAME = "Stage 2: Technology Fingerprinting"

    def __init__(self, target: str, output_dir: str, config: dict, logger: logging.Logger):
        self.target = target
        self.output_dir = os.path.join(output_dir, "stage2_tech_fingerprint")
        self.config = config.get("stage2", {})
        self.content_config = config.get("content_discovery", {})
        self.general_config = config.get("general", {})
        self.logger = logger
        Utils.ensure_dir(self.output_dir)
        Utils.ensure_dir(os.path.join(self.output_dir, "screenshots"))
        Utils.ensure_dir(os.path.join(self.output_dir, "js_analysis"))
        Utils.ensure_dir(os.path.join(self.output_dir, "content_discovery"))

    def run(self, subdomains_file: str) -> Tuple[List[str], Dict[str, List[str]]]:
        """Run HTTP probing, tech detection, screenshots, content discovery."""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"  {self.STAGE_NAME} - Target: {self.target}")
        self.logger.info(f"{'='*60}")

        # Step 1: HTTP Probing
        live_hosts = self._run_httpx(subdomains_file)
        live_hosts_file = os.path.join(self.output_dir, "live_hosts.txt")

        if not live_hosts:
            # Fallback to httprobe
            live_hosts = self._run_httprobe(subdomains_file)

        if live_hosts:
            Utils.write_file_lines(live_hosts_file, live_hosts)
            self.logger.info(f"  ► Live hosts discovered: {len(live_hosts)}")
        else:
            self.logger.warning("  ✗ No live hosts found")
            return [], {}

        # Step 2: Screenshots (parallel with other tasks)
        # Step 3: Content Discovery
        # Step 4: JavaScript Analysis
        technologies = {}

        with ThreadPoolExecutor(max_workers=3) as executor:
            screenshot_future = executor.submit(self._run_screenshots, live_hosts_file)
            content_future = executor.submit(self._run_content_discovery, live_hosts_file)
            js_future = executor.submit(self._run_js_analysis, live_hosts)

            try:
                screenshot_future.result()
            except Exception as e:
                self.logger.error(f"Screenshots failed: {e}")

            try:
                content_future.result()
            except Exception as e:
                self.logger.error(f"Content discovery failed: {e}")

            try:
                js_future.result()
            except Exception as e:
                self.logger.error(f"JS analysis failed: {e}")

        # Parse httpx JSON output for technologies
        technologies = self._parse_httpx_tech()

        return live_hosts, technologies

    def _run_httpx(self, subdomains_file: str) -> List[str]:
        """Run httpx for HTTP probing and technology detection."""
        if not Utils.check_tool("httpx"):
            return []

        output_file = os.path.join(self.output_dir, "httpx_output.txt")
        json_file = os.path.join(self.output_dir, "httpx_output.json")
        threads = self.config.get("httpx_threads", 50)
        rate = self.config.get("httpx_rate_limit", 150)
        tech_flag = "-tech-detect" if self.config.get("tech_detect", True) else ""

        cmd = (
            f"cat {subdomains_file} | httpx -silent -t {threads} "
            f"-rl {rate} {tech_flag} "
            f"-status-code -title -content-length -cdn -follow-redirects "
            f"-json -o {json_file} "
            f"| cut -d' ' -f1 > {output_file}"
        )

        code, stdout, stderr = Utils.run_command(cmd, timeout=900, logger=self.logger)
        if code == 0:
            return Utils.read_file_lines(output_file)
        return []

    def _run_httprobe(self, subdomains_file: str) -> List[str]:
        """Fallback: run httprobe for HTTP probing."""
        if not Utils.check_tool("httprobe"):
            return []

        output_file = os.path.join(self.output_dir, "httprobe_output.txt")
        cmd = f"cat {subdomains_file} | httprobe -c 50 | sort -u > {output_file}"

        code, stdout, stderr = Utils.run_command(cmd, timeout=600, logger=self.logger)
        if code == 0:
            return Utils.read_file_lines(output_file)
        return []

    def _parse_httpx_tech(self) -> Dict[str, List[str]]:
        """Parse httpx JSON output for technology data."""
        json_file = os.path.join(self.output_dir, "httpx_output.json")
        technologies = {}

        if not os.path.exists(json_file):
            return technologies

        for line in Utils.read_file_lines(json_file):
            try:
                data = json.loads(line)
                url = data.get("url", "")
                tech = data.get("tech", [])
                if url and tech:
                    technologies[url] = tech
            except json.JSONDecodeError:
                continue

        if technologies:
            self.logger.info(f"  ► Technologies detected for {len(technologies)} hosts")
            # Write summary
            tech_summary = os.path.join(self.output_dir, "technologies.json")
            with open(tech_summary, "w") as f:
                json.dump(technologies, f, indent=2)

        return technologies

    def _run_screenshots(self, live_hosts_file: str):
        """Capture screenshots using gowitness or eyewitness."""
        screenshot_dir = os.path.join(self.output_dir, "screenshots")
        threads = self.config.get("screenshot_threads", 10)

        if Utils.check_tool("gowitness"):
            cmd = (
                f"gowitness file -f {live_hosts_file} "
                f"--screenshot-path {screenshot_dir} "
                f"--threads {threads} --timeout 15"
            )
            code, _, _ = Utils.run_command(cmd, timeout=1200, logger=self.logger)
            if code == 0:
                screenshots = list(Path(screenshot_dir).glob("*.png"))
                self.logger.info(f"  ✓ Screenshots captured: {len(screenshots)}")
                return

        if Utils.check_tool("eyewitness"):
            cmd = (
                f"eyewitness -f {live_hosts_file} "
                f"-d {screenshot_dir} --timeout 15 --no-prompt "
                f"--threads {threads}"
            )
            code, _, _ = Utils.run_command(cmd, timeout=1200, logger=self.logger)
            if code == 0:
                self.logger.info("  ✓ EyeWitness screenshots captured")
                return

        self.logger.warning("  ✗ No screenshot tool available (gowitness/eyewitness)")

    def _run_content_discovery(self, live_hosts_file: str):
        """Run content discovery with ffuf or feroxbuster on live hosts."""
        content_dir = os.path.join(self.output_dir, "content_discovery")
        wordlist = self.content_config.get("wordlist", "")

        if not wordlist or not os.path.exists(wordlist):
            self.logger.warning("  ✗ Content discovery wordlist not found, skipping")
            return

        live_hosts = Utils.read_file_lines(live_hosts_file)
        # Limit to avoid excessive scanning
        max_hosts = 20
        hosts_to_scan = live_hosts[:max_hosts]

        if len(live_hosts) > max_hosts:
            self.logger.info(
                f"  ⚠ Limiting content discovery to first {max_hosts} hosts "
                f"(of {len(live_hosts)})"
            )

        if Utils.check_tool("ffuf"):
            self._run_ffuf(hosts_to_scan, wordlist, content_dir)
        elif Utils.check_tool("feroxbuster"):
            self._run_feroxbuster(hosts_to_scan, wordlist, content_dir)
        elif Utils.check_tool("dirsearch"):
            self._run_dirsearch(hosts_to_scan, wordlist, content_dir)
        else:
            self.logger.warning("  ✗ No content discovery tool available")

    def _run_ffuf(self, hosts: List[str], wordlist: str, output_dir: str):
        """Run ffuf against a list of hosts."""
        threads = self.content_config.get("ffuf_threads", 40)
        rate = self.content_config.get("ffuf_rate", 0)
        extensions = self.content_config.get("extensions", "php,html,js,txt")
        rate_flag = f"-rate {rate}" if rate > 0 else ""

        for i, host in enumerate(hosts):
            safe_name = host.replace("://", "_").replace("/", "_").replace(":", "_")
            out_file = os.path.join(output_dir, f"ffuf_{safe_name}.json")

            cmd = (
                f"ffuf -u {host}/FUZZ -w {wordlist} "
                f"-t {threads} {rate_flag} "
                f"-e {extensions} "
                f"-mc 200,201,202,204,301,302,307,401,403,405,500 "
                f"-fc 404 -ac -sf "
                f"-o {out_file} -of json -s"
            )
            self.logger.debug(f"  ffuf [{i+1}/{len(hosts)}]: {host}")
            Utils.run_command(cmd, timeout=300, logger=self.logger)

        self.logger.info(f"  ✓ Content discovery (ffuf) completed for {len(hosts)} hosts")

    def _run_feroxbuster(self, hosts: List[str], wordlist: str, output_dir: str):
        """Run feroxbuster against a list of hosts."""
        depth = self.content_config.get("feroxbuster_depth", 3)

        for i, host in enumerate(hosts):
            safe_name = host.replace("://", "_").replace("/", "_").replace(":", "_")
            out_file = os.path.join(output_dir, f"feroxbuster_{safe_name}.txt")

            cmd = (
                f"feroxbuster -u {host} -w {wordlist} "
                f"-d {depth} -t 50 --silent "
                f"-o {out_file}"
            )
            self.logger.debug(f"  feroxbuster [{i+1}/{len(hosts)}]: {host}")
            Utils.run_command(cmd, timeout=600, logger=self.logger)

        self.logger.info(f"  ✓ Content discovery (feroxbuster) completed for {len(hosts)} hosts")

    def _run_dirsearch(self, hosts: List[str], wordlist: str, output_dir: str):
        """Run dirsearch against a list of hosts."""
        extensions = self.content_config.get("extensions", "php,html,js,txt")

        for i, host in enumerate(hosts):
            safe_name = host.replace("://", "_").replace("/", "_").replace(":", "_")
            out_file = os.path.join(output_dir, f"dirsearch_{safe_name}.txt")

            cmd = (
                f"dirsearch -u {host} -w {wordlist} "
                f"-e {extensions} -t 50 --format plain "
                f"-o {out_file} --quiet-mode"
            )
            self.logger.debug(f"  dirsearch [{i+1}/{len(hosts)}]: {host}")
            Utils.run_command(cmd, timeout=600, logger=self.logger)

        self.logger.info(f"  ✓ Content discovery (dirsearch) completed for {len(hosts)} hosts")

    def _run_js_analysis(self, live_hosts: List[str]):
        """Run JavaScript analysis with LinkFinder and SecretFinder."""
        js_dir = os.path.join(self.output_dir, "js_analysis")
        max_hosts = 30
        hosts = live_hosts[:max_hosts]

        # Step 1: Collect JS files using httpx or gau
        js_files_list = os.path.join(js_dir, "js_urls.txt")
        if Utils.check_tool("gau"):
            cmd = (
                f"echo {self.target} | gau --threads 5 --subs "
                f"| grep -iE '\\.js$' | sort -u > {js_files_list}"
            )
            Utils.run_command(cmd, timeout=300, logger=self.logger)

        # Step 2: Run LinkFinder on JS files
        if Utils.check_tool("linkfinder") or Utils.check_tool("python3"):
            links_output = os.path.join(js_dir, "linkfinder_results.txt")
            for host in hosts[:10]:
                cmd = (
                    f"python3 -m linkfinder -i {host} -o cli 2>/dev/null "
                    f">> {links_output}"
                )
                Utils.run_command(cmd, timeout=60, logger=self.logger)

            if os.path.exists(links_output):
                links = Utils.read_file_lines(links_output)
                self.logger.info(f"  ✓ LinkFinder: {len(links)} endpoints found")

        # Step 3: Run SecretFinder on JS files
        if Utils.check_tool("secretfinder") or Utils.check_tool("python3"):
            secrets_output = os.path.join(js_dir, "secretfinder_results.txt")
            for host in hosts[:10]:
                cmd = (
                    f"python3 -m SecretFinder -i {host} -o cli 2>/dev/null "
                    f">> {secrets_output}"
                )
                Utils.run_command(cmd, timeout=60, logger=self.logger)

            if os.path.exists(secrets_output):
                secrets = Utils.read_file_lines(secrets_output)
                self.logger.info(f"  ✓ SecretFinder: {len(secrets)} potential secrets found")


# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 3: PORT SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

class Stage3PortScanning:
    """
    Stage 3: Port Scanning
    - Fast port discovery with naabu / masscan
    - Detailed service detection with nmap
    """

    STAGE_NAME = "Stage 3: Port Scanning"

    def __init__(self, target: str, output_dir: str, config: dict, logger: logging.Logger):
        self.target = target
        self.output_dir = os.path.join(output_dir, "stage3_port_scanning")
        self.config = config.get("stage3", {})
        self.general_config = config.get("general", {})
        self.logger = logger
        Utils.ensure_dir(self.output_dir)

    def run(self, subdomains_file: str) -> Dict[str, List[PortInfo]]:
        """Run port scanning pipeline."""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"  {self.STAGE_NAME} - Target: {self.target}")
        self.logger.info(f"{'='*60}")

        open_ports: Dict[str, List[PortInfo]] = {}

        # Step 1: Fast port discovery with naabu
        naabu_results = self._run_naabu(subdomains_file)
        if naabu_results:
            open_ports.update(naabu_results)
        else:
            # Fallback to masscan
            masscan_results = self._run_masscan(subdomains_file)
            if masscan_results:
                open_ports.update(masscan_results)

        # Step 2: Detailed nmap scan on discovered ports
        if open_ports:
            nmap_results = self._run_nmap_service_detection(open_ports)
            # Merge nmap service info into open_ports
            for host, ports in nmap_results.items():
                if host in open_ports:
                    # Update with service information
                    port_map = {p.port: p for p in open_ports[host]}
                    for p in ports:
                        if p.port in port_map:
                            port_map[p.port].service = p.service
                            port_map[p.port].version = p.version
                        else:
                            open_ports[host].append(p)
                else:
                    open_ports[host] = ports

        # Save results
        self._save_results(open_ports)

        total_ports = sum(len(p) for p in open_ports.values())
        self.logger.info(
            f"  ► Total: {total_ports} open ports across {len(open_ports)} hosts"
        )

        return open_ports

    def _run_naabu(self, subdomains_file: str) -> Dict[str, List[PortInfo]]:
        """Run naabu for fast port scanning."""
        if not Utils.check_tool("naabu"):
            return {}

        output_file = os.path.join(self.output_dir, "naabu_output.txt")
        json_file = os.path.join(self.output_dir, "naabu_output.json")
        rate = self.config.get("naabu_rate", 5000)
        top_ports = self.config.get("naabu_top_ports", 1000)

        port_flag = "-p -" if self.config.get("full_port_scan", False) else f"-top-ports {top_ports}"

        cmd = (
            f"naabu -list {subdomains_file} -rate {rate} "
            f"{port_flag} -silent -json -o {json_file}"
        )

        code, stdout, stderr = Utils.run_command(cmd, timeout=1800, logger=self.logger)

        results = {}
        if code == 0 and os.path.exists(json_file):
            for line in Utils.read_file_lines(json_file):
                try:
                    data = json.loads(line)
                    host = data.get("host", data.get("ip", ""))
                    port = data.get("port", 0)
                    if host and port:
                        if host not in results:
                            results[host] = []
                        results[host].append(PortInfo(port=port))
                except json.JSONDecodeError:
                    continue

            self.logger.info(f"  ✓ Naabu: found ports on {len(results)} hosts")

        return results

    def _run_masscan(self, subdomains_file: str) -> Dict[str, List[PortInfo]]:
        """Run masscan as fallback port scanner."""
        if not Utils.check_tool("masscan"):
            return {}

        # masscan needs IPs, so we need to resolve first
        output_file = os.path.join(self.output_dir, "masscan_output.json")
        rate = self.config.get("masscan_rate", 10000)
        ports = "1-65535" if self.config.get("full_port_scan", False) else "1-10000"

        # Resolve subdomains to IPs for masscan
        ips_file = os.path.join(self.output_dir, "ips_for_masscan.txt")
        if Utils.check_tool("dnsx"):
            cmd = f"cat {subdomains_file} | dnsx -silent -a -resp-only | sort -u > {ips_file}"
            Utils.run_command(cmd, timeout=300, logger=self.logger)
        else:
            # Simple fallback using dig
            subdomains = Utils.read_file_lines(subdomains_file)
            ips = set()
            for sub in subdomains[:100]:
                code, stdout, _ = Utils.run_command(
                    f"dig +short {sub} A | head -1", timeout=10
                )
                if code == 0 and stdout.strip():
                    ip = stdout.strip().split('\n')[0]
                    if ip and not ip.startswith(';'):
                        ips.add(ip)
            Utils.write_file_lines(ips_file, sorted(ips))

        if not Utils.read_file_lines(ips_file):
            return {}

        cmd = (
            f"masscan -iL {ips_file} -p {ports} --rate {rate} "
            f"-oJ {output_file} --wait 3"
        )

        code, stdout, stderr = Utils.run_command(cmd, timeout=3600, logger=self.logger)

        results = {}
        if os.path.exists(output_file):
            try:
                with open(output_file) as f:
                    content = f.read().strip()
                    if content:
                        # masscan JSON can have trailing commas
                        content = content.rstrip(",\n") 
                        if not content.startswith("["):
                            content = "[" + content + "]"
                        data = json.loads(content)
                        for entry in data:
                            ip = entry.get("ip", "")
                            for port_info in entry.get("ports", []):
                                port = port_info.get("port", 0)
                                proto = port_info.get("proto", "tcp")
                                if ip and port:
                                    if ip not in results:
                                        results[ip] = []
                                    results[ip].append(
                                        PortInfo(port=port, protocol=proto)
                                    )
            except (json.JSONDecodeError, Exception) as e:
                self.logger.warning(f"Failed to parse masscan output: {e}")

            self.logger.info(f"  ✓ Masscan: found ports on {len(results)} hosts")

        return results

    def _run_nmap_service_detection(
        self, open_ports: Dict[str, List[PortInfo]]
    ) -> Dict[str, List[PortInfo]]:
        """Run nmap for detailed service/version detection on discovered ports."""
        if not Utils.check_tool("nmap"):
            self.logger.warning("  ✗ nmap not found, skipping service detection")
            return {}

        results = {}
        scripts = self.config.get("nmap_scripts", "default,vuln")

        # Group by host, limit scope
        max_hosts = 50
        hosts_to_scan = dict(list(open_ports.items())[:max_hosts])

        for host, ports in hosts_to_scan.items():
            port_list = ",".join(str(p.port) for p in ports)
            output_file = os.path.join(self.output_dir, f"nmap_{host.replace('.', '_')}.xml")

            cmd = (
                f"nmap -sV -sC --script={scripts} "
                f"-p {port_list} {host} "
                f"-oX {output_file} --open -T4"
            )

            code, stdout, stderr = Utils.run_command(cmd, timeout=600, logger=self.logger)

            if code == 0:
                parsed = self._parse_nmap_xml(output_file, host)
                if parsed:
                    results[host] = parsed

        self.logger.info(f"  ✓ Nmap service detection completed for {len(results)} hosts")
        return results

    def _parse_nmap_xml(self, xml_file: str, host: str) -> List[PortInfo]:
        """Parse nmap XML output for service information."""
        ports = []
        if not os.path.exists(xml_file):
            return ports

        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for host_elem in root.findall(".//host"):
                for port_elem in host_elem.findall(".//port"):
                    state = port_elem.find("state")
                    if state is not None and state.get("state") == "open":
                        port_num = int(port_elem.get("portid", 0))
                        protocol = port_elem.get("protocol", "tcp")

                        service_elem = port_elem.find("service")
                        service_name = ""
                        service_version = ""
                        if service_elem is not None:
                            service_name = service_elem.get("name", "")
                            product = service_elem.get("product", "")
                            version = service_elem.get("version", "")
                            service_version = f"{product} {version}".strip()

                        ports.append(PortInfo(
                            port=port_num,
                            protocol=protocol,
                            service=service_name,
                            version=service_version,
                        ))
        except Exception as e:
            self.logger.debug(f"Failed to parse nmap XML for {host}: {e}")

        return ports

    def _save_results(self, open_ports: Dict[str, List[PortInfo]]):
        """Save port scanning results to files."""
        summary_file = os.path.join(self.output_dir, "port_scan_summary.txt")
        json_file = os.path.join(self.output_dir, "port_scan_results.json")

        # Text summary
        with open(summary_file, "w") as f:
            for host, ports in sorted(open_ports.items()):
                for p in sorted(ports, key=lambda x: x.port):
                    service_str = f" ({p.service})" if p.service else ""
                    version_str = f" - {p.version}" if p.version else ""
                    f.write(f"{host}:{p.port}{service_str}{version_str}\n")

        # JSON output
        json_data = {
            host: [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "version": p.version,
                }
                for p in ports
            ]
            for host, ports in open_ports.items()
        }
        with open(json_file, "w") as f:
            json.dump(json_data, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 4: OSINT
# ═══════════════════════════════════════════════════════════════════════════════

class Stage4OSINT:
    """
    Stage 4: OSINT
    - GitHub dorking for leaked secrets
    - Google dorking for exposed data
    - Shodan / Censys queries
    - theHarvester for email/host/name gathering
    - Secret detection with trufflehog / gitleaks
    """

    STAGE_NAME = "Stage 4: OSINT & Secret Detection"

    def __init__(self, target: str, output_dir: str, config: dict, logger: logging.Logger):
        self.target = target
        self.output_dir = os.path.join(output_dir, "stage4_osint")
        self.config = config.get("stage4", {})
        self.api_keys = config.get("api_keys", {})
        self.general_config = config.get("general", {})
        self.logger = logger
        Utils.ensure_dir(self.output_dir)
        Utils.ensure_dir(os.path.join(self.output_dir, "github_dorks"))
        Utils.ensure_dir(os.path.join(self.output_dir, "google_dorks"))
        Utils.ensure_dir(os.path.join(self.output_dir, "secrets"))

    def run(self) -> Dict[str, Any]:
        """Run all OSINT operations."""
        self.logger.info(f"{'='*60}")
        self.logger.info(f"  {self.STAGE_NAME} - Target: {self.target}")
        self.logger.info(f"{'='*60}")

        osint_results = {
            "github_dorks": [],
            "google_dorks": [],
            "shodan": {},
            "censys": {},
            "theharvester": {},
            "secrets": [],
        }

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self._run_github_dorking): "github_dorks",
                executor.submit(self._run_shodan): "shodan",
                executor.submit(self._run_theharvester): "theharvester",
                executor.submit(self._run_secret_detection): "secrets",
            }

            for future in as_completed(futures):
                key = futures[future]
                try:
                    result = future.result()
                    osint_results[key] = result
                except Exception as e:
                    self.logger.error(f"  ✗ {key} failed: {e}")

        # Google dorking runs sequentially due to rate limits
        osint_results["google_dorks"] = self._run_google_dorking()

        # Censys
        osint_results["censys"] = self._run_censys()

        # Save full results
        results_file = os.path.join(self.output_dir, "osint_results.json")
        with open(results_file, "w") as f:
            json.dump(osint_results, f, indent=2, default=str)

        return osint_results

    def _run_github_dorking(self) -> List[Dict]:
        """Search GitHub for leaked secrets related to the target domain."""
        github_token = self.api_keys.get("github_token", "")
        if not github_token:
            self.logger.warning("  ✗ GitHub token not configured, skipping GitHub dorking")
            return []

        results = []
        delay = self.config.get("github_dork_delay", 5)
        output_file = os.path.join(self.output_dir, "github_dorks", "results.json")

        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3.text-match+json",
        }

        for dork in GITHUB_DORKS:
            query = dork.replace("{domain}", self.target)
            try:
                resp = requests.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 10},
                    headers=headers,
                    timeout=30,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    count = data.get("total_count", 0)
                    if count > 0:
                        for item in data.get("items", []):
                            result = {
                                "dork": query,
                                "repo": item.get("repository", {}).get("full_name", ""),
                                "file": item.get("path", ""),
                                "url": item.get("html_url", ""),
                                "text_matches": [
                                    m.get("fragment", "")
                                    for m in item.get("text_matches", [])
                                ],
                            }
                            results.append(result)
                        self.logger.info(
                            f"  🔍 GitHub dork hit: '{query[:50]}...' -> {count} results"
                        )
                elif resp.status_code == 403:
                    self.logger.warning("  ⚠ GitHub API rate limit reached, pausing...")
                    time.sleep(60)
                elif resp.status_code == 422:
                    self.logger.debug(f"  GitHub dork validation error: {query[:50]}")

                time.sleep(delay)

            except Exception as e:
                self.logger.debug(f"GitHub dork failed: {e}")
                time.sleep(delay)

        # Save results
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)

        self.logger.info(f"  ✓ GitHub dorking: {len(results)} potential findings")
        return results

    def _run_google_dorking(self) -> List[str]:
        """Generate Google dork queries (manual review - not automated scraping)."""
        output_file = os.path.join(self.output_dir, "google_dorks", "google_dorks.txt")

        dorks = []
        for dork_template in GOOGLE_DORKS:
            dork = dork_template.replace("{domain}", self.target)
            dorks.append(dork)

        Utils.write_file_lines(output_file, dorks)
        self.logger.info(
            f"  ✓ Generated {len(dorks)} Google dork queries -> {output_file}"
        )
        self.logger.info(
            "  ℹ Google dorks saved for manual review (automated scraping may violate ToS)"
        )

        return dorks

    def _run_shodan(self) -> Dict:
        """Query Shodan for target intelligence."""
        api_key = self.api_keys.get("shodan", "")
        if not api_key:
            self.logger.warning("  ✗ Shodan API key not configured, skipping")
            return {}

        output_file = os.path.join(self.output_dir, "shodan_results.json")
        results = {"hosts": [], "summary": {}}

        try:
            import shodan
            api = shodan.Shodan(api_key)

            # Search for the domain
            query = f"hostname:{self.target}"
            search_results = api.search(query)

            results["summary"] = {
                "total_results": search_results.get("total", 0),
                "query": query,
            }

            for match in search_results.get("matches", []):
                host_info = {
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", 0),
                    "org": match.get("org", ""),
                    "os": match.get("os", ""),
                    "product": match.get("product", ""),
                    "version": match.get("version", ""),
                    "hostnames": match.get("hostnames", []),
                    "vulns": match.get("vulns", []),
                    "ssl": bool(match.get("ssl", {})),
                    "location": {
                        "country": match.get("location", {}).get("country_name", ""),
                        "city": match.get("location", {}).get("city", ""),
                    },
                }
                results["hosts"].append(host_info)

            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)

            self.logger.info(
                f"  ✓ Shodan: {len(results['hosts'])} hosts found, "
                f"{results['summary']['total_results']} total results"
            )

        except ImportError:
            self.logger.warning("  ✗ Shodan Python library not installed (pip install shodan)")
        except Exception as e:
            self.logger.error(f"  ✗ Shodan query failed: {e}")

        return results

    def _run_censys(self) -> Dict:
        """Query Censys for target intelligence."""
        censys_id = self.api_keys.get("censys_id", "")
        censys_secret = self.api_keys.get("censys_secret", "")

        if not censys_id or not censys_secret:
            self.logger.warning("  ✗ Censys API keys not configured, skipping")
            return {}

        output_file = os.path.join(self.output_dir, "censys_results.json")
        results = {"hosts": [], "certificates": []}

        try:
            from censys.search import CensysHosts, CensysCertificates

            # Host search
            h = CensysHosts(api_id=censys_id, api_secret=censys_secret)
            query = self.target
            for page in h.search(query, per_page=25, pages=2):
                for host in page:
                    results["hosts"].append({
                        "ip": host.get("ip", ""),
                        "services": host.get("services", []),
                        "location": host.get("location", {}),
                        "autonomous_system": host.get("autonomous_system", {}),
                    })

            # Certificate search
            try:
                c = CensysCertificates(api_id=censys_id, api_secret=censys_secret)
                for page in c.search(f"parsed.names: {self.target}", per_page=25, pages=1):
                    for cert in page:
                        results["certificates"].append({
                            "fingerprint": cert.get("fingerprint_sha256", ""),
                            "names": cert.get("parsed", {}).get("names", []),
                            "issuer": cert.get("parsed", {}).get("issuer_dn", ""),
                        })
            except Exception:
                pass  # Certificates API may not be available on all plans

            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)

            self.logger.info(
                f"  ✓ Censys: {len(results['hosts'])} hosts, "
                f"{len(results['certificates'])} certificates"
            )

        except ImportError:
            self.logger.warning("  ✗ Censys Python library not installed (pip install censys)")
        except Exception as e:
            self.logger.error(f"  ✗ Censys query failed: {e}")

        return results

    def _run_theharvester(self) -> Dict:
        """Run theHarvester for OSINT data gathering."""
        if not Utils.check_tool("theHarvester"):
            # Try alternate name
            if not Utils.check_tool("theharvester"):
                self.logger.warning("  ✗ theHarvester not found, skipping")
                return {}

        output_file = os.path.join(self.output_dir, "theharvester_results")
        sources = self.config.get(
            "theharvester_sources", "google,bing,linkedin,twitter,dnsdumpster"
        )

        # Try both common binary names
        tool_name = "theHarvester" if Utils.check_tool("theHarvester") else "theharvester"

        cmd = (
            f"{tool_name} -d {self.target} "
            f"-b {sources} "
            f"-f {output_file}"
        )

        code, stdout, stderr = Utils.run_command(cmd, timeout=600, logger=self.logger)

        results = {"emails": [], "hosts": [], "ips": []}

        # Parse theHarvester XML output
        xml_file = f"{output_file}.xml"
        if os.path.exists(xml_file):
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(xml_file)
                root = tree.getroot()

                for email in root.findall(".//email"):
                    if email.text:
                        results["emails"].append(email.text.strip())

                for host in root.findall(".//host"):
                    if host.text:
                        results["hosts"].append(host.text.strip())

                for ip in root.findall(".//ip"):
                    if ip.text:
                        results["ips"].append(ip.text.strip())

            except Exception as e:
                self.logger.debug(f"Failed to parse theHarvester XML: {e}")

        # Also try parsing stdout
        if stdout:
            for line in stdout.split("\n"):
                line = line.strip()
                if "@" in line and self.target in line:
                    results["emails"].append(line)

        self.logger.info(
            f"  ✓ theHarvester: {len(results['emails'])} emails, "
            f"{len(results['hosts'])} hosts"
        )

        return results

    def _run_secret_detection(self) -> List[Dict]:
        """Run trufflehog and gitleaks for secret detection."""
        secrets = []
        secrets_dir = os.path.join(self.output_dir, "secrets")

        # Step 1: TruffleHog - scan for secrets in Git repos
        if Utils.check_tool("trufflehog"):
            secrets.extend(self._run_trufflehog(secrets_dir))

        # Step 2: Gitleaks - scan for secrets in Git repos
        if Utils.check_tool("gitleaks"):
            secrets.extend(self._run_gitleaks(secrets_dir))

        self.logger.info(f"  ✓ Secret detection: {len(secrets)} potential secrets found")
        return secrets

    def _run_trufflehog(self, output_dir: str) -> List[Dict]:
        """Run trufflehog to find secrets."""
        results = []
        output_file = os.path.join(output_dir, "trufflehog_results.json")
        verified_flag = (
            "--only-verified" if self.config.get("trufflehog_verified_only", True) else ""
        )

        # Scan GitHub org/user
        github_token = self.api_keys.get("github_token", "")
        token_flag = f"--token={github_token}" if github_token else ""

        # Extract potential org name from domain
        org_name = self.target.split(".")[0]

        cmd = (
            f"trufflehog github --org={org_name} "
            f"{verified_flag} {token_flag} "
            f"--json > {output_file} 2>/dev/null"
        )

        code, stdout, stderr = Utils.run_command(cmd, timeout=1800, logger=self.logger)

        if os.path.exists(output_file):
            for line in Utils.read_file_lines(output_file):
                try:
                    data = json.loads(line)
                    results.append({
                        "source": "trufflehog",
                        "detector": data.get("DetectorName", ""),
                        "verified": data.get("Verified", False),
                        "raw": data.get("Raw", "")[:200],
                        "source_metadata": data.get("SourceMetadata", {}),
                    })
                except json.JSONDecodeError:
                    continue

            self.logger.info(f"  ✓ TruffleHog: {len(results)} secrets found")

        return results

    def _run_gitleaks(self, output_dir: str) -> List[Dict]:
        """Run gitleaks to find secrets."""
        results = []
        output_file = os.path.join(output_dir, "gitleaks_results.json")
        depth = self.config.get("gitleaks_depth", 5)

        # Extract potential org name from domain
        org_name = self.target.split(".")[0]

        # Gitleaks needs a cloned repo, so we'll scan known repos if available
        repos_dir = os.path.join(output_dir, "repos")
        Utils.ensure_dir(repos_dir)

        github_token = self.api_keys.get("github_token", "")
        if github_token:
            # Try to list and clone org repos
            headers = {"Authorization": f"token {github_token}"}
            try:
                resp = requests.get(
                    f"https://api.github.com/orgs/{org_name}/repos",
                    headers=headers,
                    params={"per_page": 10, "sort": "updated"},
                    timeout=30,
                )
                if resp.status_code == 200:
                    repos = resp.json()
                    for repo in repos[:5]:  # Limit to 5 repos
                        repo_name = repo.get("full_name", "")
                        clone_url = repo.get("clone_url", "")
                        repo_dir = os.path.join(repos_dir, repo.get("name", ""))

                        if clone_url and not os.path.exists(repo_dir):
                            clone_cmd = (
                                f"git clone --depth {depth} "
                                f"{clone_url} {repo_dir} 2>/dev/null"
                            )
                            Utils.run_command(clone_cmd, timeout=120, logger=self.logger)

                        if os.path.exists(repo_dir):
                            repo_output = os.path.join(
                                output_dir,
                                f"gitleaks_{repo.get('name', 'unknown')}.json",
                            )
                            cmd = (
                                f"gitleaks detect --source={repo_dir} "
                                f"--report-format=json --report-path={repo_output} "
                                f"--no-banner 2>/dev/null"
                            )
                            Utils.run_command(cmd, timeout=300, logger=self.logger)

                            if os.path.exists(repo_output):
                                try:
                                    with open(repo_output) as f:
                                        findings = json.load(f)
                                    for finding in findings:
                                        results.append({
                                            "source": "gitleaks",
                                            "repo": repo_name,
                                            "rule": finding.get("RuleID", ""),
                                            "file": finding.get("File", ""),
                                            "line": finding.get("StartLine", 0),
                                            "secret": finding.get("Secret", "")[:100],
                                            "commit": finding.get("Commit", ""),
                                        })
                                except (json.JSONDecodeError, Exception):
                                    pass

            except Exception as e:
                self.logger.debug(f"GitHub repo enumeration failed: {e}")

        if results:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"  ✓ Gitleaks: {len(results)} secrets found")

        return results


# ═══════════════════════════════════════════════════════════════════════════════
# STAGE 5: CONTINUOUS MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

class Stage5ContinuousMonitoring:
    """
    Stage 5: Continuous Monitoring
    - Periodic re-scanning for new subdomains
    - New port detection
    - Vulnerability scanning with Nuclei
    - Diff-based change detection
    - Notification on new findings
    """

    STAGE_NAME = "Stage 5: Continuous Monitoring"

    def __init__(
        self,
        target: str,
        output_dir: str,
        config: dict,
        logger: logging.Logger,
        notifier: Notifier,
    ):
        self.target = target
        self.output_dir = os.path.join(output_dir, "stage5_monitoring")
        self.config = config.get("stage5", {})
        self.full_config = config
        self.general_config = config.get("general", {})
        self.logger = logger
        self.notifier = notifier
        self.base_output_dir = output_dir
        self._stop_event = threading.Event()
        Utils.ensure_dir(self.output_dir)
        Utils.ensure_dir(os.path.join(self.output_dir, "history"))
        Utils.ensure_dir(os.path.join(self.output_dir, "nuclei"))

    def run_nuclei_scan(self, live_hosts_file: str) -> List[Dict]:
        """Run Nuclei vulnerability scanner against live hosts."""
        if not Utils.check_tool("nuclei"):
            self.logger.warning("  ✗ Nuclei not found, skipping vulnerability scanning")
            return []

        self.logger.info(f"{'='*60}")
        self.logger.info(f"  Running Nuclei Vulnerability Scan")
        self.logger.info(f"{'='*60}")

        output_file = os.path.join(self.output_dir, "nuclei", "nuclei_results.json")
        severity = self.config.get("nuclei_severity", "critical,high,medium")
        rate_limit = self.config.get("nuclei_rate_limit", 150)

        cmd = (
            f"nuclei -l {live_hosts_file} "
            f"-severity {severity} "
            f"-rl {rate_limit} "
            f"-json -o {output_file} "
            f"-silent -stats"
        )

        code, stdout, stderr = Utils.run_command(cmd, timeout=7200, logger=self.logger)

        vulnerabilities = []
        if os.path.exists(output_file):
            for line in Utils.read_file_lines(output_file):
                try:
                    data = json.loads(line)
                    vuln = {
                        "template": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", ""),
                        "host": data.get("host", ""),
                        "matched_url": data.get("matched-at", ""),
                        "type": data.get("type", ""),
                        "description": data.get("info", {}).get("description", ""),
                        "reference": data.get("info", {}).get("reference", []),
                        "tags": data.get("info", {}).get("tags", []),
                        "timestamp": data.get("timestamp", ""),
                    }
                    vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    continue

            # Categorize by severity
            severity_count = {}
            for v in vulnerabilities:
                sev = v.get("severity", "unknown")
                severity_count[sev] = severity_count.get(sev, 0) + 1

            self.logger.info(f"  ✓ Nuclei scan complete: {len(vulnerabilities)} findings")
            for sev, count in sorted(severity_count.items()):
                color = {
                    "critical": Fore.RED,
                    "high": Fore.LIGHTRED_EX,
                    "medium": Fore.YELLOW,
                    "low": Fore.BLUE,
                    "info": Fore.CYAN,
                }.get(sev, "")
                self.logger.info(f"    {color}[{sev.upper()}] {count} findings{Style.RESET_ALL}")

            # Notify on critical/high findings
            critical_high = [
                v for v in vulnerabilities if v["severity"] in ("critical", "high")
            ]
            if critical_high:
                msg = (
                    f"🚨 Nuclei found {len(critical_high)} critical/high vulnerabilities "
                    f"on {self.target}!"
                )
                self.notifier.send(msg, severity="critical")
                for v in critical_high[:5]:
                    self.notifier.send(
                        f"  - [{v['severity'].upper()}] {v['name']} @ {v['host']}",
                        severity="critical",
                    )

        return vulnerabilities

    def start_monitoring(self, interval_hours: int = None):
        """Start continuous monitoring loop."""
        interval = interval_hours or self.config.get("monitor_interval_hours", 6)

        self.logger.info(f"{'='*60}")
        self.logger.info(f"  {self.STAGE_NAME} - Target: {self.target}")
        self.logger.info(f"  Monitoring interval: every {interval} hours")
        self.logger.info(f"  Press Ctrl+C to stop")
        self.logger.info(f"{'='*60}")

        self.notifier.send(
            f"🔄 Continuous monitoring started for {self.target} "
            f"(every {interval}h)",
            severity="info",
        )

        # Run first scan immediately
        self._monitoring_cycle()

        # Schedule periodic scans
        schedule.every(interval).hours.do(self._monitoring_cycle)

        while not self._stop_event.is_set():
            schedule.run_pending()
            time.sleep(60)

    def stop_monitoring(self):
        """Stop the monitoring loop."""
        self._stop_event.set()
        self.logger.info("  Monitoring stopped")

    def _monitoring_cycle(self):
        """Execute one monitoring cycle."""
        timestamp = Utils.timestamp()
        cycle_dir = os.path.join(self.output_dir, "history", timestamp)
        Utils.ensure_dir(cycle_dir)

        self.logger.info(f"\n  🔄 Monitoring cycle started at {timestamp}")

        try:
            # Re-run subdomain enumeration
            new_subdomains = self._check_new_subdomains(cycle_dir)

            # Re-run HTTP probing
            new_live_hosts = self._check_new_live_hosts(cycle_dir)

            # Re-run port scanning on new hosts
            new_ports = self._check_new_ports(cycle_dir)

            # Re-run Nuclei on new/changed hosts
            new_vulns = self._check_new_vulns(cycle_dir)

            # Generate diff report
            self._generate_diff_report(cycle_dir, new_subdomains, new_live_hosts,
                                       new_ports, new_vulns)

        except Exception as e:
            self.logger.error(f"  Monitoring cycle failed: {e}")
            self.notifier.send(
                f"❌ Monitoring cycle failed for {self.target}: {e}",
                severity="warning",
            )

    def _check_new_subdomains(self, cycle_dir: str) -> List[str]:
        """Check for newly discovered subdomains."""
        self.logger.info("  → Checking for new subdomains...")

        current_file = os.path.join(
            self.base_output_dir, "stage1_asset_discovery", "all_subdomains.txt"
        )
        previous_file = os.path.join(self.output_dir, "last_subdomains.txt")
        new_file = os.path.join(cycle_dir, "new_subdomains.txt")

        # Run quick subdomain scan
        stage1 = Stage1AssetDiscovery(
            self.target, cycle_dir, self.full_config, self.logger
        )
        new_subs = stage1.run()

        # Write current results
        current_subs_file = os.path.join(cycle_dir, "all_subdomains.txt")
        Utils.write_file_lines(current_subs_file, sorted(new_subs))

        # Diff with previous
        new_findings = Utils.diff_files(previous_file, current_subs_file)

        if new_findings:
            Utils.write_file_lines(new_file, new_findings)
            self.logger.info(f"  🔍 {len(new_findings)} NEW subdomains found!")
            for sub in new_findings[:10]:
                self.logger.info(f"    + {sub}")

            if self.config.get("notify_new_subdomains", True):
                self.notifier.send(
                    f"🔍 {len(new_findings)} new subdomains found for {self.target}:\n"
                    + "\n".join(new_findings[:5]),
                    severity="new_finding",
                )

        # Update baseline
        shutil.copy2(current_subs_file, previous_file)

        return new_findings

    def _check_new_live_hosts(self, cycle_dir: str) -> List[str]:
        """Check for newly alive hosts."""
        self.logger.info("  → Checking for new live hosts...")

        previous_file = os.path.join(self.output_dir, "last_live_hosts.txt")
        subs_file = os.path.join(cycle_dir, "stage1_asset_discovery", "all_subdomains.txt")

        if not os.path.exists(subs_file):
            return []

        # Quick HTTP probe
        current_file = os.path.join(cycle_dir, "live_hosts.txt")
        if Utils.check_tool("httpx"):
            cmd = f"cat {subs_file} | httpx -silent -t 50 > {current_file}"
            Utils.run_command(cmd, timeout=600, logger=self.logger)
        elif Utils.check_tool("httprobe"):
            cmd = f"cat {subs_file} | httprobe -c 50 > {current_file}"
            Utils.run_command(cmd, timeout=600, logger=self.logger)

        new_findings = Utils.diff_files(previous_file, current_file)

        if new_findings:
            self.logger.info(f"  🔍 {len(new_findings)} NEW live hosts!")
            if self.config.get("notify_new_subdomains", True):
                self.notifier.send(
                    f"🌐 {len(new_findings)} new live hosts for {self.target}",
                    severity="new_finding",
                )

        if os.path.exists(current_file):
            shutil.copy2(current_file, previous_file)

        return new_findings

    def _check_new_ports(self, cycle_dir: str) -> List[str]:
        """Check for newly opened ports."""
        self.logger.info("  → Checking for new open ports...")

        previous_file = os.path.join(self.output_dir, "last_ports.txt")
        subs_file = os.path.join(cycle_dir, "stage1_asset_discovery", "all_subdomains.txt")

        if not os.path.exists(subs_file):
            return []

        current_file = os.path.join(cycle_dir, "ports.txt")

        if Utils.check_tool("naabu"):
            cmd = (
                f"naabu -list {subs_file} -top-ports 100 -silent "
                f"| sort -u > {current_file}"
            )
            Utils.run_command(cmd, timeout=600, logger=self.logger)

        new_findings = Utils.diff_files(previous_file, current_file)

        if new_findings:
            self.logger.info(f"  🔍 {len(new_findings)} NEW open ports!")
            if self.config.get("notify_new_ports", True):
                self.notifier.send(
                    f"🔓 {len(new_findings)} new open ports for {self.target}:\n"
                    + "\n".join(new_findings[:10]),
                    severity="new_finding",
                )

        if os.path.exists(current_file):
            shutil.copy2(current_file, previous_file)

        return new_findings

    def _check_new_vulns(self, cycle_dir: str) -> List[Dict]:
        """Run Nuclei scan and check for new vulnerabilities."""
        self.logger.info("  → Checking for new vulnerabilities...")

        live_hosts_file = os.path.join(cycle_dir, "live_hosts.txt")
        if not os.path.exists(live_hosts_file):
            return []

        previous_file = os.path.join(self.output_dir, "last_vulns.json")
        nuclei_output = os.path.join(cycle_dir, "nuclei_results.json")

        if Utils.check_tool("nuclei"):
            severity = self.config.get("nuclei_severity", "critical,high,medium")
            cmd = (
                f"nuclei -l {live_hosts_file} -severity {severity} "
                f"-json -o {nuclei_output} -silent"
            )
            Utils.run_command(cmd, timeout=3600, logger=self.logger)

        new_vulns = []
        if os.path.exists(nuclei_output):
            # Load previous vulns for comparison
            prev_vuln_keys = set()
            if os.path.exists(previous_file):
                try:
                    with open(previous_file) as f:
                        prev_vulns = json.load(f)
                    for v in prev_vulns:
                        key = f"{v.get('template', '')}|{v.get('host', '')}"
                        prev_vuln_keys.add(key)
                except Exception:
                    pass

            current_vulns = []
            for line in Utils.read_file_lines(nuclei_output):
                try:
                    data = json.loads(line)
                    vuln = {
                        "template": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", ""),
                        "host": data.get("host", ""),
                    }
                    current_vulns.append(vuln)

                    key = f"{vuln['template']}|{vuln['host']}"
                    if key not in prev_vuln_keys:
                        new_vulns.append(vuln)
                except json.JSONDecodeError:
                    continue

            # Save current as baseline
            with open(previous_file, "w") as f:
                json.dump(current_vulns, f, indent=2)

            if new_vulns:
                self.logger.info(f"  🚨 {len(new_vulns)} NEW vulnerabilities found!")
                if self.config.get("notify_new_vulns", True):
                    self.notifier.send(
                        f"🚨 {len(new_vulns)} new vulnerabilities for {self.target}!",
                        severity="critical",
                    )

        return new_vulns

    def _generate_diff_report(
        self,
        cycle_dir: str,
        new_subs: List[str],
        new_hosts: List[str],
        new_ports: List[str],
        new_vulns: List[Dict],
    ):
        """Generate a diff report for this monitoring cycle."""
        report_file = os.path.join(cycle_dir, "diff_report.md")

        with open(report_file, "w") as f:
            f.write(f"# Monitoring Report - {self.target}\n")
            f.write(f"**Date:** {Utils.timestamp()}\n\n")

            f.write(f"## Summary\n")
            f.write(f"- New Subdomains: {len(new_subs)}\n")
            f.write(f"- New Live Hosts: {len(new_hosts)}\n")
            f.write(f"- New Open Ports: {len(new_ports)}\n")
            f.write(f"- New Vulnerabilities: {len(new_vulns)}\n\n")

            if new_subs:
                f.write("## New Subdomains\n")
                for s in new_subs:
                    f.write(f"- `{s}`\n")
                f.write("\n")

            if new_hosts:
                f.write("## New Live Hosts\n")
                for h in new_hosts:
                    f.write(f"- `{h}`\n")
                f.write("\n")

            if new_ports:
                f.write("## New Open Ports\n")
                for p in new_ports:
                    f.write(f"- `{p}`\n")
                f.write("\n")

            if new_vulns:
                f.write("## New Vulnerabilities\n")
                for v in new_vulns:
                    f.write(
                        f"- **[{v.get('severity', '').upper()}]** "
                        f"{v.get('name', '')} @ `{v.get('host', '')}`\n"
                    )
                f.write("\n")

        self.logger.info(f"  📄 Diff report saved: {report_file}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReconStorm:
    """
    Main pipeline orchestrator that coordinates all 5 stages.
    """

    def __init__(self, args):
        self.target = args.target
        self.stages = self._parse_stages(args.stages)
        self.monitor = args.monitor
        self.monitor_interval = args.interval
        self.config_file = args.config
        self.output_base = args.output or os.path.join("recon_output", self.target)

        # Create output directory structure
        self.output_dir = os.path.join(self.output_base, Utils.timestamp())
        Utils.ensure_dir(self.output_dir)

        # Setup logging
        log_file = os.path.join(self.output_dir, "recon_storm.log")
        self.logger = setup_logger(
            "ReconStorm",
            log_file=log_file,
            level=logging.DEBUG if args.verbose else logging.INFO,
        )

        # Load configuration
        self.config = self._load_config()

        # Initialize notifier
        self.notifier = Notifier(self.config, self.logger)

        # Results
        self.results = ReconResults(target=self.target)

    def _parse_stages(self, stages_str: str) -> List[int]:
        """Parse stage selection string."""
        if not stages_str or stages_str == "all":
            return [1, 2, 3, 4, 5]
        try:
            return sorted(set(int(s.strip()) for s in stages_str.split(",")))
        except ValueError:
            return [1, 2, 3, 4, 5]

    def _load_config(self) -> dict:
        """Load configuration from file or use defaults."""
        config = DEFAULT_CONFIG.copy()

        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file) as f:
                    user_config = yaml.safe_load(f)
                if user_config:
                    # Deep merge
                    for key, value in user_config.items():
                        if isinstance(value, dict) and key in config:
                            config[key].update(value)
                        else:
                            config[key] = value
                self.logger.info(f"  Configuration loaded from {self.config_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}, using defaults")
        else:
            # Also check for environment variables
            config["api_keys"]["shodan"] = os.getenv("SHODAN_API_KEY", "")
            config["api_keys"]["censys_id"] = os.getenv("CENSYS_API_ID", "")
            config["api_keys"]["censys_secret"] = os.getenv("CENSYS_API_SECRET", "")
            config["api_keys"]["github_token"] = os.getenv("GITHUB_TOKEN", "")
            config["api_keys"]["virustotal"] = os.getenv("VT_API_KEY", "")

        # Save effective config
        config_out = os.path.join(self.output_dir, "effective_config.yaml")
        # Sanitize API keys for saving
        safe_config = json.loads(json.dumps(config))
        for key in safe_config.get("api_keys", {}):
            val = safe_config["api_keys"][key]
            if val:
                safe_config["api_keys"][key] = val[:4] + "****" + val[-4:] if len(val) > 8 else "****"
        with open(config_out, "w") as f:
            yaml.dump(safe_config, f, default_flow_style=False)

        return config

       def _check_tools(self):
        """Check which tools are available on the system."""
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"  Tool Availability Check")
        self.logger.info(f"{'='*60}")

        tool_categories = {
            "Subdomain Enumeration": ["subfinder", "amass", "assetfinder", "findomain"],
            "DNS Resolution": ["dnsx"],
            "HTTP Probing": ["httpx", "httprobe"],
            "Port Scanning": ["naabu", "nmap", "masscan"],
            "Content Discovery": ["ffuf", "feroxbuster", "dirsearch"],
            "JS Analysis": ["linkfinder", "secretfinder"],
            "Secret Detection": ["trufflehog", "gitleaks"],
            "Screenshots": ["gowitness", "eyewitness"],
            "OSINT": ["theHarvester", "theharvester"],
            "Vuln Scanning": ["nuclei"],
            "Notifications": ["notify"],
            "Utilities": ["gau", "anew", "jq"],
        }

        total_found = 0
        total_tools = 0
        tool_report = {}

        for category, tools in tool_categories.items():
            found, missing = Utils.check_required_tools(tools)
            total_found += len(found)
            total_tools += len(tools)
            tool_report[category] = {"found": found, "missing": missing}

            found_str = ", ".join(found) if found else "none"
            missing_str = ", ".join(missing) if missing else "none"

            status_icon = "✅" if not missing else ("⚠️" if found else "❌")
            self.logger.info(f"  {status_icon} {category}:")
            if found:
                self.logger.info(f"      ✓ Available: {Fore.GREEN}{found_str}{Style.RESET_ALL}")
            if missing:
                self.logger.info(f"      ✗ Missing:   {Fore.RED}{missing_str}{Style.RESET_ALL}")

        self.logger.info(f"\n  ► Tools available: {total_found}/{total_tools}")

        # Save tool report
        report_file = os.path.join(self.output_dir, "tool_report.json")
        with open(report_file, "w") as f:
            json.dump(tool_report, f, indent=2)

        # Check minimum requirements
        critical_tools = ["subfinder", "httpx", "nuclei"]
        critical_found, critical_missing = Utils.check_required_tools(critical_tools)
        if critical_missing:
            self.logger.warning(
                f"\n  ⚠ Critical tools missing: {', '.join(critical_missing)}"
            )
            self.logger.warning(
                "  ⚠ Pipeline will continue but some stages may produce limited results"
            )

        return tool_report

    def _generate_final_report(self):
        """Generate comprehensive final report."""
        report_file = os.path.join(self.output_dir, "final_report.md")
        json_report = os.path.join(self.output_dir, "final_report.json")

        # JSON report
        with open(json_report, "w") as f:
            json.dump(self.results.to_dict(), f, indent=2, default=str)

        # Markdown report
        with open(report_file, "w") as f:
            f.write(f"# 🔍 ReconStorm Report\n\n")
            f.write(f"**Target:** `{self.target}`\n")
            f.write(f"**Start Time:** {self.results.start_time}\n")
            f.write(f"**End Time:** {self.results.end_time}\n")
            f.write(f"**Output Directory:** `{self.output_dir}`\n\n")

            f.write(f"---\n\n")
            f.write(f"## 📊 Executive Summary\n\n")
            f.write(f"| Metric | Count |\n")
            f.write(f"|--------|-------|\n")
            f.write(f"| Total Subdomains | {len(self.results.subdomains)} |\n")
            f.write(f"| Live Hosts | {len(self.results.live_hosts)} |\n")
            total_ports = sum(len(p) for p in self.results.open_ports.values())
            f.write(f"| Open Ports | {total_ports} |\n")
            f.write(f"| Technologies Detected | {len(self.results.technologies)} |\n")
            f.write(f"| Vulnerabilities | {len(self.results.vulnerabilities)} |\n")
            f.write(f"| Secrets Found | {len(self.results.secrets_found)} |\n")
            f.write(f"| GitHub Dork Hits | {len(self.results.github_dork_results)} |\n\n")

            # Stage status
            f.write(f"## 🔄 Stage Status\n\n")
            for stage, status in self.results.stage_status.items():
                icon = {
                    StageStatus.COMPLETED: "✅",
                    StageStatus.FAILED: "❌",
                    StageStatus.SKIPPED: "⏭️",
                    StageStatus.RUNNING: "🔄",
                    StageStatus.PENDING: "⏳",
                }.get(status, "❓")
                f.write(f"- {icon} {stage}: **{status.value}**\n")
            f.write("\n")

            # Vulnerabilities detail
            if self.results.vulnerabilities:
                f.write(f"## 🚨 Vulnerabilities\n\n")

                # Group by severity
                by_severity = {}
                for v in self.results.vulnerabilities:
                    sev = v.get("severity", "unknown")
                    if sev not in by_severity:
                        by_severity[sev] = []
                    by_severity[sev].append(v)

                severity_order = ["critical", "high", "medium", "low", "info"]
                for sev in severity_order:
                    if sev in by_severity:
                        f.write(f"### {sev.upper()} ({len(by_severity[sev])})\n\n")
                        for v in by_severity[sev]:
                            f.write(f"- **{v.get('name', 'Unknown')}**\n")
                            f.write(f"  - Host: `{v.get('host', '')}`\n")
                            f.write(f"  - Template: `{v.get('template', '')}`\n")
                            f.write(f"  - Matched: `{v.get('matched_url', '')}`\n")
                            if v.get("reference"):
                                refs = v["reference"]
                                if isinstance(refs, list):
                                    for ref in refs[:3]:
                                        f.write(f"  - Ref: {ref}\n")
                            f.write("\n")

            # Subdomains
            if self.results.subdomains:
                f.write(f"## 🌐 Subdomains ({len(self.results.subdomains)})\n\n")
                f.write("<details>\n<summary>Click to expand</summary>\n\n")
                for sub in sorted(self.results.subdomains.keys()):
                    f.write(f"- `{sub}`\n")
                f.write("\n</details>\n\n")

            # Live Hosts
            if self.results.live_hosts:
                f.write(f"## 🟢 Live Hosts ({len(self.results.live_hosts)})\n\n")
                f.write("<details>\n<summary>Click to expand</summary>\n\n")
                for host in sorted(self.results.live_hosts):
                    f.write(f"- `{host}`\n")
                f.write("\n</details>\n\n")

            # Open Ports
            if self.results.open_ports:
                f.write(f"## 🔓 Open Ports\n\n")
                f.write("| Host | Port | Service | Version |\n")
                f.write("|------|------|---------|---------|\n")
                for host, ports in sorted(self.results.open_ports.items()):
                    for p in sorted(ports, key=lambda x: x.port):
                        f.write(
                            f"| `{host}` | {p.port} | {p.service} | {p.version} |\n"
                        )
                f.write("\n")

            # Technologies
            if self.results.technologies:
                f.write(f"## 🛠️ Technologies Detected\n\n")
                for host, techs in sorted(self.results.technologies.items()):
                    f.write(f"- `{host}`: {', '.join(techs)}\n")
                f.write("\n")

            # Secrets
            if self.results.secrets_found:
                f.write(f"## 🔑 Secrets Found ({len(self.results.secrets_found)})\n\n")
                f.write("⚠️ **Handle with care - these may contain sensitive data**\n\n")
                for s in self.results.secrets_found[:20]:
                    f.write(f"- **Source:** {s.get('source', 'unknown')}\n")
                    if s.get("repo"):
                        f.write(f"  - Repo: `{s['repo']}`\n")
                    if s.get("file"):
                        f.write(f"  - File: `{s['file']}`\n")
                    if s.get("rule"):
                        f.write(f"  - Rule: `{s['rule']}`\n")
                    f.write("\n")

            # GitHub Dork Results
            if self.results.github_dork_results:
                f.write(f"## 🐙 GitHub Dork Results ({len(self.results.github_dork_results)})\n\n")
                for r in self.results.github_dork_results[:20]:
                    f.write(f"- **Repo:** `{r.get('repo', '')}`\n")
                    f.write(f"  - File: `{r.get('file', '')}`\n")
                    f.write(f"  - URL: {r.get('url', '')}\n")
                    f.write(f"  - Dork: `{r.get('dork', '')}`\n\n")

            # Google Dorks (manual review)
            if self.results.google_dork_results:
                f.write(f"## 🔎 Google Dorks (Manual Review)\n\n")
                f.write("The following dorks were generated for manual review:\n\n")
                for dork in self.results.google_dork_results:
                    encoded = dork.replace(" ", "+")
                    f.write(
                        f"- [{dork}](https://www.google.com/search?q={encoded})\n"
                    )
                f.write("\n")

            f.write(f"\n---\n")
            f.write(f"*Generated by ReconStorm v{VERSION}*\n")

        self.logger.info(f"\n  📄 Final report: {report_file}")
        self.logger.info(f"  📄 JSON report:  {json_report}")

    def run(self):
        """Execute the full reconnaissance pipeline."""
        print(BANNER)

        self.results.start_time = Utils.timestamp()
        start_time = time.time()

        self.logger.info(f"  Target:     {self.target}")
        self.logger.info(f"  Output:     {self.output_dir}")
        self.logger.info(f"  Stages:     {self.stages}")
        self.logger.info(f"  Monitor:    {self.monitor}")
        self.logger.info(f"  Started:    {self.results.start_time}")

        # Pre-flight: Check tool availability
        self._check_tools()

        # ─── Stage 1: Asset Discovery ────────────────────────────────────
        subdomains_file = os.path.join(
            self.output_dir, "stage1_asset_discovery", "all_subdomains.txt"
        )

        if 1 in self.stages:
            try:
                self.results.stage_status["Stage 1: Asset Discovery"] = StageStatus.RUNNING
                stage1 = Stage1AssetDiscovery(
                    self.target, self.output_dir, self.config, self.logger
                )
                subdomains = stage1.run()
                self.results.subdomains = {s: SubdomainInfo(subdomain=s) for s in subdomains}
                self.results.stage_status["Stage 1: Asset Discovery"] = StageStatus.COMPLETED
            except Exception as e:
                self.logger.error(f"Stage 1 failed: {e}")
                self.results.stage_status["Stage 1: Asset Discovery"] = StageStatus.FAILED
        else:
            self.results.stage_status["Stage 1: Asset Discovery"] = StageStatus.SKIPPED
            # Check if previous results exist
            if os.path.exists(subdomains_file):
                self.logger.info("  Using existing subdomain data from previous run")
                subs = Utils.read_file_lines(subdomains_file)
                self.results.subdomains = {s: SubdomainInfo(subdomain=s) for s in subs}

        if not self.results.subdomains and not os.path.exists(subdomains_file):
            # Create a minimal subdomains file with just the target
            self.logger.warning("  No subdomains found, using target domain as baseline")
            Utils.ensure_dir(os.path.dirname(subdomains_file))
            Utils.write_file_lines(subdomains_file, [self.target])

        # ─── Stage 2: Technology Fingerprinting ──────────────────────────
        live_hosts_file = os.path.join(
            self.output_dir, "stage2_tech_fingerprint", "live_hosts.txt"
        )

        if 2 in self.stages:
            try:
                self.results.stage_status["Stage 2: Tech Fingerprinting"] = StageStatus.RUNNING
                stage2 = Stage2TechFingerprinting(
                    self.target, self.output_dir, self.config, self.logger
                )
                live_hosts, technologies = stage2.run(subdomains_file)
                self.results.live_hosts = live_hosts
                self.results.technologies = technologies

                # Update subdomain info with tech data
                for url, techs in technologies.items():
                    for sub, info in self.results.subdomains.items():
                        if sub in url:
                            info.tech = techs
                            info.is_alive = True

                self.results.stage_status["Stage 2: Tech Fingerprinting"] = StageStatus.COMPLETED
            except Exception as e:
                self.logger.error(f"Stage 2 failed: {e}")
                self.results.stage_status["Stage 2: Tech Fingerprinting"] = StageStatus.FAILED
        else:
            self.results.stage_status["Stage 2: Tech Fingerprinting"] = StageStatus.SKIPPED
            if os.path.exists(live_hosts_file):
                self.results.live_hosts = Utils.read_file_lines(live_hosts_file)

        # ─── Stage 3: Port Scanning ─────────────────────────────────────
        if 3 in self.stages:
            try:
                self.results.stage_status["Stage 3: Port Scanning"] = StageStatus.RUNNING
                stage3 = Stage3PortScanning(
                    self.target, self.output_dir, self.config, self.logger
                )
                open_ports = stage3.run(subdomains_file)
                self.results.open_ports = open_ports

                # Update subdomain info with port data
                for host, ports in open_ports.items():
                    for sub, info in self.results.subdomains.items():
                        if sub in host or host in sub:
                            info.ports = ports

                self.results.stage_status["Stage 3: Port Scanning"] = StageStatus.COMPLETED
            except Exception as e:
                self.logger.error(f"Stage 3 failed: {e}")
                self.results.stage_status["Stage 3: Port Scanning"] = StageStatus.FAILED
        else:
            self.results.stage_status["Stage 3: Port Scanning"] = StageStatus.SKIPPED

        # ─── Stage 4: OSINT & Secret Detection ──────────────────────────
        if 4 in self.stages:
            try:
                self.results.stage_status["Stage 4: OSINT"] = StageStatus.RUNNING
                stage4 = Stage4OSINT(
                    self.target, self.output_dir, self.config, self.logger
                )
                osint_results = stage4.run()
                self.results.osint_data = osint_results
                self.results.github_dork_results = osint_results.get("github_dorks", [])
                self.results.google_dork_results = osint_results.get("google_dorks", [])
                self.results.secrets_found = osint_results.get("secrets", [])
                self.results.stage_status["Stage 4: OSINT"] = StageStatus.COMPLETED
            except Exception as e:
                self.logger.error(f"Stage 4 failed: {e}")
                self.results.stage_status["Stage 4: OSINT"] = StageStatus.FAILED
        else:
            self.results.stage_status["Stage 4: OSINT"] = StageStatus.SKIPPED

        # ─── Stage 5: Vuln Scan + Continuous Monitoring ──────────────────
        if 5 in self.stages:
            try:
                self.results.stage_status["Stage 5: Monitoring & Vuln Scan"] = StageStatus.RUNNING
                stage5 = Stage5ContinuousMonitoring(
                    self.target, self.output_dir, self.config, self.logger, self.notifier
                )

                # Always run Nuclei scan first
                if os.path.exists(live_hosts_file):
                    vulns = stage5.run_nuclei_scan(live_hosts_file)
                    self.results.vulnerabilities = vulns

                self.results.stage_status["Stage 5: Monitoring & Vuln Scan"] = StageStatus.COMPLETED

                # If continuous monitoring requested, enter the loop after report
                if self.monitor:
                    # Generate report before entering monitoring loop
                    self.results.end_time = Utils.timestamp()
                    elapsed = time.time() - start_time
                    self._print_summary(elapsed)
                    self._generate_final_report()

                    self.logger.info(
                        f"\n  🔄 Entering continuous monitoring mode "
                        f"(interval: {self.monitor_interval}h)..."
                    )
                    try:
                        stage5.start_monitoring(self.monitor_interval)
                    except KeyboardInterrupt:
                        stage5.stop_monitoring()
                        self.logger.info("\n  ⏹ Monitoring stopped by user")
                    return

            except Exception as e:
                self.logger.error(f"Stage 5 failed: {e}")
                self.results.stage_status["Stage 5: Monitoring & Vuln Scan"] = StageStatus.FAILED
        else:
            self.results.stage_status["Stage 5: Monitoring & Vuln Scan"] = StageStatus.SKIPPED

        # ─── Finalization ────────────────────────────────────────────────
        self.results.end_time = Utils.timestamp()
        elapsed = time.time() - start_time
        self._print_summary(elapsed)
        self._generate_final_report()

        # Send completion notification
        self.notifier.send(
            f"✅ Recon completed for {self.target}. "
            f"{len(self.results.subdomains)} subdomains, "
            f"{len(self.results.live_hosts)} live hosts, "
            f"{len(self.results.vulnerabilities)} vulnerabilities found.",
            severity="success",
        )

    def _print_summary(self, elapsed: float):
        """Print a final summary to the terminal."""
        hours, remainder = divmod(int(elapsed), 3600)
        minutes, seconds = divmod(remainder, 60)
        elapsed_str = f"{hours}h {minutes}m {seconds}s"

        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"  {Fore.CYAN}RECON STORM - FINAL SUMMARY{Style.RESET_ALL}")
        self.logger.info(f"{'='*60}")
        self.logger.info(f"  Target:           {self.target}")
        self.logger.info(f"  Duration:         {elapsed_str}")
        self.logger.info(f"  Output:           {self.output_dir}")
        self.logger.info(f"{'─'*60}")
        self.logger.info(f"  Subdomains:       {len(self.results.subdomains)}")
        self.logger.info(f"  Live Hosts:       {len(self.results.live_hosts)}")
        total_ports = sum(len(p) for p in self.results.open_ports.values())
        self.logger.info(f"  Open Ports:       {total_ports}")
        self.logger.info(f"  Technologies:     {len(self.results.technologies)}")
        self.logger.info(f"  Vulnerabilities:  {len(self.results.vulnerabilities)}")
        self.logger.info(f"  Secrets Found:    {len(self.results.secrets_found)}")
        self.logger.info(f"  GitHub Dork Hits: {len(self.results.github_dork_results)}")
        self.logger.info(f"{'─'*60}")

        # Highlight critical findings
        critical_vulns = [
            v for v in self.results.vulnerabilities
            if v.get("severity") in ("critical", "high")
        ]
        if critical_vulns:
            self.logger.info(
                f"  {Fore.RED}🚨 CRITICAL/HIGH VULNS: {len(critical_vulns)}{Style.RESET_ALL}"
            )
            for v in critical_vulns[:5]:
                self.logger.info(
                    f"    {Fore.RED}[{v.get('severity', '').upper()}] "
                    f"{v.get('name', '')} @ {v.get('host', '')}{Style.RESET_ALL}"
                )

        if self.results.secrets_found:
            self.logger.info(
                f"  {Fore.YELLOW}🔑 SECRETS: {len(self.results.secrets_found)} "
                f"potential secrets detected{Style.RESET_ALL}"
            )

        # Stage status summary
        self.logger.info(f"\n  Stage Results:")
        for stage, status in self.results.stage_status.items():
            icon = {
                StageStatus.COMPLETED: f"{Fore.GREEN}✅",
                StageStatus.FAILED: f"{Fore.RED}❌",
                StageStatus.SKIPPED: f"{Fore.YELLOW}⏭️",
            }.get(status, "❓")
            self.logger.info(f"    {icon} {stage}: {status.value}{Style.RESET_ALL}")

        self.logger.info(f"\n{'='*60}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG FILE GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

def generate_sample_config(output_path: str = "recon_storm_config.yaml"):
    """Generate a sample configuration file."""
    config = DEFAULT_CONFIG.copy()
    config["api_keys"] = {
        "shodan": "YOUR_SHODAN_API_KEY",
        "censys_id": "YOUR_CENSYS_API_ID",
        "censys_secret": "YOUR_CENSYS_API_SECRET",
        "github_token": "YOUR_GITHUB_TOKEN",
        "virustotal": "YOUR_VT_API_KEY",
    }

    header = """# ═══════════════════════════════════════════════════════════════
# ReconStorm Configuration File
# ═══════════════════════════════════════════════════════════════
# 
# Fill in your API keys and adjust settings as needed.
# Environment variables are also supported:
#   SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET,
#   GITHUB_TOKEN, VT_API_KEY
#
# Usage: python3 recon_storm.py --target example.com --config recon_storm_config.yaml
# ═══════════════════════════════════════════════════════════════

"""
    with open(output_path, "w") as f:
        f.write(header)
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"[+] Sample config generated: {output_path}")
    print(f"[*] Edit the file and fill in your API keys before running.")


# ═══════════════════════════════════════════════════════════════════════════════
# INSTALLATION HELPER
# ═══════════════════════════════════════════════════════════════════════════════

def print_install_guide():
    """Print installation instructions for all required tools."""
    guide = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║              ReconStorm - Tool Installation Guide               ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}═══ Python Dependencies ═══{Style.RESET_ALL}
pip install shodan censys python-dotenv requests colorama pyyaml schedule

{Fore.YELLOW}═══ Go-based Tools (requires Go 1.21+) ═══{Style.RESET_ALL}
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/sensepost/gowitness@latest

{Fore.YELLOW}═══ Rust-based Tools ═══{Style.RESET_ALL}
# Findomain
curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip && chmod +x findomain && sudo mv findomain /usr/local/bin/

# Feroxbuster
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

{Fore.YELLOW}═══ Package Manager Tools ═══{Style.RESET_ALL}
# Nmap & Masscan
sudo apt install -y nmap masscan

# OWASP Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# theHarvester
pip install theHarvester

# dirsearch
pip install dirsearch

{Fore.YELLOW}═══ Secret Detection ═══{Style.RESET_ALL}
# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Gitleaks
go install github.com/gitleaks/gitleaks/v8@latest

{Fore.YELLOW}═══ JS Analysis ═══{Style.RESET_ALL}
pip install linkfinder
pip install SecretFinder

{Fore.YELLOW}═══ Screenshots ═══{Style.RESET_ALL}
# EyeWitness
git clone https://github.com/RedSiege/EyeWitness.git
cd EyeWitness/Python/setup && sudo ./setup.sh

{Fore.YELLOW}═══ Post-Install ═══{Style.RESET_ALL}
# Update Nuclei templates
nuclei -update-templates

# Verify installation
python3 recon_storm.py --check-tools

{Fore.GREEN}═══ Quick Start ═══{Style.RESET_ALL}
# 1. Generate config file
python3 recon_storm.py --generate-config

# 2. Edit config with your API keys
nano recon_storm_config.yaml

# 3. Run full scan
python3 recon_storm.py --target example.com --config recon_storm_config.yaml

# 4. Run with monitoring
python3 recon_storm.py --target example.com --monitor --interval 6
"""
    print(guide)


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL HANDLING
# ═══════════════════════════════════════════════════════════════════════════════

_orchestrator_instance = None


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    print(f"\n{Fore.YELLOW}[!] Interrupt received. Cleaning up...{Style.RESET_ALL}")
    if _orchestrator_instance:
        try:
            _orchestrator_instance.results.end_time = Utils.timestamp()
            _orchestrator_instance._generate_final_report()
            print(f"{Fore.GREEN}[+] Partial results saved.{Style.RESET_ALL}")
        except Exception:
            pass
    sys.exit(0)


# ═══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING & MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"ReconStorm v{VERSION} - Automated Bug Bounty Recon Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target example.com
  %(prog)s --target example.com --stages 1,2,3
  %(prog)s --target example.com --monitor --interval 6
  %(prog)s --target example.com --config config.yaml --verbose
  %(prog)s --target-list targets.txt
  %(prog)s --generate-config
  %(prog)s --install-guide
  %(prog)s --check-tools
        """,
    )

    # Target options
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument(
        "-t", "--target",
        help="Target domain to scan (e.g., example.com)",
    )
    target_group.add_argument(
        "-tl", "--target-list",
        help="File containing list of target domains (one per line)",
    )

    # Stage selection
    parser.add_argument(
        "-s", "--stages",
        default="all",
        help="Comma-separated stages to run (e.g., '1,2,3' or 'all'). Default: all",
    )

    # Monitoring
    parser.add_argument(
        "-m", "--monitor",
        action="store_true",
        help="Enable continuous monitoring after initial scan",
    )
    parser.add_argument(
        "-i", "--interval",
        type=int,
        default=6,
        help="Monitoring interval in hours (default: 6)",
    )

    # Configuration
    parser.add_argument(
        "-c", "--config",
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output directory (default: recon_output/<target>)",
    )

    # Utility options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--generate-config",
        action="store_true",
        help="Generate a sample configuration file and exit",
    )
    parser.add_argument(
        "--install-guide",
        action="store_true",
        help="Print tool installation guide and exit",
    )
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Check which tools are installed and exit",
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    global _orchestrator_instance

    args = parse_arguments()

    # Handle utility commands
    if args.generate_config:
        generate_sample_config()
        return

    if args.install_guide:
        print_install_guide()
        return

    if args.check_tools:
        print(BANNER)
        logger = setup_logger("ToolCheck")
        tool_categories = {
            "Subdomain Enumeration": ["subfinder", "amass", "assetfinder", "findomain"],
            "DNS Resolution": ["dnsx"],
            "HTTP Probing": ["httpx", "httprobe"],
            "Port Scanning": ["naabu", "nmap", "masscan"],
            "Content Discovery": ["ffuf", "feroxbuster", "dirsearch"],
            "JS Analysis": ["linkfinder", "secretfinder"],
            "Secret Detection": ["trufflehog", "gitleaks"],
            "Screenshots": ["gowitness", "eyewitness"],
            "OSINT": ["theHarvester", "theharvester"],
            "Vuln Scanning": ["nuclei"],
            "Notifications": ["notify"],
            "Utilities": ["gau", "anew", "jq", "dnsx"],
        }
        total_found = 0
        total_all = 0
        for cat, tools in tool_categories.items():
            found, missing = Utils.check_required_tools(tools)
            total_found += len(found)
            total_all += len(tools)
            icon = "✅" if not missing else ("⚠️" if found else "❌")
            logger.info(f"  {icon} {cat}:")
            for t in found:
                logger.info(f"      {Fore.GREEN}✓ {t}{Style.RESET_ALL}")
            for t in missing:
                logger.info(f"      {Fore.RED}✗ {t}{Style.RESET_ALL}")
        logger.info(f"\n  Total: {total_found}/{total_all} tools available")
        return

    # Validate target
    if not args.target and not args.target_list:
        print(BANNER)
        print(f"{Fore.RED}[!] Error: --target or --target-list is required{Style.RESET_ALL}")
        print(f"[*] Run with --help for usage information")
        sys.exit(1)

    # Handle target list (run pipeline for each target)
    if args.target_list:
        if not os.path.exists(args.target_list):
            print(f"{Fore.RED}[!] Target list not found: {args.target_list}{Style.RESET_ALL}")
            sys.exit(1)

        targets = Utils.read_file_lines(args.target_list)
        if not targets:
            print(f"{Fore.RED}[!] Target list is empty{Style.RESET_ALL}")
            sys.exit(1)

        print(BANNER)
        print(f"{Fore.CYAN}[*] Running pipeline for {len(targets)} targets{Style.RESET_ALL}\n")

        for i, target in enumerate(targets, 1):
            print(f"\n{'#'*60}")
            print(f"  Target {i}/{len(targets)}: {target}")
            print(f"{'#'*60}\n")

            args.target = target
            signal.signal(signal.SIGINT, signal_handler)

            orchestrator = ReconStorm(args)
            _orchestrator_instance = orchestrator
            orchestrator.run()

        return

    # Single target execution
    signal.signal(signal.SIGINT, signal_handler)

    orchestrator = ReconStorm(args)
    _orchestrator_instance = orchestrator
    orchestrator.run()


if __name__ == "__main__":
    main()
