#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                    R E C O N   S T O R M                       ║
║          Bug Bounty Enumeration & HTML Reporting Tool           ║
║                        v1.0.0                                   ║
╚══════════════════════════════════════════════════════════════════╝

Methodology:
  Phase 1 — Subdomain Enumeration (passive + active)
  Phase 2 — DNS Resolution & Record Collection
  Phase 3 — HTTP Probing & Technology Fingerprinting
  Phase 4 — Port Scanning (top ports)
  Phase 5 — Directory & Endpoint Discovery
  Phase 6 — JS File Extraction & Link Mining
  Phase 7 — Parameter Discovery
  Phase 8 — Wayback Machine URL Harvesting
  Phase 9 — WHOIS & ASN Lookup
  Phase 10 — HTML Report Generation with Metrics

Dependencies (install before running):
  pip install requests dnspython python-whois beautifulsoup4 aiohttp tldextract

Usage:
  python3 recon_storm.py -d target.com
  python3 recon_storm.py -d target.com --threads 50 --timeout 10 --ports top100
  python3 recon_storm.py -d target.com -o /path/to/output
"""

import argparse
import concurrent.futures
import datetime
import dns.resolver
import hashlib
import json
import logging
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
import tldextract
from bs4 import BeautifulSoup

try:
    import whois as python_whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

# ─────────────────────────────────────────────────────────
# CONFIGURATION & CONSTANTS
# ─────────────────────────────────────────────────────────

VERSION = "1.0.0"
BANNER = r"""
  ╦═╗╔═╗╔═╗╔═╗╔╗╔  ╔═╗╔╦╗╔═╗╦═╗╔╦╗
  ╠╦╝║╣ ║  ║ ║║║║  ╚═╗ ║ ║ ║╠╦╝║║║
  ╩╚═╚═╝╚═╝╚═╝╝╚╝  ╚═╝ ╩ ╚═╝╩╚═╩ ╩
  Bug Bounty Enumeration Framework v{}
""".format(VERSION)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

COMMON_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
    "blog", "dev", "staging", "stage", "test", "testing", "api", "app",
    "admin", "administrator", "panel", "cpanel", "whm", "webdisk", "portal",
    "vpn", "remote", "gateway", "gw", "proxy", "cdn", "static", "assets",
    "media", "img", "images", "video", "download", "downloads", "upload",
    "docs", "doc", "help", "support", "kb", "wiki", "forum", "community",
    "shop", "store", "pay", "payment", "checkout", "billing", "invoice",
    "auth", "sso", "login", "oauth", "id", "account", "accounts",
    "m", "mobile", "beta", "alpha", "demo", "sandbox", "uat",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "jenkins", "ci", "cd", "build", "deploy", "git", "gitlab", "github",
    "grafana", "prometheus", "kibana", "monitor", "monitoring", "status",
    "nagios", "zabbix", "splunk", "elk", "log", "logs", "syslog",
    "backup", "bak", "old", "new", "v1", "v2", "v3", "internal",
    "intranet", "extranet", "partner", "partners", "vendor", "vendors",
    "s3", "aws", "azure", "cloud", "k8s", "kube", "kubernetes", "docker",
    "mx", "mx1", "mx2", "relay", "edge", "firewall", "fw", "waf",
    "vpn1", "vpn2", "owa", "exchange", "autodiscover", "lyncdiscover",
    "sip", "meet", "conference", "chat", "slack", "teams",
    "jira", "confluence", "bitbucket", "bamboo", "crowd",
    "crm", "erp", "hr", "finance", "legal", "sales", "marketing",
    "analytics", "tracking", "pixel", "ads", "ad", "promo",
    "ws", "websocket", "socket", "realtime", "push", "notify",
    "graphql", "rest", "soap", "rpc", "grpc", "webhook", "webhooks",
    "feeds", "rss", "atom", "sitemap", "robots",
    "preview", "draft", "review", "qa", "preprod", "pre-prod",
    "data", "bigdata", "hadoop", "spark", "airflow", "etl",
    "cache", "memcached", "varnish", "nginx", "apache", "iis",
    "ldap", "ad", "active-directory", "radius", "kerberos",
    "mail2", "smtp2", "imap2", "pop3", "postfix", "dovecot",
    "secure", "ssl", "tls", "cert", "certs", "pki",
    "maps", "geo", "location", "search", "api2", "api3",
    "staging2", "dev2", "test2", "uat2", "perf", "performance", "load",
]

COMMON_DIRS = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/.htaccess",
    "/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/",
    "/administrator/", "/admin/", "/login", "/signin", "/signup",
    "/api/", "/api/v1/", "/api/v2/", "/graphql", "/graphiql",
    "/swagger.json", "/swagger-ui.html", "/api-docs", "/openapi.json",
    "/server-status", "/server-info", "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/phpinfo.php", "/info.php", "/test.php",
    "/config.yml", "/config.json", "/config.xml", "/config.php",
    "/backup/", "/backups/", "/dump/", "/db/", "/database/",
    "/debug/", "/trace/", "/console/", "/actuator/", "/actuator/health",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    "/elmah.axd", "/web.config", "/.DS_Store",
    "/.git/config", "/.svn/entries", "/.hg/",
    "/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
    "/wp-json/wp/v2/users", "/xmlrpc.php",
    "/cgi-bin/", "/cgi-bin/test-cgi",
    "/.well-known/openid-configuration",
    "/favicon.ico", "/health", "/healthcheck", "/ping", "/version",
    "/metrics", "/stats", "/status",
]

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Joomla": ["Joomla!", "com_content", "/media/jui/"],
    "Drupal": ["Drupal", "drupal.js", "sites/default"],
    "Laravel": ["laravel", "csrf-token", "laravel_session"],
    "Django": ["csrfmiddlewaretoken", "django", "__debug__"],
    "Flask": ["flask", "werkzeug"],
    "Express.js": ["X-Powered-By: Express"],
    "React": ["react", "_reactRoot", "__NEXT_DATA__"],
    "Angular": ["ng-version", "ng-app", "angular"],
    "Vue.js": ["vue", "__vue__", "v-cloak"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "Nuxt.js": ["__NUXT__", "_nuxt/"],
    "ASP.NET": ["__VIEWSTATE", "__EVENTVALIDATION", "asp.net"],
    "Spring": ["spring", "actuator"],
    "Ruby on Rails": ["rails", "csrf-token", "turbolinks"],
    "Nginx": ["nginx"],
    "Apache": ["Apache", "mod_"],
    "IIS": ["Microsoft-IIS", "ASP.NET"],
    "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
    "AWS": ["AmazonS3", "amz-", "x-amz-"],
    "Akamai": ["akamai", "akamaized"],
    "Fastly": ["fastly", "x-served-by"],
    "Varnish": ["varnish", "x-varnish"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
    "Tailwind": ["tailwind"],
    "GraphQL": ["graphql", "GraphQL"],
    "Elasticsearch": ["elasticsearch"],
    "Kubernetes": ["kubernetes", "k8s"],
    "Docker": ["docker"],
    "Swagger": ["swagger"],
    "Firebase": ["firebase", "firebaseapp"],
    "Shopify": ["shopify", "myshopify"],
    "Magento": ["magento", "mage"],
}

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993,
    995, 1723, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443,
    8888, 9090, 9200, 9300, 27017, 27018, 11211, 6380, 2049, 1433,
]

INTERESTING_PARAMS = [
    "id", "page", "url", "redirect", "next", "redir", "return",
    "file", "path", "dir", "folder", "download", "include",
    "template", "view", "content", "doc", "document", "load",
    "q", "query", "search", "s", "keyword", "term",
    "user", "username", "email", "name", "account", "login",
    "password", "pass", "token", "key", "api_key", "secret",
    "callback", "cb", "jsonp", "format", "type",
    "cmd", "exec", "command", "run", "ping", "eval",
    "lang", "language", "locale", "debug", "test", "admin",
]


# ─────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────

@dataclass
class SubdomainResult:
    subdomain: str
    source: str
    ip_addresses: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    is_alive: bool = False
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    content_length: Optional[int] = None
    redirect_url: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PortResult:
    host: str
    port: int
    state: str
    service: str = "unknown"
    banner: str = ""

@dataclass
class DirectoryResult:
    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    redirect: str = ""
    interesting: bool = False

@dataclass
class JSFileResult:
    url: str
    size: int
    endpoints: List[str] = field(default_factory=list)
    secrets: List[str] = field(default_factory=list)
    interesting_strings: List[str] = field(default_factory=list)

@dataclass
class WaybackURL:
    url: str
    timestamp: str
    mime_type: str = ""
    status_code: str = ""

@dataclass
class WHOISResult:
    domain: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    name_servers: List[str] = field(default_factory=list)
    org: str = ""
    emails: List[str] = field(default_factory=list)
    raw: str = ""

@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: int = 0

@dataclass
class EnumerationResults:
    target: str
    start_time: datetime.datetime = None
    end_time: datetime.datetime = None
    subdomains: List[SubdomainResult] = field(default_factory=list)
    dns_records: List[DNSRecord] = field(default_factory=list)
    open_ports: List[PortResult] = field(default_factory=list)
    directories: List[DirectoryResult] = field(default_factory=list)
    js_files: List[JSFileResult] = field(default_factory=list)
    wayback_urls: List[WaybackURL] = field(default_factory=list)
    parameters: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    whois_info: Optional[WHOISResult] = None
    errors: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────────────────

class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG:    "\033[36m",   # Cyan
        logging.INFO:     "\033[32m",   # Green
        logging.WARNING:  "\033[33m",   # Yellow
        logging.ERROR:    "\033[31m",   # Red
        logging.CRITICAL: "\033[41m",   # Red BG
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        record.msg = f"{color}{record.msg}{self.RESET}"
        return super().format(record)


def setup_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("ReconStorm")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter("[%(asctime)s] %(levelname)s :: %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    return logger


# ─────────────────────────────────────────────────────────
# UTILITY HELPERS
# ─────────────────────────────────────────────────────────

def get_session() -> requests.Session:
    """Create a requests session with retries and default headers."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENTS[0],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    adapter = requests.adapters.HTTPAdapter(max_retries=2, pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def safe_request(session: requests.Session, url: str, timeout: int = 10, method: str = "GET",
                 allow_redirects: bool = True) -> Optional[requests.Response]:
    """Make a safe HTTP request, returning None on failure."""
    try:
        resp = session.request(method, url, timeout=timeout, allow_redirects=allow_redirects, verify=False)
        return resp
    except Exception:
        return None


def extract_base_domain(domain: str) -> str:
    """Extract the registered/base domain from a hostname."""
    ext = tldextract.extract(domain)
    return f"{ext.domain}.{ext.suffix}"


# ─────────────────────────────────────────────────────────
# PHASE 1: SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────

class SubdomainEnumerator:
    """Passive + Active subdomain discovery."""

    def __init__(self, domain: str, session: requests.Session, logger: logging.Logger,
                 threads: int = 30, timeout: int = 10):
        self.domain = domain
        self.session = session
        self.logger = logger
        self.threads = threads
        self.timeout = timeout
        self.found: Dict[str, str] = {}  # subdomain -> source
        self.lock = threading.Lock()

    def enumerate(self) -> Dict[str, str]:
        """Run all passive sources, then brute-force common subdomains."""
        self.logger.info(f"[Phase 1] Subdomain Enumeration for {self.domain}")

        # Passive sources (run concurrently)
        passive_methods = [
            ("crt.sh", self._crtsh),
            ("HackerTarget", self._hackertarget),
            ("AlienVault OTX", self._alienvault),
            ("URLScan.io", self._urlscan),
            ("ThreatCrowd", self._threatcrowd),
            ("Anubis", self._anubisdb),
            ("RapidDNS", self._rapiddns),
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(passive_methods)) as executor:
            futures = {}
            for name, func in passive_methods:
                futures[executor.submit(func)] = name
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    results = future.result()
                    if results:
                        with self.lock:
                            for sub in results:
                                cleaned = sub.strip().lower().rstrip(".")
                                if cleaned.endswith(f".{self.domain}") or cleaned == self.domain:
                                    if cleaned not in self.found:
                                        self.found[cleaned] = name
                        self.logger.info(f"  ✓ {name}: {len(results)} subdomains")
                    else:
                        self.logger.debug(f"  ✗ {name}: no results")
                except Exception as e:
                    self.logger.warning(f"  ✗ {name} failed: {e}")

        # Active brute-force
        self.logger.info(f"  → Brute-forcing {len(COMMON_SUBDOMAIN_WORDLIST)} common subdomains...")
        self._bruteforce()

        self.logger.info(f"  ★ Total unique subdomains found: {len(self.found)}")
        return self.found

    def _crtsh(self) -> List[str]:
        """Query crt.sh certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        resp = safe_request(self.session, url, timeout=30)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                subs = set()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for line in name_value.split("\n"):
                        line = line.strip().lower()
                        if "*" not in line and line:
                            subs.add(line)
                return list(subs)
            except (json.JSONDecodeError, KeyError):
                pass
        return []

    def _hackertarget(self) -> List[str]:
        """Query HackerTarget API."""
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        resp = safe_request(self.session, url, timeout=15)
        if resp and resp.status_code == 200 and "error" not in resp.text.lower():
            subs = []
            for line in resp.text.strip().split("\n"):
                if "," in line:
                    subs.append(line.split(",")[0].strip())
            return subs
        return []

    def _alienvault(self) -> List[str]:
        """Query AlienVault OTX."""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        resp = safe_request(self.session, url, timeout=15)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                subs = set()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").strip().lower()
                    if hostname:
                        subs.add(hostname)
                return list(subs)
            except (json.JSONDecodeError, KeyError):
                pass
        return []

    def _urlscan(self) -> List[str]:
        """Query URLScan.io."""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"
        resp = safe_request(self.session, url, timeout=15)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                subs = set()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    domain = page.get("domain", "").strip().lower()
                    if domain:
                        subs.add(domain)
                return list(subs)
            except (json.JSONDecodeError, KeyError):
                pass
        return []

    def _threatcrowd(self) -> List[str]:
        """Query ThreatCrowd (community, may be deprecated but still useful)."""
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        resp = safe_request(self.session, url, timeout=15)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                return data.get("subdomains", [])
            except (json.JSONDecodeError, KeyError):
                pass
        return []

    def _anubisdb(self) -> List[str]:
        """Query AnubisDB."""
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        resp = safe_request(self.session, url, timeout=15)
        if resp and resp.status_code == 200:
            try:
                return resp.json()
            except (json.JSONDecodeError):
                pass
        return []

    def _rapiddns(self) -> List[str]:
        """Scrape RapidDNS."""
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        resp = safe_request(self.session, url, timeout=15)
        if resp and resp.status_code == 200:
            subs = set()
            pattern = re.compile(r'<td>([a-zA-Z0-9._-]+\.' + re.escape(self.domain) + r')</td>')
            for match in pattern.finditer(resp.text):
                subs.add(match.group(1).lower())
            return list(subs)
        return []

    def _bruteforce(self):
        """DNS brute-force common subdomains."""
        def check_sub(word):
            fqdn = f"{word}.{self.domain}"
            try:
                answers = dns.resolver.resolve(fqdn, "A", lifetime=5)
                if answers:
                    with self.lock:
                        if fqdn not in self.found:
                            self.found[fqdn] = "Brute-force"
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_sub, COMMON_SUBDOMAIN_WORDLIST)


# ─────────────────────────────────────────────────────────
# PHASE 2: DNS RESOLUTION
# ─────────────────────────────────────────────────────────

class DNSResolver:
    """Resolve DNS records for subdomains and collect record types."""

    RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "SRV", "CAA"]

    def __init__(self, domain: str, logger: logging.Logger, timeout: int = 5):
        self.domain = domain
        self.logger = logger
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout

    def resolve_domain_records(self) -> List[DNSRecord]:
        """Collect all DNS record types for the base domain."""
        self.logger.info(f"[Phase 2] DNS Record Collection for {self.domain}")
        records = []
        for rtype in self.RECORD_TYPES:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                for rdata in answers:
                    records.append(DNSRecord(
                        record_type=rtype,
                        name=self.domain,
                        value=str(rdata),
                        ttl=answers.rrset.ttl
                    ))
                    self.logger.debug(f"  {rtype}: {rdata}")
            except Exception:
                pass
        self.logger.info(f"  ★ Collected {len(records)} DNS records")
        return records

    def resolve_subdomain(self, subdomain: str) -> Tuple[List[str], Optional[str]]:
        """Resolve a subdomain to IPs and CNAME."""
        ips = []
        cname = None
        try:
            answers = self.resolver.resolve(subdomain, "CNAME")
            for rdata in answers:
                cname = str(rdata.target).rstrip(".")
        except Exception:
            pass
        try:
            answers = self.resolver.resolve(subdomain, "A")
            for rdata in answers:
                ips.append(str(rdata))
        except Exception:
            pass
        return ips, cname


# ─────────────────────────────────────────────────────────
# PHASE 3: HTTP PROBING & TECH FINGERPRINTING
# ─────────────────────────────────────────────────────────

class HTTPProber:
    """Probe subdomains over HTTP/HTTPS and fingerprint technologies."""

    def __init__(self, session: requests.Session, logger: logging.Logger,
                 threads: int = 20, timeout: int = 10):
        self.session = session
        self.logger = logger
        self.threads = threads
        self.timeout = timeout

    def probe_subdomains(self, subdomains: List[SubdomainResult]) -> List[SubdomainResult]:
        """Probe each subdomain for HTTP response, title, server, and tech stack."""
        self.logger.info(f"[Phase 3] HTTP Probing & Tech Fingerprinting ({len(subdomains)} targets)")

        def probe_one(sub: SubdomainResult) -> SubdomainResult:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{sub.subdomain}"
                resp = safe_request(self.session, url, timeout=self.timeout, allow_redirects=True)
                if resp is not None:
                    sub.is_alive = True
                    sub.status_code = resp.status_code
                    sub.content_length = len(resp.content)
                    sub.server = resp.headers.get("Server", "")

                    if resp.history:
                        sub.redirect_url = resp.url

                    # Extract title
                    try:
                        soup = BeautifulSoup(resp.text[:50000], "html.parser")
                        title_tag = soup.find("title")
                        if title_tag:
                            sub.title = title_tag.string.strip()[:120] if title_tag.string else ""
                    except Exception:
                        pass

                    # Fingerprint technologies
                    sub.technologies = self._fingerprint(resp)

                    # SSL info
                    if scheme == "https":
                        sub.ssl_info = self._get_ssl_info(sub.subdomain)

                    break  # Stop after first successful scheme
            return sub

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = list(executor.map(probe_one, subdomains))

        alive_count = sum(1 for s in results if s.is_alive)
        self.logger.info(f"  ★ {alive_count}/{len(results)} subdomains are alive")
        return results

    def _fingerprint(self, response: requests.Response) -> List[str]:
        """Identify technologies from response headers and body."""
        techs = set()
        combined = ""
        # Combine headers
        for k, v in response.headers.items():
            combined += f"{k}: {v}\n"
        # Body (first 100KB)
        combined += response.text[:100000]

        combined_lower = combined.lower()
        for tech_name, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined_lower:
                    techs.add(tech_name)
                    break

        # X-Powered-By header
        powered_by = response.headers.get("X-Powered-By", "")
        if powered_by:
            techs.add(f"X-Powered-By: {powered_by}")

        return sorted(techs)

    def _get_ssl_info(self, hostname: str) -> Dict[str, Any]:
        """Extract SSL certificate information."""
        info = {}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["notBefore"] = cert.get("notBefore", "")
                info["notAfter"] = cert.get("notAfter", "")
                info["serialNumber"] = cert.get("serialNumber", "")
                san = cert.get("subjectAltName", [])
                info["subjectAltNames"] = [x[1] for x in san]
        except Exception:
            pass
        return info


# ─────────────────────────────────────────────────────────
# PHASE 4: PORT SCANNING
# ─────────────────────────────────────────────────────────

class PortScanner:
    """TCP connect scan on discovered hosts."""

    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1723: "PPTP",
        2049: "NFS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 5985: "WinRM", 6379: "Redis", 6380: "Redis-TLS",
        8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        8888: "HTTP-Alt", 9090: "HTTP-Alt", 9200: "Elasticsearch",
        9300: "ES-Transport", 11211: "Memcached", 27017: "MongoDB",
        27018: "MongoDB",
    }

    def __init__(self, logger: logging.Logger, threads: int = 50, timeout: int = 3):
        self.logger = logger
        self.threads = threads
        self.timeout = timeout

    def scan(self, hosts: List[str], ports: List[int] = None) -> List[PortResult]:
        """Scan given hosts on specified ports."""
        if ports is None:
            ports = TOP_PORTS

        # Deduplicate hosts (use unique IPs)
        unique_hosts = list(set(hosts))
        total_checks = len(unique_hosts) * len(ports)
        self.logger.info(f"[Phase 4] Port Scanning — {len(unique_hosts)} hosts × {len(ports)} ports = {total_checks} checks")

        results = []
        lock = threading.Lock()

        def scan_port(host: str, port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = self.SERVICE_MAP.get(port, "unknown")
                    banner = self._grab_banner(sock, host, port)
                    with lock:
                        results.append(PortResult(host=host, port=port, state="open",
                                                  service=service, banner=banner))
                sock.close()
            except Exception:
                pass

        tasks = [(h, p) for h in unique_hosts for p in ports]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scan_port, h, p) for h, p in tasks]
            concurrent.futures.wait(futures)

        results.sort(key=lambda x: (x.host, x.port))
        self.logger.info(f"  ★ Found {len(results)} open ports")
        return results

    def _grab_banner(self, sock: socket.socket, host: str, port: int) -> str:
        """Attempt to grab a service banner."""
        try:
            sock.settimeout(2)
            if port in (80, 8080, 8000, 8888, 9090):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            else:
                sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200]
        except Exception:
            return ""


# ─────────────────────────────────────────────────────────
# PHASE 5: DIRECTORY & ENDPOINT DISCOVERY
# ─────────────────────────────────────────────────────────

class DirectoryBruter:
    """Check for common interesting files and directories."""

    def __init__(self, session: requests.Session, logger: logging.Logger,
                 threads: int = 15, timeout: int = 10):
        self.session = session
        self.logger = logger
        self.threads = threads
        self.timeout = timeout

    def scan(self, base_urls: List[str]) -> List[DirectoryResult]:
        """Scan each base URL for common directories/files."""
        self.logger.info(f"[Phase 5] Directory & Endpoint Discovery ({len(base_urls)} base URLs)")
        results = []
        lock = threading.Lock()

        # Interesting status codes
        interesting_codes = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

        def check_path(base_url: str, path: str):
            url = base_url.rstrip("/") + path
            resp = safe_request(self.session, url, timeout=self.timeout, allow_redirects=False)
            if resp is not None and resp.status_code in interesting_codes:
                is_interesting = resp.status_code in (200, 201, 204, 401, 403, 500)
                result = DirectoryResult(
                    url=url,
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    content_type=resp.headers.get("Content-Type", ""),
                    redirect=resp.headers.get("Location", ""),
                    interesting=is_interesting,
                )
                with lock:
                    results.append(result)

        tasks = []
        for base_url in base_urls[:10]:  # Limit to top 10 alive hosts to avoid abuse
            for path in COMMON_DIRS:
                tasks.append((base_url, path))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_path, base, path) for base, path in tasks]
            concurrent.futures.wait(futures)

        results.sort(key=lambda x: (x.url, x.status_code))
        interesting_count = sum(1 for r in results if r.interesting)
        self.logger.info(f"  ★ Found {len(results)} endpoints ({interesting_count} interesting)")
        return results


# ─────────────────────────────────────────────────────────
# PHASE 6: JS FILE EXTRACTION & LINK MINING
# ─────────────────────────────────────────────────────────

class JSAnalyzer:
    """Find JavaScript files, extract endpoints and potential secrets."""

    SECRET_PATTERNS = [
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API Key"),
        (r'(?:secret|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Secret/Token"),
        (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Password"),
        (r'(AIza[0-9A-Za-z_\-]{35})', "Google API Key"),
        (r'(AKIA[0-9A-Z]{16})', "AWS Access Key"),
        (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}', "GitHub Token"),
        (r'sk-[a-zA-Z0-9]{20,}', "Stripe/OpenAI Secret Key"),
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT Token"),
        (r'(?:slack|xox[bpas])-[a-zA-Z0-9\-]{10,}', "Slack Token"),
        (r'(?:firebase|firebaseio)\.com', "Firebase URL"),
        (r's3\.amazonaws\.com[/\w.-]+', "AWS S3 Bucket"),
        (r'[a-zA-Z0-9_-]+\.s3\.amazonaws\.com', "AWS S3 Bucket"),
    ]

    ENDPOINT_PATTERN = re.compile(
        r"""(?:"|'|`)((?:/[a-zA-Z0-9_\-./]+(?:\?[a-zA-Z0-9_\-=&]*)?)|"""
        r"""(?:https?://[a-zA-Z0-9._\-/]+))(?:"|'|`)""",
        re.IGNORECASE
    )

    def __init__(self, session: requests.Session, logger: logging.Logger, timeout: int = 10):
        self.session = session
        self.logger = logger
        self.timeout = timeout

    def analyze(self, alive_urls: List[str]) -> List[JSFileResult]:
        """Crawl alive URLs for JS files and analyze them."""
        self.logger.info(f"[Phase 6] JS File Extraction & Link Mining")
        js_urls = set()

        # Discover JS files from each alive page
        for url in alive_urls[:15]:
            resp = safe_request(self.session, url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text[:200000], "html.parser")
                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    if src.startswith("//"):
                        src = "https:" + src
                    elif src.startswith("/"):
                        src = url.rstrip("/") + src
                    elif not src.startswith("http"):
                        src = url.rstrip("/") + "/" + src
                    if src.endswith(".js") or ".js?" in src:
                        js_urls.add(src)

        self.logger.info(f"  → Found {len(js_urls)} JS files, analyzing...")
        results = []
        for js_url in list(js_urls)[:100]:  # Cap at 100
            result = self._analyze_js(js_url)
            if result:
                results.append(result)

        total_endpoints = sum(len(r.endpoints) for r in results)
        total_secrets = sum(len(r.secrets) for r in results)
        self.logger.info(f"  ★ Extracted {total_endpoints} endpoints, {total_secrets} potential secrets from {len(results)} JS files")
        return results

    def _analyze_js(self, url: str) -> Optional[JSFileResult]:
        """Download and analyze a single JS file."""
        resp = safe_request(self.session, url, timeout=self.timeout)
        if not resp or resp.status_code != 200:
            return None

        content = resp.text
        result = JSFileResult(url=url, size=len(resp.content))

        # Extract endpoints
        endpoints = set()
        for match in self.ENDPOINT_PATTERN.finditer(content):
            ep = match.group(1)
            if len(ep) > 3 and not ep.endswith((".png", ".jpg", ".gif", ".svg", ".css", ".woff", ".ttf")):
                endpoints.add(ep)
        result.endpoints = sorted(endpoints)[:50]

        # Search for secrets
        secrets = []
        for pattern, label in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                secrets.append(f"[{label}] {match.group(0)[:80]}")
        result.secrets = secrets[:20]

        return result


# ─────────────────────────────────────────────────────────
# PHASE 7: PARAMETER DISCOVERY
# ─────────────────────────────────────────────────────────

class ParameterDiscovery:
    """Discover parameters from crawled pages and JS files."""

    PARAM_PATTERN = re.compile(r'[?&]([a-zA-Z0-9_\-]+)=', re.IGNORECASE)
    INPUT_PATTERN = re.compile(r'<input[^>]+name\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    FORM_ACTION_PATTERN = re.compile(r'<form[^>]+action\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

    def __init__(self, session: requests.Session, logger: logging.Logger, timeout: int = 10):
        self.session = session
        self.logger = logger
        self.timeout = timeout

    def discover(self, alive_urls: List[str], wayback_urls: List[WaybackURL] = None) -> Dict[str, Set[str]]:
        """Discover parameters from live pages and Wayback URLs."""
        self.logger.info(f"[Phase 7] Parameter Discovery")
        params: Dict[str, Set[str]] = defaultdict(set)

        # From live pages
        for url in alive_urls[:20]:
            resp = safe_request(self.session, url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                # URL parameters
                for match in self.PARAM_PATTERN.finditer(resp.url):
                    params[url].add(match.group(1))
                # Input field names
                for match in self.INPUT_PATTERN.finditer(resp.text):
                    params[url].add(match.group(1))

        # From Wayback URLs
        if wayback_urls:
            for wu in wayback_urls:
                for match in self.PARAM_PATTERN.finditer(wu.url):
                    base = wu.url.split("?")[0]
                    params[base].add(match.group(1))

        total_params = sum(len(v) for v in params.values())
        self.logger.info(f"  ★ Discovered {total_params} unique parameters across {len(params)} endpoints")
        return params


# ─────────────────────────────────────────────────────────
# PHASE 8: WAYBACK MACHINE
# ─────────────────────────────────────────────────────────

class WaybackHarvester:
    """Harvest historical URLs from the Wayback Machine."""

    def __init__(self, domain: str, session: requests.Session, logger: logging.Logger, timeout: int = 30):
        self.domain = domain
        self.session = session
        self.logger = logger
        self.timeout = timeout

    def harvest(self) -> List[WaybackURL]:
        """Fetch URLs from the Wayback Machine CDX API."""
        self.logger.info(f"[Phase 8] Wayback Machine URL Harvesting")
        urls = []

        try:
            api_url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url=*.{self.domain}/*&output=json&fl=original,timestamp,mimetype,statuscode"
                f"&collapse=urlkey&limit=5000"
            )
            resp = safe_request(self.session, api_url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    for row in data[1:]:  # Skip header row
                        if len(row) >= 4:
                            urls.append(WaybackURL(
                                url=row[0],
                                timestamp=row[1],
                                mime_type=row[2],
                                status_code=row[3],
                            ))
                except (json.JSONDecodeError, IndexError):
                    pass
        except Exception as e:
            self.logger.warning(f"  Wayback fetch error: {e}")

        self.logger.info(f"  ★ Harvested {len(urls)} historical URLs")
        return urls


# ─────────────────────────────────────────────────────────
# PHASE 9: WHOIS & ASN
# ─────────────────────────────────────────────────────────

class WHOISLookup:
    """Perform WHOIS lookup on the target domain."""

    def __init__(self, domain: str, logger: logging.Logger):
        self.domain = domain
        self.logger = logger

    def lookup(self) -> Optional[WHOISResult]:
        """Perform WHOIS lookup."""
        self.logger.info(f"[Phase 9] WHOIS & ASN Lookup")
        if not HAS_WHOIS:
            self.logger.warning("  python-whois not installed, skipping WHOIS lookup")
            return None

        try:
            w = python_whois.whois(self.domain)
            result = WHOISResult(domain=self.domain)
            result.registrar = str(w.registrar or "")
            result.org = str(w.org or "")

            if w.creation_date:
                cd = w.creation_date
                if isinstance(cd, list):
                    cd = cd[0]
                result.creation_date = str(cd)

            if w.expiration_date:
                ed = w.expiration_date
                if isinstance(ed, list):
                    ed = ed[0]
                result.expiration_date = str(ed)

            if w.name_servers:
                ns = w.name_servers
                if isinstance(ns, list):
                    result.name_servers = [str(n).lower() for n in ns]
                else:
                    result.name_servers = [str(ns).lower()]

            if w.emails:
                em = w.emails
                if isinstance(em, list):
                    result.emails = em
                else:
                    result.emails = [em]

            self.logger.info(f"  ★ WHOIS data collected (Registrar: {result.registrar})")
            return result
        except Exception as e:
            self.logger.warning(f"  WHOIS lookup failed: {e}")
            return None


# ─────────────────────────────────────────────────────────
# PHASE 10: HTML REPORT GENERATOR
# ─────────────────────────────────────────────────────────

class HTMLReportGenerator:
    """Generate a comprehensive HTML report with metrics and charts."""

    def __init__(self, results: EnumerationResults, output_dir: str, logger: logging.Logger):
        self.results = results
        self.output_dir = output_dir
        self.logger = logger

    def generate(self) -> str:
        """Generate the full HTML report and return the file path."""
        self.logger.info("[Phase 10] Generating HTML Report...")

        r = self.results
        duration = (r.end_time - r.start_time).total_seconds() if r.end_time and r.start_time else 0
        alive_subs = [s for s in r.subdomains if s.is_alive]
        unique_ips = set()
        for s in r.subdomains:
            unique_ips.update(s.ip_addresses)
        unique_techs = set()
        for s in r.subdomains:
            unique_techs.update(s.technologies)
        status_counter = Counter(s.status_code for s in alive_subs if s.status_code)
        tech_counter = Counter()
        for s in r.subdomains:
            for t in s.technologies:
                tech_counter[t] += 1
        interesting_dirs = [d for d in r.directories if d.interesting]
        total_js_endpoints = sum(len(j.endpoints) for j in r.js_files)
        total_js_secrets = sum(len(j.secrets) for j in r.js_files)
        total_params = sum(len(v) for v in r.parameters.values())
        wayback_extensions = Counter()
        for wu in r.wayback_urls:
            parsed = urllib.parse.urlparse(wu.url)
            ext = os.path.splitext(parsed.path)[1].lower()
            if ext:
                wayback_extensions[ext] += 1

        # Build status code chart data
        status_labels = [str(k) for k in sorted(status_counter.keys())]
        status_values = [status_counter[int(k)] for k in status_labels]

        # Build tech chart data
        top_techs = tech_counter.most_common(15)
        tech_labels = [t[0] for t in top_techs]
        tech_values = [t[1] for t in top_techs]

        # Port service distribution
        port_services = Counter(p.service for p in r.open_ports)
        port_labels = [x[0] for x in port_services.most_common(15)]
        port_values = [x[1] for x in port_services.most_common(15)]

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconStorm Report — {self._esc(r.target)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {{
  --bg: #0d1117;
  --bg2: #161b22;
  --bg3: #1c2333;
  --accent: #58a6ff;
  --accent2: #1f6feb;
  --green: #3fb950;
  --red: #f85149;
  --orange: #d29922;
  --yellow: #e3b341;
  --purple: #bc8cff;
  --cyan: #39d2c0;
  --text: #c9d1d9;
  --text2: #8b949e;
  --border: #30363d;
  --card: #161b22;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
  line-height: 1.6;
  padding: 0;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

/* HEADER */
.header {{
  background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #1a1e2e 100%);
  border-bottom: 1px solid var(--border);
  padding: 40px 30px;
  text-align: center;
}}
.header h1 {{
  font-size: 2.5em;
  background: linear-gradient(135deg, var(--accent), var(--cyan));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 8px;
}}
.header .subtitle {{ color: var(--text2); font-size: 1.1em; }}
.header .meta {{ color: var(--text2); margin-top: 15px; font-size: 0.9em; }}
.header .meta span {{ margin: 0 15px; }}

/* NAV */
.nav {{
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  padding: 10px 30px;
  position: sticky;
  top: 0;
  z-index: 100;
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  justify-content: center;
}}
.nav a {{
  color: var(--text2);
  padding: 6px 14px;
  border-radius: 6px;
  font-size: 0.85em;
  transition: all 0.2s;
}}
.nav a:hover {{ background: var(--bg3); color: var(--accent); text-decoration: none; }}

/* CONTAINER */
.container {{ max-width: 1400px; margin: 0 auto; padding: 30px; }}

/* METRICS */
.metrics {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
  margin-bottom: 30px;
}}
.metric-card {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
  text-align: center;
  transition: transform 0.2s, border-color 0.2s;
}}
.metric-card:hover {{
  transform: translateY(-2px);
  border-color: var(--accent);
}}
.metric-card .number {{
  font-size: 2.2em;
  font-weight: 700;
  margin-bottom: 5px;
}}
.metric-card .label {{
  color: var(--text2);
  font-size: 0.85em;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}}
.metric-card.highlight {{ border-left: 4px solid var(--accent); }}
.metric-card .number.green {{ color: var(--green); }}
.metric-card .number.red {{ color: var(--red); }}
.metric-card .number.orange {{ color: var(--orange); }}
.metric-card .number.purple {{ color: var(--purple); }}
.metric-card .number.cyan {{ color: var(--cyan); }}
.metric-card .number.accent {{ color: var(--accent); }}

/* SECTION */
.section {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: 25px;
  overflow: hidden;
}}
.section-header {{
  padding: 18px 25px;
  background: var(--bg3);
  border-bottom: 1px solid var(--border);
  display: flex;
  justify-content: space-between;
  align-items: center;
  cursor: pointer;
}}
.section-header h2 {{
  font-size: 1.2em;
  display: flex;
  align-items: center;
  gap: 10px;
}}
.section-header .badge {{
  background: var(--accent2);
  color: #fff;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 0.8em;
}}
.section-body {{ padding: 20px 25px; }}

/* TABLE */
.data-table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 0.88em;
}}
.data-table th {{
  background: var(--bg3);
  color: var(--text2);
  padding: 10px 12px;
  text-align: left;
  font-weight: 600;
  text-transform: uppercase;
  font-size: 0.8em;
  letter-spacing: 0.5px;
  border-bottom: 2px solid var(--border);
  position: sticky;
  top: 48px;
}}
.data-table td {{
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  word-break: break-all;
}}
.data-table tr:hover td {{ background: rgba(88,166,255,0.04); }}
.data-table .scrollable {{
  max-height: 500px;
  overflow-y: auto;
}}

/* STATUS BADGES */
.status {{ padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 600; }}
.status-200 {{ background: rgba(63,185,80,0.15); color: var(--green); }}
.status-301, .status-302 {{ background: rgba(210,153,34,0.15); color: var(--orange); }}
.status-403 {{ background: rgba(188,140,255,0.15); color: var(--purple); }}
.status-404 {{ background: rgba(139,148,158,0.15); color: var(--text2); }}
.status-500 {{ background: rgba(248,81,73,0.15); color: var(--red); }}
.status-open {{ background: rgba(63,185,80,0.15); color: var(--green); }}

/* TAGS */
.tag {{
  display: inline-block;
  background: rgba(88,166,255,0.12);
  color: var(--accent);
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.78em;
  margin: 1px 2px;
}}
.tag.secret {{
  background: rgba(248,81,73,0.15);
  color: var(--red);
}}

/* CHARTS */
.charts-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 20px;
  margin-bottom: 25px;
}}
.chart-card {{
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
}}
.chart-card h3 {{
  color: var(--text2);
  font-size: 0.95em;
  margin-bottom: 15px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}}

/* COLLAPSIBLE */
.collapsible-content {{ display: block; }}
.collapsible-toggle {{ cursor: pointer; user-select: none; }}
.section.collapsed .collapsible-content {{ display: none; }}
.section.collapsed .section-header .arrow {{ transform: rotate(-90deg); }}
.arrow {{ transition: transform 0.2s; font-size: 0.8em; }}

/* FOOTER */
.footer {{
  text-align: center;
  padding: 25px;
  color: var(--text2);
  font-size: 0.85em;
  border-top: 1px solid var(--border);
  margin-top: 30px;
}}

/* SCROLLBAR */
::-webkit-scrollbar {{ width: 8px; height: 8px; }}
::-webkit-scrollbar-track {{ background: var(--bg); }}
::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--text2); }}

/* SEARCH/FILTER */
.filter-input {{
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 0.9em;
  width: 250px;
  margin-bottom: 15px;
}}
.filter-input:focus {{ outline: none; border-color: var(--accent); }}

/* RESPONSIVE */
@media (max-width: 768px) {{
  .header h1 {{ font-size: 1.5em; }}
  .metrics {{ grid-template-columns: repeat(2, 1fr); }}
  .charts-grid {{ grid-template-columns: 1fr; }}
  .container {{ padding: 15px; }}
  .data-table {{ font-size: 0.8em; }}
}}
</style>
</head>
<body>

<!-- ========== HEADER ========== -->
<div class="header">
  <h1>⚡ ReconStorm Report</h1>
  <div class="subtitle">Bug Bounty Enumeration Results for <strong>{self._esc(r.target)}</strong></div>
  <div class="meta">
    <span>📅 {r.start_time.strftime('%Y-%m-%d %H:%M:%S') if r.start_time else 'N/A'}</span>
    <span>⏱️ Duration: {duration:.1f}s</span>
    <span>🖥️ {platform.node()}</span>
    <span>🐍 Python {platform.python_version()}</span>
  </div>
</div>

<!-- ========== NAV ========== -->
<div class="nav">
  <a href="#metrics">📊 Metrics</a>
  <a href="#charts">📈 Charts</a>
  <a href="#subdomains">🌐 Subdomains</a>
  <a href="#dns">📋 DNS</a>
  <a href="#ports">🔌 Ports</a>
  <a href="#directories">📁 Directories</a>
  <a href="#jsfiles">📜 JS Files</a>
  <a href="#params">🔑 Parameters</a>
  <a href="#wayback">🕰️ Wayback</a>
  <a href="#whois">🏢 WHOIS</a>
</div>

<div class="container">

<!-- ========== METRICS ========== -->
<div id="metrics" class="metrics">
  <div class="metric-card highlight">
    <div class="number accent">{len(r.subdomains)}</div>
    <div class="label">Total Subdomains</div>
  </div>
  <div class="metric-card">
    <div class="number green">{len(alive_subs)}</div>
    <div class="label">Alive Hosts</div>
  </div>
  <div class="metric-card">
    <div class="number cyan">{len(unique_ips)}</div>
    <div class="label">Unique IPs</div>
  </div>
  <div class="metric-card">
    <div class="number purple">{len(unique_techs)}</div>
    <div class="label">Technologies</div>
  </div>
  <div class="metric-card">
    <div class="number orange">{len(r.open_ports)}</div>
    <div class="label">Open Ports</div>
  </div>
  <div class="metric-card">
    <div class="number green">{len(r.directories)}</div>
    <div class="label">Endpoints Found</div>
  </div>
  <div class="metric-card">
    <div class="number red">{len(interesting_dirs)}</div>
    <div class="label">Interesting Dirs</div>
  </div>
  <div class="metric-card">
    <div class="number cyan">{len(r.js_files)}</div>
    <div class="label">JS Files</div>
  </div>
  <div class="metric-card">
    <div class="number red">{total_js_secrets}</div>
    <div class="label">Potential Secrets</div>
  </div>
  <div class="metric-card">
    <div class="number purple">{total_js_endpoints}</div>
    <div class="label">JS Endpoints</div>
  </div>
  <div class="metric-card">
    <div class="number orange">{total_params}</div>
    <div class="label">Parameters</div>
  </div>
  <div class="metric-card">
    <div class="number accent">{len(r.wayback_urls)}</div>
    <div class="label">Wayback URLs</div>
  </div>
</div>

<!-- ========== CHARTS ========== -->
<div id="charts" class="charts-grid">
  <div class="chart-card">
    <h3>HTTP Status Code Distribution</h3>
    <canvas id="statusChart" height="250"></canvas>
  </div>
  <div class="chart-card">
    <h3>Technology Stack</h3>
    <canvas id="techChart" height="250"></canvas>
  </div>
  <div class="chart-card">
    <h3>Open Port Services</h3>
    <canvas id="portChart" height="250"></canvas>
  </div>
  <div class="chart-card">
    <h3>Subdomain Sources</h3>
    <canvas id="sourceChart" height="250"></canvas>
  </div>
</div>

<!-- ========== SUBDOMAINS ========== -->
<div id="subdomains" class="section">
  <div class="section-header collapsible-toggle" onclick="toggleSection(this)">
    <h2><span class="arrow">▼</span> 🌐 Subdomains <span class="badge">{len(r.subdomains)}</span></h2>
  </div>
  <div class="section-body collapsible-content">
    <input type="text" class="filter-input" placeholder="Filter subdomains..." onkeyup="filterTable(this, 'subdomains-table')">
    <div style="max-height:600px;overflow-y:auto;">
    <table class="data-table" id="subdomains-table">
      <thead><tr>
        <th>#</th><th>Subdomain</th><th>Source</th><th>IPs</th><th>CNAME</th>
        <th>Status</th><th>Title</th><th>Server</th><th>Technologies</th>
      </tr></thead>
      <tbody>
"""
        for i, s in enumerate(sorted(r.subdomains, key=lambda x: (not x.is_alive, x.subdomain)), 1):
            status_class = f"status-{s.status_code}" if s.status_code else ""
            status_text = str(s.status_code) if s.status_code else "—"
            techs_html = " ".join(f'<span class="tag">{self._esc(t)}</span>' for t in s.technologies)
            ips = ", ".join(s.ip_addresses) if s.ip_addresses else "—"
            html += f"""        <tr>
          <td>{i}</td>
          <td><a href="https://{self._esc(s.subdomain)}" target="_blank">{self._esc(s.subdomain)}</a></td>
          <td>{self._esc(s.source)}</td>
          <td><small>{self._esc(ips)}</small></td>
          <td><small>{self._esc(s.cname or '—')}</small></td>
          <td><span class="status {status_class}">{status_text}</span></td>
          <td><small>{self._esc(s.title or '—')}</small></td>
          <td><small>{self._esc(s.server or '—')}</small></td>
          <td>{techs_html or '—'}</td>
        </tr>
"""
        html += """      </tbody>
    </table>
    </div>
  </div>
</div>

"""

        # ========== DNS RECORDS ==========
        html += f"""<div id="dns" class="section">
  <div class="section-header collapsible-toggle" onclick="toggleSection(this)">
    <h2><span class="arrow">▼</span> 📋 DNS Records <span class="badge">{len(r.dns_records)}</span></h2>
  </div>
  <div class="section-body collapsible-content">
    <table class="data-table">
      <thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th></tr></thead>
      <tbody>
"""
        for rec in r.dns_records:
            html += f"""        <tr>
          <td><span class="tag">{self._esc(rec.record_type)}</span></td>
          <td>{self._esc(rec.name)}</td>
          <td><small>{self._esc(rec.value)}</small></td>
          <td>{rec.ttl}</td>
        </tr>
"""
        html += """      </tbody></table>
  </div>
</div>

"""

        # ========== OPEN PORTS ==========
        html += f"""<div id="ports" class="section">
  <div class="section-header collapsible-toggle" onclick="toggleSection(this)">
    <h2><span class="arrow">▼</span> 🔌 Open Ports <span class="badge">{len(r.open_ports)}</span></h2>
  </div>
  <div class="section-body collapsible-content">
    <div style="max-height:500px;overflow-y:auto;">
    <table class="data-table">
      <thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr></thead>
      <tbody>
"""
        for p in r.open_ports:
            html += f"""        <tr>
          <td>{self._esc(p.host)}</td>
          <td><strong>{p.port}</strong></td>
          <td><span class="status status-open">{self._esc(p.state)}</span></td>
          <td>{self._esc(p.service)}</td>
          <td><small>{self._esc(p.banner[:120])}</small></td>
        </tr>
"""
        html += """      </tbody></table>
    </div>
  </div>
</div>

"""

        # ========== DIRECTORIES ==========
        html += f"""<div id="directories" class="section">
  <div class="section-header collapsible-toggle" onclick="toggleSection(this)">
    <h2><span class="arrow">▼</span> 📁 Directories & Endpoints <span class="badge">{len(r.directories)}</span></h2>
  </div>
  <div class="section-body collapsible-content">
    <input type="text" class="filter-input" placeholder="Filter URLs..." onkeyup="filterTable(this, 'dirs-table')">
    <div style="max-height:500px;overflow-y:auto;">
    <table class="data-table" id="dirs-table">
      <thead><tr><th>URL</th><th>Status</th><th>Size</th><th>Content-Type</th><th>Redirect</th></tr></thead>
      <tbody>
"""
        for d in sorted(r.directories, key=lambda x: (not x.interesting, x.status_code, x.url)):
            sc = f"status-{d.status_code}"
            row_style = ' style="background:rgba(248,81,73,0.04);"' if d.interesting else ''
            html += f"""        <tr{row_style}>
          <td><a href="{self._esc(d.url)}" target="_blank">{self._esc(d.url)}</a></td>
          <td><span class="status {sc}">{d.status_code}</span></td>
          <td>{d.content_length}</td>
          <td><small>{self._esc(d.content_type[:50])}</small></td>
          <td><small>{self._esc(d.redirect[:80])}</small></td>
        </tr>
"""
        html += """      </tbody></table>
    </div>
  </div>
</div>

"""

        # ========== JS FILES ==========
        html += f"""<div id="jsfiles" class="section">
  <div class="section-header collapsible-toggle" onclick="toggleSection(this)">
    <h2><span class="arrow">▼</span> 📜 JavaScript Files <span class="badge">{len(r.js_files)}</span></h2>
  </div>
  <div class="section-body collapsible-content">
"""
        if r.js_files:
            for jf in r.js_files:
                secrets_html = ""
                if jf.secrets:
                    secrets_html = "<br>".join(f'<span class="tag secret">🔑 {self._esc(s)}</span>' for s in jf.secrets)
                endpoints_html = " ".join(f'<span class="tag">{self._esc(e)}</span>' for e in jf.endpoints[:15])
                if len(jf.endpoints) > 15:
                    endpoints_html += f' <span class="tag">... +{len(jf.endpoints)-15} more</span>'

                html += f"""    <div style="margin-bottom:15px;padding:12px;background:var(--bg);border-radius:6px;border:1px solid var(--border);">
      <div><strong><a href="{self._esc(jf.url)}" target="_blank">{self._esc(jf.url)}</a></strong>
        <small style="color:var(--text2);"> ({jf.size:,} bytes)</small></div>
      {f'<div style="margin-top:8px;"><strong style="color:var(--red);">Secrets:</strong><br>{secrets_html}</div>' if jf.secrets else ''}
      {f'<div style="margin-top:8px;"><strong>Endpoints ({len(jf.endpoints)}):</strong><br>{endpoints_html}</div>' if jf.endpoints else ''}
    </div>
"""
        else:
            html += "    <p>No JS files analyzed.</p>\n"
        html += """  </div>
</div>

"""

        # ========== PARAMETERS ==========
        html += f"""<div id="params" class="section">
  <div class="section-header collapsible-toggle" onclick="toggleSection(this)">
    <h2><span class="arrow">▼</span> 🔑 Discovered Parameters <span class="badge">{total_params}</span></h2>
  </div>
  <div class="section-body collapsible-content">
    <table class="data-table">
      <thead><tr><th>Endpoint</th><th>Parameters</th></tr></thead>
      <tbody>
"""
        for endpoint, params in sorted(r.parameters.items()):
            params_html = " ".join(f'<span class="tag">{self._esc(p)}</span>' for p in sorted(params))
            # Highlight interesting params
            for p in params:
                if p.lower() in INTERESTING_PARAMS:
                    params_html = params_html.replace(
                        f'<span class="tag">{self._esc(p)}</span>',
                        f'<span class="tag secret">{self._esc(p)}</span>'
                    )
            html += f"""        <tr>
          <td><small>{self._esc(endpoint[:100])}</small></td>
          <td>{params_html}</td>
        </tr>
"""
        html += """      </tbody></table>
  </div>
</div>

"""

        # ========== WAYBACK ==========
        html += f"""<div id="wayback" class="section">
  <div class="section-header collapsible-toggle" onclick="toggleSection(this)">
    <h2><span class="arrow">▼</span> 🕰️ Wayback Machine URLs <span class="badge">{len(r.wayback_urls)}</span></h2>
  </div>
  <div class="section-body collapsible-content">
    <input type="text" class="filter-input" placeholder="Filter URLs..." onkeyup="filterTable(this, 'wayback-table')">
    <div style="max-height:500px;overflow-y:auto;">
    <table class="data-table" id="wayback-table">
      <thead><tr><th>URL</th><th>Timestamp</th><th>MIME</th><th>Status</th></tr></thead>
      <tbody>
"""
        for wu in r.wayback_urls[:500]:  # Cap display at 500
            html += f"""        <tr>
          <td><a href="{self._esc(wu.url)}" target="_blank"><small>{self._esc(wu.url[:120])}</small></a></td>
          <td><small>{self._esc(wu.timestamp)}</small></td>
          <td><small>{self._esc(wu.mime_type)}</small></td>
          <td>{self._esc(wu.status_code)}</td>
        </tr>
"""
        if len(r.wayback_urls) > 500:
            html += f'        <tr><td colspan="4" style="text-align:center;color:var(--text2);">... and {len(r.wayback_urls)-500} more URLs (see raw output)</td></tr>\n'
        html += """      </tbody></table>
    </div>
  </div>
</div>

"""

        # ========== WHOIS ==========
        html += f"""<div id="whois" class="section">
  <div class="section-header collapsible-toggle" onclick="toggleSection(this)">
    <h2><span class="arrow">▼</span> 🏢 WHOIS Information</h2>
  </div>
  <div class="section-body collapsible-content">
"""
        if r.whois_info:
            w = r.whois_info
            html += f"""    <table class="data-table">
      <tbody>
        <tr><td><strong>Domain</strong></td><td>{self._esc(w.domain)}</td></tr>
        <tr><td><strong>Registrar</strong></td><td>{self._esc(w.registrar)}</td></tr>
        <tr><td><strong>Organization</strong></td><td>{self._esc(w.org)}</td></tr>
        <tr><td><strong>Created</strong></td><td>{self._esc(w.creation_date)}</td></tr>
        <tr><td><strong>Expires</strong></td><td>{self._esc(w.expiration_date)}</td></tr>
        <tr><td><strong>Name Servers</strong></td><td>{self._esc(', '.join(w.name_servers))}</td></tr>
        <tr><td><strong>Emails</strong></td><td>{self._esc(', '.join(w.emails))}</td></tr>
      </tbody>
    </table>
"""
        else:
            html += "    <p>WHOIS data not available.</p>\n"
        html += """  </div>
</div>

"""

        # ========== ERRORS ==========
        if r.errors:
            html += f"""<div class="section">
  <div class="section-header">
    <h2>⚠️ Errors & Warnings <span class="badge" style="background:var(--red);">{len(r.errors)}</span></h2>
  </div>
  <div class="section-body">
    <ul style="list-style:none;">
"""
            for err in r.errors:
                html += f'      <li style="padding:4px 0;color:var(--orange);">⚠ {self._esc(err)}</li>\n'
            html += """    </ul>
  </div>
</div>
"""

        # ========== SUBDOMAIN SOURCE DISTRIBUTION (for chart) ==========
        source_counter = Counter(s.source for s in r.subdomains)
        source_labels = [x[0] for x in source_counter.most_common()]
        source_values = [x[1] for x in source_counter.most_common()]

        # ========== FOOTER + SCRIPTS ==========
        html += f"""
</div> <!-- /container -->

<div class="footer">
  Generated by <strong>ReconStorm v{VERSION}</strong> | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
  Target: {self._esc(r.target)} | Duration: {duration:.1f}s
</div>

<script>
// ─── Collapsible Sections ───
function toggleSection(header) {{
  header.parentElement.classList.toggle('collapsed');
}}

// ─── Table Filter ───
function filterTable(input, tableId) {{
  const filter = input.value.toLowerCase();
  const table = document.getElementById(tableId);
  const rows = table.getElementsByTagName('tr');
  for (let i = 1; i < rows.length; i++) {{
    const text = rows[i].textContent.toLowerCase();
    rows[i].style.display = text.includes(filter) ? '' : 'none';
  }}
}}

// ─── Chart.js Config ───
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#30363d';
Chart.defaults.font.family = "'Segoe UI', sans-serif";

const palette = ['#58a6ff','#3fb950','#d29922','#f85149','#bc8cff','#39d2c0','#f0883e',
                 '#a5d6ff','#7ee787','#e3b341','#ff7b72','#d2a8ff','#56d4dd','#ffa657'];

// Status Code Chart
new Chart(document.getElementById('statusChart'), {{
  type: 'doughnut',
  data: {{
    labels: {json.dumps(status_labels)},
    datasets: [{{ data: {json.dumps(status_values)}, backgroundColor: palette, borderWidth: 0 }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ position: 'right', labels: {{ padding: 12, usePointStyle: true }} }}
    }}
  }}
}});

// Technology Chart
new Chart(document.getElementById('techChart'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(tech_labels)},
    datasets: [{{ label: 'Count', data: {json.dumps(tech_values)}, backgroundColor: '#58a6ff88', borderColor: '#58a6ff', borderWidth: 1 }}]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ x: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }} }}
  }}
}});

// Port Services Chart
new Chart(document.getElementById('portChart'), {{
  type: 'doughnut',
  data: {{
    labels: {json.dumps(port_labels)},
    datasets: [{{ data: {json.dumps(port_values)}, backgroundColor: palette, borderWidth: 0 }}]
  }},
  options: {{
    responsive: true,
    plugins: {{
      legend: {{ position: 'right', labels: {{ padding: 12, usePointStyle: true }} }}
    }}
  }}
}});

// Source Chart
new Chart(document.getElementById('sourceChart'), {{
  type: 'bar',
  data: {{
    labels: {json.dumps(source_labels)},
    datasets: [{{ label: 'Subdomains', data: {json.dumps(source_values)}, backgroundColor: '#3fb95088', borderColor: '#3fb950', borderWidth: 1 }}]
  }},
  options: {{
    indexAxis: 'y',
    responsive: true,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{ x: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }} }}
  }}
}});
</script>

</body>
</html>"""

        # Write to file
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"recon_storm_{r.target}_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        self.logger.info(f"  ★ Report saved to: {filepath}")
        return filepath

    def _esc(self, text: str) -> str:
        """Escape HTML special characters."""
        if not text:
            return ""
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))


# ─────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────

class ReconStorm:
    """Main orchestrator that runs all enumeration phases."""

    def __init__(self, domain: str, threads: int = 30, timeout: int = 10,
                 output_dir: str = "./recon_output", verbose: bool = False):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.output_dir = output_dir
        self.logger = setup_logger(verbose)
        self.session = get_session()
        self.results = EnumerationResults(target=self.domain)

        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def run(self):
        """Execute the full enumeration pipeline."""
        print(BANNER)
        self.logger.info(f"Target: {self.domain}")
        self.logger.info(f"Threads: {self.threads} | Timeout: {self.timeout}s")
        self.logger.info(f"Output: {os.path.abspath(self.output_dir)}")
        self.logger.info("=" * 60)

        self.results.start_time = datetime.datetime.now()

        try:
            # ── Phase 1: Subdomain Enumeration ──
            enumerator = SubdomainEnumerator(
                self.domain, self.session, self.logger, self.threads, self.timeout
            )
            found_subs = enumerator.enumerate()

            # ── Phase 2: DNS Resolution ──
            dns_resolver = DNSResolver(self.domain, self.logger, self.timeout)
            self.results.dns_records = dns_resolver.resolve_domain_records()

            # Build SubdomainResult objects and resolve each
            self.logger.info(f"  → Resolving {len(found_subs)} subdomains...")
            subdomain_results = []
            for sub, source in found_subs.items():
                sr = SubdomainResult(subdomain=sub, source=source)
                ips, cname = dns_resolver.resolve_subdomain(sub)
                sr.ip_addresses = ips
                sr.cname = cname
                subdomain_results.append(sr)
            self.results.subdomains = subdomain_results

            # ── Phase 3: HTTP Probing ──
            prober = HTTPProber(self.session, self.logger, self.threads, self.timeout)
            self.results.subdomains = prober.probe_subdomains(self.results.subdomains)

            # ── Phase 4: Port Scanning ──
            all_ips = set()
            for s in self.results.subdomains:
                all_ips.update(s.ip_addresses)
            if all_ips:
                scanner = PortScanner(self.logger, self.threads, timeout=3)
                self.results.open_ports = scanner.scan(list(all_ips))

            # Build alive URL list for subsequent phases
            alive_urls = []
            for s in self.results.subdomains:
                if s.is_alive:
                    scheme = "https" if s.redirect_url and s.redirect_url.startswith("https") else "https"
                    alive_urls.append(f"{scheme}://{s.subdomain}")

            # ── Phase 5: Directory Discovery ──
            if alive_urls:
                dir_bruter = DirectoryBruter(self.session, self.logger, self.threads, self.timeout)
                self.results.directories = dir_bruter.scan(alive_urls)

            # ── Phase 6: JS Analysis ──
            if alive_urls:
                js_analyzer = JSAnalyzer(self.session, self.logger, self.timeout)
                self.results.js_files = js_analyzer.analyze(alive_urls)

            # ── Phase 8: Wayback Machine ──
            wayback = WaybackHarvester(self.domain, self.session, self.logger)
            self.results.wayback_urls = wayback.harvest()

            # ── Phase 7: Parameter Discovery ──
            if alive_urls:
                param_disco = ParameterDiscovery(self.session, self.logger, self.timeout)
                self.results.parameters = param_disco.discover(alive_urls, self.results.wayback_urls)

            # ── Phase 9: WHOIS ──
            whois_lookup = WHOISLookup(self.domain, self.logger)
            self.results.whois_info = whois_lookup.lookup()

        except KeyboardInterrupt:
            self.logger.warning("Interrupted by user!")
            self.results.errors.append("Scan interrupted by user (Ctrl+C)")
        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            self.results.errors.append(f"Fatal error: {str(e)}")

        self.results.end_time = datetime.datetime.now()

                # ── Phase 10: Report Generation ──
        self.logger.info("=" * 60)
        report_gen = HTMLReportGenerator(self.results, self.output_dir, self.logger)
        report_path = report_gen.generate()

        # Also dump raw JSON for programmatic use
        json_path = self._dump_json()

        # Print summary
        self._print_summary(report_path, json_path)

        return report_path

    def _dump_json(self) -> str:
        """Dump all results to a JSON file for programmatic consumption."""
        r = self.results
        data = {
            "target": r.target,
            "start_time": r.start_time.isoformat() if r.start_time else None,
            "end_time": r.end_time.isoformat() if r.end_time else None,
            "duration_seconds": (r.end_time - r.start_time).total_seconds() if r.end_time and r.start_time else 0,
            "summary": {
                "total_subdomains": len(r.subdomains),
                "alive_subdomains": sum(1 for s in r.subdomains if s.is_alive),
                "unique_ips": len(set(ip for s in r.subdomains for ip in s.ip_addresses)),
                "open_ports": len(r.open_ports),
                "directories_found": len(r.directories),
                "interesting_dirs": sum(1 for d in r.directories if d.interesting),
                "js_files_analyzed": len(r.js_files),
                "potential_secrets": sum(len(j.secrets) for j in r.js_files),
                "js_endpoints": sum(len(j.endpoints) for j in r.js_files),
                "parameters_found": sum(len(v) for v in r.parameters.values()),
                "wayback_urls": len(r.wayback_urls),
            },
            "subdomains": [
                {
                    "subdomain": s.subdomain,
                    "source": s.source,
                    "ip_addresses": s.ip_addresses,
                    "cname": s.cname,
                    "is_alive": s.is_alive,
                    "status_code": s.status_code,
                    "title": s.title,
                    "server": s.server,
                    "content_length": s.content_length,
                    "redirect_url": s.redirect_url,
                    "technologies": s.technologies,
                    "ssl_info": s.ssl_info,
                }
                for s in r.subdomains
            ],
            "dns_records": [
                {
                    "type": rec.record_type,
                    "name": rec.name,
                    "value": rec.value,
                    "ttl": rec.ttl,
                }
                for rec in r.dns_records
            ],
            "open_ports": [
                {
                    "host": p.host,
                    "port": p.port,
                    "state": p.state,
                    "service": p.service,
                    "banner": p.banner,
                }
                for p in r.open_ports
            ],
            "directories": [
                {
                    "url": d.url,
                    "status_code": d.status_code,
                    "content_length": d.content_length,
                    "content_type": d.content_type,
                    "redirect": d.redirect,
                    "interesting": d.interesting,
                }
                for d in r.directories
            ],
            "js_files": [
                {
                    "url": j.url,
                    "size": j.size,
                    "endpoints": j.endpoints,
                    "secrets": j.secrets,
                }
                for j in r.js_files
            ],
            "parameters": {
                endpoint: sorted(params)
                for endpoint, params in r.parameters.items()
            },
            "wayback_urls": [
                {
                    "url": wu.url,
                    "timestamp": wu.timestamp,
                    "mime_type": wu.mime_type,
                    "status_code": wu.status_code,
                }
                for wu in r.wayback_urls
            ],
            "whois": {
                "domain": r.whois_info.domain,
                "registrar": r.whois_info.registrar,
                "org": r.whois_info.org,
                "creation_date": r.whois_info.creation_date,
                "expiration_date": r.whois_info.expiration_date,
                "name_servers": r.whois_info.name_servers,
                "emails": r.whois_info.emails,
            } if r.whois_info else None,
            "errors": r.errors,
        }

        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = f"recon_storm_{r.target}_{timestamp}.json"
        json_path = os.path.join(self.output_dir, json_filename)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        self.logger.info(f"  ★ JSON data saved to: {json_path}")
        return json_path

    def _print_summary(self, report_path: str, json_path: str):
        """Print a final summary to the console."""
        r = self.results
        duration = (r.end_time - r.start_time).total_seconds() if r.end_time and r.start_time else 0
        alive = sum(1 for s in r.subdomains if s.is_alive)
        unique_ips = len(set(ip for s in r.subdomains for ip in s.ip_addresses))
        interesting = sum(1 for d in r.directories if d.interesting)
        secrets = sum(len(j.secrets) for j in r.js_files)
        js_endpoints = sum(len(j.endpoints) for j in r.js_files)
        total_params = sum(len(v) for v in r.parameters.values())

        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║                   RECON STORM — SUMMARY                     ║
╠══════════════════════════════════════════════════════════════╣
║  Target:             {r.target:<39} ║
║  Duration:           {duration:<39.1f} ║
╠══════════════════════════════════════════════════════════════╣
║  Subdomains Found:   {len(r.subdomains):<39} ║
║  Alive Hosts:        {alive:<39} ║
║  Unique IPs:         {unique_ips:<39} ║
║  DNS Records:        {len(r.dns_records):<39} ║
║  Open Ports:         {len(r.open_ports):<39} ║
║  Endpoints Found:    {len(r.directories):<39} ║
║  Interesting Dirs:   {interesting:<39} ║
║  JS Files Analyzed:  {len(r.js_files):<39} ║
║  Potential Secrets:  {secrets:<39} ║
║  JS Endpoints:       {js_endpoints:<39} ║
║  Parameters:         {total_params:<39} ║
║  Wayback URLs:       {len(r.wayback_urls):<39} ║
╠══════════════════════════════════════════════════════════════╣
║  HTML Report: {report_path:<46} ║
║  JSON Data:   {json_path:<46} ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(summary)

        # Highlight critical findings
        if secrets > 0:
            self.logger.warning(f"🚨 {secrets} POTENTIAL SECRETS found in JavaScript files! Review immediately.")
        if interesting > 0:
            self.logger.warning(f"🔍 {interesting} INTERESTING directories/files found (admin panels, configs, debug endpoints).")

        # Highlight potential takeover candidates (CNAME with no resolution)
        takeover_candidates = []
        for s in r.subdomains:
            if s.cname and not s.is_alive:
                takeover_candidates.append(s)
        if takeover_candidates:
            self.logger.warning(f"🎯 {len(takeover_candidates)} potential SUBDOMAIN TAKEOVER candidates detected:")
            for tc in takeover_candidates[:10]:
                self.logger.warning(f"   → {tc.subdomain} (CNAME: {tc.cname})")

        # Highlight high-risk open ports
        high_risk_ports = {21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 11211, 27017}
        risky = [p for p in r.open_ports if p.port in high_risk_ports]
        if risky:
            self.logger.warning(f"⚠️  {len(risky)} HIGH-RISK ports found open:")
            for rp in risky[:10]:
                self.logger.warning(f"   → {rp.host}:{rp.port} ({rp.service})")


# ─────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ReconStorm — Bug Bounty Enumeration & HTML Reporting Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com
  %(prog)s -d example.com --threads 50 --timeout 15
  %(prog)s -d example.com -o ./reports --verbose

Methodology Phases:
  1. Subdomain Enumeration (7 passive sources + DNS brute-force)
  2. DNS Record Collection (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA)
  3. HTTP Probing & Technology Fingerprinting
  4. Port Scanning (top 35 common ports)
  5. Directory & Endpoint Discovery (80+ common paths)
  6. JavaScript File Analysis (endpoint + secret extraction)
  7. Parameter Discovery (from HTML forms, URLs, Wayback)
  8. Wayback Machine URL Harvesting
  9. WHOIS & ASN Lookup
  10. HTML Report Generation with Interactive Charts
        """,
    )

    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain to enumerate (e.g., example.com)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=30,
        help="Number of concurrent threads (default: 30)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "-o", "--output",
        default="./recon_output",
        help="Output directory for reports (default: ./recon_output)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ReconStorm v{VERSION}"
    )

    args = parser.parse_args()

    # Validate domain
    domain = args.domain.lower().strip()
    domain = domain.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in domain:
        domain = domain.split("/")[0]

    # Run the enumeration
    recon = ReconStorm(
        domain=domain,
        threads=args.threads,
        timeout=args.timeout,
        output_dir=args.output,
        verbose=args.verbose,
    )
    recon.run()


if __name__ == "__main__":
    main()
