# THIS TOOL WAS CREATED WITH THE HELP OF CLAUDE OPUS 4.6 FOR FUN AND EXPERIMENTATION. USE IT ONLY FOR TESTING AND ETHICAL PURPOSES.

## IF YOU FIND THE IDEA INTERESTING, YOU CAN FORK THIS REPO AND ANY CONTRIBUTIONS ARE MORE THAN WELCOME!

### 1) Architecture

    recon-storm/
    ├── main.go                     # Entry point, signal handling
    ├── pkg/config/config.go        # Configuration
    ├── pkg/installer/installer.go  # Auto tool installation
    ├── pkg/logger/logger.go        # Structured logging
    ├── pkg/state/state.go          # Persistent state & crash recovery
    ├── pkg/scanner/
    │   ├── scanner.go              # Orchestrator
    │   ├── subdomain.go            # Subdomain enumeration
    │   ├── dns.go                  # DNS resolution & zone transfers
    │   ├── port.go                 # Port scanning
    │   ├── web.go                  # Web probing & tech detection
    │   ├── endpoints.go            # URL/endpoint discovery
    │   ├── vuln.go                 # Vulnerability scanning
    │   ├── secrets.go              # Secret discovery
    │   └── screenshots.go          # Visual recon
    └── pkg/reporter/reporter.go    # Report generation

### 2) Installation

# Clone

    git clone https://github.com/H3llKa1ser/recon-storm.git
    cd /recon-storm

# Build

    go mod tidy
    go build -ldflags="-s -w" -o reconstorm .

# System-wide use (optional)

    sudo cp reconstorm /usr/local/bin/

# Cross-compile

    GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o reconstorm-linux .
    GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o reconstorm-mac .
    GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o reconstorm.exe .    

# Run

    ./reconstorm -d example.com

### 3) Usage

# Basic scan

    ./reconstorm -d example.com

# Domain list + custom output

    ./reconstorm -dL targets.txt -o ./results -t 100

# Passive only

    ./reconstorm -d example.com -passive

# Specific modules

    ./reconstorm -d example.com -modules subdomains,dns,web

# With API keys

    ./reconstorm -d example.com -shodan-key KEY -vt-key KEY

# Resume interrupted scan

    ./reconstorm -d example.com -o ./recon-example.com-20260311 -resume

## TODO LATER:

    I'm developing a bug bounty reconnaissance framework called ReconStorm, written in Go.
    
    Repository: https://github.com/H3llKa1ser/recon-storm
    Go module path: github.com/H3llKa1ser/recon-storm
    
    The framework is fully built, tested on live targets across different systems, and actively being improved.
    
    ## Architecture
    
    recon-storm/
    ├── go.mod                          # module github.com/H3llKa1ser/recon-storm
    ├── main.go                         # Entry point, CLI flags, signal handling, panic recovery, global timeout watchdog
    ├── pkg/
    │   ├── config/config.go            # Config struct, domain resolution, module/API key checks
    │   ├── installer/installer.go      # Auto-checks and installs 26+ tools with 9 fallback methods
    │   ├── logger/logger.go            # Thread-safe colored console + file logger with progress bars
    │   ├── state/state.go              # Persistent state manager: findings, module results, stats, auto-save every 30s, atomic JSON writes, crash recovery
    │   ├── scanner/
    │   │   ├── scanner.go              # Orchestrator: runs modules sequentially per domain, per-module timeout & panic recovery, resume support
    │   │   ├── subdomain.go            # Concurrent: subfinder, amass, assetfinder, findomain, crt.sh → deduplicated all_subdomains.txt
    │   │   ├── dns.go                  # dnsx resolution, zone transfer attempts via dig
    │   │   ├── port.go                 # naabu fast scan → nmap service detection. If naabu missing, falls back to nmap top-1000 directly
    │   │   ├── web.go                  # httpx probing with tech detection, CDN, JARM, favicon hash. Includes findHttpx() to resolve Python vs ProjectDiscovery httpx conflict
    │   │   ├── endpoints.go            # Concurrent: waybackurls, gau, katana, gospider → categorized (JS, API, params, sensitive)
    │   │   ├── vuln.go                 # nuclei scanner + custom sensitive path checks via httpx (26 paths checked)
    │   │   ├── secrets.go              # ffuf content discovery + JS file regex scanning for API keys/tokens/credentials
    │   │   └── screenshots.go          # gowitness visual recon
    │   └── reporter/reporter.go        # Generates HTML (dark theme, styled), JSON, and Markdown reports
    
    ## Key Design Decisions
    - All modules implement Module interface: Name() string, Run(ctx context.Context, domain string) error
    - State is saved atomically (write .tmp → rename) every 30 seconds + on every module completion
    - Emergency report generation on: SIGINT, SIGTERM, SIGHUP, panic, global timeout
    - Resume mode (-resume flag) skips modules already marked StatusCompleted in state.json
    - No external Go dependencies — only stdlib + net/http for GitHub API. External recon tools are called via os/exec
    - All imports use: github.com/H3llKa1ser/recon-storm/pkg/...
    
    ## Installer Details (Major Rewrite Completed)
    The installer was completely rewritten and now supports 9 installation methods in priority order:
    1. go install (for Go tools)
    2. sudo apt-get install (for system packages)
    3. GitHub Release binary download (universal fallback — uses GitHub API, auto-detects arch, handles zip/tar.gz/raw binary)
    4. git clone + make (compile from source, used for MassDNS)
    5. cargo install (for Rust tools like Findomain)
    6. pip3 install (for Python tools)
    7. brew install (for macOS)
    8. snap install
    9. Custom script (arbitrary bash commands)
    
    The installer also:
    - Runs in phases: build deps → httpx conflict resolution → recon tools → post-install (nuclei templates, SecLists)
    - Auto-detects and resolves Python httpx vs ProjectDiscovery httpx conflict (renames Python binary, installs correct Go one)
    - Installs build dependencies first (libpcap-dev, unzip, curl, git)
    - Installs SecLists wordlists via apt or git clone fallback
    - Runs apt-get update at start
    - Nuclei installs via GitHub Release FIRST (precompiled binary), falls back to go install
    
    ## Test Results So Far
    
    I have tested this tool on two different Kali Linux systems with different pre-installed tools, different apt source configurations, and different targets. The results need to be compared side-by-side to identify which issues are code bugs vs system-specific environment problems.
    
    ### Test 1: Kali Linux System A — Target: 21-school.ru
    This was run with the OLD installer (only 3 methods: go install, apt, brew).
    - System had many recon tools pre-installed (11 found)
    - 0 tools auto-installed, 4 required failures (subfinder, dnsx, naabu, nuclei)
    - CRITICAL BUG FOUND: Python httpx (encode/httpx) was in PATH instead of ProjectDiscovery httpx. Flag -l doesn't exist in Python httpx. httpx failed with "No such option: -l", resulting in 0 live web servers
    - httpx failure cascaded downstream: vulns found 0, secrets had no targets, screenshots had no URLs
    - Subdomains worked well: amass (82), assetfinder (28), crt.sh (1) → 93 unique
    - DNS zone transfer detection worked: found 2 vulnerable nameservers (ns1/ns2.21-school.ru) — but may be false positives (check only validates response >100 bytes)
    - Port module was a silent no-op: Naabu missing, Nmap had no input, completed in 2ms
    - Endpoints worked via passive tools despite httpx failure: waybackurls (5772), gau (49)
    - Total scan time: 14m26s
    
    ### Test 2: Kali Linux System B — Target: scanme.nmap.org
    This was run with the NEW installer (9 methods with GitHub Release downloader).
    - Clean system, only 3 tools pre-installed (nmap, ffuf, amass)
    - Go version: 1.24.1
    - 13 tools successfully auto-installed from scratch
    - httpx conflict auto-resolved: Python version detected and renamed, ProjectDiscovery version installed
    - gowitness installed successfully via GitHub Release (previously failed via go install on System A)
    - Full pipeline working: subdomains (4) → dns (2 resolved) → ports (nmap fallback) → web (1 live) → endpoints (1402) → vulns (2 findings) → secrets (11 findings) → screenshots (1 captured)
    - Naabu failed: libpcap-dev unavailable via apt (exit status 100), GitHub Release downloaded but also failed
    - Nuclei failed: GitHub Release downloaded v3.7.1 but binary didn't reach /usr/local/bin, go install also failed
    - ALL apt-get install commands failed with exit status 100 (libpcap-dev, massdns, jq) — broken apt sources on this system
    - Total scan time: 6m37s
    
    ### Side-by-Side Comparison
    
    | Metric                    | System A (21-school.ru)  | System B (scanme.nmap.org) |
    |---------------------------|--------------------------|----------------------------|
    | Installer version         | Old (3 methods)          | New (9 methods)            |
    | Tools pre-installed       | 11                       | 3                          |
    | Tools auto-installed      | 0                        | 13                         |
    | Required tool failures    | 4                        | 2 (Naabu, Nuclei)         |
    | httpx working             | ❌ Python version        | ✅ Auto-resolved           |
    | Live web servers found    | 0 (httpx broken)         | 1 ✅                       |
    | Port scanning             | Silent no-op             | Nmap fallback ✅            |
    | Screenshots               | ❌ gowitness missing      | ✅ 1 captured              |
    | Pipeline data flow        | Modules starved           | All modules fed ✅          |
    | apt-get working           | Partially                | ❌ All exit status 100     |
    | Reports generated         | ✅ All 3                 | ✅ All 3                   |
    
    ### Issues on BOTH systems
    - Nuclei fails to install (go install OOM/timeout, GitHub Release extraction issue)
    - Findomain GitHub Release asset pattern doesn't match actual filenames
    - crt.sh parser is brittle (string splitting vs proper JSON parsing)
    
    ### Fixed between System A → System B
    - httpx conflict (FIXED: auto-detection + rename)
    - Port module no-op (FIXED: Nmap fallback)
    - Installer methods (FIXED: 3 → 9 methods)
    - gowitness install (FIXED: GitHub Release works)
    - Install failure logging (FIXED: warns per attempt)
    
    ### System B only issues
    - Broken apt sources (exit status 100 on everything)
    - Naabu needs libpcap.so runtime dependency
    - Nuclei/trufflehog GitHub Release download + extraction doesn't complete
    
    ## I am now testing on a THIRD Kali Linux system.
    
    I will provide the full terminal output from this new system. Please:
    1. Compare the results across all three systems
    2. Identify which issues are code bugs (appear everywhere) vs environment-specific (appear on one system only)
    3. Evaluate whether the installer reliably bootstraps from scratch
    4. Check if the scan pipeline flows correctly end-to-end
    5. Flag any new issues that appear on the third system
    6. Suggest fixes prioritized by impact
    
    ## Known Issues Still Open (from previous testing)
    1. Naabu install fails — needs libpcap-dev (apt broken) + possible runtime libpcap.so dependency
    2. Nuclei GitHub Release downloads but binary doesn't reach PATH — findAndInstallBinary() or zip extraction bug
    3. Findomain GitHub Release asset pattern "linux_amd64" doesn't match actual release filenames
    4. trufflehog GitHub Release same extraction issue as Nuclei
    5. crt.sh parser brittle — should use encoding/json instead of string splitting
    6. Zone transfer false positive potential — validates >100 bytes instead of actual zone records
    7. Zone transfers not gated behind PassiveOnly flag
    8. No Shodan/Censys/VirusTotal API integration despite CLI flags existing
    9. apt-get exit status 100 handling — installer should detect broken apt and skip gracefully
    
    ## What Has Been Fixed So Far
    - httpx Python vs ProjectDiscovery conflict: RESOLVED
    - Port module silent no-op when Naabu missing: RESOLVED (Nmap fallback)
    - Installer expanded from 3 to 9 install methods: RESOLVED
    - Install failure logging: RESOLVED
    - apt-get update at start: RESOLVED
    - Build dependency installation: RESOLVED
    - SecLists auto-installation: RESOLVED
    - DNS module silent skip: RESOLVED
    - gowitness installation via GitHub Release: RESOLVED
    
    The full source code is at https://github.com/H3llKa1ser/recon-storm — review the repo, wait for my System C test output, then do the full cross-system comparison and continue development.
