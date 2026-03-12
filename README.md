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
    
    The framework is fully built, tested on live targets across multiple systems, and actively being improved.
    
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
    
    ## Multi-System Test Results
    
    ### System 1: Target 21-school.ru (Kali Linux, had many tools pre-installed)
    This was the first test, run BEFORE the installer was rewritten.
    - Old installer only had 3 methods: go install, apt, brew
    - 11 tools already installed, 0 newly installed, 4 required failures (subfinder, dnsx, naabu, nuclei)
    - httpx bug discovered: Python httpx (encode/httpx) was in PATH instead of ProjectDiscovery httpx. The -l flag doesn't exist in Python httpx. This caused httpx to fail with "No such option: -l", resulting in 0 live web servers found
    - The httpx failure cascaded: vulns module found 0, secrets had no targets, screenshots had no URLs
    - Subdomains worked well: amass (82), assetfinder (28), crt.sh (1) → 93 unique
    - DNS zone transfer detection worked: found 2 vulnerable nameservers (ns1/ns2.21-school.ru)
    - Port module was a silent no-op: Naabu missing, Nmap had no input, completed in 2ms with no results
    - Endpoints module still worked via passive tools: waybackurls (5772), gau (49) → heavily relied on archive data
    - Total scan time: 14m26s
    - Key discovery: Zone transfer false positive potential — check only validates response >100 bytes, not actual zone data
    
    ### System 2: Target scanme.nmap.org (Clean system, Go 1.24.1, minimal tools pre-installed)
    This was run AFTER the installer rewrite with 9 fallback methods.
    - Only 3 tools pre-installed (nmap, ffuf, amass), everything else installed from scratch
    - 13 tools successfully auto-installed
    - httpx conflict auto-resolved: Python version detected, ProjectDiscovery version installed via go install
    - gowitness installed successfully via GitHub Release (previously failed via go install)
    - Full pipeline working end-to-end: subdomains (4) → dns (2 resolved) → ports (nmap fallback) → web (1 live) → endpoints (1402) → vulns (2 findings) → secrets (11 findings) → screenshots (1 captured)
    - Port module Nmap fallback worked correctly when Naabu was unavailable
    - All 3 report formats generated (HTML, JSON, Markdown)
    - Total scan time: 6m37s
    
    ### Cross-System Comparison
    
    | Metric                    | System 1 (21-school.ru) | System 2 (scanme.nmap.org) |
    |---------------------------|-------------------------|----------------------------|
    | Installer version         | Old (3 methods)         | New (9 methods)            |
    | Tools pre-installed       | 11                      | 3                          |
    | Tools auto-installed      | 0                       | 13                         |
    | Required tool failures    | 4                       | 2 (Naabu, Nuclei)         |
    | httpx working             | ❌ Python version       | ✅ Auto-resolved           |
    | Live web servers found    | 0 (httpx broken)        | 1 ✅                       |
    | Port scanning             | Silent no-op            | Nmap fallback worked ✅    |
    | Screenshots               | ❌ gowitness missing     | ✅ 1 captured              |
    | Pipeline starvation       | Modules starved          | All modules fed ✅          |
    | Reports generated         | ✅ All 3                | ✅ All 3                   |
    
    ### Issues that appeared on BOTH systems
    - Nuclei fails to install (go install OOM/timeout, GitHub Release extraction issue)
    - apt packages fail on some systems (exit status 100)
    - Findomain GitHub Release asset pattern doesn't match actual filenames
    - crt.sh parser is brittle (string splitting vs proper JSON parsing)
    
    ### Issues that appeared on System 1 ONLY (fixed by rewrite)
    - httpx Python conflict (FIXED: auto-detection + rename)
    - Port module silent no-op (FIXED: Nmap fallback)
    - Installer had no GitHub Release method (FIXED: full downloader added)
    - No install failure logging (FIXED: warns on each attempt)
    
    ### Issues that appeared on System 2 ONLY
    - libpcap-dev unavailable via apt (broken apt sources on that system)
    - Naabu GitHub Release binary downloaded but may need libpcap.so at runtime
    - trufflehog GitHub Release downloaded but didn't install (extraction/PATH issue)
    - Nuclei GitHub Release downloaded v3.7.1 but binary didn't reach /usr/local/bin
    
    ## Known Issues Still Open
    1. Naabu fails to install — requires libpcap-dev which fails via apt on some systems. GitHub Release binary may also need libpcap.so at runtime. Need to add libpcap runtime detection or static binary download
    2. Nuclei GitHub Release downloads but binary doesn't end up in PATH — needs debugging in findAndInstallBinary() or the zip extraction logic. Worked for gowitness but not nuclei
    3. Findomain GitHub Release asset pattern "linux_amd64" doesn't match actual release filenames — need to check Findomain's actual release naming convention on their GitHub releases page
    4. trufflehog GitHub Release downloaded but didn't install — same extraction/PATH issue as Nuclei potentially
    5. crt.sh found 0 subdomains for scanme.nmap.org and only 1 for 21-school.ru — the JSON string-splitting parser is brittle, should use encoding/json proper parsing
    6. Zone transfer check (dns.go) considers any AXFR response >100 bytes as successful — could produce false positives on System 1, should validate actual zone records
    7. Zone transfers are not gated behind PassiveOnly flag — they are active techniques
    8. No Shodan/Censys/VirusTotal API integration yet despite CLI flags existing
    9. apt-get install fails with exit status 100 on some systems — installer should handle this more gracefully, perhaps checking apt sources validity first
    
    ## What Has Been Fixed So Far
    - httpx Python vs ProjectDiscovery conflict: RESOLVED (auto-detection + rename + reinstall)
    - Port module silent no-op when Naabu missing: RESOLVED (Nmap top-1000 fallback added)
    - Installer only had 3 install methods: RESOLVED (expanded to 9 methods with GitHub Release downloader)
    - Installer didn't log failure reasons: RESOLVED (warns on each failed attempt with method name)
    - Installer didn't run apt-get update: RESOLVED
    - No build dependency installation: RESOLVED (libpcap-dev, unzip, curl, git checked first)
    - No SecLists installation: RESOLVED (auto-installs via apt or git clone)
    - DNS module silently skipped when dnsx missing: RESOLVED (now logs skip message)
    - gowitness installation: RESOLVED (GitHub Release fallback works)
    
    The full source code for all files is pushed to the repository. Please review the repo code against this context, compare the cross-system test results, reevaluate the current state of the tool, and help me continue development — focus on fixing the remaining known issues listed above.
