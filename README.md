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
    
    The framework is fully built with the following structure and files:
    
    recon-storm/
    ├── go.mod                          # module github.com/H3llKa1ser/recon-storm
    ├── main.go                         # Entry point, CLI flags, signal handling, panic recovery, global timeout watchdog
    ├── pkg/
    │   ├── config/config.go            # Config struct, domain resolution, module/API key checks
    │   ├── installer/installer.go      # Auto-checks and installs 25+ tools (subfinder, amass, naabu, httpx, nuclei, ffuf, etc.)
    │   ├── logger/logger.go            # Thread-safe colored console + file logger with progress bars
    │   ├── state/state.go              # Persistent state manager: findings, module results, stats, auto-save every 30s, atomic JSON writes, crash recovery
    │   ├── scanner/
    │   │   ├── scanner.go              # Orchestrator: runs modules sequentially per domain, per-module timeout & panic recovery, resume support
    │   │   ├── subdomain.go            # Concurrent: subfinder, amass, assetfinder, findomain, crt.sh → deduplicated all_subdomains.txt
    │   │   ├── dns.go                  # dnsx resolution, zone transfer attempts via dig
    │   │   ├── port.go                 # naabu fast scan → nmap service detection on discovered ports
    │   │   ├── web.go                  # httpx probing with tech detection, CDN, JARM, favicon hash
    │   │   ├── endpoints.go            # Concurrent: waybackurls, gau, katana, gospider → categorized (JS, API, params, sensitive)
    │   │   ├── vuln.go                 # nuclei scanner + custom sensitive path checks via httpx
    │   │   ├── secrets.go              # ffuf content discovery + JS file regex scanning for API keys/tokens
    │   │   └── screenshots.go          # gowitness visual recon
    │   └── reporter/reporter.go        # Generates HTML (dark theme, styled), JSON, and Markdown reports
    
    Key design decisions:
    - All modules implement Module interface: Name() string, Run(ctx context.Context, domain string) error
    - State is saved atomically (write .tmp → rename) every 30 seconds + on every module completion
    - Emergency report generation on: SIGINT, SIGTERM, SIGHUP, panic, global timeout
    - Resume mode (-resume flag) skips modules already marked StatusCompleted in state.json
    - No external Go dependencies — only stdlib. External recon tools are called via os/exec
    - All imports use: github.com/H3llKa1ser/recon-storm/pkg/...
    
    The full source code for all files is already pushed to the repository.
    Please review the repo and help me continue development from here.
