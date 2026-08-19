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

# Resume an interrupted scan

    ./reconstorm -d example.com -o ./recon-example.com -resume

# Scan several domains in parallel (thread budget is split across them)

    ./reconstorm -dL targets.txt -domain-concurrency 3 -t 90

# Exclude noisy nuclei template tags (default: run all tags)

    ./reconstorm -d example.com -nuclei-exclude-tags ssl,dns

### 4) Flags

| Flag | Description |
|------|-------------|
| `-d` | Target domain |
| `-dL` | File containing a list of domains |
| `-o` | Output directory |
| `-t` | Threads (global budget; split across parallel domains) |
| `-domain-concurrency` | Domains to scan in parallel with `-dL` (default 1) |
| `-passive` | Passive only — no active packets toward the target |
| `-modules` | Comma-separated modules to run (subdomains,dns,ports,web,endpoints,vulns,secrets,screenshots) |
| `-nuclei-exclude-tags` | Comma-separated nuclei tags to exclude (default: none) |
| `-resume` | Resume a previous scan from its state.json |
| `-timeout` | Global scan timeout |

> Note: reports redact discovered secrets to the last 4 characters. The full
> value is kept only in the local `state.json`, so a shared report never carries
> live credentials.
