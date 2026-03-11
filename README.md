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

    go build -ldflags="-s -w" -o reconstorm .

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
