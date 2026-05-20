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

    # Install Python dependencies
    pip install shodan censys python-dotenv requests colorama pyyaml schedule
    
    # Check which tools are installed
    python3 recon_storm.py --check-tools
    
    # Print full installation guide
    python3 recon_storm.py --install-guide
    
    # Generate config file template
    python3 recon_storm.py --generate-config
    
    # Full scan against a target
    python3 recon_storm.py --target example.com
    
    # Run only stages 1, 2, 3
    python3 recon_storm.py --target example.com --stages 1,2,3
    
    # Full scan + continuous monitoring every 4 hours
    python3 recon_storm.py --target example.com --monitor --interval 4
    
    # Scan with custom config
    python3 recon_storm.py --target example.com --config recon_storm_config.yaml -v
    
    # Scan multiple targets from a file
    python3 recon_storm.py --target-list targets.txt
