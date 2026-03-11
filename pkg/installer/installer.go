package installer

import (
    "fmt"
    "os"
    "os/exec"
    "runtime"
    "strings"

    "github.com/H3llKa1ser/recon-storm/pkg/logger"
)

type Tool struct {
    Name        string
    Binary      string
    InstallCmds []string
    Required    bool
    Category    string
}

type Installer struct {
    log   *logger.Logger
    tools []Tool
}

func New(log *logger.Logger) *Installer {
    goInstall := "go install -v %s@latest"

    return &Installer{
        log: log,
        tools: []Tool{
            // ── Subdomain Enumeration ──
            {
                Name:     "Subfinder",
                Binary:   "subfinder",
                Category: "subdomain",
                Required: true,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
                },
            },
            {
                Name:     "Amass",
                Binary:   "amass",
                Category: "subdomain",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/owasp-amass/amass/v4/..."),
                    "apt-get install -y amass",
                    "brew install amass",
                },
            },
            {
                Name:     "Assetfinder",
                Binary:   "assetfinder",
                Category: "subdomain",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/tomnomnom/assetfinder"),
                },
            },
            {
                Name:     "Findomain",
                Binary:   "findomain",
                Category: "subdomain",
                Required: false,
                InstallCmds: []string{
                    "apt-get install -y findomain",
                    "brew install findomain",
                },
            },
            {
                Name:     "Shuffledns",
                Binary:   "shuffledns",
                Category: "subdomain",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/projectdiscovery/shuffledns/cmd/shuffledns"),
                },
            },

            // ── DNS ──
            {
                Name:     "dnsx",
                Binary:   "dnsx",
                Category: "dns",
                Required: true,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/projectdiscovery/dnsx/cmd/dnsx"),
                },
            },
            {
                Name:     "MassDNS",
                Binary:   "massdns",
                Category: "dns",
                Required: false,
                InstallCmds: []string{
                    "apt-get install -y massdns",
                    "brew install massdns",
                },
            },

            // ── Port Scanning ──
            {
                Name:     "Naabu",
                Binary:   "naabu",
                Category: "ports",
                Required: true,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/projectdiscovery/naabu/v2/cmd/naabu"),
                },
            },
            {
                Name:     "Nmap",
                Binary:   "nmap",
                Category: "ports",
                Required: false,
                InstallCmds: []string{
                    "apt-get install -y nmap",
                    "brew install nmap",
                },
            },

            // ── Web Probing ──
            {
                Name:     "httpx",
                Binary:   "httpx",
                Category: "web",
                Required: true,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/projectdiscovery/httpx/cmd/httpx"),
                },
            },
            {
                Name:     "httprobe",
                Binary:   "httprobe",
                Category: "web",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/tomnomnom/httprobe"),
                },
            },

            // ── Endpoint Discovery ──
            {
                Name:     "katana",
                Binary:   "katana",
                Category: "endpoints",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/projectdiscovery/katana/cmd/katana"),
                },
            },
            {
                Name:     "waybackurls",
                Binary:   "waybackurls",
                Category: "endpoints",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/tomnomnom/waybackurls"),
                },
            },
            {
                Name:     "gau",
                Binary:   "gau",
                Category: "endpoints",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/lc/gau/v2/cmd/gau"),
                },
            },
            {
                Name:     "GoSpider",
                Binary:   "gospider",
                Category: "endpoints",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/jaeles-project/gospider"),
                },
            },
            {
                Name:     "hakrawler",
                Binary:   "hakrawler",
                Category: "endpoints",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/hakluke/hakrawler"),
                },
            },

            // ── Vulnerability Scanning ──
            {
                Name:     "Nuclei",
                Binary:   "nuclei",
                Category: "vulns",
                Required: true,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
                },
            },

            // ── Secrets / Sensitive Files ──
            {
                Name:     "ffuf",
                Binary:   "ffuf",
                Category: "secrets",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/ffuf/ffuf/v2"),
                },
            },
            {
                Name:     "trufflehog",
                Binary:   "trufflehog",
                Category: "secrets",
                Required: false,
                InstallCmds: []string{
                    "pip3 install trufflehog",
                    "brew install trufflehog",
                },
            },

            // ── Screenshots ──
            {
                Name:     "gowitness",
                Binary:   "gowitness",
                Category: "screenshots",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/sensepost/gowitness"),
                },
            },

            // ── Utility ──
            {
                Name:     "anew",
                Binary:   "anew",
                Category: "utility",
                Required: false,
                InstallCmds: []string{
                    fmt.Sprintf(goInstall, "github.com/tomnomnom/anew"),
                },
            },
            {
                Name:     "jq",
                Binary:   "jq",
                Category: "utility",
                Required: false,
                InstallCmds: []string{
                    "apt-get install -y jq",
                    "brew install jq",
                },
            },
        },
    }
}

// CheckAndInstall verifies each tool and attempts installation if missing
func (i *Installer) CheckAndInstall() error {
    i.log.Info("Checking %d tools across all categories...", len(i.tools))

    // Check Go installation first
    if !i.commandExists("go") {
        i.log.Error("Go is not installed! Most tools require Go. Install from https://go.dev/dl/")
        return fmt.Errorf("go is not installed")
    }

    // Ensure GOPATH/bin is in PATH
    i.ensureGoPath()

    var missing []string
    var installed []string
    var failed []string

    for _, tool := range i.tools {
        if i.commandExists(tool.Binary) {
            i.log.Success("  ✓ %s (%s) — found", tool.Name, tool.Binary)
            continue
        }

        i.log.Warn("  ✗ %s (%s) — not found, attempting install...", tool.Name, tool.Binary)
        installOK := false

        for _, cmd := range tool.InstallCmds {
            i.log.Debug("    Trying: %s", cmd)
            if err := i.runCommand(cmd); err == nil {
                if i.commandExists(tool.Binary) {
                    i.log.Success("    ✓ Successfully installed %s", tool.Name)
                    installed = append(installed, tool.Name)
                    installOK = true
                    break
                }
            }
        }

        if !installOK {
            if tool.Required {
                i.log.Error("    ✗ FAILED to install required tool: %s", tool.Name)
                failed = append(failed, tool.Name)
            } else {
                i.log.Warn("    ✗ Could not install %s (optional, continuing)", tool.Name)
                missing = append(missing, tool.Name)
            }
        }
    }

    // Update nuclei templates if nuclei is available
    if i.commandExists("nuclei") {
        i.log.Info("Updating Nuclei templates...")
        i.runCommand("nuclei -update-templates")
    }

    // Summary
    i.log.Info("─── Installation Summary ───")
    i.log.Info("  Already installed:  %d tools", len(i.tools)-len(installed)-len(missing)-len(failed))
    i.log.Info("  Newly installed:    %d tools", len(installed))
    i.log.Info("  Optional missing:   %d tools", len(missing))
    i.log.Info("  Required failures:  %d tools", len(failed))

    if len(failed) > 0 {
        return fmt.Errorf("failed to install required tools: %s", strings.Join(failed, ", "))
    }
    return nil
}

func (i *Installer) commandExists(name string) bool {
    _, err := exec.LookPath(name)
    return err == nil
}

func (i *Installer) runCommand(command string) error {
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd", "/C", command)
    } else {
        cmd = exec.Command("bash", "-c", command)
    }

    cmd.Env = os.Environ()

    output, err := cmd.CombinedOutput()
    if err != nil {
        i.log.Debug("    Command failed: %v — %s", err, string(output))
        return err
    }
    return nil
}

func (i *Installer) ensureGoPath() {
    home, _ := os.UserHomeDir()
    goBin := home + "/go/bin"

    path := os.Getenv("PATH")
    if !strings.Contains(path, goBin) {
        os.Setenv("PATH", goBin+":"+path)
        i.log.Debug("Added %s to PATH", goBin)
    }
}
