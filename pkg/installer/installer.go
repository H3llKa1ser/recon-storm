package installer

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strings"
    "time"

    "github.com/H3llKa1ser/recon-storm/pkg/logger"
)

// ── Install Method Types ────────────────────────────────

type InstallMethod int

const (
    MethodGoInstall      InstallMethod = iota // go install ...@latest
    MethodApt                                 // sudo apt-get install -y ...
    MethodGitHubRelease                       // Download binary from GitHub Releases
    MethodGitCloneMake                        // git clone + make + sudo make install
    MethodCargoInstall                        // cargo install ...
    MethodPipInstall                          // pip3 install ...
    MethodBrew                                // brew install ...
    MethodSnap                                // sudo snap install ...
    MethodCustomScript                        // Custom bash commands
)

// InstallStep represents one installation attempt
type InstallStep struct {
    Method  InstallMethod
    Command string // for MethodGoInstall, MethodApt, MethodBrew, MethodPipInstall, MethodCargoInstall, MethodSnap

    // For MethodGitHubRelease
    GHRepo     string // e.g., "projectdiscovery/nuclei"
    GHAsset    string // substring to match in asset name, e.g., "linux_amd64"
    GHAssetExt string // "zip", "tar.gz", or "" for raw binary
    GHBinary   string // binary name inside the archive (if different from tool binary)

    // For MethodGitCloneMake
    GitURL     string   // e.g., "https://github.com/blechschmidt/massdns.git"
    BuildCmds  []string // commands to run after clone, e.g., ["make", "sudo make install"]

    // For MethodCustomScript
    Script []string // list of bash commands to execute in order
}

type Tool struct {
    Name         string
    Binary       string
    Category     string
    Required     bool
    InstallSteps []InstallStep
}

type Installer struct {
    log       *logger.Logger
    tools     []Tool
    arch      string
    osName    string
    aptReady  bool
}

func New(log *logger.Logger) *Installer {
    // Detect system architecture
    arch := runtime.GOARCH
    osName := runtime.GOOS

    // Map Go arch names to common release naming conventions
    archMap := map[string]string{
        "amd64": "amd64",
        "arm64": "arm64",
        "arm":   "armv6",
        "386":   "386",
    }
    if mapped, ok := archMap[arch]; ok {
        arch = mapped
    }

    inst := &Installer{
        log:    log,
        arch:   arch,
        osName: osName,
    }

    inst.tools = inst.defineTools()
    return inst
}

func (i *Installer) defineTools() []Tool {
    goInstallCmd := func(pkg string) InstallStep {
        return InstallStep{
            Method:  MethodGoInstall,
            Command: fmt.Sprintf("go install -v %s@latest", pkg),
        }
    }

    aptInstall := func(pkg string) InstallStep {
        return InstallStep{
            Method:  MethodApt,
            Command: fmt.Sprintf("sudo apt-get install -y %s", pkg),
        }
    }

    brewInstall := func(pkg string) InstallStep {
        return InstallStep{
            Method:  MethodBrew,
            Command: fmt.Sprintf("brew install %s", pkg),
        }
    }

    ghRelease := func(repo, assetPattern, ext, binaryName string) InstallStep {
        return InstallStep{
            Method:     MethodGitHubRelease,
            GHRepo:     repo,
            GHAsset:    assetPattern,
            GHAssetExt: ext,
            GHBinary:   binaryName,
        }
    }

    gitClone := func(url string, cmds []string) InstallStep {
        return InstallStep{
            Method:    MethodGitCloneMake,
            GitURL:    url,
            BuildCmds: cmds,
        }
    }

    pipInstall := func(pkg string) InstallStep {
        return InstallStep{
            Method:  MethodPipInstall,
            Command: fmt.Sprintf("pip3 install %s", pkg),
        }
    }

    cargoInstall := func(pkg string) InstallStep {
        return InstallStep{
            Method:  MethodCargoInstall,
            Command: fmt.Sprintf("cargo install %s", pkg),
        }
    }

    return []Tool{
        // ── Subdomain Enumeration ────────────────────────
        {
            Name:     "Subfinder",
            Binary:   "subfinder",
            Category: "subdomain",
            Required: true,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
                ghRelease("projectdiscovery/subfinder", fmt.Sprintf("linux_%s", i.arch), "zip", "subfinder"),
            },
        },
        {
            Name:     "Amass",
            Binary:   "amass",
            Category: "subdomain",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/owasp-amass/amass/v4/..."),
                ghRelease("owasp-amass/amass", fmt.Sprintf("linux_%s", i.arch), "zip", "amass"),
                aptInstall("amass"),
                brewInstall("amass"),
            },
        },
        {
            Name:     "Assetfinder",
            Binary:   "assetfinder",
            Category: "subdomain",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/tomnomnom/assetfinder"),
            },
        },
        {
            Name:     "Findomain",
            Binary:   "findomain",
            Category: "subdomain",
            Required: false,
            InstallSteps: []InstallStep{
                ghRelease("Findomain/Findomain", fmt.Sprintf("linux_%s", i.arch), "", "findomain"),
                cargoInstall("findomain"),
                InstallStep{
                    Method: MethodCustomScript,
                    Script: []string{
                        fmt.Sprintf("curl -sL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-%s.zip -o /tmp/findomain.zip", i.arch),
                        "unzip -o /tmp/findomain.zip -d /tmp/findomain_extract",
                        "chmod +x /tmp/findomain_extract/findomain",
                        "sudo mv /tmp/findomain_extract/findomain /usr/local/bin/",
                        "rm -rf /tmp/findomain.zip /tmp/findomain_extract",
                    },
                },
                brewInstall("findomain"),
            },
        },
        {
            Name:     "Shuffledns",
            Binary:   "shuffledns",
            Category: "subdomain",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/projectdiscovery/shuffledns/cmd/shuffledns"),
                ghRelease("projectdiscovery/shuffledns", fmt.Sprintf("linux_%s", i.arch), "zip", "shuffledns"),
            },
        },

        // ── DNS ──────────────────────────────────────────
        {
            Name:     "dnsx",
            Binary:   "dnsx",
            Category: "dns",
            Required: true,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/projectdiscovery/dnsx/cmd/dnsx"),
                ghRelease("projectdiscovery/dnsx", fmt.Sprintf("linux_%s", i.arch), "zip", "dnsx"),
            },
        },
        {
            Name:     "MassDNS",
            Binary:   "massdns",
            Category: "dns",
            Required: false,
            InstallSteps: []InstallStep{
                aptInstall("massdns"),
                gitClone("https://github.com/blechschmidt/massdns.git", []string{
                    "make",
                    "sudo make install",
                }),
                brewInstall("massdns"),
            },
        },

        // ── Port Scanning ────────────────────────────────
        {
            Name:     "Naabu",
            Binary:   "naabu",
            Category: "ports",
            Required: true,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/projectdiscovery/naabu/v2/cmd/naabu"),
                ghRelease("projectdiscovery/naabu", fmt.Sprintf("linux_%s", i.arch), "zip", "naabu"),
                InstallStep{
                    Method: MethodCustomScript,
                    Script: []string{
                        "sudo apt-get install -y libpcap-dev",
                    },
                },
            },
        },
        {
            Name:     "Nmap",
            Binary:   "nmap",
            Category: "ports",
            Required: false,
            InstallSteps: []InstallStep{
                aptInstall("nmap"),
                brewInstall("nmap"),
            },
        },

        // ── Web Probing ──────────────────────────────────
        {
            Name:     "httpx-pd",
            Binary:   "httpx",
            Category: "web",
            Required: true,
            InstallSteps: []InstallStep{
                // ProjectDiscovery httpx — must verify it's not the Python one
                goInstallCmd("github.com/projectdiscovery/httpx/cmd/httpx"),
                ghRelease("projectdiscovery/httpx", fmt.Sprintf("linux_%s", i.arch), "zip", "httpx"),
            },
        },
        {
            Name:     "httprobe",
            Binary:   "httprobe",
            Category: "web",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/tomnomnom/httprobe"),
            },
        },

        // ── Endpoint Discovery ───────────────────────────
        {
            Name:     "katana",
            Binary:   "katana",
            Category: "endpoints",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/projectdiscovery/katana/cmd/katana"),
                ghRelease("projectdiscovery/katana", fmt.Sprintf("linux_%s", i.arch), "zip", "katana"),
            },
        },
        {
            Name:     "waybackurls",
            Binary:   "waybackurls",
            Category: "endpoints",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/tomnomnom/waybackurls"),
            },
        },
        {
            Name:     "gau",
            Binary:   "gau",
            Category: "endpoints",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/lc/gau/v2/cmd/gau"),
                ghRelease("lc/gau", fmt.Sprintf("linux_%s", i.arch), "tar.gz", "gau"),
            },
        },
        {
            Name:     "GoSpider",
            Binary:   "gospider",
            Category: "endpoints",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/jaeles-project/gospider"),
            },
        },
        {
            Name:     "hakrawler",
            Binary:   "hakrawler",
            Category: "endpoints",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/hakluke/hakrawler"),
            },
        },

        // ── Vulnerability Scanning ───────────────────────
        {
            Name:     "Nuclei",
            Binary:   "nuclei",
            Category: "vulns",
            Required: true,
            InstallSteps: []InstallStep{
                ghRelease("projectdiscovery/nuclei", fmt.Sprintf("linux_%s", i.arch), "zip", "nuclei"),
                goInstallCmd("github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
            },
        },

        // ── Secrets / Fuzzing ────────────────────────────
        {
            Name:     "ffuf",
            Binary:   "ffuf",
            Category: "secrets",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/ffuf/ffuf/v2"),
                ghRelease("ffuf/ffuf", fmt.Sprintf("linux_%s", i.arch), "tar.gz", "ffuf"),
                aptInstall("ffuf"),
            },
        },
        {
            Name:     "trufflehog",
            Binary:   "trufflehog",
            Category: "secrets",
            Required: false,
            InstallSteps: []InstallStep{
                ghRelease("trufflesecurity/trufflehog", fmt.Sprintf("linux_%s", i.arch), "tar.gz", "trufflehog"),
                pipInstall("trufflehog"),
                brewInstall("trufflehog"),
            },
        },

        // ── Screenshots ──────────────────────────────────
        {
            Name:     "gowitness",
            Binary:   "gowitness",
            Category: "screenshots",
            Required: false,
            InstallSteps: []InstallStep{
                ghRelease("sensepost/gowitness", fmt.Sprintf("linux-%s", i.arch), "", "gowitness"),
                goInstallCmd("github.com/sensepost/gowitness"),
                InstallStep{
                    Method: MethodCustomScript,
                    Script: []string{
                        fmt.Sprintf("curl -sL $(curl -s https://api.github.com/repos/sensepost/gowitness/releases/latest | grep browser_download_url | grep linux-%s | head -1 | cut -d '\"' -f4) -o /tmp/gowitness", i.arch),
                        "chmod +x /tmp/gowitness",
                        "sudo mv /tmp/gowitness /usr/local/bin/",
                    },
                },
            },
        },

        // ── Utility ──────────────────────────────────────
        {
            Name:     "anew",
            Binary:   "anew",
            Category: "utility",
            Required: false,
            InstallSteps: []InstallStep{
                goInstallCmd("github.com/tomnomnom/anew"),
            },
        },
        {
            Name:     "jq",
            Binary:   "jq",
            Category: "utility",
            Required: false,
            InstallSteps: []InstallStep{
                aptInstall("jq"),
                brewInstall("jq"),
            },
        },

        // ── Build Dependencies (installed first) ─────────
        {
            Name:     "libpcap-dev",
            Binary:   "",
            Category: "build-dep",
            Required: false,
            InstallSteps: []InstallStep{
                aptInstall("libpcap-dev"),
            },
        },
        {
            Name:     "unzip",
            Binary:   "unzip",
            Category: "build-dep",
            Required: false,
            InstallSteps: []InstallStep{
                aptInstall("unzip"),
            },
        },
        {
            Name:     "curl",
            Binary:   "curl",
            Category: "build-dep",
            Required: true,
            InstallSteps: []InstallStep{
                aptInstall("curl"),
            },
        },
        {
            Name:     "git",
            Binary:   "git",
            Category: "build-dep",
            Required: true,
            InstallSteps: []InstallStep{
                aptInstall("git"),
            },
        },
    }
}

// ── Main Entry Point ────────────────────────────────────

func (i *Installer) CheckAndInstall() error {
    i.log.Info("Checking %d tools across all categories...", len(i.tools))
    i.log.Info("System: %s/%s", i.osName, i.arch)

    // ── Phase 0: Verify Go is installed ──
    if !i.commandExists("go") {
        i.log.Error("Go is not installed! Install from https://go.dev/dl/")
        return fmt.Errorf("go is not installed")
    }
    goVer, _ := i.getCommandOutput("go", "version")
    i.log.Info("Go version: %s", strings.TrimSpace(goVer))

    // Ensure GOPATH/bin is in PATH
    i.ensureGoPath()

    // ── Phase 1: Refresh package lists ──
    if i.osName == "linux" {
        i.log.Info("Refreshing package lists (sudo apt-get update)...")
        if err := i.runCommand("sudo apt-get update -qq"); err != nil {
            i.log.Warn("apt-get update failed — apt installs may not work: %v", err)
        } else {
            i.aptReady = true
        }
    }

    // ── Phase 2: Install build dependencies first ──
    i.log.Info("Checking build dependencies...")
    for _, tool := range i.tools {
        if tool.Category != "build-dep" {
            continue
        }
        if tool.Binary != "" && i.commandExists(tool.Binary) {
            i.log.Success("  ✓ %s — found", tool.Name)
            continue
        }
        // For library packages (no binary), check via dpkg
        if tool.Binary == "" {
            if i.dpkgInstalled(tool.Name) {
                i.log.Success("  ✓ %s — found", tool.Name)
                continue
            }
        }
        i.log.Warn("  ✗ %s — installing...", tool.Name)
        i.tryInstall(tool)
    }

    // ── Phase 3: Handle httpx binary conflict ──
    i.resolveHttpxConflict()

    // ── Phase 4: Install all recon tools ──
    var installed []string
    var missing []string
    var failed []string

    for _, tool := range i.tools {
        if tool.Category == "build-dep" {
            continue // already handled
        }

        // Special handling for httpx (already resolved in Phase 3)
        if tool.Name == "httpx-pd" {
            if i.isProjectDiscoveryHttpx() {
                i.log.Success("  ✓ %s (%s) — found (projectdiscovery)", tool.Name, tool.Binary)
                continue
            }
        } else if i.commandExists(tool.Binary) {
            i.log.Success("  ✓ %s (%s) — found", tool.Name, tool.Binary)
            continue
        }

        i.log.Warn("  ✗ %s (%s) — not found, attempting install...", tool.Name, tool.Binary)

        if i.tryInstall(tool) {
            installed = append(installed, tool.Name)
        } else {
            if tool.Required {
                i.log.Error("    ✗ FAILED to install required tool: %s", tool.Name)
                failed = append(failed, tool.Name)
            } else {
                i.log.Warn("    ✗ Could not install %s (optional, continuing)", tool.Name)
                missing = append(missing, tool.Name)
            }
        }
    }

    // ── Phase 5: Post-install setup ──
    if i.commandExists("nuclei") {
        i.log.Info("Updating Nuclei templates...")
        i.runCommand("nuclei -update-templates")
    }

    // Install SecLists wordlists if not present
    i.installWordlists()

    // ── Summary ──
    alreadyInstalled := len(i.tools) - len(installed) - len(missing) - len(failed)
    // Subtract build-dep count for accurate reporting
    buildDepCount := 0
    for _, t := range i.tools {
        if t.Category == "build-dep" {
            buildDepCount++
        }
    }
    alreadyInstalled -= buildDepCount

    i.log.Info("─── Installation Summary ───")
    i.log.Info("  Already installed:  %d tools", alreadyInstalled)
    i.log.Info("  Newly installed:    %d tools", len(installed))
    i.log.Info("  Optional missing:   %d tools", len(missing))
    i.log.Info("  Required failures:  %d tools", len(failed))

    if len(failed) > 0 {
        return fmt.Errorf("failed to install required tools: %s", strings.Join(failed, ", "))
    }
    return nil
}

// ── Installation Methods ────────────────────────────────

func (i *Installer) tryInstall(tool Tool) bool {
    for _, step := range tool.InstallSteps {
        i.log.Debug("    Trying method: %v", step.Method)

        var success bool
        switch step.Method {
        case MethodGoInstall:
            success = i.installViaGo(step.Command, tool.Binary)
        case MethodApt:
            success = i.installViaApt(step.Command, tool.Binary)
        case MethodGitHubRelease:
            success = i.installViaGitHubRelease(step, tool.Binary)
        case MethodGitCloneMake:
            success = i.installViaGitClone(step, tool.Binary)
        case MethodCargoInstall:
            success = i.installViaCargo(step.Command, tool.Binary)
        case MethodPipInstall:
            success = i.installViaPip(step.Command, tool.Binary)
        case MethodBrew:
            success = i.installViaBrew(step.Command, tool.Binary)
        case MethodSnap:
            success = i.installViaSnap(step.Command, tool.Binary)
        case MethodCustomScript:
            success = i.installViaScript(step.Script, tool.Binary)
        }

        if success {
            i.log.Success("    ✓ Successfully installed %s", tool.Name)
            return true
        }
    }
    return false
}

func (i *Installer) installViaGo(command string, binary string) bool {
    if !i.commandExists("go") {
        return false
    }
    err := i.runCommand(command)
    if err != nil {
        i.log.Warn("    Install attempt failed: %s — %v", command, err)
        return false
    }
    return binary == "" || i.commandExists(binary)
}

func (i *Installer) installViaApt(command string, binary string) bool {
    if i.osName != "linux" {
        return false
    }
    err := i.runCommand(command)
    if err != nil {
        i.log.Warn("    Install attempt failed: %s — %v", command, err)
        return false
    }
    // For library packages (binary == ""), check dpkg
    if binary == "" {
        return true
    }
    return i.commandExists(binary)
}

func (i *Installer) installViaBrew(command string, binary string) bool {
    if !i.commandExists("brew") {
        return false
    }
    err := i.runCommand(command)
    if err != nil {
        i.log.Warn("    Install attempt failed: %s — %v", command, err)
        return false
    }
    return binary == "" || i.commandExists(binary)
}

func (i *Installer) installViaCargo(command string, binary string) bool {
    if !i.commandExists("cargo") {
        i.log.Debug("    cargo not found, skipping Rust install")
        return false
    }
    err := i.runCommand(command)
    if err != nil {
        i.log.Warn("    Install attempt failed: %s — %v", command, err)
        return false
    }
    return binary == "" || i.commandExists(binary)
}

func (i *Installer) installViaPip(command string, binary string) bool {
    if !i.commandExists("pip3") {
        i.log.Debug("    pip3 not found, skipping Python install")
        return false
    }
    err := i.runCommand(command)
    if err != nil {
        i.log.Warn("    Install attempt failed: %s — %v", command, err)
        return false
    }
    return binary == "" || i.commandExists(binary)
}

func (i *Installer) installViaSnap(command string, binary string) bool {
    if !i.commandExists("snap") {
        return false
    }
    err := i.runCommand(command)
    if err != nil {
        i.log.Warn("    Install attempt failed: %s — %v", command, err)
        return false
    }
    return binary == "" || i.commandExists(binary)
}

func (i *Installer) installViaScript(script []string, binary string) bool {
    for _, cmd := range script {
        if err := i.runCommand(cmd); err != nil {
            i.log.Warn("    Script step failed: %s — %v", cmd, err)
            return false
        }
    }
    return binary == "" || i.commandExists(binary)
}

// ── GitHub Release Downloader ───────────────────────────

type ghAsset struct {
    Name               string `json:"name"`
    BrowserDownloadURL string `json:"browser_download_url"`
}

type ghRelease struct {
    TagName string    `json:"tag_name"`
    Assets  []ghAsset `json:"assets"`
}

func (i *Installer) installViaGitHubRelease(step InstallStep, binary string) bool {
    i.log.Debug("    Downloading from GitHub Releases: %s", step.GHRepo)

    // Fetch latest release info from GitHub API
    apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", step.GHRepo)

    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Get(apiURL)
    if err != nil {
        i.log.Warn("    GitHub API request failed: %v", err)
        return false
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        i.log.Warn("    GitHub API returned status %d for %s", resp.StatusCode, step.GHRepo)
        return false
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        i.log.Warn("    Failed to read GitHub API response: %v", err)
        return false
    }

    var release ghRelease
    if err := json.Unmarshal(body, &release); err != nil {
        i.log.Warn("    Failed to parse GitHub release JSON: %v", err)
        return false
    }

    // Find matching asset
    var downloadURL string
    assetPattern := strings.ToLower(step.GHAsset)

    for _, asset := range release.Assets {
        name := strings.ToLower(asset.Name)
        // Match the asset pattern (e.g., "linux_amd64") and extension
        if strings.Contains(name, assetPattern) {
            // If extension specified, match it too
            if step.GHAssetExt != "" {
                if strings.HasSuffix(name, "."+step.GHAssetExt) {
                    downloadURL = asset.BrowserDownloadURL
                    i.log.Debug("    Matched asset: %s", asset.Name)
                    break
                }
            } else {
                // No extension specified — prefer the raw binary (no .zip/.tar.gz)
                if !strings.HasSuffix(name, ".zip") &&
                    !strings.HasSuffix(name, ".tar.gz") &&
                    !strings.HasSuffix(name, ".txt") &&
                    !strings.HasSuffix(name, ".sha256") {
                    downloadURL = asset.BrowserDownloadURL
                    i.log.Debug("    Matched asset: %s", asset.Name)
                    break
                }
            }
        }
    }

    if downloadURL == "" {
        i.log.Warn("    No matching asset found for pattern '%s' in %s (release: %s)",
            step.GHAsset, step.GHRepo, release.TagName)
        i.log.Debug("    Available assets:")
        for _, a := range release.Assets {
            i.log.Debug("      - %s", a.Name)
        }
        return false
    }

    i.log.Info("    Downloading %s %s...", step.GHRepo, release.TagName)

    // Download the asset
    tmpDir := "/tmp/reconstorm_install"
    os.MkdirAll(tmpDir, 0755)
    defer os.RemoveAll(tmpDir)

    downloadPath := filepath.Join(tmpDir, "download")
    if err := i.downloadFile(downloadURL, downloadPath); err != nil {
        i.log.Warn("    Download failed: %v", err)
        return false
    }

    // Determine the binary name inside the archive
    binaryName := binary
    if step.GHBinary != "" {
        binaryName = step.GHBinary
    }

    installDir := "/usr/local/bin"

    // Handle based on extension
    switch step.GHAssetExt {
    case "zip":
        return i.extractZip(downloadPath, tmpDir, binaryName, installDir)
    case "tar.gz":
        return i.extractTarGz(downloadPath, tmpDir, binaryName, installDir)
    case "":
        // Raw binary — just move it
        destPath := filepath.Join(installDir, binaryName)
        if err := i.runCommand(fmt.Sprintf("chmod +x %s && sudo mv %s %s", downloadPath, downloadPath, destPath)); err != nil {
            i.log.Warn("    Failed to install binary: %v", err)
            return false
        }
        return i.commandExists(binary)
    default:
        i.log.Warn("    Unknown asset extension: %s", step.GHAssetExt)
        return false
    }
}

func (i *Installer) downloadFile(url string, destPath string) error {
    client := &http.Client{
        Timeout: 5 * time.Minute,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return nil // follow redirects
        },
    }

    resp, err := client.Get(url)
    if err != nil {
        return fmt.Errorf("HTTP GET failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return fmt.Errorf("HTTP %d", resp.StatusCode)
    }

    out, err := os.Create(destPath)
    if err != nil {
        return fmt.Errorf("cannot create file: %w", err)
    }
    defer out.Close()

    written, err := io.Copy(out, resp.Body)
    if err != nil {
        return fmt.Errorf("download interrupted: %w", err)
    }

    i.log.Debug("    Downloaded %d bytes", written)
    return nil
}

func (i *Installer) extractZip(zipPath, tmpDir, binaryName, installDir string) bool {
    extractDir := filepath.Join(tmpDir, "extracted")
    os.MkdirAll(extractDir, 0755)

    if err := i.runCommand(fmt.Sprintf("unzip -o %s -d %s", zipPath, extractDir)); err != nil {
        i.log.Warn("    Unzip failed: %v", err)
        return false
    }

    return i.findAndInstallBinary(extractDir, binaryName, installDir)
}

func (i *Installer) extractTarGz(tarPath, tmpDir, binaryName, installDir string) bool {
    extractDir := filepath.Join(tmpDir, "extracted")
    os.MkdirAll(extractDir, 0755)

    if err := i.runCommand(fmt.Sprintf("tar -xzf %s -C %s", tarPath, extractDir)); err != nil {
        i.log.Warn("    Tar extraction failed: %v", err)
        return false
    }

    return i.findAndInstallBinary(extractDir, binaryName, installDir)
}

func (i *Installer) findAndInstallBinary(searchDir, binaryName, installDir string) bool {
    // Search recursively for the binary
    var binaryPath string

    filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        if !info.IsDir() && info.Name() == binaryName {
            binaryPath = path
            return filepath.SkipAll
        }
        return nil
    })

    if binaryPath == "" {
        i.log.Warn("    Binary '%s' not found in extracted archive", binaryName)
        // List what was extracted for debugging
        filepath.Walk(searchDir, func(path string, info os.FileInfo, err error) error {
            if err == nil && !info.IsDir() {
                i.log.Debug("      Found file: %s", path)
            }
            return nil
        })
        return false
    }

    destPath := filepath.Join(installDir, binaryName)
    cmd := fmt.Sprintf("chmod +x %s && sudo mv %s %s", binaryPath, binaryPath, destPath)
    if err := i.runCommand(cmd); err != nil {
        i.log.Warn("    Failed to install %s to %s: %v", binaryName, installDir, err)
        return false
    }

    return i.commandExists(binaryName)
}

// ── Git Clone + Build ───────────────────────────────────

func (i *Installer) installViaGitClone(step InstallStep, binary string) bool {
    if !i.commandExists("git") {
        i.log.Debug("    git not found, skipping clone install")
        return false
    }

    tmpDir := "/tmp/reconstorm_build"
    os.RemoveAll(tmpDir)

    // Clone
    i.log.Debug("    Cloning %s...", step.GitURL)
    if err := i.runCommand(fmt.Sprintf("git clone --depth 1 %s %s", step.GitURL, tmpDir)); err != nil {
        i.log.Warn("    Git clone failed: %v", err)
        return false
    }
    defer os.RemoveAll(tmpDir)

    // Run build commands
    for _, cmd := range step.BuildCmds {
        fullCmd := fmt.Sprintf("cd %s && %s", tmpDir, cmd)
        if err := i.runCommand(fullCmd); err != nil {
            i.log.Warn("    Build step failed: %s — %v", cmd, err)
            return false
        }
    }

    return binary == "" || i.commandExists(binary)
}

// ── httpx Conflict Resolution ───────────────────────────

func (i *Installer) resolveHttpxConflict() {
    i.log.Info("Checking httpx binary (Python vs ProjectDiscovery)...")

    if !i.commandExists("httpx") {
        i.log.Debug("  httpx not found at all, will install fresh")
        return
    }

    if i.isProjectDiscoveryHttpx() {
        i.log.Success("  ✓ httpx is ProjectDiscovery version — no conflict")
        return
    }

    // It's the Python httpx — we need to resolve
    i.log.Warn("  ⚠ Detected Python httpx — resolving conflict...")

    pythonPath, _ := exec.LookPath("httpx")
    i.log.Warn("  Python httpx location: %s", pythonPath)

    // Strategy 1: Rename the Python binary
    if pythonPath != "" {
        newName := pythonPath + "-py"
        err := i.runCommand(fmt.Sprintf("sudo mv %s %s", pythonPath, newName))
        if err != nil {
            i.log.Warn("  Could not rename Python httpx: %v", err)
            // Strategy 2: Try to remove the apt package
            i.runCommand("sudo apt-get remove -y python3-httpx 2>/dev/null")
        } else {
            i.log.Success("  Renamed Python httpx to %s", newName)
        }
    }

    // Install ProjectDiscovery httpx
    i.log.Info("  Installing ProjectDiscovery httpx...")

    // Try go install first
    if i.commandExists("go") {
        if err := i.runCommand("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"); err == nil {
            if i.isProjectDiscoveryHttpx() {
                i.log.Success("  ✓ ProjectDiscovery httpx installed via go install")
                return
            }
        }
    }

    // Fallback to GitHub Release
    step := InstallStep{
        Method:     MethodGitHubRelease,
        GHRepo:     "projectdiscovery/httpx",
        GHAsset:    fmt.Sprintf("linux_%s", i.arch),
        GHAssetExt: "zip",
        GHBinary:   "httpx",
    }
    if i.installViaGitHubRelease(step, "httpx") {
        if i.isProjectDiscoveryHttpx() {
            i.log.Success("  ✓ ProjectDiscovery httpx installed via GitHub Release")
            return
        }
    }

    i.log.Error("  ✗ Failed to resolve httpx conflict — web probing may not work")
}

func (i *Installer) isProjectDiscoveryHttpx() bool {
    // ProjectDiscovery httpx responds to -version with "Current Version: ..."
    // or contains "projectdiscovery" in its output
    output, err := i.getCommandOutput("httpx", "-version")
    if err != nil {
        // Also try with just the binary — some versions output to stderr
        output, err = i.getCommandOutputStderr("httpx", "-version")
        if err != nil {
            return false
        }
    }

    lower := strings.ToLower(output)
    return strings.Contains(lower, "projectdiscovery") ||
        strings.Contains(lower, "current version") ||
        strings.Contains(lower, "pd") ||
        strings.Contains(lower, "-list") // help text contains -list flag
}

// ── Wordlist Installation ───────────────────────────────

func (i *Installer) installWordlists() {
    seclistsPath := "/usr/share/seclists"
    if _, err := os.Stat(seclistsPath); err == nil {
        i.log.Success("  ✓ SecLists wordlists found at %s", seclistsPath)
        return
    }

    // Try alternative locations
    altPaths := []string{
        "/usr/share/wordlists/seclists",
        "/opt/seclists",
    }
    for _, p := range altPaths {
        if _, err := os.Stat(p); err == nil {
            i.log.Success("  ✓ SecLists found at %s", p)
            return
        }
    }

    i.log.Info("  Installing SecLists wordlists...")

    // Try apt first
    if i.aptReady {
        if err := i.runCommand("sudo apt-get install -y seclists"); err == nil {
            i.log.Success("  ✓ SecLists installed via apt")
            return
        }
    }

    // Fallback: clone from GitHub (shallow)
    i.log.Info("  Cloning SecLists from GitHub (this may take a while)...")
    if err := i.runCommand(fmt.Sprintf("sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git %s", seclistsPath)); err != nil {
        i.log.Warn("  Could not install SecLists: %v", err)
        i.log.Warn("  Fuzzing modules may have limited wordlists")
    } else {
        i.log.Success("  ✓ SecLists installed to %s", seclistsPath)
    }
}

// ── Utility Functions ───────────────────────────────────

func (i *Installer) commandExists(name string) bool {
    _, err := exec.LookPath(name)
    return err == nil
}

func (i *Installer) dpkgInstalled(pkg string) bool {
    err := i.runCommand(fmt.Sprintf("dpkg -s %s 2>/dev/null | grep -q 'Status: install ok installed'", pkg))
    return err == nil
}

func (i *Installer) runCommand(command string) error {
    var cmd *exec.Cmd
    if i.osName == "windows" {
        cmd = exec.Command("cmd", "/C", command)
    } else {
        cmd = exec.Command("bash", "-c", command)
    }

    cmd.Env = os.Environ()

    output, err := cmd.CombinedOutput()
    if err != nil {
        i.log.Debug("    Command output: %s", strings.TrimSpace(string(output)))
        return fmt.Errorf("%v", err)
    }
    return nil
}

func (i *Installer) getCommandOutput(name string, args ...string) (string, error) {
    cmd := exec.Command(name, args...)
    output, err := cmd.Output()
    return string(output), err
}

func (i *Installer) getCommandOutputStderr(name string, args ...string) (string, error) {
    cmd := exec.Command(name, args...)
    output, err := cmd.CombinedOutput()
    return string(output), err
}

func (i *Installer) ensureGoPath() {
    home, _ := os.UserHomeDir()
    goPaths := []string{
        filepath.Join(home, "go", "bin"),
        "/usr/local/go/bin",
    }

    path := os.Getenv("PATH")
    modified := false

    for _, gp := range goPaths {
        if !strings.Contains(path, gp) {
            path = gp + ":" + path
            modified = true
        }
    }

    if modified {
        os.Setenv("PATH", path)
        i.log.Debug("  Updated PATH to include Go binary directories")
    }
}
