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

type InstallMethod int

const (
    MethodGoInstall InstallMethod = iota
    MethodApt
    MethodGitHubRelease
    MethodGitCloneMake
    MethodCargoInstall
    MethodPipInstall
    MethodBrew
    MethodCustomScript
)

type InstallStep struct {
    Method     InstallMethod
    Command    string
    GHRepo     string
    GHAsset    string
    GHAssetExt string
    GHBinary   string
    GitURL     string
    BuildCmds  []string
    Script     []string
}

type Tool struct {
    Name         string
    Binary       string
    Category     string
    Required     bool
    InstallSteps []InstallStep
}

type Installer struct {
    log   *logger.Logger
    tools []Tool
    arch  string
    os    string
}

func New(log *logger.Logger) *Installer {
    i := &Installer{
        log:  log,
        arch: runtime.GOARCH,
        os:   runtime.GOOS,
    }
    i.tools = i.defineTools()
    return i
}

func (i *Installer) goCmd(pkg string) InstallStep {
    return InstallStep{Method: MethodGoInstall, Command: fmt.Sprintf("go install -v %s@latest", pkg)}
}

func (i *Installer) apt(pkg string) InstallStep {
    return InstallStep{Method: MethodApt, Command: fmt.Sprintf("sudo apt-get install -y %s", pkg)}
}

func (i *Installer) brew(pkg string) InstallStep {
    return InstallStep{Method: MethodBrew, Command: fmt.Sprintf("brew install %s", pkg)}
}

func (i *Installer) gh(repo, asset, ext, bin string) InstallStep {
    return InstallStep{Method: MethodGitHubRelease, GHRepo: repo, GHAsset: asset, GHAssetExt: ext, GHBinary: bin}
}

func (i *Installer) gitClone(url string, cmds []string) InstallStep {
    return InstallStep{Method: MethodGitCloneMake, GitURL: url, BuildCmds: cmds}
}

func (i *Installer) script(cmds []string) InstallStep {
    return InstallStep{Method: MethodCustomScript, Script: cmds}
}

func (i *Installer) defineTools() []Tool {
    a := i.arch // amd64, arm64, etc.
    linuxArch := fmt.Sprintf("linux_%s", a)

    return []Tool{
        // ── Build Dependencies ──
        {Name: "curl", Binary: "curl", Category: "build-dep", Required: true, InstallSteps: []InstallStep{i.apt("curl")}},
        {Name: "git", Binary: "git", Category: "build-dep", Required: true, InstallSteps: []InstallStep{i.apt("git")}},
        {Name: "unzip", Binary: "unzip", Category: "build-dep", Required: false, InstallSteps: []InstallStep{i.apt("unzip")}},
        {Name: "jq", Binary: "jq", Category: "build-dep", Required: false, InstallSteps: []InstallStep{i.apt("jq")}},
        {Name: "dig", Binary: "dig", Category: "build-dep", Required: false, InstallSteps: []InstallStep{i.apt("dnsutils")}},
        {Name: "libpcap-dev", Binary: "", Category: "build-dep", Required: false, InstallSteps: []InstallStep{i.apt("libpcap-dev")}},
        {Name: "chromium", Binary: "chromium", Category: "build-dep", Required: false, InstallSteps: []InstallStep{
            i.apt("chromium"),
            i.apt("chromium-browser"),
        }},

        // ── Subdomain Enumeration ──
        {Name: "Subfinder", Binary: "subfinder", Category: "subdomain", Required: true, InstallSteps: []InstallStep{
            i.goCmd("github.com/projectdiscovery/subfinder/v2/cmd/subfinder"),
            i.gh("projectdiscovery/subfinder", linuxArch, "zip", "subfinder"),
        }},
        {Name: "Amass", Binary: "amass", Category: "subdomain", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/owasp-amass/amass/v4/..."),
            i.gh("owasp-amass/amass", linuxArch, "zip", "amass"),
            i.apt("amass"),
        }},
        {Name: "Assetfinder", Binary: "assetfinder", Category: "subdomain", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/tomnomnom/assetfinder"),
        }},
        {Name: "Findomain", Binary: "findomain", Category: "subdomain", Required: false, InstallSteps: []InstallStep{
            i.gh("Findomain/Findomain", "linux", "", "findomain"),
            i.script([]string{
                "curl -sL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -o /tmp/findomain.zip",
                "unzip -o /tmp/findomain.zip -d /tmp/findomain_ex",
                "chmod +x /tmp/findomain_ex/findomain",
                "sudo mv /tmp/findomain_ex/findomain /usr/local/bin/",
                "rm -rf /tmp/findomain.zip /tmp/findomain_ex",
            }),
        }},

        // ── DNS ──
        {Name: "dnsx", Binary: "dnsx", Category: "dns", Required: true, InstallSteps: []InstallStep{
            i.goCmd("github.com/projectdiscovery/dnsx/cmd/dnsx"),
            i.gh("projectdiscovery/dnsx", linuxArch, "zip", "dnsx"),
        }},
        {Name: "MassDNS", Binary: "massdns", Category: "dns", Required: false, InstallSteps: []InstallStep{
            i.apt("massdns"),
            i.gitClone("https://github.com/blechschmidt/massdns.git", []string{"make", "sudo cp bin/massdns /usr/local/bin/"}),
        }},

        // ── Port Scanning ──
        {Name: "Naabu", Binary: "naabu", Category: "ports", Required: false, InstallSteps: []InstallStep{
            i.gh("projectdiscovery/naabu", linuxArch, "zip", "naabu"),
            i.goCmd("github.com/projectdiscovery/naabu/v2/cmd/naabu"),
        }},
        {Name: "Nmap", Binary: "nmap", Category: "ports", Required: true, InstallSteps: []InstallStep{
            i.apt("nmap"),
        }},

        // ── Web Probing ──
        {Name: "httpx-pd", Binary: "httpx", Category: "web", Required: true, InstallSteps: []InstallStep{
            i.goCmd("github.com/projectdiscovery/httpx/cmd/httpx"),
            i.gh("projectdiscovery/httpx", linuxArch, "zip", "httpx"),
        }},
        {Name: "httprobe", Binary: "httprobe", Category: "web", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/tomnomnom/httprobe"),
        }},

        // ── Endpoint Discovery ──
        {Name: "katana", Binary: "katana", Category: "endpoints", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/projectdiscovery/katana/cmd/katana"),
            i.gh("projectdiscovery/katana", linuxArch, "zip", "katana"),
        }},
        {Name: "waybackurls", Binary: "waybackurls", Category: "endpoints", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/tomnomnom/waybackurls"),
        }},
        {Name: "gau", Binary: "gau", Category: "endpoints", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/lc/gau/v2/cmd/gau"),
            i.gh("lc/gau", linuxArch, "tar.gz", "gau"),
        }},
        {Name: "GoSpider", Binary: "gospider", Category: "endpoints", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/jaeles-project/gospider"),
        }},
        {Name: "hakrawler", Binary: "hakrawler", Category: "endpoints", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/hakluke/hakrawler"),
        }},

        // ── Vulnerability Scanning ──
        {Name: "Nuclei", Binary: "nuclei", Category: "vulns", Required: true, InstallSteps: []InstallStep{
            i.gh("projectdiscovery/nuclei", linuxArch, "zip", "nuclei"),
            i.goCmd("github.com/projectdiscovery/nuclei/v3/cmd/nuclei"),
        }},

        // ── Fuzzing / Secrets ──
        {Name: "ffuf", Binary: "ffuf", Category: "secrets", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/ffuf/ffuf/v2"),
            i.gh("ffuf/ffuf", linuxArch, "tar.gz", "ffuf"),
            i.apt("ffuf"),
        }},

        // ── Screenshots ──
        {Name: "gowitness", Binary: "gowitness", Category: "screenshots", Required: false, InstallSteps: []InstallStep{
            i.gh("sensepost/gowitness", fmt.Sprintf("linux-%s", a), "", "gowitness"),
            i.goCmd("github.com/sensepost/gowitness"),
        }},

        // ── Utility ──
        {Name: "anew", Binary: "anew", Category: "utility", Required: false, InstallSteps: []InstallStep{
            i.goCmd("github.com/tomnomnom/anew"),
        }},
    }
}

func (i *Installer) CheckAndInstall() error {
    i.log.Info("Checking %d tools (%s/%s)...", len(i.tools), i.os, i.arch)

    if !i.commandExists("go") {
        i.log.Error("Go not installed — https://go.dev/dl/")
        return fmt.Errorf("go not installed")
    }
    goVer, _ := i.cmdOutput("go", "version")
    i.log.Info("Go: %s", strings.TrimSpace(goVer))
    i.ensureGoPath()

    // Phase 1: apt update
    if i.os == "linux" {
        i.log.Info("Updating package lists...")
        if err := i.run("sudo apt-get update -qq 2>/dev/null"); err != nil {
            i.log.Warn("apt-get update failed: %v", err)
        }
    }

    // Phase 2: Build deps
    i.log.Info("Checking build dependencies...")
    for _, t := range i.tools {
        if t.Category != "build-dep" {
            continue
        }
        if t.Binary != "" && i.commandExists(t.Binary) {
            i.log.Success("  ✓ %s", t.Name)
            continue
        }
        if t.Binary == "" && i.dpkgInstalled(t.Name) {
            i.log.Success("  ✓ %s", t.Name)
            continue
        }
        i.log.Warn("  ✗ %s — installing...", t.Name)
        i.tryInstall(t)
    }

    // Phase 3: httpx conflict
    i.resolveHttpxConflict()

    // Phase 4: All recon tools
    var installed, missing, failed []string

    for _, t := range i.tools {
        if t.Category == "build-dep" {
            continue
        }
        if t.Name == "httpx-pd" {
            if i.isPDHttpx() {
                i.log.Success("  ✓ %s (%s) — projectdiscovery", t.Name, t.Binary)
                continue
            }
        } else if i.commandExists(t.Binary) {
            i.log.Success("  ✓ %s (%s)", t.Name, t.Binary)
            continue
        }

        i.log.Warn("  ✗ %s (%s) — installing...", t.Name, t.Binary)
        if i.tryInstall(t) {
            installed = append(installed, t.Name)
        } else if t.Required {
            i.log.Error("    ✗ FAILED required: %s", t.Name)
            failed = append(failed, t.Name)
        } else {
            i.log.Warn("    ✗ Optional missing: %s", t.Name)
            missing = append(missing, t.Name)
        }
    }

    // Phase 5: Post-install
    if i.commandExists("nuclei") {
        i.log.Info("Updating Nuclei templates...")
        i.run("nuclei -update-templates 2>/dev/null")
    }
    i.installSecLists()

    i.log.Info("─── Installation Summary ───")
    i.log.Info("  Newly installed: %d", len(installed))
    i.log.Info("  Optional missing: %d", len(missing))
    i.log.Info("  Required failures: %d", len(failed))

    if len(failed) > 0 {
        return fmt.Errorf("failed: %s", strings.Join(failed, ", "))
    }
    return nil
}

func (i *Installer) tryInstall(tool Tool) bool {
    for _, step := range tool.InstallSteps {
        var ok bool
        switch step.Method {
        case MethodGoInstall:
            ok = i.doGoInstall(step.Command, tool.Binary)
        case MethodApt:
            ok = i.doApt(step.Command, tool.Binary, tool.Name)
        case MethodGitHubRelease:
            ok = i.doGHRelease(step, tool.Binary)
        case MethodGitCloneMake:
            ok = i.doGitClone(step, tool.Binary)
        case MethodCargoInstall:
            ok = i.doRun(step.Command, tool.Binary, "cargo")
        case MethodPipInstall:
            ok = i.doRun(step.Command, tool.Binary, "pip3")
        case MethodBrew:
            ok = i.doRun(step.Command, tool.Binary, "brew")
        case MethodCustomScript:
            ok = i.doScript(step.Script, tool.Binary)
        }
        if ok {
            i.log.Success("    ✓ Installed %s", tool.Name)
            return true
        }
    }
    return false
}

func (i *Installer) doGoInstall(cmd, bin string) bool {
    if !i.commandExists("go") {
        return false
    }
    if err := i.run(cmd); err != nil {
        i.log.Warn("    go install failed: %v", err)
        return false
    }
    return bin == "" || i.commandExists(bin)
}

func (i *Installer) doApt(cmd, bin, name string) bool {
    if i.os != "linux" {
        return false
    }
    if err := i.run(cmd); err != nil {
        i.log.Warn("    apt failed: %s — %v", cmd, err)
        return false
    }
    if bin == "" {
        return i.dpkgInstalled(name)
    }
    return i.commandExists(bin)
}

func (i *Installer) doRun(cmd, bin, requires string) bool {
    if requires != "" && !i.commandExists(requires) {
        return false
    }
    if err := i.run(cmd); err != nil {
        i.log.Warn("    failed: %s — %v", cmd, err)
        return false
    }
    return bin == "" || i.commandExists(bin)
}

func (i *Installer) doScript(cmds []string, bin string) bool {
    for _, cmd := range cmds {
        if err := i.run(cmd); err != nil {
            i.log.Warn("    script failed: %s — %v", cmd, err)
            return false
        }
    }
    return bin == "" || i.commandExists(bin)
}

func (i *Installer) doGitClone(step InstallStep, bin string) bool {
    if !i.commandExists("git") {
        return false
    }
    tmpDir := "/tmp/reconstorm_build"
    os.RemoveAll(tmpDir)
    if err := i.run(fmt.Sprintf("git clone --depth 1 %s %s", step.GitURL, tmpDir)); err != nil {
        return false
    }
    defer os.RemoveAll(tmpDir)
    for _, cmd := range step.BuildCmds {
        if err := i.run(fmt.Sprintf("cd %s && %s", tmpDir, cmd)); err != nil {
            i.log.Warn("    build failed: %s — %v", cmd, err)
            return false
        }
    }
    return bin == "" || i.commandExists(bin)
}

// ── GitHub Release Downloader ───────────────────────────

type ghAssetInfo struct {
    Name string `json:"name"`
    URL  string `json:"browser_download_url"`
}
type ghReleaseInfo struct {
    Tag    string        `json:"tag_name"`
    Assets []ghAssetInfo `json:"assets"`
}

func (i *Installer) doGHRelease(step InstallStep, bin string) bool {
    apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", step.GHRepo)

    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Get(apiURL)
    if err != nil {
        i.log.Warn("    GH API error: %v", err)
        return false
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        i.log.Warn("    GH API status %d for %s", resp.StatusCode, step.GHRepo)
        return false
    }

    body, _ := io.ReadAll(resp.Body)
    var release ghReleaseInfo
    if err := json.Unmarshal(body, &release); err != nil {
        i.log.Warn("    GH JSON parse error: %v", err)
        return false
    }

    // Find matching asset
    var dlURL string
    pattern := strings.ToLower(step.GHAsset)

    for _, a := range release.Assets {
        name := strings.ToLower(a.Name)
        if !strings.Contains(name, pattern) {
            continue
        }
        // Skip checksums and signatures
        if strings.HasSuffix(name, ".sha256") || strings.HasSuffix(name, ".sig") || strings.HasSuffix(name, ".txt") {
            continue
        }
        if step.GHAssetExt != "" {
            if strings.HasSuffix(name, "."+step.GHAssetExt) {
                dlURL = a.URL
                break
            }
        } else {
            // Raw binary — skip archives
            if !strings.HasSuffix(name, ".zip") && !strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, ".deb") {
                dlURL = a.URL
                break
            }
        }
    }

    if dlURL == "" {
        i.log.Warn("    No matching asset for '%s' in %s %s", step.GHAsset, step.GHRepo, release.Tag)
        i.log.Debug("    Available assets:")
        for _, a := range release.Assets {
            i.log.Debug("      %s", a.Name)
        }
        return false
    }

    i.log.Info("    Downloading %s %s...", step.GHRepo, release.Tag)

    tmpDir := "/tmp/reconstorm_gh"
    os.MkdirAll(tmpDir, 0755)
    defer os.RemoveAll(tmpDir)

    dlPath := filepath.Join(tmpDir, "download")
    if err := i.download(dlURL, dlPath); err != nil {
        i.log.Warn("    Download failed: %v", err)
        return false
    }

    binaryName := bin
    if step.GHBinary != "" {
        binaryName = step.GHBinary
    }

    switch step.GHAssetExt {
    case "zip":
        return i.extractAndInstall("unzip -o %s -d %s", dlPath, tmpDir, binaryName)
    case "tar.gz":
        return i.extractAndInstall("tar -xzf %s -C %s", dlPath, tmpDir, binaryName)
    case "":
        dest := filepath.Join("/usr/local/bin", binaryName)
        if err := i.run(fmt.Sprintf("chmod +x %s && sudo mv %s %s", dlPath, dlPath, dest)); err != nil {
            return false
        }
        return i.commandExists(bin)
    }
    return false
}

func (i *Installer) extractAndInstall(extractFmt, dlPath, tmpDir, binaryName string) bool {
    extractDir := filepath.Join(tmpDir, "out")
    os.MkdirAll(extractDir, 0755)

    cmd := fmt.Sprintf(extractFmt, dlPath, extractDir)
    if err := i.run(cmd); err != nil {
        i.log.Warn("    Extract failed: %v", err)
        return false
    }

    // Find binary recursively
    var found string
    filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
        if err == nil && !info.IsDir() && info.Name() == binaryName {
            found = path
            return filepath.SkipAll
        }
        return nil
    })

    if found == "" {
        i.log.Warn("    Binary '%s' not found in archive", binaryName)
        filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
            if err == nil && !info.IsDir() {
                i.log.Debug("      file: %s (%d bytes)", info.Name(), info.Size())
            }
            return nil
        })
        return false
    }

    dest := filepath.Join("/usr/local/bin", binaryName)
    if err := i.run(fmt.Sprintf("chmod +x %s && sudo mv %s %s", found, found, dest)); err != nil {
        i.log.Warn("    Install to /usr/local/bin failed: %v", err)
        return false
    }
    return i.commandExists(binaryName)
}

func (i *Installer) download(url, dest string) error {
    client := &http.Client{Timeout: 5 * time.Minute}
    resp, err := client.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return fmt.Errorf("HTTP %d", resp.StatusCode)
    }
    f, err := os.Create(dest)
    if err != nil {
        return err
    }
    defer f.Close()
    _, err = io.Copy(f, resp.Body)
    return err
}

// ── httpx Conflict Resolution ───────────────────────────

func (i *Installer) resolveHttpxConflict() {
    i.log.Info("Checking httpx binary...")

    if !i.commandExists("httpx") {
        i.log.Debug("  httpx not found, will install fresh")
        return
    }

    if i.isPDHttpx() {
        i.log.Success("  ✓ httpx is ProjectDiscovery version")
        return
    }

    i.log.Warn("  ⚠ Python httpx detected — resolving...")

    pyPath, _ := exec.LookPath("httpx")
    if pyPath != "" {
        if err := i.run(fmt.Sprintf("sudo mv %s %s-py", pyPath, pyPath)); err != nil {
            i.log.Warn("  Rename failed, trying apt remove...")
            i.run("sudo apt-get remove -y python3-httpx 2>/dev/null")
        } else {
            i.log.Success("  Renamed %s → %s-py", pyPath, pyPath)
        }
    }

    // Install correct version
    if i.commandExists("go") {
        i.run("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        if i.isPDHttpx() {
            i.log.Success("  ✓ ProjectDiscovery httpx installed")
            return
        }
    }

    step := InstallStep{
        GHRepo: "projectdiscovery/httpx", GHAsset: fmt.Sprintf("linux_%s", i.arch),
        GHAssetExt: "zip", GHBinary: "httpx",
    }
    i.doGHRelease(step, "httpx")
}

func (i *Installer) isPDHttpx() bool {
    out, err := i.cmdOutputAll("httpx", "-version")
    if err != nil {
        return false
    }
    lower := strings.ToLower(out)
    return strings.Contains(lower, "projectdiscovery") || strings.Contains(lower, "current version")
}

func (i *Installer) installSecLists() {
    paths := []string{"/usr/share/seclists", "/usr/share/wordlists/seclists", "/opt/seclists"}
    for _, p := range paths {
        if _, err := os.Stat(p); err == nil {
            i.log.Success("  ✓ SecLists: %s", p)
            return
        }
    }
    i.log.Info("  Installing SecLists...")
    if err := i.run("sudo apt-get install -y seclists 2>/dev/null"); err == nil {
        return
    }
    i.run("sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists")
}

// ── Helpers ─────────────────────────────────────────────

func (i *Installer) commandExists(name string) bool {
    _, err := exec.LookPath(name)
    return err == nil
}

func (i *Installer) dpkgInstalled(pkg string) bool {
    return i.run(fmt.Sprintf("dpkg -s %s 2>/dev/null | grep -q 'install ok installed'", pkg)) == nil
}

func (i *Installer) run(command string) error {
    cmd := exec.Command("bash", "-c", command)
    cmd.Env = os.Environ()
    out, err := cmd.CombinedOutput()
    if err != nil {
        i.log.Debug("    cmd failed: %s — %s", command, strings.TrimSpace(string(out)))
    }
    return err
}

func (i *Installer) cmdOutput(name string, args ...string) (string, error) {
    out, err := exec.Command(name, args...).Output()
    return string(out), err
}

func (i *Installer) cmdOutputAll(name string, args ...string) (string, error) {
    out, err := exec.Command(name, args...).CombinedOutput()
    return string(out), err
}

func (i *Installer) ensureGoPath() {
    home, _ := os.UserHomeDir()
    paths := []string{filepath.Join(home, "go", "bin"), "/usr/local/go/bin"}
    p := os.Getenv("PATH")
    for _, gp := range paths {
        if !strings.Contains(p, gp) {
            p = gp + ":" + p
        }
    }
    os.Setenv("PATH", p)
}
