package scanner

import (
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

type SecretsModule struct {
    cfg   *config.Config
    state *state.Manager
    log   *logger.Logger
}

func NewSecretsModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *SecretsModule {
    return &SecretsModule{cfg: cfg, state: sm, log: log}
}

func (m *SecretsModule) Name() string { return "secrets" }

func (m *SecretsModule) Run(ctx context.Context, domain string) error {
    outDir := filepath.Join(m.cfg.OutputDir, domain, "secrets")
    os.MkdirAll(outDir, 0755)

    // ── ffuf — Directory/File Fuzzing ──
    liveURLsFile := filepath.Join(m.cfg.OutputDir, domain, "web", "live_urls.txt")
    if _, err := os.Stat(liveURLsFile); err == nil {
        if _, err := exec.LookPath("ffuf"); err == nil {
            m.runFfuf(ctx, domain, outDir, liveURLsFile)
        }
    }

    // ── Search JS files for secrets ──
    jsFile := filepath.Join(m.cfg.OutputDir, domain, "endpoints", "js_files.txt")
    if _, err := os.Stat(jsFile); err == nil {
        m.scanJSFiles(ctx, domain, outDir, jsFile)
    }

    return nil
}

func (m *SecretsModule) runFfuf(ctx context.Context, domain string, outDir string, urlsFile string) {
    m.log.Info("  Running ffuf content discovery...")

    urls := readLines(urlsFile)
    wordlist := "/usr/share/seclists/Discovery/Web-Content/common.txt"

    fallbacks := []string{
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    }

    if _, err := os.Stat(wordlist); os.IsNotExist(err) {
        for _, fb := range fallbacks {
            if _, err := os.Stat(fb); err == nil {
                wordlist = fb
                break
            }
        }
    }

    if _, err := os.Stat(wordlist); os.IsNotExist(err) {
        m.log.Warn("  No wordlist found, skipping ffuf. Install seclists.")
        return
    }

    maxURLs := 20
    if len(urls) < maxURLs {
        maxURLs = len(urls)
    }

    for i, baseURL := range urls[:maxURLs] {
        m.log.Progress("ffuf", i+1, maxURLs)

        outFile := filepath.Join(outDir, fmt.Sprintf("ffuf_%d.json", i))
        cmd := exec.CommandContext(ctx, "ffuf",
            "-u", baseURL+"/FUZZ",
            "-w", wordlist,
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-ac",
            "-sf",
            "-se",
            "-t", fmt.Sprintf("%d", m.cfg.Threads/2),
            "-rate", "100",
            "-o", outFile,
            "-of", "json",
            "-s",
        )
        cmd.Run()
    }

    m.log.Info("  Merging ffuf results...")
    secretCount := 0
    for i := 0; i < maxURLs; i++ {
        outFile := filepath.Join(outDir, fmt.Sprintf("ffuf_%d.json", i))
        lines := readLines(outFile)
        secretCount += len(lines)
    }

    m.state.UpdateStats(func(s *state.ScanStats) {
        s.TotalSecrets += secretCount
    })
}

func (m *SecretsModule) scanJSFiles(ctx context.Context, domain string, outDir string, jsFile string) {
    m.log.Info("  Scanning JS files for secrets...")

    jsURLs := readLines(jsFile)
    secretsFile := filepath.Join(outDir, "js_secrets.txt")
    f, err := os.Create(secretsFile)
    if err != nil {
        return
    }
    defer f.Close()

    patterns := []string{
        `(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"\x60]([^'"\x60\s]{16,})`,
        `(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*['"\x60]([^'"\x60\s]{16,})`,
        `(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['"\x60]([A-Z0-9]{20})`,
        `(?i)(secret[_-]?key|private[_-]?key)\s*[:=]\s*['"\x60]([^'"\x60\s]{16,})`,
        `(?i)(password|passwd|pwd)\s*[:=]\s*['"\x60]([^'"\x60\s]{6,})`,
        `(?i)(firebase|supabase|mongodb\+srv)://[^\s'"]+`,
        `(?i)(sk-[a-zA-Z0-9]{20,})`,
        `(?i)(ghp_[a-zA-Z0-9]{36})`,
        `(?i)(AIza[0-9A-Za-z\-_]{35})`,
        `(?i)(AKIA[0-9A-Z]{16})`,
        `(?i)(xox[baprs]-[0-9a-zA-Z]{10,})`,
    }

    secretCount := 0
    for _, jsURL := range jsURLs {
        cmd := exec.CommandContext(ctx, "curl", "-s", "-L", "--max-time", "10", jsURL)
        content, err := cmd.Output()
        if err != nil {
            continue
        }

        for _, pattern := range patterns {
            grepCmd := exec.CommandContext(ctx, "grep", "-oP", pattern)
            grepCmd.Stdin = strings.NewReader(string(content))
            matches, err := grepCmd.Output()
            if err == nil && len(matches) > 0 {
                line := fmt.Sprintf("[%s] %s\n", jsURL, strings.TrimSpace(string(matches)))
                f.WriteString(line)

                m.state.AddFinding(state.Finding{
                    Type:     "secret",
                    Value:    strings.TrimSpace(string(matches)),
                    Source:   "js_analysis",
                    Domain:   domain,
                    Severity: "high",
                    Metadata: map[string]string{"file": jsURL},
                })
                secretCount++
            }
        }
    }

    m.state.UpdateStats(func(s *state.ScanStats) {
        s.TotalSecrets += secretCount
    })

    m.log.Success("  Found %d potential secrets in JS files", secretCount)
}
