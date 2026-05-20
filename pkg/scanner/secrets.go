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

    // ── ffuf content discovery ──
    liveURLsFile := filepath.Join(m.cfg.OutputDir, domain, "web", "live_urls.txt")
    if fileExists(liveURLsFile) && toolExists("ffuf") {
        m.runFfuf(ctx, domain, outDir, liveURLsFile)
    } else if !toolExists("ffuf") {
        m.log.Warn("  ffuf not found, skipping content discovery")
    }

    // ── JS file secret scanning ──
    jsFile := filepath.Join(m.cfg.OutputDir, domain, "endpoints", "js_files.txt")
    if fileExists(jsFile) {
        m.scanJSFiles(ctx, domain, outDir, jsFile)
    } else {
        m.log.Info("  No JS files to scan for secrets")
    }

    return nil
}

func (m *SecretsModule) runFfuf(ctx context.Context, domain, outDir, urlsFile string) {
    m.log.Info("  Running ffuf content discovery...")

    urls := readLines(urlsFile)
    if len(urls) == 0 {
        m.log.Warn("  No live URLs for ffuf")
        return
    }

    // Find wordlist
    wordlist := ""
    candidates := []string{
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    }
    for _, wl := range candidates {
        if fileExistsAny(wl) {
            wordlist = wl
            break
        }
    }
    if wordlist == "" {
        m.log.Warn("  No wordlist found — install seclists: sudo apt install seclists")
        return
    }

    m.log.Info("  Fuzzing %d target URLs with wordlist %s", len(urls), filepath.Base(wordlist))

    // Limit targets
    maxURLs := 20
    if len(urls) < maxURLs {
        maxURLs = len(urls)
    }

    totalFindings := 0

    for i, baseURL := range urls[:maxURLs] {
        m.log.Progress("ffuf", i+1, maxURLs)

        baseURL = strings.TrimRight(baseURL, "/")
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

        // Count results in this JSON
        if fileExists(outFile) {
            lines := readLines(outFile)
            count := 0
            for _, l := range lines {
                if strings.Contains(l, "\"status\"") {
                    count++
                }
            }
            if count > 0 {
                m.log.Info("  ffuf found %d results for %s", count, baseURL)
                totalFindings += count
            }
        }
    }

    m.state.UpdateStats(func(s *state.ScanStats) {
        s.TotalSecrets += totalFindings
    })

    m.log.Success("  ffuf content discovery complete: %d findings across %d targets", totalFindings, maxURLs)
}

func (m *SecretsModule) scanJSFiles(ctx context.Context, domain, outDir, jsFile string) {
    m.log.Info("  Scanning JS files for secrets...")

    jsURLs := readLines(jsFile)
    if len(jsURLs) == 0 {
        return
    }

    // Limit to prevent excessive scanning
    maxJS := 100
    if len(jsURLs) < maxJS {
        maxJS = len(jsURLs)
    }
    jsURLs = jsURLs[:maxJS]

    m.log.Info("  Downloading and scanning %d JS files...", len(jsURLs))

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
        `(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})`,
        `(?i)(sq0[a-z]{3}-[0-9A-Za-z\-_]{22,})`,
        `(?i)(SK[a-f0-9]{32})`,
    }

    secretCount := 0

    for _, jsURL := range jsURLs {
        // Download JS file
        dlCmd := exec.CommandContext(ctx, "curl", "-s", "-L", "--max-time", "10",
            "-H", "User-Agent: Mozilla/5.0 (ReconStorm/2.0)", jsURL)
        content, err := dlCmd.Output()
        if err != nil || len(content) == 0 {
            continue
        }

        contentStr := string(content)

        for _, pattern := range patterns {
            grepCmd := exec.CommandContext(ctx, "grep", "-oP", pattern)
            grepCmd.Stdin = strings.NewReader(contentStr)
            matches, err := grepCmd.Output()
            if err == nil && len(matches) > 0 {
                for _, match := range strings.Split(strings.TrimSpace(string(matches)), "\n") {
                    match = strings.TrimSpace(match)
                    if match == "" {
                        continue
                    }

                    line := fmt.Sprintf("[%s] %s\n", jsURL, match)
                    f.WriteString(line)

                    m.state.AddFinding(state.Finding{
                        Type: "secret", Value: match,
                        Source: "js_analysis", Domain: domain, Severity: "high",
                        Metadata: map[string]string{"file": jsURL, "pattern": pattern},
                    })
                    secretCount++
                }
            }
        }
    }

    m.state.UpdateStats(func(s *state.ScanStats) {
        s.TotalSecrets += secretCount
    })

    m.log.Success("  Found %d potential secrets in JS files", secretCount)
}
