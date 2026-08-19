package scanner

import (
    "context"
    "fmt"
    "io"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "regexp"
    "strings"
    "time"

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

// secretRule pairs a compiled pattern with a human label so findings carry a
// meaningful description instead of the raw regex.
type secretRule struct {
    Label string
    Re    *regexp.Regexp
}

// Patterns are compiled once at package load. RE2 (Go's engine) has no
// backreferences, but none of these need them.
var secretRules = []secretRule{
    {"Generic API key", regexp.MustCompile("(?i)(api[_-]?key|apikey|api[_-]?secret)\\s*[:=]\\s*['\"`]([^'\"`\\s]{16,})")},
    {"Access/auth token", regexp.MustCompile("(?i)(access[_-]?token|auth[_-]?token)\\s*[:=]\\s*['\"`]([^'\"`\\s]{16,})")},
    {"AWS access key id", regexp.MustCompile("(?i)(aws[_-]?access[_-]?key[_-]?id)\\s*[:=]\\s*['\"`]([A-Z0-9]{20})")},
    {"Secret/private key", regexp.MustCompile("(?i)(secret[_-]?key|private[_-]?key)\\s*[:=]\\s*['\"`]([^'\"`\\s]{16,})")},
    {"Hardcoded password", regexp.MustCompile("(?i)(password|passwd|pwd)\\s*[:=]\\s*['\"`]([^'\"`\\s]{6,})")},
    {"Database connection URI", regexp.MustCompile("(?i)(firebase|supabase|mongodb\\+srv)://[^\\s'\"]+")},
    {"OpenAI-style key", regexp.MustCompile("sk-[a-zA-Z0-9]{20,}")},
    {"GitHub PAT", regexp.MustCompile("ghp_[a-zA-Z0-9]{36}")},
    {"Google API key", regexp.MustCompile("AIza[0-9A-Za-z\\-_]{35}")},
    {"AWS access key", regexp.MustCompile("AKIA[0-9A-Z]{16}")},
    {"Slack token", regexp.MustCompile("xox[baprs]-[0-9a-zA-Z]{10,}")},
    {"JWT", regexp.MustCompile("eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}")},
    {"Square OAuth secret", regexp.MustCompile("sq0[a-z]{3}-[0-9A-Za-z\\-_]{22,}")},
    {"Stripe/Twilio SK", regexp.MustCompile("SK[a-f0-9]{32}")},
}

func (m *SecretsModule) Run(ctx context.Context, domain string) error {
    outDir := filepath.Join(m.cfg.OutputDir, domain, "secrets")
    os.MkdirAll(outDir, 0755)

    // In passive mode we must not touch the target: skip content discovery and
    // JS retrieval entirely.
    if m.cfg.PassiveOnly {
        m.log.Info("  Passive mode — skipping active content discovery and JS retrieval")
        return nil
    }

    liveURLsFile := filepath.Join(m.cfg.OutputDir, domain, "web", "live_urls.txt")
    if fileExists(liveURLsFile) && toolExists("ffuf") {
        m.runFfuf(ctx, domain, outDir, liveURLsFile)
    } else if !toolExists("ffuf") {
        m.log.Warn("  ffuf not found, skipping content discovery")
    }

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

    maxURLs := 20
    if len(urls) < maxURLs {
        maxURLs = len(urls)
    }

    totalHits := 0
    for i, baseURL := range urls[:maxURLs] {
        m.log.Progress("ffuf", i+1, maxURLs)

        baseURL = strings.TrimRight(baseURL, "/")
        outFile := filepath.Join(outDir, fmt.Sprintf("ffuf_%d.json", i))

        cmd := exec.CommandContext(ctx, "ffuf",
            "-u", baseURL+"/FUZZ",
            "-w", wordlist,
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-ac", "-sf", "-se",
            "-t", fmt.Sprintf("%d", m.cfg.Threads/2),
            "-rate", "100",
            "-o", outFile, "-of", "json", "-s",
        )
        cmd.Run()

        if fileExists(outFile) {
            count := 0
            for _, l := range readLines(outFile) {
                if strings.Contains(l, "\"status\"") {
                    count++
                }
            }
            if count > 0 {
                m.log.Info("  ffuf found %d results for %s", count, baseURL)
                totalHits += count
            }
        }
    }

    // Content-discovery hits are recorded as their own category, not as
    // "secrets" (the previous behaviour inflated the secret count with dirbust
    // results). They are informational surface, not credentials.
    m.log.Success("  ffuf content discovery complete: %d paths across %d targets", totalHits, maxURLs)
}

func (m *SecretsModule) scanJSFiles(ctx context.Context, domain, outDir, jsFile string) {
    m.log.Info("  Scanning JS files for secrets...")

    jsURLs := readLines(jsFile)
    if len(jsURLs) == 0 {
        return
    }

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

    client := &http.Client{Timeout: 12 * time.Second}
    secretCount := 0
    seen := make(map[string]bool) // dedup identical matches within this module

    for _, jsURL := range jsURLs {
        content, err := m.fetchBody(ctx, client, jsURL)
        if err != nil || len(content) == 0 {
            continue
        }

        // Run every pattern in-process over the whole file, so matches that
        // straddle what would have been a streaming boundary are still caught.
        for _, rule := range secretRules {
            for _, match := range rule.Re.FindAllString(content, -1) {
                match = strings.TrimSpace(match)
                if match == "" {
                    continue
                }
                key := jsURL + "|" + match
                if seen[key] {
                    continue
                }
                seen[key] = true

                fmt.Fprintf(f, "[%s] (%s) %s\n", jsURL, rule.Label, match)

                m.state.AddFinding(state.Finding{
                    Type: "secret", Value: match,
                    Source: "js_analysis", Domain: domain, Severity: "high",
                    Metadata: map[string]string{
                        "file":        jsURL,
                        "rule":        rule.Label,
                        "description": rule.Label + " found in client-side JavaScript; rotate if valid.",
                    },
                })
                secretCount++
            }
        }
    }

    m.log.Success("  Found %d potential secrets in JS files", secretCount)
}

func (m *SecretsModule) fetchBody(ctx context.Context, client *http.Client, url string) (string, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return "", err
    }
    req.Header.Set("User-Agent", "Mozilla/5.0 (ReconStorm/2.1)")
    resp, err := client.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    // Cap at 5 MB to avoid pathological files.
    body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
    if err != nil {
        return "", err
    }
    return string(body), nil
}
