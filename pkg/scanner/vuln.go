package scanner

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "strings"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

type VulnModule struct {
    cfg   *config.Config
    state *state.Manager
    log   *logger.Logger
}

func NewVulnModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *VulnModule {
    return &VulnModule{cfg: cfg, state: sm, log: log}
}

func (m *VulnModule) Name() string { return "vulns" }

func (m *VulnModule) Run(ctx context.Context, domain string) error {
    outDir := filepath.Join(m.cfg.OutputDir, domain, "vulns")
    os.MkdirAll(outDir, 0755)

    liveURLsFile := filepath.Join(m.cfg.OutputDir, domain, "web", "live_urls.txt")
    if !fileExists(liveURLsFile) {
        m.log.Warn("  No live URLs found — skipping vulnerability scan")
        return nil
    }

    urlCount := countFileLines(liveURLsFile)

    // ── Nuclei ──
    if toolExists("nuclei") {
        m.log.Info("  Running Nuclei on %d live URLs...", urlCount)

        nucleiOut := filepath.Join(outDir, "nuclei_results.txt")
        nucleiJSON := filepath.Join(outDir, "nuclei_results.jsonl")

        cmd := exec.CommandContext(ctx, "nuclei",
            "-l", liveURLsFile,
            "-severity", "info,low,medium,high,critical",
            "-c", fmt.Sprintf("%d", m.cfg.Threads),
            "-bs", "50",
            "-rl", "150",
            "-timeout", "10",
            "-retries", "2",
            "-o", nucleiOut,
            "-jsonl", nucleiJSON,
            "-silent",
            "-stats",
        )

        out, err := cmd.CombinedOutput()
        if err != nil {
            m.log.Warn("  Nuclei error: %v — %s", err, strings.TrimSpace(string(out)))
        }

        m.parseNucleiResults(nucleiJSON, domain)

        results := readLines(nucleiOut)
        m.log.Success("  Nuclei found %d potential vulnerabilities", len(results))
    } else {
        m.log.Warn("  Nuclei not found — install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    }

    // ── Custom sensitive path checks ──
    m.customChecks(ctx, domain, outDir, liveURLsFile)

    return nil
}

func (m *VulnModule) parseNucleiResults(jsonFile string, domain string) {
    lines := readLines(jsonFile)
    count := 0

    for _, line := range lines {
        var result map[string]interface{}
        if err := json.Unmarshal([]byte(line), &result); err != nil {
            continue
        }

        templateID, _ := result["template-id"].(string)
        severity, name := "", ""
        if info, ok := result["info"].(map[string]interface{}); ok {
            severity, _ = info["severity"].(string)
            name, _ = info["name"].(string)
        }
        matchedAt, _ := result["matched-at"].(string)
        matcherName, _ := result["matcher-name"].(string)

        m.state.AddFinding(state.Finding{
            Type:   "vulnerability",
            Value:  fmt.Sprintf("[%s] %s — %s", severity, name, matchedAt),
            Source: "nuclei", Domain: domain, Severity: severity,
            Metadata: map[string]string{
                "template_id": templateID, "name": name,
                "matched_at": matchedAt, "matcher_name": matcherName,
            },
        })
        count++
    }

    m.state.UpdateStats(func(s *state.ScanStats) {
        s.TotalVulns += count
    })
}

func (m *VulnModule) customChecks(ctx context.Context, domain, outDir, urlsFile string) {
    httpxBin, found := findHttpx(m.log)
    if !found {
        m.log.Warn("  httpx not found — skipping custom checks")
        return
    }

    urls := readLines(urlsFile)
    if len(urls) == 0 {
        return
    }

    sensitivePaths := []string{
        "/.env", "/.git/config", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
        "/.well-known/security.txt", "/server-status", "/server-info",
        "/.DS_Store", "/wp-config.php.bak", "/crossdomain.xml",
        "/clientaccesspolicy.xml", "/.htaccess", "/.htpasswd",
        "/web.config", "/phpinfo.php", "/info.php",
        "/actuator", "/actuator/env", "/actuator/health",
        "/swagger-ui.html", "/swagger/v1/swagger.json",
        "/api-docs", "/graphql", "/graphiql",
        "/.svn/entries", "/elmah.axd", "/trace.axd",
    }

    var checkURLs []string
    for _, base := range urls {
        base = strings.TrimRight(base, "/")
        for _, path := range sensitivePaths {
            checkURLs = append(checkURLs, base+path)
        }
    }

    m.log.Info("  Running custom security checks...")
    m.log.Info("  Checking %d sensitive paths across %d hosts...", len(sensitivePaths), len(urls))

    checkFile := filepath.Join(outDir, "custom_check_urls.txt")
    writeLines(checkFile, checkURLs)

    resultFile := filepath.Join(outDir, "sensitive_files.txt")
    cmd := exec.CommandContext(ctx, httpxBin,
        "-l", checkFile,
        "-sc", "-cl",
        "-mc", "200,301,302,403",
        "-silent",
        "-threads", fmt.Sprintf("%d", m.cfg.Threads),
        "-o", resultFile,
    )
    cmd.Run()

    results := readLines(resultFile)
    for _, r := range results {
        severity := "medium"
        lower := strings.ToLower(r)
        // Upgrade severity for confirmed sensitive files
        if strings.Contains(lower, ".env") || strings.Contains(lower, ".git/") ||
            strings.Contains(lower, "wp-config") || strings.Contains(lower, "phpinfo") ||
            strings.Contains(lower, "actuator/env") {
            severity = "high"
        }

        m.state.AddFinding(state.Finding{
            Type: "sensitive_file", Value: r, Source: "custom_check",
            Domain: domain, Severity: severity,
        })
    }
    m.log.Info("  Custom checks found %d interesting responses", len(results))
}
