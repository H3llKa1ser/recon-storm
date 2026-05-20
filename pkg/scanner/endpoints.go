package scanner

import (
    "context"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "sort"
    "strings"
    "sync"

    "github.com/H3llKa1ser/recon-storm/pkg/config"
    "github.com/H3llKa1ser/recon-storm/pkg/logger"
    "github.com/H3llKa1ser/recon-storm/pkg/state"
)

type EndpointsModule struct {
    cfg   *config.Config
    state *state.Manager
    log   *logger.Logger
}

func NewEndpointsModule(cfg *config.Config, sm *state.Manager, log *logger.Logger) *EndpointsModule {
    return &EndpointsModule{cfg: cfg, state: sm, log: log}
}

func (m *EndpointsModule) Name() string { return "endpoints" }

func (m *EndpointsModule) Run(ctx context.Context, domain string) error {
    outDir := filepath.Join(m.cfg.OutputDir, domain, "endpoints")
    os.MkdirAll(outDir, 0755)

    liveURLsFile := filepath.Join(m.cfg.OutputDir, domain, "web", "live_urls.txt")
    subsFile := filepath.Join(m.cfg.OutputDir, domain, "subdomains", "all_subdomains.txt")

    var mu sync.Mutex
    allEndpoints := make(map[string]bool)

    var wg sync.WaitGroup

    // ── waybackurls ──
    if toolExists("waybackurls") {
        if fileExists(subsFile) {
            wg.Add(1)
            go func() {
                defer wg.Done()
                m.log.Info("  Running waybackurls...")
                outFile := filepath.Join(outDir, "waybackurls.txt")
                cmd := exec.CommandContext(ctx, "bash", "-c",
                    fmt.Sprintf("cat %s | waybackurls | sort -u > %s", subsFile, outFile))
                cmd.Run()
                lines := readLines(outFile)
                mu.Lock()
                for _, l := range lines {
                    allEndpoints[l] = true
                }
                mu.Unlock()
                m.log.Info("  waybackurls found %d URLs", len(lines))
            }()
        }
    } else {
        m.log.Warn("  waybackurls not found, skipping")
    }

    // ── gau ──
    if toolExists("gau") {
        if fileExists(subsFile) {
            wg.Add(1)
            go func() {
                defer wg.Done()
                m.log.Info("  Running gau...")
                outFile := filepath.Join(outDir, "gau.txt")
                cmd := exec.CommandContext(ctx, "bash", "-c",
                    fmt.Sprintf("cat %s | gau --threads %d | sort -u > %s", subsFile, m.cfg.Threads, outFile))
                cmd.Run()
                lines := readLines(outFile)
                mu.Lock()
                for _, l := range lines {
                    allEndpoints[l] = true
                }
                mu.Unlock()
                m.log.Info("  gau found %d URLs", len(lines))
            }()
        }
    } else {
        m.log.Warn("  gau not found, skipping")
    }

    // ── katana (active crawling) ──
    if toolExists("katana") {
        if fileExists(liveURLsFile) {
            wg.Add(1)
            go func() {
                defer wg.Done()
                m.log.Info("  Running katana crawler...")
                outFile := filepath.Join(outDir, "katana.txt")
                cmd := exec.CommandContext(ctx, "katana",
                    "-list", liveURLsFile,
                    "-d", "3",
                    "-jc",
                    "-kf", "all",
                    "-c", fmt.Sprintf("%d", m.cfg.Threads),
                    "-silent",
                    "-o", outFile,
                )
                cmd.Run()
                lines := readLines(outFile)
                mu.Lock()
                for _, l := range lines {
                    allEndpoints[l] = true
                }
                mu.Unlock()
                m.log.Info("  katana found %d URLs", len(lines))
            }()
        } else {
            m.log.Warn("  katana skipped — no live URLs available")
        }
    } else {
        m.log.Warn("  katana not found, skipping")
    }

    // ── gospider ──
    if toolExists("gospider") {
        if fileExists(liveURLsFile) {
            wg.Add(1)
            go func() {
                defer wg.Done()
                m.log.Info("  Running GoSpider...")
                rawDir := filepath.Join(outDir, "gospider_raw")
                outFile := filepath.Join(outDir, "gospider.txt")

                cmd := exec.CommandContext(ctx, "gospider",
                    "-S", liveURLsFile,
                    "-d", "2",
                    "-c", fmt.Sprintf("%d", m.cfg.Threads),
                    "--other-source",
                    "--include-subs",
                    "-o", rawDir,
                )
                cmd.Run()

                // Merge all gospider output files
                mergeCmd := exec.CommandContext(ctx, "bash", "-c",
                    fmt.Sprintf("cat %s/* 2>/dev/null | grep -oP 'https?://[^ ]+' | sort -u > %s", rawDir, outFile))
                mergeCmd.Run()

                lines := readLines(outFile)
                mu.Lock()
                for _, l := range lines {
                    allEndpoints[l] = true
                }
                mu.Unlock()
                m.log.Info("  GoSpider found %d URLs", len(lines))
            }()
        } else {
            m.log.Warn("  GoSpider skipped — no live URLs available")
        }
    } else {
        m.log.Warn("  GoSpider not found, skipping")
    }

    // ── hakrawler ──
    if toolExists("hakrawler") {
        if fileExists(liveURLsFile) {
            wg.Add(1)
            go func() {
                defer wg.Done()
                m.log.Info("  Running hakrawler...")
                outFile := filepath.Join(outDir, "hakrawler.txt")
                cmd := exec.CommandContext(ctx, "bash", "-c",
                    fmt.Sprintf("cat %s | hakrawler -d 2 -subs | sort -u > %s", liveURLsFile, outFile))
                cmd.Run()
                lines := readLines(outFile)
                mu.Lock()
                for _, l := range lines {
                    allEndpoints[l] = true
                }
                mu.Unlock()
                m.log.Info("  hakrawler found %d URLs", len(lines))
            }()
        }
    }

    wg.Wait()

    // ── Consolidate ──
    uniqueEndpoints := make([]string, 0, len(allEndpoints))
    for ep := range allEndpoints {
        ep = strings.TrimSpace(ep)
        if ep != "" && (strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://")) {
            uniqueEndpoints = append(uniqueEndpoints, ep)
        }
    }
    sort.Strings(uniqueEndpoints)

    if len(uniqueEndpoints) == 0 {
        m.log.Warn("  No endpoints discovered")
        return nil
    }

    finalFile := filepath.Join(outDir, "all_endpoints.txt")
    writeLines(finalFile, uniqueEndpoints)

    // ── Categorize ──
    m.categorize(outDir, uniqueEndpoints, domain)

    m.state.UpdateStats(func(s *state.ScanStats) {
        s.TotalEndpoints += len(uniqueEndpoints)
    })

    m.log.Success("  Total unique endpoints: %d → %s", len(uniqueEndpoints), finalFile)
    return nil
}

func (m *EndpointsModule) categorize(outDir string, endpoints []string, domain string) {
    categories := map[string][]string{
        "js_files":       {},
        "api_endpoints":  {},
        "params":         {},
        "sensitive":      {},
    }

    sensitivePatterns := []string{
        ".env", ".git", ".svn", "wp-admin", "wp-config", "phpinfo",
        "admin", "login", "dashboard", "api/v", "swagger", "graphql",
        ".sql", ".bak", ".backup", ".old", "config", "secret",
        "token", "password", "credential", ".key", ".pem",
        ".htaccess", ".htpasswd", "web.config", "crossdomain.xml",
        "actuator", "server-status", "server-info", ".DS_Store",
    }

    for _, ep := range endpoints {
        lower := strings.ToLower(ep)

        if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") ||
            strings.HasSuffix(lower, ".jsx") || strings.HasSuffix(lower, ".ts") {
            categories["js_files"] = append(categories["js_files"], ep)
        }

        if strings.Contains(lower, "/api/") || strings.Contains(lower, "/v1/") ||
            strings.Contains(lower, "/v2/") || strings.Contains(lower, "/v3/") ||
            strings.Contains(lower, "/graphql") || strings.Contains(lower, "/rest/") ||
            strings.Contains(lower, "/api-docs") || strings.Contains(lower, "/swagger") {
            categories["api_endpoints"] = append(categories["api_endpoints"], ep)
        }

        if strings.Contains(ep, "?") || strings.Contains(ep, "=") {
            categories["params"] = append(categories["params"], ep)
        }

        for _, pat := range sensitivePatterns {
            if strings.Contains(lower, pat) {
                categories["sensitive"] = append(categories["sensitive"], ep)
                m.state.AddFinding(state.Finding{
                    Type: "sensitive_endpoint", Value: ep,
                    Source: "endpoint_analysis", Domain: domain, Severity: "medium",
                    Metadata: map[string]string{"pattern": pat},
                })
                break
            }
        }
    }

    for cat, items := range categories {
        if len(items) > 0 {
            writeLines(filepath.Join(outDir, cat+".txt"), items)
            m.log.Info("  Categorized: %s = %d items", cat, len(items))
        }
    }
}
