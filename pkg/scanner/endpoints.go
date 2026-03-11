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
    if _, err := exec.LookPath("waybackurls"); err == nil {
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

    // ── gau ──
    if _, err := exec.LookPath("gau"); err == nil {
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

    // ── katana (active crawling) ──
    if _, err := exec.LookPath("katana"); err == nil {
        if _, err := os.Stat(liveURLsFile); err == nil {
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
        }
    }

    // ── gospider ──
    if _, err := exec.LookPath("gospider"); err == nil {
        if _, err := os.Stat(liveURLsFile); err == nil {
            wg.Add(1)
            go func() {
                defer wg.Done()
                m.log.Info("  Running GoSpider...")

                outFile := filepath.Join(outDir, "gospider.txt")
                cmd := exec.CommandContext(ctx, "gospider",
                    "-S", liveURLsFile,
                    "-d", "2",
                    "-c", fmt.Sprintf("%d", m.cfg.Threads),
                    "--other-source",
                    "--include-subs",
                    "-o", filepath.Join(outDir, "gospider_raw"),
                )
                cmd.Run()

                mergeCmd := exec.CommandContext(ctx, "bash", "-c",
                    fmt.Sprintf("cat %s/gospider_raw/* 2>/dev/null | grep -oP 'https?://[^ ]+' | sort -u > %s",
                        outDir, outFile))
                mergeCmd.Run()

                lines := readLines(outFile)
                mu.Lock()
                for _, l := range lines {
                    allEndpoints[l] = true
                }
                mu.Unlock()
                m.log.Info("  GoSpider found %d URLs", len(lines))
            }()
        }
    }

    wg.Wait()

    // ── Consolidate all endpoints ──
    uniqueEndpoints := make([]string, 0, len(allEndpoints))
    for ep := range allEndpoints {
        ep = strings.TrimSpace(ep)
        if ep != "" {
            uniqueEndpoints = append(uniqueEndpoints, ep)
        }
    }
    sort.Strings(uniqueEndpoints)

    finalFile := filepath.Join(outDir, "all_endpoints.txt")
    writeLines(finalFile, uniqueEndpoints)

    // ── Categorize endpoints ──
    m.categorizeEndpoints(outDir, uniqueEndpoints, domain)

    m.state.UpdateStats(func(s *state.ScanStats) {
        s.TotalEndpoints += len(uniqueEndpoints)
    })

    m.log.Success("  Total unique endpoints: %d → %s", len(uniqueEndpoints), finalFile)
    return nil
}

func (m *EndpointsModule) categorizeEndpoints(outDir string, endpoints []string, domain string) {
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
    }

    for _, ep := range endpoints {
        lower := strings.ToLower(ep)

        if strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") {
            categories["js_files"] = append(categories["js_files"], ep)
        }
        if strings.Contains(lower, "/api/") || strings.Contains(lower, "/v1/") ||
            strings.Contains(lower, "/v2/") || strings.Contains(lower, "/graphql") {
            categories["api_endpoints"] = append(categories["api_endpoints"], ep)
        }
        if strings.Contains(ep, "?") || strings.Contains(ep, "=") {
            categories["params"] = append(categories["params"], ep)
        }
        for _, pat := range sensitivePatterns {
            if strings.Contains(lower, pat) {
                categories["sensitive"] = append(categories["sensitive"], ep)

                m.state.AddFinding(state.Finding{
                    Type:     "sensitive_endpoint",
                    Value:    ep,
                    Source:   "endpoint_analysis",
                    Domain:   domain,
                    Severity: "medium",
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
